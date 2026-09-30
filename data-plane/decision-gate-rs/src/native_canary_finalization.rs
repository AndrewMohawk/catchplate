//! One actual generation/snapshot, one signed heartbeat, one durable delivery.
use super::*;
use serverware_decision_gate::native_canary_finalization_v1 as wire;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes as ascii;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use ring::rand::{SecureRandom,SystemRandom};

pub(super) struct Chain {pub(super) poisoned:bool,inflight:bool,generation:Option<String>,originals:Vec<String>,bytes:usize,observed:u64,pub(super) next:u64,pub(super) sealed:bool,pub(super) interval:Option<policy_shadow::Sha256Digest>}
impl Chain {pub(super) fn new()->Self{Self{poisoned:false,inflight:false,generation:None,originals:Vec::new(),bytes:0,observed:0,next:0,sealed:false,interval:None}}}
/// No Deserialize/public constructor: definite consumed delivery plus the exact
/// sealed accounting snapshot. A later checkpoint must use THIS snapshot.
pub(crate) struct RetainedHeartbeat {snapshot:policy_core::NativeAccountingSnapshot,original:String,sha256:String,seal:Option<policy_core::NativeDrainSnapshot>,deadline:u64,next:u64}
impl RetainedHeartbeat {
    pub(crate) fn seal(&self)->Option<&policy_core::NativeDrainSnapshot>{self.seal.as_ref()}
    pub(crate) fn snapshot(&self)->&policy_core::NativeAccountingSnapshot{&self.snapshot}
    pub(crate) fn original(&self)->&str{&self.original}
    pub(crate) fn sha256(&self)->&str{&self.sha256}
}

fn checkpoint_owned(state:&GateState,deadline:u64,snapshot:policy_core::NativeAccountingSnapshot,scope:Value,seal:Option<policy_core::NativeDrainSnapshot>)
    ->Result<RetainedHeartbeat,String>{
    let holder=state.measured_canary_delivery.as_ref().ok_or("heartbeat delivery absent")?;
    let mut owner=holder.try_lock().map_err(|_|"heartbeat delivery busy")?;owner.check(state)?;
    let generation=snapshot.generation_id().as_str().to_owned();
    if !owner.initialized || owner.finalization.poisoned || owner.finalization.inflight || owner.finalization.sealed
        || owner.finalization.originals.len()>=wire::MAX_HEARTBEATS
        || owner.finalization.generation.as_ref().is_some_and(|old|old!=&generation){
        owner.finalization.poisoned=true;return Err("heartbeat chain unavailable, exhausted or generation changed".into());
    }
    owner.finalization.inflight=true;
    let result=(||{
        let canary=scope["canary_id"].as_str().ok_or("heartbeat actual canary")?;
        let (assignment,purpose)=owner.authority.finalization_assignment(canary)?;
        let policy=owner.authority.finalization_policy()?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("heartbeat native signing owner absent".into());};
        signer.transport.require_native()?;
        let current=current_snapshot(state);
        if !snapshot_is_active(state,&current) || current_binary_digest()?!=state.binary_digest{return Err("heartbeat current policy/source changed".into());}
        let observed=u64::try_from(snapshot.observed_at_unix_nanos()).map_err(|_|"heartbeat trusted time")?;
        let boot=native_canary_transport::boottime_ns()?;
        let remaining=native_service_remaining(state)?.ok_or("heartbeat actual lifetime absent")?;
        let remaining=u64::try_from(remaining.as_nanos()).map_err(|_|"heartbeat remaining overflow")?;
        let scope_end=scope["expiresAtUnixNanos"].as_u64().ok_or("finalization scope end")?
            .min(wire::number(policy,"expiresAtEpochNs")?);
        let scope_remaining=scope_end.checked_sub(observed).ok_or("original finalization scope elapsed")?;
        let deadline=deadline.min(boot.checked_add(remaining.min(scope_remaining)
            .min(wire::number(policy,"operationMaxSeconds")?*1_000_000_000)).ok_or("heartbeat deadline overflow")?);
        let expires=observed.checked_add(deadline.checked_sub(boot).ok_or("heartbeat original deadline elapsed")?).ok_or("heartbeat expiry overflow")?
            .min(wire::number(policy,"expiresAtEpochNs")?).min(scope["expiresAtUnixNanos"].as_u64().ok_or("heartbeat scope end")?);
        if observed<=owner.finalization.observed || (owner.finalization.observed>0
            && observed-owner.finalization.observed>wire::number(policy,"maximumGapNanos")?){return Err("heartbeat continuity gap".into());}
        let previous=owner.finalization.originals.last().map(|value|sha256_prefixed(value.as_bytes())).unwrap_or_else(||generation.clone());
        let mut nonce=[0u8;32];SystemRandom::new().fill(&mut nonce).map_err(|_|"heartbeat nonce")?;
        if nonce==[0;32]{return Err("heartbeat zero nonce".into());}
        let opening=snapshot.last_ingress();
        let statement=json!({"apiVersion":wire::SCHEMA,"purpose":wire::PURPOSE,"deploymentId":owner.authority.configuration().deployment_id,
            "instanceId":scope["instance_id"],"holderId":serverware_decision_gate::native_currentness_v1::holder_id(&signer.boot_id,&signer.key_id)?,
            "bootId":signer.boot_id,"keyId":signer.key_id,"controlPlaneResponseSigningKeyId":signer.control_plane_response_signing_key_id,
            "policyHash":current.hash,"dataPlaneBinarySha256":state.binary_digest,"purposeAssignmentSha256":purpose,
            "canaryId":canary,"canaryAssignmentSha256":scope["assignment_envelope_digest"],"canaryBootId":scope["boot_id"],
            "assignmentPayloadSha256":scope["assignment_payload_digest"],"loadReceiptSha256":scope["load_receipt_envelope_digest"],
            "publicationSha256":scope["publication_envelope_digest"],"generationId":generation,"runtimeIdentitySha256":scope["runtimeIdentitySha256"],
            "heartbeatSequence":owner.finalization.originals.len()+1,"previousHeartbeatSha256":previous,
            "baselineEventOrdinal":snapshot.baseline_event_ordinal(),"baselineHeadSha256":snapshot.baseline_head_sha256(),
            "eventOrdinal":snapshot.event_ordinal(),"headSha256":snapshot.head_sha256(),"originalCount":snapshot.original_count(),
            "lastIngressSequence":opening.as_ref().map(|v|v.0),"openingReceiptSha256":opening.as_ref().map(|v|&v.1),
            "observedAtUnixNanos":observed,"issuedAtEpochNs":observed,"expiresAtEpochNs":expires,"nonce":URL_SAFE_NO_PAD.encode(nonce),"seal":seal.as_ref().map(|value|value.value())});
        for name in ["holderId","bootId","keyId","controlPlaneResponseSigningKeyId","policyHash","instanceId","canaryId","canaryAssignmentSha256","canaryBootId"]{
            if statement[name]!=assignment[name]{return Err("heartbeat actual owner differs from independent assignment".into());}
        }
        if statement["dataPlaneBinarySha256"]!=assignment["expectedBinaryDigest"]{return Err("heartbeat independent source pin".into());}
        let prepared=wire::Prepared::new(statement,deadline)?;
        let evidence={let mut identity=state.mitm_authority.as_ref().ok_or("heartbeat native identity absent")?.lock().map_err(|_|"heartbeat identity poisoned")?;
            let MitmAuthority::Native(identity)=&mut *identity else{return Err("heartbeat imported identity refused".into());};
            signer.transport.canary_finalization(identity,&prepared,deadline)?};
        if !snapshot_is_active(state,&current){return Err("heartbeat policy changed during signature".into());}
        let record=json!({"apiVersion":wire::RECORD,"canary_id":scope["canary_id"],"instance_id":scope["instance_id"],"boot_id":scope["boot_id"],
            "assignment_envelope_digest":scope["assignment_envelope_digest"],"assignment_payload_digest":scope["assignment_payload_digest"],
            "load_receipt_envelope_digest":scope["load_receipt_envelope_digest"],"publication_envelope_digest":scope["publication_envelope_digest"],"evidence":evidence});
        let raw=ascii(&record)?;
        if raw.len()>wire::MAX_RECORD || owner.finalization.bytes.checked_add(raw.len()).filter(|n|*n<=512*1024).is_none(){return Err("heartbeat retained original capacity".into());}
        let original=String::from_utf8(raw).map_err(|_|"heartbeat ASCII")?;
        let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"heartbeat request entropy")?;id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;
        let id=hex::encode(id);let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
        let batch=json!({"apiVersion":"serverware.policyCanaryEvidenceOriginal/v1","requestId":request,"canaryId":canary,"events":[{"kind":"custody","record":record}]});
        let window_end=scope["windowEndsAtUnixNanos"].as_u64().ok_or("final original window end")?;
        let delay=if observed<window_end {(window_end-observed).min(wire::number(policy,"maximumGapNanos")?/2)}
            else {wire::number(policy,"maximumGapNanos")?/2};
        let next=boot.checked_add(delay).ok_or("final cadence overflow")?;
        Ok((original,serverware_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(String::from_utf8(ascii(&batch)?).map_err(|_|"heartbeat batch ASCII")?)?,deadline,observed,next))
    })();
    let (original,batch,deadline,observed,next)=match result{Ok(value)=>value,Err(error)=>{owner.finalization.poisoned=true;return Err(error);}};
    drop(owner);
    // Existing real durable prepare/claim/intake/recover protocol. No direct
    // HTTP response or missing acknowledgement is promoted to completion.
    let complete=native_canary_delivery::submit(state,batch,deadline);
    let mut owner=holder.lock().map_err(|_|"heartbeat completion owner poisoned")?;
    match complete {
        Ok(value) if value.observation().status()=="consumed"=>{},
        _=>{owner.finalization.poisoned=true;return Err("heartbeat outcome unresolved; no retry or successor".into());}
    }
    owner.check(state)?;
    let digest=sha256_prefixed(original.as_bytes());owner.finalization.bytes+=original.len();
    owner.finalization.originals.push(original.clone());owner.finalization.generation=Some(generation);
    owner.finalization.observed=observed;owner.finalization.inflight=false;
    Ok(RetainedHeartbeat{snapshot,original,sha256:digest,seal,deadline,next})
}

/// Actual worker cadence. One fresh observation owns its own bounded processing
/// deadline; previous unknown delivery/head state can never be renewed.
pub(crate) fn tick(state:&GateState)->Result<(),String>{
    let now=native_canary_transport::boottime_ns()?;
    let holder=state.measured_canary_delivery.as_ref().ok_or("final delivery absent")?;
    {
        let owner=match holder.try_lock(){
            Ok(owner)=>owner,Err(std::sync::TryLockError::WouldBlock)=>return Ok(()),
            Err(std::sync::TryLockError::Poisoned(_))=>return Err("final cadence owner poisoned".into())};
        if !owner.authority.native_finalization_selected()? {return Err("final cadence profile changed".into());}
        owner.check(state)?;
        if owner.finalization.poisoned {return Err("final cadence follows uncertainty".into());}
        if owner.finalization.sealed || now<owner.finalization.next {return Ok(());}
    }
    let control=state.policy_shadow_generation_control.as_ref().ok_or("final generation owner absent")?;
    // No observation exists before the actual generation/snapshot is acquired.
    let deadline=native_canary_opening::deadline(state)?;
    let Some(heartbeat)=control.with_native_finalization_snapshot(state,
        |snapshot,scope,seal|checkpoint_owned(state,deadline,snapshot,scope,seal))? else{return Ok(());};
    let result=(||{
        let sealed=heartbeat.seal().is_some();
        let attempt=state.policy_shadow.native_finalization_begin(heartbeat.snapshot(),sealed)?;
        let interval={holder.try_lock().map_err(|_|"final interval owner busy")?.finalization.interval.clone()};
        let checkpoint=control.native_final_cumulative_observation(&heartbeat,&attempt,interval.as_ref())?;
        let digest=checkpoint.sha256().map_err(|e|e.to_string())?;
        let original:Value=serde_json::from_str(&checkpoint.original().map_err(|e|e.to_string())?).map_err(|_|"final original")?;
        let event=checkpoint.into_event();
        let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"final checkpoint entropy")?;
        id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;let id=hex::encode(id);
        let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
        let batch=json!({"apiVersion":"serverware.policyCanaryEvidenceOriginal/v1","requestId":request,
            "canaryId":event["record"]["canary_id"],"events":[event]});
        let batch=serverware_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(
            String::from_utf8(ascii(&batch)?).map_err(|_|"final batch ASCII")?)?;
        let complete=native_canary_delivery::submit(state,batch,heartbeat.deadline)?;
        state.policy_shadow.native_cumulative_complete(attempt,&digest,&complete)?;
        {
            let mut owner=holder.try_lock().map_err(|_|"final completion owner busy")?;owner.check(state)?;
            owner.finalization.sealed=sealed;
            owner.finalization.next=heartbeat.next;
        }
        if sealed {
            // Actual protected final original, not local readiness. The paired
            // readiness owner performs exactly one independently admitted read/
            // derivation and cannot renew this processing window.
            native_canary_readiness::submit(state,&original,heartbeat.deadline)?;
        }
        Ok(())
    })();
    if result.is_err(){if let Ok(mut owner)=holder.lock(){owner.finalization.poisoned=true;}}
    result
}
