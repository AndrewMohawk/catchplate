//! One actual generation/snapshot, one signed heartbeat, one durable delivery.
use super::*;
use serverware_decision_gate::native_canary_heartbeat_v1 as wire;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes as ascii;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use ring::rand::{SecureRandom,SystemRandom};

pub(super) struct Chain {pub(super) poisoned:bool,inflight:bool,generation:Option<String>,originals:Vec<String>,bytes:usize,observed:u64}
impl Chain {pub(super) fn new()->Self{Self{poisoned:false,inflight:false,generation:None,originals:Vec::new(),bytes:0,observed:0}}}
/// No Deserialize/public constructor: definite consumed delivery plus the exact
/// sealed accounting snapshot. A later checkpoint must use THIS snapshot.
pub(crate) struct RetainedHeartbeat {snapshot:policy_core::NativeAccountingSnapshot,original:String,sha256:String}
impl RetainedHeartbeat {
    pub(crate) fn snapshot(&self)->&policy_core::NativeAccountingSnapshot{&self.snapshot}
    pub(crate) fn original(&self)->&str{&self.original}
    pub(crate) fn sha256(&self)->&str{&self.sha256}
}

pub(crate) fn checkpoint(state:&GateState,deadline:u64)->Result<RetainedHeartbeat,String>{
    if !native_canary_delivery::native_cumulative_selected(state)? {return Err("native heartbeat not selected".into());}
    let control=state.policy_shadow_generation_control.as_ref().ok_or("heartbeat native generation owner absent")?;
    control.with_native_heartbeat_snapshot(state,|snapshot,scope|checkpoint_owned(state,deadline,snapshot,scope))
}
fn checkpoint_owned(state:&GateState,deadline:u64,snapshot:policy_core::NativeAccountingSnapshot,scope:Value)
    ->Result<RetainedHeartbeat,String>{
    let holder=state.measured_canary_delivery.as_ref().ok_or("heartbeat delivery absent")?;
    let mut owner=holder.try_lock().map_err(|_|"heartbeat delivery busy")?;owner.check(state)?;
    let generation=snapshot.generation_id().as_str().to_owned();
    if !owner.initialized || owner.heartbeat.poisoned || owner.heartbeat.inflight
        || owner.heartbeat.originals.len()>=wire::MAX_HEARTBEATS
        || owner.heartbeat.generation.as_ref().is_some_and(|old|old!=&generation){
        owner.heartbeat.poisoned=true;return Err("heartbeat chain unavailable, exhausted or generation changed".into());
    }
    owner.heartbeat.inflight=true;
    let result=(||{
        let canary=scope["canary_id"].as_str().ok_or("heartbeat actual canary")?;
        let (assignment,purpose)=owner.authority.heartbeat_assignment(canary)?;
        let policy=owner.authority.heartbeat_policy()?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("heartbeat native signing owner absent".into());};
        signer.transport.require_native()?;
        let current=current_snapshot(state);
        if !snapshot_is_active(state,&current) || current_binary_digest()?!=state.binary_digest{return Err("heartbeat current policy/source changed".into());}
        let observed=u64::try_from(snapshot.observed_at_unix_nanos()).map_err(|_|"heartbeat trusted time")?;
        let boot=native_canary_transport::boottime_ns()?;
        let remaining=native_service_remaining(state)?.ok_or("heartbeat actual lifetime absent")?;
        let remaining=u64::try_from(remaining.as_nanos()).map_err(|_|"heartbeat remaining overflow")?;
        let deadline=deadline.min(boot.checked_add(remaining.min(wire::number(policy,"operationMaxSeconds")?*1_000_000_000)).ok_or("heartbeat deadline overflow")?);
        let expires=observed.checked_add(deadline.checked_sub(boot).ok_or("heartbeat original deadline elapsed")?).ok_or("heartbeat expiry overflow")?
            .min(wire::number(policy,"expiresAtEpochNs")?).min(scope["expiresAtUnixNanos"].as_u64().ok_or("heartbeat scope end")?);
        if observed<owner.heartbeat.observed || (owner.heartbeat.observed>0
            && observed-owner.heartbeat.observed>wire::number(policy,"maximumGapNanos")?){return Err("heartbeat continuity gap".into());}
        let previous=owner.heartbeat.originals.last().map(|value|sha256_prefixed(value.as_bytes())).unwrap_or_else(||generation.clone());
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
            "heartbeatSequence":owner.heartbeat.originals.len()+1,"previousHeartbeatSha256":previous,
            "baselineEventOrdinal":snapshot.baseline_event_ordinal(),"baselineHeadSha256":snapshot.baseline_head_sha256(),
            "eventOrdinal":snapshot.event_ordinal(),"headSha256":snapshot.head_sha256(),"originalCount":snapshot.original_count(),
            "lastIngressSequence":opening.as_ref().map(|v|v.0),"openingReceiptSha256":opening.as_ref().map(|v|&v.1),
            "observedAtUnixNanos":observed,"issuedAtEpochNs":observed,"expiresAtEpochNs":expires,"nonce":URL_SAFE_NO_PAD.encode(nonce)});
        for name in ["holderId","bootId","keyId","controlPlaneResponseSigningKeyId","policyHash","instanceId","canaryId","canaryAssignmentSha256","canaryBootId"]{
            if statement[name]!=assignment[name]{return Err("heartbeat actual owner differs from independent assignment".into());}
        }
        if statement["dataPlaneBinarySha256"]!=assignment["expectedBinaryDigest"]{return Err("heartbeat independent source pin".into());}
        let prepared=wire::Prepared::new(statement,deadline)?;
        let evidence={let mut identity=state.mitm_authority.as_ref().ok_or("heartbeat native identity absent")?.lock().map_err(|_|"heartbeat identity poisoned")?;
            let MitmAuthority::Native(identity)=&mut *identity else{return Err("heartbeat imported identity refused".into());};
            signer.transport.canary_heartbeat(identity,&prepared,deadline)?};
        if !snapshot_is_active(state,&current){return Err("heartbeat policy changed during signature".into());}
        let record=json!({"apiVersion":wire::RECORD,"canary_id":scope["canary_id"],"instance_id":scope["instance_id"],"boot_id":scope["boot_id"],
            "assignment_envelope_digest":scope["assignment_envelope_digest"],"assignment_payload_digest":scope["assignment_payload_digest"],
            "load_receipt_envelope_digest":scope["load_receipt_envelope_digest"],"publication_envelope_digest":scope["publication_envelope_digest"],"evidence":evidence});
        let raw=ascii(&record)?;
        if raw.len()>wire::MAX_RECORD || owner.heartbeat.bytes.checked_add(raw.len()).filter(|n|*n<=512*1024).is_none(){return Err("heartbeat retained original capacity".into());}
        let original=String::from_utf8(raw).map_err(|_|"heartbeat ASCII")?;
        let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"heartbeat request entropy")?;id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;
        let id=hex::encode(id);let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
        let batch=json!({"apiVersion":"serverware.policyCanaryEvidenceOriginal/v1","requestId":request,"canaryId":canary,"events":[{"kind":"custody","record":record}]});
        Ok((original,serverware_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(String::from_utf8(ascii(&batch)?).map_err(|_|"heartbeat batch ASCII")?)?,deadline,observed))
    })();
    let (original,batch,deadline,observed)=match result{Ok(value)=>value,Err(error)=>{owner.heartbeat.poisoned=true;return Err(error);}};
    drop(owner);
    // Existing real durable prepare/claim/intake/recover protocol. No direct
    // HTTP response or missing acknowledgement is promoted to completion.
    let complete=native_canary_delivery::submit(state,batch,deadline);
    let mut owner=holder.lock().map_err(|_|"heartbeat completion owner poisoned")?;
    match complete {
        Ok(value) if value.observation().status()=="consumed"=>{},
        _=>{owner.heartbeat.poisoned=true;return Err("heartbeat outcome unresolved; no retry or successor".into());}
    }
    owner.check(state)?;
    let digest=sha256_prefixed(original.as_bytes());owner.heartbeat.bytes+=original.len();
    owner.heartbeat.originals.push(original.clone());owner.heartbeat.generation=Some(generation);
    owner.heartbeat.observed=observed;owner.heartbeat.inflight=false;
    Ok(RetainedHeartbeat{snapshot,original,sha256:digest})
}
