//! Actual native durable delivery owner. Real twelve-kind exporters will call this
//! private source API; no HTTP upload, synthetic record or readiness flag is
//! introduced here. Unknown claim/contact state is irreversible.
use super::*;
use catchplate_decision_gate::{native_canary_delivery_v1 as wire,native_canary_evidence_v1 as intake};
pub(super) use wire::Configuration;
use std::collections::BTreeMap;

/// Source selection from the actual cold owner, never a caller capability bit.
/// Call before acquiring any generation/ledger lock.
pub(crate) fn native_cumulative_selected(state:&GateState)->Result<bool,String>{
    let Some(holder)=&state.measured_canary_delivery else{return Ok(false);};
    let owner=holder.try_lock().map_err(|_|"native cumulative delivery owner busy")?;
    if owner.authority.configuration().api_version=="catchplate.nativeCanaryDurableDelivery/v1" {return Ok(false);}
    owner.check(state)?;
    if owner.heartbeat.poisoned {return Err("native heartbeat owner is poisoned".into());}
    owner.authority.native_cumulative_selected()
}
pub(crate) fn native_finalization_selected(state:&GateState)->Result<bool,String>{
    let Some(holder)=&state.measured_canary_delivery else{return Ok(false);};
    let owner=holder.try_lock().map_err(|_|"native finalization delivery owner busy")?;
    if owner.authority.configuration().api_version!="catchplate.nativeCanaryDurableDelivery/v3" {return Ok(false);}
    owner.check(state)?;
    if owner.finalization.poisoned {return Err("native finalization owner is poisoned".into());}
    owner.authority.native_finalization_selected()
}

#[derive(Clone,Copy,PartialEq,Eq)]
enum Phase { PrepareAttempted, Prepared, ClaimAttempted, IntakeAttempted, Consumed }
struct Pending {
    original:intake::SignedEvidence,sender:wire::Sender,selector:wire::Selector,
    expires:u64,deadline:u64,assignment:String,phase:Phase,first:Option<wire::Completion>,
}
pub(super) struct Owner {
    pub(super) authority:wire::Authority,transport:native_canary_transport::Owner,
    pending:BTreeMap<String,Pending>,heads:BTreeMap<String,String>,observations:BTreeMap<String,wire::Completion>,
    pub(super) initialized:bool,pid:u32,pub(super) heartbeat:native_canary_heartbeat::Chain,
    pub(super) finalization:native_canary_finalization::Chain,
    readiness:BTreeMap<String,RetainedReadiness>,
}
struct RetainedReadiness{completion:wire::Completion,request_id:String,result_original:String,core_sha256:String}

pub(super) fn prepare(config:Configuration,inputs:&gate_state_init::GateStateInputs,
    roots:&ControlPlaneClientConfig,relays:&Arc<NativeUpstreamRelaysV1>,identity:&mut EnclaveRuntimeIdentityV1,
    deadline:u64)->Result<Owner,String>{
    let authority=wire::Authority::admit(config)?;let config=authority.configuration();
    if inputs.server_instance_id.as_deref()!=Some(config.instance_id.as_str()) || !inputs.is_production
        || !matches!(&inputs.service_tokens,native_service_tokens::Source::Installed) {
        return Err("canary durable delivery requires the same explicit native instance/encrypted cold profile".into());
    }
    let transport=native_canary_transport::prepare(roots,relays,&config.intake_url,&config.deployment_id,&config.instance_id,identity,deadline)?;
    Ok(Owner{authority,transport,pending:BTreeMap::new(),heads:BTreeMap::new(),observations:BTreeMap::new(),initialized:false,pid:std::process::id(),heartbeat:native_canary_heartbeat::Chain::new(),finalization:native_canary_finalization::Chain::new(),readiness:BTreeMap::new()})
}

/// Only the actual exporter hands off its opaque consumed completion. HTTP
/// callers cannot seed this slot with a result-shaped object or historical read.
pub(super) fn retain_readiness(state:&GateState,record:&Value,completion:wire::Completion)->Result<(),String>{
    let mut owner=state.measured_canary_delivery.as_ref().ok_or("native readiness owner absent")?
        .try_lock().map_err(|_|"native readiness owner busy")?;
    owner.check(state)?;
    let canary=record["canary_id"].as_str().ok_or("native readiness canary")?;
    if owner.readiness.contains_key(canary) || owner.readiness.len()>=32 || completion.observation().status()!="consumed"{
        return Err("native readiness original is not a fresh consumed exporter result".into());
    }
    let row=completion.observation().intake();
    let batch_raw=row["batch_original"].as_str().ok_or("native readiness original batch absent")?;
    let batch=strict_json_value_from_slice(batch_raw.as_bytes()).map_err(|e|e.to_string())?;
    let events=batch["events"].as_array().ok_or("native readiness events")?;
    if events.len()!=1 || events[0]["kind"]!="readiness" || events[0]["record"]!=*record {
        return Err("native readiness consumed a different original record".into());
    }
    let result_raw=row["result_original"].as_str().ok_or("native readiness result original absent")?;
    let result=strict_json_value_from_slice(result_raw.as_bytes()).map_err(|e|e.to_string())?;
    let results=result["results"].as_array().ok_or("native readiness result inventory")?;
    if results.len()!=1 || results[0]["kind"]!="readiness"
        || results[0]["recordSha256"]!=sha256_prefixed(&catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(record)?){
        return Err("native readiness result differs from source record".into());
    }
    let original=results[0]["storedOriginal"].as_str().ok_or("native readiness stored original")?.to_owned();
    let stored=strict_json_value_from_slice(original.as_bytes()).map_err(|e|e.to_string())?;
    if stored["apiVersion"]!="catchplate.nativePolicyReadinessResult/v1" || stored["okForAction"]!=false
        || stored["activationApprovalConsumed"]!=false || stored["automaticRetryAllowed"]!=false{
        return Err("native readiness stored result has another purpose".into());
    }
    let core=stored["coreSha256"].as_str().ok_or("native readiness core")?.to_owned();
    let request_id=batch["requestId"].as_str().ok_or("native readiness actual request ID")?.to_owned();
    owner.readiness.insert(canary.to_owned(),RetainedReadiness{completion,request_id,result_original:original,core_sha256:core});Ok(())
}
pub(super) fn require_readiness(state:&GateState,prepared:&Value)->Result<(),String>{
    let owner=state.measured_canary_delivery.as_ref().ok_or("native activation has no actual readiness owner")?
        .try_lock().map_err(|_|"native readiness owner busy")?;owner.check(state)?;
    let held=owner.readiness.get(prepared["canaryId"].as_str().ok_or("native activation canary")?).ok_or("native activation lacks source-retained readiness")?;
    if held.completion.observation().status()!="consumed" || prepared["readinessRequestId"]!=held.request_id
        || prepared["readinessOriginal"]!=held.result_original || prepared["readinessCoreSha256"]!=held.core_sha256
        || prepared["readinessResultSha256"]!=sha256_prefixed(held.result_original.as_bytes()){
        return Err("native activation substitutes retained original readiness".into());
    }Ok(())
}
fn original_deadline(state:&GateState,deadline:u64)->Result<u64,String>{
    let remaining=native_service_remaining(state)?.ok_or("canary actual native lifetime absent")?;
    let now=native_canary_transport::boottime_ns()?;
    let remaining=u64::try_from(remaining.as_nanos()).map_err(|_|"canary native lifetime overflow")?;
    let selected=deadline.min(now.checked_add(remaining).ok_or("canary deadline overflow")?);
    if selected<=now{return Err("canary original native deadline elapsed".into());}Ok(selected)
}
impl Owner {
    pub(super) fn check(&self,state:&GateState)->Result<(),String>{
        if self.pid!=std::process::id(){return Err("canary durable owner crossed process".into());}
        self.authority.check()?;native_service_remaining(state)?.ok_or("canary native lifetime absent")?;Ok(())
    }
    fn observe(&mut self,state:&GateState,target:&wire::RecoveryTarget,deadline:u64)->Result<wire::Completion,String>{
        self.check(state)?;target.selector().validate()?;
        let binding=self.authority.binding(&target.canary_id)?.clone();
        let deadline=self.authority.operation_deadline(original_deadline(state,deadline)?,false)?;
        let sender=self.transport.recovery_sender(state,&binding,deadline)?;
        // This fresh current signing owner is recovery-only. It does not adopt
        // the historical boot, old deadline, or a presumed unattempted contact.
        self.transport.delivery(state,&self.authority,wire::Operation::Recover,&sender,
            serde_json::to_value(target.selector()).map_err(|_|"recovery selector encoding")?,
            &binding.delivery_purpose_assignment_sha256,target.original_expires_at_epoch_ns,deadline)
    }
    fn drive(&mut self,state:&GateState,pending:&mut Pending)->Result<wire::Completion,String>{
        self.check(state)?;
        if ![Phase::PrepareAttempted,Phase::Prepared].contains(&pending.phase){return Err("claim/intake uncertainty cannot become another contact".into());}
        pending.original.check()?;
        let recover=serde_json::to_value(&pending.selector).map_err(|_|"delivery recovery selector")?;
        if pending.first.is_none(){
            let first=self.transport.delivery(state,&self.authority,wire::Operation::Recover,&pending.sender,recover.clone(),&pending.assignment,pending.expires,pending.deadline)?;
            if first.observation().status()!="prepared" || first.observation().http_original().map(str::as_bytes)!=Some(pending.original.original()){
                return Err("lost prepare has no exact original prepared commit; no prepare resend".into());
            }
            pending.first=Some(first);pending.phase=Phase::Prepared;
        }
        let read=self.transport.delivery(state,&self.authority,wire::Operation::Recover,&pending.sender,recover.clone(),&pending.assignment,pending.expires,pending.deadline)?;
        if read.observation().http_original().map(str::as_bytes)!=Some(pending.original.original()){
            return Err("delivery authenticated read differs from retained future HTTP original".into());
        }
        let request=read.claim_request(pending.first.as_ref().ok_or("delivery first proof absent")?)?;
        pending.phase=Phase::ClaimAttempted;
        let claim=self.transport.delivery(state,&self.authority,wire::Operation::Claim,&pending.sender,request,&pending.assignment,pending.expires,pending.deadline)?;
        if claim.observation().status()!="claimed"{return Err("delivery claim did not definitely complete".into());}
        pending.phase=Phase::IntakeAttempted;
        // Status/body returned by intake is not the durable terminal proof.
        // Even a lost response is followed only by authenticated observation,
        // never a second POST of this original or a replacement batch.
        let contact=self.transport.intake_once(state,claim,&pending.original);
        let observed=self.transport.delivery(state,&self.authority,wire::Operation::Recover,&pending.sender,recover,&pending.assignment,pending.expires,pending.deadline);
        match observed {
            Ok(value) if value.observation().status()=="consumed"=>{pending.phase=Phase::Consumed;Ok(value)},
            Ok(_)=>Err("intake outcome remains unresolved; no resend or fresh head".into()),
            Err(error)=>Err(format!("intake completion not authenticated; contact {}; {error}",if contact.is_ok(){"returned data"}else{"unknown"})),
        }
    }
    fn finish(&mut self,canary:&str,pending:Pending,result:Result<wire::Completion,String>)->Result<wire::Completion,String>{
        match result {
            Ok(value) if pending.phase==Phase::Consumed=>{
                self.heads.insert(canary.into(),sha256_prefixed(&catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(value.observation().head())?));
                Ok(value)
            },
            other=>{self.pending.insert(canary.into(),pending);other},
        }
    }
}

/// Actual source caller seam for genuine exporters. BatchOriginal validates
/// wire structure only; independent intake verifies each producer original.
pub(super) fn submit(state:&GateState,batch:intake::BatchOriginal,deadline:u64)->Result<wire::Completion,String>{
    let holder=state.measured_canary_delivery.as_ref().ok_or("native canary delivery not cold selected")?;
    let mut owner=holder.try_lock().map_err(|_|"another canary original owns the delivery phase")?;
    owner.check(state)?;
    if !owner.initialized{return Err("canary delivery not initialized".into());}
    let canary=batch.canary_id().to_owned();
    if owner.pending.contains_key(&canary){return Err("canary unresolved local original cannot be replaced".into());}
    let binding=owner.authority.binding(&canary)?.clone();
    let deadline=owner.authority.operation_deadline(original_deadline(state,deadline)?,true)?;
    let prepared=owner.transport.prepare_evidence(state,intake::Operation::Intake,batch,&binding.intake_purpose_assignment_sha256,
        &binding.canary_assignment_sha256,&binding.canary_boot_id,deadline)?;
    owner.authority.require_sender(&serde_json::to_value(prepared.statement()).map_err(|_|"canary intake statement")?,false)?;
    let sender=wire::Sender::from_intake(prepared.statement());let expires=prepared.statement().expires_at_epoch_ns;
    let original=owner.transport.sign(state,&prepared)?;
    let selector=wire::Selector::from_http(original.original())?;
    let request=json!({"httpOriginal":std::str::from_utf8(original.original()).map_err(|_|"canary HTTP ASCII")?,"expectedHeadSha256":owner.heads.get(&canary)});
    let mut pending=Pending{original,sender,selector,expires,deadline:prepared.deadline(),assignment:binding.delivery_purpose_assignment_sha256,
        phase:Phase::PrepareAttempted,first:None};
    let result=(||{
        let Owner{transport,authority,..}=&mut *owner;
        let first=transport.delivery(state,authority,wire::Operation::Prepare,&pending.sender,request,&pending.assignment,pending.expires,pending.deadline)?;
        if first.observation().status()!="prepared"{return Err("canary durable prepare not definitely committed".into());}
        pending.first=Some(first);pending.phase=Phase::Prepared;
        owner.drive(state,&mut pending)
    })();
    owner.finish(&canary,pending,result)
}

/// Same retained owner and exact unexpired HTTP original only. This never
/// resends prepare, and refuses once any claim/contact has been attempted.
pub(super) fn continue_prepared(state:&GateState,canary:&str)->Result<wire::Completion,String>{
    let mut owner=state.measured_canary_delivery.as_ref().ok_or("canary delivery absent")?.try_lock().map_err(|_|"canary delivery busy")?;
    let mut pending=owner.pending.remove(canary).ok_or("same-boot original not retained")?;
    let result=owner.drive(state,&mut pending);owner.finish(canary,pending,result)
}

/// Explicit selectors are data only. The current independent recovery grant,
/// protected head and historical original decide what can be observed.
pub(super) fn recover(state:&GateState,target:&wire::RecoveryTarget,deadline:u64)->Result<wire::Completion,String>{
    let mut owner=state.measured_canary_delivery.as_ref().ok_or("canary delivery absent")?.try_lock().map_err(|_|"canary delivery busy")?;
    let observed=owner.observe(state,target,deadline)?;
    // Settle a known consumed result only when this process still owns the
    // exact attempted original. This grants no contact and adopts no history.
    let same=owner.pending.get(&target.canary_id).is_some_and(|pending|
        [Phase::ClaimAttempted,Phase::IntakeAttempted].contains(&pending.phase)
        && pending.selector.slot_id==target.slot_id
        && observed.observation().http_original().map(str::as_bytes)==Some(pending.original.original()));
    if same && observed.observation().status()=="consumed" {
        let head=observed.observation().head();
        if head["slot_id"]==target.slot_id && head["status"]=="consumed" {
            owner.heads.insert(target.canary_id.clone(),sha256_prefixed(&catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(head)?));
            owner.pending.remove(&target.canary_id);
        }
    }
    Ok(observed)
}
pub(super) fn initialize(state:&GateState)->Result<(),String>{
    let Some(holder)=&state.measured_canary_delivery else{return Ok(());};
    let mut owner=holder.lock().map_err(|_|"canary cold owner poisoned")?;
    if owner.initialized{return Err("canary delivery initialized twice".into());}
    let targets=owner.authority.configuration().recovery_targets.clone();
    for target in targets{
        let now=native_canary_transport::boottime_ns()?;
        let deadline=now.checked_add(30_000_000_000).ok_or("canary recovery processing interval")?;
        let observation=owner.observe(state,&target,deadline)?;
        // Even prepared/claimed history remains observation only. No pending
        // same-boot send owner, expected head or permit is reconstructed here.
        owner.observations.insert(target.slot_id,observation);
    }
    owner.initialized=true;Ok(())
}
