//! Retained real lifecycle -> fixed original -> existing durable delivery owner.
use super::*;
use ring::rand::{SecureRandom,SystemRandom};
use std::sync::Weak;

/// The weak reference points to the SAME serving Arc, never a reconstructed
/// signing/transport owner. Only a definitely consumed opening creates this.
pub(super) struct Opening {
    gate:Weak<GateState>,generation:policy_shadow::Sha256Digest,ingress:u64,
    request_binding:policy_shadow::Sha256Digest,request_commitment:policy_shadow::Sha256Digest,
    opening:policy_shadow::Sha256Digest,phase:Mutex<Phase>,
    details_selected:bool,native_early_sampling:bool,facts_attempted:std::sync::atomic::AtomicBool,
}
enum Phase {
    Open, Terminal(policy_shadow::Sha256Digest),
    Request {terminal:policy_shadow::Sha256Digest,request:policy_shadow::Sha256Digest},
    Attempted, Complete{terminal:policy_shadow::Sha256Digest,request:policy_shadow::Sha256Digest,response:policy_shadow::Sha256Digest},
}

/// One processing owner fixed before the actual custody compaction. Consumed
/// by submit, never reconstructed from a receipt, interval or delivery result.
pub(super) struct CheckpointAttempt {state:Arc<GateState>,deadline:u64,generation:policy_shadow::Sha256Digest}
impl CheckpointAttempt {
    pub(super) fn prepare(state:Arc<GateState>)->Result<Self,String> {
        if state.measured_canary_delivery.is_none() {return Err("checkpoint durable owner absent".into());}
        let deadline=native_canary_opening::deadline(&state)?;
        let before=native_canary_transport::boottime_ns()?;
        let (generation,remaining)=state.policy_shadow_generation_control.as_ref().ok_or("checkpoint generation owner absent")?
            .native_checkpoint_window()?;
        let deadline=deadline.min(before.checked_add(remaining).ok_or("checkpoint window overflow")?);
        Ok(Self{state,deadline,generation})
    }
    pub(super) fn submit(self,applied:policy_core::AppliedSpoolCheckpoint)->Result<(),String> {
        let result=(|| {
            if native_canary_transport::boottime_ns()?>=self.deadline {return Err("checkpoint original processing deadline elapsed".into());}
            if applied.receipt().generation_id()!=&self.generation {return Err("checkpoint crossed its original generation window".into());}
            let control=self.state.policy_shadow_generation_control.as_ref().ok_or("checkpoint generation owner absent")?;
            let event=control.native_checkpoint_observation(&applied)?.into_event();
            let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"checkpoint entropy")?;
            id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;let id=hex::encode(id);
            let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
            let raw=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                "apiVersion":"catchplate.policyCanaryEvidenceOriginal/v1","requestId":request,
                "canaryId":event["record"]["canary_id"],"events":[event]}))?;
            let batch=catchplate_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(
                String::from_utf8(raw).map_err(|_|"checkpoint ASCII")?)?;
            let complete=native_canary_delivery::submit(&self.state,batch,self.deadline)?;
            if complete.observation().status()!="consumed" {return Err("checkpoint not definitely consumed".into());}
            if native_canary_delivery::native_finalization_selected(&self.state)? {
                let mut owner=self.state.measured_canary_delivery.as_ref().ok_or("finalization owner absent")?
                    .try_lock().map_err(|_|"finalization interval owner busy")?;
                owner.check(&self.state)?;
                owner.finalization.interval=Some(applied.receipt().signed_receipt_sha256().clone());
            } else if native_canary_delivery::native_cumulative_selected(&self.state)? {
                // Same original processing window; the heartbeat's ledger lock
                // fixes both the complete retained head and its observation time.
                let heartbeat=native_canary_heartbeat::checkpoint(&self.state,self.deadline)?;
                let attempt=self.state.policy_shadow.native_cumulative_begin(heartbeat.snapshot())?;
                let checkpoint=control.native_cumulative_observation(&heartbeat,&attempt,applied.receipt().signed_receipt_sha256())?;
                let digest=checkpoint.sha256().map_err(|error|error.to_string())?;
                let event=checkpoint.into_event();
                let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"cumulative entropy")?;
                id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;let id=hex::encode(id);
                let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
                let raw=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"catchplate.policyCanaryEvidenceOriginal/v1","requestId":request,
                    "canaryId":event["record"]["canary_id"],"events":[event]}))?;
                let batch=catchplate_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(
                    String::from_utf8(raw).map_err(|_|"cumulative ASCII")?)?;
                let complete=native_canary_delivery::submit(&self.state,batch,self.deadline)?;
                self.state.policy_shadow.native_cumulative_complete(attempt,&digest,&complete)?;
            }
            Ok(())
        })();
        if result.is_err(){self.state.policy_shadow.fail_native_observation();}
        result
    }
}
impl Opening {
    pub(super) fn details_selected(&self)->bool {self.details_selected}
    pub(super) fn protected_request(&self,facts:&policy_shadow::ProtectedRequestFacts,observed:i64)->Result<Option<Value>,String>{
        if !self.native_early_sampling{return Ok(None);}
        let state=self.gate.upgrade().ok_or("facts original lost its actual serving owner")?;
        let result=(||{
            let phase=self.phase.try_lock().map_err(|_|"facts lifecycle busy")?;
            if !self.details_selected || !matches!(&*phase,Phase::Terminal(_))
                || self.facts_attempted.swap(true,std::sync::atomic::Ordering::AcqRel) {
                return Err("facts commitment requires its sole actual post-terminal attempt".into());
            }
            let commitment=state.policy_shadow_generation_control.as_ref().ok_or("facts generation owner absent")?
                .commit_native_request_facts(&self.generation,self.ingress,observed,facts)?;
            Ok(Some(json!({"apiVersion":"catchplate.nativeProtectedRequestCommitment/v1",
                "openingReceiptSha256":self.opening,"samplingCommitmentSha256":self.request_commitment,
                "computationOriginal":commitment.native_computation_original().ok_or("actual computation absent")?})))
        })();
        if result.is_err(){state.policy_shadow.fail_native_observation();}
        result
    }
    pub(super) fn requires_protected_request(&self)->bool{self.details_selected && self.native_early_sampling}
    pub(super) fn completed_lifecycle(&self,dispatch:bool)->Result<Value,String> {
        let phase=self.phase.try_lock().map_err(|_|"native lifecycle observation still active")?;
        let (terminal,request,response)=match (&*phase,dispatch) {
            (Phase::Request{terminal,request},false)=>(terminal,request,None),
            (Phase::Complete{terminal,request,response},true)=>(terminal,request,Some(response)),
            _=>return Err("native lifecycle observation is unfinished or unresolved".into()),
        };
        Ok(json!({"openingReceiptSha256":self.opening,"terminalReceiptSha256":terminal,
            "candidateReceiptSha256":request,"responseReceiptSha256":response}))
    }
    pub(super) fn new(gate:Weak<GateState>,admission:&policy_shadow::PersistedIngressAdmission)->Result<Self,String> {
        let state=gate.upgrade().ok_or("native runtime has no actual serving owner")?;
        if state.measured_canary_delivery.is_none(){return Err("runtime exporter lacks selected durable owner".into());}
        let details_selected={
            let owner=state.measured_canary_delivery.as_ref().ok_or("runtime delivery owner absent")?
                .try_lock().map_err(|_|"runtime delivery owner busy")?;
            owner.check(&state)?;
            owner.authority.configuration().api_version=="catchplate.nativeCanaryDurableDelivery/v3"
        };
        Ok(Self{gate,generation:admission.generation_id().clone(),ingress:admission.ingress_sequence(),
            request_binding:admission.request_binding_sha256().clone(),request_commitment:admission.request_commitment_sha256().clone(),
            opening:admission.opening_spill_receipt().signed_receipt_sha256().clone(),phase:Mutex::new(Phase::Open),details_selected,
            native_early_sampling:admission.sampling().uses_native_early_sampling()
                && state.policy_shadow_generation_control.as_ref().ok_or("facts selector has no actual generation owner")?
                    .native_request_facts_selected()?,
            facts_attempted:std::sync::atomic::AtomicBool::new(false)})
    }
    pub(super) fn append(&self,receipt:&policy_shadow::VerifiedShadowSpillReceipt)->Result<(),String> {
        let state=self.gate.upgrade().ok_or("runtime original outlived actual serving owner")?;
        let result=(||{
            let mut phase=self.phase.try_lock().map_err(|_|"runtime original is already being exported")?;
            let (terminal,request_observation)=match &*phase {
                Phase::Open=>(None,None),Phase::Terminal(value)=>(Some(value.clone()),None),
                Phase::Request{terminal,request}=>(Some(terminal.clone()),Some(request.clone())),
                _=>return Err("runtime observation attempt cannot be renewed".into())};
            // Irreversible local attempt before any preparation/contact. An
            // unresolved protected sender head also forbids a replacement.
            *phase=Phase::Attempted;
            if receipt.generation_id()!=&self.generation || receipt.ingress_sequence()!=self.ingress
                || receipt.request_binding_sha256()!=&self.request_binding || receipt.request_commitment_sha256()!=&self.request_commitment {
                return Err("runtime receipt crossed its real opening".into());
            }
            // This is a NEW observation, not an extension of opening delivery.
            // Fix its one-shot processing bound before constructing the HTTP
            // original; keep the original signed observation time unchanged.
            let deadline=native_canary_opening::deadline(&state)?;
            let control=state.policy_shadow_generation_control.as_ref().ok_or("runtime generation owner absent")?;
            let event=match (&terminal,&request_observation) {
                (Some(terminal),Some(request))=>control.native_response_observation(receipt,&self.opening,terminal,request)?,
                _=>control.native_runtime_observation(receipt,&self.opening,terminal.as_ref())?,
            }.into_event();
            let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"runtime evidence entropy")?;
            id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;let id=hex::encode(id);
            let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
            let value=json!({"apiVersion":"catchplate.policyCanaryEvidenceOriginal/v1","requestId":request,
                "canaryId":event["record"]["canary_id"],"events":[event]});
            let raw=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&value)?;
            let batch=catchplate_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(String::from_utf8(raw).map_err(|_|"runtime ASCII")?)?;
            let complete=native_canary_delivery::submit(&state,batch,deadline)?;
            if complete.observation().status()!="consumed" {return Err("runtime original not definitely consumed".into());}
            *phase=match (terminal,request_observation) {
                (None,None)=>Phase::Terminal(receipt.signed_receipt_sha256().clone()),
                (Some(terminal),None)=>Phase::Request{terminal,request:receipt.signed_receipt_sha256().clone()},
                (Some(terminal),Some(request))=>Phase::Complete{terminal,request,response:receipt.signed_receipt_sha256().clone()},
                _=>return Err("runtime observation phase is impossible".into()),
            };
            Ok(())
        })();
        if result.is_err(){state.policy_shadow.fail_native_observation();}
        result
    }
}
