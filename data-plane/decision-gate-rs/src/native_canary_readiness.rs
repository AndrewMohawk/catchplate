//! One finalization-owned readiness request; no activation or retry authority.
use super::*;
use ring::rand::{SecureRandom,SystemRandom};
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes as ascii;

pub(crate) fn submit(state:&GateState,final_checkpoint_original:&Value,deadline:u64)->Result<(),String>{
    if native_canary_transport::boottime_ns()?>=deadline{return Err("native readiness original deadline expired".into());}
    let checkpoint=final_checkpoint_original.as_object().ok_or("native readiness final original")?;
    if checkpoint.get("apiVersion")!=Some(&json!("serverware.nativeCumulativeCheckpoint/v2"))
        || checkpoint.get("seal").is_none_or(Value::is_null){
        return Err("native readiness requires a real sealed final checkpoint".into());
    }
    let record={
        let owner=state.measured_canary_delivery.as_ref().ok_or("native readiness delivery absent")?
            .try_lock().map_err(|_|"native readiness delivery busy")?;
        owner.check(state)?;
        if !owner.initialized{return Err("native readiness delivery not initialized".into());}
        let canary=final_checkpoint_original["canary_id"].as_str().ok_or("native readiness canary")?;
        let binding=owner.authority.binding(canary)?;
        if final_checkpoint_original["instance_id"]!=owner.authority.configuration().instance_id
            || final_checkpoint_original["boot_id"]!=binding.canary_boot_id
            || final_checkpoint_original["assignment_envelope_digest"]!=binding.canary_assignment_sha256{
            return Err("native readiness final original crossed its actual cold owner".into());
        }
        let policy=owner.authority.native_readiness_policy()?;
        if !policy["canaries"].as_array().ok_or("native readiness policy inventory")?.iter().any(|item|
            item["canaryId"]==canary && item["assignmentSha256"]==binding.canary_assignment_sha256){
            return Err("native readiness canary has no independent derivation permission".into());
        }
        json!({"apiVersion":"serverware.nativePolicyReadinessRequest/v1",
            "canary_id":canary,"instance_id":final_checkpoint_original["instance_id"],"boot_id":final_checkpoint_original["boot_id"],
            "assignment_envelope_digest":final_checkpoint_original["assignment_envelope_digest"],
            "assignment_payload_digest":final_checkpoint_original["assignment_payload_digest"],
            "final_checkpoint_sha256":sha256_prefixed(&ascii(final_checkpoint_original)?),"readiness_policy":policy})
    };
    if ascii(&record)?.len()>16384{return Err("native readiness complete request exceeds fixed bound".into());}
    let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"native readiness entropy")?;
    id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;let id=hex::encode(id);
    let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
    let batch=json!({"apiVersion":"serverware.policyCanaryEvidenceOriginal/v1","requestId":request,
        "canaryId":record["canary_id"],"events":[{"kind":"readiness","record":record}]});
    let original=serverware_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(
        String::from_utf8(ascii(&batch)?).map_err(|_|"native readiness ASCII")?)?;
    // Existing retained prepare/claim/send/capture/recover owner. The finalizer
    // marks its chain terminal BEFORE this call; even a missing ACK cannot
    // create a second finalization/readiness attempt or a fresh time window.
    let completion=native_canary_delivery::submit(state,original,deadline)?;
    if completion.observation().status()!="consumed"{return Err("native readiness outcome unresolved; no retry".into());}
    // Consumption means only that the kernel stored its derived result. It is
    // never a Fleet READY envelope, human approval, publication or promotion.
    native_canary_delivery::retain_readiness(state,&record,completion)
}
