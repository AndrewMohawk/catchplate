//! The actual request capture caller of the retained native durable sender.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};

/// Fixed once before custody admission, clipped by the original native lifetime
/// and delivery policy later. A failed/unknown attempt never obtains a new one.
pub(super) fn deadline(state:&GateState)->Result<u64,String> {
    let now=native_canary_transport::boottime_ns()?;
    let remaining=native_service_remaining(state)?.ok_or("native opening has no retained service lifetime")?;
    let budget=u64::try_from(remaining.as_nanos()).map_err(|_|"opening lifetime overflow")?.min(30_000_000_000);
    if budget==0 {return Err("native opening lifetime elapsed".into());}
    now.checked_add(budget).ok_or_else(||"opening deadline overflow".into())
}
pub(super) fn submit(state:&GateState,admission:&policy_shadow::PersistedIngressAdmission,deadline:u64)->Result<(),String> {
    if native_canary_transport::boottime_ns()?>=deadline {return Err("opening original deadline elapsed".into());}
    let control=state.policy_shadow_generation_control.as_ref().ok_or("opening has no installed generation owner")?;
    let opening=control.native_opening(admission)?;
    let record=opening.into_record();
    let canary=record["canary_id"].as_str().ok_or("opening canary missing")?.to_owned();
    let mut id=[0u8;16];SystemRandom::new().fill(&mut id).map_err(|_|"opening request entropy")?;
    id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;
    let id=hex::encode(id);
    let request=format!("{}-{}-{}-{}-{}",&id[..8],&id[8..12],&id[12..16],&id[16..20],&id[20..]);
    let value=json!({"apiVersion":"serverware.policyCanaryEvidenceOriginal/v1","requestId":request,
        "canaryId":canary,"events":[{"kind":"custody","record":record}]});
    let raw=serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&value)?;
    let batch=serverware_decision_gate::native_canary_evidence_v1::BatchOriginal::parse(
        String::from_utf8(raw).map_err(|_|"opening ASCII original")?)?;
    let complete=native_canary_delivery::submit(state,batch,deadline)?;
    if complete.observation().status()!="consumed" {return Err("opening has no authenticated consumed completion".into());}
    Ok(())
}
