//! Actual management caller for the retained generation, not a supplied
//! generation decoder or an alias for an old Fleet load receipt.
use super::*;
use serverware_decision_gate::native_generation_origin_v1 as wire;
pub(super) struct Prepared {statement:wire::Statement}
impl Prepared{pub(super) fn statement(&self)->&wire::Statement{&self.statement}}
fn observe(state:&GateState,raw:&[u8])->Result<Value,String>{
    if !state.is_production{return Err("native generation origin requires production ownership".into());}
    native_runtime_live(state)?;
    state.native_runtime_lifetime.as_ref().ok_or("native lifetime absent")?.check()?;
    let request:wire::Request=serde_json::from_slice(raw).map_err(|_|"generation origin request invalid")?;
    if native_response_profile::canonical_ascii_bytes(&request)?.as_slice()!=raw{return Err("generation origin request original differs".into());}
    let policy=state.native_policy_bytes.as_ref().ok_or("native loaded policy original absent")?;
    let snapshot=state.snapshot.read().map_err(|_|"native loaded snapshot poisoned")?;
    if request.policy_hash!=snapshot.hash{return Err("origin policy is not actually loaded".into());}
    let control=state.policy_shadow_generation_control.as_ref().ok_or("installed generation owner absent")?;
    control.with_native_generation_origin(state,&request.assignment_payload_sha256,&request.generation_id,|originals,observed|{
        request.validate(observed)?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("native origin signer absent".into());};
        signer.transport.require_native()?;
        let prepared=Prepared{statement:wire::Statement{api_version:wire::STATEMENT.into(),request:request.clone(),originals,
            policy_original_sha256:sha256_prefixed(policy),boot_id:signer.boot_id.clone(),key_id:signer.key_id.clone(),
            control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),
            data_plane_binary_sha256:current_binary_digest()?,observed_at_epoch_ns:observed}};
        prepared.statement.validate(observed)?;
        let mut authority=state.mitm_authority.as_ref().ok_or("native identity absent")?.lock().map_err(|_|"native identity poisoned")?;
        let MitmAuthority::Native(identity)=&mut *authority else{return Err("native identity absent".into());};
        let deadline=identity.deadline();
        identity.verify_tls_scope(OffsetDateTime::now_utc(),deadline)?;
        let evidence=signer.transport.generation_origin_evidence(identity,&prepared,deadline)?;
        native_runtime_live(state)?;
        if native_response_profile::canonical_ascii_bytes(&evidence)?.len()>wire::MAX_EVIDENCE{return Err("generation origin evidence exceeds complete bound".into());}
        Ok(evidence)
    })
}
pub(super) fn handle(state:&GateState,head:RequestHead,stream:&mut DirectProxyStream){
    let deadline=Instant::now()+Duration::from_secs(30);
    stream.restrict_operation_deadline(deadline);stream.set_terminal_write_deadline(Some(deadline));
    let result=(||{
        if head.headers.get("content-type").map(String::as_str)!=Some("application/json") || !head.has_content_length
            || head.content_length==0 || head.content_length>wire::MAX_REQUEST{return Err("bounded original required".to_owned());}
        let request=read_request_body_from_head(stream,head,wire::MAX_REQUEST as u64)?;
        let value=observe(state,&request.body)?;
        if Instant::now()>=deadline{return Err("original origin deadline elapsed".into());}Ok(value)
    })();
    let (status,value)=match result{Ok(v)=>("200 OK",v),Err(_)=>("409 Conflict",json!({"error":"native_generation_origin_unavailable"}))};
    let Ok(body)=native_response_profile::canonical_ascii_bytes(&value) else{return;};
    let mut response=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",body.len()).into_bytes();
    response.extend_from_slice(&body);let _=stream.write_all(&response);let _=stream.flush();
}
