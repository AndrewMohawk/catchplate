//! Fixed Setup hardware challenge from the actual live gate and role-4 owners.
use super::*;
use serverware_decision_gate::native_setup_hardware_v1 as wire;

// Only this actual GateState path may prepare the binary's signing call.
pub(super) struct Prepared { statement:wire::Statement }
impl Prepared { pub(super) fn statement(&self)->&wire::Statement { &self.statement } }
fn now()->Result<u64,String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"Setup hardware clock before epoch")?
        .as_nanos().try_into().map_err(|_|"Setup hardware clock overflow".into())
}

fn observe(state:&GateState, raw:&[u8])->Result<Value,String> {
    if !state.is_production {return Err("Setup hardware observation requires production native ownership".into());}
    let lifetime=state.native_runtime_lifetime.as_ref().ok_or("native serving lifetime absent")?;
    lifetime.check()?;
    native_runtime_live(state)?;
    let started=now()?;
    let request:wire::Attempt=serde_json::from_slice(raw).map_err(|_|"Setup hardware request invalid")?;
    request.validate(started)?;
    if native_response_profile::canonical_ascii_bytes(&request)?.as_slice()!=raw {
        return Err("Setup hardware request must retain exact canonical originals".into());
    }
    let original=state.native_policy_bytes.as_ref().ok_or("native immutable policy owner absent")?;
    // Hold the same read guard through quotation. This cannot admit a supplied
    // snapshot, hot reload a file, or substitute a shadow candidate generation.
    let snapshot=state.snapshot.read().map_err(|_|"native policy owner poisoned")?;
    if snapshot.hash!=request.policy_hash {return Err("requested policy is not actually loaded".into());}
    let bundle:Value=serde_json::from_slice(original).map_err(|_|"retained native policy is invalid")?;
    let routes=bundle.get("routes").and_then(Value::as_array).ok_or("retained routes absent")?;
    let selected:Vec<_>=routes.iter().filter(|row|row.get("id").and_then(Value::as_str)==Some(request.route_id.as_str())).collect();
    let principals=bundle.get("principals").and_then(Value::as_array).ok_or("retained principals absent")?;
    if selected.len()!=1 || principals.iter().filter(|row|row.get("id").and_then(Value::as_str)==Some(request.principal_id.as_str())).count()!=1
        || !snapshot.principals.iter().any(|row|row.id==request.principal_id) {
        return Err("native policy lacks exact principal/route association".into());
    }
    let route=selected[0];
    if route.get("credentialRef").and_then(Value::as_str)!=Some(request.credential_id.as_str())
        || !route.get("principals").and_then(Value::as_array).is_some_and(|rows|rows.iter().any(|row|
            row.as_str()==Some(request.principal_id.as_str()) || row.as_str()==Some("*"))) {
        return Err("native policy credential/route association differs".into());
    }
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else {
        return Err("native loaded observation requires actual custody".into());
    };
    signer.transport.require_native()?;
    let prepared=Prepared {statement:wire::Statement {api_version:wire::STATEMENT.into(),attempt:request,
        policy_original_sha256:sha256_prefixed(original),
        route_policy_digest:sha256_prefixed(&native_response_profile::canonical_ascii_bytes(route)?),
        boot_id:signer.boot_id.clone(),key_id:signer.key_id.clone(),
        control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),
        data_plane_binary_sha256:current_binary_digest()?,observed_at_epoch_ns:now()?}};
    let mut authority=state.mitm_authority.as_ref().ok_or("native identity absent")?
        .lock().map_err(|_|"native identity owner poisoned")?;
    let MitmAuthority::Native(identity)=&mut *authority else {return Err("native identity absent".into());};
    let deadline=identity.deadline(); // unchanged original absolute native lifetime
    prepared.statement.validate(now()?)?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(),deadline)?;
    let evidence=signer.transport.setup_hardware_evidence(identity,&prepared,deadline)?;
    prepared.statement.validate(now()?)?;
    native_runtime_live(state)?;
    if native_response_profile::canonical_ascii_bytes(&evidence)?.len()>wire::MAX_EVIDENCE {
        return Err("Setup hardware evidence exceeds fixed bound".into());
    }
    Ok(evidence)
}

pub(super) fn handle(state:&GateState, head:RequestHead, stream:&mut DirectProxyStream) {
    // Caller already owns the management listener and authenticates its fixed
    // service token. No workload listener or response-proxy path reaches here.
    let operation=Instant::now()+Duration::from_secs(30);
    stream.restrict_operation_deadline(operation);
    stream.set_terminal_write_deadline(Some(operation));
    let result=(|| {
        if head.headers.get("content-type").map(String::as_str)!=Some("application/json")
            || !head.has_content_length || head.content_length==0 || head.content_length>wire::MAX_REQUEST {
            return Err("native observation requires bounded canonical JSON".to_owned());
        }
        let request=read_request_body_from_head(stream,head,wire::MAX_REQUEST as u64)?;
        let evidence=observe(state,request.body.as_slice())?;
        if Instant::now()>=operation {return Err("original management observation deadline expired".into());}
        Ok(evidence)
    })();
    let (status,value)=match result {Ok(value)=>("200 OK",value),
        Err(_)=>("409 Conflict",json!({"error":"native_setup_hardware_unavailable"}))};
    let Ok(body)=native_response_profile::canonical_ascii_bytes(&value) else {return;};
    let mut response=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",body.len()).into_bytes();
    response.extend_from_slice(&body);
    let _=stream.write_all(&response); let _=stream.flush();
}
