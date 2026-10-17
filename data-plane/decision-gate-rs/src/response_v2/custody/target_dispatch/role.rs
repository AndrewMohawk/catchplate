//! Actual CredentialTransport operations. The zero-key router never signs a
//! permit, persistence receipt or target-effect observation on their behalf.
use super::*;
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use super::super::attestation::RoleSigningKey;
use super::super::config::ScopedCustodyServiceConfig;
use super::super::protocol::{self,AttemptStateQueryRequestV1,UnsignedStateAuthorityIntentV1};
use super::super::services::{self,engine};
use crate::response_observation_v2_api::{V2ResponseDataRequest as Request,V2ResponseDataResult as ResultValue};

fn current(config:&Config,deadline:u64)->Result<(),V2RuntimeError> {
    selected(config,deadline)?;
    config.ledger_raw_persistence.as_ref().ok_or_else(||fail("durable capture persistence is not separately admitted"))?
        .validate(config)?;
    Ok(())
}
fn key<'a>(keys:&'a BTreeMap<String,RoleSigningKey>)->Result<&'a RoleSigningKey,V2RuntimeError> {
    keys.get("target-transport").filter(|key|key.logical_role()=="target-transport")
        .ok_or_else(||fail("actual target-transport role key unavailable"))
}
fn query(config:&Config,original:&DispatchOriginal,revision:u64,state:lifecycle::AttemptState,
    dispatch:Option<String>,suffix:&str,deadline:u64)->Result<protocol::SignedStagedOriginalV1,V2RuntimeError> {
    services::query_staged_original(config,&protocol::StagedOriginalQueryV1 {
        api_version:protocol::STAGED_ORIGINAL_QUERY_API_VERSION.to_owned(),generation_id:original.generation_id.clone(),
        generation:original.generation,request_id:format!("{}:{suffix}",begin_operation_id(original)?),
        operation_id:format!("{}:{suffix}",begin_operation_id(original)?),attempt_id:original.binding.attempt_id.clone(),
        expected_stable_resume_id:original.stable_resume_id.clone(),expected_revision:revision,
        expected_fencing_token:original.binding.fencing_token,expected_state:state,
        expected_dispatch_request_sha256:dispatch,deadline_boottime_ns:deadline})
}
fn stage_binding(config:&Config,original:&DispatchOriginal,witness:&protocol::SignedStagedOriginalV1)->Result<(),V2RuntimeError> {
    let rpc::MutationPayload::Reserve(reserve)=&witness.body.reserve.frame.request.payload
        else{return Err(fail("staged witness lacks actual Reserve original"));};
    let rpc::MutationPayload::Stage(stage)=&witness.body.stage.frame.request.payload
        else{return Err(fail("staged witness lacks actual Stage original"));};
    let binding=&original.binding;
    if witness.body.attempt_id!=binding.attempt_id || witness.body.stable_resume_id!=original.stable_resume_id
        || witness.body.fencing_token!=binding.fencing_token
        || witness.body.original_deadline.clock!="CLOCK_BOOTTIME"
        || witness.body.original_deadline.boot_id.0!=selected(config,original_deadline(original)?)?.assignment.kernel_boot_id
        || witness.body.original_deadline.deadline_boot_millis.checked_mul(1_000_000)!=Some(original_deadline(original)?)
        || reserve.request_sha256.0!=binding.transaction.client_request_sha256
        || reserve.route_sha256.0!=binding.transaction.route_semantics_sha256
        || Some(reserve.credential_scope_sha256.0.as_str())!=binding.transaction.credential_binding_sha256.as_deref()
        || !same(&stage.staged_request_object,&original.staged_request)?
        || original.staged_request.object_kind.0!="staged-request"
        || Some(stage.credential_binding_sha256.0.as_str())!=binding.transaction.credential_binding_sha256.as_deref() {
        return Err(fail("native gate request differs from actual reserved/staged authority originals"));
    }
    Ok(())
}
fn observe(config:&Config,original:&DispatchOriginal,operation:&str,deadline:u64)
    ->Result<protocol::SignedAttemptStateObservationV1,V2RuntimeError> {
    services::query_attempt_state(config,&AttemptStateQueryRequestV1 {
        api_version:protocol::ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),generation_id:original.generation_id.clone(),
        generation:original.generation,request_id:format!("{operation}:observed"),operation_id:operation.to_owned(),
        attempt_id:original.binding.attempt_id.clone(),expected_stable_resume_id:original.stable_resume_id.clone(),
        raw_response_object_id:None,include_proof_material:false,deadline_boottime_ns:deadline})
}

pub(crate) fn execute(config:&Config,scoped:&ScopedCustodyServiceConfig,request:&Request,
    keys:&BTreeMap<String,RoleSigningKey>,mut files:Vec<OwnedFd>)->Result<ResultValue,V2RuntimeError> {
    if scoped.role!=CustodyServiceRole::CredentialTransport {return Err(fail("wrong actual dispatch service owner"));}
    let deadline=request.deadline().0.absolute_boottime_ns.parse::<u64>().map_err(|_|fail("invalid original dispatch deadline"))?;
    current(config,deadline)?;
    match request {
        Request::TargetDispatchBegin {request_id,params,..} if files.is_empty()=>{
            if params.api_version!="catchplate.responseV2.targetDispatchBegin/v1" || params.gate_evidence.statement.phase!="prepare"
                || request_id!=&params.original.binding.request_id || !same(&params.original,&params.gate_evidence.statement.original)? {
                return Err(fail("prepare does not bind actual original request"));
            }
            native::verify(selected(config,deadline)?,&params.gate_evidence,now_ns()?).map_err(fail)?;
            let original=&params.original;
            let before=query(config,original,original.binding.attempt_revision,lifecycle::AttemptState::Staged,None,"before",deadline)?;
            stage_binding(config,original,&before)?;
            let operation=begin_operation_id(original)?;
            let digest=original_sha256(original)?;
            let signer=key(keys)?;
            let credential_signer=keys.get("credential-authority").filter(|key|key.logical_role()=="credential-authority")
                .ok_or_else(||fail("actual credential-authority role key unavailable"))?;
            let artifact=engine::sign_nested_artifact(config,CustodyServiceRole::CredentialTransport,credential_signer,
                lifecycle::OperationKind::DispatchBegin,&operation,&original.binding.attempt_id,
                original.binding.attempt_revision,original.binding.fencing_token,original.binding.deadline_at_epoch_ms,
                rpc::NestedAuthorityPayload::CredentialUse(rpc::CredentialUseArtifact {
                    credential_use_id:contract::Identifier(format!("credential-use:{}",&digest[7..])),
                    credential_binding_sha256:contract::Digest(original.binding.transaction.credential_binding_sha256.clone()
                        .ok_or_else(||fail("actual credential binding absent"))?),
                    target_effect_id:contract::Identifier(format!("effect:{}",&digest[7..])),
                    one_use_nonce_sha256:contract::Digest(digest)}),None,deadline)?;
            let expected=begin_request(config,original,&artifact)?;
            let frame=engine::signed_state_authority_frame(config,scoped,&expected.request_id.0,&expected.operation_id.0,
                &expected.attempt_id.0,expected.expected_revision,original.binding.fencing_token,deadline,
                &UnsignedStateAuthorityIntentV1 {expected_state:expected.expected_state,payload:expected.payload.clone()},keys)?;
            if !same(&frame.request,&expected)? {return Err(fail("actual signed DispatchBegin differs from retained intent"));}
            current(config,deadline)?;
            let mutation=engine::state_execution_request(request_id,&operation,&original.binding.attempt_id,&original.stable_resume_id,
                original.binding.attempt_revision,original.binding.fencing_token,deadline,frame.clone());
            let (execution,fd)=services::execute_state_mutation(config,&mutation,false)?;
            if fd.is_some() || execution.exact_object.is_some() || execution.response_data_result.is_some() {
                return Err(fail("DispatchBegin unexpectedly returned an object or alternate result"));
            }
            let frame_sha=canonical::sha256_digest(&canonical::canonical_jcs_bytes(&frame).map_err(|e|fail(e.to_string()))?).0;
            let after=query(config,original,original.binding.attempt_revision.checked_add(1).ok_or_else(||fail("revision overflow"))?,
                lifecycle::AttemptState::Dispatching,Some(frame_sha.clone()),"after",deadline)?;
            stage_binding(config,original,&after)?;
            let actual=after.body.dispatch.as_ref().ok_or_else(||fail("state authority omitted actual committed DispatchBegin"))?;
            if actual.exact_request_sha256!=frame_sha || !same(&actual.frame,&frame)? {
                return Err(fail("state authority retained a different DispatchBegin original"));
            }
            let post=observe(config,original,&operation,deadline)?;
            let mut permit=SignedTargetDispatchPermit {api_version:wire::PERMIT.to_owned(),original:original.clone(),
                credential_use:artifact,dispatch_request:frame,dispatch_receipt:execution.receipt,post_state:post,
                public_key_base64:signer.public_key_base64(),signature:String::new()};
            permit.signature=signer.sign(wire::PERMIT_DOMAIN,&permit.unsigned())?;
            verify_permit(config,&permit,deadline)?;
            current(config,deadline)?;
            Ok(ResultValue::TargetDispatchBegin(permit))
        },
        Request::CapturePersist {params,..} if files.len()==1=>{
            let file=File::from(files.remove(0));
            let capture=verify_capture(config,params,file.try_clone().map_err(|_|fail("retain actual raw original"))?,deadline)?;
            let original=&params.permit.original;
            let frame_sha=canonical::sha256_digest(&canonical::canonical_jcs_bytes(&params.permit.dispatch_request)
                .map_err(|e|fail(e.to_string()))?).0;
            let current_dispatch=query(config,original,params.permit.post_state.attempt_revision,lifecycle::AttemptState::Dispatching,
                Some(frame_sha),"persist",deadline)?;
            stage_binding(config,original,&current_dispatch)?;
            capture.check()?;
            // The actual ledger re-verifies the same owner before writing its
            // private CAS; no router key and no parent flat-store substitute.
            let persisted=services::ledger_put::put(config,params,file,deadline)?;
            capture.check()?;
            let operation=format!("observed:{}",&capture.capture_sha256()[7..]);
            let signer=key(keys)?;
            let digest=original_sha256(original)?;
            let target=engine::sign_nested_artifact(config,CustodyServiceRole::CredentialTransport,signer,
                lifecycle::OperationKind::DispatchRecordOutcome,&format!("target-artifact:{}",&capture.capture_sha256()[7..]),
                capture.attempt_id(),persisted.post_state.attempt_revision,capture.fencing_token(),capture.expires_at_epoch_ms(),
                rpc::NestedAuthorityPayload::TargetEffect(rpc::TargetEffectArtifact {
                    target_effect_id:contract::Identifier(format!("effect:{}",&digest[7..])),
                    idempotency_key_sha256:contract::Digest(digest),request_object_sha256:original.staged_request.content_sha256.clone(),
                    response_object_sha256:Some(contract::Digest(capture.descriptor().sha256.clone())),
                    outcome:lifecycle::TargetEffectState::Observed}),None,deadline)?;
            let raw=rpc::RawObjectReference {generation_id:contract::Identifier(capture.generation_id().to_owned()),
                object_id:contract::Identifier(capture.descriptor().object_id.clone()),object_kind:contract::Identifier("raw-response".into()),
                content_sha256:contract::Digest(capture.descriptor().sha256.clone()),content_length:capture.descriptor().byte_length,
                media_type:"http11-response".into()};
            let intent=UnsignedStateAuthorityIntentV1 {expected_state:lifecycle::AttemptState::Dispatching,
                payload:rpc::MutationPayload::RecordDispatchOutcome(rpc::RecordDispatchOutcomeMutation {
                    target_effect_id:contract::Identifier(format!("effect:{}",&original_sha256(original)?[7..])),
                    outcome:lifecycle::TargetEffectState::Observed,response_object:Some(raw),uncertainty_code:None,
                    transport_evidence:target.clone()})};
            let frame=engine::signed_state_authority_frame(config,scoped,&operation,&operation,capture.attempt_id(),
                persisted.post_state.attempt_revision,capture.fencing_token(),deadline,&intent,keys)?;
            let mutation=engine::state_execution_request(&operation,&operation,capture.attempt_id(),capture.stable_resume_id(),
                persisted.post_state.attempt_revision,capture.fencing_token(),deadline,frame.clone());
            capture.check()?;
            let (execution,fd)=services::execute_state_mutation(config,&mutation,false)?;
            let expected=canonical::sha256_digest(&canonical::canonical_jcs_bytes(&frame).map_err(|e|fail(e.to_string()))?).0;
            let receipt=&execution.receipt;
            let next=persisted.post_state.attempt_revision.checked_add(1).ok_or_else(||fail("outcome revision overflow"))?;
            if fd.is_some() || execution.exact_object.is_some() || receipt.exact_request_sha256!=expected
                || receipt.disposition!="APPLIED" || receipt.authoritative_state!="OBSERVED" || receipt.authoritative_revision!=next
                || receipt.fencing_token!=capture.fencing_token() || receipt.attempt_id!=capture.attempt_id()
                || receipt.operation_id!=operation || receipt.request_id!=operation || receipt.stable_resume_id!=capture.stable_resume_id() {
                return Err(fail("actual raw outcome commit did not bind its durable successor revision"));
            }
            let post=observe(config,original,&operation,deadline)?;
            if post.attempt_revision!=next || post.authoritative_state!=lifecycle::AttemptState::Observed
                || post.fencing_token!=capture.fencing_token() {return Err(fail("actual observed successor differs"));}
            capture.check()?;
            Ok(ResultValue::CapturePersist(wire::CompletedCapture {api_version:"catchplate.responseV2.targetCaptureCommitted/v1".into(),
                capture_sha256:capture.capture_sha256().to_owned(),object:persisted.object,outcome_request:frame,
                outcome_receipt:execution.receipt,post_state:post,target_effect:target}))
        },
        _=>Err(fail("target dispatch request or exact descriptor count differs")),
    }
}
