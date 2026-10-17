//! Actual StateAuthority public staging orchestrator. Definite claim precedes
//! each one-shot role call; every terminal contains actual committed originals.
use super::*;
use std::{collections::BTreeMap,fs::File,io::Write,os::fd::{FromRawFd,OwnedFd,AsRawFd}};
use super::super::{engine,invoke_service_wire};
use super::super::super::{staging::{self,wire,inputs::Inputs,verification},protocol::UnsignedStateAuthorityIntentV1};
use super::super::super::super::state_authority::{canonical::{canonical_jcs_bytes,sha256_digest},
    lifecycle::{AttemptState,OperationKind},postgres::store::{CommittedRequestOriginalV1,NativeStagingClaimResult},
    rpc::{self,MutationPayload,NestedAuthorityPayload,RpcRequestFrame}};
use crate::response_observation_v2_api::*;
fn fail(reason:impl Into<String>)->V2RuntimeError{staging::fail(reason)}
fn native_wire(value:&staging::VerifiedRequest)->Result<wire::StagingRequest,V2RuntimeError>{
    serde_json::from_slice(value.exact_request()).map_err(|_|fail("retained native envelope shape"))
}
fn original(frame:RpcRequestFrame,bytes:ExactSignedResultBytes)->Result<CommittedRequestOriginalV1,V2RuntimeError>{
    let result:rpc::SignedOperationResult=serde_json::from_slice(&bytes.canonical_bytes).map_err(|_|fail("actual state result shape"))?;
    let exact_request_sha256=sha256_digest(&canonical_jcs_bytes(&frame).map_err(authority_error)?).0;
    let exact_result_sha256=sha256_digest(&bytes.canonical_bytes).0;
    if canonical_jcs_bytes(&result).map_err(authority_error)?!=bytes.canonical_bytes
        ||result.body.disposition!=rpc::ResultDisposition::Applied||result.body.exact_request_sha256.0!=exact_request_sha256
        ||result.body.conflict_code.is_some(){return Err(fail("state mutation has no exact positive committed result"));}
    Ok(CommittedRequestOriginalV1{frame,exact_request_sha256,result,exact_result_sha256})
}
fn seal(raw:&[u8])->Result<File,V2RuntimeError>{
    let fd=unsafe{libc::memfd_create(c"native-staging-metadata".as_ptr(),libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)};
    if fd<0{return Err(fail("create retained metadata descriptor"));}
    let mut file=unsafe{File::from_raw_fd(fd)};
    file.write_all(raw).map_err(|_|fail("write retained metadata descriptor"))?;
    if unsafe{libc::fcntl(file.as_raw_fd(),libc::F_ADD_SEALS,libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL)}<0{
        return Err(fail("seal retained metadata descriptor"));}
    Ok(file)
}
fn signed_claim(config:&RootOwnedResponseObservationV2Config,key:&RoleSigningKey,value:&staging::VerifiedRequest)
    ->Result<wire::SignedClaim,V2RuntimeError>{
    let binding=value.binding();let scope=provider_authority_scope(config.custody_topology(),CustodyServiceRole::StateAuthority,
        key,ServiceOperationV1::StateCas,&format!("staging-claim:{}",&value.original_sha256()[7..]),
        &binding.attempt_id,binding.attempt_revision,binding.fencing_token)?;
    let mut result=wire::SignedClaim{api_version:wire::CLAIM.into(),generation_id:value.original().generation_id.clone(),
        generation:value.original().generation,original_sha256:value.original_sha256().into(),session_sha256:value.original().session_sha256.clone(),
        phase:value.phase().into(),predecessor_result_sha256:value.original().predecessor_result_sha256.clone()
            .ok_or_else(||fail("role action requires a real predecessor"))?,authority_scope:scope,
        signer_logical_role:key.logical_role().into(),signer_key_id:key.key_id().into(),signature:String::new()};
    result.signature=key.sign(wire::CLAIM_DOMAIN,&result.unsigned())?;Ok(result)
}

pub(in super::super::super) fn execute(config:&RootOwnedResponseObservationV2Config,
    scoped:&super::super::super::config::ScopedCustodyServiceConfig,envelope:&super::super::super::protocol::ServiceRpcEnvelopeV1,
    keys:&BTreeMap<String,RoleSigningKey>,fds:Vec<OwnedFd>)->Result<engine::EngineResult,V2RuntimeError>{
    if scoped.role!=CustodyServiceRole::StateAuthority||envelope.operation!=ServiceOperationV1::StateCas{
        return Err(fail("public staging must execute on actual StateAuthority"));}
    let request:wire::StagingRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("closed native staging request"))?;
    let value=staging::admit(config,request)?;
    if envelope.request_id!=value.binding().request_id||envelope.deadline_boottime_ns!=value.deadline().deadline_boot_millis*1_000_000{
        return Err(fail("public staging transport changed the original request/deadline"));}
    let inputs=Inputs::admit(config,&value,fds.into_iter().map(File::from).collect())?;
    let key=keys.get("linearizable-store").ok_or_else(||fail("actual state signing owner absent"))?;
    let authority=trusted_query_authority(config,key)?;
    let claimed=authority.claim_native_staging(&value,&inputs).map_err(authority_error)?;
    let claim=match claimed{
        NativeStagingClaimResult::Replay(bytes)=>{
            let result:wire::SignedStagingResult=serde_json::from_slice(&bytes).map_err(|_|fail("retained public terminal shape"))?;
            verification::result(config,&result)?;value.check(config)?;
            return Ok(engine::EngineResult{result:serde_json::to_value(result).map_err(|_|fail("terminal encoding"))?,exact_object_fds:Vec::new()});
        },NativeStagingClaimResult::Claimed(claim)=>claim,
    };
    // From this point any error leaves a consumed durable claim. No retries,
    // replacement signatures or reconstructed missing results are attempted.
    let binding=value.binding();let operation_id=format!("staging-{}:{}",value.phase().to_ascii_lowercase(),&value.original_sha256()[7..]);
    let mut selected_object=None;
    let state_originals=match &value.original().request{
        V2OperationRequest::Reserve{..}=>{
            let tx=&binding.transaction;let owner=&value.original().owner;
            let intent=UnsignedStateAuthorityIntentV1{expected_state:AttemptState::Absent,
                payload:MutationPayload::Reserve(rpc::ReserveMutation{
                    stable_resume_id:Identifier(response_observation_v2_stable_resume_id_sha256(&value.original().generation_id,
                        value.original().generation,&tx.client_request_sha256,&binding.attempt_id)),
                    owner_process_id:Identifier(owner.process_id.clone()),owner_pid:owner.pid,owner_start_time_ticks:owner.start_time_ticks,
                    owner_cgroup_id:Identifier(owner.cgroup_id.clone()),attempt_deadline:value.deadline().clone(),
                    request_sha256:Digest(tx.client_request_sha256.clone()),route_sha256:Digest(tx.route_semantics_sha256.clone()),
                    credential_scope_sha256:Digest(tx.credential_binding_sha256.clone().ok_or_else(||fail("credential scope absent"))?),})};
            let frame=engine::signed_native_staging_frame(config,scoped,&value,&operation_id,0,&intent,keys)?;
            value.check(config)?;let exact=authority.execute_sequence_mutation(&frame).map_err(authority_error)?;
            vec![original(frame,exact)?]
        },
        V2OperationRequest::Authority{params,..}=>{
            let prior=claim.previous().ok_or_else(||fail("actual Reserve terminal absent"))?.clone();
            let prior_request=claim.previous_request().ok_or_else(||fail("actual Reserve native original absent"))?.clone();
            let V2OperationResult::Reserve(V2ReserveResult::Reserved{reservation_evidence,..})=&prior.body.result else{return Err(fail("required Reserved public terminal absent"));};
            if &params.reservation_evidence!=reservation_evidence{return Err(fail("Authorize selected a different reservation evidence"));}
            let originals=staging::inputs::retained_metadata(&prior_request,claim.previous_inputs().ok_or_else(||fail("actual Reserve inputs absent"))?)?;
            let mut files=originals.iter().map(|raw|seal(raw)).collect::<Result<Vec<_>,_>>()?;
            files.push(inputs.clone_file(0)?);files.push(inputs.clone_file(1)?);
            let policy=wire::PolicyRequest{api_version:"catchplate.responseV2.nativeStagingPolicy/v1".into(),
                claim:signed_claim(config,key,&value)?,request:native_wire(&value)?,reserve_request:prior_request,reserve_result:prior};
            value.check(config)?;
            let (reply,extra)=invoke_service_wire(config,CustodyServiceRole::PolicyProofVerifier,ServiceOperationV1::TransitionAuthorize,
                &binding.request_id,&policy,envelope.deadline_boottime_ns,&files,false)?;
            if !extra.is_empty(){return Err(fail("policy artifact response carried unexpected descriptors"));}
            let artifact=staging::policy::decode_artifact(reply.result)?;
            engine::verify_pinned_authority_artifact(config.custody_topology(),&artifact,&binding.attempt_id,binding.fencing_token)?;
            let NestedAuthorityPayload::TransitionAuthorization(transition)=&artifact.body.payload else{return Err(fail("policy returned another artifact purpose"));};
            if artifact.body.operation!=OperationKind::AttemptAuthorize||artifact.body.attempt_revision!=binding.attempt_revision
                ||transition.policy_generation_sha256.0!=binding.transaction.policy_sha256||!transition.passed{
                return Err(fail("actual policy artifact does not authorize the required transition"));}
            let intent=UnsignedStateAuthorityIntentV1{expected_state:AttemptState::Reserved,payload:MutationPayload::Authorize(rpc::AuthorizeMutation{
                policy_decision_id:transition.policy_decision_id.clone(),policy_generation_sha256:transition.policy_generation_sha256.clone(),
                authorization_artifacts:vec![artifact]})};
            let frame=engine::signed_native_staging_frame(config,scoped,&value,&operation_id,binding.attempt_revision,&intent,keys)?;
            inputs.check(config,&value)?;let exact=authority.execute_sequence_mutation(&frame).map_err(authority_error)?;
            vec![original(frame,exact)?]
        },
        V2OperationRequest::Stage{params,..}=>{
            let prior=claim.previous().ok_or_else(||fail("actual Authorize terminal absent"))?.clone();
            let V2OperationResult::Authority(V2AuthorityResult::Ready{authority_state,..})=&prior.body.result else{return Err(fail("required Authorized public terminal absent"));};
            if &params.authority_state!=authority_state{return Err(fail("Stage selected another authority state"));}
            let template:serde_json::Value=serde_json::from_slice(inputs.bytes(0)?).map_err(|_|fail("credential template shape"))?;
            let credential=params.credential_reference.as_ref().ok_or_else(||fail("actual credential reference missing"))?;
            let injection=template.get("injectionPlan").ok_or_else(||fail("actual injection template missing"))?;
            let commitment=serde_json::json!({"credentialId":credential.credential_id,"credentialGeneration":credential.credential_generation,
                "injectionPlanSha256":crate::native_staging_v1::sha256(&crate::canonical_json_bytes(injection).map_err(|_|fail("injection canonical original"))?)});
            let digest=crate::native_staging_v1::sha256(&crate::canonical_json_bytes(&commitment).map_err(|_|fail("credential commitment encoding"))?);
            if crate::canonical_json_bytes(&template).map_err(|_|fail("template encoding"))?!=inputs.bytes(0)?
                ||template.get("apiVersion").and_then(|v|v.as_str())!=Some("catchplate.responseObservationV2CredentialTemplate/v1")
                ||template.get("credentialRequired").and_then(|v|v.as_bool())!=Some(true)
                ||template.get("credentialBindingSha256").and_then(|v|v.as_str())!=Some(digest.as_str())
                ||binding.transaction.credential_binding_sha256.as_deref()!=Some(digest.as_str())||credential.credential_binding_sha256!=digest{
                return Err(fail("Stage template does not bind the exact reserved credential and injection plan"));}
            let put=wire::StagedPutRequest{api_version:"catchplate.responseV2.nativeStagedPut/v1".into(),claim:signed_claim(config,key,&value)?,
                request:native_wire(&value)?,authority_result:prior.clone()};
            let published=staging::ledger::put(config,&put,inputs.clone_file(1)?)?;
            value.check(config)?;
            let persisted=original(published.state_request.clone(),authority.execute_sequence_mutation(&published.state_request).map_err(authority_error)?)?;
            let authorize=prior.body.state_originals.first().ok_or_else(||fail("exact Authorize original missing"))?;
            let MutationPayload::Authorize(authorize_payload)=&authorize.frame.request.payload else{return Err(fail("exact Authorize payload missing"));};
            let staged=rpc::RawObjectReference{generation_id:Identifier(value.original().generation_id.clone()),
                object_id:Identifier(published.object.retrieval_id.clone()),object_kind:Identifier("staged-request".into()),
                content_sha256:Digest(published.object.object_sha256.clone()),content_length:published.object.byte_length,
                media_type:"http11-request".into()};
            let intent=UnsignedStateAuthorityIntentV1{expected_state:AttemptState::Authorized,payload:MutationPayload::Stage(rpc::StageMutation{
                staged_request_object:staged,credential_binding_sha256:Digest(digest),transition_artifacts:authorize_payload.authorization_artifacts.clone()})};
            let frame=engine::signed_native_staging_frame(config,scoped,&value,&operation_id,persisted.result.body.authoritative_revision,&intent,keys)?;
            inputs.check(config,&value)?;
            let exact=authority.execute_native_staging_stage(&value,&frame,authorize,&persisted).map_err(authority_error)?;
            selected_object=Some(published.object);vec![persisted,original(frame,exact)?]
        },_=>return Err(fail("unadmitted public staging phase")),
    };
    let terminal=state_originals.last().ok_or_else(||fail("actual terminal original missing"))?;
    let last=&terminal.result.body;
    let fence=last.fence_token.0.parse::<u64>().map_err(|_|fail("actual sequence fence shape"))?;
    let evidence_digest=sha256_digest(&canonical_jcs_bytes(&state_originals).map_err(authority_error)?).0;
    let evidence_type=match value.phase(){"RESERVE"=>V2EvidenceType::Reservation,"AUTHORIZE"=>V2EvidenceType::AuthorityState,_=>V2EvidenceType::Staging};
    let evidence=EvidenceReference{evidence_type,evidence_sha256:evidence_digest.clone(),retrieval_id:operation_id.clone()};
    let mut attempt=AttemptStateReference{attempt_id:binding.attempt_id.clone(),state:match value.phase(){"RESERVE"=>V2AttemptState::Reserved,
        "AUTHORIZE"=>V2AttemptState::AuthorityReady,_=>V2AttemptState::Staged},state_sha256:String::new(),
        attempt_revision:last.authoritative_revision,fencing_token:fence};
    attempt.state_sha256=response_observation_v2_lifecycle_state_sha256(&value.original().request,binding,&attempt,&evidence_digest);
    let result=match value.phase(){"RESERVE"=>V2OperationResult::Reserve(V2ReserveResult::Reserved{attempt,reservation_evidence:evidence}),
        "AUTHORIZE"=>V2OperationResult::Authority(V2AuthorityResult::Ready{attempt,authority_state:evidence.clone(),
            authority_evidence_root:EvidenceReference{evidence_type:V2EvidenceType::AuthorityEvidenceRoot,..evidence}}),
        _=>V2OperationResult::Stage(V2StageResult{attempt,staged_request:selected_object.ok_or_else(||fail("actual persisted staged object absent"))?,staging_evidence:evidence})};
    let scope=provider_authority_scope(config.custody_topology(),CustodyServiceRole::StateAuthority,key,ServiceOperationV1::StateCas,
        &operation_id,&binding.attempt_id,last.authoritative_revision,fence)?;
    let mut terminal=wire::SignedStagingResult{api_version:wire::RESULT.into(),generation_id:value.original().generation_id.clone(),
        generation:value.original().generation,original_sha256:value.original_sha256().into(),session_sha256:value.original().session_sha256.clone(),
        body:wire::ResultBody{result,state_originals,predecessor_result_sha256:value.original().predecessor_result_sha256.clone()},
        authority_scope:scope,signer_logical_role:key.logical_role().into(),signer_key_id:key.key_id().into(),signature:String::new()};
    terminal.signature=key.sign(wire::RESULT_DOMAIN,&terminal.unsigned())?;
    verification::result(config,&terminal)?;inputs.check(config,&value)?;
    authority.complete_native_staging(claim,&value,&terminal).map_err(authority_error)?;
    value.check(config)?;
    Ok(engine::EngineResult{result:serde_json::to_value(terminal).map_err(|_|fail("completed staging result encoding"))?,exact_object_fds:Vec::new()})
}
