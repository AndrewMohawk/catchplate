//! Actual gate caller, same authenticated native session and original allowance.
//! A lost result never enters the old re-sign/reopen/recovery loop.
use super::*;
use serverware_decision_gate::native_staging_v1 as profile;
use serverware_decision_gate::native_response_gate::{staging as wire, state_receipt};
fn invalid()->ResponseObservationV2TransactionError{ResponseObservationV2TransactionError::InvalidResponse}
fn same<T:Serialize>(left:&T,right:&T)->Result<bool,ResponseObservationV2TransactionError>{
    Ok(profile::canonical(left).map_err(|_|invalid())?==profile::canonical(right).map_err(|_|invalid())?)
}

pub(super) fn execute(state:&GateState,snapshot:&Arc<Snapshot>,decision:&Value,session:&ResponseObservationV2Session<'_>,
    cursor:&mut ResponseObservationV2AttemptCursor,request:&V2OperationRequest,objects:Vec<ResponseObservationV2ExactInput>,
    previous:&mut Option<String>,stable_resume_id:&str)->Result<V2OperationResult,ResponseObservationV2TransactionError>{
    if !session.client.native_staging{return Err(invalid());}
    let preparation=native_staging::Prepared::open(state,snapshot,decision,request,session,previous.clone())
        .map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    let admitted=preparation.request().map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    let binding=request.mutation_binding().ok_or_else(invalid)?;
    let wrapped=V2ResponseDataRequest::NativeStaging{api_version:RESPONSE_OBSERVATION_V2_API_VERSION.into(),
        request_id:binding.request_id.clone(),boot_id:session.client.boot_id.clone(),params:serverware_decision_gate::V2NativeStagingParams{
            binding:binding.clone(),stable_resume_id:stable_resume_id.into(),request:admitted.clone()}};
    let reply=session.execute_response_data(&wrapped,objects)?;
    let response:V2ResponseDataControlResponse=decode_canonical_custody_json(&reply.canonical_response).map_err(|_|invalid())?;
    let V2ResponseDataControlResponse::Success{attestation:Some(attestation),..}=response else{return Err(invalid());};
    if !reply.exact_bytes.is_empty()||session.lifecycle_deadline.expired()
        ||attestation.authenticated_session_sha256!=session.hello_attestation.authenticated_session_sha256
        ||attestation.client_identity_sha256!=session.client.authenticated_client_identity_sha256{return Err(invalid());}
    let V2ResponseDataResult::NativeStaging(terminal)=reply.result else{return Err(invalid());};
    let original=&admitted.evidence.statement.original;
    if terminal.api_version!=wire::RESULT||terminal.generation_id!=session.client.generation_id
        ||terminal.generation!=session.client.provider_generation||terminal.original_sha256!=profile::original_sha256(original).map_err(|_|invalid())?
        ||terminal.session_sha256!=original.session_sha256||terminal.body.predecessor_result_sha256!=*previous
        ||terminal.signer_logical_role!="linearizable-store" {return Err(invalid());}
    let mut unsigned=terminal.clone();unsigned.signature.clear();
    super::target_dispatch_client::signed(session.client,"linearizable-store",&terminal.signer_key_id,
        wire::RESULT_DOMAIN,&unsigned,&terminal.signature)?;
    let stage=matches!(request,V2OperationRequest::Stage{..});let count=if stage{2}else{1};
    if terminal.body.state_originals.len()!=count{return Err(invalid());}
    let deadline=profile::deadline(original).map_err(|_|invalid())?;
    for (index,value) in terminal.body.state_originals.iter().enumerate(){
        let frame=&value.frame.request;let result=&value.result.body;
        let (operation,from,to)=match (request,index){
            (V2OperationRequest::Reserve{..},0)=>(state_receipt::OperationKind::AttemptReserve,state_receipt::AttemptState::Absent,state_receipt::AttemptState::Reserved),
            (V2OperationRequest::Authority{..},0)=>(state_receipt::OperationKind::AttemptAuthorize,state_receipt::AttemptState::Reserved,state_receipt::AttemptState::Authorized),
            (V2OperationRequest::Stage{..},0)=>(state_receipt::OperationKind::ObjectCommitRaw,state_receipt::AttemptState::Authorized,state_receipt::AttemptState::Authorized),
            (V2OperationRequest::Stage{..},1)=>(state_receipt::OperationKind::AttemptStage,state_receipt::AttemptState::Authorized,state_receipt::AttemptState::Staged),
            _=>return Err(invalid()),};
        let expected_revision=binding.attempt_revision.checked_add(index as u64).ok_or_else(invalid)?;
        let expected_request=if stage&&index==0 {format!("staged-put:{}",&terminal.original_sha256[7..])}
            else {binding.request_id.clone()};
        if value.exact_request_sha256!=state_receipt::sha256_digest(&state_receipt::canonical_jcs_bytes(&value.frame).map_err(|_|invalid())?).0
            ||value.exact_result_sha256!=state_receipt::sha256_digest(&state_receipt::canonical_jcs_bytes(&value.result).map_err(|_|invalid())?).0
            ||frame.generation_id.0!=session.client.generation_id||frame.attempt_id.0!=binding.attempt_id||frame.request_id.0!=expected_request
            ||frame.operation!=operation||frame.expected_state!=from||frame.expected_revision!=expected_revision
            ||frame.deadline.clock!="CLOCK_BOOTTIME"||frame.deadline.deadline_boot_millis.checked_mul(1_000_000)!=Some(deadline)
            ||result.disposition!=state_receipt::ResultDisposition::Applied||result.operation!=operation||result.authoritative_state!=to
            ||result.generation_id!=frame.generation_id||result.attempt_id!=frame.attempt_id||result.request_id!=frame.request_id
            ||result.operation_id!=frame.operation_id||result.exact_request_sha256.0!=value.exact_request_sha256
            ||result.authoritative_revision!=expected_revision.checked_add(1).ok_or_else(invalid)?||result.stable_resume_id.0!=stable_resume_id
            ||result.conflict_code.is_some()||result.immutable_inspection.is_some()||result.retrieved_immutable_raw.is_some()||result.response_data_result.is_some(){return Err(invalid());}
        let fence=result.fence_token.0.parse::<u64>().map_err(|_|invalid())?;
        if fence==0||fence>9_007_199_254_740_991||result.fence_token.0!=fence.to_string()
            ||(binding.fencing_token!=0&&fence!=binding.fencing_token){return Err(invalid());}
    }
    let last=&terminal.body.state_originals.last().ok_or_else(invalid)?.result.body;
    let fence=last.fence_token.0.parse::<u64>().map_err(|_|invalid())?;
    super::target_dispatch_client::scope(session.client,&terminal.authority_scope,&binding.attempt_id,&last.operation_id.0,
        last.authoritative_revision,fence)?;
    let (attempt,evidence)=match (&terminal.body.result,request){
        (V2OperationResult::Reserve(V2ReserveResult::Reserved{attempt,reservation_evidence}),V2OperationRequest::Reserve{..})=>(attempt,reservation_evidence),
        (V2OperationResult::Authority(V2AuthorityResult::Ready{attempt,authority_state,authority_evidence_root}),V2OperationRequest::Authority{..})=>{
            if authority_evidence_root.evidence_type!=V2EvidenceType::AuthorityEvidenceRoot
                ||authority_evidence_root.evidence_sha256!=authority_state.evidence_sha256{return Err(invalid());}(attempt,authority_state)
        },
        (V2OperationResult::Stage(value),V2OperationRequest::Stage{params,..})=>{
            if value.staged_request.object_type!=ImmutableObjectType::StagedRequest
                ||value.staged_request.retrieval_id!=params.credential_free_request.object_id
                ||value.staged_request.object_sha256!=params.credential_free_request.sha256
                ||value.staged_request.byte_length!=params.credential_free_request.byte_length{return Err(invalid());}
            let state_receipt::MutationPayload::Stage(selection)=&terminal.body.state_originals[1].frame.request.payload else{return Err(invalid());};
            if selection.staged_request_object.object_id.0!=value.staged_request.retrieval_id
                ||selection.staged_request_object.content_sha256.0!=value.staged_request.object_sha256
                ||selection.staged_request_object.content_length!=value.staged_request.byte_length
                ||Some(selection.credential_binding_sha256.0.as_str())!=binding.transaction.credential_binding_sha256.as_deref(){return Err(invalid());}
            (&value.attempt,&value.staging_evidence)
        },_=>return Err(invalid()),};
    let expected_evidence=state_receipt::sha256_digest(&state_receipt::canonical_jcs_bytes(&terminal.body.state_originals).map_err(|_|invalid())?).0;
    let expected_state=match request{V2OperationRequest::Reserve{..}=>V2AttemptState::Reserved,
        V2OperationRequest::Authority{..}=>V2AttemptState::AuthorityReady,_=>V2AttemptState::Staged};
    if evidence.evidence_sha256!=expected_evidence||attempt.attempt_id!=binding.attempt_id||attempt.state!=expected_state
        ||attempt.attempt_revision!=last.authoritative_revision||attempt.fencing_token!=fence
        ||attempt.state_sha256!=response_observation_v2_lifecycle_state_sha256(request,binding,attempt,&expected_evidence)
        ||binding.attempt_id!=cursor.attempt.attempt_id||binding.predecessor_state_sha256!=cursor.attempt.state_sha256
        ||binding.predecessor_lifecycle_state!=cursor.attempt.state||binding.attempt_revision!=cursor.attempt.attempt_revision
        ||binding.fencing_token!=cursor.attempt.fencing_token||binding.transaction!=cursor.transaction
        ||binding.monotonic_deadline!=cursor.monotonic_deadline||binding.deadline_at_epoch_ms!=cursor.deadline_at_epoch_ms
        ||!same(&original.request,request)?{return Err(invalid());}
    preparation.statement().map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    // Explicit +2 Stage is justified by both actual signed commits, never by
    // broadening the older public cursor's single-step contract.
    cursor.attempt=attempt.clone();
    *previous=Some(profile::sha256(&custody_canonical_json_bytes(&terminal).map_err(|_|invalid())?));
    Ok(terminal.body.result)
}
