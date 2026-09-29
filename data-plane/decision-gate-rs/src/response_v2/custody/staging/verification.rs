//! Exact state-signed predecessor/claim verification used by the independently
//! keyed policy and storage roles. No synchronous callback into StateAuthority.
use super::*;
use super::super::{attestation,config::CustodyServiceRole,protocol::ServiceOperationV1};
use super::super::super::state_authority::{canonical,lifecycle::{AttemptState,OperationKind},rpc};

fn same<T:serde::Serialize>(left:&T,right:&T)->Result<bool,V2RuntimeError> {
    Ok(native::canonical(left).map_err(fail)?==native::canonical(right).map_err(fail)?)
}
pub(crate) fn result(config:&Config,value:&wire::SignedStagingResult)->Result<(),V2RuntimeError> {
    let topology=config.custody_topology();
    if value.api_version!=wire::RESULT||value.generation_id!=topology.generation_id||value.generation!=topology.generation
        ||value.signer_logical_role!="linearizable-store"||!crate::native_currentness_v1::digest(&value.original_sha256)
        ||!crate::native_currentness_v1::digest(&value.session_sha256)||value.body.state_originals.is_empty()
        ||value.body.state_originals.len()>2 {return Err(fail("staging result closed scope differs"));}
    attestation::verify_provider_authority_scope(topology,CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,&value.authority_scope)?;
    let last=&value.body.state_originals.last().ok_or_else(||fail("staging state original missing"))?.result.body;
    if value.authority_scope.logical_role!=value.signer_logical_role||value.authority_scope.key_id!=value.signer_key_id
        ||value.authority_scope.operation_id!=last.operation_id.0||value.authority_scope.attempt_id!=last.attempt_id.0
        ||value.authority_scope.attempt_revision!=last.authoritative_revision
        ||value.authority_scope.fencing_token.to_string()!=last.fence_token.0 {
        return Err(fail("staging result signer scope differs from actual successor"));
    }
    for original in &value.body.state_originals {
        let request=&original.frame.request;let result=&original.result.body;
        if canonical::sha256_digest(&canonical::canonical_jcs_bytes(&original.frame).map_err(|e|fail(e.to_string()))?).0
                !=original.exact_request_sha256
            ||canonical::sha256_digest(&canonical::canonical_jcs_bytes(&original.result).map_err(|e|fail(e.to_string()))?).0
                !=original.exact_result_sha256||request.generation_id.0!=value.generation_id
            ||result.generation_id!=request.generation_id||result.attempt_id!=request.attempt_id
            ||result.operation_id!=request.operation_id||result.request_id!=request.request_id||result.operation!=request.operation
            ||result.disposition!=rpc::ResultDisposition::Applied||result.exact_request_sha256.0!=original.exact_request_sha256
            ||result.conflict_code.is_some()||result.immutable_inspection.is_some()||result.retrieved_immutable_raw.is_some()
            ||result.response_data_result.is_some()||request.expected_revision.checked_add(1)!=Some(result.authoritative_revision)
            ||request.fence.fence_token.as_ref().is_some_and(|f|f!=&result.fence_token) {
            return Err(fail("staging result lacks exact positive signed-frame/result commitments"));
        }
    }
    attestation::verify_logical_role_signature(topology,CustodyServiceRole::StateAuthority,&value.signer_logical_role,
        &value.signer_key_id,wire::RESULT_DOMAIN,&value.unsigned(),&value.signature)
}
pub(crate) fn claim(config:&Config,value:&VerifiedRequest,claim:&wire::SignedClaim,
    previous:&wire::SignedStagingResult)->Result<(),V2RuntimeError> {
    value.check(config)?;result(config,previous)?;
    let digest=native::sha256(&crate::canonical_json_bytes(previous).map_err(|_|fail("staging previous encoding"))?);
    if !matches!(value.phase(),"AUTHORIZE"|"STAGE")||claim.api_version!=wire::CLAIM
        ||claim.generation_id!=value.original().generation_id||claim.generation!=value.original().generation
        ||claim.original_sha256!=value.original_sha256()||claim.session_sha256!=value.original().session_sha256
        ||previous.session_sha256!=claim.session_sha256||claim.phase!=value.phase()
        ||claim.predecessor_result_sha256!=digest||value.original().predecessor_result_sha256.as_deref()!=Some(digest.as_str())
        ||claim.signer_logical_role!="linearizable-store" {return Err(fail("staging durable claim/predecessor differs"));}
    let last=&previous.body.state_originals.last().ok_or_else(||fail("staging predecessor original absent"))?.result.body;
    let expected=if value.phase()=="AUTHORIZE" {OperationKind::AttemptReserve} else {OperationKind::AttemptAuthorize};
    let state=if value.phase()=="AUTHORIZE" {AttemptState::Reserved} else {AttemptState::Authorized};
    if last.operation!=expected||last.authoritative_state!=state||last.attempt_id.0!=value.binding().attempt_id
        ||last.authoritative_revision!=value.binding().attempt_revision||last.fence_token.0!=value.binding().fencing_token.to_string()
        ||previous.body.state_originals.len()!=1 {return Err(fail("staging predecessor is not the required real transition"));}
    let scope=&claim.authority_scope;
    attestation::verify_provider_authority_scope(config.custody_topology(),CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,scope)?;
    if scope.key_id!=claim.signer_key_id||scope.logical_role!=claim.signer_logical_role
        ||scope.operation_id!=format!("staging-claim:{}",&value.original_sha256()[7..])
        ||scope.attempt_id!=value.binding().attempt_id||scope.attempt_revision!=value.binding().attempt_revision
        ||scope.fencing_token!=value.binding().fencing_token {return Err(fail("staging claim scope differs"));}
    attestation::verify_logical_role_signature(config.custody_topology(),CustodyServiceRole::StateAuthority,
        &claim.signer_logical_role,&claim.signer_key_id,wire::CLAIM_DOMAIN,&claim.unsigned(),&claim.signature)
}

pub(crate) fn reserve_pair(config:&Config,current:&VerifiedRequest,request:&wire::PolicyRequest)->Result<(),V2RuntimeError> {
    claim(config,current,&request.claim,&request.reserve_result)?;
    let reserved=admit(config,request.reserve_request.clone())?;
    if request.api_version!="serverware.responseV2.nativeStagingPolicy/v1"||reserved.phase()!="RESERVE"
        ||request.reserve_result.original_sha256!=reserved.original_sha256()
        ||reserved.original().owner!=current.original().owner||reserved.original().session_sha256!=current.original().session_sha256
        ||reserved.original().gate_key_id!=current.original().gate_key_id||reserved.deadline()!=current.deadline()
        ||!same(&reserved.binding().transaction,&current.binding().transaction)? {
        return Err(fail("policy phase does not retain the exact admitted Reserve original"));
    }
    Ok(())
}
