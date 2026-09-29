//! Closed purpose selection at both actual role transport endpoints.
use super::*;
use super::super::{config::CustodyServiceRole as Role,protocol::{ServiceOperationV1,ServiceRpcEnvelopeV1}};
use crate::response_observation_v2_api::{V2ResponseDataRequest,V2NativeStagingParams,response_observation_v2_stable_resume_id_sha256};
pub(crate) fn public<'a>(config:&Config,value:&'a V2ResponseDataRequest)->Result<&'a V2NativeStagingParams,V2RuntimeError>{
    let V2ResponseDataRequest::NativeStaging{api_version,request_id,boot_id,params}=value else{return Err(fail("not native staging transport"));};
    let admitted=admit(config,params.request.clone())?;
    if api_version!=crate::response_observation_v2_api::RESPONSE_OBSERVATION_V2_API_VERSION
        ||request_id!=&admitted.binding().request_id||boot_id!=&admitted.binding().custody_boot_id
        ||native::canonical(&params.binding).map_err(fail)?!=native::canonical(admitted.binding()).map_err(fail)?
        ||params.stable_resume_id!=response_observation_v2_stable_resume_id_sha256(&admitted.original().generation_id,
            admitted.original().generation,&admitted.binding().transaction.client_request_sha256,&admitted.binding().attempt_id){
        return Err(fail("public native wrapper does not equal the admitted exact original"));}
    Ok(params)
}
pub(crate) fn selection(config:&Config,role:Role,envelope:&ServiceRpcEnvelopeV1)->Result<Option<usize>,V2RuntimeError>{
    let label=envelope.payload.get("apiVersion").and_then(serde_json::Value::as_str);
    let public_label=envelope.payload.get("operation").and_then(serde_json::Value::as_str);
    if public_label==Some("responseObservationV2.nativeStaging/v1"){
        if role!=Role::StateAuthority||envelope.operation!=ServiceOperationV1::StateCas{return Err(fail("native staging routed to wrong role"));}
        let request:V2ResponseDataRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("native public closed request"))?;
        let params=public(config,&request)?;
        return Ok(Some(params.request.evidence.statement.original.request.exact_object_descriptors().len()));
    }
    if label==Some("serverware.responseV2.nativeStagingPolicy/v1"){
        if role!=Role::PolicyProofVerifier||envelope.operation!=ServiceOperationV1::TransitionAuthorize{return Err(fail("native policy routed to wrong role"));}
        let request:wire::PolicyRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("native policy closed request"))?;
        let value=admit(config,request.request.clone())?;verification::reserve_pair(config,&value,&request)?;return Ok(Some(5));
    }
    if label==Some("serverware.responseV2.nativeStagedPut/v1"){
        if role!=Role::ImmutableArtifactLedger||envelope.operation!=ServiceOperationV1::ImmutablePut{return Err(fail("native staged publication routed to wrong role"));}
        let request:wire::StagedPutRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("native staged put closed request"))?;
        let value=admit(config,request.request.clone())?;verification::claim(config,&value,&request.claim,&request.authority_result)?;return Ok(Some(1));
    }
    Ok(None)
}

pub(crate) fn preserve(operation:ServiceOperationV1,request:&serde_json::Value,result:&serde_json::Value)
    ->Result<bool,V2RuntimeError>{
    let label=request.get("apiVersion").and_then(serde_json::Value::as_str);
    match (operation,label){
        (ServiceOperationV1::TransitionAuthorize,Some("serverware.responseV2.nativeStagingPolicy/v1"))=>{
            let _:wire::PolicyRequest=serde_json::from_value(request.clone()).map_err(|_|fail("policy request shape"))?;
            let _:super::super::super::state_authority::rpc::SignedAuthorityArtifact=serde_json::from_value(result.clone())
                .map_err(|_|fail("actual policy artifact shape"))?;Ok(true)
        },
        (ServiceOperationV1::ImmutablePut,Some("serverware.responseV2.nativeStagedPut/v1"))=>{
            let _:wire::StagedPutRequest=serde_json::from_value(request.clone()).map_err(|_|fail("staged request shape"))?;
            ledger::preserve(result.clone())?;Ok(true)
        },_=>Ok(false),
    }
}
