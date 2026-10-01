//! Selected native completion uses actual durable bridge originals. A caller's
//! operation label, result-disposition flag or hash is never completion evidence.
use super::*;
use super::super::super::native_terminal;

fn refused()->ProductionPrimitiveRejectionV4 {
    ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::CleanupUnauthorized,
        "native invocation has no matching definite completed original")
}

impl<A:ExistingFiveServiceProductionAuthoritiesV4> ProductionRpcServiceBridgeV4<A> {
    pub(super) fn settle_native_original(&mut self,settlement:&ProductionRpcRequestV4)
        ->Result<CanonicalProductionArtifactV4,ProductionPrimitiveRejectionV4> {
        if !self.authority.native_terminal_selected(){return Err(refused());}
        let ProductionRpcRequestBodyV4::Settle{operation_id_sha256,termination_fence_sha256,
            result_disposition,cleanup_deadline_boottime_nanos}=&settlement.request else{return Err(refused());};
        if *result_disposition!=super::super::super::super::ProductionCustodyResultDisposition::ResultCommitted {
            return Err(refused());
        }
        let key=self.dispatch_identities.replay_for_operation(operation_id_sha256).ok_or_else(refused)?;
        let request_raw=self.durable_requests.get(key).ok_or_else(refused)?.clone();
        let response_raw=self.durable_responses.get(key).ok_or_else(refused)?.clone();
        let request:ProductionRpcRequestV4=decode_canonical_frame(&request_raw).map_err(|_|refused())?;
        let response:ProductionRpcResponseV4=decode_canonical_frame(&response_raw).map_err(|_|refused())?;
        request.validate().map_err(|_|refused())?;
        response.validate_for_request(&request).map_err(|_|refused())?;
        validate_authority_response(&self.histories.borrowed(),&request,&response).map_err(|_|refused())?;
        let ProductionRpcRequestBodyV4::Dispatch(dispatch)=&request.request else{return Err(refused());};
        let binding=dispatch.binding();
        if &binding.operation_id_sha256!=operation_id_sha256 || &binding.termination_fence_sha256!=termination_fence_sha256
            || binding.cleanup_deadline_boottime_nanos!=*cleanup_deadline_boottime_nanos
            || settlement.deadline_boottime_nanos!=*cleanup_deadline_boottime_nanos {
            return Err(refused());
        }
        self.authority.settle_native_completed(settlement,&request_raw,&response_raw)
    }
}

impl ConcreteFiveV3ProductionAuthoritiesV4 {
    pub(super) fn native_completed_artifact(&self,settlement:&ProductionRpcRequestV4,
        request_raw:&[u8],response_raw:&[u8])
        ->Result<CanonicalProductionArtifactV4,ProductionPrimitiveRejectionV4> {
        if !self.native_terminal {return Err(refused());}
        self.require_all_services_current()?;
        let request:ProductionRpcRequestV4=decode_canonical_frame(request_raw).map_err(|_|refused())?;
        let response:ProductionRpcResponseV4=decode_canonical_frame(response_raw).map_err(|_|refused())?;
        let ProductionRpcRequestBodyV4::Dispatch(dispatch)=request.request else{return Err(refused());};
        let closed=match response.response {
            ProductionRpcResponseBodyV4::Dispatch(value)=>value,
            ProductionRpcResponseBodyV4::NativeCommitRequest{dispatch,..}=>dispatch,
            _=>return Err(refused()),
        };
        let publication=self.publication.is_some();
        let query=native_terminal::Query{api_version:(if publication{native_terminal::PUBLICATION_QUERY_API}else{native_terminal::QUERY_API}).into(),
            cleanup_not_before_boottime_nanos:dispatch.binding().operation_deadline_boottime_nanos,
            dispatch_response_sha256:super::super::super::super::Sha256Digest::compute(
                &super::super::super::super::canonical_json_bytes(&closed).map_err(|_|refused())?),dispatch};
        query.validate().map_err(|_|refused())?;
        let endpoint=self.proof_endpoint(ProductionProofEndpointKindV4::Persistence)?;
        let wire=ProductionAuthorityEndpointRequestV4::new(endpoint.identity,query.dispatch.binding().replay_id_sha256.clone(),
            settlement.deadline_boottime_nanos,ProductionAuthorityEndpointRequestBodyV4::VerifyCompletedInvocation{query})?;
        let reply=self.call_endpoint_original(endpoint,wire.clone(),ProductionRpcRejectionCodeV4::CleanupUnauthorized)?;
        let ProductionAuthorityEndpointResultV4::CompletedInvocation(proof)=&reply.result else{return Err(refused());};
        if proof.api_version!=(if publication{native_terminal::PUBLICATION_PROOF_API}else{native_terminal::PROOF_API}) || proof.commit_original.is_empty()
            || proof.head_original.is_empty() || !proof.commit_original.is_ascii() || !proof.head_original.is_ascii()
            || proof.current_head_sequence==0 || proof.current_head_sequence>128 {return Err(refused());}
        let artifact=native_terminal::Wire{api_version:(if publication{native_terminal::PUBLICATION_WIRE_API}else{native_terminal::WIRE_API}).into(),
            persistence_request_original:String::from_utf8(encode_canonical_frame(&wire).map_err(|_|refused())?).map_err(|_|refused())?,
            persistence_reply_original:String::from_utf8(encode_canonical_frame(&reply).map_err(|_|refused())?).map_err(|_|refused())?,
            dispatch_request_original_sha256:super::super::super::super::Sha256Digest::compute(request_raw),
            dispatch_response_original_sha256:super::super::super::super::Sha256Digest::compute(response_raw)};
        CanonicalProductionArtifactV4::from_serializable(
            super::super::super::production_dispatch::ProductionArtifactKindV4::NativeInvocationSettlement,&artifact)
            .map_err(|_|refused())
    }
}
