//! The actual bridge effect attempt. All three ordinary service signatures are
//! required, and a lost or ambiguous contact permanently fences this owner.
use super::*;
use crate::policy_shadow::policy_custody::services::active_effect_values as values;
impl Client {
    pub(super) fn run_effect(&mut self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,request:&Dispatch,
        mut native:impl FnMut(Endpoint,Body)->Result<(Request,Response),ServiceError>)->Result<(Request,Response),ServiceError>{
        let b=request.binding();let deadline=b.operation_deadline_boottime_nanos;self.check(deadline)?;
        self.head.payload.scope.binding(request)?;
        require(self.effects_selected() && self.origin.is_some() && !self.poisoned && self.used.len()<128
            && self.used.insert(b.operation_id_sha256.clone()))?;self.poisoned=true;
        let signer=if matches!(request,Dispatch::AppendActiveEffectBarrier{..}){Signer::ActiveEffectBarrier}else{Signer::ActiveEffectCommit};
        let endpoint=Endpoint::ParentSigner(signer);
        let command=Command{api_version:"serverware.nativeSpoolHeadCommand/v2".into(),action:Action::EffectClaim(request.clone())};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,&encode_canonical_frame(&command)?,deadline)?;
        let Reply::EffectAllocated(allocation)=decode_canonical_frame(&raw)? else{return Err(invalid());};
        allocation.verify(request,&self.head.payload.scope,&Sha256Digest::compute(self.selection.head_grant_original.as_bytes()),
            self.histories.borrowed().history(HistoricalServiceRoleV3::DurableRecoveryStore))?;
        require(self.origin.as_ref().is_some_and(|v|v.sha256()==&allocation.payload.origin_sha256))?;
        self.journal_sequence=self.journal_sequence.checked_add(1).ok_or_else(invalid)?;
        let (_,reply)=native(endpoint,Body::PrepareNativeActiveEffect{request:request.clone(),allocation:allocation.clone(),
            head_grant_original:self.selection.head_grant_original.clone()})?;
        let ResultBody::NativeActiveEffectPrepared(prepared)=reply.result else{return Err(invalid());};
        prepared.verify(self.head.key(request)?)?;
        require(prepared.core.request==*request && prepared.core.allocation==allocation && prepared.core.proof_scope_sha256==self.head.payload.scope.proof_scope_sha256)?;
        let (_,reply)=native(Endpoint::Proof(Proof::Retrieval),Body::StoreActiveEffectCore{prepared:prepared.clone()})?;
        let ResultBody::ActiveEffectCoreStored(stored)=reply.result else{return Err(invalid());};
        values::stored_verify(&stored,&prepared,self.head.payload.proof_scope_original.as_bytes(),
            &self.head.payload.scope.retrieval_namespace_sha256,&self.head.payload.retrieval)?;
        let (_,reply)=native(endpoint,Body::CompleteNativeActiveEffect{prepared,stored})?;
        let ResultBody::NativeActiveEffectCompletion(completion)=reply.result else{return Err(invalid());};
        completion.verify(&self.head)?;require(completion.prepared.core.request==*request && completion.prepared.core.allocation==allocation)?;
        let command=super::super::active_effect_cleanup::Command{api_version:super::super::active_effect_cleanup::API.into(),completion:completion.clone()};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,&encode_canonical_frame(&command)?,deadline)?;
        let cleanup:values::Cleanup=decode_canonical_frame(&raw)?;cleanup.verify(&completion,&self.head)?;
        self.transition(TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,&cleanup.transition,request,&cleanup.result)?;
        let command=Command{api_version:"serverware.nativeSpoolHeadCommand/v2".into(),action:Action::EffectCommit{completion:completion.clone(),cleanup:cleanup.clone()}};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,&encode_canonical_frame(&command)?,deadline)?;
        let durable:Reply=decode_canonical_frame(&raw)?;let Reply::EffectCommitted{result,transition}=&durable else{return Err(invalid());};
        require(result==&cleanup.result)?;
        self.transition(TrustedHostServiceRoleV3::DurableRecoveryStore,transition,request,result)?;
        self.journal_sequence=self.journal_sequence.checked_add(1).ok_or_else(invalid)?;
        let command=spool_current::Command::Effect(spool_current::EffectCommand{api_version:"serverware.nativeSpoolCurrentCommand/v2".into(),
            completion:completion.clone(),cleanup:cleanup.clone(),durable:durable.clone()});
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::CurrentSignatureAuthority,&encode_canonical_frame(&command)?,deadline)?;
        let current:Transition=decode_canonical_frame(&raw)?;self.transition(TrustedHostServiceRoleV3::CurrentSignatureAuthority,&current,request,result)?;
        let output=native(endpoint,Body::FinishNativeActiveEffect{completion,result:result.clone(),
            service_transitions:vec![transition.clone(),current,cleanup.transition]})?;
        let ResultBody::Dispatch(response)=&output.1.result else{return Err(invalid());};
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        require(response.result==*result)?;self.check(deadline)?;Ok(output)
    }
}
