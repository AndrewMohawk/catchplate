//! One actual assigned effect signer per guest. The preparation is retained
//! before any storage contact; a later request cannot replace it or its clock.
use super::*;
use services::active_effect_values as effect;
pub(super) struct Flight {grant:services::spool_head::Grant,prepared:effect::Prepared,completion:Option<effect::Completion>}
impl Work {
    pub(super) fn handle_effect(&mut self,wire:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;let kind=self.kind()?;
        require(matches!(kind,Kind::ActiveEffectBarrier|Kind::ActiveEffectCommit) && self.flight.is_none())?;
        let local=keys.keys.get(&kind.role()).ok_or(ShadowError::SignerBindingMismatch)?;
        match &wire.request {
            Body::PrepareNativeActiveEffect{request,allocation,head_grant_original}=>{
                let grant=self.grant(head_grant_original,keys,trust)?;let scope=&grant.payload.scope;let b=request.binding();
                allocation.verify(request,scope,&Sha256Digest::compute(head_grant_original.as_bytes()),
                    self.histories.borrowed().history(HistoricalServiceRoleV3::DurableRecoveryStore)).map_err(fail)?;
                require(self.effect_flight.is_none() && self.used.len()<128
                    && (kind==Kind::ActiveEffectBarrier)==matches!(request,Dispatch::AppendActiveEffectBarrier{..})
                    && wire.replay_id_sha256==b.replay_id_sha256 && wire.deadline_boottime_nanos==b.operation_deadline_boottime_nanos)?;
                if let Some(barrier)=&allocation.payload.barrier {
                    let DispatchResult::SealedArtifact{reference,exact_signed_artifact}=&barrier.result else{return Err(ShadowError::BindingDrift);};
                    exact_signed_artifact.validate(reference,barrier.request.binding(),
                        crate::policy_shadow::policy_custody::production_dispatch::ProductionArtifactKindV4::ActiveEffectPermit,
                        HistoricalServiceRoleV3::CleanupAuthorizationConsumer,&self.histories.borrowed()).map_err(fail)?;
                    barrier.wire().map_err(fail)?;
                }
                require(self.used.insert(b.operation_id_sha256.clone()))?;
                let core=effect::Core{api_version:effect::CORE_API.into(),request:request.clone(),allocation:allocation.clone(),
                    proof_scope_sha256:scope.proof_scope_sha256.clone(),native_grant_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?),
                    observed_at_unix_nanos:time.now_interval_unix_nanos()?.1,trusted_time_checkpoint_sha256:trust.current_checkpoint()?.checkpoint_id,
                    signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()};
                let mut prepared=effect::Prepared{core,prepared_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                prepared.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&prepared.preimage().map_err(fail)?).to_bytes()));
                prepared.verify(grant.key(request).map_err(fail)?).map_err(fail)?;
                self.effect_flight=Some(Flight{grant,prepared:prepared.clone(),completion:None});
                Ok(ResultBody::NativeActiveEffectPrepared(prepared))
            },
            Body::CompleteNativeActiveEffect{prepared,stored}=>{
                let flight=self.effect_flight.as_ref().ok_or(ShadowError::BindingDrift)?;let b=prepared.core.request.binding();
                require(&flight.prepared==prepared && flight.completion.is_none() && wire.replay_id_sha256==b.replay_id_sha256
                    && wire.deadline_boottime_nanos==b.operation_deadline_boottime_nanos)?;
                let p=&flight.grant.payload;
                effect::stored_verify(stored,prepared,p.proof_scope_original.as_bytes(),&p.scope.retrieval_namespace_sha256,&p.retrieval).map_err(fail)?;
                let scope=self.configuration.verify(keys,trust,time)?;
                let artifact=prepared.core.artifact(stored,|payload|{
                    let authority=scope.authority_payload(kind.signer(),payload).map_err(|_|fixed::invalid())?;
                    Ok(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(kind.signer().signature_domain(),&authority)).to_bytes()))
                }).map_err(fail)?;
                let mut completion=effect::Completion{prepared:prepared.clone(),stored:stored.clone(),artifact,
                    completed_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                completion.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&completion.preimage().map_err(fail)?).to_bytes()));
                completion.verify(&flight.grant).map_err(fail)?;
                self.effect_flight.as_mut().ok_or(ShadowError::BindingDrift)?.completion=Some(completion.clone());
                Ok(ResultBody::NativeActiveEffectCompletion(completion))
            },
            Body::FinishNativeActiveEffect{completion,result,service_transitions}=>{
                let flight=self.effect_flight.as_ref().ok_or(ShadowError::BindingDrift)?;let request=&completion.prepared.core.request;
                require(flight.completion.as_ref()==Some(completion) && wire.replay_id_sha256==request.binding().replay_id_sha256
                    && wire.deadline_boottime_nanos==request.binding().operation_deadline_boottime_nanos)?;
                let exact=match result{DispatchResult::Artifact(v)=>v,DispatchResult::SealedArtifact{exact_signed_artifact,..}=>&exact_signed_artifact.artifact,
                    _=>return Err(ShadowError::BindingDrift)};require(exact==&completion.artifact)?;
                let response=DispatchResponse::from_parts(request,result.clone(),service_transitions.clone()).map_err(fail)?;
                response.validate(request,&self.histories.borrowed()).map_err(fail)?;
                self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.effect_flight=None;Ok(ResultBody::Dispatch(response))
            },_=>Err(ShadowError::CustodyUnavailable),
        }
    }
}
