//! Fixed active-effect protocol. A cleanup-sealed permit and an effect result
//! are different objects; no claimed result can manufacture a prior permit.
use super::*;
use super::ledger_spool_values::{invalid,sha,Scope,Stored};
use super::spool_head_values::{require,RoleKey};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as ResultBody,CanonicalProductionArtifactV4 as Artifact,
    ProductionArtifactKindV4 as Kind,SignedProductionServiceTransitionV4 as Transition};
use super::super::authority_history::AuthorityEpochRefV3;
use crate::policy_shadow::{ActiveEffectPreparation,ActiveEffectCommitState,ActiveEffectBarrierReceiptWire,
    ActiveEffectCommitReceiptWire,PolicyShadowCustodySignerRole as Signer,CanonicalEd25519Signature,
    signature_preimage,hash_domain_frames};
pub(super) const CORE_API:&str="serverware.nativeActiveEffectCore/v1";
pub(super) const ALLOCATION_DOMAIN:&[u8]=b"serverware.nativeActiveEffectAllocation.signature/v1";
pub(super) const PREPARED_DOMAIN:&str="serverware.nativeActiveEffectPreparation.signature/v1";
pub(super) const COMPLETED_DOMAIN:&str="serverware.nativeActiveEffectCompletion.signature/v1";
pub(super) fn selected(request:&Dispatch)->bool{matches!(request,Dispatch::AppendActiveEffectBarrier{..}
    |Dispatch::CommitActiveEffect{..}|Dispatch::ReconcileActiveEffect{..})}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Barrier {pub(super) request:Dispatch,pub(super) result:ResultBody}
impl Barrier {
    pub(super) fn wire(&self)->Result<ActiveEffectBarrierReceiptWire,ServiceError>{
        let Dispatch::AppendActiveEffectBarrier{preparation,..}=&self.request else{return Err(invalid());};
        let ResultBody::SealedArtifact{reference,exact_signed_artifact}=&self.result else{return Err(invalid());};
        require(reference.kind==Kind::ActiveEffectPermit && reference.issuing_service_role==HistoricalServiceRoleV3::CleanupAuthorizationConsumer
            && reference.origin_operation_id_sha256==self.request.binding().operation_id_sha256
            && reference.origin_request_sha256==self.request.binding().request_sha256
            && exact_signed_artifact.artifact.kind==Kind::ActiveEffectPermit
            && reference.signed_receipt_sha256==exact_signed_artifact.signed_receipt_sha256)?;
        let wire:ActiveEffectBarrierReceiptWire=decode_canonical_frame(&exact_signed_artifact.artifact.exact_bytes().map_err(|_|invalid())?)?;
        wire.native_payload().map_err(|_|invalid())?;
        let original:ActiveEffectPreparation=decode_canonical_frame(&preparation.exact_bytes().map_err(|_|invalid())?)?;
        require(wire.native_preparation()==&original)?;Ok(wire)
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct AllocationPayload {
    pub(super) api_version:String,pub(super) authority_epoch:AuthorityEpochRefV3,pub(super) service_grant_sha256:Sha256Digest,
    pub(super) request_sha256:Sha256Digest,pub(super) owner_state_sha256:Sha256Digest,pub(super) origin_sha256:Sha256Digest,
    pub(super) preparation:ActiveEffectPreparation,pub(super) barrier:Option<Barrier>,pub(super) barrier_ordinal:u64,
    pub(super) predecessor_head_sha256:Sha256Digest,pub(super) resulting_head_sha256:Sha256Digest,
    pub(super) allocated_at_boottime_nanos:u64,pub(super) original_deadline_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Allocation {pub(super) payload:AllocationPayload,pub(super) signature_base64url:String}
impl Allocation {
    pub(super) fn validate(&self,request:&Dispatch,scope:&Scope)->Result<(),ServiceError>{
        scope.binding(request)?;let p=&self.payload;let b=request.binding();let (generation,ingress)=p.preparation.reconciliation_identity();
        p.preparation.validate_native().map_err(|_|invalid())?;
        use crate::policy_shadow::ActiveMutableEffectKind as Effect;
        require(matches!(p.preparation.effect_kind(),Effect::CredentialGeneration|Effect::CredentialLease|Effect::CredentialDecrypt
            |Effect::CredentialInjection|Effect::OauthRotation|Effect::ProviderSend))?;
        require(selected(request) && p.api_version=="serverware.nativeActiveEffectAllocation/v1"
            && p.request_sha256==sha(request)? && generation==&scope.generation_id && ingress>0 && p.barrier_ordinal>0
            && b.opened_at_boottime_nanos<=p.allocated_at_boottime_nanos && p.allocated_at_boottime_nanos<b.operation_deadline_boottime_nanos
            && p.original_deadline_boottime_nanos==b.operation_deadline_boottime_nanos)?;
        match request {
            Dispatch::AppendActiveEffectBarrier{preparation,..}=>{
                require(preparation.kind==Kind::ActiveEffectPreparation && p.barrier.is_none())?;
                let original:ActiveEffectPreparation=decode_canonical_frame(&preparation.exact_bytes().map_err(|_|invalid())?)?;
                require(original==p.preparation && p.resulting_head_sha256==hash_domain_frames(b"serverware.nativeActiveEffectHead/v1",
                    &[&encode_canonical_frame(&(&p.origin_sha256,&p.preparation,p.barrier_ordinal,&p.predecessor_head_sha256))?]))?;
            },
            Dispatch::CommitActiveEffect{effect_permit,terminal_state,..}=>{
                let barrier=p.barrier.as_ref().ok_or_else(invalid)?;let wire=barrier.wire()?;
                let ResultBody::SealedArtifact{reference,..}=&barrier.result else{return Err(invalid());};
                require(effect_permit==reference && wire.native_preparation()==&p.preparation)?;
                let _:ActiveEffectCommitState=decode_canonical_frame(&terminal_state.exact_bytes().map_err(|_|invalid())?)?;
            },
            Dispatch::ReconcileActiveEffect{generation_id,ingress_sequence,effect_id_sha256,..}=>{
                require(generation_id==generation && *ingress_sequence==ingress && effect_id_sha256==p.preparation.effect_id_sha256()
                    && p.barrier.as_ref().ok_or_else(invalid)?.wire()?.native_preparation()==&p.preparation)?;
            },_=>return Err(invalid()),
        }Ok(())
    }
    pub(super) fn verify(&self,request:&Dispatch,scope:&Scope,grant:&Sha256Digest,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        self.validate(request,scope)?;let p=&self.payload;
        require(&p.service_grant_sha256==grant && p.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference())?;
        history.verify_service_signature(&p.authority_epoch,ALLOCATION_DOMAIN,&encode_canonical_frame(p)?,&self.signature_base64url).map_err(|_|invalid())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Core {
    pub(super) api_version:String,pub(super) request:Dispatch,pub(super) allocation:Allocation,
    pub(super) proof_scope_sha256:Sha256Digest,pub(super) native_grant_sha256:Sha256Digest,
    pub(super) observed_at_unix_nanos:i64,pub(super) trusted_time_checkpoint_sha256:Sha256Digest,
    pub(super) signing_key_id:Sha256Digest,pub(super) signing_key_spki_sha256:Sha256Digest,
}
impl Core {
    pub(super) fn role(&self)->Signer{if matches!(self.request,Dispatch::AppendActiveEffectBarrier{..}){Signer::ActiveEffectBarrier}else{Signer::ActiveEffectCommit}}
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        self.request.validate().map_err(|_|invalid())?;
        require(self.api_version==CORE_API && selected(&self.request) && self.observed_at_unix_nanos>0
            && self.allocation.payload.request_sha256==sha(&self.request)? && encode_canonical_frame(self)?.len()<=super::ledger_spool_values::MAX_CORE)
    }
    pub(super) fn identity(&self)->Result<Sha256Digest,ServiceError>{self.validate()?;
        Ok(hash_domain_frames(CORE_API.as_bytes(),&[&encode_canonical_frame(self)?]))}
    pub(super) fn retrieval_id(&self,namespace:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        Ok(hash_domain_frames(b"serverware.nativeActiveEffectRetrievalId/v1",&[namespace.as_str().as_bytes(),&encode_canonical_frame(self)?]))}
    pub(super) fn retrieval_proof(&self,scope:&[u8],id:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        require(Sha256Digest::compute(scope)==self.proof_scope_sha256)?;
        Ok(hash_domain_frames(b"serverware.nativeActiveEffectRetrievalProof/v1",&[scope,id.as_str().as_bytes(),&encode_canonical_frame(self)?]))}
    pub(super) fn outcome(&self)->Result<(ActiveEffectCommitState,Sha256Digest),ServiceError>{match &self.request {
        Dispatch::CommitActiveEffect{terminal_state,result_sha256,..}=>Ok((decode_canonical_frame(&terminal_state.exact_bytes().map_err(|_|invalid())?)?,result_sha256.clone())),
        // This is a signed requirement to reconcile, never an inference that
        // the business effect did or did not occur.
        Dispatch::ReconcileActiveEffect{..}=>Ok((ActiveEffectCommitState::ReconcileRequired,
            hash_domain_frames(b"serverware.nativeActiveEffectReconciliationRequired/v1",&[&encode_canonical_frame(&self.allocation)?,&encode_canonical_frame(&self.request)?]))),
        _=>Err(invalid()),
    }}
    pub(super) fn payload(&self,stored:&Stored)->Result<Vec<u8>,ServiceError>{
        self.validate()?;let a=&self.allocation.payload;let p=&stored.payload;let persistence=sha(stored)?;
        if self.role()==Signer::ActiveEffectBarrier {
            encode_canonical_frame(&serde_json::json!([&a.preparation,a.barrier_ordinal,&a.predecessor_head_sha256,&a.resulting_head_sha256,
                self.observed_at_unix_nanos,&self.trusted_time_checkpoint_sha256,&persistence,&p.retrieval_id_sha256,&p.retrieval_proof_sha256,
                self.role(),&self.signing_key_id,&self.signing_key_spki_sha256]))
        }else{
            let (state,result)=self.outcome()?;let barrier=a.barrier.as_ref().ok_or_else(invalid)?.wire()?;
            encode_canonical_frame(&serde_json::json!([a.preparation.effect_id_sha256(),barrier.native_digest(),state,&result,
                matches!(state,ActiveEffectCommitState::OutcomeUnknown|ActiveEffectCommitState::ReconcileRequired),
                self.observed_at_unix_nanos,&self.trusted_time_checkpoint_sha256,&persistence,&p.retrieval_id_sha256,&p.retrieval_proof_sha256,
                self.role(),&self.signing_key_id,&self.signing_key_spki_sha256]))
        }
    }
    pub(super) fn artifact(&self,stored:&Stored,sign:impl FnOnce(&[u8])->Result<String,ServiceError>)->Result<Artifact,ServiceError>{
        let payload=self.payload(stored)?;let signature=sign(&payload)?;let p=&stored.payload;let a=&self.allocation.payload;
        let persistence=sha(stored)?;
        if self.role()==Signer::ActiveEffectBarrier {
            let digest=hash_domain_frames(b"serverware.policyShadowActiveEffectBarrierReceipt/v1",&[&payload,signature.as_bytes()]);
            let wire=ActiveEffectBarrierReceiptWire::from_custody(a.preparation.clone(),a.barrier_ordinal,a.predecessor_head_sha256.clone(),
                a.resulting_head_sha256.clone(),self.observed_at_unix_nanos,self.trusted_time_checkpoint_sha256.clone(),persistence,
                p.retrieval_id_sha256.clone(),p.retrieval_proof_sha256.clone(),self.signing_key_id.clone(),self.signing_key_spki_sha256.clone(),signature,digest).map_err(|_|invalid())?;
            Artifact::from_serializable(Kind::ActiveEffectPermit,&wire).map_err(|_|invalid())
        }else{
            let (state,result)=self.outcome()?;let digest=hash_domain_frames(b"serverware.policyShadowActiveEffectCommitReceipt/v1",&[&payload,signature.as_bytes()]);
            let wire=ActiveEffectCommitReceiptWire::from_custody(a.preparation.effect_id_sha256().clone(),a.barrier.as_ref().ok_or_else(invalid)?.wire()?.native_digest().clone(),
                state,result,self.observed_at_unix_nanos,self.trusted_time_checkpoint_sha256.clone(),persistence,p.retrieval_id_sha256.clone(),
                p.retrieval_proof_sha256.clone(),self.signing_key_id.clone(),self.signing_key_spki_sha256.clone(),signature,digest).map_err(|_|invalid())?;
            Artifact::from_serializable(Kind::ActiveEffectCommitReceipt,&wire).map_err(|_|invalid())
        }
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Prepared {pub(super) core:Core,pub(super) prepared_at_boottime_nanos:u64,pub(super) signature:CanonicalEd25519Signature}
impl Prepared {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{Ok(signature_preimage(PREPARED_DOMAIN,&encode_canonical_frame(&(&self.core,self.prepared_at_boottime_nanos))?))}
    pub(super) fn verify(&self,key:&RoleKey)->Result<(),ServiceError>{
        self.core.validate()?;let b=self.core.request.binding();
        require(self.core.native_grant_sha256==key.grant_sha256 && self.core.signing_key_id==key.key_id
            && self.core.signing_key_spki_sha256==key.key_spki_sha256
            && self.core.allocation.payload.allocated_at_boottime_nanos<=self.prepared_at_boottime_nanos
            && self.prepared_at_boottime_nanos<b.operation_deadline_boottime_nanos)?;
        key.material()?.verify_strict(&self.preimage()?,&Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
pub(super) fn stored_verify(stored:&Stored,prepared:&Prepared,scope:&[u8],namespace:&Sha256Digest,key:&RoleKey)->Result<(),ServiceError>{
    let p=&stored.payload;let c=&prepared.core;c.validate()?;
    require(p.api_version=="serverware.nativeActiveEffectStorage/v1" && p.grant_sha256==key.grant_sha256
        && p.signing_key_id==key.key_id && p.signing_key_spki_sha256==key.key_spki_sha256
        && p.core_sha256==c.identity()? && p.object_sha256==sha(c)? && p.fsverity_sha256!=Sha256Digest::compute(&[])
        && p.retrieval_id_sha256==c.retrieval_id(namespace)? && p.retrieval_proof_sha256==c.retrieval_proof(scope,&p.retrieval_id_sha256)?
        && p.sequence>0 && prepared.prepared_at_boottime_nanos<=p.stored_at_boottime_nanos
        && p.stored_at_boottime_nanos<p.original_deadline_boottime_nanos
        && p.original_deadline_boottime_nanos==c.request.binding().operation_deadline_boottime_nanos)?;
    key.material()?.verify_strict(&stored.preimage()?,&Signature::from_bytes(&stored.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Completion {pub(super) prepared:Prepared,pub(super) stored:Stored,pub(super) artifact:Artifact,
    pub(super) completed_at_boottime_nanos:u64,pub(super) signature:CanonicalEd25519Signature}
impl Completion {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{Ok(signature_preimage(COMPLETED_DOMAIN,
        &encode_canonical_frame(&(&self.prepared,&self.stored,&self.artifact,self.completed_at_boottime_nanos))?))}
    pub(super) fn verify(&self,grant:&spool_head::Grant)->Result<(),ServiceError>{
        let c=&self.prepared.core;let p=&grant.payload;let key=grant.key(&c.request)?;
        require(grant.effects_selected())?;c.allocation.validate(&c.request,&p.scope)?;self.prepared.verify(key)?;
        stored_verify(&self.stored,&self.prepared,p.proof_scope_original.as_bytes(),&p.scope.retrieval_namespace_sha256,&p.retrieval)?;
        let raw=self.artifact.exact_bytes().map_err(|_|invalid())?;
        let payload=if c.role()==Signer::ActiveEffectBarrier {require(self.artifact.kind==Kind::ActiveEffectPermit)?;
            decode_canonical_frame::<ActiveEffectBarrierReceiptWire>(&raw)?.native_payload().map_err(|_|invalid())?
        }else{require(self.artifact.kind==Kind::ActiveEffectCommitReceipt)?;
            decode_canonical_frame::<ActiveEffectCommitReceiptWire>(&raw)?.native_payload().map_err(|_|invalid())?};
        require(payload==c.payload(&self.stored)? && self.stored.payload.stored_at_boottime_nanos<=self.completed_at_boottime_nanos
            && self.completed_at_boottime_nanos<c.request.binding().operation_deadline_boottime_nanos)?;
        key.material()?.verify_strict(&self.preimage()?,&Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Cleanup {pub(super) result:ResultBody,pub(super) transition:Transition}
pub(super) fn verify_transition(transition:&Transition,request:&Dispatch,result:&ResultBody,
    epoch:&AuthorityEpochRefV3,key:&VerifyingKey)->Result<(),ServiceError>{
    require(&transition.authority_epoch==epoch)?;
    transition.validate_with_history(request.binding(),&sha(result)?,|actual,domain,payload,signature|{
        if actual!=epoch{return Err("effect service epoch differs");}
        let raw=URL_SAFE_NO_PAD.decode(signature).map_err(|_|"effect service signature differs")?;
        if raw.len()!=64 || URL_SAFE_NO_PAD.encode(&raw)!=signature{return Err("effect service signature differs");}
        key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(domain,payload)
            .map_err(|_|"effect service signature differs")?,&Signature::from_slice(&raw).map_err(|_|"effect service signature differs")?)
            .map_err(|_|"effect service signature differs")
    }).map_err(|_|invalid())
}
impl Cleanup {
    pub(super) fn verify(&self,completion:&Completion,grant:&spool_head::Grant)->Result<(),ServiceError>{
        completion.verify(grant)?;let c=&completion.prepared.core;let p=grant.payload.effects.as_ref().ok_or_else(invalid)?;
        require(self.transition.service_role==HistoricalServiceRoleV3::CleanupAuthorizationConsumer)?;
        verify_transition(&self.transition,&c.request,&self.result,&p.cleanup_authority_epoch,&p.cleanup_key()?)?;
        if c.role()==Signer::ActiveEffectBarrier {
            let barrier=Barrier{request:c.request.clone(),result:self.result.clone()};barrier.wire()?;
            let ResultBody::SealedArtifact{exact_signed_artifact,..}=&self.result else{return Err(invalid());};
            require(exact_signed_artifact.artifact==completion.artifact)
        }else{require(self.result==ResultBody::Artifact(completion.artifact.clone()))}
    }
}
