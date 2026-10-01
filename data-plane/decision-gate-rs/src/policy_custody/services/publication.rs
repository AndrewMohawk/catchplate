//! Fixed publication originals, not a state owner. DRS owns the durable state;
//! the native signer and CSA independently check these exact proposals.
use super::*;
use super::ledger_spool_values::{Scope,Stored,invalid,sha};
use super::spool_head_values::RoleKey;
use super::super::authority_history::AuthorityEpochRefV3;
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as ResultBody,CanonicalProductionArtifactV4 as Artifact,
    ProductionArtifactKindV4 as Kind};
use crate::policy_shadow::{AuthorityRole,PublicationReconciliationReceiptWire as Receipt,PublicationReconciliationState as State,
    PreparedGenerationPublication,ShadowGenerationIdentity,CanonicalEd25519Signature,PolicyShadowCustodySignerRole as Role,
    canonical_json_bytes,hash_domain_frames,signature_preimage};
use ed25519_dalek::Signer;

pub(super) const SNAPSHOT_DOMAIN:&[u8]=b"serverware.nativePublicationSnapshot.signature/v1";
pub(super) const PREPARED_DOMAIN:&str="serverware.nativePublicationPreparation.signature/v1";
pub(super) const PROPOSAL_DOMAIN:&str="serverware.nativePublicationProposal.signature/v1";
pub(super) const STORAGE_DOMAIN:&str="serverware.nativePublicationStorage.signature/v1";
pub(super) const MAX_ORIGINAL:usize=1024*1024;
fn require(ok:bool)->Result<(),ServiceError>{if ok{Ok(())}else{Err(invalid())}}
fn original<T:serde::de::DeserializeOwned+Serialize>(raw:&str)->Result<T,ServiceError>{
    require(!raw.is_empty() && raw.is_ascii() && raw.len()<=MAX_ORIGINAL)?;decode_canonical_frame(raw.as_bytes())
}
fn text<T:Serialize>(value:&T)->Result<String,ServiceError>{String::from_utf8(encode_canonical_frame(value)?).map_err(|_|invalid())}

/// Native admission pins the independently assigned Retrieval key and guest,
/// not its future grant digest. Ordinary grants pin that exact digest later;
/// this avoids a native-grant <-> retrieval-grant hash cycle.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct RetrievalAuthority {
    pub(super) key_id:Sha256Digest,pub(super) key_spki_sha256:Sha256Digest,pub(super) public_key_base64url:String,
}
impl RetrievalAuthority {
    pub(super) fn material(&self)->Result<VerifyingKey,ServiceError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(|_|invalid())?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(verifying_key_spki_sha256(&key).map_err(|_|invalid())?==self.key_spki_sha256 && self.key_id!=Sha256Digest::compute(&[]))?;Ok(key)
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Admission {
    pub(super) scope:Scope,pub(super) proof_scope_original:String,pub(super) prior_receipt_original:String,
    pub(super) first_ingress_sequence:u64,pub(super) last_ingress_sequence:u64,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="crate::policy_shadow::deserialize_optional_present")]
    pub(super) adoption:Option<Box<super::publication_adoption::Authorization>>,
}
pub(super) fn authority_payload_for_adoption(scope:&str,payload:&[u8])->Result<Vec<u8>,ServiceError>{
    super::guest::native_keys::admission::publication::authority_payload(scope,payload).map_err(|_|invalid())
}
impl Admission {
    pub(super) fn receipt(&self)->Result<Receipt,ServiceError>{original(&self.prior_receipt_original)}
    pub(super) fn validate(&self,native:&RoleKey)->Result<(),ServiceError>{
        require(native.role==AuthorityRole::CustodyPublicationReconciliation
            && self.first_ingress_sequence>0 && self.first_ingress_sequence<=self.last_ingress_sequence
            && self.last_ingress_sequence<u64::MAX && self.scope.assignment_revision>0
            && self.scope.issued_at_boottime_nanos>0 && self.scope.issued_at_boottime_nanos<self.scope.expires_at_boottime_nanos
            && self.proof_scope_original.is_ascii() && !self.proof_scope_original.is_empty()
            && self.proof_scope_original.len()<=16384
            && Sha256Digest::compute(self.proof_scope_original.as_bytes())==self.scope.proof_scope_sha256)?;
        if let Some(adoption)=&self.adoption {
            adoption.require_admission(&self.scope,&self.proof_scope_original,native)?;
            require(self.prior_receipt_original==adoption.cold_bundle()?.completion.receipt_original)?;
        }
        self.verify_receipt(&self.prior_receipt_original,native).map(|_|())
    }
    pub(super) fn request(&self,request:&Dispatch)->Result<(),ServiceError>{
        self.scope.binding(request)?;
        require(matches!(request,Dispatch::RecoverCurrentState{..}|Dispatch::PrepareGenerationPublication{..}
            |Dispatch::CommitGenerationPublication{..}|Dispatch::AbortGenerationPublication{..}))
    }
    pub(super) fn verify_receipt(&self,raw:&str,native:&RoleKey)->Result<Receipt,ServiceError>{
        if raw==self.prior_receipt_original {
            if let Some(adoption)=&self.adoption {
                adoption.require_admission(&self.scope,&self.proof_scope_original,native)?;
                let bundle=adoption.cold_bundle()?;
                require(raw==bundle.completion.receipt_original)?;
                return original(raw);
            }
        }
        let receipt:Receipt=original(raw)?;receipt.validate_deserialized_invariants().map_err(|_|invalid())?;
        require(receipt.signer_role==Role::PublicationReconciliation && receipt.signing_key_id==native.key_id
            && receipt.signing_key_spki_sha256==native.key_spki_sha256)?;
        let payload=receipt.canonical_payload().map_err(|_|invalid())?;
        let authority=super::guest::native_keys::admission::publication::authority_payload(&self.proof_scope_original,&payload)
            .map_err(|_|invalid())?;
        native.material()?.verify_strict(&signature_preimage(Role::PublicationReconciliation.signature_domain(),&authority),
            &Signature::from_bytes(&receipt.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())?;
        Ok(receipt)
    }
}
pub(super) fn state_sha(current:&str,pending:&Option<String>)->Result<Sha256Digest,ServiceError>{
    let _:Receipt=original(current)?;
    if let Some(raw)=pending{let _:PreparedGenerationPublication=original(raw)?;}
    Ok(hash_domain_frames(b"serverware.nativePublicationState/v1",&[&encode_canonical_frame(&(current,pending))?]))
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Snapshot {
    pub(super) api_version:String,pub(super) native_grant_sha256:Sha256Digest,pub(super) request:Dispatch,
    pub(super) current_receipt_original:String,pub(super) pending_prepared_original:Option<String>,
    pub(super) state_sha256:Sha256Digest,pub(super) authority_epoch:AuthorityEpochRefV3,
    pub(super) observed_at_boottime_nanos:u64,pub(super) signature_base64url:String,
}
impl Snapshot {
    pub(super) fn payload(&self)->Result<Vec<u8>,ServiceError>{encode_canonical_frame(&(
        &self.api_version,&self.native_grant_sha256,&self.request,&self.current_receipt_original,
        &self.pending_prepared_original,&self.state_sha256,&self.authority_epoch,self.observed_at_boottime_nanos))}
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        self.request.validate().map_err(|_|invalid())?;let binding=self.request.binding();
        require(self.api_version=="serverware.nativePublicationSnapshot/v1"
            && self.state_sha256==state_sha(&self.current_receipt_original,&self.pending_prepared_original)?
            && self.authority_epoch.authority_role==super::super::authority_history::HistoricalAuthorityRoleV3::IsolatedService(
                HistoricalServiceRoleV3::DurableRecoveryStore)
            && binding.opened_at_boottime_nanos<=self.observed_at_boottime_nanos
            && self.observed_at_boottime_nanos<binding.operation_deadline_boottime_nanos)
    }
    pub(super) fn verify(&self,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        self.validate()?;history.verify_service_signature(&self.authority_epoch,SNAPSHOT_DOMAIN,&self.payload()?,
            &self.signature_base64url).map_err(|_|invalid())
    }
    pub(super) fn verify_with_key(&self,epoch:&AuthorityEpochRefV3,key:&VerifyingKey)->Result<(),ServiceError>{
        self.validate()?;require(&self.authority_epoch==epoch
            && verifying_key_spki_sha256(key).map_err(|_|invalid())?==epoch.service_signing_key_spki_sha256)?;
        let raw=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        require(raw.len()==64 && URL_SAFE_NO_PAD.encode(&raw)==self.signature_base64url)?;
        key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(SNAPSHOT_DOMAIN,&self.payload()?)?,
            &Signature::from_slice(&raw).map_err(|_|invalid())?).map_err(|_|invalid())
    }
    pub(super) fn sign(request:Dispatch,native_grant_sha256:Sha256Digest,current_receipt_original:String,
        pending_prepared_original:Option<String>,authority_epoch:AuthorityEpochRefV3,now:u64,key:&SigningKey)->Result<Self,ServiceError>{
        let mut value=Self{api_version:"serverware.nativePublicationSnapshot/v1".into(),native_grant_sha256,request,
            state_sha256:state_sha(&current_receipt_original,&pending_prepared_original)?,current_receipt_original,
            pending_prepared_original,authority_epoch,observed_at_boottime_nanos:now,signature_base64url:String::new()};
        value.validate()?;
        value.signature_base64url=URL_SAFE_NO_PAD.encode(key.sign(&super::super::protocol::domain_separated_signature_preimage(
            SNAPSHOT_DOMAIN,&value.payload()?)?).to_bytes());Ok(value)
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(tag="kind",content="body",rename_all="kebab-case",deny_unknown_fields)]
pub(super) enum Candidate {
    ExistingReceipt,Prepared(PreparedGenerationPublication),
    Commit {publication_revision:u64,predecessor_generation_sha256:Option<Sha256Digest>,prepared:PreparedGenerationPublication},
    Abort,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Core {
    pub(super) api_version:String,pub(super) native_grant_sha256:Sha256Digest,pub(super) request:Dispatch,
    pub(super) snapshot:Snapshot,pub(super) candidate:Candidate,pub(super) observed_at_unix_nanos:i64,
    pub(super) trust_checkpoint_sha256:Sha256Digest,pub(super) signing_key_id:Sha256Digest,pub(super) signing_key_spki_sha256:Sha256Digest,
}
fn decode_artifact<T:serde::de::DeserializeOwned+Serialize>(artifact:&Artifact,kind:Kind)->Result<T,ServiceError>{
    require(artifact.kind==kind)?;decode_canonical_frame(&artifact.exact_bytes().map_err(|_|invalid())?)
}
fn candidate(admission:&Admission,snapshot:&Snapshot)->Result<Candidate,ServiceError>{
    admission.request(&snapshot.request)?;
    let current:Receipt=original(&snapshot.current_receipt_original)?;
    current.validate_deserialized_invariants().map_err(|_|invalid())?;
    let pending:Option<PreparedGenerationPublication>=snapshot.pending_prepared_original.as_ref().map(|v|original(v)).transpose()?;
    let actual=current.published_generation_sha256.as_ref().or(current.committed_generation_sha256.as_ref());
    match &snapshot.request {
        Dispatch::RecoverCurrentState{..}=>Ok(Candidate::ExistingReceipt),
        Dispatch::PrepareGenerationPublication{previous,successor,..}=>{
            let successor:ShadowGenerationIdentity=decode_artifact(successor,Kind::ShadowGenerationIdentity)?;
            successor.validate().map_err(|_|invalid())?;
            require(successor.generation_id()==&admission.scope.generation_id
                && successor.assignment_revision()==admission.scope.assignment_revision
                && successor.ingress_range_start_sequence()==admission.first_ingress_sequence
                && successor.publication_reconciliation_receipt_sha256()==&current.signed_receipt_sha256
                && successor.signed_publication_revision()==current.publication_revision
                && successor.authoritative_ledger_event_ordinal()==current.ledger_event_ordinal
                && successor.authoritative_ledger_head_sha256()==&current.ledger_head_sha256
                && successor.authoritative_spool_root_sha256()==&current.spool_root_sha256)?;
            let previous:Option<ShadowGenerationIdentity>=previous.as_ref().map(|v|decode_artifact(v,Kind::ShadowGenerationIdentity)).transpose()?;
            if let Some(value)=&previous{value.validate().map_err(|_|invalid())?;}
            let same=actual==Some(successor.generation_id());
            require(same || actual==previous.as_ref().map(|v|v.generation_id()))?;
            require(actual.is_some() || current.state==State::Uninstalled)?;
            let (first,last,preparation)=if same {
                require(current.state==State::Published)?;
                (current.first_ingress_sequence.ok_or_else(invalid)?,current.last_ingress_sequence.ok_or_else(invalid)?,
                    current.prepared_publication_sha256.clone().ok_or_else(invalid)?)
            }else{
                (admission.first_ingress_sequence,admission.last_ingress_sequence,hash_domain_frames(
                    b"serverware.nativePublicationPreparedState/v1",&[&encode_canonical_frame(&(
                        &snapshot.state_sha256,&snapshot.request,admission.first_ingress_sequence,admission.last_ingress_sequence))?]))
            };
            require(first==admission.first_ingress_sequence && last==admission.last_ingress_sequence)?;
            let range=hash_domain_frames(b"serverware.policyShadowPersistedSequenceRange/v1",&[&canonical_json_bytes(&(
                successor.generation_id(),first,last,successor.ingress_range_predecessor_head_sha256())).map_err(|_|invalid())?]);
            let mut prepared=PreparedGenerationPublication::from_custody(previous.as_ref(),&successor,first,last,
                current.ledger_event_ordinal,current.ledger_head_sha256.clone(),range,current.spool_root_sha256.clone(),preparation)
                .map_err(|_|invalid())?;
            if same{prepared.expected_predecessor_generation_sha256=current.predecessor_generation_sha256.clone();}
            require(pending.as_ref().is_none_or(|held|held==&prepared))?;
            Ok(Candidate::Prepared(prepared))
        },
        Dispatch::CommitGenerationPublication{prepared,..}=>{
            let prepared:PreparedGenerationPublication=decode_artifact(prepared,Kind::PreparedGenerationPublication)?;
            require(pending.as_ref()==Some(&prepared) && prepared.successor_generation_sha256==admission.scope.generation_id)?;
            if actual==Some(&admission.scope.generation_id){
                require(current.state==State::Published && current.prepared_publication_sha256.as_ref()==Some(prepared.preparation_receipt_sha256())
                    && current.first_ingress_sequence==Some(prepared.first_ingress_sequence)
                    && current.last_ingress_sequence==Some(prepared.last_ingress_sequence))?;
                Ok(Candidate::ExistingReceipt)
            }else{
                require(prepared.expected_predecessor_generation_sha256.as_ref()==actual)?;
                Ok(Candidate::Commit{publication_revision:current.publication_revision.checked_add(1).ok_or_else(invalid)?,
                    predecessor_generation_sha256:actual.cloned(),prepared})
            }
        },
        Dispatch::AbortGenerationPublication{prepared,..}=>{
            let prepared:PreparedGenerationPublication=decode_artifact(prepared,Kind::PreparedGenerationPublication)?;
            require(pending.as_ref()==Some(&prepared) && prepared.successor_generation_sha256==admission.scope.generation_id)?;
            Ok(Candidate::Abort)
        },
        _=>Err(invalid()),
    }
}
impl Core {
    pub(super) fn new(admission:&Admission,snapshot:Snapshot,native:&RoleKey,now:i64,checkpoint:Sha256Digest)->Result<Self,ServiceError>{
        let value=Self{api_version:"serverware.nativePublicationCore/v1".into(),native_grant_sha256:native.grant_sha256.clone(),
            request:snapshot.request.clone(),candidate:candidate(admission,&snapshot)?,snapshot,observed_at_unix_nanos:now,
            trust_checkpoint_sha256:checkpoint,signing_key_id:native.key_id.clone(),signing_key_spki_sha256:native.key_spki_sha256.clone()};
        value.validate(admission,native)?;Ok(value)
    }
    pub(super) fn validate(&self,admission:&Admission,native:&RoleKey)->Result<(),ServiceError>{
        admission.validate(native)?;admission.request(&self.request)?;self.snapshot.validate()?;
        admission.verify_receipt(&self.snapshot.current_receipt_original,native)?;
        require(self.api_version=="serverware.nativePublicationCore/v1" && self.request==self.snapshot.request
            && self.native_grant_sha256==native.grant_sha256 && self.snapshot.native_grant_sha256==native.grant_sha256
            && self.signing_key_id==native.key_id && self.signing_key_spki_sha256==native.key_spki_sha256
            && self.observed_at_unix_nanos>0 && self.trust_checkpoint_sha256!=Sha256Digest::compute(&[])
            && self.candidate==candidate(admission,&self.snapshot)?)
    }
    pub(super) fn identity(&self)->Result<Sha256Digest,ServiceError>{
        Ok(hash_domain_frames(b"serverware.nativePublicationCore/v1",&[&encode_canonical_frame(self)?]))
    }
    pub(super) fn retrieval_id(&self,namespace:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        Ok(hash_domain_frames(b"serverware.nativePublicationRetrievalId/v1",&[namespace.as_str().as_bytes(),self.identity()?.as_str().as_bytes()]))
    }
    pub(super) fn retrieval_proof(&self,scope:&[u8],id:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        Ok(hash_domain_frames(b"serverware.nativePublicationRetrievalProof/v1",&[scope,id.as_str().as_bytes(),&encode_canonical_frame(self)?]))
    }
    pub(super) fn payload(&self,stored:&Stored)->Result<Vec<u8>,ServiceError>{
        let Candidate::Commit{publication_revision,predecessor_generation_sha256,prepared}=&self.candidate else{return Err(invalid());};
        let current:Receipt=original(&self.snapshot.current_receipt_original)?;
        canonical_json_bytes(&serde_json::json!([State::Published,publication_revision,predecessor_generation_sha256,
            Some(&prepared.successor_generation_sha256),Some(&prepared.successor_generation_sha256),
            Some(prepared.first_ingress_sequence),Some(prepared.last_ingress_sequence),current.ledger_event_ordinal,
            &current.ledger_head_sha256,&current.spool_root_sha256,Some(prepared.preparation_receipt_sha256()),
            self.observed_at_unix_nanos,&self.trust_checkpoint_sha256,sha(stored)?,&stored.payload.retrieval_id_sha256,
            &stored.payload.retrieval_proof_sha256,Role::PublicationReconciliation,&self.signing_key_id,&self.signing_key_spki_sha256]))
            .map_err(|_|invalid())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Prepared {pub(super) core:Core,pub(super) prepared_at_boottime_nanos:u64,pub(super) signature:CanonicalEd25519Signature}
impl Prepared {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{Ok(signature_preimage(PREPARED_DOMAIN,
        &encode_canonical_frame(&(&self.core,self.prepared_at_boottime_nanos))?))}
    pub(super) fn verify(&self,admission:&Admission,native:&RoleKey,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        self.core.snapshot.verify(history)?;self.verify_native(admission,native)
    }
    pub(super) fn verify_with_key(&self,admission:&Admission,native:&RoleKey,epoch:&AuthorityEpochRefV3,key:&VerifyingKey)
        ->Result<(),ServiceError>{self.core.snapshot.verify_with_key(epoch,key)?;self.verify_native(admission,native)}
    fn verify_native(&self,admission:&Admission,native:&RoleKey)->Result<(),ServiceError>{
        self.core.validate(admission,native)?;let binding=self.core.request.binding();
        require(self.core.snapshot.observed_at_boottime_nanos<=self.prepared_at_boottime_nanos
            && self.prepared_at_boottime_nanos<binding.operation_deadline_boottime_nanos)?;
        native.material()?.verify_strict(&self.preimage()?,&Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
pub(super) fn stored_verify(stored:&Stored,prepared:&Prepared,admission:&Admission,retrieval:&RoleKey)->Result<(),ServiceError>{
    require(retrieval.role==AuthorityRole::CustodyRetrievalResponse && stored.payload.grant_sha256==retrieval.grant_sha256)?;
    stored_verify_key(stored,prepared,admission,&RetrievalAuthority{key_id:retrieval.key_id.clone(),
        key_spki_sha256:retrieval.key_spki_sha256.clone(),public_key_base64url:retrieval.public_key_base64url.clone()})
}
pub(super) fn stored_verify_assigned(stored:&Stored,prepared:&Prepared,admission:&Admission,retrieval:&RetrievalAuthority,
    guest:&guest::GuestClosureBinding)->Result<(),ServiceError>{
    require(&stored.payload.guest==guest)?;stored_verify_key(stored,prepared,admission,retrieval)
}
fn stored_verify_key(stored:&Stored,prepared:&Prepared,admission:&Admission,retrieval:&RetrievalAuthority)->Result<(),ServiceError>{
    let core=&prepared.core;let p=&stored.payload;
    require(matches!(core.candidate,Candidate::Commit{..})
        && p.api_version=="serverware.nativePublicationStorage/v1" && p.grant_sha256!=Sha256Digest::compute(&[])
        && p.signing_key_id==retrieval.key_id && p.signing_key_spki_sha256==retrieval.key_spki_sha256
        && p.core_sha256==core.identity()? && p.object_sha256==sha(core)? && p.fsverity_sha256!=Sha256Digest::compute(&[])
        && p.sequence>0 && p.sequence<=128 && p.previous_head_sha256!=Sha256Digest::compute(&[])
        && p.retrieval_id_sha256==core.retrieval_id(&admission.scope.retrieval_namespace_sha256)?
        && p.retrieval_proof_sha256==core.retrieval_proof(admission.proof_scope_original.as_bytes(),&p.retrieval_id_sha256)?
        && prepared.prepared_at_boottime_nanos<=p.stored_at_boottime_nanos && p.stored_at_boottime_nanos<p.original_deadline_boottime_nanos
        && p.original_deadline_boottime_nanos==core.request.binding().operation_deadline_boottime_nanos)?;
    retrieval.material()?.verify_strict(&signature_preimage(STORAGE_DOMAIN,&encode_canonical_frame(p)?),
        &Signature::from_bytes(&stored.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
}
pub(super) fn final_artifact(core:&Core,stored:Option<&Stored>,sign:impl FnOnce(&[u8])->Result<String,ServiceError>)
    ->Result<Option<Artifact>,ServiceError>{
    Ok(match &core.candidate {
        Candidate::ExistingReceipt=>{
            require(stored.is_none())?;let receipt:Receipt=original(&core.snapshot.current_receipt_original)?;
            Some(Artifact::from_serializable(Kind::PublicationReconciliationReceipt,&receipt).map_err(|_|invalid())?)
        },
        Candidate::Prepared(prepared)=>{require(stored.is_none())?;
            Some(Artifact::from_serializable(Kind::PreparedGenerationPublication,prepared).map_err(|_|invalid())?)},
        Candidate::Abort=>{require(stored.is_none())?;None},
        Candidate::Commit{publication_revision,predecessor_generation_sha256,prepared}=>{
            let stored=stored.ok_or_else(invalid)?;let current:Receipt=original(&core.snapshot.current_receipt_original)?;
            let payload=core.payload(stored)?;let signature=sign(&payload)?;
            let signed=hash_domain_frames(b"serverware.policyShadowPublicationReconciliationReceipt/v1",&[&payload,signature.as_bytes()]);
            let receipt=Receipt::from_custody(State::Published,*publication_revision,predecessor_generation_sha256.clone(),
                Some(prepared.successor_generation_sha256.clone()),Some(prepared.successor_generation_sha256.clone()),
                Some(prepared.first_ingress_sequence),Some(prepared.last_ingress_sequence),current.ledger_event_ordinal,
                current.ledger_head_sha256,current.spool_root_sha256,Some(prepared.preparation_receipt_sha256().clone()),
                core.observed_at_unix_nanos,core.trust_checkpoint_sha256.clone(),sha(stored)?,stored.payload.retrieval_id_sha256.clone(),
                stored.payload.retrieval_proof_sha256.clone(),core.signing_key_id.clone(),core.signing_key_spki_sha256.clone(),signature,signed)
                .map_err(|_|invalid())?;
            Some(Artifact::from_serializable(Kind::PublicationReconciliationReceipt,&receipt).map_err(|_|invalid())?)
        },
    })
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Proposal {
    pub(super) api_version:String,pub(super) prepared:Prepared,pub(super) stored:Option<Stored>,
    pub(super) artifact:Option<Artifact>,pub(super) completed_at_boottime_nanos:u64,pub(super) signature:CanonicalEd25519Signature,
}
impl Proposal {
    pub(super) fn payload(&self)->Result<Vec<u8>,ServiceError>{encode_canonical_frame(&(&self.api_version,&self.prepared,
        &self.stored,&self.artifact,self.completed_at_boottime_nanos))}
    pub(super) fn verify(&self,admission:&Admission,native:&RoleKey,retrieval:&RoleKey,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        self.prepared.verify(admission,native,history)?;self.verify_complete(admission,native,retrieval)
    }
    pub(super) fn verify_with_key(&self,admission:&Admission,native:&RoleKey,retrieval:&RoleKey,
        epoch:&AuthorityEpochRefV3,key:&VerifyingKey)->Result<(),ServiceError>{
        self.prepared.verify_with_key(admission,native,epoch,key)?;self.verify_complete(admission,native,retrieval)
    }
    fn verify_complete(&self,admission:&Admission,native:&RoleKey,retrieval:&RoleKey)->Result<(),ServiceError>{
        if let Some(stored)=&self.stored{stored_verify(stored,&self.prepared,admission,retrieval)?;}
        self.verify_artifact(admission,native)
    }
    pub(super) fn verify_assigned(&self,admission:&Admission,native:&RoleKey,retrieval:&RetrievalAuthority,
        guest:&guest::GuestClosureBinding,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        self.prepared.verify(admission,native,history)?;
        if let Some(stored)=&self.stored{stored_verify_assigned(stored,&self.prepared,admission,retrieval,guest)?;}
        self.verify_artifact(admission,native)
    }
    fn verify_artifact(&self,admission:&Admission,native:&RoleKey)->Result<(),ServiceError>{
        let core=&self.prepared.core;
        require(self.api_version=="serverware.nativePublicationProposal/v1"
            && self.completed_at_boottime_nanos>=self.prepared.prepared_at_boottime_nanos
            && self.completed_at_boottime_nanos<core.request.binding().operation_deadline_boottime_nanos)?;
        if let Some(stored)=&self.stored{
            require(self.completed_at_boottime_nanos>=stored.payload.stored_at_boottime_nanos)?;}
        let expected=final_artifact(core,self.stored.as_ref(),|payload|{
            let artifact=self.artifact.as_ref().ok_or_else(invalid)?;
            let receipt:Receipt=decode_artifact(artifact,Kind::PublicationReconciliationReceipt)?;
            require(receipt.canonical_payload().map_err(|_|invalid())?==payload)?;
            admission.verify_receipt(&text(&receipt)?,native)?;Ok(receipt.signature.0.clone())
        })?;
        require(self.artifact==expected)?;
        native.material()?.verify_strict(&signature_preimage(PROPOSAL_DOMAIN,&self.payload()?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
    pub(super) fn require_result(&self,result:&ResultBody)->Result<(),ServiceError>{
        require(match (&self.prepared.core.candidate,&self.artifact,result) {
            (Candidate::ExistingReceipt|Candidate::Commit{..},Some(artifact),ResultBody::SealedArtifact{exact_signed_artifact,..})=>
                exact_signed_artifact.artifact==*artifact,
            (Candidate::Prepared(_),Some(artifact),ResultBody::Artifact(actual))=>actual==artifact,
            (Candidate::Abort,None,ResultBody::Aborted{abort_evidence_sha256})=>
                *abort_evidence_sha256==self.prepared.core.identity()?,
            _=>false,
        })
    }
    pub(super) fn next_state(&self)->Result<(String,Option<String>),ServiceError>{
        let core=&self.prepared.core;let snapshot=&core.snapshot;
        match &core.candidate {
            Candidate::Prepared(prepared)=>Ok((snapshot.current_receipt_original.clone(),Some(text(prepared)?))),
            Candidate::Commit{..}=>Ok((String::from_utf8(self.artifact.as_ref().ok_or_else(invalid)?.exact_bytes()
                .map_err(|_|invalid())?).map_err(|_|invalid())?,None)),
            Candidate::Abort=>Ok((snapshot.current_receipt_original.clone(),None)),
            Candidate::ExistingReceipt=>Ok((snapshot.current_receipt_original.clone(),
                if matches!(core.request,Dispatch::CommitGenerationPublication{..}){None}else{snapshot.pending_prepared_original.clone()})),
        }
    }
}
