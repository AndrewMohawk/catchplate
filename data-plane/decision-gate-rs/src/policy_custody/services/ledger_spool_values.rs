//! Acyclic, source-fixed spool material. Storage addresses the typed core,
//! never a receipt which already contains its own retrieval addresses.
use super::*;
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    CanonicalProductionArtifactV4 as Artifact,ProductionArtifactKindV4 as Kind};
use crate::policy_shadow::{ShadowSpoolEvent,ShadowSpoolPhase,ShadowSpoolDisposition,
    PolicyShadowCustodySignerRole,SignedShadowSpillReceipt,SpoolAppendReservationReceiptWire,
    CanonicalEd25519Signature,canonical_json_bytes,hash_domain_frames};
pub(super) const CORE_API:&str="serverware.nativeLedgerSpoolCore/v1";
pub(super) const COMPLETION_CORE_API:&str="serverware.nativeLedgerSpoolCore/v2";
pub(super) const PREPARED_DOMAIN:&str="serverware.nativeLedgerSpoolPreparation.signature/v1";
pub(super) const STORED_DOMAIN:&str="serverware.nativeLedgerSpoolStorage.signature/v1";
pub(super) const MAX_CORE:usize=512*1024;
pub(super) fn invalid()->ServiceError {ServiceError::Invalid("native spool original differs")}
fn require(v:bool)->Result<(),ServiceError>{if v{Ok(())}else{Err(invalid())}}
pub(super) fn sha<T:Serialize>(v:&T)->Result<Sha256Digest,ServiceError>{Ok(Sha256Digest::compute(&encode_canonical_frame(v)?))}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
pub(super) enum Phase {Ingress,Reserve,Append,Terminal,Unavailable}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub(super) generation_id:Sha256Digest,pub(super) ingress_sequence:u64,pub(super) request_binding_sha256:Sha256Digest,
    pub(super) request_commitment_sha256:Sha256Digest,pub(super) phase:ShadowSpoolPhase,pub(super) event_sha256:Sha256Digest,pub(super) canonical_event_bytes:Vec<u8>,
}
impl Event {
    pub(super) fn generation_id(&self)->&Sha256Digest{&self.generation_id}
    pub(super) fn actual(&self)->Result<ShadowSpoolEvent,ServiceError>{
        if self.phase==ShadowSpoolPhase::IngressOpen {
            let (generation,sampling)=crate::policy_shadow::native_ingress::decode_event(&self.canonical_event_bytes).map_err(|_|invalid())?;
            let event=sampling.event(&generation).map_err(|_|invalid())?;
            require(self.generation_id==generation.generation_id().clone() && self.ingress_sequence==sampling.context.ingress_sequence
                && self.request_binding_sha256==sampling.context.request_binding_sha256
                && self.request_commitment_sha256==sampling.sha256().map_err(|_|invalid())?
                && self.event_sha256==Sha256Digest::compute(&self.canonical_event_bytes))?;
            return Ok(event);
        }
        require(matches!(self.phase,ShadowSpoolPhase::Capture|ShadowSpoolPhase::Decision|ShadowSpoolPhase::Response
            |ShadowSpoolPhase::Candidate|ShadowSpoolPhase::RangeClosure
            |ShadowSpoolPhase::PreDispatchTerminal|ShadowSpoolPhase::PostDispatchTerminal))?;
        ShadowSpoolEvent::new(self.generation_id.clone(),self.ingress_sequence,self.request_binding_sha256.clone(),
            self.request_commitment_sha256.clone(),self.phase,self.event_sha256.clone(),self.canonical_event_bytes.clone()).map_err(|_|invalid())
    }
    pub(super) fn from_request(request:&Dispatch)->Result<(Phase,Self),ServiceError>{
        request.validate().map_err(|_|invalid())?;
        if let Dispatch::AppendTerminal{request:artifact,..}=request {
            require(artifact.kind==Kind::TerminalSlotAppendRequest)?;
            #[derive(Serialize,Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Terminal {generation_id:Sha256Digest,ingress_sequence:u64,terminal_event_sha256:Sha256Digest,terminal_event:Event}
            let value:Terminal=decode_canonical_frame(&artifact.exact_bytes().map_err(|_|invalid())?)?;
            require(value.generation_id==value.terminal_event.generation_id && value.ingress_sequence==value.terminal_event.ingress_sequence
                && value.terminal_event_sha256==value.terminal_event.event_sha256
                && matches!(value.terminal_event.phase,ShadowSpoolPhase::PreDispatchTerminal|ShadowSpoolPhase::PostDispatchTerminal))?;
            value.terminal_event.actual()?;return Ok((Phase::Terminal,value.terminal_event));
        }
        let (phase,artifact)=match request {Dispatch::ReserveSpoolAppend{event,..}=>(Phase::Reserve,event),
            Dispatch::AppendSpoolEvent{event,..}=>(Phase::Append,event),_=>return Err(invalid())};
        require(artifact.kind==Kind::ShadowSpoolEvent)?;
        let value:Self=decode_canonical_frame(&artifact.exact_bytes().map_err(|_|invalid())?)?;
        require(!matches!(value.phase,ShadowSpoolPhase::IngressOpen|ShadowSpoolPhase::PreDispatchTerminal|ShadowSpoolPhase::PostDispatchTerminal))?;
        value.actual()?;Ok((phase,value))
    }
}
/// Independent operation scope. It is not a verified driver or an installed
/// generation; every effect owner also holds its real generation gate.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Scope {
    pub(super) production_configuration_binding_sha256:Sha256Digest,
    pub(super) kernel_driver_identity_sha256:Sha256Digest,
    pub(super) retained_descriptor_set_sha256:Sha256Digest,
    pub(super) driver_generation_receipt_sha256:Sha256Digest,
    pub(super) assignment_payload_sha256:Sha256Digest,pub(super) assignment_revision:u64,
    pub(super) generation_id:Sha256Digest,pub(super) proof_scope_sha256:Sha256Digest,
    pub(super) retrieval_namespace_sha256:Sha256Digest,
    pub(super) issued_at_boottime_nanos:u64,pub(super) expires_at_boottime_nanos:u64,
}
impl Scope {
    pub(super) fn binding(&self,request:&Dispatch)->Result<(),ServiceError>{
        request.validate().map_err(|_|invalid())?;let b=request.binding();
        require(b.production_configuration_binding_sha256==self.production_configuration_binding_sha256
            && b.kernel_driver_identity_sha256==self.kernel_driver_identity_sha256
            && b.retained_descriptor_set_sha256==self.retained_descriptor_set_sha256
            && b.driver_generation_receipt_sha256==self.driver_generation_receipt_sha256
            && self.assignment_revision>0
            && self.issued_at_boottime_nanos>0 && self.issued_at_boottime_nanos<=b.opened_at_boottime_nanos
            && b.cleanup_deadline_boottime_nanos<=self.expires_at_boottime_nanos)?;
        Ok(())
    }
    pub(super) fn request(&self,request:&Dispatch)->Result<(Phase,Event),ServiceError>{
        self.binding(request)?;let (phase,event)=Event::from_request(request)?;
        require(event.generation_id==self.generation_id)?;Ok((phase,event))
    }
    pub(super) fn prepared(&self,value:&Prepared,grant:&Sha256Digest,key:&VerifyingKey)->Result<(),ServiceError>{
        self.binding(&value.core.request)?;value.verify(key)?;
        require(&value.core.native_grant_sha256==grant && value.core.proof_scope_sha256==self.proof_scope_sha256
            && value.core.event.generation_id==self.generation_id
            && value.core.signing_key_spki_sha256==verifying_key_spki_sha256(key).map_err(|_|invalid())?)
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Core {
    pub(super) api_version:String,pub(super) phase:Phase,pub(super) request:Dispatch,
    pub(super) proof_scope_sha256:Sha256Digest,pub(super) native_grant_sha256:Sha256Digest,
    pub(super) allocation_sha256:Sha256Digest,
    pub(super) event:Event,pub(super) event_ordinal:u64,pub(super) predecessor_event_ordinal:u64,
    pub(super) predecessor_head_sha256:Sha256Digest,pub(super) lane:u16,
    pub(super) observed_at_unix_nanos:i64,pub(super) trusted_time_checkpoint_sha256:Sha256Digest,
    pub(super) signing_key_id:Sha256Digest,pub(super) signing_key_spki_sha256:Sha256Digest,
}
impl Core {
    pub(super) fn role(&self)->PolicyShadowCustodySignerRole{match self.phase {
        Phase::Ingress=>PolicyShadowCustodySignerRole::IngressAdmission,
        Phase::Terminal=>PolicyShadowCustodySignerRole::TerminalAppend,
        _=>PolicyShadowCustodySignerRole::LedgerAppend,
    }}
    pub(super) fn disposition(&self)->ShadowSpoolDisposition {
        if self.phase==Phase::Unavailable{ShadowSpoolDisposition::Unavailable}else{ShadowSpoolDisposition::Appended}
    }
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        self.request.validate().map_err(|_|invalid())?;
        match &self.request {
            Dispatch::BeginIngress{request_binding_sha256,..}=>{
                require(self.phase==Phase::Ingress && self.event.phase==ShadowSpoolPhase::IngressOpen
                    && &self.event.request_binding_sha256==request_binding_sha256)?;
                self.event.actual()?;
                let (_,sample)=crate::policy_shadow::native_ingress::decode_event(&self.event.canonical_event_bytes).map_err(|_|invalid())?;
                require(sample.context.observed_at_unix_nanos==self.observed_at_unix_nanos)?;
            },
            _=>{let (phase,event)=Event::from_request(&self.request)?;
                require((self.phase==phase || (self.phase==Phase::Unavailable && phase==Phase::Reserve)) && self.event==event)?;},
        }
        require((self.api_version==CORE_API && !matches!(self.phase,Phase::Terminal|Phase::Unavailable)
                || self.api_version==COMPLETION_CORE_API) && self.allocation_sha256!=Sha256Digest::compute(&[])
            && self.observed_at_unix_nanos>0 && self.lane<64
            && self.event_ordinal==self.predecessor_event_ordinal.checked_add(1).ok_or_else(invalid)?
            && encode_canonical_frame(self)?.len()<=MAX_CORE)?;
        Ok(())
    }
    pub(super) fn event(&self)->Result<ShadowSpoolEvent,ServiceError>{self.validate()?;self.event.actual()}
    pub(super) fn identity(&self)->Result<Sha256Digest,ServiceError>{
        self.validate()?;Ok(hash_domain_frames(self.api_version.as_bytes(),&[&encode_canonical_frame(self)?]))
    }
    pub(super) fn retrieval_id(&self,namespace:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        Ok(hash_domain_frames(b"serverware.nativeLedgerSpoolRetrievalId/v1",&[namespace.as_str().as_bytes(),&encode_canonical_frame(self)?]))
    }
    pub(super) fn retrieval_proof(&self,scope:&[u8],id:&Sha256Digest)->Result<Sha256Digest,ServiceError>{
        require(Sha256Digest::compute(scope)==self.proof_scope_sha256)?;
        Ok(hash_domain_frames(b"serverware.nativeLedgerSpoolRetrievalProof/v1",&[scope,id.as_str().as_bytes(),&encode_canonical_frame(self)?]))
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Prepared {pub(super) core:Core,pub(super) prepared_at_boottime_nanos:u64,pub(super) signature:CanonicalEd25519Signature}
impl Prepared {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{
        Ok(crate::policy_shadow::signature_preimage(PREPARED_DOMAIN,&encode_canonical_frame(&(&self.core,self.prepared_at_boottime_nanos))?))
    }
    pub(super) fn verify(&self,key:&VerifyingKey)->Result<(),ServiceError>{
        self.core.validate()?;let b=self.core.request.binding();
        require(b.opened_at_boottime_nanos<=self.prepared_at_boottime_nanos && self.prepared_at_boottime_nanos<b.operation_deadline_boottime_nanos)?;
        key.verify_strict(&self.preimage()?,&Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct StoredPayload {
    pub(super) api_version:String,pub(super) guest:guest::GuestClosureBinding,pub(super) grant_sha256:Sha256Digest,
    pub(super) core_sha256:Sha256Digest,pub(super) object_sha256:Sha256Digest,pub(super) fsverity_sha256:Sha256Digest,
    pub(super) retrieval_id_sha256:Sha256Digest,pub(super) retrieval_proof_sha256:Sha256Digest,
    pub(super) previous_head_sha256:Sha256Digest,pub(super) sequence:u64,
    pub(super) stored_at_boottime_nanos:u64,pub(super) original_deadline_boottime_nanos:u64,
    pub(super) signing_key_id:Sha256Digest,pub(super) signing_key_spki_sha256:Sha256Digest,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Stored {pub(super) payload:StoredPayload,pub(super) signature:CanonicalEd25519Signature}
impl Stored {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{
        Ok(crate::policy_shadow::signature_preimage(STORED_DOMAIN,&encode_canonical_frame(&self.payload)?))
    }
    pub(super) fn verify(&self,prepared:&Prepared,scope:&[u8],namespace:&Sha256Digest,key:&VerifyingKey)->Result<(),ServiceError>{
        let core=&prepared.core;core.validate()?;let p=&self.payload;
        require(p.api_version=="serverware.nativeLedgerSpoolStorage/v1" && p.core_sha256==core.identity()?
            && p.object_sha256==sha(core)? && p.retrieval_id_sha256==core.retrieval_id(namespace)?
            && p.retrieval_proof_sha256==core.retrieval_proof(scope,&p.retrieval_id_sha256)?
            && p.sequence>0 && p.fsverity_sha256!=Sha256Digest::compute(&[])
            && prepared.prepared_at_boottime_nanos<=p.stored_at_boottime_nanos
            && p.stored_at_boottime_nanos<p.original_deadline_boottime_nanos
            && p.original_deadline_boottime_nanos==core.request.binding().operation_deadline_boottime_nanos)?;
        key.verify_strict(&self.preimage()?,&Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
/// These references are derived only from a checked full storage original.
/// Signing a receipt requires the native caller to verify that original's
/// assigned key, current grant/scope and exact retained one-shot preparation.
pub(super) fn final_artifact(core:&Core,stored:&Stored,sign:impl FnOnce(&[u8])->Result<String,ServiceError>)
    ->Result<Artifact,ServiceError>{
    core.validate()?;let persistence=sha(stored)?;let id=&stored.payload.retrieval_id_sha256;
    let proof=&stored.payload.retrieval_proof_sha256;
    let role=core.role();
    match core.phase {
        Phase::Reserve=>{
            let payload=canonical_json_bytes(&(&core.event.generation_id,core.event.ingress_sequence,core.lane,
                core.event_ordinal,core.predecessor_event_ordinal,&core.predecessor_head_sha256,&core.event.event_sha256,
                core.observed_at_unix_nanos,&core.trusted_time_checkpoint_sha256,&persistence,id,proof,role,
                &core.signing_key_id,&core.signing_key_spki_sha256)).map_err(|_|invalid())?;
            let signature=sign(&payload)?;
            let digest=hash_domain_frames(b"serverware.policyShadowSpoolAppendReservationReceipt/v1",&[&payload,signature.as_bytes()]);
            let wire=SpoolAppendReservationReceiptWire::from_custody(core.event.generation_id.clone(),core.event.ingress_sequence,
                core.lane,core.event_ordinal,core.predecessor_event_ordinal,core.predecessor_head_sha256.clone(),core.event.event_sha256.clone(),
                core.observed_at_unix_nanos,core.trusted_time_checkpoint_sha256.clone(),persistence,id.clone(),proof.clone(),
                core.signing_key_id.clone(),core.signing_key_spki_sha256.clone(),signature,digest).map_err(|_|invalid())?;
            if core.api_version==COMPLETION_CORE_API {
                Artifact::from_serializable(Kind::SpoolAppendReservationOutcome,&crate::policy_shadow::NativeSpoolReservationOutcomeWire{
                    api_version:"serverware.nativeSpoolReservationOutcome/v1".into(),
                    result:crate::policy_shadow::NativeSpoolReservationResultWire::Reserved(wire)}).map_err(|_|invalid())
            }else{Artifact::from_serializable(Kind::SpoolAppendReservationOutcome,&wire).map_err(|_|invalid())}
        }
        Phase::Append|Phase::Ingress|Phase::Terminal|Phase::Unavailable=>{
            let event=core.event()?;let disposition=core.disposition();
            let record=hash_domain_frames(b"serverware.policyShadowSpoolRecord/v1",&[&canonical_json_bytes(&(
                &core.event.generation_id,core.event.ingress_sequence,&core.event.request_binding_sha256,&core.event.request_commitment_sha256,
                core.event.phase,disposition,&core.event.event_sha256,&core.event.canonical_event_bytes,core.event_ordinal,
                core.predecessor_event_ordinal,&core.predecessor_head_sha256,core.observed_at_unix_nanos,
                &core.trusted_time_checkpoint_sha256,&persistence,id,proof)).map_err(|_|invalid())?]);
            let head=hash_domain_frames(b"serverware.policyShadowSpoolHead/v1",&[&canonical_json_bytes(&(
                core.predecessor_event_ordinal,&core.predecessor_head_sha256,core.event_ordinal,&record)).map_err(|_|invalid())?]);
            let payload=canonical_json_bytes(&serde_json::json!([&core.event.generation_id,core.event.ingress_sequence,
                &core.event.request_binding_sha256,&core.event.request_commitment_sha256,core.event_ordinal,core.event.phase,
                disposition,&core.event.event_sha256,&core.event.canonical_event_bytes,core.predecessor_event_ordinal,
                &core.predecessor_head_sha256,&head,core.observed_at_unix_nanos,&core.trusted_time_checkpoint_sha256,
                &persistence,id,proof,role,&core.signing_key_id,&core.signing_key_spki_sha256])).map_err(|_|invalid())?;
            let signature=sign(&payload)?;
            let digest=hash_domain_frames(b"serverware.policyShadowSpillReceipt/v1",&[&canonical_json_bytes(&(
                &record,&head,&core.signing_key_id,&core.signing_key_spki_sha256,CanonicalEd25519Signature(signature.clone()))).map_err(|_|invalid())?]);
            let wire=SignedShadowSpillReceipt::from_custody(&event,core.event_ordinal,disposition,core.predecessor_event_ordinal,
                core.predecessor_head_sha256.clone(),head,core.observed_at_unix_nanos,core.trusted_time_checkpoint_sha256.clone(),
                persistence,id.clone(),proof.clone(),core.signing_key_id.clone(),core.signing_key_spki_sha256.clone(),signature,digest).map_err(|_|invalid())?;
            if core.phase==Phase::Ingress {
                let (_,sampling)=crate::policy_shadow::native_ingress::decode_event(&core.event.canonical_event_bytes).map_err(|_|invalid())?;
                let ingress=crate::policy_shadow::IngressCustodyAdmissionWire::NativeAssigned(crate::policy_shadow::native_ingress::Wire{
                    api_version:"serverware.nativeIngressCustodyAdmission/v1".into(),sampling_commitment:sampling,opening_spill_receipt:wire});
                Artifact::from_serializable(Kind::IngressCustodyAdmission,&ingress).map_err(|_|invalid())
            }else if core.phase==Phase::Terminal {
                Artifact::from_serializable(Kind::TerminalSlotAppendOutcome,&crate::policy_shadow::TerminalSlotAppendOutcomeWire::Committed(wire)).map_err(|_|invalid())
            }else if core.phase==Phase::Unavailable {
                Artifact::from_serializable(Kind::SpoolAppendReservationOutcome,&crate::policy_shadow::NativeSpoolReservationOutcomeWire{
                    api_version:"serverware.nativeSpoolReservationOutcome/v1".into(),
                    result:crate::policy_shadow::NativeSpoolReservationResultWire::Unavailable(wire)}).map_err(|_|invalid())
            }else{Artifact::from_serializable(Kind::ShadowSpillReceipt,&wire).map_err(|_|invalid())}
        }
    }
}
/// Exact inverse boundary for the acyclic retrieval profile. All final fields,
/// including the derived head and every returned storage reference, must match.
pub(super) fn require_final_payload(core:&Core,stored:&Stored,payload:&[u8])->Result<(),ServiceError>{
    core.validate()?;let persistence=sha(stored)?;let p=&stored.payload;
    let expected=match core.phase {
        Phase::Reserve=>canonical_json_bytes(&(&core.event.generation_id,core.event.ingress_sequence,core.lane,
            core.event_ordinal,core.predecessor_event_ordinal,&core.predecessor_head_sha256,&core.event.event_sha256,
            core.observed_at_unix_nanos,&core.trusted_time_checkpoint_sha256,&persistence,&p.retrieval_id_sha256,
            &p.retrieval_proof_sha256,PolicyShadowCustodySignerRole::LedgerAppend,&core.signing_key_id,&core.signing_key_spki_sha256)),
        Phase::Append|Phase::Ingress|Phase::Terminal|Phase::Unavailable=>{
            let record=hash_domain_frames(b"serverware.policyShadowSpoolRecord/v1",&[&canonical_json_bytes(&(
                &core.event.generation_id,core.event.ingress_sequence,&core.event.request_binding_sha256,&core.event.request_commitment_sha256,
                core.event.phase,core.disposition(),&core.event.event_sha256,&core.event.canonical_event_bytes,
                core.event_ordinal,core.predecessor_event_ordinal,&core.predecessor_head_sha256,core.observed_at_unix_nanos,
                &core.trusted_time_checkpoint_sha256,&persistence,&p.retrieval_id_sha256,&p.retrieval_proof_sha256)).map_err(|_|invalid())?]);
            let head=hash_domain_frames(b"serverware.policyShadowSpoolHead/v1",&[&canonical_json_bytes(&(
                core.predecessor_event_ordinal,&core.predecessor_head_sha256,core.event_ordinal,&record)).map_err(|_|invalid())?]);
            canonical_json_bytes(&serde_json::json!([&core.event.generation_id,core.event.ingress_sequence,
                &core.event.request_binding_sha256,&core.event.request_commitment_sha256,core.event_ordinal,core.event.phase,
                core.disposition(),&core.event.event_sha256,&core.event.canonical_event_bytes,core.predecessor_event_ordinal,
                &core.predecessor_head_sha256,&head,core.observed_at_unix_nanos,&core.trusted_time_checkpoint_sha256,&persistence,
                &p.retrieval_id_sha256,&p.retrieval_proof_sha256,
                core.role(),
                &core.signing_key_id,&core.signing_key_spki_sha256]))
        }
    }.map_err(|_|invalid())?;
    require(expected==payload)
}
