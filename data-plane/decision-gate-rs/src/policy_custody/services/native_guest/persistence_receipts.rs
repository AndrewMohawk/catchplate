//! Closed typed extraction of the receipt actually returned by each current
//! production dispatch operation. No field walking or caller-selected payload.
use super::*;
use crate::policy_shadow::policy_custody::production_dispatch::{CanonicalProductionArtifactV4 as Artifact,
    ProductionArtifactKindV4 as ArtifactKind,ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as DispatchResult};

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Receipt {
    pub(super) signer_role:PolicyShadowCustodySignerRole,
    pub(super) persistence_receipt_sha256:Sha256Digest,
    pub(super) canonical_payload_base64url:String,
    pub(super) signed_authority_payload_base64url:String,
    pub(super) signing_key_id:Sha256Digest,
    pub(super) signing_key_spki_sha256:Sha256Digest,
    pub(super) signature:CanonicalEd25519Signature,
    pub(super) observed_at_unix_nanos:i64,
    pub(super) trusted_time_checkpoint_sha256:Sha256Digest,
}
fn decode<T:for<'de> Deserialize<'de>+Serialize>(artifact:&Artifact,kind:ArtifactKind)->Result<T,ShadowError>{
    require(artifact.kind==kind)?;guest::exact(&artifact.exact_bytes().map_err(fail)?)
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {generation_id:Sha256Digest,ingress_sequence:u64,request_binding_sha256:Sha256Digest,
    request_commitment_sha256:Sha256Digest,phase:ShadowSpoolPhase,event_sha256:Sha256Digest,canonical_event_bytes:Vec<u8>}
impl Event {fn actual(self)->Result<ShadowSpoolEvent,ShadowError>{ShadowSpoolEvent::new(self.generation_id,self.ingress_sequence,
    self.request_binding_sha256,self.request_commitment_sha256,self.phase,self.event_sha256,self.canonical_event_bytes)}}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {generation_id:Sha256Digest,ingress_sequence:u64,terminal_event_sha256:Sha256Digest,terminal_event:Event}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Compaction {generation_id:Sha256Digest,old_spool_head_sha256:Sha256Digest,compacted_first_event_ordinal:u64,
    compacted_last_event_ordinal:u64,compacted_ordered_range_root_sha256:Sha256Digest,compacted_record_count:u64,
    compacted_through_spill_receipt_sha256:Sha256Digest,retained_successor_event_ordinal:Option<u64>,
    retained_successor_head_sha256:Option<Sha256Digest>,expected_new_spool_root_sha256:Sha256Digest}
impl Compaction {fn actual(self)->Result<AuthenticatedSpoolCompactionRequest,ShadowError>{AuthenticatedSpoolCompactionRequest::new(
    self.generation_id,self.old_spool_head_sha256,self.compacted_first_event_ordinal,self.compacted_last_event_ordinal,
    self.compacted_ordered_range_root_sha256,self.compacted_record_count,self.compacted_through_spill_receipt_sha256,
    self.retained_successor_event_ordinal,self.retained_successor_head_sha256,self.expected_new_spool_root_sha256)}}
macro_rules! receipt {
    ($wire:expr,$role:expr,$method:ident,$scope:expr)=>{{
        let wire=$wire;wire.validate_deserialized_invariants()?;
        let role=$role;let payload=wire.$method()?;
        Receipt{signer_role:role,persistence_receipt_sha256:wire.persistence_receipt_sha256.clone(),
            canonical_payload_base64url:URL_SAFE_NO_PAD.encode(&payload),
            signed_authority_payload_base64url:URL_SAFE_NO_PAD.encode($scope.authority_payload(role,&payload)?),
            signing_key_id:wire.signing_key_id.clone(),signing_key_spki_sha256:wire.signing_key_spki_sha256.clone(),
            signature:wire.signature.clone(),observed_at_unix_nanos:wire.trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256:wire.trusted_time_checkpoint_sha256.clone()}
    }};
}
fn spill(wire:SignedShadowSpillReceipt,scope:&scope::Scope)->Result<Receipt,ShadowError>{
    let role=wire.signer_role();Ok(receipt!(&wire,role,canonical_signature_payload,scope))
}
pub(super) fn is_adopted(request:&Dispatch,result:&DispatchResult,adoption:Option<&Adoption>)->Result<bool,ShadowError>{
    let Some(adoption)=adoption else{return Ok(false);};
    let (Dispatch::RecoverCurrentState{..},DispatchResult::SealedArtifact{exact_signed_artifact,..})=(request,result)
        else{return Ok(false);};
    require(exact_signed_artifact.artifact.kind==ArtifactKind::PublicationReconciliationReceipt)?;
    Ok(exact_signed_artifact.artifact.exact_bytes().map_err(fail)?==adoption.baseline_original()?.as_bytes())
}
pub(super) fn extract(request:&Dispatch,result:&DispatchResult,scope:&scope::Scope,adoption:Option<&Adoption>)->Result<Option<Receipt>,ShadowError>{
    use PolicyShadowCustodySignerRole as Role;
    let value=match (request,result) {
        (Dispatch::RecoverCurrentState{..}|Dispatch::CommitGenerationPublication{..},
            DispatchResult::SealedArtifact{exact_signed_artifact,..})=>{
            let wire:PublicationReconciliationReceiptWire=decode(&exact_signed_artifact.artifact,ArtifactKind::PublicationReconciliationReceipt)?;
            let mut receipt=receipt!(&wire,Role::PublicationReconciliation,canonical_payload,scope);
            if let Some(adoption)=adoption {
                require(is_adopted(request,result,Some(adoption))?)?;
                receipt.signed_authority_payload_base64url=URL_SAFE_NO_PAD.encode(adoption.prior_authority_payload(&wire.canonical_payload()?)?);
            }
            receipt
        },
        (Dispatch::BeginIngress{request_binding_sha256,..},DispatchResult::Artifact(artifact))=>{
            let wire:IngressCustodyAdmissionWire=decode(artifact,ArtifactKind::IngressCustodyAdmission)?;
            match wire {
                IngressCustodyAdmissionWire::NativeAssigned(wire)=>{
                    require(wire.api_version=="catchplate.nativeIngressCustodyAdmission/v1"
                        && wire.sampling_commitment.context.request_binding_sha256==*request_binding_sha256
                        && wire.opening_spill_receipt.request_binding_sha256==*request_binding_sha256
                        && wire.opening_spill_receipt.event_phase==ShadowSpoolPhase::IngressOpen)?;
                    let (generation,sampling)=crate::policy_shadow::native_ingress::decode_event(&wire.opening_spill_receipt.canonical_event_bytes)?;
                    require(sampling==wire.sampling_commitment && wire.opening_spill_receipt.matches_event(&sampling.event(&generation)?))?;
                    spill(wire.opening_spill_receipt,scope)?
                },
                IngressCustodyAdmissionWire::Assigned(wire)=>{
                    require(wire.sampling.request_binding_sha256==*request_binding_sha256
                        && wire.opening_spill_receipt.request_binding_sha256==*request_binding_sha256
                        && wire.opening_spill_receipt.event_phase==ShadowSpoolPhase::IngressOpen)?;
                    spill(wire.opening_spill_receipt,scope)?
                },
                IngressCustodyAdmissionWire::Unavailable(wire)=>{
                    require(wire.request_binding_sha256==*request_binding_sha256)?;
                    receipt!(&wire,Role::UnavailableIngress,canonical_signature_payload,scope)
                },
            }
        },
        (Dispatch::ReserveSpoolAppend{event,..},DispatchResult::SealedArtifact{exact_signed_artifact,..})=>{
            let event=decode::<Event>(event,ArtifactKind::ShadowSpoolEvent)?.actual()?;
            let wire:SpoolAppendReservationReceiptWire=decode(&exact_signed_artifact.artifact,ArtifactKind::SpoolAppendReservationOutcome)?;
            require(wire.generation_id==event.generation_id && wire.ingress_sequence==event.ingress_sequence
                && wire.event_sha256==event.event_sha256)?;
            receipt!(&wire,Role::LedgerAppend,canonical_signature_payload,scope)
        },
        (Dispatch::AppendSpoolEvent{event,..},DispatchResult::Artifact(artifact))=>{
            let event=decode::<Event>(event,ArtifactKind::ShadowSpoolEvent)?.actual()?;
            let wire:SignedShadowSpillReceipt=decode(artifact,ArtifactKind::ShadowSpillReceipt)?;
            require(wire.matches_event(&event))?;spill(wire,scope)?
        },
        (Dispatch::AppendTerminal{request,..},DispatchResult::Artifact(artifact))=>{
            let raw:Terminal=decode(request,ArtifactKind::TerminalSlotAppendRequest)?;
            require(raw.generation_id==raw.terminal_event.generation_id && raw.ingress_sequence==raw.terminal_event.ingress_sequence
                && raw.terminal_event_sha256==raw.terminal_event.event_sha256)?;
            let original=TerminalSlotAppendRequest::new(raw.terminal_event.actual()?)?;
            let wire:TerminalSlotAppendOutcomeWire=decode(artifact,ArtifactKind::TerminalSlotAppendOutcome)?;
            let (wire,_)=wire.receipt_and_expected_event(&original)?;
            match wire {TerminalSlotAppendOutcomeWire::Committed(w)|TerminalSlotAppendOutcomeWire::Existing(w)
                |TerminalSlotAppendOutcomeWire::Fork(w)=>spill(w,scope)?}
        },
        (Dispatch::CompactSpool{request,..},DispatchResult::Artifact(artifact))=>{
            let original=decode::<Compaction>(request,ArtifactKind::AuthenticatedSpoolCompactionRequest)?.actual()?;
            let wire:AuthenticatedSpoolCompactionReceipt=decode(artifact,ArtifactKind::SpoolCompactionReceipt)?;
            require(wire.matches_request(&original))?;
            receipt!(&wire,Role::SpoolCompaction,canonical_signature_payload,scope)
        },
        (Dispatch::AppendActiveEffectBarrier{preparation,..},DispatchResult::SealedArtifact{exact_signed_artifact,..})=>{
            let original:ActiveEffectPreparation=decode(preparation,ArtifactKind::ActiveEffectPreparation)?;
            let wire:ActiveEffectBarrierReceiptWire=decode(&exact_signed_artifact.artifact,ArtifactKind::ActiveEffectPermit)?;
            require(wire.preparation==original)?;receipt!(&wire,Role::ActiveEffectBarrier,canonical_payload,scope)
        },
        (Dispatch::CommitActiveEffect{terminal_state,result_sha256,..},DispatchResult::Artifact(artifact))=>{
            let wire:ActiveEffectCommitReceiptWire=decode(artifact,ArtifactKind::ActiveEffectCommitReceipt)?;
            let terminal_state:ActiveEffectCommitState=decode(terminal_state,ArtifactKind::ActiveEffectCommitState)?;
            require(wire.terminal_state==terminal_state && wire.result_sha256==*result_sha256)?;
            receipt!(&wire,Role::ActiveEffectCommit,canonical_payload,scope)
        },
        (Dispatch::ReconcileActiveEffect{effect_id_sha256,..},DispatchResult::Artifact(artifact))=>{
            let wire:ActiveEffectCommitReceiptWire=decode(artifact,ArtifactKind::ActiveEffectCommitReceipt)?;
            require(wire.effect_id_sha256==*effect_id_sha256)?;
            receipt!(&wire,Role::ActiveEffectCommit,canonical_payload,scope)
        },
        (Dispatch::ConsumeAndPublishActivation{transaction,..},DispatchResult::Artifact(artifact))=>{
            let original=crate::policy_shadow::policy_custody::production_dispatch::persistence_activation_transaction_sha256(transaction).map_err(fail)?;
            let wire:ActivationPublicationReceiptWire=decode(artifact,ArtifactKind::ActivationPublicationReceipt)?;
            require(wire.transaction_sha256==original)?;
            receipt!(&wire,Role::ActivationPublication,canonical_payload,scope)
        },
        // These results do not claim a generic persisted receipt. Preserve
        // their actual tagged originals in the commit chain, without making
        // them satisfy a later persistence lookup.
        (Dispatch::VerifyCheckpointSuccessor{..}|Dispatch::VerifyCurrentCheckpointHead{..}
            |Dispatch::VerifyObservationEvidence{..}|Dispatch::AbortGenerationPublication{..},DispatchResult::Verified)=>return Ok(None),
        (Dispatch::AbortGenerationPublication{..},DispatchResult::Aborted{abort_evidence_sha256})=>{
            require(*abort_evidence_sha256!=Sha256Digest::compute(&[]))?;return Ok(None)
        },
        (Dispatch::PrepareGenerationPublication{..},DispatchResult::Artifact(a))=>{
            require(a.kind==ArtifactKind::PreparedGenerationPublication)?;a.exact_bytes().map_err(fail)?;return Ok(None)
        },
        (Dispatch::CommitRequest{..},DispatchResult::Artifact(a))=>{
            let _:RequestCommitment=decode(a,ArtifactKind::RequestCommitment)?;return Ok(None)
        },
        _=>return Err(ShadowError::BindingDrift),
    };
    Ok(Some(value))
}
