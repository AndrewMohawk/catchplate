//! Authenticated native recovery, not RecoveryNotReady relabelled as absence.
//! Retained originals never confer permission to resume an unfinished phase.
use super::*;
use super::generation_service::{Response,Phase};
use super::generation_service_client::Replies;
use super::super::production_dispatch::{ClosedProductionGenerationRequestV4 as Request,
    ClosedProductionGenerationResponseV4 as Completion,ProductionGenerationTransitionV4 as Transition,
    ExactSignedProductionGenerationInstallEnvelopeWireV4 as Installation,
    ProductionGenerationPreparationResultWireV4 as Preparation,ProductionArtifactKindV4 as Kind};
use super::super::terminal_settlement::FiveServiceHistoricalKeyringsV4;
use super::super::authority_history::AuthorityPublicKeyV3;
use crate::policy_shadow::{SignedEnvelope,ProductionCustodyGenerationInstallReceiptPayload,signature_preimage};
pub(in crate::policy_shadow::policy_custody) const API:&str="serverware.nativeGenerationRecovery/v1";
pub(in crate::policy_shadow::policy_custody) const RESPONSE_API:&str="serverware.policyCustodyProductionGeneration/v5";
pub(in crate::policy_shadow::policy_custody) const DOMAIN:&str="serverware.nativeGenerationRecovery.signature/v1";
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct Installed {
    pub(in crate::policy_shadow::policy_custody) prepare_request:Request,pub(in crate::policy_shadow::policy_custody) preparation:Completion,
    pub(in crate::policy_shadow::policy_custody) commit_request:Request,pub(in crate::policy_shadow::policy_custody) installation:Completion,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct Payload {
    pub(in crate::policy_shadow::policy_custody) api_version:String,pub(in crate::policy_shadow::policy_custody) purpose:String,pub(in crate::policy_shadow::policy_custody) request:Request,pub(in crate::policy_shadow::policy_custody) services:Replies,
    pub(in crate::policy_shadow::policy_custody) coordinator_assignment_sha256:Sha256Digest,pub(in crate::policy_shadow::policy_custody) journal_head_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) journal_sequence:u64,pub(in crate::policy_shadow::policy_custody) installed:Option<Installed>,pub(in crate::policy_shadow::policy_custody) observed_at_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct Evidence {
    pub(in crate::policy_shadow::policy_custody) payload:Payload,pub(in crate::policy_shadow::policy_custody) authority_public_key:AuthorityPublicKeyV3,pub(in crate::policy_shadow::policy_custody) signature_base64url:String,
}
fn invalid()->&'static str{"native generation recovery originals are unavailable or inconsistent"}
fn ensure(ok:bool)->Result<(),&'static str>{if ok{Ok(())}else{Err(invalid())}}
fn sha<T:Serialize>(v:&T)->Result<Sha256Digest,&'static str>{Ok(Sha256Digest::compute(&encode_canonical_frame(v).map_err(|_|invalid())?))}
fn decode<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,&'static str>{decode_canonical_frame(raw).map_err(|_|invalid())}
/// Compare complete original scope, without rewriting replay IDs or deadlines.
pub(in crate::policy_shadow::policy_custody) fn same_scope(recover:&Request,prepare:&Request)->Result<(),&'static str>{
    let (Request::Recover{transition_id_sha256:a,previous_configuration_binding_sha256:b,successor_configuration_binding_sha256:c,
        dispatch_manifest_sha256:d,kernel_driver_identity_sha256:e,retained_descriptor_set_sha256:f,
        driver_generation_receipt_sha256:g,install_context:h,..},
        Request::Prepare{transition_id_sha256:i,previous_configuration_binding_sha256:j,successor_configuration_binding_sha256:k,
        dispatch_manifest_sha256:l,kernel_driver_identity_sha256:m,retained_descriptor_set_sha256:n,
        driver_generation_receipt_sha256:o,install_context:p,..})=(recover,prepare) else{return Err(invalid());};
    ensure((a,b,c,d,e,f,g,h)==(i,j,k,l,m,n,o,p))
}
impl Evidence {
    pub(in crate::policy_shadow::policy_custody) fn validate(&self,request:&Request,keyrings:&FiveServiceHistoricalKeyringsV4<'_>)->Result<(),&'static str>{
        let Request::Recover{install_context,..}=request else{return Err(invalid());};let p=&self.payload;
        ensure(p.api_version==API && p.purpose=="native-generation-recovery-observation" && p.request==*request
            && p.services.api_version=="serverware.custodyGenerationServicesResult/v1" && p.services.request_sha256==request.request_sha256()?
            && p.services.services.keys().copied().collect::<BTreeSet<_>>()==generation_service_client::roles()
            && p.coordinator_assignment_sha256!=Sha256Digest::compute(&[]) && p.journal_head_sha256!=Sha256Digest::compute(&[])
            && p.observed_at_boottime_nanos>0 && p.observed_at_boottime_nanos<request.deadline_boottime_nanos()
            && p.journal_sequence<=8 && self.authority_public_key.key_id==install_context.envelope_authority_key_id
            && self.authority_public_key.key_spki_sha256==install_context.envelope_authority_key_spki_sha256)?;
        let public=self.authority_public_key.validate_and_decode().map_err(|_|invalid())?;
        let signature=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        ensure(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==self.signature_base64url)?;
        public.verify_strict(&signature_preimage(DOMAIN,&encode_canonical_frame(p).map_err(|_|invalid())?),
            &Signature::from_slice(&signature).map_err(|_|invalid())?).map_err(|_|invalid())?;
        let installed=if let Some(retained)=&p.installed {
            ensure(p.journal_sequence==6 && retained.prepare_request.transition()==Transition::Prepare
                && retained.commit_request.transition()==Transition::Commit
                && retained.preparation.api_version==super::super::production_dispatch::PRODUCTION_GENERATION_PROTOCOL_VERSION
                && retained.installation.api_version==super::super::production_dispatch::PRODUCTION_GENERATION_PROTOCOL_VERSION)?;
            same_scope(request,&retained.prepare_request)?;
            retained.preparation.validate(&retained.prepare_request,keyrings)?;
            retained.installation.validate(&retained.commit_request,keyrings)?;
            ensure(retained.preparation.result.kind==Kind::GenerationTransitionPreparation
                && retained.installation.result.kind==Kind::GenerationInstallAttestation)?;
            let preparation:Preparation=decode(&retained.preparation.result.exact_bytes()?)?;
            let installation:Installation=decode(&retained.installation.result.exact_bytes()?)?;
            let signed:SignedEnvelope<ProductionCustodyGenerationInstallReceiptPayload>=decode(&installation.exact_signed_install_envelope_bytes)?;
            let payload=signed.untrusted_payload();
            ensure(signed.untrusted_signer()==(&install_context.envelope_authority_key_id,&install_context.envelope_authority_key_spki_sha256)
                && payload.assignment_id==install_context.assignment_id && payload.assignment_payload_sha256==install_context.assignment_payload_sha256
                && payload.assignment_revision==install_context.assignment_revision
                && payload.operation_coverage_root_sha256==install_context.operation_coverage_root_sha256
                && payload.five_service_protocol_set_sha256==install_context.five_service_protocol_set_sha256
                && payload.issued_at_unix_nanos==install_context.issued_at_unix_nanos && payload.expires_at_unix_nanos==install_context.expires_at_unix_nanos
                && payload.transition_id_sha256==preparation.transition_id_sha256
                && payload.previous_configuration_binding_sha256==preparation.previous_configuration_binding_sha256
                && payload.successor_configuration_binding_sha256==preparation.successor_configuration_binding_sha256
                && payload.dispatch_manifest_sha256==preparation.dispatch_manifest_sha256
                && payload.kernel_driver_identity_sha256==preparation.kernel_driver_identity_sha256
                && payload.kernel_retained_descriptor_set_sha256==preparation.retained_descriptor_set_sha256
                && payload.driver_generation_receipt_sha256==preparation.driver_generation_receipt_sha256
                && payload.preparation_receipt_sha256==installation.preparation_receipt_sha256.clone().ok_or_else(invalid)?
                && retained.commit_request.transition_id_sha256()==retained.prepare_request.transition_id_sha256()
                && retained.commit_request.deadline_boottime_nanos()==retained.prepare_request.deadline_boottime_nanos())?;
            Some((retained,payload.clone()))
        }else{ensure(p.journal_sequence==0)?;None};
        for (role,exchange) in &p.services.services {
            ensure(exchange.command.api_version==generation_service::API && exchange.command.request==*request
                && exchange.command.prepared_effect_sha256.is_none())?;
            let Response::Observation(value)=&exchange.response else{return Err(invalid());};let o=&value.payload;
            let history=keyrings.history(historical_service_role(*role));
            ensure(o.api_version=="serverware.custodyServiceGenerationObservation/v1" && o.purpose=="cold-service-generation-observation"
                && o.service_role==*role && o.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
                && o.command_sha256==sha(&exchange.command)? && o.observed_at_boottime_nanos>0
                && o.observed_at_boottime_nanos<=p.observed_at_boottime_nanos && o.deadline_boottime_nanos==request.deadline_boottime_nanos())?;
            history.verify_service_signature(&o.authority_epoch,b"serverware.custodyServiceGenerationObservation.signature/v1",
                &encode_canonical_frame(o).map_err(|_|invalid())?,&value.signature_base64url).map_err(|_|invalid())?;
            if let Some((retained,installation))=&installed {
                let prepared=o.prepared.as_ref().ok_or_else(invalid)?;let committed=o.decision.as_ref().ok_or_else(invalid)?;
                ensure(prepared.payload.phase==Phase::Prepared && committed.payload.phase==Phase::Committed
                    && prepared.payload.service_role==*role && committed.payload.service_role==*role
                    && prepared.payload.request_sha256==retained.prepare_request.request_sha256()?
                    && committed.payload.request_sha256==retained.commit_request.request_sha256()?
                    && committed.payload.prepared_effect_sha256==Some(sha(prepared)?)
                    && prepared.payload.owner_state_sha256==o.owner_state_sha256 && committed.payload.owner_state_sha256==o.owner_state_sha256)?;
                let expected=match role {
                    TrustedHostServiceRoleV3::DurableRecoveryStore=>&installation.durable_recovery_store_receipt_sha256,
                    TrustedHostServiceRoleV3::CleanupAuthorizationConsumer=>&installation.cleanup_authorization_receipt_sha256,
                    TrustedHostServiceRoleV3::RecoveryTargetProvider=>&installation.recovery_target_receipt_sha256,
                    TrustedHostServiceRoleV3::BoundedCleanupHelper=>&installation.bounded_cleanup_receipt_sha256,
                    TrustedHostServiceRoleV3::CurrentSignatureAuthority=>&installation.current_signature_receipt_sha256,
                };ensure(&sha(committed)?==expected)?;
            } else {ensure(o.prepared.is_none() && o.decision.is_none())?;}
        }Ok(())
    }
}
