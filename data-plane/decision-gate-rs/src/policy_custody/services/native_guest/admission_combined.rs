//! Exact two independently signed result originals over ONE actual combined
//! quote. Neither a context result nor a parsed full result can activate alone.
use super::*;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Original {api_version:String,context_result_original:String,production_result_original:String}

pub(super) fn accept(raw:&[u8],owner:&mut AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
    ->Result<(),ShadowError>{
    require(!raw.is_empty() && raw.len()<=32768 && owner.result.is_none() && owner.combined_original.is_none())?;
    owner.check(trust,time)?;owner.association.check_startup().map_err(fail)?;
    let original:Original=serde_json::from_slice(raw).map_err(fail)?;
    require(original.api_version=="serverware.nativeShadowBridgeAdmissionVerifierResult/v1"
        && canonical_json_bytes(&original)?==raw && original.context_result_original.is_ascii()
        && original.production_result_original.is_ascii())?;
    let context=result::verify(original.context_result_original.as_bytes(),owner,trust,time)?;
    let wire=super::super::verifier_result::decode(original.production_result_original.as_bytes())?;
    context.require_production(&wire)?;
    let evidence=owner.evidence.as_ref().ok_or(ShadowError::CustodyUnavailable)?;
    require(evidence.api_version=="serverware.nativeShadowBridgeAdmissionEvidence/v1"
        && wire.quote_sha256==Sha256Digest::compute(&URL_SAFE_NO_PAD.decode(&evidence.attestation_document_base64url).map_err(fail)?)
        && Some(&wire.production_configuration_binding_sha256)==evidence.statement.production_configuration_binding_sha256.as_ref())?;
    let configuration=owner.production.as_ref().ok_or(ShadowError::BindingDrift)?;
    let verified=verify_production_custody_tee_attestation(configuration,wire,trust,time)?;
    let activated=configuration.clone().activate_with_verified_attestation(verified)?;
    activated.revalidate_active_attestation(trust,time)?;
    owner.production=Some(activated);owner.result=Some(context);owner.combined_original=Some(raw.to_vec());
    owner.association.check_startup().map_err(fail)?;owner.check(trust,time)
}

impl AdmittedKeys {
    pub(in crate::policy_shadow::policy_custody::services) fn admitted_bridge_configuration(&self,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<&ProductionCustodyConfiguration,ShadowError>{
        self.check(trust,time)?;require(self.result.is_some() && self.combined_original.is_some())?;
        let configuration=self.production.as_ref().ok_or(ShadowError::CustodyUnavailable)?;
        configuration.revalidate_active_attestation(trust,time)?;Ok(configuration)
    }
}
