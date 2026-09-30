//! Independent admission signature; no conversion to a settlement attestation.
use super::*;
const DOMAIN:&str="serverware.nativeShadowKeyAdmissionResult.signature/v1";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,statement_sha256:Sha256Digest,quote_sha256:Sha256Digest,native_context_sha256:Sha256Digest,
    admission_authorization_sha256:Sha256Digest,key_authorization_sha256:Sha256Digest,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,
    measurement_sha256:Sha256Digest,endorsement_evidence_sha256:Sha256Digest,endorsement_root_sha256:Sha256Digest,
    collateral_policy_sha256:Sha256Digest,revocation_source_sha256:Sha256Digest,
    collateral_revocation_generation:u64,collateral_revocation_root_sha256:Sha256Digest,
    trust_checkpoint_id:Sha256Digest,trust_revocation_generation:u64,trust_revocation_root_sha256:Sha256Digest,
    verified_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    production_configuration_binding_sha256:Option<Sha256Digest>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Wire {api_version:String,payload:Payload,signature:CanonicalEd25519Signature}
pub(super) struct VerifiedResult {wire:Wire,original:Vec<u8>}
impl VerifiedResult {
    pub(super) fn check(&self,owner:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        require(canonical_json_bytes(&self.wire)?==self.original)?;
        let p=&self.wire.payload;let checkpoint=trust.current_checkpoint()?;
        let evidence=owner.evidence.as_ref().ok_or(ShadowError::CustodyUnavailable)?;
        let statement=&evidence.statement;
        let domain=if let Some(configuration)=&owner.production {
            require(self.wire.api_version=="serverware.nativeShadowBridgeContextVerifierResult/v1"
                && p.api_version=="serverware.nativeShadowBridgeContextResult/v1" && p.purpose=="native-shadow-context-and-production-admission"
                && p.production_configuration_binding_sha256.as_ref()==Some(configuration.production_configuration_binding_sha256())
                && p.production_configuration_binding_sha256==statement.production_configuration_binding_sha256)?;
            "serverware.nativeShadowBridgeContextResult.signature/v1"
        }else{
            require(self.wire.api_version=="serverware.nativeShadowKeyAdmissionVerifierResult/v1"
                && p.api_version=="serverware.nativeShadowKeyAdmissionResult/v1" && p.purpose=="native-shadow-key-admission"
                && p.production_configuration_binding_sha256.is_none() && statement.production_configuration_binding_sha256.is_none())?;DOMAIN
        };
        require(p.statement_sha256==Sha256Digest::compute(&canonical_json_bytes(statement)?)
            && p.quote_sha256==Sha256Digest::compute(&URL_SAFE_NO_PAD.decode(&evidence.attestation_document_base64url).map_err(fail)?)
            && p.native_context_sha256==statement.native_context_sha256
            && p.admission_authorization_sha256==statement.admission_authorization_sha256
            && p.key_authorization_sha256==statement.key_authorization_sha256
            && p.full_key_set_root_sha256==statement.full_key_set_root_sha256 && p.local_key_set_root_sha256==statement.local_key_set_root_sha256
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.trust_revocation_generation==checkpoint.revocation_generation
            && p.trust_revocation_root_sha256==checkpoint.revocation_root_sha256 && p.collateral_revocation_generation>0)?;
        match &owner.assignment.payload().custody_authority.attestation_mode {
            CustodyAttestationMode::Tee{platform:TeePlatform::AwsNitroEnclave,expected_measurement_sha256,endorsement_root_sha256,
                collateral_policy_sha256,revocation_source_sha256}=>require(&p.measurement_sha256==expected_measurement_sha256
                    && &p.endorsement_root_sha256==endorsement_root_sha256 && &p.collateral_policy_sha256==collateral_policy_sha256
                    && &p.revocation_source_sha256==revocation_source_sha256)?,
            _=>return Err(ShadowError::BindingDrift),
        }
        validate_trusted_freshness(p.verified_at_unix_nanos,p.expires_at_unix_nanos,time,30_000_000_000)?;
        require(p.expires_at_unix_nanos<=owner.authorization.payload.expires_at_unix_nanos)?;
        let b=owner.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyAttestationVerifier,&owner.assignment.payload().assignment_id)?;
        require(p.signing_key_id==b.key_id && p.signing_key_spki_sha256==b.key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodyAttestationVerifier),&b.key_id,&b.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==b.key_material_sha256)?;
        key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.wire.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==checkpoint)
    }
    pub(super) fn require_production(&self,wire:&CustodyTeeAttestationVerifierResultWire)->Result<(),ShadowError>{
        let p=&self.wire.payload;
        require(p.production_configuration_binding_sha256.as_ref()==Some(&wire.production_configuration_binding_sha256)
            && p.quote_sha256==wire.quote_sha256 && p.full_key_set_root_sha256==wire.quote_bound_custody_key_set_root_sha256
            && p.measurement_sha256==wire.measurement_sha256 && p.endorsement_evidence_sha256==wire.endorsement_evidence_sha256
            && p.endorsement_root_sha256==wire.endorsement_root_sha256 && p.collateral_policy_sha256==wire.collateral_policy_sha256
            && p.revocation_source_sha256==wire.revocation_source_sha256 && p.collateral_revocation_generation==wire.collateral_revocation_generation
            && p.collateral_revocation_root_sha256==wire.collateral_revocation_root_sha256
            && p.trust_checkpoint_id==wire.trust_checkpoint_id && p.trust_revocation_generation==wire.trust_revocation_generation
            && p.trust_revocation_root_sha256==wire.trust_revocation_root_sha256
            && p.verified_at_unix_nanos==wire.verified_at_unix_nanos && p.expires_at_unix_nanos==wire.expires_at_unix_nanos
            && p.signing_key_id==wire.signing_key_id && p.signing_key_spki_sha256==wire.signing_key_spki_sha256)
    }
}
pub(super) fn verify(raw:&[u8],owner:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<VerifiedResult,ShadowError> {
    require(!raw.is_empty() && raw.len()<=32768)?;
    let wire:Wire=serde_json::from_slice(raw).map_err(fail)?;
    let result=VerifiedResult{wire,original:raw.to_vec()};result.check(owner,trust,time)?;Ok(result)
}
