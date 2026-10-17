//! Data-only original decoder. Only the actual retained key owner can consume
//! the independently signed result; parsing creates no verified capability.
use crate::policy_shadow::*;
use super::NativeCustodyKeys;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Original {api_version:String,result:ResultFields}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ResultFields {
    platform:TeePlatform,quote_sha256:Sha256Digest,endorsement_evidence_sha256:Sha256Digest,
    endorsement_root_sha256:Sha256Digest,collateral_policy_sha256:Sha256Digest,revocation_source_sha256:Sha256Digest,
    collateral_revocation_generation:u64,collateral_revocation_root_sha256:Sha256Digest,measurement_sha256:Sha256Digest,
    production_configuration_binding_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    execution_closure_manifest_sha256:Sha256Digest,structurally_verified_seccomp_policy_sha256:Sha256Digest,
    quote_bound_custody_key_set_root_sha256:Sha256Digest,verified_at_unix_nanos:i64,expires_at_unix_nanos:i64,
    trust_checkpoint_id:Sha256Digest,trust_revocation_generation:u64,trust_revocation_root_sha256:Sha256Digest,
    signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,signature:CanonicalEd25519Signature,
}
pub(super) fn decode(raw:&[u8])->Result<CustodyTeeAttestationVerifierResultWire,ShadowError> {
    if raw.is_empty() || raw.len()>32*1024 {return Err(ShadowError::CustodyUnavailable);}
    let original:Original=serde_json::from_slice(raw).map_err(|_|ShadowError::BindingDrift)?;
    if original.api_version!="catchplate.nativeShadowNitroVerifierResult/v1"
        || canonical_json_bytes(&original)?!=raw || original.result.platform!=TeePlatform::AwsNitroEnclave {
        return Err(ShadowError::BindingDrift);
    }
    let r=original.result;
    CustodyTeeAttestationVerifierResultWire::from_verifier_with_execution_closure(
        r.platform,r.quote_sha256,r.endorsement_evidence_sha256,r.endorsement_root_sha256,
        r.collateral_policy_sha256,r.revocation_source_sha256,r.collateral_revocation_generation,
        r.collateral_revocation_root_sha256,r.measurement_sha256,r.production_configuration_binding_sha256,
        r.worker_executable_sha256,r.execution_closure_manifest_sha256,r.structurally_verified_seccomp_policy_sha256,
        r.quote_bound_custody_key_set_root_sha256,r.verified_at_unix_nanos,r.expires_at_unix_nanos,
        r.trust_checkpoint_id,r.trust_revocation_generation,r.trust_revocation_root_sha256,
        r.signing_key_id,r.signing_key_spki_sha256,r.signature.0)
}
impl NativeCustodyKeys {
    /// The transport supplies original public bytes, not a claimed success or
    /// a deserialized owner. Any malformed/mismatched result poisons this owner.
    pub(crate) fn accept_verifier_original(&mut self,raw:&[u8],trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<(),ShadowError> {
        let result=(|| {
            self.check(trust,time)?;self.association.check_startup().map_err(|_|ShadowError::CustodyUnavailable)?;
            let wire=decode(raw)?;
            self.accept_verifier_result(wire,trust,time)
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);}
        result
    }
}
