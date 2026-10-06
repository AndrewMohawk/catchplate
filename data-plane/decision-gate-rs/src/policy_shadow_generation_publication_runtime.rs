//! Verify existing Nitro originals under the retained runtime owner's PUBLIC
//! projection. This does not attest the publication key/journal or mint a new
//! runtime verdict. The actual Nitro verifier, not this consumer, checks quotes.
use crate::policy_shadow::{canonical_json_bytes, EnvelopePayload, Sha256Digest, SignedEnvelope,
    CANONICAL_PROFILE, SIGNED_ENVELOPE_DOMAIN};
use crate::policy_shadow_generation_publication_protocol::{PublicationAttestationChain,
    PublicationGenerationBinding, PublicationRuntimeBinding, PublicationTrustBinding,
    STARTUP_ATTESTATION_HANDOFF_API_VERSION, MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS};
use serverware_decision_gate::native_shadow_workers::runtime_resources::PublicationVerificationAuthority;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::{DecodePublicKey, EncodePublicKey}, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("publication Nitro originals differ from retained runtime authority".into()) }
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    canonical_json_bytes(value).map_err(|e| e.to_string())
}
fn digest<T: Serialize>(value: &T) -> Result<Sha256Digest, String> {
    Ok(Sha256Digest::compute(&canonical(value)?))
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Key { key_id: Sha256Digest, key_spki_sha256: Sha256Digest, public_key_pem: String }
impl Key {
    fn public(&self) -> Result<VerifyingKey, String> {
        require(self.public_key_pem.len() <= 1024)?;
        let key = VerifyingKey::from_public_key_pem(&self.public_key_pem).map_err(|_| "publication runtime authority PEM")?;
        let der = key.to_public_key_der().map_err(|_| "publication runtime authority SPKI")?;
        require(!key.is_weak() && self.key_id == self.key_spki_sha256 && self.key_id == Sha256Digest::compute(der.as_bytes()))?;
        Ok(key)
    }
}
fn verify_envelope<T: EnvelopePayload>(envelope: &SignedEnvelope<T>, key: &VerifyingKey,
    key_id: &Sha256Digest, spki: &Sha256Digest, interval: (i64, i64), maximum: i64) -> Result<(), String> {
    let payload = envelope.untrusted_payload();
    payload.validate_intrinsic().map_err(|e| e.to_string())?;
    require(payload.issued_at_unix_nanos() <= interval.0 && interval.1 <= payload.expires_at_unix_nanos()
        && payload.expires_at_unix_nanos().checked_sub(payload.issued_at_unix_nanos())
            .is_some_and(|span| span > 0 && span <= maximum))?;
    let value = serde_json::to_value(envelope).map_err(|_| "publication embedded envelope encoding")?;
    let encoded = value["signature"].as_str().ok_or("publication embedded signature absent")?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "publication embedded signature encoding")?
        .try_into().map_err(|_| "publication embedded signature size")?;
    require(URL_SAFE_NO_PAD.encode(signature) == encoded)?;
    let expected = SignedEnvelope::from_external_signature(payload.clone(), key_id.clone(), spki.clone(), encoded.into())
        .map_err(|e| e.to_string())?;
    require(canonical(&expected)? == canonical(envelope)?)?;
    let bytes = canonical(payload)?;
    let preimage = [SIGNED_ENVELOPE_DOMAIN, &[0], payload.envelope_signature_domain().as_bytes(),
        &[0], CANONICAL_PROFILE.as_bytes(), &[0], bytes.as_slice()].concat();
    key.verify_strict(&preimage, &Signature::from_bytes(&signature)).map_err(|_| "publication embedded signature invalid".into())
}

/// Historical journal replay verifies the same original signed intervals;
/// the publisher separately requires the requested interval CURRENT at every
/// effect/sign/output boundary. Reading history never extends that interval.
pub(crate) fn verify(selected: &PublicationVerificationAuthority, chain: &PublicationAttestationChain,
    generation: &PublicationGenerationBinding, runtime: &PublicationRuntimeBinding,
    trust: &PublicationTrustBinding, interval: (i64, i64)) -> Result<(), String> {
    selected.validate()?;
    let pins = &selected.pins;
    require(interval.0 > 0 && interval.0 < interval.1
        && pins.not_before_unix_nanos <= interval.0 && interval.1 <= pins.not_after_unix_nanos
        && pins.key_id == pins.key_spki_sha256
        && trust.runtime_attestation_verifier_signing_key_id.as_str() == pins.key_id
        && trust.runtime_attestation_verifier_signing_key_spki_sha256.as_str() == pins.key_spki_sha256
        && trust.runtime_attestation_policy_sha256.as_str() == pins.policy_sha256
        && trust.trust_checkpoint_sha256.as_str() == pins.trust_checkpoint_sha256
        && trust.revocation_generation == pins.revocation_generation
        && trust.revocation_root_sha256.as_str() == pins.revocation_root_sha256
        && runtime.runtime_attestation_verifier_executable_sha256.as_str() == pins.verifier_executable_sha256
        && trust.publication_signing_key_id != trust.runtime_attestation_verifier_signing_key_id
        && trust.publication_signing_key_spki_sha256 != trust.runtime_attestation_verifier_signing_key_spki_sha256)?;
    // The original policy is independently pinned by the runtime owner. Only
    // its existing receipt/role verification keys are projected here; no new
    // quotation policy or alternate PCR/measurement interpretation is admitted.
    let policy: serde_json::Value = serde_json::from_str(&selected.policy_original).map_err(|_| "publication runtime policy encoding")?;
    let receipt_key: Key = serde_json::from_value(policy["startupReceiptAuthority"].clone()).map_err(|_| "publication receipt authority fields")?;
    let role_key: Key = serde_json::from_value(policy["shadowRoleAuthority"].clone()).map_err(|_| "publication role authority fields")?;
    require(receipt_key.key_id != role_key.key_id && receipt_key.key_id.as_str() != pins.key_id
        && role_key.key_id.as_str() != pins.key_id && receipt_key.key_id != trust.publication_signing_key_id
        && role_key.key_id != trust.publication_signing_key_id)?;
    let public: [u8; 32] = URL_SAFE_NO_PAD.decode(&selected.verifier_public_key_base64url)
        .map_err(|_| "publication verifier public key")?.try_into().map_err(|_| "publication verifier public key size")?;
    let verifier = VerifyingKey::from_bytes(&public).map_err(|_| "publication verifier public key invalid")?;
    verify_envelope(&chain.runtime_attestation_verification, &verifier,
        &trust.runtime_attestation_verifier_signing_key_id, &trust.runtime_attestation_verifier_signing_key_spki_sha256,
        interval, MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS)?;
    let handoff = &chain.startup_attestation;
    verify_envelope(&handoff.receipt, &receipt_key.public()?, &receipt_key.key_id, &receipt_key.key_spki_sha256,
        interval, 86_400_000_000_000)?;
    verify_envelope(&handoff.role_authorization, &role_key.public()?, &role_key.key_id, &role_key.key_spki_sha256,
        interval, 86_400_000_000_000)?;
    let result = chain.runtime_attestation_verification.untrusted_payload();
    let role_payload = handoff.role_authorization.untrusted_payload();
    let role = &role_payload.record;
    let receipt = &handoff.receipt.untrusted_payload().record;
    let evidence = &handoff.evidence;
    require(chain.attestation_mode == "aws-nitro-enclave" && chain.hardware_attested
        && result.attestation_mode == "aws-nitro-enclave" && result.hardware_attested
        && result.trusted_now_unix_nanos == interval.0
        && result.attestation_policy_sha256 == trust.runtime_attestation_policy_sha256
        && result.verifier_executable_sha256 == runtime.runtime_attestation_verifier_executable_sha256
        && result.trust_checkpoint_sha256.as_str() == pins.trust_checkpoint_sha256
        && result.revocation_generation == pins.revocation_generation
        && result.revocation_root_sha256.as_str() == pins.revocation_root_sha256
        && handoff.api_version == STARTUP_ATTESTATION_HANDOFF_API_VERSION
        && digest(&handoff.receipt)? == handoff.receipt_sha256
        && digest(handoff.receipt.untrusted_payload())? == handoff.receipt_payload_sha256
        && digest(&handoff.role_authorization)? == handoff.role_authorization_sha256
        && digest(role_payload)? == handoff.role_authorization_payload_sha256
        && result.runtime_attestation_receipt_sha256 == handoff.receipt_sha256
        && result.runtime_attestation_payload_sha256 == handoff.receipt_payload_sha256
        && result.role_authorization_sha256 == handoff.role_authorization_sha256
        && result.role_authorization_payload_sha256 == handoff.role_authorization_payload_sha256
        && result.attestation_evidence_id == evidence.evidence_id && result.attestation_evidence_revision == evidence.evidence_revision
        && result.tee_evidence_sha256 == evidence.evidence_sha256 && evidence.evidence_type == "aws-nitro-enclave"
        && handoff.chain_sha256 == result.evidence_chain_sha256
        && role.authorization_id == handoff.role_authorization_id && role.authorization_revision == handoff.role_authorization_revision
        && role.runtime_attestation_receipt_id == handoff.receipt_id && role.runtime_attestation_receipt_revision == handoff.receipt_revision
        && role.runtime_attestation_receipt_sha256 == handoff.receipt_sha256 && role.runtime_attestation_payload_sha256 == handoff.receipt_payload_sha256
        && role.attestation_evidence_id == evidence.evidence_id && role.attestation_evidence_revision == evidence.evidence_revision
        && role.attestation_evidence_sha256 == evidence.evidence_sha256
        && role.assignment_sha256 == generation.assignment_envelope_sha256 && role.assignment_payload_sha256 == generation.assignment_payload_sha256
        && role.assignment_revision == generation.assignment_revision && role.load_receipt_sha256 == generation.load_receipt_envelope_sha256
        && role.load_receipt_payload_sha256 == generation.load_receipt_payload_sha256
        && role.runtime_identity_sha256 == runtime.runtime_identity_sha256
        && role.instance_id == runtime.runtime_instance_id && role.boot_id_sha256 == runtime.runtime_boot_id_sha256
        && role.runtime_executable_sha256 == result.runtime_executable_sha256 && role.runtime_release_sha256 == result.runtime_release_sha256
        && role.runtime_config_sha256 == result.runtime_config_sha256 && role.runtime_policy_sha256 == result.runtime_policy_sha256
        && role.attestation_policy_sha256 == trust.runtime_attestation_policy_sha256
        && role.attestation_trust_checkpoint_sha256.as_str() == pins.trust_checkpoint_sha256
        && role.revocation_generation == pins.revocation_generation && role.revocation_root_sha256.as_str() == pins.revocation_root_sha256
        && role.shadow_signing_key_id == trust.publication_signing_key_id && role.shadow_signing_key_spki_sha256 == trust.publication_signing_key_spki_sha256
        && result.shadow_signing_key_id == role.shadow_signing_key_id && result.shadow_signing_key_spki_sha256 == role.shadow_signing_key_spki_sha256
        && role.tee_measurement_sha256 == result.tee_measurement_sha256 && role.tee_measurement_sha256 == runtime.runtime_tee_measurement_sha256
        && receipt.fleet_id == role.fleet_id && receipt.membership_revision == role.fleet_membership_revision
        && receipt.member_ordinal == role.member_ordinal && receipt.member_id == role.member_id
        && receipt.instance_id == role.instance_id && receipt.boot_id_sha256 == role.boot_id_sha256
        && receipt.tee_platform == "aws-nitro-enclave" && receipt.tee_evidence_sha256 == evidence.evidence_sha256
        && receipt.tee_measurement_sha256 == role.tee_measurement_sha256)
}
