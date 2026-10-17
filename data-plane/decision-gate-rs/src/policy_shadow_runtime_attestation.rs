//! Fixed Nitro runtime verifier. All authority is supplied by the retained cold
//! owner; the request contains originals, never a verdict or a signing policy.
//! Role-4 quotation proves runtime identity, NOT custody of the shadow seed.
use crate::native_verifier::runtime_shadow::{parse_original, Scope};
use crate::policy_shadow::{canonical_json_bytes, EnvelopePayload, RuntimeIdentity,
    Sha256Digest, SignedEnvelope, CANONICAL_PROFILE, SIGNED_ENVELOPE_DOMAIN};
use crate::policy_shadow_generation_publication_protocol::{
    bounded_ascii_token, domain_digest, startup_attestation_handoff_chain_sha256, PublicationRequestBinding,
    RuntimeAttestationHandoff, RuntimeAttestationVerificationResult,
    RUNTIME_EVIDENCE_API_VERSION, RUNTIME_VERIFIER_RESPONSE_API_VERSION,
    STARTUP_ATTESTATION_HANDOFF_API_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::{DecodePublicKey, EncodePublicKey}, Signature, Signer,
    SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json as object, Value};
use sha2::{Digest, Sha256};

pub(crate) const MAX_INPUT: usize = 32 * 1024 * 1024;
const MAX_POLICY: usize = 64 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;
const SECOND: i64 = 1_000_000_000;

pub(crate) struct Authority<'a> {
    pub(crate) key: &'a SigningKey,
    pub(crate) key_id: &'a str,
    pub(crate) key_spki_sha256: &'a str,
    pub(crate) policy_sha256: &'a str,
    pub(crate) trust_checkpoint_sha256: &'a str,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_root_sha256: &'a str,
    pub(crate) not_before_unix_nanos: i64,
    pub(crate) not_after_unix_nanos: i64,
    pub(crate) verifier_executable_sha256: &'a str,
    pub(crate) check: &'a dyn Fn() -> Result<i64, String>,
}

// Same-call output only, not a deserializable or reusable authorization token.
pub(crate) struct Output {
    pub(crate) original: Vec<u8>,
    pub(crate) expires_at_unix_nanos: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String, operation: String, request: PublicationRequestBinding,
    assignment_payload_sha256: Sha256Digest, load_receipt_payload_sha256: Sha256Digest,
    runtime_identity: RuntimeIdentity, runtime_identity_sha256: Sha256Digest,
    runtime_attestation: RuntimeAttestationHandoff, trust_checkpoint_sha256: Sha256Digest,
    attestation_policy_sha256: Sha256Digest, verifier_executable_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Key { key_id: Sha256Digest, key_spki_sha256: Sha256Digest, public_key_pem: String }
impl Key {
    fn actual(&self) -> Result<VerifyingKey, String> {
        ensure(self.public_key_pem.len() <= 1024, "runtime authority key exceeds bound")?;
        let key = VerifyingKey::from_public_key_pem(&self.public_key_pem).map_err(|_| "runtime authority key invalid")?;
        let der = key.to_public_key_der().map_err(|_| "runtime authority key encoding")?;
        ensure(!key.is_weak() && self.key_id == self.key_spki_sha256
            && self.key_id == Sha256Digest::compute(der.as_bytes()), "runtime authority SPKI differs")?;
        Ok(key)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    api_version: String, trust_roots_sha256: Sha256Digest, expected_pcrs: Value,
    expected_eif: String, expected_module_id: String,
    expected_runtime_executable_sha256: Sha256Digest,
    expected_runtime_release_sha256: Sha256Digest, expected_tee_measurement_sha256: Sha256Digest,
    max_age_seconds: u64, future_skew_seconds: u64,
    startup_receipt_authority: Key, shadow_role_authority: Key,
}
fn ensure(ok: bool, why: &'static str) -> Result<(), String> { if ok { Ok(()) } else { Err(why.into()) } }
fn sha(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
fn pin(value: &str) -> Result<Sha256Digest, String> {
    ensure(value.len() == 71 && value.starts_with("sha256:") && value[7..].bytes().any(|b| b != b'0'),
        "runtime pin absent")?;
    Sha256Digest::parse(value.to_owned()).map_err(|e| e.to_string())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    canonical_json_bytes(value).map_err(|e| e.to_string())
}
fn preimage<T: EnvelopePayload>(payload: &T) -> Result<Vec<u8>, String> {
    let raw = canonical(payload)?;
    Ok([SIGNED_ENVELOPE_DOMAIN, &[0], payload.envelope_signature_domain().as_bytes(),
        &[0], CANONICAL_PROFILE.as_bytes(), &[0], &raw].concat())
}
fn verify<T: EnvelopePayload + Clone>(envelope: &SignedEnvelope<T>, authority: &Key,
    now: i64) -> Result<(), String> {
    let payload = envelope.untrusted_payload();
    payload.validate_intrinsic().map_err(|e| e.to_string())?;
    ensure(payload.issued_at_unix_nanos() <= now && now < payload.expires_at_unix_nanos()
        && payload.expires_at_unix_nanos().checked_sub(payload.issued_at_unix_nanos())
            .is_some_and(|span| span > 0 && span <= 86_400 * SECOND), "runtime authorization expired")?;
    let value = serde_json::to_value(envelope).map_err(|_| "runtime envelope encoding")?;
    let encoded = value["signature"].as_str().ok_or("runtime signature absent")?;
    ensure(encoded.len() == 86, "runtime signature bound")?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "runtime signature encoding")?
        .try_into().map_err(|_| "runtime signature size")?;
    ensure(URL_SAFE_NO_PAD.encode(signature) == encoded, "runtime signature is not canonical")?;
    let expected = SignedEnvelope::from_external_signature(payload.clone(), authority.key_id.clone(),
        authority.key_spki_sha256.clone(), encoded.to_owned()).map_err(|e| e.to_string())?;
    ensure(canonical(&expected)? == canonical(envelope)?, "runtime envelope metadata or digest differs")?;
    authority.actual()?.verify_strict(&preimage(payload)?, &Signature::from_bytes(&signature))
        .map_err(|_| "runtime authorization signature invalid".to_owned())
}


pub(crate) fn handle(original: &[u8], policy_original: &[u8], roots_original: &[u8],
    authority: Authority<'_>) -> Result<Output, String> {
    let opening = (authority.check)()?;
    ensure(opening > 0 && authority.not_before_unix_nanos <= opening && opening < authority.not_after_unix_nanos
        && authority.revocation_generation > 0, "runtime cold authority is not current")?;
    let request_value = parse_original(original, MAX_INPUT)?;
    ensure(canonical(&request_value)? == original, "runtime request is not canonical")?;
    let request: Request = serde_json::from_value(request_value).map_err(|_| "runtime request fields differ")?;
    let policy: Policy = serde_json::from_value(parse_original(policy_original, MAX_POLICY)?)
        .map_err(|_| "runtime policy fields differ")?;
    ensure(policy.api_version == "catchplate.nativeShadowRuntimeAttestationPolicy/v1"
        && sha(policy_original) == authority.policy_sha256
        && policy.trust_roots_sha256 == Sha256Digest::compute(roots_original)
        && request.api_version == "catchplate.policyShadowRuntimeAttestationVerificationRequest/v1"
        && request.operation == "verify-generation-runtime"
        && request.attestation_policy_sha256 == pin(authority.policy_sha256)?
        && request.verifier_executable_sha256 == pin(authority.verifier_executable_sha256)?
        && request.trust_checkpoint_sha256 == pin(authority.trust_checkpoint_sha256)?,
        "runtime request differs from independently admitted policy or executable")?;
    let signer = authority.key.verifying_key().to_public_key_der().map_err(|_| "runtime signer SPKI")?;
    ensure(authority.key_id == authority.key_spki_sha256 && sha(signer.as_bytes()) == authority.key_id
        && policy.startup_receipt_authority.key_id != policy.shadow_role_authority.key_id
        && policy.startup_receipt_authority.key_id.as_str() != authority.key_id
        && policy.shadow_role_authority.key_id.as_str() != authority.key_id,
        "runtime verifier/receipt/role keys are not independent")?;
    // Request IDs remain opaque management bindings, never authority.
    let binding = &request.request;
    ensure([&binding.request_id, &binding.replay_id, &binding.management_handoff_id]
        .iter().all(|s| bounded_ascii_token(s, 128))
        && binding.request_id != binding.replay_id && binding.request_id != binding.management_handoff_id
        && binding.replay_id != binding.management_handoff_id
        && binding.management_handoff_sha256 == domain_digest(
            b"catchplate.policyShadowGenerationManagementHandoff/v1",
            &(&binding.request_id, &binding.replay_id, &binding.management_handoff_id,
                &binding.request_sha256, &request.runtime_identity_sha256))?,
        "runtime management request binding differs")?;
    let runtime = &request.runtime_identity;
    let handoff = &request.runtime_attestation;
    verify(&handoff.receipt, &policy.startup_receipt_authority, opening)?;
    verify(&handoff.role_authorization, &policy.shadow_role_authority, opening)?;
    let receipt = handoff.receipt.untrusted_payload();
    let role_payload = handoff.role_authorization.untrusted_payload();
    let role = &role_payload.record;
    let evidence = &handoff.evidence;
    let evidence_raw = canonical(&evidence.evidence)?;
    let chain = startup_attestation_handoff_chain_sha256(handoff, &request.assignment_payload_sha256,
        &request.load_receipt_payload_sha256, &request.runtime_identity_sha256, &request.attestation_policy_sha256)?;
    ensure(handoff.api_version == STARTUP_ATTESTATION_HANDOFF_API_VERSION
        && evidence.api_version == RUNTIME_EVIDENCE_API_VERSION && evidence.evidence_revision > 0
        && evidence.evidence_type == "aws-nitro-enclave" && runtime.tee_platform_label() == "aws-nitro-enclave"
        && !evidence_raw.is_empty() && evidence_raw.len() < MAX_OUTPUT
        && evidence.evidence_sha256 == Sha256Digest::compute(&evidence_raw)
        && *runtime.tee_evidence_sha256() == evidence.evidence_sha256
        && request.runtime_identity_sha256 == Sha256Digest::compute(&canonical(runtime)?)
        && handoff.receipt_sha256 == Sha256Digest::compute(&canonical(&handoff.receipt)?)
        && handoff.receipt_payload_sha256 == Sha256Digest::compute(&canonical(receipt)?)
        && handoff.role_authorization_sha256 == Sha256Digest::compute(&canonical(&handoff.role_authorization)?)
        && handoff.role_authorization_payload_sha256 == Sha256Digest::compute(&canonical(role_payload)?)
        && handoff.chain_sha256 == chain, "runtime original handoff digests differ")?;
    ensure(role.authorization_id == handoff.role_authorization_id
        && role.authorization_revision == handoff.role_authorization_revision
        && role.runtime_attestation_receipt_id == handoff.receipt_id
        && role.runtime_attestation_receipt_revision == handoff.receipt_revision
        && role.runtime_attestation_receipt_sha256 == handoff.receipt_sha256
        && role.runtime_attestation_payload_sha256 == handoff.receipt_payload_sha256
        && role.attestation_evidence_id == evidence.evidence_id
        && role.attestation_evidence_revision == evidence.evidence_revision
        && role.attestation_evidence_sha256 == evidence.evidence_sha256
        && role.assignment_payload_sha256 == request.assignment_payload_sha256
        && role.load_receipt_payload_sha256 == request.load_receipt_payload_sha256
        && role.runtime_identity_sha256 == request.runtime_identity_sha256
        && role.instance_id == runtime.instance_id().as_str()
        && role.boot_id_sha256 == *runtime.boot_id_sha256()
        && role.attestation_policy_sha256 == request.attestation_policy_sha256
        && role.attestation_trust_checkpoint_sha256 == request.trust_checkpoint_sha256
        && role.revocation_generation == authority.revocation_generation
        && role.revocation_root_sha256 == pin(authority.revocation_root_sha256)?
        && role.shadow_signing_key_id == *runtime.shadow_signing_key_id()
        && role.shadow_signing_key_spki_sha256 == *runtime.shadow_signing_key_spki_sha256()
        && role.runtime_executable_sha256 == policy.expected_runtime_executable_sha256
        && role.runtime_release_sha256 == policy.expected_runtime_release_sha256
        && role.tee_measurement_sha256 == policy.expected_tee_measurement_sha256
        && *runtime.tee_measurement_sha256() == policy.expected_tee_measurement_sha256,
        "runtime signed role differs from original request or independent release mapping")?;
    ensure(receipt.record.fleet_id == role.fleet_id
        && receipt.record.membership_revision == role.fleet_membership_revision
        && receipt.record.member_ordinal == role.member_ordinal && receipt.record.member_id == role.member_id
        && receipt.record.instance_id == role.instance_id && receipt.record.boot_id_sha256 == role.boot_id_sha256
        && receipt.record.spiffe_id == runtime.spiffe_id().as_str()
        && receipt.record.tee_platform == "aws-nitro-enclave"
        && receipt.record.tee_evidence_sha256 == evidence.evidence_sha256
        && receipt.record.tee_measurement_sha256 == policy.expected_tee_measurement_sha256,
        "runtime receipt differs from authenticated role and evidence")?;
    ensure(runtime.tee_attestation_key_id == runtime.tee_attestation_key_spki_sha256,
        "runtime attestation key/SPKI differs")?;
    let verified = crate::native_verifier::runtime_shadow::verify(&evidence.evidence, Scope {
        module_id: &policy.expected_module_id, pcrs: &policy.expected_pcrs, eif: &policy.expected_eif,
        max_age_seconds: policy.max_age_seconds, future_skew_seconds: policy.future_skew_seconds,
        tee_key_id: runtime.tee_attestation_key_id.as_str(), boot_sha256: runtime.boot_id_sha256().as_str(),
        release_sha256: role.runtime_release_sha256.as_str(),
        configuration_sha256: role.runtime_config_sha256.as_str(), policy_sha256: role.runtime_policy_sha256.as_str(),
    }, roots_original, opening)?;
    let now = (authority.check)()?;
    let quote_issued = i64::try_from(verified.0).ok().and_then(|n| n.checked_mul(SECOND))
        .ok_or("runtime quote time overflow")?;
    let quote_expiry = i64::try_from(verified.1).ok().and_then(|n| n.checked_mul(SECOND))
        .ok_or("runtime quote expiry overflow")?;
    let age = i64::try_from(policy.max_age_seconds).ok().and_then(|n| n.checked_mul(SECOND))
        .ok_or("runtime maximum age overflow")?;
    let expires = [authority.not_after_unix_nanos, receipt.expires_at_epoch_ns,
        role_payload.expires_at_epoch_ns, quote_expiry,
        quote_issued.checked_add(age).ok_or("runtime quote age overflow")?].into_iter().min().unwrap();
    ensure(now >= opening && now < expires && now >= authority.not_before_unix_nanos,
        "runtime originals expired before signing")?;
    let result = RuntimeAttestationVerificationResult {
        schema_version: RUNTIME_VERIFIER_RESPONSE_API_VERSION.into(), status: "verified".into(),
        attestation_policy_sha256: request.attestation_policy_sha256,
        verifier_executable_sha256: request.verifier_executable_sha256,
        attestation_mode: "aws-nitro-enclave".into(), hardware_attested: true,
        assignment_payload_sha256: request.assignment_payload_sha256,
        load_receipt_payload_sha256: request.load_receipt_payload_sha256,
        runtime_identity_sha256: request.runtime_identity_sha256,
        runtime_attestation_receipt_sha256: handoff.receipt_sha256.clone(),
        runtime_attestation_payload_sha256: handoff.receipt_payload_sha256.clone(),
        role_authorization_sha256: handoff.role_authorization_sha256.clone(),
        role_authorization_payload_sha256: handoff.role_authorization_payload_sha256.clone(),
        attestation_evidence_id: evidence.evidence_id.clone(), attestation_evidence_revision: evidence.evidence_revision,
        tee_evidence_sha256: evidence.evidence_sha256.clone(),
        tee_measurement_sha256: policy.expected_tee_measurement_sha256,
        runtime_executable_sha256: policy.expected_runtime_executable_sha256,
        runtime_release_sha256: policy.expected_runtime_release_sha256,
        runtime_config_sha256: role.runtime_config_sha256.clone(), runtime_policy_sha256: role.runtime_policy_sha256.clone(),
        shadow_signing_key_id: role.shadow_signing_key_id.clone(),
        shadow_signing_key_spki_sha256: role.shadow_signing_key_spki_sha256.clone(),
        trust_checkpoint_sha256: request.trust_checkpoint_sha256,
        revocation_generation: authority.revocation_generation, revocation_root_sha256: pin(authority.revocation_root_sha256)?,
        evidence_chain_sha256: chain, trusted_now_unix_nanos: now, maximum_age_nanos: age,
        issued_at_unix_nanos: now, expires_at_unix_nanos: expires,
    };
    result.validate_intrinsic().map_err(|e| e.to_string())?;
    let signature = URL_SAFE_NO_PAD.encode(authority.key.sign(&preimage(&result)?).to_bytes());
    let envelope = SignedEnvelope::from_external_signature(result, pin(authority.key_id)?,
        pin(authority.key_spki_sha256)?, signature).map_err(|e| e.to_string())?;
    let response = canonical(&object!({"apiVersion":RUNTIME_VERIFIER_RESPONSE_API_VERSION,
        "evidence":evidence,"verification":envelope}))?;
    ensure(response.len() <= MAX_OUTPUT, "runtime response exceeds existing verifier bound")?;
    let finished = (authority.check)()?;
    ensure(finished >= now && finished < expires, "runtime authority expired before response")?;
    Ok(Output { original: response, expires_at_unix_nanos: expires })
}
