//! Native target-dispatch evidence. Independent guest assignment is mandatory;
//! an existing holder registration or response signature grants no new purpose.

#[path = "native_verifier/cbor.rs"]
mod cbor;
#[path = "native_verifier/certificates.rs"]
mod certificates;
#[path = "native_verifier/nitro.rs"]
mod nitro;
mod config;

pub use config::{Assignment, Configuration};
pub use crate::response_observation_v2::custody::target_dispatch::wire::{
    NativeCaptureEnvelope, NativeKeyEvidence, NativeStatement,
};
use crate::response_observation_v2::custody::target_dispatch::wire;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    crate::native_response_profile_v1::canonical_ascii_bytes(value)
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn preimage(statement: &NativeStatement) -> Result<Vec<u8>, String> {
    let raw = canonical(statement)?;
    ensure(raw.len() <= 48 * 1024, "native dispatch statement exceeds its bound")?;
    let mut result = wire::NATIVE_DOMAIN.to_vec();
    result.extend(raw);
    Ok(result)
}

pub fn quote_nonce(statement: &NativeStatement, signature: &[u8; 64]) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(wire::QUOTE_DOMAIN);
    hash.update(Sha256::digest(canonical(statement)?));
    hash.update(signature);
    Ok(hash.finalize().into())
}

pub fn validate_statement(statement: &NativeStatement, now_ns: u64) -> Result<(), String> {
    use crate::native_currentness_v1::{bytes32, digest};
    let original = &statement.original;
    let binding = &original.binding;
    let deadline = binding.monotonic_deadline.absolute_boottime_ns.parse::<u64>()
        .map_err(|_| "native dispatch deadline is not an unsigned integer")?;
    ensure(statement.api_version == wire::NATIVE_STATEMENT
        && matches!(statement.phase.as_str(), "prepare" | "capture")
        && original.api_version == wire::ORIGINAL
        && original.generation > 0 && original.generation <= i64::MAX as u64
        && !original.generation_id.is_empty() && original.generation_id.len() <= 256
        && !original.stable_resume_id.is_empty() && original.stable_resume_id.len() <= 256
        && digest(&original.session_sha256) && digest(&original.gate_key_id)
        && original.gate_key_id == statement.key_id && digest(&original.request_sha256)
        && digest(&original.staged_request.content_sha256.0)
        && original.staged_request.generation_id.0 == original.generation_id
        && original.staged_request.content_length > 0
        && original.staged_request.content_length <= wire::MAX_RAW_BYTES
        && original.target.scheme == "https" && original.target.port != 0
        && !original.target.host.is_empty() && original.target.host.len() <= 253
        && original.target.host.is_ascii()
        && !original.target.host.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && !original.target.host.contains(['/', '?', '#', '@', '\\'])
        && original.target.address.parse::<std::net::IpAddr>().is_ok()
        && binding.predecessor_lifecycle_state == crate::response_observation_v2_api::V2AttemptState::Staged
        && binding.attempt_revision > 0 && binding.fencing_token > 0
        && digest(&binding.predecessor_state_sha256)
        && digest(&binding.client_identity_sha256)
        && digest(&binding.transaction.policy_sha256)
        && binding.transaction.upstream_response_sha256.is_none()
        && deadline > 0 && deadline % 1_000_000 == 0
        && deadline.to_string() == binding.monotonic_deadline.absolute_boottime_ns
        && binding.monotonic_deadline.api_version==crate::response_observation_v2_api::V2_MONOTONIC_DEADLINE_VERSION
        && binding.monotonic_deadline.clock_id==crate::response_observation_v2_api::V2MonotonicClockId::ClockBoottime
        && binding.custody_boot_id == binding.monotonic_deadline.custody_boot_id
        && statement.issued_at_epoch_ns > 0 && statement.issued_at_epoch_ns <= now_ns
        && now_ns < statement.expires_at_epoch_ns
        && statement.expires_at_epoch_ns <= binding.deadline_at_epoch_ms.checked_mul(1_000_000)
            .ok_or("native dispatch epoch deadline overflow")?
        && statement.expires_at_epoch_ns - statement.issued_at_epoch_ns <= 30_000_000_000
        && digest(&statement.key_id) && digest(&statement.control_plane_response_signing_key_id),
        "native dispatch statement binding is invalid")?;
    bytes32(&statement.boot_id)?;
    if statement.phase == "prepare" {
        ensure(statement.permit_sha256.is_none() && statement.raw_response.is_none() && statement.tls.is_none(),
            "native dispatch prepare cannot claim a capture")?;
    } else {
        let raw = statement.raw_response.as_ref().ok_or("native capture lacks its exact descriptor")?;
        let tls = statement.tls.as_ref().ok_or("native capture lacks its actual TLS binding")?;
        ensure(statement.permit_sha256.as_deref().is_some_and(digest)
            && raw.fd_index == 0 && raw.byte_length > 0 && raw.byte_length <= wire::MAX_RAW_BYTES
            && digest(&raw.sha256)
            && raw.object_id == format!("obj:{}", &raw.sha256[7..])
            && matches!(raw.media_type, crate::response_observation_v2_api::ExactObjectMediaType::Http11Response)
            && matches!(raw.required_seals, crate::response_observation_v2_api::MemfdSealProfile::ImmutableV1)
            && tls.server_name == original.target.host && tls.port == original.target.port
            && matches!(tls.protocol.as_str(), "TLSv1_2" | "TLSv1_3")
            && !tls.cipher_suite.is_empty() && tls.cipher_suite.len() <= 128
            && tls.cipher_suite.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && digest(&tls.peer_chain_sha256) && digest(&tls.exporter_sha256),
            "native capture does not bind one exact HTTP/1.1 TLS response")?;
    }
    Ok(())
}

/// Pure original-evidence verification. The caller must supply configuration
/// from its actual retained signed guest delivery, never the request envelope.
pub(crate) fn verify(configuration: &Configuration, evidence: &NativeCaptureEnvelope, now_ns: u64)
    -> Result<(), String> {
    let (expected, roots) = configuration.admit(now_ns)?;
    let statement = &evidence.statement;
    validate_statement(statement, now_ns)?;
    let assignment = &configuration.assignment;
    ensure(statement.original.generation_id == configuration.generation_id
        && statement.original.generation == configuration.generation
        && statement.boot_id == assignment.boot_id && statement.key_id == assignment.key_id
        && statement.control_plane_response_signing_key_id == assignment.control_plane_response_signing_key_id
        && statement.original.binding.transaction.policy_sha256 == assignment.policy_hash,
        "native dispatch signer is outside its independent assignment")?;
    ensure(evidence.native_key_evidence.api_version == "serverware.nativeResponseProofKeyEvidence/v1",
        "native dispatch key-evidence family differs")?;
    let key: [u8; 32] = fixed(&evidence.native_key_evidence.response_proof_public_key)?;
    ensure(key != [0; 32], "native dispatch key is zero")?;
    let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    spki.extend(key);
    ensure(sha256(&spki) == assignment.key_id, "native dispatch key differs from independent assignment")?;
    let signature: [u8; 64] = fixed(evidence.signature.strip_prefix("ed25519:")
        .ok_or("native dispatch signature family differs")?)?;
    VerifyingKey::from_bytes(&key).map_err(|_| "native dispatch public key invalid")?
        .verify(&preimage(statement)?, &Signature::from_bytes(&signature))
        .map_err(|_| "native dispatch signature failed")?;
    let mut boot = Sha256::new();
    boot.update(b"serverware/native-proof-custody-boot/v1\0");
    boot.update(fixed::<32>(&assignment.boot_id)?);
    boot.update(digest_bytes(&assignment.key_id)?);
    boot.update(digest_bytes(&assignment.control_plane_response_signing_key_id)?);
    let mut user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04".to_vec();
    for value in [&assignment.release_record_sha256, &assignment.policy_hash, &assignment.configuration_sha256,
        &assignment.ca_certificate_sha256, &assignment.ca_public_key_spki_sha256, &assignment.expected_binary_digest] {
        user_data.extend(digest_bytes(value)?);
    }
    user_data.extend(boot.finalize());
    let document = decode(&evidence.native_key_evidence.attestation_document_b64, 12 * 1024)?;
    nitro::verify(&document, &expected, &roots, &key, &user_data,
        &quote_nonce(statement, &signature)?, now_ns / 1_000_000_000)?;
    Ok(())
}

fn ensure(condition: bool, message: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}
fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= maximum.saturating_mul(4).saturating_add(2) / 3,
        "native dispatch encoding exceeds its bound")?;
    let raw = general_purpose::URL_SAFE_NO_PAD.decode(value).map_err(|_| "native dispatch encoding invalid")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && general_purpose::URL_SAFE_NO_PAD.encode(&raw) == value,
        "native dispatch encoding is not canonical")?;
    Ok(raw)
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode(value, N)?.try_into().map_err(|_| "native dispatch byte length differs".to_owned())
}
fn digest_bytes(value: &str) -> Result<[u8; 32], String> {
    ensure(crate::native_currentness_v1::digest(value), "native dispatch digest invalid")?;
    let mut result = [0; 32];
    hex::decode_to_slice(&value[7..], &mut result).map_err(|_| "native dispatch digest invalid")?;
    Ok(result)
}
