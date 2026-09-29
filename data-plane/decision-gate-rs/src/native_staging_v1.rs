//! Independently admitted measured Reserve/Authorize/Stage purpose. The raw
//! Nitro verifier is shared; neither an old response nor target-dispatch
//! assignment is accepted as permission for this new statement family.
#[path = "native_verifier/cbor.rs"] mod cbor;
#[path = "native_verifier/certificates.rs"] mod certificates;
#[path = "native_verifier/nitro.rs"] mod nitro;
mod config;
pub use config::{Assignment, Configuration};
pub use crate::response_observation_v2::custody::staging::wire::{NativeEvidence, NativeStatement, Original};
use crate::response_observation_v2::custody::staging::wire;
use crate::response_observation_v2_api::{V2AttemptState, V2OperationBinding, V2OperationRequest};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    crate::native_response_profile_v1::canonical_ascii_bytes(value)
}
pub fn sha256(value: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(value)) }
pub fn binding(original: &Original) -> Result<&V2OperationBinding, String> {
    match &original.request {
        V2OperationRequest::Reserve { params, .. } => Ok(&params.binding),
        V2OperationRequest::Authority { params, .. } => Ok(&params.binding),
        V2OperationRequest::Stage { params, .. } => Ok(&params.binding),
        _ => Err("native staging cannot authorize another public operation".into()),
    }
}
pub fn phase(original: &Original) -> Result<&'static str, String> {
    match &original.request {
        V2OperationRequest::Reserve { .. } => Ok("RESERVE"),
        V2OperationRequest::Authority { .. } => Ok("AUTHORIZE"),
        V2OperationRequest::Stage { .. } => Ok("STAGE"),
        _ => Err("native staging phase is not admitted".into()),
    }
}
pub fn deadline(original: &Original) -> Result<u64, String> {
    let encoded = &binding(original)?.monotonic_deadline.absolute_boottime_ns;
    let value = encoded.parse::<u64>().map_err(|_| "native staging deadline invalid")?;
    ensure(value > 0 && value % 1_000_000 == 0 && value.to_string() == *encoded,
        "native staging cannot round or renew original deadline")?;
    Ok(value)
}
pub fn original_sha256(original: &Original) -> Result<String, String> { Ok(sha256(&canonical(original)?)) }
pub fn preimage(statement: &NativeStatement) -> Result<Vec<u8>, String> {
    let raw = canonical(statement)?;
    ensure(raw.len() <= 48 * 1024, "native staging statement exceeds bound")?;
    let mut result = wire::NATIVE_DOMAIN.to_vec(); result.extend(raw); Ok(result)
}
pub fn quote_nonce(statement: &NativeStatement, signature: &[u8; 64]) -> Result<[u8; 32], String> {
    let mut result = Sha256::new(); result.update(wire::QUOTE_DOMAIN);
    result.update(Sha256::digest(canonical(statement)?)); result.update(signature); Ok(result.finalize().into())
}

pub fn validate_statement(value: &NativeStatement, now_ns: u64) -> Result<(), String> {
    use crate::native_currentness_v1::{digest, identifier};
    let original = &value.original; let binding = binding(original)?;
    let owner = &original.owner;
    deadline(original)?;
    ensure(value.api_version == wire::STATEMENT && original.api_version == wire::ORIGINAL
        && identifier(&original.generation_id) && original.generation > 0 && original.generation <= i64::MAX as u64
        && digest(&original.session_sha256) && original.gate_key_id == value.key_id
        && digest(&value.key_id) && digest(&value.control_plane_response_signing_key_id)
        && value.key_id != value.control_plane_response_signing_key_id
        && original.request.api_version() == crate::response_observation_v2_api::RESPONSE_OBSERVATION_V2_API_VERSION
        && original.request.request_id() == binding.request_id
        && original.request.boot_id() == Some(binding.custody_boot_id.as_str())
        && binding.custody_boot_id == binding.monotonic_deadline.custody_boot_id
        && binding.monotonic_deadline.api_version == crate::response_observation_v2_api::V2_MONOTONIC_DEADLINE_VERSION
        && binding.monotonic_deadline.clock_id == crate::response_observation_v2_api::V2MonotonicClockId::ClockBoottime
        && digest(&binding.client_identity_sha256) && digest(&binding.predecessor_state_sha256)
        && digest(&binding.transaction.policy_sha256) && digest(&binding.transaction.client_request_sha256)
        && digest(&binding.transaction.route_semantics_sha256) && binding.transaction.upstream_response_sha256.is_none()
        && binding.transaction.credential_binding_sha256.as_deref().is_some_and(digest)
        && identifier(&owner.process_id) && owner.process_id.len() <= 128
        && owner.pid > 0 && owner.start_time_ticks > 0 && digest(&owner.process_binding_sha256)
        && digest(&owner.cgroup_sha256) && !owner.cgroup_id.is_empty() && owner.cgroup_id.len() <= 128
        && !owner.cgroup_id.starts_with('/') && owner.cgroup_id.split('/').all(|part|
            !part.is_empty() && part != "." && part != ".." && part.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        && value.issued_at_epoch_ns > 0 && value.issued_at_epoch_ns <= now_ns && now_ns < value.expires_at_epoch_ns
        && value.expires_at_epoch_ns - value.issued_at_epoch_ns <= 30_000_000_000
        && value.expires_at_epoch_ns <= binding.deadline_at_epoch_ms.checked_mul(1_000_000)
            .ok_or("native staging epoch overflow")?, "native staging original scope is invalid")?;
    ensure(fixed::<32>(&value.boot_id)? != [0; 32], "native staging boot is zero")?;
    let phase = phase(original)?;
    if phase == "RESERVE" {
        ensure(binding.predecessor_lifecycle_state == V2AttemptState::Genesis
            && binding.attempt_revision == 0 && binding.fencing_token == 0
            && original.predecessor_result_sha256.is_none(), "Reserve must be fresh pre-allocation intent")?;
    } else {
        ensure(binding.attempt_revision > 0 && binding.fencing_token > 0
            && binding.attempt_revision <= crate::response_observation_v2::state_authority::contract::MAX_SAFE_INTEGER
            && binding.fencing_token <= crate::response_observation_v2::state_authority::contract::MAX_SAFE_INTEGER
            && original.predecessor_result_sha256.as_deref().is_some_and(digest)
            && binding.predecessor_lifecycle_state == if phase == "AUTHORIZE" { V2AttemptState::Reserved }
                else { V2AttemptState::AuthorityReady }, "staging predecessor is not exact positive current authority")?;
    }
    let objects = original.request.exact_object_descriptors();
    ensure(objects.len() == if phase == "RESERVE" { 3 } else { 2 }, "staging exact input inventory differs")?;
    for (index, object) in objects.iter().enumerate() {
        ensure(object.fd_index as usize == index && object.byte_length > 0 && object.byte_length <= wire::MAX_INPUT
            && digest(&object.sha256) && identifier(&object.object_id),
            "staging exact input descriptor differs")?;
    }
    Ok(())
}

pub(crate) fn verify(configuration: &Configuration, evidence: &NativeEvidence, now_ns: u64) -> Result<(), String> {
    let (expected, roots) = configuration.admit(now_ns)?;
    let statement = &evidence.statement; validate_statement(statement, now_ns)?;
    let assignment = &configuration.assignment;
    ensure(statement.original.generation_id == configuration.generation_id
        && statement.original.generation == configuration.generation && statement.boot_id == assignment.boot_id
        && statement.key_id == assignment.key_id
        && statement.control_plane_response_signing_key_id == assignment.control_plane_response_signing_key_id
        && binding(&statement.original)?.transaction.policy_sha256 == assignment.policy_hash,
        "native staging signer is outside independently admitted purpose")?;
    ensure(evidence.native_key_evidence.api_version == "serverware.nativeResponseProofKeyEvidence/v1",
        "native staging key evidence family differs")?;
    let key: [u8; 32] = fixed(&evidence.native_key_evidence.response_proof_public_key)?;
    let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]; spki.extend(key);
    ensure(key != [0; 32] && sha256(&spki) == assignment.key_id, "native staging key differs")?;
    let signature: [u8; 64] = fixed(evidence.signature.strip_prefix("ed25519:")
        .ok_or("native staging signature family differs")?)?;
    VerifyingKey::from_bytes(&key).map_err(|_| "native staging public key invalid")?
        .verify(&preimage(statement)?, &Signature::from_bytes(&signature)).map_err(|_| "native staging signature failed")?;
    let mut boot = Sha256::new(); boot.update(b"serverware/native-proof-custody-boot/v1\0");
    boot.update(fixed::<32>(&assignment.boot_id)?); boot.update(digest_bytes(&assignment.key_id)?);
    boot.update(digest_bytes(&assignment.control_plane_response_signing_key_id)?);
    let mut user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04".to_vec();
    for value in [&assignment.release_record_sha256,&assignment.policy_hash,&assignment.configuration_sha256,
        &assignment.ca_certificate_sha256,&assignment.ca_public_key_spki_sha256,&assignment.expected_binary_digest] {
        user_data.extend(digest_bytes(value)?);
    }
    user_data.extend(boot.finalize());
    let document = decode(&evidence.native_key_evidence.attestation_document_b64,12*1024)?;
    nitro::verify(&document,&expected,&roots,&key,&user_data,&quote_nonce(statement,&signature)?,now_ns/1_000_000_000)?;
    Ok(())
}
fn ensure(ok: bool, message: &'static str) -> Result<(), String> { if ok { Ok(()) } else { Err(message.into()) } }
fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= maximum.saturating_mul(4).saturating_add(2)/3,
        "native staging encoding exceeds bound")?;
    let raw = general_purpose::URL_SAFE_NO_PAD.decode(value).map_err(|_| "native staging encoding invalid")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && general_purpose::URL_SAFE_NO_PAD.encode(&raw) == value,
        "native staging encoding is not canonical")?; Ok(raw)
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode(value,N)?.try_into().map_err(|_| "native staging byte count differs".into())
}
fn digest_bytes(value: &str) -> Result<[u8; 32], String> {
    ensure(crate::native_currentness_v1::digest(value), "native staging digest invalid")?;
    let mut bytes=[0;32]; hex::decode_to_slice(&value[7..],&mut bytes).map_err(|_| "native staging digest invalid")?; Ok(bytes)
}
