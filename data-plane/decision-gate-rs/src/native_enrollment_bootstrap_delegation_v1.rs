//! Independently signed caller-to-target delegation originals, not admission.
//!
//! The expected authorizer and exact PEM pin come from retained cold authority.
//! This private owner authenticates the closed delegation and target-request
//! hash. The actual caller, runtime/policy/TLS, target CSR/PoP and selected issuer
//! must still be admitted from their own originals by the consuming owner. No
//! copied result, target certificate, packet, durable claim or signer is input.

use super::assignment;
use super::native_workload_bootstrap_request_v1::{decode_canonical, encode_canonical, validate_sans};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::net::SocketAddr;

const ENVELOPE_VERSION: &str = "catchplate.signedNativeEnrollmentBootstrapDelegation/v1";
const PAYLOAD_VERSION: &str = "catchplate.nativeEnrollmentBootstrapDelegation/v1";
const PURPOSE: &str = "native-enrollment-bootstrap";
const DOMAIN: &[u8] = b"catchplate/native-enrollment-bootstrap-delegation/v1\0";
const MAX_ORIGINAL_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_SECONDS: u64 = 9_223_372_036;
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;
const PROCESSING_NS: u64 = 30_000_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    api_version: String,
    delegation: WireDelegation,
    signature_base64url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestedSans {
    dns_names: Vec<String>,
    uris: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDelegation {
    api_version: String,
    purpose: String,
    authorizer_key_id: String,
    delegation_id: String,
    release_record_sha256: String,
    policy_hash: String,
    configuration_sha256: String,
    runtime_ca_certificate_sha256: String,
    runtime_ca_spki_sha256: String,
    ingress_leaf_certificate_sha256: String,
    client_trust_bundle_sha256: String,
    caller_principal_id: String,
    caller_issuer_certificate_sha256: String,
    caller_issuer_spki_sha256: String,
    caller_certificate_sha256: String,
    caller_spki_sha256: String,
    ingress_host: String,
    server_instance_id: String,
    proxy_endpoint: String,
    client_challenge_base64url: String,
    target_principal_id: String,
    target_nonce: String,
    target_request_sha256: String,
    target_csr_sha256: String,
    target_spki_sha256: String,
    target_requested_sans: RequestedSans,
    target_issuer_certificate_der_sha256: String,
    target_issuer_spki_sha256: String,
    target_created_at_epoch_ms: u64,
    target_expires_at_epoch_ms: u64,
    not_before_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

/// Immutable comparisons only. No API accepts this payload as evidence or
/// constructs an owner from a successful target-verification result.
pub(crate) struct DelegationPayload {
    pub(crate) authorizer_key_id: [u8; 32],
    pub(crate) delegation_id: [u8; 32],
    pub(crate) release_record_sha256: [u8; 32],
    pub(crate) policy_hash: [u8; 32],
    pub(crate) configuration_sha256: [u8; 32],
    pub(crate) runtime_ca_certificate_sha256: [u8; 32],
    pub(crate) runtime_ca_spki_sha256: [u8; 32],
    pub(crate) ingress_leaf_certificate_sha256: [u8; 32],
    pub(crate) client_trust_bundle_sha256: [u8; 32],
    pub(crate) caller_principal_id: String,
    pub(crate) caller_issuer_certificate_sha256: [u8; 32],
    pub(crate) caller_issuer_spki_sha256: [u8; 32],
    pub(crate) caller_certificate_sha256: [u8; 32],
    pub(crate) caller_spki_sha256: [u8; 32],
    pub(crate) ingress_host: String,
    pub(crate) server_instance_id: String,
    pub(crate) proxy_endpoint: SocketAddr,
    pub(crate) client_challenge: [u8; 32],
    pub(crate) target_principal_id: String,
    pub(crate) target_nonce: String,
    pub(crate) target_request_sha256: [u8; 32],
    pub(crate) target_csr_sha256: [u8; 32],
    pub(crate) target_spki_sha256: [u8; 32],
    pub(crate) target_requested_dns: Vec<String>,
    pub(crate) target_requested_uris: Vec<String>,
    pub(crate) target_issuer_certificate_der_sha256: [u8; 32],
    pub(crate) target_issuer_spki_sha256: [u8; 32],
    pub(crate) target_created_at_epoch_ms: u64,
    pub(crate) target_expires_at_epoch_ms: u64,
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

/// Non-Clone/non-Debug original owner. Any failed check poisons it; a later
/// caller deadline or forward wall-clock step can only shorten its bound.
pub(crate) struct VerifiedNativeEnrollmentBootstrapDelegationV1 {
    payload: DelegationPayload,
    original_sha256: [u8; 32],
    deadline: u64,
    owner_pid: libc::pid_t,
    last_wall_ns: u64,
    last_boot_ns: u64,
    poisoned: bool,
}

fn require(condition: bool, error: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_owned()) }
}

fn digest(original: &[u8]) -> [u8; 32] { Sha256::digest(original).into() }

fn framing(original: &[u8]) -> Result<&[u8], String> {
    require(original.len() > 1 && original.len() <= MAX_ORIGINAL_BYTES
        && original.last() == Some(&b'\n'), "native bootstrap delegation requires one bounded JSON line")?;
    let body = &original[..original.len() - 1];
    require(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native bootstrap delegation JSON framing differs")?;
    // The additive codec bounds nesting to four before typed decoding, rejects
    // duplicates/extra fields and checks exact Python ensure_ascii=True bytes.
    // A Unicode target principal is retained, not narrowed to printable ASCII.
    Ok(body)
}

pub(crate) fn verify_original(delegation_original: &[u8], authorizer_pem_original: &[u8],
    expected_authorizer_pem_sha256: &str, target_request_original: &[u8], deadline: u64)
    -> Result<VerifiedNativeEnrollmentBootstrapDelegationV1, String> {
    let owner_pid = unsafe { libc::getpid() };
    let (wall, boot) = assignment::sample()?;
    require(owner_pid > 0 && boot < deadline, "native bootstrap delegation original deadline expired")?;
    let deadline = deadline.min(boot.checked_add(PROCESSING_NS)
        .ok_or("native bootstrap delegation deadline overflow")?);
    require(!target_request_original.is_empty() && target_request_original.len() <= MAX_REQUEST_BYTES,
        "native bootstrap target request original exceeds its bound")?;
    let envelope: Envelope = decode_canonical(framing(delegation_original)?, MAX_ORIGINAL_BYTES)?;
    require(envelope.api_version == ENVELOPE_VERSION
        && envelope.delegation.api_version == PAYLOAD_VERSION && envelope.delegation.purpose == PURPOSE,
        "native bootstrap delegation version or purpose differs")?;
    let (key, key_id) = assignment::authorizer(authorizer_pem_original, expected_authorizer_pem_sha256)?;
    require(!key.is_weak(), "native bootstrap delegation authorizer key is weak")?;
    let p = envelope.delegation;
    let canonical = encode_canonical(&p, MAX_ORIGINAL_BYTES)?;
    let signature = Signature::from_bytes(&assignment::fixed_base64::<64>(&envelope.signature_base64url)?);
    let mut signed = Vec::with_capacity(DOMAIN.len() + canonical.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&canonical);
    key.verify_strict(&signed, &signature).map_err(|_| "native bootstrap delegation signature is invalid")?;
    require(assignment::digest_field(&p.authorizer_key_id)? == key_id,
        "native bootstrap delegation differs from the independent authorizer")?;
    require(!p.caller_principal_id.is_empty() && p.caller_principal_id.len() <= 256
        && p.caller_principal_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && assignment::host(&p.ingress_host) && assignment::instance(&p.server_instance_id),
        "native bootstrap delegation caller, host or instance is invalid")?;
    require(!p.target_principal_id.is_empty() && p.target_principal_id.len() <= 1024
        && (32..=256).contains(&p.target_nonce.len())
        && p.target_nonce.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "native bootstrap delegation target principal or nonce is invalid")?;
    validate_sans(&p.target_requested_sans.dns_names, &p.target_requested_sans.uris)?;
    require(p.not_before_unix_seconds > 0 && p.expires_at_unix_seconds <= MAX_SECONDS
        && p.expires_at_unix_seconds > p.not_before_unix_seconds
        && p.expires_at_unix_seconds - p.not_before_unix_seconds <= 300,
        "native bootstrap delegation interval is invalid")?;
    require(p.target_created_at_epoch_ms > 0 && p.target_expires_at_epoch_ms <= MAX_EPOCH_MS
        && p.target_expires_at_epoch_ms > p.target_created_at_epoch_ms
        && p.target_expires_at_epoch_ms - p.target_created_at_epoch_ms <= 300_000
        && p.not_before_unix_seconds * 1000 >= p.target_created_at_epoch_ms
        && p.expires_at_unix_seconds * 1000 <= p.target_expires_at_epoch_ms,
        "native bootstrap delegation exceeds the original target request interval")?;
    let before = p.not_before_unix_seconds * NS_PER_SECOND;
    let expires = p.expires_at_unix_seconds * NS_PER_SECOND;
    require(before <= wall && wall < expires, "native bootstrap delegation is outside its original interval")?;
    let target_request_sha256 = assignment::digest_field(&p.target_request_sha256)?;
    require(digest(target_request_original) == target_request_sha256,
        "native bootstrap target request differs from its delegated original")?;
    let payload = DelegationPayload {
        authorizer_key_id: key_id, delegation_id: assignment::nonzero_base64(&p.delegation_id)?,
        release_record_sha256: assignment::digest_field(&p.release_record_sha256)?,
        policy_hash: assignment::digest_field(&p.policy_hash)?,
        configuration_sha256: assignment::digest_field(&p.configuration_sha256)?,
        runtime_ca_certificate_sha256: assignment::digest_field(&p.runtime_ca_certificate_sha256)?,
        runtime_ca_spki_sha256: assignment::digest_field(&p.runtime_ca_spki_sha256)?,
        ingress_leaf_certificate_sha256: assignment::digest_field(&p.ingress_leaf_certificate_sha256)?,
        client_trust_bundle_sha256: assignment::digest_field(&p.client_trust_bundle_sha256)?,
        caller_principal_id: p.caller_principal_id,
        caller_issuer_certificate_sha256: assignment::digest_field(&p.caller_issuer_certificate_sha256)?,
        caller_issuer_spki_sha256: assignment::digest_field(&p.caller_issuer_spki_sha256)?,
        caller_certificate_sha256: assignment::digest_field(&p.caller_certificate_sha256)?,
        caller_spki_sha256: assignment::digest_field(&p.caller_spki_sha256)?,
        ingress_host: p.ingress_host, server_instance_id: p.server_instance_id,
        proxy_endpoint: assignment::validate_proxy_endpoint_original(&p.proxy_endpoint)?,
        client_challenge: assignment::nonzero_base64(&p.client_challenge_base64url)?,
        target_principal_id: p.target_principal_id, target_nonce: p.target_nonce,
        target_request_sha256,
        target_csr_sha256: assignment::digest_field(&p.target_csr_sha256)?,
        target_spki_sha256: assignment::digest_field(&p.target_spki_sha256)?,
        target_requested_dns: p.target_requested_sans.dns_names,
        target_requested_uris: p.target_requested_sans.uris,
        target_issuer_certificate_der_sha256: assignment::digest_field(&p.target_issuer_certificate_der_sha256)?,
        target_issuer_spki_sha256: assignment::digest_field(&p.target_issuer_spki_sha256)?,
        target_created_at_epoch_ms: p.target_created_at_epoch_ms,
        target_expires_at_epoch_ms: p.target_expires_at_epoch_ms,
        not_before_unix_seconds: p.not_before_unix_seconds, expires_at_unix_seconds: p.expires_at_unix_seconds,
    };
    require([payload.runtime_ca_spki_sha256, payload.caller_issuer_spki_sha256,
        payload.caller_spki_sha256, payload.target_issuer_spki_sha256, payload.target_spki_sha256]
        .iter().all(|candidate| candidate != &key_id),
        "native bootstrap authorizer shares a delegated runtime, issuer or workload key role")?;
    let expiry_deadline = boot.checked_add(expires - wall)
        .ok_or("native bootstrap delegation expiry deadline overflow")?;
    let mut result = VerifiedNativeEnrollmentBootstrapDelegationV1 { payload,
        original_sha256: digest(delegation_original), deadline: deadline.min(expiry_deadline),
        owner_pid, last_wall_ns: wall, last_boot_ns: boot, poisoned: false };
    result.check(deadline)?;
    Ok(result)
}

impl VerifiedNativeEnrollmentBootstrapDelegationV1 {
    pub(crate) fn payload(&self) -> &DelegationPayload { &self.payload }
    pub(crate) fn original_sha256(&self) -> [u8; 32] { self.original_sha256 }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), String> {
        require(!std::mem::replace(&mut self.poisoned, true), "native bootstrap delegation owner is poisoned")?;
        self.deadline = self.deadline.min(deadline);
        require(unsafe { libc::getpid() } == self.owner_pid, "native bootstrap delegation crossed its process")?;
        let (wall, boot) = assignment::sample()?;
        let before = self.payload.not_before_unix_seconds * NS_PER_SECOND;
        let expires = self.payload.expires_at_unix_seconds * NS_PER_SECOND;
        require(wall >= self.last_wall_ns && boot >= self.last_boot_ns
            && boot < self.deadline && before <= wall && wall < expires,
            "native bootstrap delegation expired or a clock moved backwards")?;
        self.deadline = self.deadline.min(boot.checked_add(expires - wall)
            .ok_or("native bootstrap delegation remaining interval overflow")?);
        self.last_wall_ns = wall;
        self.last_boot_ns = boot;
        self.poisoned = false;
        Ok(())
    }
}
