//! Independently signed native-enrollment assignment originals, not admission.
//!
//! The authorizer PEM and its exact-byte pin must come from independent cold
//! authority. Neither the envelope nor a quote chooses that root. This private
//! owner authenticates the closed assignment and exact packet hash only: it
//! does not admit runtime/PCR provenance, principal policy, packet semantics,
//! TLS possession, a durable nonce claim or a production enrollment endpoint.
//! No cloning, serialization, private key, file access or public signer exists.

// Both private compilation sites use the same canonical implementation: the
// custody library directly and the native receiver through its library imports.
use super::{canonical_json_bytes, decode_canonical_json};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const ENVELOPE_VERSION: &str = "serverware.signedNativeEnrollmentAssignment/v1";
const ASSIGNMENT_VERSION: &str = "serverware.nativeEnrollmentAssignment/v1";
const DOMAIN: &[u8] = b"serverware/native-enrollment-assignment/v1\0";
const MAX_ORIGINAL_BYTES: usize = 16 * 1024;
const MAX_PACKET_BYTES: usize = 512 * 1024;
const MAX_SECONDS: u64 = 9_223_372_036;
const PROCESSING_NS: u64 = 30_000_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;
const ED25519_SPKI: &[u8] = &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    api_version: String,
    assignment: WireAssignment,
    signature_base64url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireAssignment {
    api_version: String,
    authorizer_key_id: String,
    assignment_id: String,
    release_record_sha256: String,
    policy_hash: String,
    configuration_sha256: String,
    runtime_ca_certificate_sha256: String,
    runtime_ca_spki_sha256: String,
    ingress_leaf_certificate_sha256: String,
    client_trust_bundle_sha256: String,
    principal_id: String,
    workload_issuer_certificate_sha256: String,
    workload_issuer_spki_sha256: String,
    client_certificate_sha256: String,
    client_spki_sha256: String,
    ingress_host: String,
    server_instance_id: String,
    proxy_endpoint: String,
    packet_sha256: String,
    client_challenge_base64url: String,
    not_before_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

/// Immutable fields can be compared by the private consuming owner. A copied
/// payload is never accepted in place of verified original bytes.
pub(crate) struct AssignmentPayload {
    pub(crate) authorizer_key_id: [u8; 32],
    pub(crate) assignment_id: [u8; 32],
    pub(crate) release_record_sha256: [u8; 32],
    pub(crate) policy_hash: [u8; 32],
    pub(crate) configuration_sha256: [u8; 32],
    pub(crate) runtime_ca_certificate_sha256: [u8; 32],
    pub(crate) runtime_ca_spki_sha256: [u8; 32],
    pub(crate) ingress_leaf_certificate_sha256: [u8; 32],
    pub(crate) client_trust_bundle_sha256: [u8; 32],
    pub(crate) principal_id: String,
    pub(crate) workload_issuer_certificate_sha256: [u8; 32],
    pub(crate) workload_issuer_spki_sha256: [u8; 32],
    pub(crate) client_certificate_sha256: [u8; 32],
    pub(crate) client_spki_sha256: [u8; 32],
    pub(crate) ingress_host: String,
    pub(crate) server_instance_id: String,
    pub(crate) proxy_endpoint: SocketAddr,
    pub(crate) packet_sha256: [u8; 32],
    pub(crate) client_challenge: [u8; 32],
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

/// Source-created, non-Clone/non-Debug owner, consumed by value at the signing
/// boundary. Failure poisons it; later checks only tighten its original bound.
pub(crate) struct VerifiedNativeEnrollmentAssignmentV1 {
    payload: AssignmentPayload,
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

pub(crate) fn digest_field(value: &str) -> Result<[u8; 32], String> {
    let encoded = value.strip_prefix("sha256:").ok_or("native assignment digest prefix differs")?;
    require(encoded.len() == 64 && encoded.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native assignment digest is not canonical")?;
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(encoded, &mut decoded).map_err(|_| "native assignment digest is invalid")?;
    require(decoded != [0; 32], "native assignment digest must be nonzero")?;
    Ok(decoded)
}

pub(crate) fn fixed_base64<const N: usize>(value: &str) -> Result<[u8; N], String> {
    require(value.len() == (N * 4 + 2) / 3, "native assignment base64url size differs")?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "native assignment base64url is invalid")?;
    require(raw.len() == N && URL_SAFE_NO_PAD.encode(&raw) == value,
        "native assignment base64url is not canonical")?;
    raw.try_into().map_err(|_| "native assignment base64url size differs".to_owned())
}

pub(crate) fn nonzero_base64(value: &str) -> Result<[u8; 32], String> {
    let decoded = fixed_base64(value)?;
    require(decoded != [0; 32], "native assignment identity or challenge must be nonzero")?;
    Ok(decoded)
}

pub(crate) fn authorizer(original: &[u8], expected: &str) -> Result<(VerifyingKey, [u8; 32]), String> {
    require(!original.is_empty() && original.len() <= MAX_ORIGINAL_BYTES
        && digest(original) == digest_field(expected)?, "native assignment authorizer pin differs")?;
    let text = std::str::from_utf8(original).map_err(|_| "native assignment authorizer PEM is invalid")?;
    let head = "-----BEGIN PUBLIC KEY-----\n";
    let tail = "-----END PUBLIC KEY-----\n";
    let body = text.strip_prefix(head).and_then(|value| value.strip_suffix(tail))
        .ok_or("native assignment authorizer PEM framing differs")?;
    let compact: String = body.chars().filter(|value| *value != '\n').collect();
    let der = STANDARD.decode(compact).map_err(|_| "native assignment authorizer PEM base64 is invalid")?;
    require(der.len() == ED25519_SPKI.len() + 32 && der.starts_with(ED25519_SPKI),
        "native assignment authorizer must be an exact Ed25519 SPKI")?;
    let encoded = STANDARD.encode(&der);
    let canonical = format!("{head}{encoded}\n{tail}");
    require(canonical.as_bytes() == original, "native assignment authorizer PEM is not canonical")?;
    let public: [u8; 32] = der[ED25519_SPKI.len()..].try_into()
        .map_err(|_| "native assignment authorizer key size differs")?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| "native assignment authorizer key is invalid")?;
    Ok((key, digest(&der)))
}

/// Public-original shape/key validation for cold intake, not root provenance
/// or an assignment verification. No signing key or accepted carrier escapes.
pub(crate) fn validate_authorizer_original(original: &[u8], expected: &str)
    -> Result<[u8; 32], String> {
    let (key, key_id) = authorizer(original, expected)?;
    require(!key.is_weak(), "native enrollment authorizer key is weak")?;
    Ok(key_id)
}

/// Reuse the exact assignment endpoint profile for independently pinned cold
/// configuration. This is a public endpoint pin, not observed transport data.
pub(crate) fn validate_proxy_endpoint_original(original: &str) -> Result<SocketAddr, String> {
    endpoint(original)
}

// The only containers are the envelope and its assignment. Bound depth before
// the shared duplicate-rejecting canonical decoder allocates a JSON graph.
fn framing(original: &[u8]) -> Result<&[u8], String> {
    require(original.len() > 1 && original.len() <= MAX_ORIGINAL_BYTES
        && original.last() == Some(&b'\n'), "native assignment requires one bounded JSON line")?;
    let body = &original[..original.len() - 1];
    require(!body.contains(&b'\n') && !body.contains(&b'\r') && body.is_ascii(),
        "native assignment JSON framing is invalid")?;
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for byte in body {
        if quoted {
            if escaped { escaped = false; }
            else if *byte == b'\\' { escaped = true; }
            else if *byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' => { depth += 1; require(depth <= 2, "native assignment JSON is too deep")?; }
                b'}' => { depth = depth.checked_sub(1).ok_or("native assignment JSON nesting is invalid")?; }
                b'[' | b']' => return Err("native assignment JSON arrays are unsupported".to_owned()),
                _ => {},
            }
        }
    }
    require(!quoted && !escaped && depth == 0, "native assignment JSON is incomplete")?;
    Ok(body)
}

fn dns(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit() || byte == b'-'))
}

pub(crate) fn host(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.is_ascii()
        && value == value.to_ascii_lowercase() && !value.contains('*') && !value.ends_with('.')
        && match value.parse::<IpAddr>() {
            Ok(address) => address.to_string() == value,
            Err(_) => dns(value),
        }
}

pub(crate) fn instance(value: &str) -> bool {
    if !value.starts_with("spiffe://") || value.len() > 256 || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| url.as_str() == value && url.scheme() == "spiffe"
        && url.username().is_empty() && url.password().is_none()
        && url.host_str().is_some_and(dns) && url.port().is_none()
        && url.query().is_none() && url.fragment().is_none()
        && !url.path().contains("//")
        && !url.path().split('/').any(|segment| matches!(segment, "." | ".."))
        && url.path().bytes().all(|byte| byte.is_ascii_alphanumeric()
            || b"._~!$&'()*+,;=:@%/-".contains(&byte)))
}

fn endpoint(value: &str) -> Result<SocketAddr, String> {
    require(!value.is_empty() && value.len() <= 64 && value.is_ascii(),
        "native assignment endpoint is not bounded ASCII")?;
    let address: SocketAddr = value.parse().map_err(|_| "native assignment endpoint is not a socket address")?;
    require(address.to_string() == value && address.port() != 0,
        "native assignment endpoint is not canonical")?;
    let ip = match address {
        SocketAddr::V4(value) => IpAddr::V4(*value.ip()),
        SocketAddr::V6(value) => {
            require(value.scope_id() == 0 && value.flowinfo() == 0,
                "native assignment endpoint cannot select an IPv6 scope")?;
            value.ip().to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(*value.ip()))
        },
    };
    require(!ip.is_unspecified() && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(value) if value.is_broadcast()),
        "native assignment endpoint must be concrete unicast")?;
    Ok(address)
}

pub(crate) fn sample() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native assignment wall clock is invalid")?.as_nanos();
    let wall = u64::try_from(wall).map_err(|_| "native assignment wall clock overflow")?;
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } == 0
        && observed.tv_sec >= 0 && (0..1_000_000_000).contains(&observed.tv_nsec),
        "native assignment boottime clock is invalid")?;
    let boot = u64::try_from(observed.tv_sec as u128 * NS_PER_SECOND as u128 + observed.tv_nsec as u128)
        .map_err(|_| "native assignment boottime clock overflow")?;
    require(wall > 0 && boot > 0, "native assignment clock must be positive")?;
    Ok((wall, boot))
}

pub(crate) fn verify_original(assignment_original: &[u8], authorizer_pem_original: &[u8],
    expected_authorizer_pem_sha256: &str, packet_original: &[u8], deadline: u64)
    -> Result<VerifiedNativeEnrollmentAssignmentV1, String> {
    let owner_pid = unsafe { libc::getpid() };
    let (wall, boot) = sample()?;
    require(owner_pid > 0 && boot < deadline, "native assignment original deadline expired")?;
    let deadline = deadline.min(boot.checked_add(PROCESSING_NS).ok_or("native assignment deadline overflow")?);
    require(!packet_original.is_empty() && packet_original.len() <= MAX_PACKET_BYTES,
        "native assignment packet original exceeds its bound")?;
    let envelope: Envelope = decode_canonical_json(framing(assignment_original)?)
        .map_err(|_| "native assignment violates its closed canonical envelope")?;
    require(envelope.api_version == ENVELOPE_VERSION && envelope.assignment.api_version == ASSIGNMENT_VERSION,
        "native assignment version differs")?;
    let (key, key_id) = authorizer(authorizer_pem_original, expected_authorizer_pem_sha256)?;
    let p = envelope.assignment;
    let canonical = canonical_json_bytes(&p).map_err(|_| "native assignment payload encoding failed")?;
    let signature = Signature::from_bytes(&fixed_base64::<64>(&envelope.signature_base64url)?);
    let mut signed = Vec::with_capacity(DOMAIN.len() + canonical.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&canonical);
    key.verify_strict(&signed, &signature).map_err(|_| "native assignment signature is invalid")?;
    require(digest_field(&p.authorizer_key_id)? == key_id,
        "native assignment authorizer key differs from the independent original")?;
    require(!p.principal_id.is_empty() && p.principal_id.len() <= 256
        && p.principal_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && host(&p.ingress_host) && instance(&p.server_instance_id),
        "native assignment principal, host or instance is invalid")?;
    require(p.not_before_unix_seconds > 0 && p.expires_at_unix_seconds <= MAX_SECONDS
        && p.expires_at_unix_seconds > p.not_before_unix_seconds
        && p.expires_at_unix_seconds - p.not_before_unix_seconds <= 300,
        "native assignment interval is invalid")?;
    let not_before = p.not_before_unix_seconds * NS_PER_SECOND;
    let expires = p.expires_at_unix_seconds * NS_PER_SECOND;
    require(not_before <= wall && wall < expires, "native assignment is outside its original interval")?;
    let packet_sha256 = digest_field(&p.packet_sha256)?;
    require(digest(packet_original) == packet_sha256, "native assignment packet original differs")?;
    let payload = AssignmentPayload {
        authorizer_key_id: key_id, assignment_id: nonzero_base64(&p.assignment_id)?,
        release_record_sha256: digest_field(&p.release_record_sha256)?,
        policy_hash: digest_field(&p.policy_hash)?, configuration_sha256: digest_field(&p.configuration_sha256)?,
        runtime_ca_certificate_sha256: digest_field(&p.runtime_ca_certificate_sha256)?,
        runtime_ca_spki_sha256: digest_field(&p.runtime_ca_spki_sha256)?,
        ingress_leaf_certificate_sha256: digest_field(&p.ingress_leaf_certificate_sha256)?,
        client_trust_bundle_sha256: digest_field(&p.client_trust_bundle_sha256)?,
        workload_issuer_certificate_sha256: digest_field(&p.workload_issuer_certificate_sha256)?,
        workload_issuer_spki_sha256: digest_field(&p.workload_issuer_spki_sha256)?,
        client_certificate_sha256: digest_field(&p.client_certificate_sha256)?,
        client_spki_sha256: digest_field(&p.client_spki_sha256)?,
        proxy_endpoint: endpoint(&p.proxy_endpoint)?, packet_sha256,
        client_challenge: nonzero_base64(&p.client_challenge_base64url)?,
        principal_id: p.principal_id, ingress_host: p.ingress_host, server_instance_id: p.server_instance_id,
        not_before_unix_seconds: p.not_before_unix_seconds, expires_at_unix_seconds: p.expires_at_unix_seconds,
    };
    let expiry_deadline = boot.checked_add(expires - wall).ok_or("native assignment expiry deadline overflow")?;
    let mut result = VerifiedNativeEnrollmentAssignmentV1 { payload,
        original_sha256: digest(assignment_original), deadline: deadline.min(expiry_deadline),
        owner_pid, last_wall_ns: wall, last_boot_ns: boot, poisoned: false };
    result.check(deadline)?;
    Ok(result)
}

impl VerifiedNativeEnrollmentAssignmentV1 {
    pub(crate) fn payload(&self) -> &AssignmentPayload { &self.payload }
    pub(crate) fn original_sha256(&self) -> [u8; 32] { self.original_sha256 }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), String> {
        require(!std::mem::replace(&mut self.poisoned, true), "native assignment owner is poisoned")?;
        self.deadline = self.deadline.min(deadline);
        require(unsafe { libc::getpid() } == self.owner_pid, "native assignment owner crossed its process")?;
        let (wall, boot) = sample()?;
        let before = self.payload.not_before_unix_seconds * NS_PER_SECOND;
        let expires = self.payload.expires_at_unix_seconds * NS_PER_SECOND;
        require(wall >= self.last_wall_ns && boot >= self.last_boot_ns
            && boot < self.deadline && before <= wall && wall < expires,
            "native assignment expired or a clock moved backwards")?;
        // A forward wall-clock step can shorten, never replenish, boottime.
        self.deadline = self.deadline.min(boot.checked_add(expires - wall)
            .ok_or("native assignment remaining interval overflow")?);
        self.last_wall_ns = wall;
        self.last_boot_ns = boot;
        self.poisoned = false;
        Ok(())
    }
}
