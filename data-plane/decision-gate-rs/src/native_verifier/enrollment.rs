//! Verify enrollment originals against independent pins and one held TLS session.
//!
//! This diagnostic receiver does not construct/admit packet semantics, consume
//! a durable assignment claim, install trust, or expose the dormant signer.
//! The outer owner supplies the peer address from the same StreamOwned socket;
//! its reviewed TLS configuration and actual selected client-chain provenance
//! remain caller obligations, not facts established by a copied result here.

use super::{decode_b64, digest, digest_text, ensure, exact, fixed_b64,
    ingress_session, json, native_enrollment_assignment_v1 as assignment,
    nitro, text};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::ClientConnection;
use serde_json::{json as value, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_ASSIGNMENT_BYTES: usize = 16 * 1024;
const MAX_PACKET_BYTES: usize = 512 * 1024;
const MAX_SESSION_BYTES: usize = 96 * 1024;
const MAX_QUOTE_BYTES: usize = 12 * 1024;
const MAX_SCOPE_BYTES: usize = 16 * 1024;
const MAX_ROOTS_BYTES: usize = 1024 * 1024;
const MAX_ISSUER_BYTES: usize = 16 * 1024;
const MAX_CLIENT_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 3 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 4096;
const PROCESSING_NS: u64 = 30_000_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;
const RUNTIME_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const REQUEST_DOMAIN: &[u8] = b"serverware/native-enrollment-key-binding/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"serverware/native-enrollment-packet-signature/v1\0";
const ROLE: u8 = 5;

/// Starts before outer JSON decode, not after the assignment or quote. Later
/// owners may narrow this same absolute bound, never create a new allowance.
struct Processing {
    pid: libc::pid_t,
    deadline: u64,
    last_wall: u64,
    last_boot: u64,
    valid_until_wall: u64,
    stopped: bool,
}

fn clocks() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native enrollment wall clock is invalid")?;
    let wall = u64::try_from(wall.as_nanos())
        .map_err(|_| "native enrollment wall clock exceeds its bound")?;
    let mut boot: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) } == 0
        && boot.tv_sec >= 0 && (0..1_000_000_000).contains(&boot.tv_nsec),
        "native enrollment boottime clock is invalid")?;
    let boot = (boot.tv_sec as u64).checked_mul(NS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(boot.tv_nsec as u64))
        .ok_or("native enrollment boottime clock exceeds its bound")?;
    ensure(wall > 0, "native enrollment wall clock is invalid")?;
    Ok((wall, boot))
}

impl Processing {
    fn open(deadline: u64) -> Result<Self, String> {
        let pid = unsafe { libc::getpid() };
        let (wall, boot) = clocks()?;
        let deadline = deadline.min(boot.checked_add(PROCESSING_NS)
            .ok_or("native enrollment processing deadline overflow")?);
        ensure(pid > 0 && boot < deadline, "native enrollment original deadline expired")?;
        Ok(Self { pid, deadline, last_wall: wall, last_boot: boot,
            valid_until_wall: u64::MAX, stopped: false })
    }

    fn check(&mut self, deadline: u64) -> Result<(), String> {
        ensure(!std::mem::replace(&mut self.stopped, true),
            "native enrollment processing owner is stopped")?;
        self.deadline = self.deadline.min(deadline);
        let (wall, boot) = clocks()?;
        ensure(unsafe { libc::getpid() } == self.pid && wall >= self.last_wall
            && boot >= self.last_boot && boot < self.deadline && wall < self.valid_until_wall,
            "native enrollment processing expired or its context changed")?;
        if self.valid_until_wall != u64::MAX {
            self.deadline = self.deadline.min(boot.checked_add(self.valid_until_wall - wall)
                .ok_or("native enrollment remaining original interval overflow")?);
        }
        self.last_wall = wall;
        self.last_boot = boot;
        self.stopped = false;
        Ok(())
    }

    fn restrict_until(&mut self, until_seconds: u64) -> Result<(), String> {
        let until = until_seconds.checked_mul(NS_PER_SECOND)
            .ok_or("native enrollment original expiry exceeds its clock bound")?;
        self.valid_until_wall = self.valid_until_wall.min(until);
        self.check(self.deadline)
    }
}

struct Originals {
    assignment: Vec<u8>,
    packet: Vec<u8>,
    session: Vec<u8>,
    signature: [u8; 64],
    public_key: [u8; 32],
    quote: Vec<u8>,
}

fn original_field(evidence: &Value, field: &str, maximum: usize,
    processing: &mut Processing) -> Result<Vec<u8>, String> {
    processing.check(processing.deadline)?;
    let bytes = decode_b64(text(evidence, field)?, maximum)?;
    processing.check(processing.deadline)?;
    Ok(bytes)
}

fn originals(raw: &[u8], processing: &mut Processing) -> Result<Originals, String> {
    processing.check(processing.deadline)?;
    ensure(raw.len() > 1 && raw.len() <= MAX_EVIDENCE_BYTES && raw.last() == Some(&b'\n'),
        "native enrollment evidence requires one bounded JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native enrollment evidence contains extra framing")?;
    let evidence = json::parse(body, MAX_EVIDENCE_BYTES - 1)?;
    processing.check(processing.deadline)?;
    exact(&evidence, &["apiVersion", "evidenceScope", "okForAction", "assignmentBase64url",
        "packetBase64url", "ingressSessionEvidenceBase64url", "enrollmentSignatureBase64url",
        "enrollmentPublicKeyBase64url", "enrollmentQuoteBase64url"])?;
    ensure(text(&evidence, "apiVersion")? == "serverware.nativeEnrollmentEvidence/v1"
        && text(&evidence, "evidenceScope")? == "unverified-enrollment-public-material"
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native enrollment evidence version or scope differs")?;
    // Sorting explicitly does not depend on serde_json's optional map backend.
    // All nine accepted values are scalars; each original is canonical base64.
    let ordered: BTreeMap<&str, &Value> = evidence.as_object().ok_or("native enrollment object is absent")?
        .iter().map(|(key, item)| (key.as_str(), item)).collect();
    let canonical = serde_json::to_vec(&ordered)
        .map_err(|_| "native enrollment evidence canonical encoding failed")?;
    ensure(canonical.as_slice() == body, "native enrollment evidence is not canonical")?;
    processing.check(processing.deadline)?;
    let assignment = original_field(&evidence, "assignmentBase64url", MAX_ASSIGNMENT_BYTES, processing)?;
    let packet = original_field(&evidence, "packetBase64url", MAX_PACKET_BYTES, processing)?;
    let session = original_field(&evidence, "ingressSessionEvidenceBase64url", MAX_SESSION_BYTES, processing)?;
    let quote = original_field(&evidence, "enrollmentQuoteBase64url", MAX_QUOTE_BYTES, processing)?;
    let signature = fixed_b64::<64>(text(&evidence, "enrollmentSignatureBase64url")?)?;
    let public_key = fixed_b64::<32>(text(&evidence, "enrollmentPublicKeyBase64url")?)?;
    ensure(public_key != [0; 32], "native enrollment key must be nonzero")?;
    processing.check(processing.deadline)?;
    Ok(Originals { assignment, packet, session, signature, public_key, quote })
}

fn assignment_session(assigned: &assignment::VerifiedNativeEnrollmentAssignmentV1,
    session: &ingress_session::VerifiedEnrollmentSession, expected_principal: &str,
    actual_endpoint: SocketAddr, challenge: [u8; 32]) -> Result<(), String> {
    let p = assigned.payload();
    ensure(p.release_record_sha256 == session.scope.release_record
        && p.policy_hash == session.scope.policy
        && p.configuration_sha256 == session.scope.configuration
        && p.runtime_ca_certificate_sha256 == session.ca_certificate_sha256
        && p.runtime_ca_spki_sha256 == session.ca_spki_sha256
        && p.ingress_leaf_certificate_sha256 == session.leaf_certificate_sha256
        && p.client_trust_bundle_sha256 == session.scope.client_trust
        && p.workload_issuer_certificate_sha256 == session.issuer_certificate_sha256
        && p.workload_issuer_spki_sha256 == session.issuer_spki_sha256
        && p.client_certificate_sha256 == session.client_certificate_sha256
        && p.client_spki_sha256 == session.client_spki_sha256
        && p.ingress_host == session.scope.host && p.server_instance_id == session.scope.instance
        && p.client_challenge == challenge && session.challenge == challenge
        && p.principal_id == expected_principal && p.proxy_endpoint == actual_endpoint,
        "native enrollment assignment differs from independent pins or the actual session")
}

fn role_binding(assigned: &assignment::VerifiedNativeEnrollmentAssignmentV1,
    session: &ingress_session::VerifiedEnrollmentSession, public_key: &[u8; 32]) -> Vec<u8> {
    let mut request = Sha256::new();
    request.update(REQUEST_DOMAIN);
    request.update(assigned.original_sha256());
    request.update(assigned.payload().packet_sha256);
    request.update(session.leaf_certificate_sha256);
    request.update(session.scope.client_trust);
    let request: [u8; 32] = request.finalize().into();
    let mut user_data = Vec::with_capacity(RUNTIME_DOMAIN.len() + 1 + 7 * 32);
    user_data.extend_from_slice(RUNTIME_DOMAIN);
    user_data.push(ROLE);
    for field in [session.scope.release_record, session.scope.policy, session.scope.configuration,
        session.ca_certificate_sha256, session.ca_spki_sha256, digest(public_key), request] {
        user_data.extend_from_slice(&field);
    }
    user_data
}

/// Original-only receiver; no supplied successful verifier output is accepted.
/// The wrapper must extract actual_endpoint from the same owned TLS socket.
pub(super) fn verify(raw: &[u8], authorizer_pem: &[u8], pem_sha: &str,
    scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32], client: &ClientConnection,
    issuer_der: &[u8], client_pem: &[u8], expected_principal: &str,
    actual_endpoint: SocketAddr, deadline: u64) -> Result<Vec<u8>, String> {
    let mut processing = Processing::open(deadline)?;
    let inputs = [(raw.len(), MAX_EVIDENCE_BYTES), (authorizer_pem.len(), MAX_ASSIGNMENT_BYTES),
        (scope_raw.len(), MAX_SCOPE_BYTES), (roots_raw.len(), MAX_ROOTS_BYTES),
        (issuer_der.len(), MAX_ISSUER_BYTES), (client_pem.len(), MAX_CLIENT_BYTES)];
    let mut total = 0usize;
    for (size, maximum) in inputs {
        ensure(size > 0 && size <= maximum, "native enrollment original input exceeds its bound")?;
        total = total.checked_add(size).ok_or("native enrollment original aggregate overflow")?;
    }
    ensure(total <= MAX_INPUT_BYTES && pem_sha.len() == 71 && challenge != [0; 32]
        && !expected_principal.is_empty() && expected_principal.len() <= 256
        && expected_principal.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && actual_endpoint.port() != 0,
        "native enrollment independent inputs are outside the fixed profile")?;
    let original = originals(raw, &mut processing)?;
    let mut assigned = assignment::verify_original(&original.assignment, authorizer_pem,
        pem_sha, &original.packet, processing.deadline)?;
    processing.check(assigned.deadline())?;
    assigned.check(processing.deadline)?;
    let mut session = ingress_session::verify_enrollment_with_challenge(&original.session,
        scope_raw, roots_raw, challenge, client, issuer_der, client_pem, processing.deadline)?;
    processing.check(assigned.deadline())?;
    assigned.check(processing.deadline)?;
    assignment_session(&assigned, &session, expected_principal, actual_endpoint, challenge)?;
    ensure(digest(&original.packet) == assigned.payload().packet_sha256,
        "native enrollment original packet digest differs")?;
    let user_data = role_binding(&assigned, &session, &original.public_key);
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + 8 + original.packet.len());
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(&assigned.original_sha256());
    signed.extend_from_slice(&(original.packet.len() as u64).to_be_bytes());
    signed.extend_from_slice(&original.packet);
    let key = VerifyingKey::from_bytes(&original.public_key)
        .map_err(|_| "native enrollment Ed25519 public key is invalid")?;
    key.verify_strict(&signed, &Signature::from_bytes(&original.signature))
        .map_err(|_| "native enrollment packet signature is invalid")?;
    processing.check(assigned.deadline())?;
    assigned.check(processing.deadline)?;
    let opening = session.check(processing.deadline)?;
    let quote = nitro::verify_enrollment(&original.quote, &nitro::NitroExpectationsV1 {
        module_id: &session.scope.module_id, pcrs: &session.scope.pcrs,
        max_age: session.scope.max_age, future_skew: session.scope.future_skew,
    }, &session.roots, &original.public_key, &user_data, &session.quote_nonce, opening)?;
    ensure(quote.issued_unix_seconds >= assigned.payload().not_before_unix_seconds
        && quote.issued_unix_seconds < assigned.payload().expires_at_unix_seconds,
        "native enrollment quote is outside the original assignment interval")?;
    let fresh_until = quote.issued_unix_seconds.checked_add(session.scope.max_age)
        .and_then(|seconds| seconds.checked_add(1))
        .ok_or("native enrollment original quote freshness overflow")?;
    processing.restrict_until(quote.valid_until_unix_seconds.min(fresh_until)
        .min(session.valid_until_unix_seconds).min(assigned.payload().expires_at_unix_seconds))?;

    // Encoding and its fixed bound precede all final lifetime checks. These
    // scalar diagnostics must never be fed back as verification authority.
    let result = value!({
        "apiVersion":"serverware.nativeEnrollmentVerification/v1",
        "resultScope":"local-enrollment-signature-and-session-only", "okForAction":false,
        "evidenceSha256":digest_text(&digest(raw)),
        "assignmentSha256":digest_text(&assigned.original_sha256()),
        "packetSha256":digest_text(&assigned.payload().packet_sha256),
        "enrollmentPublicKeySha256":digest_text(&digest(&original.public_key)),
        "enrollmentQuoteSha256":digest_text(&digest(&original.quote)),
        "ingressSessionEvidenceSha256":digest_text(&digest(&original.session)),
        "expectedPrincipal":expected_principal, "actualProxyEndpoint":actual_endpoint.to_string(),
    });
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native enrollment diagnostic")?;
    ensure(!bytes.is_empty() && bytes.len() < MAX_RESULT_BYTES,
        "native enrollment diagnostic exceeds its bound")?;
    assigned.check(processing.deadline)?;
    processing.check(assigned.deadline())?;
    let closing = session.check(processing.deadline)?;
    ensure(closing >= opening && closing < quote.valid_until_unix_seconds
        && quote.issued_unix_seconds <= closing.saturating_add(session.scope.future_skew)
        && closing.saturating_sub(quote.issued_unix_seconds) <= session.scope.max_age,
        "native enrollment quote or signing certificate expired during verification")?;
    assignment_session(&assigned, &session, expected_principal, actual_endpoint, challenge)?;
    assigned.check(processing.deadline)?;
    processing.check(assigned.deadline())?;
    Ok(bytes)
}
