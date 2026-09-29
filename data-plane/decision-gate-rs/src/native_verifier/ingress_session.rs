//! Join fresh role-3 originals to the caller's actual completed outer TLS.
//!
//! This API does not create or vet the client TLS configuration, perform HTTP
//! IO, consume a one-use challenge, install a CA or admit a production release.
//! The caller must retain the outer connection and use a reviewed verifier
//! which checks the TLS CertificateVerify signature; ClientConnection does not
//! expose whether its configuration used an unsafe custom verifier.

use super::{b64, config::TrustRoots, decode_b64, digest, digest_text, ensure, exact,
    fixed_b64, ingress::{self, EvidenceProfile}, ingress_config::{Expectations, SessionScope}, json, text};
use rustls::{ClientConnection, HandshakeKind, ProtocolVersion};
use serde_json::{json, Value};
use serverware_decision_gate::native_ingress_challenge_v1::{derive_nonce, EXPORTER_LABEL};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INPUT: usize = 96 * 1024;
const MAX_PUBLIC_IDENTITY: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;

enum SessionExpectations<'a> {
    PinnedNonce { expected: &'a Expectations, original: &'a [u8] },
    ClientChallenge { scope: &'a SessionScope, original: &'a [u8], challenge: [u8; 32] },
}

struct VerifiedSession {
    public_identity: Vec<u8>,
    ingress: ingress::VerifiedIngress,
    workload: Option<ingress::VerifiedClientIssuer>,
    exporter: [u8; 32],
    peer_leaf_sha256: [u8; 32],
}

/// Private, same-call facts for the original-only enrollment receiver. No
/// external API accepts this object or a serialized summary as authority.
/// Certificate intervals and the supplied original deadline are never renewed.
pub(super) struct VerifiedEnrollmentSession {
    pub(super) scope: SessionScope,
    pub(super) roots: TrustRoots,
    pub(super) ca_certificate_sha256: [u8; 32],
    pub(super) ca_spki_sha256: [u8; 32],
    pub(super) leaf_certificate_sha256: [u8; 32],
    pub(super) issuer_certificate_sha256: [u8; 32],
    pub(super) issuer_spki_sha256: [u8; 32],
    pub(super) client_certificate_sha256: [u8; 32],
    pub(super) client_spki_sha256: [u8; 32],
    pub(super) challenge: [u8; 32],
    pub(super) quote_nonce: [u8; 32],
    pub(super) quote_issued_unix_seconds: u64,
    pub(super) valid_until_unix_seconds: u64,
    valid_from_unix_seconds: u64,
    deadline: u64,
    owner_pid: libc::pid_t,
    last_wall_ns: u64,
    last_boot_ns: u64,
    failed: bool,
}

fn clocks() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native enrollment session wall clock is invalid")?.as_nanos();
    let wall = u64::try_from(wall).map_err(|_| "native enrollment session wall clock overflow")?;
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } == 0
        && observed.tv_sec >= 0 && (0..1_000_000_000).contains(&observed.tv_nsec),
        "native enrollment session boottime is invalid")?;
    let boot = u64::try_from(observed.tv_sec as u128 * 1_000_000_000 + observed.tv_nsec as u128)
        .map_err(|_| "native enrollment session boottime overflow")?;
    ensure(wall > 0 && boot > 0, "native enrollment session clock must be positive")?;
    Ok((wall, boot))
}

impl VerifiedEnrollmentSession {
    pub(super) fn check(&mut self, deadline: u64) -> Result<u64, String> {
        ensure(!std::mem::replace(&mut self.failed, true), "native enrollment session is poisoned")?;
        self.deadline = self.deadline.min(deadline);
        ensure(unsafe { libc::getpid() } == self.owner_pid,
            "native enrollment session crossed its creating process")?;
        let (wall, boot) = clocks()?;
        let now = wall / 1_000_000_000;
        ensure(wall >= self.last_wall_ns && boot >= self.last_boot_ns && boot < self.deadline
            && self.valid_from_unix_seconds <= now && now < self.valid_until_unix_seconds
            && self.quote_issued_unix_seconds <= now.checked_add(self.scope.future_skew)
                .ok_or("native enrollment session quote age overflow")?
            && now.saturating_sub(self.quote_issued_unix_seconds) <= self.scope.max_age,
            "native enrollment session expired or a clock moved backwards")?;
        self.last_wall_ns = wall;
        self.last_boot_ns = boot;
        self.failed = false;
        Ok(now)
    }
}

pub(super) fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8],
    client: &ClientConnection) -> Result<Value, String> {
    let expected = Expectations::parse(expectations_raw)?;
    // Unlike the startup-only CLI, this entrypoint interprets the independently
    // pinned nonce field as the raw client challenge, not a derived quote nonce.
    verify_checked(raw, SessionExpectations::PinnedNonce {
        expected: &expected, original: expectations_raw,
    }, trust_roots_raw, client, None)
}

pub(super) fn verify_with_challenge(raw: &[u8], scope_raw: &[u8], trust_roots_raw: &[u8],
    challenge: [u8; 32], client: &ClientConnection) -> Result<Value, String> {
    let scope = SessionScope::parse(scope_raw)?;
    ensure(challenge != [0; 32], "native ingress client challenge must be nonzero")?;
    verify_checked(raw, SessionExpectations::ClientChallenge {
        scope: &scope, original: scope_raw, challenge,
    }, trust_roots_raw, client, None)
}

/// The explicit workload lane requires paired v2 originals. Its independently
/// pinned issuer and actual configured client chain are public original bytes,
/// not previously successful verifier output or an evidence-selected root.
pub(super) fn verify_client_trust_with_challenge(raw: &[u8], scope_raw: &[u8],
    trust_roots_raw: &[u8], challenge: [u8; 32], client: &ClientConnection,
    issuer_der: &[u8], client_certificate_pem: &[u8]) -> Result<Value, String> {
    let scope = SessionScope::parse(scope_raw)?;
    ensure(challenge != [0; 32], "native workload client challenge must be nonzero")?;
    verify_checked(raw, SessionExpectations::ClientChallenge {
        scope: &scope, original: scope_raw, challenge,
    }, trust_roots_raw, client, Some((issuer_der, client_certificate_pem)))
}

/// Re-authenticate originals on the actual retained TLS connection. No prior
/// ingress summary or assignment material is accepted. The caller retains its
/// original operation deadline and the actual client certificate/key owner.
pub(super) fn verify_enrollment_with_challenge(raw: &[u8], scope_raw: &[u8],
    trust_roots_raw: &[u8], challenge: [u8; 32], client: &ClientConnection,
    issuer_der: &[u8], client_certificate_pem: &[u8], deadline: u64)
    -> Result<VerifiedEnrollmentSession, String> {
    verify_enrollment_originals(raw, scope_raw, trust_roots_raw, challenge, client,
        issuer_der, client_certificate_pem, None, deadline)
}

/// Same genuine role3/TLS admission, with an additional target issuer original
/// checked against the authenticated inventory. The client chain remains the
/// bootstrap caller's; no target leaf or copied verification result is input.
pub(super) fn verify_bootstrap_enrollment_with_challenge(raw: &[u8], scope_raw: &[u8],
    trust_roots_raw: &[u8], challenge: [u8; 32], client: &ClientConnection,
    caller_issuer_der: &[u8], caller_certificate_pem: &[u8], target_issuer_der: &[u8], deadline: u64)
    -> Result<VerifiedEnrollmentSession, String> {
    verify_enrollment_originals(raw, scope_raw, trust_roots_raw, challenge, client,
        caller_issuer_der, caller_certificate_pem, Some(target_issuer_der), deadline)
}

fn verify_enrollment_originals(raw: &[u8], scope_raw: &[u8], trust_roots_raw: &[u8],
    challenge: [u8; 32], client: &ClientConnection, issuer_der: &[u8],
    client_certificate_pem: &[u8], target_issuer_der: Option<&[u8]>, deadline: u64)
    -> Result<VerifiedEnrollmentSession, String> {
    let owner_pid = unsafe { libc::getpid() };
    let (wall, boot) = clocks()?;
    ensure(owner_pid > 0 && boot < deadline && challenge != [0; 32],
        "native enrollment session original deadline/challenge is invalid")?;
    let scope = SessionScope::parse(scope_raw)?;
    let roots = TrustRoots::parse(trust_roots_raw)?;
    let checked = verify_session_original(raw, &scope, &roots, challenge, client,
        Some((issuer_der, client_certificate_pem)))?;
    if let Some(issuer) = target_issuer_der { checked.ingress.require_client_issuer_original(issuer)?; }
    let workload = checked.workload.ok_or("native enrollment requires original client trust")?;
    let checked_wall = workload.verified_at.checked_mul(1_000_000_000)
        .ok_or("native enrollment session verification time overflow")?;
    let quote_valid_until = checked.ingress.issued.checked_add(scope.max_age)
        .and_then(|value| value.checked_add(1))
        .ok_or("native enrollment session quote interval overflow")?;
    let mut result = VerifiedEnrollmentSession {
        ca_certificate_sha256: digest(&checked.ingress.ca),
        ca_spki_sha256: checked.ingress.ca_spki_sha,
        leaf_certificate_sha256: digest(&checked.ingress.leaf),
        issuer_certificate_sha256: workload.issuer_certificate_sha256,
        issuer_spki_sha256: workload.issuer_spki_sha256,
        client_certificate_sha256: workload.client_certificate_sha256,
        client_spki_sha256: workload.client_spki_sha256,
        challenge, quote_nonce: checked.ingress.nonce,
        quote_issued_unix_seconds: checked.ingress.issued,
        valid_until_unix_seconds: checked.ingress.valid_until.min(workload.valid_until)
            .min(checked.ingress.quote_valid_until).min(quote_valid_until),
        valid_from_unix_seconds: checked.ingress.verified_at.max(workload.valid_from),
        scope, roots, deadline, owner_pid, last_wall_ns: wall.max(checked_wall),
        last_boot_ns: boot, failed: false,
    };
    result.check(deadline)?;
    Ok(result)
}

fn verify_session_original(raw: &[u8], expected: &SessionScope, roots: &TrustRoots,
    challenge: [u8; 32], client: &ClientConnection, workload: Option<(&[u8], &[u8])>)
    -> Result<VerifiedSession, String> {
    ensure(!client.is_handshaking()
        && client.protocol_version() == Some(ProtocolVersion::TLSv1_3)
        && matches!(client.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)),
        "native ingress requires a completed full outer TLS 1.3 handshake")?;
    let peer_chain = client.peer_certificates().ok_or("native ingress TLS peer chain is absent")?;
    ensure(peer_chain.len() == 2
        && peer_chain.iter().all(|certificate| !certificate.as_ref().is_empty()
            && certificate.as_ref().len() <= MAX_CERTIFICATE),
        "native ingress TLS peer must present the bounded leaf and CA pair")?;
    let exporter = client.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native ingress actual TLS exporter is unavailable")?;
    let quote_nonce = derive_nonce(challenge, exporter)?;

    ensure(raw.len() > 1 && raw.len() <= MAX_INPUT && raw.last() == Some(&b'\n'),
        "native ingress session requires one bounded original JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native ingress session evidence contains extra framing")?;
    let evidence = json::parse(body, MAX_INPUT - 1)?;
    exact(&evidence, &["apiVersion", "evidenceScope", "okForAction",
        "clientChallengeBase64url", "tlsExporterBase64url", "publicIdentityBase64url"])?;
    let evidence_version = if workload.is_some() {
        "serverware.nativeIngressSessionEvidence/v2"
    } else { "serverware.nativeIngressSessionEvidence/v1" };
    ensure(text(&evidence, "apiVersion")? == evidence_version
        && text(&evidence, "evidenceScope")? == "unverified-session-public-material"
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native ingress session evidence version or scope differs")?;
    ensure(fixed_b64::<32>(text(&evidence, "clientChallengeBase64url")?)? == challenge
        && fixed_b64::<32>(text(&evidence, "tlsExporterBase64url")?)? == exporter,
        "native ingress echoes differ from the held challenge and actual TLS exporter")?;
    let public_identity = decode_b64(text(&evidence, "publicIdentityBase64url")?, MAX_PUBLIC_IDENTITY)?;
    let evidence_profile = if workload.is_some() {
        EvidenceProfile::SessionClientTrust
    } else { EvidenceProfile::Session };
    let checked = ingress::verify_original(&public_identity, expected, roots,
        evidence_profile, &quote_nonce)?;
    ensure(peer_chain[0].as_ref() == checked.leaf.as_slice()
        && peer_chain[1].as_ref() == checked.ca.as_slice(),
        "native ingress quoted certificates differ from the actual TLS peer originals")?;
    let workload_verification = match workload {
        Some((issuer, chain)) => Some(checked.verify_client_issuer(issuer, chain, expected)?),
        None => None,
    };

    Ok(VerifiedSession { public_identity, ingress: checked, workload: workload_verification,
        exporter, peer_leaf_sha256: digest(peer_chain[0].as_ref()) })
}

fn verify_checked(raw: &[u8], profile: SessionExpectations<'_>, trust_roots_raw: &[u8],
    client: &ClientConnection, workload: Option<(&[u8], &[u8])>) -> Result<Value, String> {
    let roots = TrustRoots::parse(trust_roots_raw)?;
    let (expected, challenge) = match &profile {
        SessionExpectations::PinnedNonce { expected, .. } => (&expected.scope, expected.nonce),
        SessionExpectations::ClientChallenge { scope, challenge, .. } => (*scope, *challenge),
    };
    let VerifiedSession { public_identity, ingress: checked, workload: workload_verification,
        exporter, peer_leaf_sha256 } = verify_session_original(raw, expected, &roots, challenge,
            client, workload)?;

    let (version, quote_verification) = match profile {
        SessionExpectations::PinnedNonce { expected, original } => (
            "serverware.nativeIngressSessionVerification/v1",
            checked.summary(&public_identity, original, trust_roots_raw, expected),
        ),
        SessionExpectations::ClientChallenge { scope, original, .. } => (
            "serverware.nativeIngressSessionVerification/v2",
            checked.summary_for_session_scope(&public_identity, original, trust_roots_raw, scope),
        ),
    };
    let mut result = json!({
        "apiVersion":version,
        "resultScope":"local-ingress-session-and-quote-only", "okForAction":false,
        "evidenceSha256":digest_text(&digest(raw)),
        "clientChallengeBase64url":b64(&challenge),
        "tlsExporterSha256":digest_text(&digest(&exporter)),
        "peerCertificateSha256":digest_text(&peer_leaf_sha256),
        "quoteVerification":quote_verification,
    });
    if let Some(verified) = workload_verification {
        let verified = verified.summary();
        result["apiVersion"] = json!("serverware.nativeIngressSessionVerification/v3");
        for field in ["clientIssuerCertificateSha256", "clientIssuerSpkiSha256",
            "clientLeafCertificateSha256"] {
            result[field] = verified[field].clone();
        }
    }
    Ok(result)
}
