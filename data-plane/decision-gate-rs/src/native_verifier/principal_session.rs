//! Retained original principal-preflight admission on the actual outer TLS.
//!
//! This verifies a current principal-authentication statement, not permission
//! for CONNECT, upstream traffic, a canary, installation or another session.
//! Only the reviewed transport owner can establish actual selected-chain and
//! ClientConfig provenance. No public diagnostic or serialized owner enters.

use super::{canonical_json_bytes, config::TrustRoots, decode_b64, digest, ensure,
    exact, fixed_b64, ingress::{self, EvidenceProfile}, ingress_config::SessionScope,
    ingress_session::clocks, json, parse_digest, text};
use rustls::{ClientConnection, HandshakeKind, ProtocolVersion};
use serde_json::Value;
use serverware_decision_gate::native_ingress_challenge_v1::EXPORTER_LABEL;
use serverware_decision_gate::native_principal_preflight_v1::{self as wire,
    MAX_REQUEST_BYTES, MAX_STATEMENT_BYTES, REQUEST_EXPORTER_LABEL};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_EVIDENCE: usize = 96 * 1024;
const MAX_PUBLIC_IDENTITY: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;
const MAX_CLIENT_PEM: usize = 64 * 1024;
const SECOND: u64 = 1_000_000_000;

struct Processing {
    opened: Instant,
    opened_wall: u64,
    opened_boot: u64,
    deadline: Instant,
    boot_deadline: u64,
    last_wall: u64,
    last_boot: u64,
    pid: libc::pid_t,
    failed: bool,
}

impl Processing {
    fn inherit(deadline: Instant) -> Result<Self, String> {
        let opened = Instant::now();
        let pid = unsafe { libc::getpid() };
        let (wall, boot) = clocks()?;
        let remaining = deadline.checked_duration_since(Instant::now())
            .ok_or("native principal inherited deadline ended")?;
        let remaining = u64::try_from(remaining.as_nanos())
            .map_err(|_| "native principal inherited deadline exceeds its clock bound")?;
        let boot_deadline = boot.checked_add(remaining)
            .ok_or("native principal inherited boottime overflow")?;
        ensure(pid > 0 && remaining > 0, "native principal process or deadline is invalid")?;
        let mut result = Self { opened, opened_wall: wall, opened_boot: boot,
            deadline, boot_deadline, last_wall: wall, last_boot: boot, pid, failed: false };
        result.check()?;
        Ok(result)
    }

    fn check(&mut self) -> Result<u64, String> {
        ensure(!std::mem::replace(&mut self.failed, true), "native principal clock owner is stopped")?;
        let (wall, boot) = clocks()?;
        ensure(unsafe { libc::getpid() } == self.pid && Instant::now() < self.deadline
            && wall >= self.last_wall && boot >= self.last_boot && boot < self.boot_deadline,
            "native principal inherited lifetime ended or a clock/process changed")?;
        self.last_wall = wall;
        self.last_boot = boot;
        self.failed = false;
        Ok(wall / SECOND)
    }

    fn restrict_until(&mut self, until: u64) -> Result<(), String> {
        self.check()?;
        let until = until.checked_mul(SECOND).ok_or("native principal certificate time overflow")?;
        let remaining = until.checked_sub(self.opened_wall)
            .ok_or("native principal originals already expired")?;
        // Both ceilings derive from the ORIGINAL opening sample, never the
        // duration remaining at a later check or a newly minted allowance.
        self.deadline = self.deadline.min(self.opened.checked_add(Duration::from_nanos(remaining))
            .ok_or("native principal monotonic certificate bound overflow")?);
        self.boot_deadline = self.boot_deadline.min(self.opened_boot.checked_add(remaining)
            .ok_or("native principal boottime certificate bound overflow")?);
        self.check()?;
        Ok(())
    }
}

fn tls_originals(client: &ClientConnection, challenge: [u8; 32])
    -> Result<([u8; 32], Zeroizing<[u8; 32]>), String> {
    ensure(challenge != [0; 32] && !client.is_handshaking()
        && client.protocol_version() == Some(ProtocolVersion::TLSv1_3)
        && matches!(client.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)),
        "native principal preflight requires the completed full outer TLS 1.3 session")?;
    let peers = client.peer_certificates().ok_or("native principal peer originals are absent")?;
    ensure(peers.len() == 2 && peers.iter().all(|original|
        !original.is_empty() && original.len() <= MAX_CERTIFICATE),
        "native principal peer originals must be the exact bounded leaf and CA pair")?;
    let exporter = client.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native principal actual session exporter is unavailable")?;
    let secret = Zeroizing::new(client.export_keying_material([0u8; 32],
        REQUEST_EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native principal actual private request exporter is unavailable")?);
    ensure(exporter != [0; 32] && *secret != [0; 32],
        "native principal actual exporters must be nonzero")?;
    Ok((exporter, secret))
}

fn statement(raw: &[u8], expected_principal: &str, identity: [u8; 32],
    policy: [u8; 32], request_binding: [u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
    let value = json::parse(raw, MAX_STATEMENT_BYTES)?;
    exact(&value, &["apiVersion", "principalId", "identityPolicySha256", "policySha256",
        "clientCertificateSha256", "clientSpkiSha256", "sourceAddress", "requestBindingSha256"])?;
    ensure(canonical_json_bytes(&value).map_err(|_| "encode native principal statement")? == raw
        && text(&value, "apiVersion")? == "serverware.nativePrincipalPreflight/v1"
        && text(&value, "principalId")? == expected_principal,
        "native principal statement encoding, profile or independently expected principal differs")?;
    let pin = |field| parse_digest::<32>(text(&value, field)?, "sha256:", true);
    ensure(pin("identityPolicySha256")? == identity && pin("policySha256")? == policy
        && pin("requestBindingSha256")? == request_binding,
        "native principal statement differs from independent policy or actual sent request")?;
    match value.get("sourceAddress") {
        Some(Value::Null) => (),
        Some(Value::String(original)) => {
            ensure(!original.is_empty() && original.len() <= 45,
                "native principal source address exceeds its bound")?;
            let address = original.parse::<IpAddr>()
                .map_err(|_| "native principal source address is invalid")?;
            ensure(address.to_string() == *original,
                "native principal source address is not canonical")?;
        }
        _ => return Err("native principal source address must be canonical IP or null".into()),
    }
    Ok((pin("clientCertificateSha256")?, pin("clientSpkiSha256")?))
}

/// Same-call immutable cryptographic facts plus a sticky original clock owner.
/// No public fields, Clone/Debug/serde implementation, diagnostic constructor or
/// permission export. The actual transport retains this through CONNECT/output.
pub(crate) struct PrincipalSession {
    processing: Processing,
    scope: SessionScope,
    ingress: ingress::VerifiedIngress,
    workload: ingress::VerifiedClientIssuer,
    challenge: [u8; 32],
    exporter: [u8; 32],
    request_exporter_sha256: [u8; 32],
    selected_client_pem: Vec<u8>,
    statement_original: Vec<u8>,
    valid_until: u64,
    failed: bool,
}

impl PrincipalSession {
    pub(crate) fn check(&mut self, client: &ClientConnection, selected_client_pem: &[u8])
        -> Result<(), String> {
        ensure(!std::mem::replace(&mut self.failed, true), "native principal owner is stopped")?;
        let now = self.processing.check()?;
        ensure(now >= self.ingress.verified_at && now >= self.workload.verified_at
            && now >= self.workload.valid_from && now < self.valid_until
            && self.ingress.issued <= now.checked_add(self.scope.future_skew)
                .ok_or("native principal quote age overflow")?
            && now.saturating_sub(self.ingress.issued) <= self.scope.max_age,
            "native principal original quote or certificate validity ended")?;
        ensure(selected_client_pem == self.selected_client_pem.as_slice(),
            "native principal selected client chain changed")?;
        let (exporter, secret) = tls_originals(client, self.challenge)?;
        ensure(exporter == self.exporter && digest(secret.as_ref()) == self.request_exporter_sha256
            && wire::derive_nonce(self.challenge, exporter, &self.statement_original)? == self.ingress.nonce,
            "native principal actual TLS exporters or quoted statement changed")?;
        let peers = client.peer_certificates().ok_or("native principal peer originals are absent")?;
        ensure(peers[0].as_ref() == self.ingress.leaf.as_slice()
            && peers[1].as_ref() == self.ingress.ca.as_slice(),
            "native principal actual TLS peer changed")?;
        self.processing.check()?;
        self.failed = false;
        Ok(())
    }
}

pub(super) fn verify(raw: &[u8], scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32],
    client: &ClientConnection, issuer_der: &[u8], selected_client_pem: &[u8],
    expected_principal: &str, expected_identity_policy_sha256: &str,
    request_original: &[u8], deadline: Instant) -> Result<PrincipalSession, String> {
    let mut processing = Processing::inherit(deadline)?;
    ensure(!raw.is_empty() && raw.len() <= MAX_EVIDENCE && raw.last() == Some(&b'\n')
        && !raw[..raw.len() - 1].contains(&b'\n') && !raw.contains(&b'\r')
        && !scope_raw.is_empty() && scope_raw.len() <= 16 * 1024
        && !roots_raw.is_empty() && roots_raw.len() <= 1024 * 1024
        && !issuer_der.is_empty() && issuer_der.len() <= MAX_CERTIFICATE
        && !selected_client_pem.is_empty() && selected_client_pem.len() <= MAX_CLIENT_PEM
        && !request_original.is_empty() && request_original.len() <= MAX_REQUEST_BYTES
        && !expected_principal.is_empty() && expected_principal.len() <= 1024,
        "native principal original input exceeds its fixed profile")?;
    let identity = parse_digest::<32>(expected_identity_policy_sha256, "sha256:", true)?;
    let scope = SessionScope::parse(scope_raw)?;
    let roots = TrustRoots::parse(roots_raw)?;
    processing.check()?;
    let (exporter, secret) = tls_originals(client, challenge)?;
    let request_binding = wire::request_binding(*secret, request_original)?;
    let request_exporter_sha256 = digest(secret.as_ref());
    drop(secret);
    let value = json::parse(&raw[..raw.len() - 1], MAX_EVIDENCE - 1)?;
    exact(&value, &["apiVersion", "evidenceScope", "okForAction", "clientChallengeBase64url",
        "tlsExporterBase64url", "publicIdentityBase64url", "principalPreflightBase64url"])?;
    ensure(text(&value, "apiVersion")? == "serverware.nativeIngressSessionEvidence/v3"
        && text(&value, "evidenceScope")? == "unverified-session-public-material"
        && value.get("okForAction").and_then(Value::as_bool) == Some(false)
        && fixed_b64::<32>(text(&value, "clientChallengeBase64url")?)? == challenge
        && fixed_b64::<32>(text(&value, "tlsExporterBase64url")?)? == exporter,
        "native principal evidence profile, challenge or actual exporter differs")?;
    let statement_original = decode_b64(text(&value, "principalPreflightBase64url")?, MAX_STATEMENT_BYTES)?;
    let (leaf, spki) = statement(&statement_original, expected_principal, identity, scope.policy, request_binding)?;
    let quote_nonce = wire::derive_nonce(challenge, exporter, &statement_original)?;
    let public_identity = decode_b64(text(&value, "publicIdentityBase64url")?, MAX_PUBLIC_IDENTITY)?;
    processing.check()?;
    let ingress = ingress::verify_original(&public_identity, &scope, &roots,
        EvidenceProfile::SessionClientTrust, &quote_nonce)?;
    processing.check()?;
    let workload = ingress.verify_client_issuer(issuer_der, selected_client_pem, &scope)?;
    ensure(workload.client_certificate_sha256 == leaf && workload.client_spki_sha256 == spki,
        "native principal statement differs from the actual selected client leaf and key")?;
    let quote_until = ingress.issued.checked_add(scope.max_age).and_then(|value| value.checked_add(1))
        .ok_or("native principal quote interval overflow")?;
    let valid_until = ingress.valid_until.min(ingress.quote_valid_until)
        .min(workload.valid_until).min(quote_until);
    processing.restrict_until(valid_until)?;
    let mut result = PrincipalSession { processing, scope, ingress, workload, challenge, exporter,
        request_exporter_sha256, selected_client_pem: selected_client_pem.to_vec(),
        statement_original, valid_until, failed: false };
    result.check(client, selected_client_pem)?;
    Ok(result)
}
