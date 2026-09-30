//! Explicit retained-service trust introduction, never a renewed startup quote.
//!
//! Startup must be fresh when this nonserializable owner is created. Thereafter
//! its unchanged originals introduce only the fixed TLS identity: every new
//! connection still needs a new genuine principal/session quote. V1-v3's
//! single-connection startup freshness checks are not changed by this module.

use super::{config::TrustRoots, ensure, ingress::{self, EvidenceProfile},
    ingress_certificates, ingress_config::{Expectations, SessionScope},
    ingress_session::clocks, parse_digest, principal_session, PrincipalSession};
use rustls::ClientConnection;
use std::time::{Duration, Instant};

const SECOND: u64 = 1_000_000_000;
const MAX_CONNECTION: Duration = Duration::from_secs(120);

/// These borrowed, unverified originals confer no authority. Only admit()
/// constructs the retained result, after actual startup signature verification.
pub(crate) struct IngressServiceOriginals<'a> {
    pub(crate) startup: &'a [u8],
    pub(crate) expectations: &'a [u8],
    pub(crate) scope: &'a [u8],
    pub(crate) roots: &'a [u8],
    pub(crate) workload_issuer: &'a [u8],
    pub(crate) target_certificate: &'a [u8],
    pub(crate) principal: &'a str,
    pub(crate) identity_policy_sha256: &'a str,
}

/// No Clone/Deserialize or diagnostic-to-owner conversion. The caller keeps
/// this behind its actual original-file custody lock, not a caller callback.
pub(crate) struct IngressServiceSource {
    leaf: Vec<u8>,
    ca: Vec<u8>,
    host: String,
    scope: Vec<u8>,
    roots: Vec<u8>,
    issuer: Vec<u8>,
    target_certificate: Vec<u8>,
    principal: String,
    identity_policy_sha256: String,
    startup_nonce: [u8; 32],
    instance: String,
    pid: u32,
    deadline: Instant,
    boot_deadline: u64,
    expires: u64,
    last_wall: u64,
    last_boot: u64,
    failed: bool,
}

fn certificate_interval(original: &[u8], wall: u64, expires: u64) -> Result<(), String> {
    ensure(!original.is_empty() && original.len() <= 16 * 1024,
        "native service certificate exceeds its original bound")?;
    let (rest, certificate) = x509_parser::parse_x509_certificate(original)
        .map_err(|_| "native service certificate is malformed")?;
    let before = i128::from(certificate.validity().not_before.timestamp()) * i128::from(SECOND);
    let after = i128::from(certificate.validity().not_after.timestamp()) * i128::from(SECOND);
    ensure(rest.is_empty() && before <= i128::from(wall) && i128::from(wall) < after
        && i128::from(expires) <= after,
        "native service exceeds an original certificate interval")
}

impl IngressServiceSource {
    pub(crate) fn admit(originals: IngressServiceOriginals<'_>, deadline: Instant,
        boot_deadline: u64, expires: u64) -> Result<Self, String> {
        let opened = Instant::now();
        let (wall, boot) = clocks()?;
        ensure(opened < deadline && boot < boot_deadline && wall < expires
            && expires <= i64::MAX as u64 && expires - wall <= 86_400 * SECOND,
            "native service original interval is unavailable")?;
        ensure(!originals.principal.is_empty() && originals.principal.len() <= 1024
            && originals.principal.trim() == originals.principal
            && !originals.principal.chars().any(char::is_control),
            "native service expected principal differs")?;
        parse_digest::<32>(originals.identity_policy_sha256, "sha256:", true)?;
        let startup = Expectations::parse(originals.expectations)?;
        let scope = SessionScope::parse(originals.scope)?;
        ensure(startup.scope == scope, "native service startup and session scope differ")?;
        let roots = TrustRoots::parse(originals.roots)?;
        // This remains the original fresh-startup verification, including its
        // unchanged maxAgeSeconds<=300 and original independently pinned nonce.
        let verified = ingress::verify_original(originals.startup, &scope, &roots,
            EvidenceProfile::Startup, &startup.nonce)?;
        let original_until = verified.valid_until.min(verified.quote_valid_until)
            .checked_mul(SECOND).ok_or("native service certificate interval overflows")?;
        ensure(expires <= original_until, "native service exceeds its original TLS or Nitro PKI expiry")?;
        // A successful startup is a one-time introduction, not an infinitely
        // fresh quote. Preserve both original certificate ceilings, but require
        // a NEW current role-3 quote before any new tunnel can be returned.
        certificate_interval(originals.workload_issuer, wall, expires)?;
        let target = ingress::client_chain(originals.target_certificate)?;
        ensure(!target.is_empty(), "native service target certificate is absent")?;
        for certificate in &target { certificate_interval(certificate, wall, expires)?; }
        // Signature/path/clientAuth and quoted issuer membership are checked
        // against the ACTUAL selected chain by the fresh principal verifier,
        // not inferred here from caller-provided certificate metadata.
        let remaining = expires - wall;
        let mut owner = Self { leaf: verified.leaf, ca: verified.ca, host: scope.host,
            instance: scope.instance, scope: originals.scope.to_vec(), roots: originals.roots.to_vec(),
            issuer: originals.workload_issuer.to_vec(), target_certificate: originals.target_certificate.to_vec(),
            principal: originals.principal.to_owned(), identity_policy_sha256: originals.identity_policy_sha256.to_owned(),
            startup_nonce: startup.nonce, pid: std::process::id(),
            deadline: deadline.min(opened.checked_add(Duration::from_nanos(remaining))
                .ok_or("native service certificate deadline overflows")?),
            boot_deadline: boot_deadline.min(boot.checked_add(remaining)
                .ok_or("native service certificate boottime overflows")?),
            expires, last_wall: wall, last_boot: boot, failed: false };
        owner.check()?;
        Ok(owner)
    }

    pub(crate) fn host(&self) -> &str { &self.host }
    pub(crate) fn ca(&self) -> &[u8] { &self.ca }

    pub(crate) fn check(&mut self) -> Result<(), String> {
        ensure(!std::mem::replace(&mut self.failed, true), "native service source is stopped")?;
        let (wall, boot) = clocks()?;
        ensure(std::process::id() == self.pid && Instant::now() < self.deadline
            && boot < self.boot_deadline && wall < self.expires
            && wall >= self.last_wall && boot >= self.last_boot,
            "native service original process or interval ended")?;
        // Recheck the actual same certificates, not the old quote's age. A
        // service source alone cannot admit TLS application bytes or CONNECT.
        ingress_certificates::verify(&self.leaf, &self.ca, &self.host, &self.instance, wall / SECOND)?;
        self.last_wall = wall;
        self.last_boot = boot;
        self.failed = false;
        Ok(())
    }

    pub(crate) fn require_connection_bounds(&mut self, deadline: Instant, boot_deadline: u64)
        -> Result<(), String> {
        self.check()?;
        let remaining = deadline.checked_duration_since(Instant::now())
            .ok_or("native service connection deadline ended")?;
        let (_, boot) = clocks()?;
        ensure(!remaining.is_zero() && remaining <= MAX_CONNECTION && deadline <= self.deadline
            && boot < boot_deadline && boot_deadline <= self.boot_deadline
            && boot_deadline - boot <= 120 * SECOND,
            "native service connection exceeds its original source interval")
    }

    pub(crate) fn restrict_connection_bounds(&mut self, deadline: Instant, boot_deadline: u64)
        -> Result<(Instant, u64), String> {
        let deadline = deadline.min(self.deadline);
        let boot_deadline = boot_deadline.min(self.boot_deadline);
        self.require_connection_bounds(deadline, boot_deadline)?;
        Ok((deadline, boot_deadline))
    }

    pub(crate) fn require_peer(&mut self, client: &ClientConnection, selected_client: &[u8],
        challenge: &[u8; 32]) -> Result<(), String> {
        self.check()?;
        ensure(*challenge != [0; 32] && *challenge != self.startup_nonce,
            "native service session challenge is zero or reuses startup")?;
        let peer = client.peer_certificates().ok_or("native service actual TLS peer is absent")?;
        ensure(peer.len() == 2 && peer[0].as_ref() == self.leaf.as_slice()
            && peer[1].as_ref() == self.ca.as_slice() && selected_client == self.target_certificate.as_slice(),
            "native service actual server or selected target identity changed")
    }

    pub(crate) fn verify_session(&mut self, evidence: &[u8], challenge: [u8; 32],
        client: &ClientConnection, selected_client: &[u8], request: &[u8],
        deadline: Instant, boot_deadline: u64) -> Result<PrincipalSession, String> {
        self.require_connection_bounds(deadline, boot_deadline)?;
        self.require_peer(client, selected_client, &challenge)?;
        let proof = principal_session::verify(evidence, &self.scope, &self.roots, challenge,
            client, &self.issuer, selected_client, &self.principal, &self.identity_policy_sha256,
            request, deadline)?;
        self.check()?;
        Ok(proof)
    }
}
