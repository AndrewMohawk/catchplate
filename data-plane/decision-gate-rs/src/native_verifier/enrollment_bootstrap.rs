//! Original-only caller-to-target bootstrap signature/session verification.
//!
//! The existing TLS client is the bootstrap caller, never the prospective
//! target. Independent setup/delegation roots and target request pins are
//! required. This returns diagnostics, not an installation, issuance, policy
//! decision, durable-claim receipt, or permission to expose the signer.

use super::{bootstrap_packet, bootstrap_setup, decode_b64, digest, digest_text,
    ensure, exact, fixed_b64, ingress_session, json, native_workload_bootstrap_request_v1 as request,
    nitro, parse_digest, text};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::ClientConnection;
use serde_json::{json as value, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_BYTES: usize = 96 * 1024;
const MAX_QUOTE_BYTES: usize = 12 * 1024;
const MAX_INPUT_BYTES: usize = 3 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 4096;
const PROCESSING_NS: u64 = 30_000_000_000;
const SECOND: u64 = 1_000_000_000;
const RUNTIME_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const REQUEST_DOMAIN: &[u8] = b"serverware/native-enrollment-bootstrap-key-binding/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"serverware/native-enrollment-bootstrap-packet-signature/v1\0";

/// Source-owned clock continuation, not an evidence verdict. The fixed client
/// creates it before network IO and retains it through authenticated EOF.
pub(crate) struct Processing {
    pid: u32,
    deadline: u64,
    last_wall: u64,
    last_boot: u64,
    valid_until: u64,
    stopped: bool,
}

fn clocks() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native bootstrap wall clock is invalid")?.as_nanos();
    let wall = u64::try_from(wall).map_err(|_| "native bootstrap wall clock overflow")?;
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } == 0
        && observed.tv_sec >= 0 && (0..1_000_000_000).contains(&observed.tv_nsec),
        "native bootstrap boottime clock is invalid")?;
    let boot = (observed.tv_sec as u64).checked_mul(SECOND)
        .and_then(|value| value.checked_add(observed.tv_nsec as u64))
        .ok_or("native bootstrap boottime clock overflow")?;
    ensure(wall > 0 && boot > 0, "native bootstrap clocks must be positive")?;
    Ok((wall, boot))
}

impl Processing {
    pub(crate) fn open(deadline: u64) -> Result<Self, String> {
        let (wall, boot) = clocks()?;
        let deadline = deadline.min(boot.checked_add(PROCESSING_NS)
            .ok_or("native bootstrap original processing interval overflow")?);
        ensure(boot < deadline, "native bootstrap original deadline expired")?;
        Ok(Self { pid: std::process::id(), deadline, last_wall: wall, last_boot: boot,
            valid_until: u64::MAX, stopped: false })
    }

    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), String> {
        ensure(!std::mem::replace(&mut self.stopped, true), "native bootstrap processing is stopped")?;
        self.deadline = self.deadline.min(deadline);
        let (wall, boot) = clocks()?;
        ensure(self.pid == std::process::id() && wall >= self.last_wall && boot >= self.last_boot
            && boot < self.deadline && wall < self.valid_until,
            "native bootstrap processing expired or changed process/clock")?;
        if self.valid_until != u64::MAX {
            self.deadline = self.deadline.min(boot.checked_add(self.valid_until - wall)
                .ok_or("native bootstrap remaining original interval overflow")?);
        }
        self.last_wall = wall;
        self.last_boot = boot;
        self.stopped = false;
        Ok(())
    }

    fn restrict_until(&mut self, seconds: u64) -> Result<(), String> {
        self.valid_until = self.valid_until.min(seconds.checked_mul(SECOND)
            .ok_or("native bootstrap certificate expiry overflow")?);
        self.check(self.deadline)
    }

    pub(crate) fn valid_until_epoch_ns(&self) -> Option<u64> {
        (self.valid_until != u64::MAX).then_some(self.valid_until)
    }
}

struct Evidence {
    packet: Vec<u8>,
    session: Vec<u8>,
    quote: Vec<u8>,
    signature: [u8; 64],
    public_key: [u8; 32],
}

/// Same-call original owners for the fixed installation continuation. Neither
/// deserialization nor a caller-supplied successful diagnostic constructs this.
/// The separate host authorization, protected reservation and observed host
/// owner remain mandatory; these originals alone are not installation permission.
pub(crate) struct InstallationOriginals {
    diagnostic: Vec<u8>,
    setup: bootstrap_setup::VerifiedNativeEnrollmentBootstrapSetupV1,
    target: request::VerifiedWorkloadBootstrapRequestV1,
    session: ingress_session::VerifiedEnrollmentSession,
    evidence_sha256: [u8; 32],
    packet_sha256: [u8; 32],
    valid_until: u64,
}

impl InstallationOriginals {
    pub(crate) fn into_diagnostic(self) -> Vec<u8> { self.diagnostic }
    pub(crate) fn diagnostic(&self) -> &[u8] { &self.diagnostic }
    pub(crate) fn setup(&self) -> &bootstrap_setup::SetupPayload { self.setup.payload() }
    pub(crate) fn setup_sha256(&self) -> [u8; 32] { self.setup.original_sha256() }
    pub(crate) fn delegation_sha256(&self) -> [u8; 32] { self.setup.delegation().original_sha256() }
    pub(crate) fn delegation_authorizer(&self) -> [u8; 32] {
        self.setup.delegation().payload().authorizer_key_id
    }
    pub(crate) fn delegation(&self) -> &super::bootstrap_delegation::DelegationPayload {
        self.setup.delegation().payload()
    }
    /// Rebind this retained proof to the actual still-owned TLS session. Public
    /// capture fields or an equivalent-looking independent connection cannot
    /// supply the original exporter-derived quote nonce.
    pub(crate) fn check_connection(&mut self, client: &ClientConnection,
        endpoint: SocketAddr, challenge: [u8; 32], deadline: u64) -> Result<(), String> {
        self.check(deadline)?;
        let exporter = client.export_keying_material([0u8; 32],
            serverware_decision_gate::native_ingress_challenge_v1::EXPORTER_LABEL,
            Some(&challenge)).map_err(|_| "native egress retained TLS exporter unavailable")?;
        let nonce = serverware_decision_gate::native_ingress_challenge_v1::derive_nonce(challenge, exporter)?;
        let peers = client.peer_certificates().ok_or("native egress retained peer chain absent")?;
        ensure(peers.len() == 2 && digest(peers[0].as_ref()) == self.session.leaf_certificate_sha256
            && digest(peers[1].as_ref()) == self.session.ca_certificate_sha256
            && nonce == self.session.quote_nonce && challenge == self.session.challenge
            && challenge == self.delegation().client_challenge
            && endpoint == self.delegation().proxy_endpoint,
            "native egress proof differs from its actual retained TLS session")?;
        self.check(deadline)
    }
    pub(crate) fn evidence_sha256(&self) -> [u8; 32] { self.evidence_sha256 }
    pub(crate) fn packet_sha256(&self) -> [u8; 32] { self.packet_sha256 }
    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), String> {
        self.setup.check(deadline)?;
        self.target.check(deadline)?;
        ensure(self.session.check(deadline)? < self.valid_until,
            "native installation original quote or session expired")?;
        target_scope(&self.setup, &self.target)
    }
}

fn evidence(raw: &[u8], processing: &mut Processing) -> Result<Evidence, String> {
    processing.check(processing.deadline)?;
    ensure(raw.len() > 1 && raw.len() <= MAX_EVIDENCE_BYTES && raw.last() == Some(&b'\n'),
        "native bootstrap evidence requires one bounded original JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(body.is_ascii() && !body.contains(&b'\n') && !body.contains(&b'\r'),
        "native bootstrap evidence framing differs")?;
    let value = json::parse(body, MAX_EVIDENCE_BYTES - 1)?;
    exact(&value, &["apiVersion", "evidenceScope", "okForAction", "packetBase64url",
        "ingressSessionEvidenceBase64url", "enrollmentSignatureBase64url",
        "enrollmentPublicKeyBase64url", "enrollmentQuoteBase64url"])?;
    ensure(text(&value, "apiVersion")? == "serverware.nativeEnrollmentBootstrapEvidence/v1"
        && text(&value, "evidenceScope")? == "unverified-bootstrap-enrollment-public-material"
        && value.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native bootstrap evidence version or scope differs")?;
    let ordered: BTreeMap<&str, &Value> = value.as_object().ok_or("native bootstrap evidence is not an object")?
        .iter().map(|(key, value)| (key.as_str(), value)).collect();
    ensure(serde_json::to_vec(&ordered).map_err(|_| "encode native bootstrap canonical evidence")?.as_slice() == body,
        "native bootstrap evidence is not canonical")?;
    processing.check(processing.deadline)?;
    let mut original = |field, maximum| -> Result<Vec<u8>, String> {
        processing.check(processing.deadline)?;
        let original = decode_b64(text(&value, field)?, maximum)?;
        processing.check(processing.deadline)?;
        Ok(original)
    };
    let packet = original("packetBase64url", bootstrap_packet::MAX_PACKET_BYTES)?;
    let session = original("ingressSessionEvidenceBase64url", MAX_SESSION_BYTES)?;
    let quote = original("enrollmentQuoteBase64url", MAX_QUOTE_BYTES)?;
    let signature = fixed_b64::<64>(text(&value, "enrollmentSignatureBase64url")?)?;
    let public_key = fixed_b64::<32>(text(&value, "enrollmentPublicKeyBase64url")?)?;
    ensure(public_key != [0; 32], "native bootstrap enrollment public key is zero")?;
    processing.check(processing.deadline)?;
    Ok(Evidence { packet, session, quote, signature, public_key })
}

fn caller_scope(setup: &bootstrap_setup::VerifiedNativeEnrollmentBootstrapSetupV1,
    session: &ingress_session::VerifiedEnrollmentSession, expected_caller: &str,
    expected_target: &str, expected_nonce: &str, expected_request: &[u8; 32],
    endpoint: SocketAddr, challenge: [u8; 32]) -> Result<(), String> {
    let d = setup.delegation().payload();
    let p = setup.payload();
    ensure(d.release_record_sha256 == session.scope.release_record && d.policy_hash == session.scope.policy
        && d.configuration_sha256 == session.scope.configuration
        && d.runtime_ca_certificate_sha256 == session.ca_certificate_sha256
        && d.runtime_ca_spki_sha256 == session.ca_spki_sha256
        && d.ingress_leaf_certificate_sha256 == session.leaf_certificate_sha256
        && d.client_trust_bundle_sha256 == session.scope.client_trust
        && d.caller_issuer_certificate_sha256 == session.issuer_certificate_sha256
        && d.caller_issuer_spki_sha256 == session.issuer_spki_sha256
        && d.caller_certificate_sha256 == session.client_certificate_sha256
        && d.caller_spki_sha256 == session.client_spki_sha256
        && d.caller_principal_id == expected_caller && d.target_principal_id == expected_target
        && d.target_nonce == expected_nonce && &d.target_request_sha256 == expected_request
        && d.ingress_host == session.scope.host && d.server_instance_id == session.scope.instance
        && d.client_challenge == challenge && session.challenge == challenge
        && d.proxy_endpoint == endpoint && p.proxy_endpoint == endpoint,
        "native bootstrap delegation differs from independent pins or actual caller/session")
}

fn target_scope(setup: &bootstrap_setup::VerifiedNativeEnrollmentBootstrapSetupV1,
    target: &request::VerifiedWorkloadBootstrapRequestV1) -> Result<(), String> {
    let d = setup.delegation().payload();
    let t = target.payload();
    ensure(target.original_sha256() == d.target_request_sha256
        && t.principal_id == d.target_principal_id && t.nonce == d.target_nonce
        && t.requested_dns == d.target_requested_dns && t.requested_uris == d.target_requested_uris
        && t.issuer_certificate_der_sha256 == d.target_issuer_certificate_der_sha256
        && t.issuer_spki_sha256 == d.target_issuer_spki_sha256
        && t.subject_public_key_info_sha256 == d.target_spki_sha256 && t.csr_sha256 == d.target_csr_sha256
        && t.created_at_epoch_ms == d.target_created_at_epoch_ms
        && t.expires_at_epoch_ms == d.target_expires_at_epoch_ms,
        "native bootstrap target originals differ from the genuine delegation")
}

fn role_binding(setup: &bootstrap_setup::VerifiedNativeEnrollmentBootstrapSetupV1,
    session: &ingress_session::VerifiedEnrollmentSession, packet_sha: &[u8; 32], public_key: &[u8; 32]) -> Vec<u8> {
    let mut request = Sha256::new();
    request.update(REQUEST_DOMAIN);
    request.update(setup.delegation().original_sha256());
    request.update(setup.original_sha256());
    request.update(packet_sha);
    request.update(session.leaf_certificate_sha256);
    request.update(session.scope.client_trust);
    let request: [u8; 32] = request.finalize().into();
    let mut result = Vec::with_capacity(RUNTIME_DOMAIN.len() + 1 + 7 * 32);
    result.extend_from_slice(RUNTIME_DOMAIN);
    result.push(5);
    for field in [session.scope.release_record, session.scope.policy, session.scope.configuration,
        session.ca_certificate_sha256, session.ca_spki_sha256, digest(public_key), request] {
        result.extend_from_slice(&field);
    }
    result
}

/// All inputs are originals or independently selected expectations. The outer
/// wrapper alone supplies endpoint from the same retained connected socket.
pub(super) fn verify(raw: &[u8], delegation_pem: &[u8], delegation_pem_sha: &str,
    setup_pem: &[u8], setup_pem_sha: &str, scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32],
    client: &ClientConnection, caller_issuer_der: &[u8], caller_client_pem: &[u8],
    expected_caller: &str, expected_target: &str, expected_nonce: &str, expected_request_sha: &str,
    endpoint: SocketAddr, deadline: u64) -> Result<Vec<u8>, String> {
    let mut processing = Processing::open(deadline)?;
    verify_on_processing(raw, delegation_pem, delegation_pem_sha, setup_pem, setup_pem_sha,
        scope_raw, roots_raw, challenge, client, caller_issuer_der, caller_client_pem,
        expected_caller, expected_target, expected_nonce, expected_request_sha,
        endpoint, None, &mut processing)
}

/// The fixed acquisition owner supplies the actual selected client chain and
/// observed endpoint, plus the exact originals it sent. This low-level function
/// does not establish TLS-configuration or file-pin provenance by itself.
pub(super) fn verify_on_processing(raw: &[u8], delegation_pem: &[u8], delegation_pem_sha: &str,
    setup_pem: &[u8], setup_pem_sha: &str, scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32],
    client: &ClientConnection, caller_issuer_der: &[u8], caller_client_pem: &[u8],
    expected_caller: &str, expected_target: &str, expected_nonce: &str, expected_request_sha: &str,
    endpoint: SocketAddr, sent_originals: Option<(&[u8], &[u8], &[u8])>,
    processing: &mut Processing) -> Result<Vec<u8>, String> {
    Ok(admit_on_processing(raw, delegation_pem, delegation_pem_sha, setup_pem, setup_pem_sha,
        scope_raw, roots_raw, challenge, client, caller_issuer_der, caller_client_pem,
        expected_caller, expected_target, expected_nonce, expected_request_sha, endpoint,
        sent_originals, processing)?.into_diagnostic())
}

pub(super) fn admit_on_processing(raw: &[u8], delegation_pem: &[u8], delegation_pem_sha: &str,
    setup_pem: &[u8], setup_pem_sha: &str, scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32],
    client: &ClientConnection, caller_issuer_der: &[u8], caller_client_pem: &[u8],
    expected_caller: &str, expected_target: &str, expected_nonce: &str, expected_request_sha: &str,
    endpoint: SocketAddr, sent_originals: Option<(&[u8], &[u8], &[u8])>,
    processing: &mut Processing) -> Result<InstallationOriginals, String> {
    processing.check(processing.deadline)?;
    let mut total = 0usize;
    for (size, maximum) in [(raw.len(), MAX_EVIDENCE_BYTES), (delegation_pem.len(), 16 * 1024),
        (setup_pem.len(), 16 * 1024), (scope_raw.len(), 16 * 1024), (roots_raw.len(), 1024 * 1024),
        (caller_issuer_der.len(), 16 * 1024), (caller_client_pem.len(), 64 * 1024)] {
        ensure(size > 0 && size <= maximum, "native bootstrap original input exceeds its bound")?;
        total = total.checked_add(size).ok_or("native bootstrap aggregate input overflow")?;
    }
    if let Some((delegation, setup, request)) = sent_originals {
        for (size, maximum) in [(delegation.len(), 32 * 1024), (setup.len(), 32 * 1024),
            (request.len(), 64 * 1024)] {
            ensure(size > 0 && size <= maximum, "native bootstrap sent original exceeds its bound")?;
            total = total.checked_add(size).ok_or("native bootstrap aggregate input overflow")?;
        }
    }
    ensure(total <= MAX_INPUT_BYTES && delegation_pem_sha.len() == 71 && setup_pem_sha.len() == 71
        && challenge != [0; 32] && endpoint.port() != 0
        && !expected_caller.is_empty() && expected_caller.len() <= 256
        && expected_caller.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !expected_target.is_empty() && expected_target.len() <= 1024
        && (32..=256).contains(&expected_nonce.len())
        && expected_nonce.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "native bootstrap independent inputs exceed the fixed profile")?;
    let expected_request = parse_digest::<32>(expected_request_sha, "sha256:", true)?;
    let original = evidence(raw, processing)?;
    processing.check(processing.deadline)?;
    let packet = bootstrap_packet::decode_original(&original.packet)?;
    processing.check(processing.deadline)?;
    if let Some((delegation, setup, request)) = sent_originals {
        ensure(packet.delegation_original() == delegation && packet.setup_original() == setup
            && packet.target_request_original() == request,
            "native bootstrap response substituted an originally submitted authority or request")?;
    }
    ensure(digest(packet.target_request_original()) == expected_request,
        "native bootstrap packet differs from the independently retained target request")?;
    let mut setup = bootstrap_setup::verify_original(packet.setup_original(), setup_pem, setup_pem_sha,
        packet.delegation_original(), delegation_pem, delegation_pem_sha, packet.target_request_original(),
        packet.policy_requirements_original(), processing.deadline)?;
    processing.check(setup.deadline())?;
    setup.check(processing.deadline)?;
    let mut session = ingress_session::verify_bootstrap_enrollment_with_challenge(&original.session,
        scope_raw, roots_raw, challenge, client, caller_issuer_der, caller_client_pem,
        packet.target_issuer_original(), processing.deadline)?;
    processing.check(setup.deadline())?;
    setup.check(processing.deadline)?;
    caller_scope(&setup, &session, expected_caller, expected_target, expected_nonce,
        &expected_request, endpoint, challenge)?;
    let d = setup.delegation().payload();
    let mut target = request::verify_original(packet.target_request_original(), packet.target_issuer_original(),
        expected_target, expected_nonce, &d.target_requested_dns, &d.target_requested_uris, processing.deadline)?;
    target_scope(&setup, &target)?;
    processing.check(setup.deadline().min(target.deadline()))?;
    setup.check(processing.deadline)?;
    target.check(processing.deadline)?;
    let packet_sha = digest(&original.packet);
    let user_data = role_binding(&setup, &session, &packet_sha, &original.public_key);
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + 32 + 8 + original.packet.len());
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(&setup.delegation().original_sha256());
    signed.extend_from_slice(&setup.original_sha256());
    signed.extend_from_slice(&(original.packet.len() as u64).to_be_bytes());
    signed.extend_from_slice(&original.packet);
    let key = VerifyingKey::from_bytes(&original.public_key)
        .map_err(|_| "native bootstrap enrollment public key is invalid")?;
    ensure(!key.is_weak(), "native bootstrap enrollment public key is weak")?;
    key.verify_strict(&signed, &Signature::from_bytes(&original.signature))
        .map_err(|_| "native bootstrap packet signature is invalid")?;
    processing.check(setup.deadline().min(target.deadline()))?;
    setup.check(processing.deadline)?;
    target.check(processing.deadline)?;
    let opening = session.check(processing.deadline)?;
    let quote = nitro::verify_enrollment(&original.quote, &nitro::NitroExpectationsV1 {
        module_id: &session.scope.module_id, pcrs: &session.scope.pcrs,
        max_age: session.scope.max_age, future_skew: session.scope.future_skew,
    }, &session.roots, &original.public_key, &user_data, &session.quote_nonce, opening)?;
    ensure(quote.issued_unix_seconds >= setup.payload().not_before_unix_seconds
        && quote.issued_unix_seconds < setup.payload().expires_at_unix_seconds,
        "native bootstrap quote is outside the original setup/delegation/target interval")?;
    let fresh_until = quote.issued_unix_seconds.checked_add(session.scope.max_age)
        .and_then(|value| value.checked_add(1)).ok_or("native bootstrap quote freshness overflow")?;
    processing.restrict_until(quote.valid_until_unix_seconds.min(fresh_until)
        .min(session.valid_until_unix_seconds).min(setup.payload().expires_at_unix_seconds))?;
    let result = value!({
        "apiVersion":"serverware.nativeEnrollmentBootstrapVerification/v1",
        "resultScope":"local-bootstrap-signature-and-session-only", "okForAction":false,
        "evidenceSha256":digest_text(&digest(raw)), "packetSha256":digest_text(&packet_sha),
        "delegationSha256":digest_text(&setup.delegation().original_sha256()),
        "setupAuthorizationSha256":digest_text(&setup.original_sha256()),
        "policyRequirementsSha256":digest_text(&setup.payload().policy_requirements_sha256),
        "targetRequestSha256":digest_text(&target.original_sha256()),
        "targetCsrSha256":digest_text(&target.payload().csr_sha256),
        "targetSpkiSha256":digest_text(&target.payload().subject_public_key_info_sha256),
        "targetIssuerCertificateDerSha256":digest_text(&target.payload().issuer_certificate_der_sha256),
        "targetIssuerSpkiSha256":digest_text(&target.payload().issuer_spki_sha256),
        "enrollmentPublicKeySha256":digest_text(&digest(&original.public_key)),
        "enrollmentQuoteSha256":digest_text(&digest(&original.quote)),
        "ingressSessionEvidenceSha256":digest_text(&digest(&original.session)),
        "expectedCallerPrincipal":expected_caller,
        "expectedTargetPrincipalSha256":digest_text(&digest(expected_target.as_bytes())),
        "expectedTargetNonce":expected_nonce, "actualProxyEndpoint":endpoint.to_string(),
    });
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native bootstrap diagnostic")?;
    ensure(!bytes.is_empty() && bytes.len() < MAX_RESULT_BYTES, "native bootstrap diagnostic exceeds its bound")?;
    // Serialization precedes final original-owner and selected-chain checks.
    processing.check(setup.deadline().min(target.deadline()))?;
    setup.check(processing.deadline)?;
    target.check(processing.deadline)?;
    let closing = session.check(processing.deadline)?;
    ensure(closing >= opening && closing < quote.valid_until_unix_seconds
        && quote.issued_unix_seconds <= closing.saturating_add(session.scope.future_skew)
        && closing.saturating_sub(quote.issued_unix_seconds) <= session.scope.max_age,
        "native bootstrap quote or selected signing certificate expired during verification")?;
    caller_scope(&setup, &session, expected_caller, expected_target, expected_nonce,
        &expected_request, endpoint, challenge)?;
    target_scope(&setup, &target)?;
    setup.check(processing.deadline)?;
    target.check(processing.deadline)?;
    processing.check(setup.deadline().min(target.deadline()))?;
    Ok(InstallationOriginals { diagnostic: bytes, valid_until: quote.valid_until_unix_seconds
        .min(fresh_until).min(session.valid_until_unix_seconds).min(setup.payload().expires_at_unix_seconds),
        setup, target, session, evidence_sha256: digest(raw), packet_sha256: packet_sha })
}
