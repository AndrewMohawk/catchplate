//! Original native response/ingress/enrollment verification and a TLS join.
//!
//! No network acquisition, subprocess, environment configuration, private key or copied
//! verifier result participates. Successful output proves only the fixed local
//! signature/quote profile; it is not an actionable production admission.

mod cbor;
mod certificates;
mod cli;
mod config;
mod json;
mod nitro;
mod statement;
mod ingress;
mod ingress_certificates;
mod ingress_cli;
mod ingress_config;
mod ingress_session;
mod principal_session;
mod ingress_client;
mod ingress_service;
mod enrollment;
mod enrollment_bootstrap;
// Reuse the assignment parser/signature/lifetime implementation without
// exporting its private owner as a cross-boundary authorization carrier.
#[path = "../native_enrollment_assignment_v1.rs"]
mod native_enrollment_assignment_v1;
use self::native_enrollment_assignment_v1 as assignment;
#[path = "../native_workload_bootstrap_request_v1.rs"]
mod native_workload_bootstrap_request_v1;
#[path = "../native_enrollment_bootstrap_delegation_v1.rs"]
mod bootstrap_delegation;
#[path = "../native_enrollment_bootstrap_setup_v1.rs"]
mod bootstrap_setup;
#[path = "../native_enrollment_bootstrap_packet_v2.rs"]
mod bootstrap_packet;

pub(crate) use ingress_client::IngressClientBootstrap;
pub(crate) use ingress_service::{IngressServiceOriginals, IngressServiceSource};
pub(crate) use principal_session::PrincipalSession;

use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use serverware_decision_gate::{canonical_json_bytes, decode_canonical_json};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn run() -> Result<(), String> { cli::run() }
pub(crate) fn run_ingress() -> Result<(), String> { ingress_cli::run() }

pub(crate) fn prepare_ingress_client(raw: &[u8], startup_raw: &[u8], session_raw: &[u8], roots_raw: &[u8])
    -> Result<IngressClientBootstrap, String> {
    ingress_client::prepare(raw, startup_raw, session_raw, roots_raw)
}

/// Verify still-fresh startup originals against the independently pinned static
/// session scope and a nonzero, separately caller-owned challenge. No RNG or
/// challenge-use/replay authority is supplied by the verifier.
pub(crate) fn prepare_ingress_client_with_challenge(raw: &[u8], startup_raw: &[u8],
    scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32])
    -> Result<IngressClientBootstrap, String> {
    ingress_client::prepare_with_challenge(raw, startup_raw, scope_raw, roots_raw, challenge)
}

/// Verify fresh ingress originals against the actual retained outer client TLS
/// connection. The independently held expectation nonce is the raw client
/// challenge here. No network owner, HTTP framing or TLS-policy admission is
/// supplied; see ingress_session's caller obligations.
pub(crate) fn verify_ingress_session(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8],
    client: &rustls::ClientConnection) -> Result<Vec<u8>, String> {
    let result = ingress_session::verify(raw, expectations_raw, trust_roots_raw, client)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native ingress session verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native ingress session verdict exceeds its bound")?;
    Ok(bytes)
}

/// The challenge is caller-owned, not a field in the pinned scope original.
/// Retains the same actual TLS/exporter/peer joins and caller obligations as
/// v1, returning only a bounded v2 local verdict over those exact originals.
pub(crate) fn verify_ingress_session_with_challenge(raw: &[u8], scope_raw: &[u8],
    roots_raw: &[u8], challenge: [u8; 32], client: &rustls::ClientConnection)
    -> Result<Vec<u8>, String> {
    let result = ingress_session::verify_with_challenge(raw, scope_raw, roots_raw, challenge, client)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native ingress session verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native ingress session verdict exceeds its bound")?;
    Ok(bytes)
}

/// Source-selected v2 evidence verifies the actual quoted native client-root
/// inventory and the caller's retained certificate chain under its independent
/// issuer. The caller must use that exact chain on this held TLS connection;
/// copied summaries, standard PEM-bundle diagnostics and legacy evidence cannot
/// select this lane. Returns only a bounded local v3 verdict, not permission.
pub(crate) fn verify_ingress_session_client_trust_with_challenge(raw: &[u8], scope_raw: &[u8],
    roots_raw: &[u8], challenge: [u8; 32], client: &rustls::ClientConnection,
    issuer_der: &[u8], client_certificate_pem: &[u8]) -> Result<Vec<u8>, String> {
    let result = ingress_session::verify_client_trust_with_challenge(raw, scope_raw,
        roots_raw, challenge, client, issuer_der, client_certificate_pem)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native workload ingress verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native workload ingress verdict exceeds its bound")?;
    Ok(bytes)
}

/// Original-only principal-v3 admission for the reviewed transport owner. The
/// caller must supply its actual selected client chain and retain the same
/// ClientConfig/connection; a bare ClientConnection cannot prove that history.
/// No serialized verdict, installation receipt or caller-set source address is
/// accepted. The private result retains the inherited deadline through use.
pub(crate) fn verify_ingress_principal_preflight(raw: &[u8], scope_raw: &[u8],
    roots_raw: &[u8], challenge: [u8; 32], client: &rustls::ClientConnection,
    issuer_der: &[u8], selected_client_pem: &[u8], expected_principal: &str,
    expected_identity_policy_sha256: &str, request_original: &[u8],
    deadline: std::time::Instant) -> Result<PrincipalSession, String> {
    principal_session::verify(raw, scope_raw, roots_raw, challenge, client,
        issuer_der, selected_client_pem, expected_principal,
        expected_identity_policy_sha256, request_original, deadline)
}

/// Authenticate original enrollment signatures/quotes against the retained
/// outer TLS connection and that owned stream's actual connected endpoint.
/// The fixed acquisition owner must have used the supplied retained client
/// chain and a reviewed TLS verifier on this stream. This function cannot infer
/// that configuration history, independent pin provenance, semantic packet
/// authorization or one-use claims from public evidence. It returns a local
/// diagnostic only, never an installation decision or usable signing API.
pub(crate) fn verify_native_enrollment_on_stream(raw: &[u8], authorizer_pem: &[u8],
    expected_authorizer_pem_sha256: &str, scope_raw: &[u8], roots_raw: &[u8],
    challenge: [u8; 32], outer: &rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    issuer_der: &[u8], client_certificate_pem: &[u8], expected_principal: &str,
    original_deadline: u64) -> Result<Vec<u8>, String> {
    let endpoint = outer.sock.peer_addr()
        .map_err(|_| "native enrollment actual connected endpoint is unavailable")?;
    enrollment::verify(raw, authorizer_pem, expected_authorizer_pem_sha256,
        scope_raw, roots_raw, challenge, &outer.conn, issuer_der,
        client_certificate_pem, expected_principal, endpoint, original_deadline)
}

/// Explicit caller-to-target bootstrap profile. All public roots, request pins,
/// and the selected caller certificate chain come from the fixed acquisition
/// owner, not Python diagnostics or this evidence. That owner retains its
/// reviewed TLS configuration/key through the complete operation. A target
/// certificate is neither required nor implied by successful verification.
pub(crate) fn verify_native_bootstrap_enrollment_on_stream(raw: &[u8],
    delegation_pem: &[u8], delegation_pem_sha: &str, setup_pem: &[u8], setup_pem_sha: &str,
    scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32],
    outer: &rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    caller_issuer_der: &[u8], caller_client_pem: &[u8], expected_caller_principal: &str,
    expected_target_principal: &str, expected_target_nonce: &str,
    expected_target_request_sha256: &str, original_deadline: u64) -> Result<Vec<u8>, String> {
    let endpoint = outer.sock.peer_addr()
        .map_err(|_| "native bootstrap actual connected endpoint is unavailable")?;
    enrollment_bootstrap::verify(raw, delegation_pem, delegation_pem_sha, setup_pem, setup_pem_sha,
        scope_raw, roots_raw, challenge, &outer.conn, caller_issuer_der, caller_client_pem,
        expected_caller_principal, expected_target_principal, expected_target_nonce,
        expected_target_request_sha256, endpoint, original_deadline)
}

pub(crate) use enrollment_bootstrap::Processing as BootstrapProcessing;
pub(crate) use enrollment_bootstrap::InstallationOriginals as BootstrapInstallationOriginals;

pub(crate) fn installation_authorizer(original: &[u8], expected: &str)
    -> Result<(ed25519_dalek::VerifyingKey, [u8; 32]), String> {
    let (key, key_id) = assignment::authorizer(original, expected)?;
    ensure(!key.is_weak(), "native installation root is weak")?;
    Ok((key, key_id))
}

/// Fixed-client-only continuation retaining the genuine children. A serialized
/// diagnostic cannot enter this API; the original TLS/configuration owner must
/// still remain alive while a separate host authorization permits installation.
pub(crate) fn admit_native_bootstrap_installation_originals(raw: &[u8],
    delegation_pem: &[u8], delegation_pem_sha: &str, setup_pem: &[u8], setup_pem_sha: &str,
    scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32], client: &rustls::ClientConnection,
    caller_issuer_der: &[u8], caller_client_pem: &[u8], expected_caller: &str,
    expected_target: &str, expected_nonce: &str, expected_request_sha: &str,
    endpoint: std::net::SocketAddr, sent_delegation: &[u8], sent_setup: &[u8], sent_request: &[u8],
    processing: &mut BootstrapProcessing) -> Result<BootstrapInstallationOriginals, String> {
    enrollment_bootstrap::admit_on_processing(raw, delegation_pem, delegation_pem_sha,
        setup_pem, setup_pem_sha, scope_raw, roots_raw, challenge, client,
        caller_issuer_der, caller_client_pem, expected_caller, expected_target, expected_nonce,
        expected_request_sha, endpoint, Some((sent_delegation, sent_setup, sent_request)), processing)
}

/// Private fixed-client continuation over original inputs. The owning transport
/// establishes reviewed ClientConfig and selected-certificate provenance; these
/// scalar/connection parameters alone are not a configuration-admission API.
pub(crate) fn verify_native_bootstrap_enrollment_originals(raw: &[u8],
    delegation_pem: &[u8], delegation_pem_sha: &str, setup_pem: &[u8], setup_pem_sha: &str,
    scope_raw: &[u8], roots_raw: &[u8], challenge: [u8; 32], client: &rustls::ClientConnection,
    caller_issuer_der: &[u8], caller_client_pem: &[u8], expected_caller: &str,
    expected_target: &str, expected_nonce: &str, expected_request_sha: &str,
    endpoint: std::net::SocketAddr, sent_delegation: &[u8], sent_setup: &[u8], sent_request: &[u8],
    processing: &mut BootstrapProcessing) -> Result<Vec<u8>, String> {
    enrollment_bootstrap::verify_on_processing(raw, delegation_pem, delegation_pem_sha,
        setup_pem, setup_pem_sha, scope_raw, roots_raw, challenge, client,
        caller_issuer_der, caller_client_pem, expected_caller, expected_target, expected_nonce,
        expected_request_sha, endpoint, Some((sent_delegation, sent_setup, sent_request)), processing)
}

pub(super) fn verify_ingress(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8])
    -> Result<Vec<u8>, String> {
    let result = ingress::verify(raw, expectations_raw, trust_roots_raw)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native ingress verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native ingress verdict exceeds its bound")?;
    Ok(bytes)
}

fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8])
    -> Result<Vec<u8>, String> {
    let expected = config::Expectations::parse(expectations_raw)?;
    let roots = config::TrustRoots::parse(trust_roots_raw)?;
    let result = statement::verify(raw, &expected, &roots)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native verdict exceeds its bound")?;
    Ok(bytes)
}

fn ensure(condition: bool, error: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_owned()) }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| "missing native text field".to_owned())
}

fn uint(value: &Value, key: &str) -> Result<u64, String> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| "missing native unsigned integer".to_owned())
}

fn exact(value: &Value, fields: &[&str]) -> Result<(), String> {
    let map = value.as_object().ok_or("native value must be an object")?;
    ensure(map.len() == fields.len() && fields.iter().all(|key| map.contains_key(*key)),
        "native object fields are not exact")
}

fn digest(value: &[u8]) -> [u8; 32] { Sha256::digest(value).into() }
fn digest_text(value: &[u8]) -> String { format!("sha256:{}", hex::encode(value)) }
fn b64(value: &[u8]) -> String { general_purpose::URL_SAFE_NO_PAD.encode(value) }

fn decode_b64(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= maximum.saturating_mul(4).saturating_add(2) / 3,
        "native base64url exceeds its bound")?;
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "native base64url is invalid")?;
    ensure(!bytes.is_empty() && bytes.len() <= maximum && b64(&bytes) == value,
        "native base64url is not canonical")?;
    Ok(bytes)
}

fn fixed_b64<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode_b64(value, N)?.try_into().map_err(|_| "native base64url size differs".to_owned())
}

fn parse_digest<const N: usize>(value: &str, prefix: &str, nonzero: bool) -> Result<[u8; N], String> {
    let encoded = value.strip_prefix(prefix).ok_or("native digest prefix differs")?;
    ensure(encoded.len() == N * 2
        && encoded.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native digest is not canonical")?;
    let mut result = [0; N];
    hex::decode_to_slice(encoded, &mut result).map_err(|_| "native digest is invalid")?;
    ensure(!nonzero || result != [0; N], "native digest must be nonzero")?;
    Ok(result)
}

fn now_seconds() -> Result<u64, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native verifier clock is invalid")?.as_secs();
    ensure(now > 0, "native verifier clock is invalid")?;
    Ok(now)
}

fn fresh(issued: u64, now: u64, expected: &config::Expectations) -> Result<(), String> {
    ensure(issued > 0
        && issued <= now.checked_add(expected.future_skew).ok_or("native age overflow")?
        && now.saturating_sub(issued) <= expected.max_age, "native evidence is not fresh")
}

/// Exact canonical ASCII PEM armor; DER is parsed by the appropriate key or
/// certificate verifier. No permissive PEM prefix/suffix or multi-object load.
fn pem_der(pem: &str, label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!pem.is_empty() && pem.len() <= maximum && pem.is_ascii(), "native PEM exceeds its bound")?;
    let head = format!("-----BEGIN {label}-----\n");
    let tail = format!("-----END {label}-----\n");
    let body = pem.strip_prefix(&head).and_then(|text| text.strip_suffix(&tail))
        .ok_or("native PEM armor differs")?;
    let compact: String = body.chars().filter(|ch| *ch != '\n').collect();
    let bytes = general_purpose::STANDARD.decode(&compact).map_err(|_| "native PEM base64 is invalid")?;
    ensure(!bytes.is_empty(), "native PEM is empty")?;
    let encoded = general_purpose::STANDARD.encode(&bytes);
    let mut canonical = head;
    for line in encoded.as_bytes().chunks(64) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| "native PEM cannot be encoded")?);
        canonical.push('\n');
    }
    canonical.push_str(&tail);
    ensure(canonical == pem, "native PEM is not canonical")?;
    Ok(bytes)
}
