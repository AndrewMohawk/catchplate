//! Closed independently pinned inputs; parsing is not signature admission.

use super::{ensure, json, originals::ArtifactV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, PathBuf};
use std::time::Duration;

pub(super) const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    api_version: String,
    endpoint: String,
    timeout_milliseconds: u64,
    startup_evidence: ArtifactV1,
    startup_expectations: ArtifactV1,
    session_scope: ArtifactV1,
    trust_roots: ArtifactV1,
    client_certificate: ArtifactV1,
    client_private_key: ArtifactV1,
    caller_issuer: ArtifactV1,
    delegation_authorizer: ArtifactV1,
    setup_authorizer: ArtifactV1,
    request: ArtifactV1,
    client_challenge_base64url: String,
    expected_caller_principal: String,
    expected_target_principal: String,
    expected_target_nonce: String,
    expected_target_request_sha256: String,
}

pub(super) struct Configuration {
    pub(super) endpoint: SocketAddr,
    pub(super) timeout: Duration,
    pub(super) startup_evidence: ArtifactV1,
    pub(super) startup_expectations: ArtifactV1,
    pub(super) session_scope: ArtifactV1,
    pub(super) trust_roots: ArtifactV1,
    pub(super) client_certificate: ArtifactV1,
    pub(super) client_private_key: ArtifactV1,
    pub(super) caller_issuer: ArtifactV1,
    pub(super) delegation_authorizer: ArtifactV1,
    pub(super) setup_authorizer: ArtifactV1,
    pub(super) request: ArtifactV1,
    pub(super) challenge: [u8; 32],
    pub(super) expected_caller_principal: String,
    pub(super) expected_target_principal: String,
    pub(super) expected_target_nonce: String,
    pub(super) expected_target_request_sha256: String,
}

fn artifact(value: &ArtifactV1) -> Result<(), String> {
    let bytes = value.path.as_os_str().as_bytes();
    ensure(!bytes.is_empty() && bytes.len() <= 4096 && !bytes.contains(&0)
        && value.path.is_absolute() && value.path.file_name().is_some()
        && value.path.components().all(|part| matches!(part,
            Component::RootDir | Component::Normal(_))),
        "bootstrap client artifact path is invalid")?;
    let rebuilt: PathBuf = value.path.components().collect();
    ensure(rebuilt.as_os_str().as_bytes() == bytes
        && super::super::is_sha256_digest(&value.sha256),
        "bootstrap client artifact spelling or digest differs")
}

fn endpoint(value: &str) -> Result<SocketAddr, String> {
    ensure(!value.is_empty() && value.len() <= 64 && value.is_ascii(),
        "bootstrap client endpoint exceeds its bound")?;
    let parsed = value.parse::<SocketAddr>().map_err(|_| "bootstrap client endpoint is not literal")?;
    ensure(parsed.to_string() == value && parsed.port() != 0,
        "bootstrap client endpoint is not canonical")?;
    let ip = match parsed {
        SocketAddr::V4(value) => IpAddr::V4(*value.ip()),
        SocketAddr::V6(value) => {
            ensure(value.flowinfo() == 0 && value.scope_id() == 0,
                "bootstrap client endpoint cannot select an IPv6 scope")?;
            value.ip().to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(*value.ip()))
        }
    };
    ensure(!ip.is_unspecified() && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(value) if value.is_broadcast()),
        "bootstrap client endpoint must be unicast")?;
    Ok(parsed)
}

impl Configuration {
    pub(super) fn parse_original(raw: &[u8]) -> Result<Self, String> {
        let wire: Wire = serde_json::from_value(json::parse(raw, MAX_CONFIGURATION_BYTES)?)
            .map_err(|_| "bootstrap client configuration violates its closed contract")?;
        ensure(wire.api_version == "serverware.nativeBootstrapClient/v1"
            && (100..=30_000).contains(&wire.timeout_milliseconds),
            "bootstrap client profile or timeout differs")?;
        for value in [&wire.startup_evidence, &wire.startup_expectations, &wire.session_scope,
            &wire.trust_roots, &wire.client_certificate, &wire.client_private_key,
            &wire.caller_issuer, &wire.delegation_authorizer, &wire.setup_authorizer, &wire.request]
        { artifact(value)?; }
        ensure(wire.client_challenge_base64url.len() == 43,
            "bootstrap client challenge encoding differs")?;
        let challenge: [u8; 32] = URL_SAFE_NO_PAD.decode(&wire.client_challenge_base64url)
            .map_err(|_| "bootstrap client challenge is invalid")?.try_into()
            .map_err(|_| "bootstrap client challenge length differs")?;
        ensure(challenge != [0; 32] && URL_SAFE_NO_PAD.encode(challenge) == wire.client_challenge_base64url,
            "bootstrap client challenge must be canonical and nonzero")?;
        ensure(!wire.expected_caller_principal.is_empty() && wire.expected_caller_principal.len() <= 256
            && wire.expected_caller_principal.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            && !wire.expected_target_principal.is_empty() && wire.expected_target_principal.len() <= 1024
            && (32..=256).contains(&wire.expected_target_nonce.len())
            && wire.expected_target_nonce.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-'))
            && super::super::is_sha256_digest(&wire.expected_target_request_sha256),
            "bootstrap client independent target or caller expectations differ")?;
        Ok(Self {
            endpoint: endpoint(&wire.endpoint)?, timeout: Duration::from_millis(wire.timeout_milliseconds),
            startup_evidence: wire.startup_evidence, startup_expectations: wire.startup_expectations,
            session_scope: wire.session_scope, trust_roots: wire.trust_roots,
            client_certificate: wire.client_certificate, client_private_key: wire.client_private_key,
            caller_issuer: wire.caller_issuer, delegation_authorizer: wire.delegation_authorizer,
            setup_authorizer: wire.setup_authorizer, request: wire.request, challenge,
            expected_caller_principal: wire.expected_caller_principal,
            expected_target_principal: wire.expected_target_principal,
            expected_target_nonce: wire.expected_target_nonce,
            expected_target_request_sha256: wire.expected_target_request_sha256,
        })
    }
}
