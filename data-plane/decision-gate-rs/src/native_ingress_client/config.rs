//! Closed, pinned inputs for one native-ingress quotation exchange.
//!
//! Parsing establishes local shape only. The parent retains and rechecks each
//! actual original, and separately verifies quotes before using the private CA.
//! V1 pins complete session expectations, including a caller-supplied challenge.
//! V2 pins a nonce-free session scope; the controller owns challenge generation.
//! V3 additionally pins a workload issuer for fresh, quoted client-trust admission.

use super::{ensure, json, originals::ArtifactV1};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, PathBuf};
use std::time::Duration;

pub(super) const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;

pub(super) struct Configuration {
    pub(super) endpoint: SocketAddr,
    pub(super) timeout: Duration,
    pub(super) startup_evidence: ArtifactV1,
    pub(super) startup_expectations: ArtifactV1,
    pub(super) session: SessionInput,
    pub(super) trust_roots: ArtifactV1,
    pub(super) client_certificate: ArtifactV1,
    pub(super) client_private_key: ArtifactV1,
    pub(super) workload_issuer: Option<ArtifactV1>,
}

pub(super) enum SessionInput {
    PinnedChallenge(ArtifactV1),
    GeneratedChallenge(ArtifactV1),
}

#[derive(Deserialize)]
#[serde(tag = "apiVersion", deny_unknown_fields)]
enum WireConfiguration {
    #[serde(rename = "serverware.nativeIngressClient/v1", rename_all = "camelCase")]
    V1 {
        endpoint: String,
        timeout_milliseconds: u64,
        startup_evidence: ArtifactV1,
        startup_expectations: ArtifactV1,
        session_expectations: ArtifactV1,
        trust_roots: ArtifactV1,
        client_certificate: ArtifactV1,
        client_private_key: ArtifactV1,
    },
    #[serde(rename = "serverware.nativeIngressClient/v2", rename_all = "camelCase")]
    V2 {
        endpoint: String,
        timeout_milliseconds: u64,
        startup_evidence: ArtifactV1,
        startup_expectations: ArtifactV1,
        session_scope: ArtifactV1,
        trust_roots: ArtifactV1,
        client_certificate: ArtifactV1,
        client_private_key: ArtifactV1,
    },
    #[serde(rename = "serverware.nativeIngressClient/v3", rename_all = "camelCase")]
    V3 {
        endpoint: String,
        timeout_milliseconds: u64,
        startup_evidence: ArtifactV1,
        startup_expectations: ArtifactV1,
        session_scope: ArtifactV1,
        trust_roots: ArtifactV1,
        client_certificate: ArtifactV1,
        client_private_key: ArtifactV1,
        workload_issuer: ArtifactV1,
    },
}

fn check_artifact(artifact: &ArtifactV1) -> Result<(), String> {
    let path = &artifact.path;
    let bytes = path.as_os_str().as_bytes();
    ensure(!bytes.is_empty() && bytes.len() <= 4096 && !bytes.contains(&0)
        && path.is_absolute() && path.file_name().is_some()
        && path.components().all(|part| matches!(part,
            Component::RootDir | Component::Normal(_))),
        "native ingress client artifact path must be bounded and absolute without traversal")?;
    // Component iteration normalizes dot/repeated separators. Compare the
    // actual spelling too; filesystem canonical/no-follow checks happen on open.
    let rebuilt: PathBuf = path.components().collect();
    ensure(rebuilt.as_os_str().as_bytes() == bytes,
        "native ingress client artifact path spelling is not canonical")?;
    ensure(super::super::is_sha256_digest(&artifact.sha256)
        && artifact.sha256.as_bytes()[7..].iter().any(|byte| *byte != b'0'),
        "native ingress client artifact digest must be canonical and nonzero")
}

fn endpoint(original: &str) -> Result<SocketAddr, String> {
    ensure(!original.is_empty() && original.len() <= 64 && original.is_ascii(),
        "native ingress client endpoint is not a bounded literal socket address")?;
    let endpoint = original.parse::<SocketAddr>()
        .map_err(|_| "native ingress client endpoint is not a literal socket address")?;
    ensure(endpoint.to_string() == original && endpoint.port() != 0,
        "native ingress client endpoint spelling or port is invalid")?;
    let ip = match endpoint {
        SocketAddr::V4(value) => IpAddr::V4(*value.ip()),
        SocketAddr::V6(value) => {
            ensure(value.flowinfo() == 0 && value.scope_id() == 0,
                "native ingress client endpoint cannot select an IPv6 scope")?;
            // Mapped IPv4 must not bypass the same destination-shape exclusions.
            value.ip().to_ipv4_mapped().map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(*value.ip()))
        }
    };
    ensure(!ip.is_unspecified() && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(value) if value.is_broadcast()),
        "native ingress client endpoint must be a concrete unicast address")?;
    Ok(endpoint)
}

impl Configuration {
    pub(super) fn parse_original(original: &[u8]) -> Result<Self, String> {
        let value = json::parse(original, MAX_CONFIGURATION_BYTES)?;
        let config: WireConfiguration = serde_json::from_value(value)
            .map_err(|_| "native ingress client configuration violates its closed contract")?;
        let generated = matches!(&config, WireConfiguration::V2 { .. } | WireConfiguration::V3 { .. });
        let (address, timeout_milliseconds, startup_evidence, startup_expectations,
            session_artifact, trust_roots, client_certificate, client_private_key,
            workload_issuer) = match config {
            WireConfiguration::V1 {
                endpoint: address, timeout_milliseconds, startup_evidence,
                startup_expectations, session_expectations: session_artifact,
                trust_roots, client_certificate, client_private_key,
            }
            | WireConfiguration::V2 {
                endpoint: address, timeout_milliseconds, startup_evidence,
                startup_expectations, session_scope: session_artifact,
                trust_roots, client_certificate, client_private_key,
            } => (address, timeout_milliseconds, startup_evidence, startup_expectations,
                session_artifact, trust_roots, client_certificate, client_private_key, None),
            WireConfiguration::V3 {
                endpoint: address, timeout_milliseconds, startup_evidence,
                startup_expectations, session_scope: session_artifact,
                trust_roots, client_certificate, client_private_key, workload_issuer,
            } => (address, timeout_milliseconds, startup_evidence, startup_expectations,
                session_artifact, trust_roots, client_certificate, client_private_key,
                Some(workload_issuer)),
        };
        ensure((100..=30_000).contains(&timeout_milliseconds),
            "native ingress client timeout is outside its fixed bounds")?;
        let endpoint = endpoint(&address)?;
        for artifact in [&startup_evidence, &startup_expectations,
            &session_artifact, &trust_roots, &client_certificate, &client_private_key]
        {
            check_artifact(artifact)?;
        }
        if let Some(artifact) = &workload_issuer { check_artifact(artifact)?; }
        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(timeout_milliseconds),
            startup_evidence,
            startup_expectations,
            session: if generated {
                SessionInput::GeneratedChallenge(session_artifact)
            } else {
                SessionInput::PinnedChallenge(session_artifact)
            },
            trust_roots,
            client_certificate,
            client_private_key,
            workload_issuer,
        })
    }
}
