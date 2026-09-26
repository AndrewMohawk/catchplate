//! Closed, pinned inputs for one native-ingress quotation exchange.
//!
//! Parsing establishes local shape only. The parent retains and rechecks each
//! actual original, and separately verifies quotes before using the private CA.

use super::{ensure, json, originals::ArtifactV1};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, PathBuf};
use std::time::Duration;

pub(super) const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;

pub(super) struct ConfigurationV1 {
    pub(super) endpoint: SocketAddr,
    pub(super) timeout: Duration,
    pub(super) startup_evidence: ArtifactV1,
    pub(super) startup_expectations: ArtifactV1,
    pub(super) session_expectations: ArtifactV1,
    pub(super) trust_roots: ArtifactV1,
    pub(super) client_certificate: ArtifactV1,
    pub(super) client_private_key: ArtifactV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireConfigurationV1 {
    api_version: String,
    endpoint: String,
    timeout_milliseconds: u64,
    startup_evidence: ArtifactV1,
    startup_expectations: ArtifactV1,
    session_expectations: ArtifactV1,
    trust_roots: ArtifactV1,
    client_certificate: ArtifactV1,
    client_private_key: ArtifactV1,
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

impl ConfigurationV1 {
    pub(super) fn parse_original(original: &[u8]) -> Result<Self, String> {
        let value = json::parse(original, MAX_CONFIGURATION_BYTES)?;
        let config: WireConfigurationV1 = serde_json::from_value(value)
            .map_err(|_| "native ingress client configuration violates its closed contract")?;
        ensure(config.api_version == "serverware.nativeIngressClient/v1",
            "native ingress client configuration version is invalid")?;
        ensure((100..=30_000).contains(&config.timeout_milliseconds),
            "native ingress client timeout is outside its fixed bounds")?;
        let endpoint = endpoint(&config.endpoint)?;
        for artifact in [&config.startup_evidence, &config.startup_expectations,
            &config.session_expectations, &config.trust_roots,
            &config.client_certificate, &config.client_private_key]
        {
            check_artifact(artifact)?;
        }
        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(config.timeout_milliseconds),
            startup_evidence: config.startup_evidence,
            startup_expectations: config.startup_expectations,
            session_expectations: config.session_expectations,
            trust_roots: config.trust_roots,
            client_certificate: config.client_certificate,
            client_private_key: config.client_private_key,
        })
    }
}
