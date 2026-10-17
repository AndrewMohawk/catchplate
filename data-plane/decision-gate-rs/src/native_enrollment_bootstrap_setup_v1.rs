//! Separate, original-only deployment setup authorization.
//!
//! The cold owner independently selects both public roots. This verifier replays
//! the delegation and binds the exact policy-requirements original; neither that
//! hash nor signed deployment metadata proves actual policy admission, a live CA
//! capability reservation, namespace ownership or installation. Those remain
//! separately checked effects. No token, private key, packet signer or installer
//! is accepted or returned here.

use super::{assignment, bootstrap_delegation};
use super::native_workload_bootstrap_request_v1::{decode_canonical, encode_canonical};
use ed25519_dalek::Signature;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use url::{Host, Url};

const ENVELOPE_VERSION: &str = "catchplate.signedNativeEnrollmentBootstrapSetup/v1";
const PAYLOAD_VERSION: &str = "catchplate.nativeEnrollmentBootstrapSetup/v1";
const PURPOSE: &str = "native-enrollment-bootstrap-setup";
const DOMAIN: &[u8] = b"catchplate/native-enrollment-bootstrap-setup/v1\0";
const MAX_SETUP_BYTES: usize = 32 * 1024;
const MAX_REQUIREMENTS_BYTES: usize = 64 * 1024;
const MAX_SECONDS: u64 = 9_223_372_036;
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;
const PROCESSING_NS: u64 = 30_000_000_000;
const NS_PER_SECOND: u64 = 1_000_000_000;

// deserialize_with prevents serde's missing-Option fallback: these fields must
// be present as either a value or an explicit null in the closed original.
fn required_nullable<'de, D, T>(value: D) -> Result<Option<T>, D::Error>
where D: Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(value)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    api_version: String,
    setup: WireSetup,
    signature_base64url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSetup {
    api_version: String,
    purpose: String,
    authorizer_key_id: String,
    setup_id: String,
    delegation_sha256: String,
    target_request_sha256: String,
    policy_requirements_sha256: String,
    release_record_sha256: String,
    policy_hash: String,
    configuration_sha256: String,
    runtime_ca_certificate_sha256: String,
    runtime_ca_spki_sha256: String,
    target_principal_id: String,
    target_nonce: String,
    control_plane_origin: String,
    proxy: ProxySetup,
    ca_install: CaInstallSetup,
    #[serde(deserialize_with = "required_nullable")]
    kubernetes: Option<KubernetesSetup>,
    network_owner: NetworkOwnerSetup,
    not_before_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProxySetup {
    pub(crate) origin: String,
    pub(crate) endpoint: String,
    pub(crate) egress_cidrs: Vec<String>,
    pub(crate) host_addresses: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaInstallSetup {
    pub(crate) profile: String,
    pub(crate) capability_id: String,
    pub(crate) capability_token_sha256: String,
    pub(crate) expires_at_epoch_ms: u64,
    pub(crate) destination_path: String,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) file_mode: u32,
    pub(crate) replace_existing: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) expected_existing_certificate_sha256: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KubernetesSetup {
    pub(crate) namespace: String,
    pub(crate) pod_selector: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NetworkOwnerSetup {
    pub(crate) host_id: String,
    pub(crate) boot_id: String,
    pub(crate) namespace_device: u64,
    pub(crate) namespace_inode: u64,
    pub(crate) owner_uid: u32,
}

/// Authenticated comparisons, not an observed installation or capability DTO.
/// Consuming owners retain the verifier, not just this immutable projection.
pub(crate) struct SetupPayload {
    pub(crate) authorizer_key_id: [u8; 32],
    pub(crate) setup_id: [u8; 32],
    pub(crate) delegation_sha256: [u8; 32],
    pub(crate) target_request_sha256: [u8; 32],
    pub(crate) policy_requirements_sha256: [u8; 32],
    pub(crate) release_record_sha256: [u8; 32],
    pub(crate) policy_hash: [u8; 32],
    pub(crate) configuration_sha256: [u8; 32],
    pub(crate) runtime_ca_certificate_sha256: [u8; 32],
    pub(crate) runtime_ca_spki_sha256: [u8; 32],
    pub(crate) target_principal_id: String,
    pub(crate) target_nonce: String,
    pub(crate) control_plane_origin: String,
    pub(crate) proxy: ProxySetup,
    pub(crate) proxy_endpoint: SocketAddr,
    pub(crate) ca_install: CaInstallSetup,
    pub(crate) kubernetes: Option<KubernetesSetup>,
    pub(crate) network_owner: NetworkOwnerSetup,
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
}

/// Non-Clone/non-Debug owner. Child and local clocks only tighten the original
/// processing/authorization bounds; any failed current check is irreversible.
pub(crate) struct VerifiedNativeEnrollmentBootstrapSetupV1 {
    payload: SetupPayload,
    delegation: bootstrap_delegation::VerifiedNativeEnrollmentBootstrapDelegationV1,
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

fn framing(original: &[u8]) -> Result<&[u8], String> {
    require(original.len() > 1 && original.len() <= MAX_SETUP_BYTES
        && original.last() == Some(&b'\n'), "native bootstrap setup requires one bounded JSON line")?;
    let body = &original[..original.len() - 1];
    require(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native bootstrap setup JSON framing differs")?;
    Ok(body)
}

fn origin(value: &str) -> Result<(String, u16), String> {
    require(!value.is_empty() && value.len() <= 2048
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "native bootstrap setup origin is not bounded ASCII")?;
    let parsed = Url::parse(value).map_err(|_| "native bootstrap setup origin is invalid")?;
    require(parsed.scheme() == "https" && parsed.username().is_empty()
        && parsed.password().is_none() && parsed.path() == "/"
        && parsed.query().is_none() && parsed.fragment().is_none(),
        "native bootstrap setup requires an HTTPS origin only")?;
    let (host, authority) = match parsed.host().ok_or("native bootstrap setup origin has no host")? {
        Host::Domain(value) => (value.to_owned(), value.to_owned()),
        Host::Ipv4(value) => (value.to_string(), value.to_string()),
        Host::Ipv6(value) => (value.to_string(), format!("[{value}]")),
    };
    let port = parsed.port_or_known_default().ok_or("native bootstrap setup origin has no port")?;
    let expected = if port == 443 { format!("https://{authority}") }
        else { format!("https://{authority}:{port}") };
    require(port > 0 && assignment::host(&host) && expected == value,
        "native bootstrap setup origin is not canonical")?;
    if host.parse::<IpAddr>().is_ok() { unicast(&host)?; }
    Ok((host, port))
}

fn unicast(value: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = value.parse().map_err(|_| "native bootstrap setup host address is invalid")?;
    let checked = match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    require(ip.to_string() == value && !checked.is_unspecified() && !checked.is_multicast()
        && !matches!(checked, IpAddr::V4(value) if value.is_broadcast()),
        "native bootstrap setup host address must be canonical unicast")?;
    Ok(ip)
}

fn strictly_sorted(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum
        && values.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn proxy(value: &ProxySetup, delegated_host: &str, delegated_endpoint: SocketAddr)
    -> Result<SocketAddr, String> {
    let (host, port) = origin(&value.origin)?;
    let endpoint = assignment::validate_proxy_endpoint_original(&value.endpoint)?;
    require(endpoint == delegated_endpoint && host == delegated_host && port == endpoint.port()
        && strictly_sorted(&value.egress_cidrs, 32) && strictly_sorted(&value.host_addresses, 16),
        "native bootstrap setup proxy scope differs")?;
    let mut networks = Vec::with_capacity(value.egress_cidrs.len());
    for original in &value.egress_cidrs {
        require(original.len() <= 49 && original.is_ascii(),
            "native bootstrap setup CIDR exceeds its bound")?;
        let network: IpNet = original.parse().map_err(|_| "native bootstrap setup CIDR is invalid")?;
        require(network.prefix_len() > 0 && network.addr() == network.network()
            && network.to_string() == *original, "native bootstrap setup CIDR is not canonical or is universal")?;
        networks.push(network);
    }
    let mut addresses = Vec::with_capacity(value.host_addresses.len());
    for original in &value.host_addresses {
        require(original.len() <= 45, "native bootstrap setup host address exceeds its bound")?;
        let address = unicast(original)?;
        require(networks.iter().any(|network| network.contains(&address)),
            "native bootstrap setup host address is outside authorized egress")?;
        addresses.push(address);
    }
    require(addresses.contains(&endpoint.ip()),
        "native bootstrap setup omits the independently selected proxy endpoint")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        require(addresses.len() == 1 && addresses[0] == ip && ip == endpoint.ip(),
            "native bootstrap setup IP origin selects another host mapping")?;
    }
    Ok(endpoint)
}

fn ca_install(value: &CaInstallSetup, expires_at_unix_seconds: u64) -> Result<(), String> {
    require(value.profile == "native-ca-install-association-v1"
        && (24..=128).contains(&value.capability_id.len())
        && value.capability_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && value.expires_at_epoch_ms > 0 && value.expires_at_epoch_ms <= MAX_EPOCH_MS
        && expires_at_unix_seconds * 1000 <= value.expires_at_epoch_ms
        && value.owner_uid != u32::MAX && value.owner_gid != u32::MAX && value.file_mode == 420,
        "native bootstrap setup CA capability association is invalid")?;
    assignment::digest_field(&value.capability_token_sha256)?;
    let path = &value.destination_path;
    require(path.len() > 1 && path.len() <= 4096 && path.starts_with('/') && !path.ends_with('/')
        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'\\')
        && path[1..].split('/').all(|part| !matches!(part, "" | "." | "..")),
        "native bootstrap setup CA destination is not a canonical absolute file")?;
    match (&value.expected_existing_certificate_sha256, value.replace_existing) {
        (Some(original), true) => { assignment::digest_field(original)?; }
        (None, false) => {}
        _ => return Err("native bootstrap setup rotation needs an exact existing certificate pin".to_owned()),
    }
    Ok(())
}

fn dns_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric() && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn label_part(value: &str, allow_empty: bool) -> bool {
    (allow_empty && value.is_empty()) || (!value.is_empty() && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric() && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
}

fn kubernetes(value: &KubernetesSetup) -> Result<(), String> {
    require(dns_label(&value.namespace) && !value.pod_selector.is_empty() && value.pod_selector.len() <= 16,
        "native bootstrap setup Kubernetes scope is invalid")?;
    for (key, value) in &value.pod_selector {
        let name = if let Some((prefix, name)) = key.split_once('/') {
            require(!prefix.is_empty() && prefix.len() <= 253 && prefix.split('.').all(dns_label),
                "native bootstrap setup label prefix is invalid")?;
            name
        } else { key.as_str() };
        require(label_part(name, false) && label_part(value, true),
            "native bootstrap setup label selector is invalid")?;
    }
    Ok(())
}

fn network_owner(value: &NetworkOwnerSetup) -> Result<(), String> {
    require(!value.host_id.is_empty() && value.host_id.len() <= 128
        && value.host_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        && value.namespace_inode > 0 && value.owner_uid != u32::MAX,
        "native bootstrap setup network owner scope is invalid")?;
    let boot = value.boot_id.as_bytes();
    require(boot.len() == 36 && boot.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { *byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) }
    }) && boot.iter().any(|byte| !matches!(*byte, b'0' | b'-')),
        "native bootstrap setup host boot ID is not a canonical nonzero UUID")
}

pub(crate) fn verify_original(setup_original: &[u8], setup_public_pem: &[u8],
    setup_pem_sha256: &str, delegation_original: &[u8], delegation_public_pem: &[u8],
    delegation_pem_sha256: &str, target_request_original: &[u8],
    policy_requirements_original: &[u8], deadline: u64)
    -> Result<VerifiedNativeEnrollmentBootstrapSetupV1, String> {
    let owner_pid = unsafe { libc::getpid() };
    let (wall, boot) = assignment::sample()?;
    require(owner_pid > 0 && boot < deadline, "native bootstrap setup original deadline expired")?;
    let deadline = deadline.min(boot.checked_add(PROCESSING_NS)
        .ok_or("native bootstrap setup deadline overflow")?);
    require(!policy_requirements_original.is_empty() && policy_requirements_original.len() <= MAX_REQUIREMENTS_BYTES,
        "native bootstrap setup policy-requirements original exceeds its bound")?;
    let envelope: Envelope = decode_canonical(framing(setup_original)?, MAX_SETUP_BYTES)?;
    require(envelope.api_version == ENVELOPE_VERSION && envelope.setup.api_version == PAYLOAD_VERSION
        && envelope.setup.purpose == PURPOSE, "native bootstrap setup version or purpose differs")?;
    let (key, key_id) = assignment::authorizer(setup_public_pem, setup_pem_sha256)?;
    require(!key.is_weak(), "native bootstrap setup authorizer key is weak")?;
    let p = envelope.setup;
    let canonical = encode_canonical(&p, MAX_SETUP_BYTES)?;
    let signature = Signature::from_bytes(&assignment::fixed_base64::<64>(&envelope.signature_base64url)?);
    let mut signed = Vec::with_capacity(DOMAIN.len() + canonical.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&canonical);
    key.verify_strict(&signed, &signature).map_err(|_| "native bootstrap setup signature is invalid")?;
    require(assignment::digest_field(&p.authorizer_key_id)? == key_id,
        "native bootstrap setup differs from the independent authorizer")?;
    let mut delegation = bootstrap_delegation::verify_original(delegation_original,
        delegation_public_pem, delegation_pem_sha256, target_request_original, deadline)?;
    let d = delegation.payload();
    require([d.authorizer_key_id, d.runtime_ca_spki_sha256, d.caller_issuer_spki_sha256,
        d.caller_spki_sha256, d.target_issuer_spki_sha256, d.target_spki_sha256]
        .iter().all(|candidate| candidate != &key_id),
        "native bootstrap setup authorizer shares another authorizer, runtime or workload key role")?;
    require(p.not_before_unix_seconds > 0 && p.expires_at_unix_seconds <= MAX_SECONDS
        && p.expires_at_unix_seconds > p.not_before_unix_seconds
        && p.expires_at_unix_seconds - p.not_before_unix_seconds <= 300
        && p.not_before_unix_seconds >= d.not_before_unix_seconds
        && p.expires_at_unix_seconds <= d.expires_at_unix_seconds
        && p.not_before_unix_seconds * 1000 >= d.target_created_at_epoch_ms
        && p.expires_at_unix_seconds * 1000 <= d.target_expires_at_epoch_ms,
        "native bootstrap setup exceeds its original delegation or target interval")?;
    let before = p.not_before_unix_seconds * NS_PER_SECOND;
    let expires = p.expires_at_unix_seconds * NS_PER_SECOND;
    require(before <= wall && wall < expires, "native bootstrap setup is outside its original interval")?;
    let delegation_sha256 = assignment::digest_field(&p.delegation_sha256)?;
    let target_request_sha256 = assignment::digest_field(&p.target_request_sha256)?;
    let policy_requirements_sha256 = assignment::digest_field(&p.policy_requirements_sha256)?;
    let release_record_sha256 = assignment::digest_field(&p.release_record_sha256)?;
    let policy_hash = assignment::digest_field(&p.policy_hash)?;
    let configuration_sha256 = assignment::digest_field(&p.configuration_sha256)?;
    let runtime_ca_certificate_sha256 = assignment::digest_field(&p.runtime_ca_certificate_sha256)?;
    let runtime_ca_spki_sha256 = assignment::digest_field(&p.runtime_ca_spki_sha256)?;
    require(delegation_sha256 == delegation.original_sha256()
        && target_request_sha256 == d.target_request_sha256
        && policy_requirements_sha256 == digest(policy_requirements_original)
        && release_record_sha256 == d.release_record_sha256 && policy_hash == d.policy_hash
        && configuration_sha256 == d.configuration_sha256
        && runtime_ca_certificate_sha256 == d.runtime_ca_certificate_sha256
        && runtime_ca_spki_sha256 == d.runtime_ca_spki_sha256
        && p.target_principal_id == d.target_principal_id && p.target_nonce == d.target_nonce,
        "native bootstrap setup differs from the genuine delegation or selected originals")?;
    origin(&p.control_plane_origin)?;
    let proxy_endpoint = proxy(&p.proxy, &d.ingress_host, d.proxy_endpoint)?;
    ca_install(&p.ca_install, p.expires_at_unix_seconds)?;
    if let Some(value) = &p.kubernetes { kubernetes(value)?; }
    network_owner(&p.network_owner)?;
    let payload = SetupPayload {
        authorizer_key_id: key_id, setup_id: assignment::nonzero_base64(&p.setup_id)?,
        delegation_sha256, target_request_sha256, policy_requirements_sha256,
        release_record_sha256, policy_hash, configuration_sha256,
        runtime_ca_certificate_sha256, runtime_ca_spki_sha256,
        target_principal_id: p.target_principal_id, target_nonce: p.target_nonce,
        control_plane_origin: p.control_plane_origin, proxy: p.proxy, proxy_endpoint,
        ca_install: p.ca_install, kubernetes: p.kubernetes, network_owner: p.network_owner,
        not_before_unix_seconds: p.not_before_unix_seconds,
        expires_at_unix_seconds: p.expires_at_unix_seconds,
    };
    delegation.check(deadline)?;
    let expiry_deadline = boot.checked_add(expires - wall)
        .ok_or("native bootstrap setup expiry deadline overflow")?;
    let deadline = deadline.min(delegation.deadline()).min(expiry_deadline);
    let mut result = VerifiedNativeEnrollmentBootstrapSetupV1 { payload, delegation,
        original_sha256: digest(setup_original), deadline, owner_pid,
        last_wall_ns: wall, last_boot_ns: boot, poisoned: false };
    result.check(deadline)?;
    Ok(result)
}

impl VerifiedNativeEnrollmentBootstrapSetupV1 {
    pub(crate) fn payload(&self) -> &SetupPayload { &self.payload }
    /// Read-only access to the actual retained child, never a supplied result.
    /// Parent checks retain this child's original lifetime before and after use.
    pub(crate) fn delegation(&self)
        -> &bootstrap_delegation::VerifiedNativeEnrollmentBootstrapDelegationV1 {
        &self.delegation
    }
    pub(crate) fn original_sha256(&self) -> [u8; 32] { self.original_sha256 }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), String> {
        require(!std::mem::replace(&mut self.poisoned, true), "native bootstrap setup owner is poisoned")?;
        self.deadline = self.deadline.min(deadline);
        require(unsafe { libc::getpid() } == self.owner_pid, "native bootstrap setup crossed its process")?;
        self.delegation.check(self.deadline)?;
        self.deadline = self.deadline.min(self.delegation.deadline());
        let (wall, boot) = assignment::sample()?;
        let before = self.payload.not_before_unix_seconds * NS_PER_SECOND;
        let expires = self.payload.expires_at_unix_seconds * NS_PER_SECOND;
        require(wall >= self.last_wall_ns && boot >= self.last_boot_ns
            && boot < self.deadline && before <= wall && wall < expires,
            "native bootstrap setup expired or a clock moved backwards")?;
        self.deadline = self.deadline.min(boot.checked_add(expires - wall)
            .ok_or("native bootstrap setup remaining interval overflow")?);
        self.last_wall_ns = wall;
        self.last_boot_ns = boot;
        self.poisoned = false;
        Ok(())
    }
}
