//! Dedicated signed egress constraints, never a native-proof or effect verdict.

use super::super::{json, native_verifier, sample, OriginalClock};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signature;
use ipnet::IpNet;
use serde::Serialize;
use serde_json::{Map, Value};
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};
use url::{Host, Url};

const MAX_BYTES: usize = 32 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const SCHEMA: &str = "serverware.nativeEgressInstallationAuthorization/v1";
const ENVELOPE: &str = "serverware.signedNativeEgressInstallationAuthorization/v1";
const CREATION_SCHEMA: &str = "serverware.nativeEgressInstallationAuthorization/v2";
const CREATION_ENVELOPE: &str = "serverware.signedNativeEgressInstallationAuthorization/v2";
const NETWORK_SCHEMA: &str = "serverware.nativeEgressInstallationAuthorization/v3";
const NETWORK_ENVELOPE: &str = "serverware.signedNativeEgressInstallationAuthorization/v3";
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Proxy {
    pub(super) origin: String,
    pub(super) endpoint: String,
    pub(super) egress_cidrs: Vec<String>,
    pub(super) host_addresses: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworkOwner {
    pub(super) host_id: String,
    pub(super) boot_id: String,
    pub(super) namespace_device: u64,
    pub(super) namespace_inode: u64,
    pub(super) owner_uid: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Workload {
    pub(super) profile: String,
    pub(super) launch_manifest_sha256: String,
    pub(super) launcher_binary_sha256: String,
    pub(super) namespace_mode: String,
    pub(super) before_completion: String,
    pub(super) failure_mode: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Rule {
    pub(super) family: String,
    pub(super) address: String,
    pub(super) tcp_destination_port: u16,
    pub(super) verdict: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Ruleset {
    pub(super) profile: String,
    pub(super) table_name: String,
    pub(super) family: String,
    pub(super) chain_name: String,
    pub(super) chain_type: String,
    pub(super) hook: String,
    pub(super) priority: i32,
    pub(super) policy: String,
    pub(super) rules: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Capability {
    pub(super) capability_id: String,
    pub(super) capability_token_sha256: String,
    pub(super) expires_at_epoch_ms: u64,
}

#[derive(Serialize)]
pub(super) struct Journal {
    pub(super) path: String,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) namespace: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildNetworkPolicy { ManualDualStackV1 }

// Admission creates signed constraints only. The parent must join genuine
// same-session originals, independent roles, token and actual retained owners.
// The type is deliberately neither Clone nor Debug nor serializable authority.
pub(super) struct Authorization {
    pub(super) root_key_id: [u8; 32],
    pub(super) original_sha256: [u8; 32],
    pub(super) authorization_id: String,
    pub(super) setup_sha256: [u8; 32],
    pub(super) delegation_sha256: [u8; 32],
    pub(super) target_request_sha256: [u8; 32],
    pub(super) policy_requirements_sha256: [u8; 32],
    pub(super) release_record_sha256: [u8; 32],
    pub(super) policy_hash: [u8; 32],
    pub(super) configuration_sha256: [u8; 32],
    pub(super) runtime_ca_certificate_sha256: [u8; 32],
    pub(super) runtime_ca_spki_sha256: [u8; 32],
    pub(super) ingress_leaf_certificate_sha256: [u8; 32],
    pub(super) client_trust_bundle_sha256: [u8; 32],
    pub(super) client_challenge_sha256: [u8; 32],
    pub(super) target_spki_sha256: [u8; 32],
    pub(super) machine_id_sha256: [u8; 32],
    pub(super) target_principal_id: String,
    pub(super) target_nonce: String,
    pub(super) proxy: Proxy,
    pub(super) network_owner: NetworkOwner,
    pub(super) workload: Workload,
    pub(super) ruleset: Ruleset,
    pub(super) capability: Capability,
    pub(super) journal: Journal,
    pub(super) creation_journal: Option<Journal>,
    pub(super) child_network_policy: Option<ChildNetworkPolicy>,
    pub(super) issued_at_epoch_ns: u64,
    pub(super) expires_at_epoch_ns: u64,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native egress authorization refused".to_owned()) }
}

fn structure(raw: &[u8], clock: &OriginalClock) -> Result<(), String> {
    require(!raw.is_empty() && raw.len() <= MAX_BYTES)?;
    let mut stack = Vec::with_capacity(6);
    let (mut quoted, mut escaped) = (false, false);
    for (index, byte) in raw.iter().copied().enumerate() {
        if index % 1024 == 0 { clock.check()?; }
        require((0x20..=0x7e).contains(&byte))?;
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { require(stack.len() < 6)?; stack.push(byte); }
                b'}' => require(stack.pop() == Some(b'{'))?,
                b']' => require(stack.pop() == Some(b'['))?,
                _ => {}
            }
        }
    }
    require(stack.is_empty() && !quoted && !escaped)?;
    clock.check()
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let result = value.as_object().ok_or("native egress authorization object required")?;
    require(result.len() == fields.len() && fields.iter().all(|field| result.contains_key(*field)))?;
    Ok(result)
}

fn text(value: &Value, maximum: usize) -> Result<&str, String> {
    let value = value.as_str().ok_or("native egress authorization string required")?;
    require(!value.is_empty() && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))?;
    Ok(value)
}

fn integer(value: &Value, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = value.as_u64().ok_or("native egress authorization integer required")?;
    require((minimum..=maximum).contains(&value))?;
    Ok(value)
}

fn identifier(value: &Value) -> Result<String, String> {
    let value = text(value, 128)?;
    require(value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')))?;
    Ok(value.to_owned())
}

fn digest(value: &Value) -> Result<[u8; 32], String> {
    let value = text(value, 71)?;
    require(value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))?;
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[7 + 2 * index..9 + 2 * index], 16)
            .map_err(|_| "native egress authorization digest invalid")?;
    }
    require(result != [0; 32])?;
    Ok(result)
}

fn journal(value: &Value) -> Result<Journal, String> {
    let p = object(value, &["path", "device", "inode", "namespace"])?;
    let path = text(&p["path"], 4096)?;
    require(path.len() > 1 && path.starts_with('/') && !path.contains('\\'))?;
    for (index, component) in path[1..].split('/').enumerate() {
        require(index < 64 && component.len() <= 255 && !matches!(component, "" | "." | ".."))?;
    }
    Ok(Journal { path: path.to_owned(), device: integer(&p["device"], 1, i64::MAX as u64)?,
        inode: integer(&p["inode"], 1, i64::MAX as u64)?, namespace: identifier(&p["namespace"])? })
}

fn network_owner(value: &Value) -> Result<NetworkOwner, String> {
    let p = object(value, &["hostId", "bootId", "namespaceDevice", "namespaceInode", "ownerUid"])?;
    let host = text(&p["hostId"], 128)?;
    require(host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')))?;
    let boot = text(&p["bootId"], 36)?;
    require(boot.len() == 36 && boot.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    }) && boot.bytes().any(|byte| !matches!(byte, b'0' | b'-')))?;
    Ok(NetworkOwner { host_id: host.to_owned(), boot_id: boot.to_owned(),
        namespace_device: integer(&p["namespaceDevice"], 0, u64::MAX)?,
        namespace_inode: integer(&p["namespaceInode"], 1, u64::MAX)?,
        owner_uid: integer(&p["ownerUid"], 0, 0)? as u32 })
}

fn unicast(value: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = value.parse().map_err(|_| "native egress address invalid")?;
    let selected = match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    require(ip.to_string() == value && !selected.is_unspecified() && !selected.is_multicast()
        && !matches!(selected, IpAddr::V4(value) if value.is_broadcast()))?;
    Ok(ip)
}

fn origin(value: &str) -> Result<(String, u16), String> {
    let parsed = Url::parse(value).map_err(|_| "native egress origin invalid")?;
    require(parsed.scheme() == "https" && parsed.username().is_empty() && parsed.password().is_none()
        && parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none())?;
    let (host, authority) = match parsed.host().ok_or("native egress origin host absent")? {
        Host::Domain(value) => {
            require(!value.is_empty() && value.len() <= 253 && value == value.to_ascii_lowercase()
                && value.split('.').all(|label| !label.is_empty() && label.len() <= 63
                    && !label.starts_with('-') && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')))?;
            (value.to_owned(), value.to_owned())
        }
        Host::Ipv4(value) => (value.to_string(), value.to_string()),
        Host::Ipv6(value) => (value.to_string(), format!("[{value}]")),
    };
    if host.parse::<IpAddr>().is_ok() { unicast(&host)?; }
    let port = parsed.port_or_known_default().ok_or("native egress origin port absent")?;
    let expected = if port == 443 { format!("https://{authority}") }
        else { format!("https://{authority}:{port}") };
    require(port > 0 && expected == value)?;
    Ok((host, port))
}

fn strings(value: &Value, maximum: usize, text_maximum: usize) -> Result<Vec<String>, String> {
    let values = value.as_array().ok_or("native egress string array required")?;
    require(!values.is_empty() && values.len() <= maximum)?;
    let result = values.iter().map(|value| text(value, text_maximum).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    require(result.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes()))?;
    Ok(result)
}

fn proxy(value: &Value, clock: &OriginalClock) -> Result<(Proxy, Vec<Rule>), String> {
    let p = object(value, &["origin", "endpoint", "egressCidrs", "hostAddresses"])?;
    let result = Proxy { origin: text(&p["origin"], 2048)?.to_owned(),
        endpoint: text(&p["endpoint"], 64)?.to_owned(), egress_cidrs: strings(&p["egressCidrs"], 32, 80)?,
        host_addresses: strings(&p["hostAddresses"], 16, 64)? };
    clock.check()?;
    let (host, port) = origin(&result.origin)?;
    require(!result.endpoint.contains('%'))?;
    let endpoint: SocketAddr = result.endpoint.parse().map_err(|_| "native egress endpoint invalid")?;
    require(endpoint.to_string() == result.endpoint && endpoint.port() > 0 && endpoint.port() == port)?;
    let mut networks = Vec::with_capacity(result.egress_cidrs.len());
    for original in &result.egress_cidrs {
        clock.check()?;
        let network: IpNet = original.parse().map_err(|_| "native egress CIDR invalid")?;
        require(network.prefix_len() > 0 && network.addr() == network.network()
            && network.to_string() == *original)?;
        networks.push(network);
    }
    let mut addresses = Vec::with_capacity(result.host_addresses.len());
    for original in &result.host_addresses {
        clock.check()?;
        let address = unicast(original)?;
        require(networks.iter().any(|network| network.contains(&address)))?;
        addresses.push(address);
    }
    require(addresses.contains(&endpoint.ip()))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        require(addresses.len() == 1 && addresses[0] == ip && ip == endpoint.ip())?;
    }
    let mut effective = addresses.into_iter().map(|ip| match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }).collect::<Vec<_>>();
    effective.sort_by(|left, right| match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
    });
    effective.dedup();
    let rules = effective.into_iter().map(|ip| Rule {
        family: if ip.is_ipv4() { "ipv4" } else { "ipv6" }.to_owned(),
        address: ip.to_string(), tcp_destination_port: port, verdict: "accept".to_owned(),
    }).collect();
    clock.check()?;
    Ok((result, rules))
}

fn workload(value: &Value) -> Result<Workload, String> {
    let p = object(value, &["profile", "launchManifestSha256", "launcherBinarySha256",
        "namespaceMode", "beforeCompletion", "failureMode"])?;
    require(p["profile"] == "native-egress-create-new-workload-v1" && p["namespaceMode"] == "create-new"
        && p["beforeCompletion"] == "never-executed" && p["failureMode"] == "terminate-before-start")?;
    digest(&p["launchManifestSha256"])?; digest(&p["launcherBinarySha256"])?;
    Ok(Workload { profile: "native-egress-create-new-workload-v1".to_owned(),
        launch_manifest_sha256: text(&p["launchManifestSha256"], 71)?.to_owned(),
        launcher_binary_sha256: text(&p["launcherBinarySha256"], 71)?.to_owned(),
        namespace_mode: "create-new".to_owned(), before_completion: "never-executed".to_owned(),
        failure_mode: "terminate-before-start".to_owned() })
}

fn ruleset(value: &Value, rules: Vec<Rule>) -> Result<Ruleset, String> {
    let p = object(value, &["profile", "tableName", "family", "chainName", "chainType",
        "hook", "priority", "policy", "rules"])?;
    let table = text(&p["tableName"], 39)?;
    require(table.len() == 39 && table.starts_with("swnegr_")
        && table[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && p["profile"] == "nft-inet-output-tcp-create-v1" && p["family"] == "inet"
        && p["chainName"] == "output" && p["chainType"] == "filter" && p["hook"] == "output"
        && p["priority"].as_i64() == Some(-10) && p["policy"] == "drop")?;
    let originals = p["rules"].as_array().ok_or("native egress rules required")?;
    require(!originals.is_empty() && originals.len() <= 16 && originals.len() == rules.len())?;
    for (original, expected) in originals.iter().zip(&rules) {
        let rule = object(original, &["family", "address", "tcpDestinationPort", "verdict"])?;
        require(rule["family"].as_str() == Some(expected.family.as_str())
            && rule["address"].as_str() == Some(expected.address.as_str())
            && integer(&rule["tcpDestinationPort"], 1, 65535)? == u64::from(expected.tcp_destination_port)
            && rule["verdict"] == "accept")?;
    }
    Ok(Ruleset { profile: "nft-inet-output-tcp-create-v1".to_owned(), table_name: table.to_owned(),
        family: "inet".to_owned(), chain_name: "output".to_owned(), chain_type: "filter".to_owned(),
        hook: "output".to_owned(), priority: -10, policy: "drop".to_owned(), rules })
}

fn capability(value: &Value) -> Result<Capability, String> {
    let p = object(value, &["capabilityId", "capabilityTokenSha256", "expiresAtEpochMs"])?;
    let id = text(&p["capabilityId"], 128)?;
    require(id.len() >= 24 && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))?;
    digest(&p["capabilityTokenSha256"])?;
    Ok(Capability { capability_id: id.to_owned(),
        capability_token_sha256: text(&p["capabilityTokenSha256"], 71)?.to_owned(),
        expires_at_epoch_ms: integer(&p["expiresAtEpochMs"], 1, MAX_EPOCH_MS)? })
}

pub(super) fn admit(raw: &[u8], root_pem: &[u8], root_pem_sha: &str,
    expected_source_revision: &str, clock: &OriginalClock) -> Result<Authorization, String> {
    clock.check()?;
    let (opening_wall, _) = sample()?;
    structure(raw, clock)?;
    let value = json::parse(raw, MAX_BYTES)?;
    require(canonical_ascii_bytes(&value)? == raw)?;
    let outer = object(&value, &["schema", "payload", "signature"])?;
    let schema = match outer["schema"].as_str() {
        Some(ENVELOPE) => SCHEMA,
        Some(CREATION_ENVELOPE) => CREATION_SCHEMA,
        Some(NETWORK_ENVELOPE) => NETWORK_SCHEMA,
        _ => return Err("native egress authorization envelope profile refused".to_owned()),
    };
    let mut fields = vec!["schema", "sourceRevision", "purpose", "trustMode", "authorizationId",
        "setupSha256", "delegationSha256", "targetRequestSha256", "policyRequirementsSha256",
        "releaseRecordSha256", "policyHash", "configurationSha256", "runtimeCaCertificateSha256",
        "runtimeCaSpkiSha256", "ingressLeafCertificateSha256", "clientTrustBundleSha256",
        "clientChallengeSha256", "targetPrincipalId", "targetNonce", "targetSpkiSha256", "proxy",
        "networkOwner", "machineIdSha256", "workload", "ruleset", "capability", "journal",
        "issuedAtEpochNs", "expiresAtEpochNs"];
    if schema != SCHEMA { fields.push("creationJournal"); }
    if schema == NETWORK_SCHEMA { fields.push("childNetworkPolicy"); }
    let p = object(&outer["payload"], &fields)?;
    require(p["schema"] == schema && p["purpose"] == "native-egress-installation"
        && p["trustMode"] == "trusted-host-local"
        && text(&p["sourceRevision"], 128)? == expected_source_revision)?;
    let encoded = text(&outer["signature"], 94)?;
    require(encoded.len() == 94 && encoded.starts_with("ed25519:"))?;
    let signature = URL_SAFE_NO_PAD.decode(&encoded[8..]).map_err(|_| "native egress signature invalid")?;
    require(signature.len() == 64 && format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&signature)) == encoded)?;
    require(!root_pem.is_empty() && root_pem.len() <= MAX_KEY_BYTES)?;
    clock.check()?;
    let (root_key, root_key_id) = native_verifier::installation_authorizer(root_pem, root_pem_sha)?;
    clock.check()?;
    let canonical = canonical_ascii_bytes(&outer["payload"])?;
    let mut signed = Vec::with_capacity(schema.len() + 1 + canonical.len());
    signed.extend_from_slice(schema.as_bytes()); signed.push(0); signed.extend_from_slice(&canonical);
    root_key.verify_strict(&signed, &Signature::from_slice(&signature)
        .map_err(|_| "native egress signature width invalid")?)
        .map_err(|_| "native egress signature refused")?;
    clock.check()?;
    let principal = p["targetPrincipalId"].as_str().ok_or("native egress target principal absent")?;
    require(!principal.is_empty() && principal.len() <= 1024)?;
    let nonce = text(&p["targetNonce"], 256)?;
    require(nonce.len() >= 32 && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))?;
    let (proxy, rules) = proxy(&p["proxy"], clock)?;
    let ruleset = ruleset(&p["ruleset"], rules)?;
    let capability = capability(&p["capability"])?;
    let kernel_journal = journal(&p["journal"])?;
    let creation_journal = if schema != SCHEMA {
        let creation = journal(&p["creationJournal"])?;
        require(creation.path != kernel_journal.path
            && (creation.device, creation.inode) != (kernel_journal.device, kernel_journal.inode)
            && creation.namespace != kernel_journal.namespace)?;
        Some(creation)
    } else { None };
    let child_network_policy = if schema == NETWORK_SCHEMA {
        require(p["childNetworkPolicy"] == "manual-dual-stack-no-autoconfiguration-v1")?;
        Some(ChildNetworkPolicy::ManualDualStackV1)
    } else { None };
    let issued = integer(&p["issuedAtEpochNs"], 1, i64::MAX as u64)?;
    let expires = integer(&p["expiresAtEpochNs"], 1, i64::MAX as u64)?;
    require(issued <= opening_wall && opening_wall < expires && expires > issued
        && expires - issued <= 300_000_000_000 && expires <= capability.expires_at_epoch_ms * 1_000_000)?;
    let result = Authorization { root_key_id, original_sha256: Sha256::digest(raw).into(),
        authorization_id: identifier(&p["authorizationId"])?, setup_sha256: digest(&p["setupSha256"])?,
        delegation_sha256: digest(&p["delegationSha256"])?, target_request_sha256: digest(&p["targetRequestSha256"])?,
        policy_requirements_sha256: digest(&p["policyRequirementsSha256"])?,
        release_record_sha256: digest(&p["releaseRecordSha256"])?, policy_hash: digest(&p["policyHash"])?,
        configuration_sha256: digest(&p["configurationSha256"])?,
        runtime_ca_certificate_sha256: digest(&p["runtimeCaCertificateSha256"])?,
        runtime_ca_spki_sha256: digest(&p["runtimeCaSpkiSha256"])?,
        ingress_leaf_certificate_sha256: digest(&p["ingressLeafCertificateSha256"])?,
        client_trust_bundle_sha256: digest(&p["clientTrustBundleSha256"])?,
        client_challenge_sha256: digest(&p["clientChallengeSha256"])?, target_spki_sha256: digest(&p["targetSpkiSha256"])?,
        machine_id_sha256: digest(&p["machineIdSha256"])?, target_principal_id: principal.to_owned(),
        target_nonce: nonce.to_owned(), proxy, network_owner: network_owner(&p["networkOwner"])?,
        workload: workload(&p["workload"])?, ruleset, capability, journal: kernel_journal,
        creation_journal, child_network_policy,
        issued_at_epoch_ns: issued, expires_at_epoch_ns: expires };
    clock.restrict_until_epoch_ns(expires)?;
    let (closing_wall, _) = sample()?;
    require(closing_wall >= opening_wall && issued <= closing_wall && closing_wall < expires)?;
    clock.check()?;
    Ok(result)
}
