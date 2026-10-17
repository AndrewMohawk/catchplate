//! Original-only signed static attachment constraints, not host/effect proof.

use super::authority::{Capability, Journal, NetworkOwner};
use super::super::{json, native_verifier, sample, OriginalClock};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signature;
use serde::Serialize;
use serde_json::{Map, Value};
use catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;

const MAX_BYTES: usize = 32 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const SCHEMA: &str = "catchplate.nativeNetworkAttachmentAuthorization/v1";
const ENVELOPE: &str = "catchplate.signedNativeNetworkAttachmentAuthorization/v1";
const PROFILE: &str = "rtnetlink-veth-bridge-static-v1";
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;

#[derive(Serialize)]
pub(super) struct Lock {
    pub(super) path: String,
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Bridge {
    pub(super) name: String,
    pub(super) ifindex: u32,
    pub(super) mac_address: String,
    pub(super) mtu: u32,
    pub(super) kind: String,
    pub(super) lock: Lock,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Address {
    pub(super) family: String,
    pub(super) address: String,
    pub(super) prefix_length: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Route {
    pub(super) family: String,
    pub(super) destination: String,
    pub(super) gateway: String,
    pub(super) gateway_mac_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Attachment {
    pub(super) profile: String,
    pub(super) host_veth_name: String,
    pub(super) child_veth_name: String,
    pub(super) mtu: u32,
    pub(super) host_mac_address: String,
    pub(super) child_mac_address: String,
    pub(super) addresses: Vec<Address>,
    pub(super) routes: Vec<Route>,
}

/// Signed constraints only. No Clone, Debug, serialization or DTO constructor.
/// The actual parent joins independently authenticated originals and owners.
pub(super) struct Authorization {
    pub(super) root_key_id: [u8; 32],
    pub(super) original_sha256: [u8; 32],
    pub(super) authorization_id: String,
    pub(super) egress_authorization_sha256: [u8; 32],
    pub(super) launch_manifest_sha256: [u8; 32],
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
    pub(super) network_owner: NetworkOwner,
    pub(super) bridge: Bridge,
    pub(super) attachment: Attachment,
    pub(super) capability: Capability,
    pub(super) journal: Journal,
    pub(super) issued_at_epoch_ns: u64,
    pub(super) expires_at_epoch_ns: u64,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native network attachment authorization refused".to_owned()) }
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
    let result = value.as_object().ok_or("attachment authorization object required")?;
    require(result.len() == fields.len() && fields.iter().all(|field| result.contains_key(*field)))?;
    Ok(result)
}

fn text(value: &Value, maximum: usize) -> Result<&str, String> {
    let value = value.as_str().ok_or("attachment authorization string required")?;
    require(!value.is_empty() && value.len() <= maximum
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b)))?;
    Ok(value)
}

fn integer(value: &Value, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = value.as_u64().ok_or("attachment authorization integer required")?;
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
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[7 + index * 2..9 + index * 2], 16)
            .map_err(|_| "attachment authorization digest invalid")?;
    }
    require(result != [0; 32])?;
    Ok(result)
}

fn path(value: &Value) -> Result<String, String> {
    let value = text(value, 4096)?;
    require(value.len() > 1 && value.starts_with('/') && !value.contains('\\'))?;
    for (index, component) in value[1..].split('/').enumerate() {
        require(index < 64 && component.len() <= 255 && !matches!(component, "" | "." | ".."))?;
    }
    Ok(value.to_owned())
}

fn interface(value: &Value) -> Result<String, String> {
    let value = text(value, 15)?;
    require(value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')))?;
    Ok(value.to_owned())
}

fn mac(value: &Value) -> Result<String, String> {
    let value = text(value, 17)?;
    require(value.len() == 17 && value.bytes().enumerate().all(|(index, byte)| {
        if index % 3 == 2 { byte == b':' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    }))?;
    let mut raw = [0u8; 6];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 3..index * 3 + 2], 16)
            .map_err(|_| "attachment MAC invalid")?;
    }
    require(raw != [0; 6] && raw[0] & 1 == 0)?;
    Ok(value.to_owned())
}

fn ip(value: &Value) -> Result<IpAddr, String> {
    let value = text(value, 45)?;
    let address: IpAddr = value.parse().map_err(|_| "attachment IP address invalid")?;
    require(address.to_string() == value && !address.is_unspecified() && !address.is_multicast()
        && !matches!(address, IpAddr::V4(value) if value.is_broadcast())
        && !matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some()))?;
    Ok(address)
}

fn family(address: IpAddr) -> &'static str { if address.is_ipv4() { "ipv4" } else { "ipv6" } }

fn ip_key(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(address) => {
            let mut packed = [0u8; 16];
            packed[..4].copy_from_slice(&address.octets());
            (4, packed)
        }
        IpAddr::V6(address) => (6, address.octets()),
    }
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

fn journal(value: &Value) -> Result<Journal, String> {
    let p = object(value, &["path", "device", "inode", "namespace"])?;
    Ok(Journal { path: path(&p["path"])?, device: integer(&p["device"], 1, i64::MAX as u64)?,
        inode: integer(&p["inode"], 1, i64::MAX as u64)?, namespace: identifier(&p["namespace"])? })
}

fn capability(value: &Value) -> Result<Capability, String> {
    let p = object(value, &["capabilityId", "capabilityTokenSha256", "expiresAtEpochMs"])?;
    let id = text(&p["capabilityId"], 128)?;
    require(id.len() >= 24 && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))?;
    digest(&p["capabilityTokenSha256"])?;
    Ok(Capability { capability_id: id.to_owned(), capability_token_sha256: text(&p["capabilityTokenSha256"], 71)?.to_owned(),
        expires_at_epoch_ms: integer(&p["expiresAtEpochMs"], 1, MAX_EPOCH_MS)? })
}

fn plan(bridge: &Value, attachment: &Value, clock: &OriginalClock) -> Result<(Bridge, Attachment), String> {
    let b = object(bridge, &["name", "ifindex", "macAddress", "mtu", "kind", "lock"])?;
    require(b["kind"] == "bridge")?;
    let lock = object(&b["lock"], &["path", "device", "inode"])?;
    let bridge = Bridge { name: interface(&b["name"])?, ifindex: integer(&b["ifindex"], 1, i32::MAX as u64)? as u32,
        mac_address: mac(&b["macAddress"])?, mtu: integer(&b["mtu"], 1280, 65535)? as u32,
        kind: "bridge".to_owned(), lock: Lock { path: path(&lock["path"])?,
            device: integer(&lock["device"], 1, i64::MAX as u64)?, inode: integer(&lock["inode"], 1, i64::MAX as u64)? } };
    let p = object(attachment, &["profile", "hostVethName", "childVethName", "mtu",
        "hostMacAddress", "childMacAddress", "addresses", "routes"])?;
    require(p["profile"] == PROFILE)?;
    let host_name = interface(&p["hostVethName"])?;
    let child_name = interface(&p["childVethName"])?;
    require(host_name != child_name && host_name != bridge.name && child_name != bridge.name)?;
    let host_mac = mac(&p["hostMacAddress"])?;
    let child_mac = mac(&p["childMacAddress"])?;
    require(host_mac != child_mac && host_mac != bridge.mac_address && child_mac != bridge.mac_address)?;
    let mtu = integer(&p["mtu"], 1280, u64::from(bridge.mtu))? as u32;
    let address_values = p["addresses"].as_array().ok_or("attachment addresses must be an array")?;
    require((1..=2).contains(&address_values.len()))?;
    let mut addresses = Vec::with_capacity(address_values.len());
    let mut selected = BTreeMap::new();
    let mut previous = None;
    for value in address_values {
        clock.check()?;
        let a = object(value, &["family", "address", "prefixLength"])?;
        let address = ip(&a["address"])?;
        let name = family(address);
        let width = if address.is_ipv4() { 32 } else { 128 };
        let key = ip_key(address);
        require(a["family"] == name && previous.is_none_or(|old| old < key)
            && !selected.contains_key(name))?;
        let prefix = integer(&a["prefixLength"], width, width)? as u8;
        selected.insert(name, address);
        previous = Some(key);
        addresses.push(Address { family: name.to_owned(), address: address.to_string(), prefix_length: prefix });
    }
    let route_values = p["routes"].as_array().ok_or("attachment routes must be an array")?;
    require((1..=16).contains(&route_values.len()))?;
    let mut routes = Vec::with_capacity(route_values.len());
    let mut previous = None;
    let mut used = BTreeMap::new();
    for value in route_values {
        clock.check()?;
        let r = object(value, &["family", "destination", "gateway", "gatewayMacAddress"])?;
        let destination = ip(&r["destination"])?;
        let gateway = ip(&r["gateway"])?;
        let key = ip_key(destination);
        let name = family(destination);
        let child = selected.get(name).ok_or("attachment route has no selected address")?;
        require(r["family"] == name && family(gateway) == name
            && *child != destination && *child != gateway
            && previous.is_none_or(|old| old < key)
            && r["gatewayMacAddress"].as_str() == Some(bridge.mac_address.as_str()))?;
        previous = Some(key);
        used.insert(name, ());
        routes.push(Route { family: name.to_owned(), destination: destination.to_string(),
            gateway: gateway.to_string(), gateway_mac_address: bridge.mac_address.clone() });
    }
    require(used.len() == selected.len())?;
    clock.check()?;
    Ok((bridge, Attachment { profile: PROFILE.to_owned(), host_veth_name: host_name,
        child_veth_name: child_name, mtu, host_mac_address: host_mac, child_mac_address: child_mac,
        addresses, routes }))
}

pub(super) fn admit(raw: &[u8], root_pem: &[u8], root_pem_sha: &str,
    expected_source_revision: &str, clock: &OriginalClock) -> Result<Authorization, String> {
    clock.check()?;
    let (opening_wall, _) = sample()?;
    structure(raw, clock)?;
    let value = json::parse(raw, MAX_BYTES)?;
    require(canonical_ascii_bytes(&value)? == raw)?;
    let outer = object(&value, &["schema", "payload", "signature"])?;
    require(outer["schema"] == ENVELOPE)?;
    let p = object(&outer["payload"], &["schema", "sourceRevision", "purpose", "trustMode", "authorizationId",
        "egressAuthorizationSha256", "launchManifestSha256", "setupSha256", "delegationSha256",
        "targetRequestSha256", "policyRequirementsSha256", "releaseRecordSha256", "policyHash",
        "configurationSha256", "runtimeCaCertificateSha256", "runtimeCaSpkiSha256",
        "ingressLeafCertificateSha256", "clientTrustBundleSha256", "clientChallengeSha256",
        "targetSpkiSha256", "machineIdSha256", "targetPrincipalId", "targetNonce", "networkOwner",
        "bridge", "attachment", "capability", "journal", "issuedAtEpochNs", "expiresAtEpochNs"])?;
    require(p["schema"] == SCHEMA && p["purpose"] == "native-network-attachment"
        && p["trustMode"] == "trusted-host-local" && text(&p["sourceRevision"], 128)? == expected_source_revision)?;
    let encoded = text(&outer["signature"], 94)?;
    require(encoded.len() == 94 && encoded.starts_with("ed25519:"))?;
    let signature = URL_SAFE_NO_PAD.decode(&encoded[8..]).map_err(|_| "attachment signature invalid")?;
    require(signature.len() == 64 && format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&signature)) == encoded)?;
    require(!root_pem.is_empty() && root_pem.len() <= MAX_KEY_BYTES)?;
    clock.check()?;
    let (root_key, root_key_id) = native_verifier::installation_authorizer(root_pem, root_pem_sha)?;
    clock.check()?;
    let canonical = canonical_ascii_bytes(&outer["payload"])?;
    let mut signed = Vec::with_capacity(SCHEMA.len() + 1 + canonical.len());
    signed.extend_from_slice(SCHEMA.as_bytes()); signed.push(0); signed.extend_from_slice(&canonical);
    root_key.verify_strict(&signed, &Signature::from_slice(&signature)
        .map_err(|_| "attachment signature width invalid")?)
        .map_err(|_| "attachment signature refused")?;
    clock.check()?;
    let principal = p["targetPrincipalId"].as_str().ok_or("attachment target principal absent")?;
    require(!principal.is_empty() && principal.len() <= 1024)?;
    let nonce = text(&p["targetNonce"], 256)?;
    require(nonce.len() >= 32 && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))?;
    let (bridge, attachment) = plan(&p["bridge"], &p["attachment"], clock)?;
    let capability = capability(&p["capability"])?;
    let journal = journal(&p["journal"])?;
    require(bridge.lock.path != journal.path
        && (bridge.lock.device, bridge.lock.inode) != (journal.device, journal.inode))?;
    let issued = integer(&p["issuedAtEpochNs"], 1, i64::MAX as u64)?;
    let expires = integer(&p["expiresAtEpochNs"], 1, i64::MAX as u64)?;
    require(issued <= opening_wall && opening_wall < expires && expires > issued
        && expires - issued <= 300_000_000_000 && expires <= capability.expires_at_epoch_ms * 1_000_000)?;
    let result = Authorization { root_key_id, original_sha256: Sha256::digest(raw).into(),
        authorization_id: identifier(&p["authorizationId"])?,
        egress_authorization_sha256: digest(&p["egressAuthorizationSha256"])?,
        launch_manifest_sha256: digest(&p["launchManifestSha256"])?,
        setup_sha256: digest(&p["setupSha256"])?, delegation_sha256: digest(&p["delegationSha256"])?,
        target_request_sha256: digest(&p["targetRequestSha256"])?,
        policy_requirements_sha256: digest(&p["policyRequirementsSha256"])?,
        release_record_sha256: digest(&p["releaseRecordSha256"])?, policy_hash: digest(&p["policyHash"])?,
        configuration_sha256: digest(&p["configurationSha256"])?,
        runtime_ca_certificate_sha256: digest(&p["runtimeCaCertificateSha256"])?,
        runtime_ca_spki_sha256: digest(&p["runtimeCaSpkiSha256"])?,
        ingress_leaf_certificate_sha256: digest(&p["ingressLeafCertificateSha256"])?,
        client_trust_bundle_sha256: digest(&p["clientTrustBundleSha256"])?,
        client_challenge_sha256: digest(&p["clientChallengeSha256"])?,
        target_spki_sha256: digest(&p["targetSpkiSha256"])?, machine_id_sha256: digest(&p["machineIdSha256"])?,
        target_principal_id: principal.to_owned(), target_nonce: nonce.to_owned(),
        network_owner: network_owner(&p["networkOwner"])?, bridge, attachment, capability, journal,
        issued_at_epoch_ns: issued, expires_at_epoch_ns: expires };
    clock.restrict_until_epoch_ns(expires)?;
    let (closing_wall, _) = sample()?;
    require(closing_wall >= opening_wall && issued <= closing_wall && closing_wall < expires)?;
    clock.check()?;
    Ok(result)
}
