//! Independent original installation grant, not native evidence or host proof.

use super::super::{json, native_verifier, sample, OriginalClock};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signature;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_BYTES: usize = 32 * 1024;
const SCHEMA: &str = "serverware.nativeCaInstallationAuthorization/v1";
const ENVELOPE: &str = "serverware.signedNativeCaInstallationAuthorization/v1";
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CaInstall {
    pub(super) profile: String,
    pub(super) capability_id: String,
    pub(super) capability_token_sha256: String,
    pub(super) expires_at_epoch_ms: u64,
    pub(super) destination_path: String,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
    pub(super) file_mode: u32,
    pub(super) replace_existing: bool,
    pub(super) expected_existing_certificate_sha256: Option<String>,
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
pub(super) struct Journal {
    pub(super) path: String,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) namespace: String,
}

// Only admit constructs this type. Parsed signed constraints are not proof of
// capability possession, reservation, host observation, or native setup trust.
pub(super) struct Authorization {
    pub(super) root_key_id: [u8; 32],
    pub(super) original_sha256: [u8; 32],
    pub(super) authorization_id: String,
    pub(super) setup_sha256: [u8; 32],
    pub(super) delegation_sha256: [u8; 32],
    pub(super) target_request_sha256: [u8; 32],
    pub(super) runtime_ca_certificate_sha256: [u8; 32],
    pub(super) runtime_ca_spki_sha256: [u8; 32],
    pub(super) machine_id_sha256: [u8; 32],
    pub(super) ca_install: CaInstall,
    pub(super) network_owner: NetworkOwner,
    pub(super) journal: Journal,
    pub(super) issued_at_epoch_ns: u64,
    pub(super) expires_at_epoch_ns: u64,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native installation authorization refused".to_owned()) }
}

fn structure(raw: &[u8], clock: &OriginalClock) -> Result<(), String> {
    require(!raw.is_empty() && raw.len() <= MAX_BYTES && raw.is_ascii())?;
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for (index, byte) in raw.iter().copied().enumerate() {
        if index % 1024 == 0 { clock.check()?; }
        require(byte >= 0x20)?; // Canonical envelope has no LF or other raw controls.
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' => { depth += 1; require(depth <= 3)?; }
                b'}' => { require(depth > 0)?; depth -= 1; }
                b'[' | b']' => return Err("native installation authorization arrays refused".to_owned()),
                _ => {}
            }
        }
    }
    require(depth == 0 && !quoted && !escaped)?;
    clock.check()
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let result = value.as_object().ok_or("native installation authorization object required")?;
    require(result.len() == fields.len() && fields.iter().all(|field| result.contains_key(*field)))?;
    Ok(result)
}

fn text(value: &Value, maximum: usize) -> Result<&str, String> {
    let value = value.as_str().ok_or("native installation authorization string required")?;
    require(!value.is_empty() && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))?;
    Ok(value)
}

fn integer(value: &Value, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = value.as_u64().ok_or("native installation authorization integer required")?;
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
        *byte = u8::from_str_radix(&value[7 + 2 * index..9 + 2 * index], 16)
            .map_err(|_| "native installation authorization digest invalid")?;
    }
    require(result.iter().any(|byte| *byte != 0))?;
    Ok(result)
}

fn path(value: &Value, journal: bool) -> Result<String, String> {
    let value = text(value, 4096)?;
    require(value.len() > 1 && value.starts_with('/') && !value.contains('\\'))?;
    let mut count = 0;
    for component in value[1..].split('/') {
        count += 1;
        require(!matches!(component, "" | "." | "..")
            && (!journal || component.len() <= 255 && count <= 64))?;
    }
    Ok(value.to_owned())
}

fn ca_install(value: &Value) -> Result<CaInstall, String> {
    let p = object(value, &["profile", "capabilityId", "capabilityTokenSha256", "expiresAtEpochMs",
        "destinationPath", "ownerUid", "ownerGid", "fileMode", "replaceExisting",
        "expectedExistingCertificateSha256"])?;
    require(p["profile"] == "native-ca-install-association-v1")?;
    let capability = text(&p["capabilityId"], 128)?;
    require(capability.len() >= 24 && capability.bytes().all(|b| b.is_ascii_alphanumeric()
        || matches!(b, b'_' | b'-')))?;
    digest(&p["capabilityTokenSha256"])?;
    let replace = p["replaceExisting"].as_bool().ok_or("native installation rotation bool required")?;
    let existing = if replace {
        digest(&p["expectedExistingCertificateSha256"])?;
        Some(text(&p["expectedExistingCertificateSha256"], 71)?.to_owned())
    } else {
        require(p["expectedExistingCertificateSha256"].is_null())?;
        None
    };
    Ok(CaInstall {
        profile: "native-ca-install-association-v1".to_owned(), capability_id: capability.to_owned(),
        capability_token_sha256: text(&p["capabilityTokenSha256"], 71)?.to_owned(),
        expires_at_epoch_ms: integer(&p["expiresAtEpochMs"], 1, MAX_EPOCH_MS)?,
        destination_path: path(&p["destinationPath"], false)?,
        owner_uid: integer(&p["ownerUid"], 0, u32::MAX as u64 - 1)? as u32,
        owner_gid: integer(&p["ownerGid"], 0, u32::MAX as u64 - 1)? as u32,
        file_mode: integer(&p["fileMode"], 420, 420)? as u32,
        replace_existing: replace, expected_existing_certificate_sha256: existing,
    })
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

pub(super) fn admit(raw: &[u8], root_pem: &[u8], root_pem_sha: &str,
    expected_source_revision: &str, clock: &OriginalClock) -> Result<Authorization, String>
{
    clock.check()?;
    let (opening_wall, _) = sample()?;
    structure(raw, clock)?;
    let value = json::parse(raw, MAX_BYTES)?;
    require(serde_json::to_vec(&value).map_err(|_| "encode native installation authorization")? == raw)?;
    let outer = object(&value, &["schema", "payload", "signature"])?;
    require(outer["schema"] == ENVELOPE)?;
    let p = object(&outer["payload"], &["schema", "sourceRevision", "purpose", "trustMode",
        "authorizationId", "setupSha256", "delegationSha256", "targetRequestSha256",
        "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "caInstall", "networkOwner",
        "machineIdSha256", "journal", "issuedAtEpochNs", "expiresAtEpochNs"])?;
    require(p["schema"] == SCHEMA && p["purpose"] == "native-ca-installation"
        && p["trustMode"] == "trusted-host-local"
        && text(&p["sourceRevision"], 128)? == expected_source_revision)?;
    let signature = text(&outer["signature"], 94)?;
    require(signature.len() == 94 && signature.starts_with("ed25519:"))?;
    let signature = URL_SAFE_NO_PAD.decode(&signature[8..])
        .map_err(|_| "decode native installation signature")?;
    require(signature.len() == 64 && format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&signature))
        == outer["signature"].as_str().ok_or("native installation signature required")?)?;
    clock.check()?;
    let (root_key, root_key_id) = native_verifier::installation_authorizer(root_pem, root_pem_sha)?;
    clock.check()?;
    let canonical = serde_json::to_vec(&outer["payload"])
        .map_err(|_| "encode native installation signed payload")?;
    let mut signed = Vec::with_capacity(SCHEMA.len() + 1 + canonical.len());
    signed.extend_from_slice(SCHEMA.as_bytes()); signed.push(0); signed.extend_from_slice(&canonical);
    root_key.verify_strict(&signed, &Signature::from_slice(&signature)
        .map_err(|_| "native installation signature width invalid")?)
        .map_err(|_| "native installation signature refused")?;
    clock.check()?;
    let ca_install = ca_install(&p["caInstall"])?;
    let network_owner = network_owner(&p["networkOwner"])?;
    let journal = object(&p["journal"], &["path", "device", "inode", "namespace"])?;
    let journal = Journal { path: path(&journal["path"], true)?,
        device: integer(&journal["device"], 1, i64::MAX as u64)?,
        inode: integer(&journal["inode"], 1, i64::MAX as u64)?,
        namespace: identifier(&journal["namespace"])? };
    let issued = integer(&p["issuedAtEpochNs"], 1, i64::MAX as u64)?;
    let expires = integer(&p["expiresAtEpochNs"], 1, i64::MAX as u64)?;
    require(issued <= opening_wall && opening_wall < expires && expires > issued
        && expires - issued <= 300_000_000_000
        && expires <= ca_install.expires_at_epoch_ms * 1_000_000)?;
    let result = Authorization { root_key_id, original_sha256: Sha256::digest(raw).into(),
        authorization_id: identifier(&p["authorizationId"])?,
        setup_sha256: digest(&p["setupSha256"])?, delegation_sha256: digest(&p["delegationSha256"])?,
        target_request_sha256: digest(&p["targetRequestSha256"])?,
        runtime_ca_certificate_sha256: digest(&p["runtimeCaCertificateSha256"])?,
        runtime_ca_spki_sha256: digest(&p["runtimeCaSpkiSha256"])?,
        machine_id_sha256: digest(&p["machineIdSha256"])?, ca_install, network_owner, journal,
        issued_at_epoch_ns: issued, expires_at_epoch_ns: expires };
    clock.restrict_until_epoch_ns(expires)?;
    let (closing_wall, _) = sample()?;
    require(closing_wall >= opening_wall && issued <= closing_wall && closing_wall < expires)?;
    clock.check()?;
    Ok(result)
}
