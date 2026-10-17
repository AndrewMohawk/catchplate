//! Closed, independently pinned input data, never execution permission.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes;

pub(super) const MAX_MANIFEST: usize = 32 * 1024;
pub(super) const MAX_EXECUTABLE: u64 = 16 * 1024 * 1024;
pub(super) const MAX_IMAGE: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Rootfs {
    pub(super) profile: String,
    pub(super) mount_path: String,
    pub(super) block_device_path: String,
    pub(super) image_path: String,
    pub(super) image_fs_verity_sha256: String,
    pub(super) loop_offset: u64,
    pub(super) loop_size_limit: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Interpreter {
    pub(super) path: String,
    pub(super) sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) path: String,
    pub(super) sha256: String,
    // Explicit null is required for a static ELF; canonical typed readback
    // below also refuses an omitted Option field.
    pub(super) interpreter: Option<Interpreter>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApplicationTrust {
    pub(super) profile: String,
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) certificate_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) api_version: String,
    pub(super) profile: String,
    pub(super) rootfs: Rootfs,
    pub(super) entry: Entry,
    pub(super) argv: Vec<String>,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) cwd: String,
    pub(super) loader_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) application_trust: Option<ApplicationTrust>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) application_proxy: Option<super::application_proxy::Settings>,
}

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native execution manifest profile mismatch".to_owned()) }
}

pub(super) fn digest(value: &str) -> Result<[u8; 32], String> {
    require(value.len() == 71 && value.starts_with("sha256:"))?;
    let mut result = [0u8; 32];
    for (index, pair) in value.as_bytes()[7..].chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'), b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("native execution digest is not canonical lowercase SHA-256".to_owned()),
        };
        result[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    require(result.iter().any(|byte| *byte != 0))?;
    Ok(result)
}

pub(super) fn path(value: &str, allow_root: bool) -> Result<(), String> {
    require(!value.is_empty() && value.len() <= 4096 && value.starts_with('/')
        && value.bytes().all(|byte| (33..=126).contains(&byte) && byte != b'\\'))?;
    if value == "/" { return require(allow_root); }
    let components = value[1..].split('/').collect::<Vec<_>>();
    require(components.len() <= 64 && components.iter().all(|part|
        !part.is_empty() && *part != "." && *part != ".." && part.len() <= 255))
}

pub(super) fn decode(raw: &[u8], combined_trust: bool, application: bool) -> Result<Manifest, String> {
    require(!raw.is_empty() && raw.len() <= MAX_MANIFEST && raw.is_ascii())?;
    let value = super::super::json::parse(raw, MAX_MANIFEST)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|_| "native execution manifest fields are invalid")?;
    require(canonical_ascii_bytes(&manifest)?.as_slice() == raw)?;
    require(manifest.api_version == (if application { "catchplate.nativeExecutionManifest/v3" }
            else if combined_trust { "catchplate.nativeExecutionManifest/v2" }
            else { "catchplate.nativeExecutionManifest/v1" })
        && manifest.profile == "native-elf-erofs-v1"
        && manifest.loader_policy == "in-image-system-loader-v1"
        && manifest.rootfs.profile == "single-device-erofs-loop-fsverity-v1"
        && manifest.rootfs.loop_offset == 0 && manifest.rootfs.loop_size_limit == 0)?;
    for host_path in [&manifest.rootfs.mount_path, &manifest.rootfs.block_device_path,
        &manifest.rootfs.image_path] { path(host_path, false)?; }
    require(manifest.rootfs.mount_path != manifest.rootfs.block_device_path
        && manifest.rootfs.mount_path != manifest.rootfs.image_path
        && manifest.rootfs.block_device_path != manifest.rootfs.image_path)?;
    digest(&manifest.rootfs.image_fs_verity_sha256)?;
    path(&manifest.entry.path, false)?;
    digest(&manifest.entry.sha256)?;
    if let Some(interpreter) = &manifest.entry.interpreter {
        path(&interpreter.path, false)?;
        digest(&interpreter.sha256)?;
        require(interpreter.path != manifest.entry.path)?;
    }
    path(&manifest.cwd, true)?;
    require(!manifest.argv.is_empty() && manifest.argv.len() <= 64
        && manifest.argv[0] == manifest.entry.path && manifest.environment.len() <= 64)?;
    let mut total = 0usize;
    for argument in &manifest.argv {
        require(argument.len() <= 4096 && !argument.as_bytes().contains(&0))?;
        total = total.checked_add(argument.len() + 1).ok_or("native argument size overflow")?;
    }
    for (key, value) in &manifest.environment {
        require(!key.is_empty() && key.len() <= 128
            && key.bytes().enumerate().all(|(index, byte)|
                byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit())
            && !key.starts_with("LD_") && key != "GLIBC_TUNABLES"
            && value.len() <= 4096 && !value.as_bytes().contains(&0))?;
        total = total.checked_add(key.len() + value.len() + 2)
            .ok_or("native environment size overflow")?;
    }
    require(total <= 16 * 1024)?;
    require(manifest.application_trust.is_some() == combined_trust)?;
    require(manifest.application_proxy.is_some() == application && (!application || combined_trust))?;
    if let Some(proxy) = &manifest.application_proxy {
        proxy.validate()?;
        require(manifest.environment.get("HTTPS_PROXY") == Some(&format!("http://127.0.0.1:{}",proxy.listener_port))
            && !manifest.environment.keys().any(|key| key != "HTTPS_PROXY" &&
                matches!(key.to_ascii_uppercase().as_str(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"))
            && !manifest.environment.keys().any(|key|
                matches!(key.to_ascii_uppercase().as_str(),"SSL_CERT_DIR"|"CURL_CA_BUNDLE"|"REQUESTS_CA_BUNDLE"|"NODE_EXTRA_CA_CERTS"|"PYTHONHTTPSVERIFY")
                || key.eq_ignore_ascii_case("SSL_CERT_FILE") && key!="SSL_CERT_FILE"))?;
    }
    if let Some(trust) = &manifest.application_trust {
        require(trust.profile == "in-image-runtime-ca-pem-v1")?;
        path(&trust.path, false)?;
        digest(&trust.sha256)?;
        digest(&trust.certificate_sha256)?;
        require(manifest.environment.get("SSL_CERT_FILE") == Some(&trust.path)
            && trust.path != manifest.entry.path
            && manifest.entry.interpreter.as_ref().map_or(true, |entry| entry.path != trust.path))?;
    }
    Ok(manifest)
}
