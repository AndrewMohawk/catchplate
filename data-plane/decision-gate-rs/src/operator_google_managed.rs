//! Cold, public-only projection of committed managed Google configuration.
//! The original publication SH permit owns this read. No database, client
//! secret, custody key, provider request or runtime environment mutation occurs.
use super::{
    digest_json_ensure_ascii, operator_audit_publication::Permit, operator_demo::Deployment,
    operator_google_profile, strict_json_value_from_slice,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const FLAG: &str = "CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED";
const PATH: &str = "/data/operator-google-configuration.json";
const SCHEMA: &str = "catchplate.operatorGoogleGateConfiguration/v1";
const MAX_BYTES: u64 = 32_768;
const MAX_VERSIONS: u64 = 16; // operator_provider_custody.MAX_VERSIONS

fn refused() -> String {
    "operator managed Google public configuration refused".to_owned()
}

fn selected(flag: Option<&str>, operator: bool, external_google: bool) -> Result<bool, String> {
    match flag {
        None | Some("0") => Ok(false),
        Some("1") if operator && !external_google => Ok(true),
        _ => Err(refused()),
    }
}

fn external_google_key(name: &str) -> bool {
    name.starts_with("CATCHPLATE_GOOGLE_") || name == "CATCHPLATE_OPERATOR_GOOGLE_PROFILE"
}

pub(super) fn from_environment(operator: bool) -> Result<bool, String> {
    let raw = env::var_os(FLAG);
    let flag = raw
        .as_ref()
        .map(|value| value.to_str().ok_or_else(refused))
        .transpose()?;
    // Ownership namespaces are exclusive by presence, including empty values.
    let external_google =
        env::vars_os().any(|(name, _)| external_google_key(&name.to_string_lossy()));
    selected(flag, operator, external_google)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    operation_id: String,
    owner_id: String,
    config_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    operation: Option<Operation>,
    profile_binding: Option<Value>,
    profile_binding_digest: Option<String>,
    effective_settings: Value,
    effective_settings_digest: String,
}

pub(super) struct Identity {
    operation: Option<Operation>,
    profile_binding_digest: Option<String>,
    effective_settings_digest: String,
}

impl Identity {
    pub(super) fn status(&self) -> Value {
        json!({"operation":self.operation, "profile_binding_digest":self.profile_binding_digest,
            "effective_settings_digest":self.effective_settings_digest})
    }
}

pub(super) struct Configuration {
    pub(super) deployment: Deployment,
    pub(super) google: Option<operator_google_profile::Profile>,
    pub(super) identity: Identity,
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub(super) fn parse(bytes: &[u8]) -> Result<Configuration, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
        return Err(refused());
    }
    let value = strict_json_value_from_slice(bytes).map_err(|_| refused())?;
    // Option fields must be explicitly present: missing is not disabled state.
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != 6
        || [
            "schema",
            "operation",
            "profile_binding",
            "profile_binding_digest",
            "effective_settings",
            "effective_settings_digest",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
    {
        return Err(refused());
    }
    let manifest: Manifest = serde_json::from_value(value).map_err(|_| refused())?;
    if manifest.schema != SCHEMA
        || digest_json_ensure_ascii(&manifest.effective_settings)
            != manifest.effective_settings_digest
    {
        return Err(refused());
    }
    let deployment = Deployment::managed(&manifest.effective_settings).map_err(|_| refused())?;
    let google = match (
        &manifest.operation,
        &manifest.profile_binding,
        &manifest.profile_binding_digest,
    ) {
        (None, None, None) => None,
        (Some(operation), Some(binding), Some(digest)) => {
            if !canonical_uuid(&operation.operation_id)
                || !canonical_uuid(&operation.owner_id)
                || !(1..=MAX_VERSIONS).contains(&operation.config_version)
            {
                return Err(refused());
            }
            let profile = operator_google_profile::Profile::parse(
                Some(operator_google_profile::CAPABILITY),
                true,
                binding.get("client_id").and_then(Value::as_str),
                binding.get("redirect_uri").and_then(Value::as_str),
            )
            .map_err(|_| refused())?
            .ok_or_else(refused)?;
            // Reconstruct the existing CLOSED fixed-endpoint/scopes profile;
            // extra or changed public fields cannot acquire a new digest authority.
            if digest_json_ensure_ascii(binding) != *digest || profile.binding_digest() != digest {
                return Err(refused());
            }
            Some(profile)
        }
        _ => return Err(refused()),
    };
    deployment
        .require_google(google.is_some())
        .map_err(|_| refused())?;
    Ok(Configuration {
        deployment,
        google,
        identity: Identity {
            operation: manifest.operation,
            profile_binding_digest: manifest.profile_binding_digest,
            effective_settings_digest: manifest.effective_settings_digest,
        },
    })
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn file_identity(info: &Metadata) -> Result<FileIdentity, String> {
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o7777 != 0o600
        || info.nlink() != 1
        || info.len() == 0
        || info.len() > MAX_BYTES
    {
        return Err(refused());
    }
    Ok(FileIdentity {
        device: info.dev(),
        inode: info.ino(),
        size: info.len(),
        modified: (info.mtime(), info.mtime_nsec()),
        changed: (info.ctime(), info.ctime_nsec()),
    })
}

fn load_at(path: &Path, permit: &Permit<'_>) -> Result<Configuration, String> {
    permit.check().map_err(|_| refused())?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| refused())?;
    let before = file_identity(&file.metadata().map_err(|_| refused())?)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    let configuration = parse(&bytes)?;
    if bytes.len() as u64 != before.size
        || file_identity(&file.metadata().map_err(|_| refused())?)? != before
        || file_identity(&fs::symlink_metadata(path).map_err(|_| refused())?)? != before
    {
        return Err(refused());
    }
    permit.check().map_err(|_| refused())?;
    Ok(configuration)
}

pub(super) fn load(permit: &Permit<'_>) -> Result<Configuration, String> {
    load_at(Path::new(PATH), permit)
}

#[cfg(test)]
#[path = "operator_google_managed_tests.rs"]
mod tests;
