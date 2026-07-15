#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const LAUNCH_MANIFEST_API_VERSION: &str = "serverware.productionReadinessLaunch/v2";
const LAUNCH_MANIFEST_KIND: &str = "ProductionReadinessLaunch";
const RECEIPT_API_VERSION: &str = "serverware.bootstrapReceipt/v2";
const RECEIPT_KIND: &str = "ProductionBootstrapReceipt";
const AUTHORIZATION_REQUEST_API_VERSION: &str = "serverware.launchAuthorizationRequest/v1";
const AUTHORIZATION_REQUEST_KIND: &str = "ProductionLaunchAuthorizationRequest";
const AUTHORIZATION_API_VERSION: &str = "serverware.launchAuthorization/v1";
const AUTHORIZATION_KIND: &str = "ProductionLaunchAuthorization";
const AUTHORIZATION_SOCKET_PATH: &str = "/run/serverware/launch-authority.sock";
const AUTHORIZATION_MAX_BYTES: usize = 16 * 1024;
const AUTHORIZATION_TIMEOUT_MILLIS: i32 = 2_000;
const AUTHORIZATION_MAX_LIFETIME_SECONDS: u64 = 30;
const AUTHORIZATION_MAX_FUTURE_SKEW_SECONDS: u64 = 5;
const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const COMPILED_AUTHORITY_PUBLIC_KEY_HEX: &str =
    include_str!("../../trust/launch-authority-root.ed25519.hex");
const RECEIPT_FD: i32 = 198;
const EXPECTED_CONTROL_PLANE_ID: &str = "65532";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MEASURED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PYTHON_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
const RECEIPT_SHA256_PLACEHOLDER: &str = "sha256:<bootstrap-receipt>";
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_DYNAMIC_SIZE: usize = 16;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_SECTION_STRTAB: u32 = 3;
const ELF_SECTION_DYNAMIC: u32 = 6;
const ELF_SECTION_DYNSYM: u32 = 11;
const ELF_DYNAMIC_NEEDED: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct LauncherError(String);

impl LauncherError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LauncherError {}

type Result<T> = std::result::Result<T, LauncherError>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    manifest: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchManifest {
    api_version: String,
    kind: String,
    release_root: PathBuf,
    state_directory: PathBuf,
    source_tree_digest: String,
    authorization: LaunchAuthorizationConfiguration,
    production_env: FileRecord,
    python: PythonRecord,
    scripts: ScriptsRecord,
    compose_file: FileRecord,
    inputs: Inputs,
    outputs: Outputs,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationConfiguration {
    deployment_audience: String,
    deployment_identity_sha256: String,
    release_sequence: u64,
    rollback_epoch: u64,
}

#[derive(Debug, Deserialize)]
struct ReleaseProvenanceIdentity {
    provenance_digest: String,
    provenance: ReleaseProvenanceBodyIdentity,
}

#[derive(Debug, Deserialize)]
struct ReleaseProvenanceBodyIdentity {
    version: u64,
    source: String,
    source_tree: ReleaseSourceTreeIdentity,
}

#[derive(Debug, Deserialize)]
struct ReleaseSourceTreeIdentity {
    digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PythonRecord {
    path: PathBuf,
    sha256: String,
    import_roots: Vec<ImportRootRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRootRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptsRecord {
    preflight: FileRecord,
    runner: FileRecord,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inputs {
    production_images_build: FileRecord,
    production_images_env: FileRecord,
    production_images_published: FileRecord,
    release_provenance_summary: FileRecord,
    release_provenance: FileRecord,
    image_signatures_summary: FileRecord,
    image_signatures: FileRecord,
    bench: FileRecord,
    kms_materials: FileRecord,
    policy_bundle: FileRecord,
    policy_trusted_public_key: FileRecord,
    policy_identity_verification: FileRecord,
    policy_activation_verification: FileRecord,
    policy_activation_signature: FileRecord,
    policy_activation_trusted_public_key: FileRecord,
    reproducible_build_verification: FileRecord,
    reproducible_build_signature: FileRecord,
    reproducible_build_trusted_public_key: FileRecord,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outputs {
    config_out: PathBuf,
    claims_file: PathBuf,
    nitro_evidence_out: PathBuf,
    readiness_out: PathBuf,
    completion_proof_out: PathBuf,
    proxy_proof_summary_out: PathBuf,
    production_host_preflight: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    link_count: u64,
    size: u64,
    modified_unix_nanos: i128,
    changed_unix_nanos: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptFile {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptImportRoot {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptPython {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
    #[serde(rename = "importRoots")]
    import_roots: Vec<ReceiptImportRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptScripts {
    preflight: ReceiptFile,
    runner: ReceiptFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptArgv {
    preflight_sha256: String,
    readiness_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptEnvironment {
    names: Vec<String>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchAuthorizationRequest {
    api_version: String,
    kind: String,
    launcher_nonce: String,
    boot_id_sha256: String,
    launcher_sha256: String,
    manifest_sha256: String,
    release_provenance_sha256: String,
    provenance_digest: String,
    reproducible_build_verification_sha256: String,
    source_tree_digest: String,
    deployment_audience: String,
    deployment_identity_sha256: String,
    release_sequence: u64,
    rollback_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationStatement {
    authorization_id: String,
    authority_key_id: String,
    request_sha256: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    use_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationEnvelope {
    api_version: String,
    kind: String,
    statement: LaunchAuthorizationStatement,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptLaunchAuthorization {
    request: LaunchAuthorizationRequest,
    request_sha256: String,
    envelope: LaunchAuthorizationEnvelope,
    authorization_sha256: String,
    verified_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapReceipt {
    api_version: String,
    kind: String,
    launch_id: String,
    boot_id_sha256: String,
    launcher: ReceiptFile,
    manifest: ReceiptFile,
    source_tree_digest: String,
    launch_authorization: ReceiptLaunchAuthorization,
    production_env: ReceiptFile,
    python: ReceiptPython,
    scripts: ReceiptScripts,
    compose_file: ReceiptFile,
    inputs: BTreeMap<String, ReceiptFile>,
    argv: ReceiptArgv,
    environment: ReceiptEnvironment,
}

fn parse_cli<I>(arguments: I) -> Result<Cli>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut manifest = None;

    while let Some(raw_name) = arguments.next() {
        let name = raw_name
            .into_string()
            .map_err(|_| LauncherError::new("launcher arguments must be valid UTF-8"))?;
        let raw_value = arguments
            .next()
            .ok_or_else(|| LauncherError::new(format!("missing value for {name}")))?;
        let value = raw_value
            .into_string()
            .map_err(|_| LauncherError::new("launcher arguments must be valid UTF-8"))?;
        match name.as_str() {
            "--manifest" => {
                if manifest.replace(PathBuf::from(value)).is_some() {
                    return Err(LauncherError::new("duplicate --manifest argument"));
                }
            }
            _ => {
                return Err(LauncherError::new(format!(
                    "unknown launcher argument: {name}"
                )))
            }
        }
    }

    let manifest = manifest.ok_or_else(|| LauncherError::new("missing --manifest argument"))?;
    require_normalized_absolute(&manifest, "manifest")?;
    Ok(Cli { manifest })
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    let Some(hex_value) = value.strip_prefix("sha256:") else {
        return Err(LauncherError::new(format!(
            "{label} must be sha256:<64 lowercase hex>"
        )));
    };
    if hex_value.len() != 64
        || !hex_value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(LauncherError::new(format!(
            "{label} must be sha256:<64 lowercase hex>"
        )));
    }
    Ok(())
}

fn require_lower_hex_64(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(LauncherError::new(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn require_deployment_audience(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(LauncherError::new(
            "authorization.deploymentAudience is invalid",
        ));
    }
    Ok(())
}

fn require_json_safe_integer(value: u64, label: &str, allow_zero: bool) -> Result<()> {
    if value > JSON_SAFE_INTEGER_MAX || (!allow_zero && value == 0) {
        return Err(LauncherError::new(format!("{label} is invalid")));
    }
    Ok(())
}

fn require_digest_match(actual: &str, expected: &str, label: &str) -> Result<()> {
    require_sha256(actual, label)?;
    require_sha256(expected, label)?;
    if actual != expected {
        return Err(LauncherError::new(format!("{label} digest does not match")));
    }
    Ok(())
}

fn require_normalized_absolute(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(LauncherError::new(format!("{label} must be absolute")));
    }
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if !value.is_empty() => saw_normal = true,
            _ => {
                return Err(LauncherError::new(format!(
                    "{label} must be an absolute normalized path"
                )))
            }
        }
    }
    if !saw_normal {
        return Err(LauncherError::new(format!(
            "{label} must not be the filesystem root"
        )));
    }
    Ok(())
}

fn require_strict_descendant(path: &Path, root: &Path, label: &str) -> Result<()> {
    require_normalized_absolute(path, label)?;
    if path == root || !path.starts_with(root) {
        return Err(LauncherError::new(format!(
            "{label} must be below the configured root"
        )));
    }
    Ok(())
}

fn require_at_or_below(path: &Path, root: &Path, label: &str) -> Result<()> {
    require_normalized_absolute(path, label)?;
    if !path.starts_with(root) {
        return Err(LauncherError::new(format!(
            "{label} must equal or be below the configured root"
        )));
    }
    Ok(())
}

fn validate_python_layout(manifest: &LaunchManifest) -> Result<String> {
    let expected_python = manifest.release_root.join("runtime/python/bin/python3");
    if manifest.python.path != expected_python {
        return Err(LauncherError::new(
            "python must use releaseRoot/runtime/python/bin/python3",
        ));
    }
    if manifest.python.import_roots.len() != 4 {
        return Err(LauncherError::new(
            "python.importRoots must contain exactly four ordered roots",
        ));
    }
    let roots = &manifest.python.import_roots;
    let stdlib = &roots[1].path;
    let expected_stdlib_parent = manifest.release_root.join("runtime/python/lib");
    if stdlib.parent() != Some(expected_stdlib_parent.as_path()) {
        return Err(LauncherError::new(
            "python.importRoots[1] must be the release CPython stdlib",
        ));
    }
    let python_version = stdlib
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| LauncherError::new("python stdlib version is not valid UTF-8"))?;
    let minor = python_version.strip_prefix("python3.").ok_or_else(|| {
        LauncherError::new("python stdlib must use a canonical python3.X directory")
    })?;
    if minor.is_empty()
        || !minor.as_bytes().iter().all(u8::is_ascii_digit)
        || (minor.len() > 1 && minor.starts_with('0'))
    {
        return Err(LauncherError::new(
            "python stdlib must use a canonical python3.X directory",
        ));
    }
    let expected = [
        manifest.release_root.clone(),
        stdlib.clone(),
        stdlib.join("lib-dynload"),
        manifest.release_root.join("vendor"),
    ];
    if roots
        .iter()
        .zip(expected.iter())
        .any(|(record, expected_path)| record.path != *expected_path)
    {
        return Err(LauncherError::new(
            "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
        ));
    }
    Ok(python_version.to_string())
}

fn elf_range<'a>(data: &'a [u8], offset: usize, size: usize, label: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} range overflow")))?;
    data.get(offset..end)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} is out of bounds")))
}

fn elf_u16(data: &[u8], offset: usize, label: &str) -> Result<u16> {
    let bytes: [u8; 2] = elf_range(data, offset, 2, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u16::from_le_bytes(bytes))
}

fn elf_u32(data: &[u8], offset: usize, label: &str) -> Result<u32> {
    let bytes: [u8; 4] = elf_range(data, offset, 4, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn elf_u64(data: &[u8], offset: usize, label: &str) -> Result<u64> {
    let bytes: [u8; 8] = elf_range(data, offset, 8, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u64::from_le_bytes(bytes))
}

fn elf_usize(data: &[u8], offset: usize, label: &str) -> Result<usize> {
    usize::try_from(elf_u64(data, offset, label)?)
        .map_err(|_| LauncherError::new(format!("python ELF {label} is too large")))
}

#[derive(Clone, Copy)]
struct ElfSection {
    section_type: u32,
    offset: usize,
    size: usize,
    link: usize,
    entry_size: usize,
}

fn elf_c_string<'a>(table: &'a [u8], offset: usize, label: &str) -> Result<&'a [u8]> {
    let tail = table.get(offset..).ok_or_else(|| {
        LauncherError::new(format!("python ELF {label} string offset is invalid"))
    })?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} is not NUL-terminated")))?;
    Ok(&tail[..length])
}

fn compatible_libpython_name(value: &[u8], python_version: &str) -> bool {
    let prefix = format!("lib{python_version}.so");
    if value == prefix.as_bytes() {
        return true;
    }
    let Some(suffix) = value.strip_prefix(format!("{prefix}.").as_bytes()) else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .split(|byte| *byte == b'.')
            .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
}

fn validate_cpython_elf64(data: &[u8], python_version: &str) -> Result<()> {
    // This identifies the measured interpreter. PT_INTERP and recursive
    // non-libpython DSO closure remain an explicit production-host boundary.
    if data.len() < ELF64_HEADER_SIZE || data.get(..4) != Some(b"\x7fELF") {
        return Err(LauncherError::new(
            "python must be an ELF executable, not a script or arbitrary file",
        ));
    }
    if data.get(4..7) != Some(b"\x02\x01\x01") {
        return Err(LauncherError::new(
            "python must use the ELF64 little-endian version-1 format",
        ));
    }
    let elf_type = elf_u16(data, 16, "type")?;
    if !matches!(elf_type, 2 | 3)
        || elf_u16(data, 18, "machine")? != ELF_MACHINE_X86_64
        || elf_u32(data, 20, "version")? != 1
    {
        return Err(LauncherError::new(
            "python must be a Linux x86-64 ELF executable",
        ));
    }
    if usize::from(elf_u16(data, 52, "header size")?) != ELF64_HEADER_SIZE {
        return Err(LauncherError::new("python ELF header size is invalid"));
    }
    let program_offset = elf_usize(data, 32, "program-header offset")?;
    let program_entry_size = usize::from(elf_u16(data, 54, "program-header entry size")?);
    let program_count = usize::from(elf_u16(data, 56, "program-header count")?);
    if program_count == 0 || program_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(LauncherError::new(
            "python ELF program-header table is invalid",
        ));
    }
    let program_size = program_count
        .checked_mul(program_entry_size)
        .ok_or_else(|| LauncherError::new("python ELF program-header table overflow"))?;
    elf_range(data, program_offset, program_size, "program-header table")?;

    let section_offset = elf_usize(data, 40, "section-header offset")?;
    let section_entry_size = usize::from(elf_u16(data, 58, "section-header entry size")?);
    let section_count = usize::from(elf_u16(data, 60, "section-header count")?);
    if section_count == 0
        || section_count > 4096
        || section_entry_size != ELF64_SECTION_HEADER_SIZE
        || elf_u16(data, 62, "section-name index")? == 0xffff
    {
        return Err(LauncherError::new(
            "python ELF section-header table is unsupported or invalid",
        ));
    }
    let section_table_size = section_count
        .checked_mul(section_entry_size)
        .ok_or_else(|| LauncherError::new("python ELF section-header table overflow"))?;
    elf_range(
        data,
        section_offset,
        section_table_size,
        "section-header table",
    )?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = section_offset + index * ELF64_SECTION_HEADER_SIZE;
        let section = ElfSection {
            section_type: elf_u32(data, base + 4, "section type")?,
            offset: elf_usize(data, base + 24, "section offset")?,
            size: elf_usize(data, base + 32, "section size")?,
            link: usize::try_from(elf_u32(data, base + 40, "section link")?)
                .map_err(|_| LauncherError::new("python ELF section link is invalid"))?,
            entry_size: elf_usize(data, base + 56, "section entry size")?,
        };
        elf_range(data, section.offset, section.size, "section")?;
        sections.push(section);
    }

    let linked_strings = |link: usize, label: &str| -> Result<&[u8]> {
        let section = sections.get(link).ok_or_else(|| {
            LauncherError::new(format!("python ELF {label} string-table link is invalid"))
        })?;
        if section.section_type != ELF_SECTION_STRTAB {
            return Err(LauncherError::new(format!(
                "python ELF {label} does not link to a string table"
            )));
        }
        elf_range(data, section.offset, section.size, label)
    };

    let mut has_py_bytes_main = false;
    let mut has_compatible_libpython = false;
    for (index, section) in sections.iter().enumerate() {
        if section.section_type == ELF_SECTION_DYNSYM {
            if section.entry_size != ELF64_SYMBOL_SIZE || section.size % section.entry_size != 0 {
                return Err(LauncherError::new(
                    "python ELF dynamic symbol table is malformed",
                ));
            }
            let strings = linked_strings(section.link, "dynamic symbol")?;
            let symbols = elf_range(data, section.offset, section.size, "dynamic symbol table")?;
            for offset in (0..symbols.len()).step_by(ELF64_SYMBOL_SIZE) {
                let name_offset = usize::try_from(elf_u32(symbols, offset, "dynamic symbol name")?)
                    .map_err(|_| LauncherError::new("python ELF symbol name is invalid"))?;
                if name_offset != 0
                    && elf_c_string(strings, name_offset, "dynamic symbol")? == b"Py_BytesMain"
                {
                    has_py_bytes_main = true;
                }
            }
        } else if section.section_type == ELF_SECTION_DYNAMIC {
            if section.entry_size != ELF64_DYNAMIC_SIZE || section.size % section.entry_size != 0 {
                return Err(LauncherError::new(
                    "python ELF dynamic dependency table is malformed",
                ));
            }
            let strings = linked_strings(section.link, "dynamic dependency")?;
            let dynamic = elf_range(
                data,
                section.offset,
                section.size,
                "dynamic dependency table",
            )?;
            for offset in (0..dynamic.len()).step_by(ELF64_DYNAMIC_SIZE) {
                if elf_u64(dynamic, offset, "dynamic tag")? == ELF_DYNAMIC_NEEDED {
                    let name_offset = elf_usize(dynamic, offset + 8, "DT_NEEDED offset")?;
                    if compatible_libpython_name(
                        elf_c_string(strings, name_offset, "DT_NEEDED")?,
                        python_version,
                    ) {
                        has_compatible_libpython = true;
                    }
                }
            }
        }
        let _ = index;
    }
    if !has_py_bytes_main {
        return Err(LauncherError::new(
            "python ELF does not import the required Py_BytesMain symbol",
        ));
    }
    if !has_compatible_libpython {
        return Err(LauncherError::new(format!(
            "python ELF does not depend on a compatible lib{python_version}.so"
        )));
    }
    Ok(())
}

fn validate_output_path(value: &Path, state_directory: &Path, label: &str) -> Result<()> {
    require_strict_descendant(value, state_directory, label)?;
    if value.parent() != Some(state_directory) {
        return Err(LauncherError::new(format!(
            "{label} must be a direct child of stateDirectory"
        )));
    }
    Ok(())
}

fn all_input_records(inputs: &Inputs) -> [(&'static str, &FileRecord); 18] {
    [
        ("productionImagesBuild", &inputs.production_images_build),
        ("productionImagesEnv", &inputs.production_images_env),
        (
            "productionImagesPublished",
            &inputs.production_images_published,
        ),
        (
            "releaseProvenanceSummary",
            &inputs.release_provenance_summary,
        ),
        ("releaseProvenance", &inputs.release_provenance),
        ("imageSignaturesSummary", &inputs.image_signatures_summary),
        ("imageSignatures", &inputs.image_signatures),
        ("bench", &inputs.bench),
        ("kmsMaterials", &inputs.kms_materials),
        ("policyBundle", &inputs.policy_bundle),
        ("policyTrustedPublicKey", &inputs.policy_trusted_public_key),
        (
            "policyIdentityVerification",
            &inputs.policy_identity_verification,
        ),
        (
            "policyActivationVerification",
            &inputs.policy_activation_verification,
        ),
        (
            "policyActivationSignature",
            &inputs.policy_activation_signature,
        ),
        (
            "policyActivationTrustedPublicKey",
            &inputs.policy_activation_trusted_public_key,
        ),
        (
            "reproducibleBuildVerification",
            &inputs.reproducible_build_verification,
        ),
        (
            "reproducibleBuildSignature",
            &inputs.reproducible_build_signature,
        ),
        (
            "reproducibleBuildTrustedPublicKey",
            &inputs.reproducible_build_trusted_public_key,
        ),
    ]
}

fn validate_manifest(manifest: &LaunchManifest) -> Result<()> {
    if manifest.api_version != LAUNCH_MANIFEST_API_VERSION {
        return Err(LauncherError::new("unsupported launch manifest apiVersion"));
    }
    if manifest.kind != LAUNCH_MANIFEST_KIND {
        return Err(LauncherError::new("unsupported launch manifest kind"));
    }
    require_normalized_absolute(&manifest.release_root, "releaseRoot")?;
    require_normalized_absolute(&manifest.state_directory, "stateDirectory")?;
    if manifest.release_root.starts_with(&manifest.state_directory)
        || manifest.state_directory.starts_with(&manifest.release_root)
    {
        return Err(LauncherError::new(
            "releaseRoot and stateDirectory must not overlap",
        ));
    }
    require_sha256(&manifest.source_tree_digest, "sourceTreeDigest")?;
    require_deployment_audience(&manifest.authorization.deployment_audience)?;
    require_sha256(
        &manifest.authorization.deployment_identity_sha256,
        "authorization.deploymentIdentitySha256",
    )?;
    require_json_safe_integer(
        manifest.authorization.release_sequence,
        "authorization.releaseSequence",
        false,
    )?;
    require_json_safe_integer(
        manifest.authorization.rollback_epoch,
        "authorization.rollbackEpoch",
        true,
    )?;

    require_strict_descendant(
        &manifest.production_env.path,
        Path::new("/etc/serverware"),
        "productionEnv.path",
    )?;
    require_sha256(&manifest.production_env.sha256, "productionEnv.sha256")?;

    for (label, record) in [
        (
            "python",
            &FileRecord {
                path: manifest.python.path.clone(),
                sha256: manifest.python.sha256.clone(),
            },
        ),
        ("scripts.preflight", &manifest.scripts.preflight),
        ("scripts.runner", &manifest.scripts.runner),
        ("composeFile", &manifest.compose_file),
    ] {
        require_strict_descendant(&record.path, &manifest.release_root, label)?;
        require_sha256(&record.sha256, &format!("{label}.sha256"))?;
    }

    validate_python_layout(manifest)?;
    for (index, root) in manifest.python.import_roots.iter().enumerate() {
        let label = format!("python.importRoots[{index}]");
        require_at_or_below(&root.path, &manifest.release_root, &label)?;
        require_sha256(&root.sha256, &format!("{label}.sha256"))?;
    }

    let mut immutable_paths = BTreeSet::new();
    for (label, record) in all_input_records(&manifest.inputs) {
        require_strict_descendant(&record.path, &manifest.release_root, label)?;
        require_sha256(&record.sha256, &format!("{label}.sha256"))?;
        if !immutable_paths.insert(record.path.clone()) {
            return Err(LauncherError::new(format!(
                "immutable input path is duplicated at {label}"
            )));
        }
    }

    let output_values = [
        ("outputs.configOut", &manifest.outputs.config_out),
        ("outputs.claimsFile", &manifest.outputs.claims_file),
        (
            "outputs.nitroEvidenceOut",
            &manifest.outputs.nitro_evidence_out,
        ),
        ("outputs.readinessOut", &manifest.outputs.readiness_out),
        (
            "outputs.completionProofOut",
            &manifest.outputs.completion_proof_out,
        ),
        (
            "outputs.proxyProofSummaryOut",
            &manifest.outputs.proxy_proof_summary_out,
        ),
        (
            "outputs.productionHostPreflight",
            &manifest.outputs.production_host_preflight,
        ),
    ];
    let mut output_names = BTreeSet::new();
    for (label, value) in output_values {
        validate_output_path(value, &manifest.state_directory, label)?;
        if !output_names.insert(value) {
            return Err(LauncherError::new("output paths must be unique"));
        }
    }
    Ok(())
}

fn push_option(argv: &mut Vec<String>, name: &str, value: &Path) {
    argv.push(name.to_string());
    argv.push(value.to_string_lossy().into_owned());
}

fn push_common_inputs(argv: &mut Vec<String>, manifest: &LaunchManifest) {
    let pairs = [
        (
            "--production-images-build",
            &manifest.inputs.production_images_build.path,
        ),
        (
            "--production-images-env",
            &manifest.inputs.production_images_env.path,
        ),
        (
            "--production-images-published",
            &manifest.inputs.production_images_published.path,
        ),
        (
            "--release-provenance-summary",
            &manifest.inputs.release_provenance_summary.path,
        ),
        (
            "--release-provenance",
            &manifest.inputs.release_provenance.path,
        ),
        (
            "--image-signatures-summary",
            &manifest.inputs.image_signatures_summary.path,
        ),
        ("--image-signatures", &manifest.inputs.image_signatures.path),
        ("--bench", &manifest.inputs.bench.path),
        ("--kms-materials", &manifest.inputs.kms_materials.path),
        ("--policy-bundle", &manifest.inputs.policy_bundle.path),
        (
            "--policy-trusted-public-key",
            &manifest.inputs.policy_trusted_public_key.path,
        ),
        (
            "--policy-identity-verification",
            &manifest.inputs.policy_identity_verification.path,
        ),
        (
            "--policy-activation-verification",
            &manifest.inputs.policy_activation_verification.path,
        ),
        (
            "--policy-activation-signature",
            &manifest.inputs.policy_activation_signature.path,
        ),
        (
            "--policy-activation-trusted-public-key",
            &manifest.inputs.policy_activation_trusted_public_key.path,
        ),
        (
            "--reproducible-build-verification",
            &manifest.inputs.reproducible_build_verification.path,
        ),
        (
            "--reproducible-build-signature",
            &manifest.inputs.reproducible_build_signature.path,
        ),
        (
            "--reproducible-build-trusted-public-key",
            &manifest.inputs.reproducible_build_trusted_public_key.path,
        ),
    ];
    for (name, path) in pairs {
        push_option(argv, name, path);
    }
}

fn build_preflight_argv(manifest: &LaunchManifest) -> Vec<String> {
    let mut argv = vec![manifest
        .scripts
        .preflight
        .path
        .to_string_lossy()
        .into_owned()];
    push_option(&mut argv, "--env-file", &manifest.production_env.path);
    push_option(
        &mut argv,
        "--launcher-trusted-production-env-path",
        &manifest.production_env.path,
    );
    argv.push("--launcher-trusted-production-env-sha256".to_string());
    argv.push(manifest.production_env.sha256.clone());
    push_option(&mut argv, "--compose-file", &manifest.compose_file.path);
    push_common_inputs(&mut argv, manifest);
    argv.extend([
        "--expected-control-plane-uid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--expected-control-plane-gid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--config-out".to_string(),
        manifest.outputs.config_out.to_string_lossy().into_owned(),
        "--out".to_string(),
        manifest
            .outputs
            .production_host_preflight
            .to_string_lossy()
            .into_owned(),
    ]);
    argv
}

fn build_readiness_argv(manifest: &LaunchManifest) -> Vec<String> {
    let mut argv = vec![manifest.scripts.runner.path.to_string_lossy().into_owned()];
    push_option(&mut argv, "--env-file", &manifest.production_env.path);
    push_option(
        &mut argv,
        "--launcher-trusted-production-env-path",
        &manifest.production_env.path,
    );
    argv.push("--launcher-trusted-production-env-sha256".to_string());
    argv.push(manifest.production_env.sha256.clone());
    push_option(&mut argv, "--python", &manifest.python.path);
    push_option(&mut argv, "--compose-file", &manifest.compose_file.path);
    argv.extend([
        "--verification-mode".to_string(),
        "final".to_string(),
        "--expected-control-plane-uid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--expected-control-plane-gid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
    ]);
    push_common_inputs(&mut argv, manifest);
    argv.extend([
        "--config-out".to_string(),
        manifest.outputs.config_out.to_string_lossy().into_owned(),
        "--claims-file".to_string(),
        manifest.outputs.claims_file.to_string_lossy().into_owned(),
        "--nitro-evidence-out".to_string(),
        manifest
            .outputs
            .nitro_evidence_out
            .to_string_lossy()
            .into_owned(),
        "--readiness-out".to_string(),
        manifest
            .outputs
            .readiness_out
            .to_string_lossy()
            .into_owned(),
        "--completion-proof-out".to_string(),
        manifest
            .outputs
            .completion_proof_out
            .to_string_lossy()
            .into_owned(),
        "--production-host-preflight".to_string(),
        manifest
            .outputs
            .production_host_preflight
            .to_string_lossy()
            .into_owned(),
        "--proxy-proof-summary-out".to_string(),
        manifest
            .outputs
            .proxy_proof_summary_out
            .to_string_lossy()
            .into_owned(),
    ]);
    argv
}

fn fixed_environment(receipt_sha256: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        (
            "PATH".to_string(),
            "/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TZ".to_string(), "UTC".to_string()),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION".to_string(),
            RECEIPT_API_VERSION.to_string(),
        ),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_FD".to_string(),
            RECEIPT_FD.to_string(),
        ),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256".to_string(),
            receipt_sha256.to_string(),
        ),
    ])
}

fn environment_commitment() -> Result<ReceiptEnvironment> {
    let environment = fixed_environment(RECEIPT_SHA256_PLACEHOLDER);
    let names = environment.keys().cloned().collect::<Vec<_>>();
    let bytes = canonical_json_bytes(&environment)?;
    Ok(ReceiptEnvironment {
        names,
        sha256: sha256_prefixed(&bytes),
    })
}

fn argv_digest(argv: &[String]) -> Result<String> {
    Ok(sha256_prefixed(&canonical_json_bytes(argv)?))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn canonical_json_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| LauncherError::new("could not construct canonical JSON value"))?;
    serde_json::to_vec(&sort_json(value))
        .map_err(|_| LauncherError::new("could not serialize canonical JSON"))
}

#[derive(Serialize)]
struct LaunchAuthorizationSignedValue<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    statement: &'a LaunchAuthorizationStatement,
}

fn domain_separated_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn launch_authority_key_id(key: &VerifyingKey) -> String {
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(key.as_bytes());
    sha256_prefixed(&spki)
}

fn parse_authority_public_key(raw: &str) -> Result<VerifyingKey> {
    let trimmed = raw.strip_suffix('\n').ok_or_else(|| {
        LauncherError::new("compiled launch authority public key must end with one LF")
    })?;
    if trimmed.contains(['\r', '\n']) {
        return Err(LauncherError::new(
            "compiled launch authority public key has invalid whitespace",
        ));
    }
    require_lower_hex_64(trimmed, "compiled launch authority public key")?;
    let decoded = hex::decode(trimmed)
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))
}

fn compiled_authority_public_key() -> Result<VerifyingKey> {
    parse_authority_public_key(COMPILED_AUTHORITY_PUBLIC_KEY_HEX)
}

fn authorization_request_digest(request: &LaunchAuthorizationRequest) -> Result<String> {
    Ok(domain_separated_digest(
        b"serverware.launchAuthorizationRequest/v1\0",
        &canonical_json_bytes(request)?,
    ))
}

fn authorization_signing_bytes(envelope: &LaunchAuthorizationEnvelope) -> Result<Vec<u8>> {
    let signed = LaunchAuthorizationSignedValue {
        api_version: &envelope.api_version,
        kind: &envelope.kind,
        statement: &envelope.statement,
    };
    let canonical = canonical_json_bytes(&signed)?;
    let mut bytes = b"serverware.launchAuthorization/v1\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn require_authorization_current(
    statement: &LaunchAuthorizationStatement,
    now_unix_seconds: u64,
) -> Result<()> {
    let issued = statement.issued_at_unix_seconds;
    let expires = statement.expires_at_unix_seconds;
    if expires <= issued || expires - issued > AUTHORIZATION_MAX_LIFETIME_SECONDS {
        return Err(LauncherError::new(
            "LAUTH_TIME_INVALID: authorization validity interval is invalid",
        ));
    }
    if issued > now_unix_seconds.saturating_add(AUTHORIZATION_MAX_FUTURE_SKEW_SECONDS) {
        return Err(LauncherError::new(
            "LAUTH_FUTURE: authorization issuance time is too far in the future",
        ));
    }
    if now_unix_seconds >= expires {
        return Err(LauncherError::new(
            "LAUTH_EXPIRED: launch authorization has expired",
        ));
    }
    Ok(())
}

fn verify_launch_authorization(
    request: LaunchAuthorizationRequest,
    envelope: LaunchAuthorizationEnvelope,
    key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<ReceiptLaunchAuthorization> {
    if envelope.api_version != AUTHORIZATION_API_VERSION || envelope.kind != AUTHORIZATION_KIND {
        return Err(LauncherError::new(
            "LAUTH_SCHEMA_INVALID: unsupported launch authorization contract",
        ));
    }
    require_lower_hex_64(&envelope.statement.authorization_id, "authorizationId")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: authorizationId is invalid"))?;
    require_sha256(&envelope.statement.authority_key_id, "authorityKeyId")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: authorityKeyId is invalid"))?;
    require_sha256(&envelope.statement.request_sha256, "requestSha256")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: requestSha256 is invalid"))?;
    for (value, label) in [
        (
            envelope.statement.issued_at_unix_seconds,
            "issuedAtUnixSeconds",
        ),
        (
            envelope.statement.expires_at_unix_seconds,
            "expiresAtUnixSeconds",
        ),
    ] {
        require_json_safe_integer(value, label, false)
            .map_err(|_| LauncherError::new(format!("LAUTH_SCHEMA_INVALID: {label} is invalid")))?;
    }
    if envelope.statement.use_limit != 1 {
        return Err(LauncherError::new(
            "LAUTH_SCHEMA_INVALID: useLimit must equal one",
        ));
    }

    let expected_key_id = launch_authority_key_id(key);
    if envelope.statement.authority_key_id != expected_key_id {
        return Err(LauncherError::new(
            "LAUTH_KEY_ID_MISMATCH: authority key identity does not match compiled trust root",
        ));
    }
    let request_sha256 = authorization_request_digest(&request)?;
    if envelope.statement.request_sha256 != request_sha256 {
        return Err(LauncherError::new(
            "LAUTH_REQUEST_MISMATCH: authorization does not bind this launch request",
        ));
    }

    require_authorization_current(&envelope.statement, now_unix_seconds)?;

    if envelope.signature.contains('=') {
        return Err(LauncherError::new(
            "LAUTH_SIGNATURE_INVALID: signature must be unpadded base64url",
        ));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| {
            LauncherError::new("LAUTH_SIGNATURE_INVALID: signature is not canonical base64url")
        })?;
    if decoded.len() != 64
        || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != envelope.signature
    {
        return Err(LauncherError::new(
            "LAUTH_SIGNATURE_INVALID: signature must contain exactly 64 canonical bytes",
        ));
    }
    let signature_bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| LauncherError::new("LAUTH_SIGNATURE_INVALID: signature length is invalid"))?;
    key.verify_strict(
        &authorization_signing_bytes(&envelope)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| {
        LauncherError::new("LAUTH_SIGNATURE_INVALID: authority signature verification failed")
    })?;

    let envelope_bytes = canonical_json_bytes(&envelope)?;
    Ok(ReceiptLaunchAuthorization {
        request,
        request_sha256,
        authorization_sha256: sha256_prefixed(&envelope_bytes),
        envelope,
        verified_at_unix_seconds: now_unix_seconds,
    })
}

fn parse_manifest(bytes: &[u8]) -> Result<LaunchManifest> {
    let manifest: LaunchManifest = serde_json::from_slice(bytes)
        .map_err(|error| LauncherError::new(format!("launch manifest is invalid: {error}")))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::time::{Duration, Instant};

    const PYTHON_BOOTSTRAP_PREFIX: &str = "import os,sys\n";
    const IMMUTABLE_MEMFD_SEALS: libc::c_int =
        libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

    #[derive(Debug)]
    struct MeasuredFile {
        file: File,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct MeasuredScript {
        snapshot: OwnedFd,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct MeasuredImportRoot {
        fd: OwnedFd,
        receipt: ReceiptImportRoot,
    }

    #[derive(Debug)]
    struct VerifiedLaunch {
        manifest: LaunchManifest,
        launcher: ReceiptFile,
        manifest_receipt: ReceiptFile,
        python: MeasuredFile,
        preflight: MeasuredScript,
        runner: MeasuredScript,
        import_roots: Vec<MeasuredImportRoot>,
        production_env: ReceiptFile,
        compose_file: ReceiptFile,
        inputs: BTreeMap<String, ReceiptFile>,
        provenance_digest: String,
        release_root_fd: OwnedFd,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        owner_uid: u32,
        owner_gid: u32,
        link_count: u64,
        size: u64,
        modified_unix_nanos: i128,
        changed_unix_nanos: i128,
    }

    impl FileIdentity {
        fn receipt(self) -> ReceiptMetadata {
            ReceiptMetadata {
                device: self.device,
                inode: self.inode,
                mode: self.mode & 0o7777,
                owner_uid: self.owner_uid,
                owner_gid: self.owner_gid,
                link_count: self.link_count,
                size: self.size,
                modified_unix_nanos: self.modified_unix_nanos,
                changed_unix_nanos: self.changed_unix_nanos,
            }
        }
    }

    fn errno_message(context: &str) -> LauncherError {
        LauncherError::new(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    fn cstring_bytes(bytes: &[u8], label: &str) -> Result<CString> {
        CString::new(bytes).map_err(|_| LauncherError::new(format!("{label} contains NUL")))
    }

    fn fstat(fd: RawFd, context: &str) -> Result<FileIdentity> {
        let mut raw = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: raw points to writable storage and fd is owned by the caller.
        if unsafe { libc::fstat(fd, raw.as_mut_ptr()) } != 0 {
            return Err(errno_message(context));
        }
        // SAFETY: successful fstat initialized the complete stat structure.
        let raw = unsafe { raw.assume_init() };
        Ok(FileIdentity {
            device: raw.st_dev,
            inode: raw.st_ino,
            mode: raw.st_mode,
            owner_uid: raw.st_uid,
            owner_gid: raw.st_gid,
            link_count: u64::from(raw.st_nlink),
            size: u64::try_from(raw.st_size).unwrap_or(0),
            modified_unix_nanos: i128::from(raw.st_mtime) * 1_000_000_000
                + i128::from(raw.st_mtime_nsec),
            changed_unix_nanos: i128::from(raw.st_ctime) * 1_000_000_000
                + i128::from(raw.st_ctime_nsec),
        })
    }

    fn require_secure_directory(identity: FileIdentity, label: &str) -> Result<()> {
        if identity.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(LauncherError::new(format!("{label} must be a directory")));
        }
        if identity.owner_uid != 0 || identity.owner_gid != 0 {
            return Err(LauncherError::new(format!(
                "{label} must be owned by root:root"
            )));
        }
        if identity.mode & 0o022 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not be writable by group or other"
            )));
        }
        Ok(())
    }

    fn require_secure_regular(
        identity: FileIdentity,
        label: &str,
        exact_manifest_mode: bool,
        executable: bool,
    ) -> Result<()> {
        if identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(LauncherError::new(format!(
                "{label} must be a regular file"
            )));
        }
        if identity.owner_uid != 0 || identity.owner_gid != 0 {
            return Err(LauncherError::new(format!(
                "{label} must be owned by root:root"
            )));
        }
        if identity.link_count != 1 {
            return Err(LauncherError::new(format!(
                "{label} must have one hard link"
            )));
        }
        if identity.mode & 0o6000 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not have set-id bits"
            )));
        }
        let permissions = identity.mode & 0o7777;
        if exact_manifest_mode {
            if permissions != 0o400 && permissions != 0o440 {
                return Err(LauncherError::new(
                    "manifest mode must be exactly 0400 or 0440",
                ));
            }
        } else if permissions & 0o022 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not be writable by group or other"
            )));
        }
        if executable && permissions & 0o111 == 0 {
            return Err(LauncherError::new(format!("{label} must be executable")));
        }
        if identity.size > MAX_MEASURED_FILE_BYTES {
            return Err(LauncherError::new(format!("{label} is too large")));
        }
        Ok(())
    }

    fn open_root() -> Result<OwnedFd> {
        let root = c"/";
        // SAFETY: root is a static NUL-terminated string.
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(errno_message("could not open filesystem root"));
        }
        // SAFETY: fd is newly returned and uniquely owned.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        require_secure_directory(
            fstat(fd.as_raw_fd(), "could not inspect filesystem root")?,
            "/",
        )?;
        Ok(fd)
    }

    fn secure_open(path: &Path, final_directory: bool, label: &str) -> Result<OwnedFd> {
        require_normalized_absolute(path, label)?;
        let mut current = open_root()?;
        let components = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.as_bytes().to_vec()),
                _ => None,
            })
            .collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            let final_component = index + 1 == components.len();
            let name = cstring_bytes(component, label)?;
            let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            if !final_component || final_directory {
                flags |= libc::O_DIRECTORY;
            }
            // SAFETY: current and name remain valid for the call.
            let next = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            if next < 0 {
                return Err(errno_message(&format!("could not securely open {label}")));
            }
            // SAFETY: next is newly returned and uniquely owned.
            let next = unsafe { OwnedFd::from_raw_fd(next) };
            let identity = fstat(next.as_raw_fd(), &format!("could not inspect {label}"))?;
            if !final_component || final_directory {
                require_secure_directory(identity, label)?;
            }
            current = next;
        }
        Ok(current)
    }

    fn stable_digest_file(
        mut file: File,
        path: &Path,
        expected_digest: &str,
        label: &str,
        exact_manifest_mode: bool,
        executable: bool,
        mut snapshot: Option<&mut File>,
    ) -> Result<MeasuredFile> {
        let before = fstat(file.as_raw_fd(), &format!("could not inspect {label}"))?;
        require_secure_regular(before, label, exact_manifest_mode, executable)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not seek {label}")))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| LauncherError::new(format!("could not read {label}")))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| LauncherError::new(format!("{label} size overflow")))?;
            if total > MAX_MEASURED_FILE_BYTES {
                return Err(LauncherError::new(format!("{label} is too large")));
            }
            if let Some(snapshot) = snapshot.as_deref_mut() {
                snapshot
                    .write_all(&buffer[..count])
                    .map_err(|_| LauncherError::new(format!("could not snapshot {label}")))?;
            }
            digest.update(&buffer[..count]);
        }
        let after = fstat(file.as_raw_fd(), &format!("could not re-inspect {label}"))?;
        if before != after || total != before.size {
            return Err(LauncherError::new(format!(
                "{label} changed while it was measured"
            )));
        }
        let actual = format!("sha256:{}", hex::encode(digest.finalize()));
        if actual != expected_digest {
            return Err(LauncherError::new(format!("{label} digest does not match")));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset {label}")))?;
        Ok(MeasuredFile {
            file,
            receipt: ReceiptFile {
                path: path.to_string_lossy().into_owned(),
                sha256: actual,
                metadata: before.receipt(),
            },
        })
    }

    fn measure_file(record: &FileRecord, label: &str, executable: bool) -> Result<MeasuredFile> {
        let fd = secure_open(&record.path, false, label)?;
        stable_digest_file(
            File::from(fd),
            &record.path,
            &record.sha256,
            label,
            false,
            executable,
            None,
        )
    }

    fn validate_measured_python(file: &mut File, python_version: &str) -> Result<()> {
        let before = fstat(file.as_raw_fd(), "could not inspect measured Python")?;
        if before.size > MAX_PYTHON_EXECUTABLE_BYTES as u64 {
            return Err(LauncherError::new(
                "python exceeds the bounded executable parser limit",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured Python"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read measured Python"))?;
        let after = fstat(file.as_raw_fd(), "could not re-inspect measured Python")?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "python changed while its ELF identity was validated",
            ));
        }
        validate_cpython_elf64(&bytes, python_version)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured Python"))?;
        Ok(())
    }

    fn create_sealable_memfd(name: &CStr, label: &str) -> Result<File> {
        // SAFETY: name is NUL-terminated and flags are valid.
        let raw_fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(errno_message(&format!("could not create {label} memfd")));
        }
        // SAFETY: raw_fd is newly returned and uniquely owned.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw_fd) }))
    }

    fn seal_memfd(mut file: File, label: &str) -> Result<OwnedFd> {
        file.flush()
            .map_err(|_| LauncherError::new(format!("could not flush {label}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset {label}")))?;
        // SAFETY: file descriptor is valid and the seal mask is supported for sealable memfds.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, IMMUTABLE_MEMFD_SEALS) } != 0 {
            return Err(errno_message(&format!("could not seal {label}")));
        }
        // SAFETY: the descriptor is valid and F_GET_SEALS returns the active mask.
        let active_seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if active_seals < 0 || active_seals & IMMUTABLE_MEMFD_SEALS != IMMUTABLE_MEMFD_SEALS {
            return Err(LauncherError::new(format!(
                "{label} immutable seals were not applied"
            )));
        }
        Ok(file.into())
    }

    fn measure_script(
        record: &FileRecord,
        label: &str,
        snapshot_name: &CStr,
    ) -> Result<MeasuredScript> {
        let source_fd = secure_open(&record.path, false, label)?;
        let mut snapshot = create_sealable_memfd(snapshot_name, label)?;
        let measured = stable_digest_file(
            File::from(source_fd),
            &record.path,
            &record.sha256,
            label,
            false,
            false,
            Some(&mut snapshot),
        )?;
        let snapshot_identity = fstat(
            snapshot.as_raw_fd(),
            &format!("could not inspect {label} snapshot"),
        )?;
        if snapshot_identity.size != measured.receipt.metadata.size {
            return Err(LauncherError::new(format!(
                "{label} snapshot size does not match measured source"
            )));
        }
        let snapshot = seal_memfd(snapshot, &format!("{label} snapshot"))?;
        Ok(MeasuredScript {
            snapshot,
            receipt: measured.receipt,
        })
    }

    fn read_manifest(cli: &Cli) -> Result<(LaunchManifest, ReceiptFile)> {
        let fd = secure_open(&cli.manifest, false, "manifest")?;
        let mut file = File::from(fd);
        let before = fstat(file.as_raw_fd(), "could not inspect manifest")?;
        require_secure_regular(before, "manifest", true, false)?;
        if before.size > MAX_MANIFEST_BYTES as u64 {
            return Err(LauncherError::new("manifest is too large"));
        }
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read manifest"))?;
        let after = fstat(file.as_raw_fd(), "could not re-inspect manifest")?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new("manifest changed while it was measured"));
        }
        let digest = sha256_prefixed(&bytes);
        let manifest = parse_manifest(&bytes)?;
        Ok((
            manifest,
            ReceiptFile {
                path: cli.manifest.to_string_lossy().into_owned(),
                sha256: digest,
                metadata: before.receipt(),
            },
        ))
    }

    fn read_release_provenance_identity(
        file: &mut File,
        expected_source_tree_digest: &str,
    ) -> Result<String> {
        let before = fstat(
            file.as_raw_fd(),
            "could not inspect measured release provenance",
        )?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured release provenance"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read measured release provenance"))?;
        let after = fstat(
            file.as_raw_fd(),
            "could not re-inspect measured release provenance",
        )?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "measured release provenance changed while it was parsed",
            ));
        }
        let identity: ReleaseProvenanceIdentity = serde_json::from_slice(&bytes)
            .map_err(|_| LauncherError::new("release provenance identity fields are invalid"))?;
        if identity.provenance.version != 2 {
            return Err(LauncherError::new(
                "production release provenance payload must use version 2",
            ));
        }
        if identity.provenance.source != "serverware-digest-pinned-production-release" {
            return Err(LauncherError::new(
                "release provenance was not generated in digest-pinned production mode",
            ));
        }
        require_sha256(&identity.provenance_digest, "provenanceDigest")?;
        require_digest_match(
            &identity.provenance.source_tree.digest,
            expected_source_tree_digest,
            "release provenance source tree",
        )?;
        Ok(identity.provenance_digest)
    }

    fn directory_entries(fd: RawFd, label: &str) -> Result<Vec<Vec<u8>>> {
        // SAFETY: dup returns an independent descriptor consumed by fdopendir.
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(errno_message(&format!("could not duplicate {label}")));
        }
        // SAFETY: duplicated is a directory descriptor and ownership transfers to DIR.
        let directory = unsafe { libc::fdopendir(duplicated) };
        if directory.is_null() {
            // SAFETY: fdopendir did not take ownership on failure.
            unsafe { libc::close(duplicated) };
            return Err(errno_message(&format!("could not enumerate {label}")));
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: directory remains valid until closed below.
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                break;
            }
            // SAFETY: d_name is NUL-terminated within dirent.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        // SAFETY: directory is valid and closes duplicated.
        if unsafe { libc::closedir(directory) } != 0 {
            return Err(errno_message(&format!("could not close {label}")));
        }
        names.sort();
        Ok(names)
    }

    fn hash_import_tree(
        directory_fd: RawFd,
        relative: &mut Vec<u8>,
        digest: &mut Sha256,
        label: &str,
    ) -> Result<()> {
        let before = fstat(directory_fd, &format!("could not inspect {label}"))?;
        require_secure_directory(before, label)?;
        for name in directory_entries(directory_fd, label)? {
            let c_name = cstring_bytes(&name, label)?;
            // SAFETY: directory fd and component remain valid for this call.
            let raw_fd = unsafe {
                libc::openat(
                    directory_fd,
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw_fd < 0 {
                return Err(errno_message(&format!("could not measure {label}")));
            }
            // SAFETY: raw_fd is newly returned and uniquely owned.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let identity = fstat(fd.as_raw_fd(), &format!("could not inspect {label}"))?;
            let old_len = relative.len();
            if !relative.is_empty() {
                relative.push(b'/');
            }
            relative.extend_from_slice(&name);
            let path_length = u64::try_from(relative.len())
                .map_err(|_| LauncherError::new("import root path is too long"))?;
            match identity.mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    require_secure_directory(identity, label)?;
                    digest.update(b"directory\0");
                    digest.update(path_length.to_be_bytes());
                    digest.update(relative.as_slice());
                    digest.update((identity.mode & 0o7777).to_be_bytes());
                    hash_import_tree(fd.as_raw_fd(), relative, digest, label)?;
                    let after = fstat(fd.as_raw_fd(), &format!("could not re-inspect {label}"))?;
                    if identity != after {
                        return Err(LauncherError::new(format!(
                            "{label} changed while it was measured"
                        )));
                    }
                }
                libc::S_IFREG => {
                    require_secure_regular(identity, label, false, false)?;
                    digest.update(b"file\0");
                    digest.update(path_length.to_be_bytes());
                    digest.update(relative.as_slice());
                    digest.update((identity.mode & 0o7777).to_be_bytes());
                    let mut file = File::from(fd);
                    let mut file_digest = Sha256::new();
                    let mut buffer = [0u8; 64 * 1024];
                    let mut total = 0u64;
                    loop {
                        let count = file
                            .read(&mut buffer)
                            .map_err(|_| LauncherError::new(format!("could not read {label}")))?;
                        if count == 0 {
                            break;
                        }
                        total += count as u64;
                        file_digest.update(&buffer[..count]);
                    }
                    let after = fstat(file.as_raw_fd(), &format!("could not re-inspect {label}"))?;
                    if identity != after || total != identity.size {
                        return Err(LauncherError::new(format!(
                            "{label} changed while it was measured"
                        )));
                    }
                    digest.update(total.to_be_bytes());
                    digest.update(file_digest.finalize());
                }
                _ => {
                    return Err(LauncherError::new(format!(
                        "{label} contains an unsupported filesystem entry"
                    )))
                }
            }
            relative.truncate(old_len);
        }
        let after = fstat(directory_fd, &format!("could not re-inspect {label}"))?;
        if before != after {
            return Err(LauncherError::new(format!(
                "{label} changed while it was measured"
            )));
        }
        Ok(())
    }

    fn measure_import_root(record: &ImportRootRecord, label: &str) -> Result<MeasuredImportRoot> {
        let fd = secure_open(&record.path, true, label)?;
        let identity = fstat(fd.as_raw_fd(), &format!("could not inspect {label}"))?;
        require_secure_directory(identity, label)?;
        let mut digest = Sha256::new();
        digest.update(b"serverware.importRoot/v1\0");
        hash_import_tree(fd.as_raw_fd(), &mut Vec::new(), &mut digest, label)?;
        let actual = format!("sha256:{}", hex::encode(digest.finalize()));
        require_digest_match(&actual, &record.sha256, label)?;
        Ok(MeasuredImportRoot {
            fd,
            receipt: ReceiptImportRoot {
                path: record.path.to_string_lossy().into_owned(),
                sha256: actual,
                metadata: identity.receipt(),
            },
        })
    }

    fn read_self() -> Result<ReceiptFile> {
        let path_bytes = std::fs::read_link("/proc/self/exe")
            .map_err(|_| LauncherError::new("could not resolve launcher executable"))?;
        require_normalized_absolute(&path_bytes, "launcher executable")?;
        let fd = secure_open(&path_bytes, false, "launcher executable")?;
        let measured = stable_digest_file(
            File::from(fd),
            &path_bytes,
            &format!(
                "sha256:{}",
                hex::encode({
                    let mut direct = File::open("/proc/self/exe")
                        .map_err(|_| LauncherError::new("could not open launcher executable"))?;
                    let mut hash = Sha256::new();
                    std::io::copy(&mut direct, &mut hash)
                        .map_err(|_| LauncherError::new("could not measure launcher executable"))?;
                    hash.finalize()
                })
            ),
            "launcher executable",
            false,
            true,
            None,
        )?;
        Ok(measured.receipt)
    }

    fn verify_launch(cli: &Cli) -> Result<VerifiedLaunch> {
        let launcher = read_self()?;
        let (manifest, manifest_receipt) = read_manifest(cli)?;
        let release_root_fd = secure_open(&manifest.release_root, true, "releaseRoot")?;
        let _state_directory = secure_open(&manifest.state_directory, true, "stateDirectory")?;
        let production_env =
            measure_file(&manifest.production_env, "productionEnv", false)?.receipt;
        let python_record = FileRecord {
            path: manifest.python.path.clone(),
            sha256: manifest.python.sha256.clone(),
        };
        let mut python = measure_file(&python_record, "python", true)?;
        let python_version = validate_python_layout(&manifest)?;
        validate_measured_python(&mut python.file, &python_version)?;
        let preflight = measure_script(
            &manifest.scripts.preflight,
            "scripts.preflight",
            c"serverware-preflight-script-snapshot",
        )?;
        let runner = measure_script(
            &manifest.scripts.runner,
            "scripts.runner",
            c"serverware-readiness-script-snapshot",
        )?;
        let compose_file = measure_file(&manifest.compose_file, "composeFile", false)?.receipt;
        let mut import_roots = Vec::new();
        for (index, record) in manifest.python.import_roots.iter().enumerate() {
            import_roots.push(measure_import_root(
                record,
                &format!("python.importRoots[{index}]"),
            )?);
        }
        let mut inputs = BTreeMap::new();
        let mut provenance_digest = None;
        for (name, record) in all_input_records(&manifest.inputs) {
            let mut measured = measure_file(record, name, false)?;
            if name == "releaseProvenance" {
                provenance_digest = Some(read_release_provenance_identity(
                    &mut measured.file,
                    &manifest.source_tree_digest,
                )?);
            }
            inputs.insert(name.to_string(), measured.receipt);
        }
        Ok(VerifiedLaunch {
            manifest,
            launcher,
            manifest_receipt,
            python,
            preflight,
            runner,
            import_roots,
            production_env,
            compose_file,
            inputs,
            provenance_digest: provenance_digest
                .ok_or_else(|| LauncherError::new("release provenance input was not measured"))?,
            release_root_fd,
        })
    }

    fn revalidate_verified_launch(cli: &Cli, verified: &VerifiedLaunch) -> Result<()> {
        let launcher_record = FileRecord {
            path: PathBuf::from(&verified.launcher.path),
            sha256: verified.launcher.sha256.clone(),
        };
        let launcher = measure_file(&launcher_record, "launcher executable", true)?;
        if launcher.receipt != verified.launcher {
            return Err(LauncherError::new(
                "launcher executable changed after launch authorization",
            ));
        }
        let (_, manifest_receipt) = read_manifest(cli)?;
        if manifest_receipt != verified.manifest_receipt {
            return Err(LauncherError::new(
                "manifest changed after launch authorization",
            ));
        }
        let production_env =
            measure_file(&verified.manifest.production_env, "productionEnv", false)?;
        if production_env.receipt != verified.production_env {
            return Err(LauncherError::new(
                "production environment changed after launch authorization",
            ));
        }
        let python_record = FileRecord {
            path: verified.manifest.python.path.clone(),
            sha256: verified.manifest.python.sha256.clone(),
        };
        let python = measure_file(&python_record, "python", true)?;
        if python.receipt != verified.python.receipt {
            return Err(LauncherError::new(
                "Python executable changed after launch authorization",
            ));
        }
        for (index, record) in verified.manifest.python.import_roots.iter().enumerate() {
            let measured = measure_import_root(
                record,
                &format!("python.importRoots[{index}] post-authorization"),
            )?;
            if measured.receipt != verified.import_roots[index].receipt {
                return Err(LauncherError::new(
                    "Python import tree changed after launch authorization",
                ));
            }
        }
        Ok(())
    }

    fn random_launch_id() -> Result<String> {
        let mut bytes = [0u8; 32];
        let mut offset = 0usize;
        while offset < bytes.len() {
            // SAFETY: the remaining byte slice is writable for the supplied length.
            let count = unsafe {
                libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(LauncherError::new("could not obtain launch randomness"));
            }
            if count == 0 {
                return Err(LauncherError::new("launch randomness source returned EOF"));
            }
            offset += count as usize;
        }
        Ok(hex::encode(bytes))
    }

    fn boot_id_digest() -> Result<String> {
        let raw = std::fs::read("/proc/sys/kernel/random/boot_id")
            .map_err(|_| LauncherError::new("could not read kernel boot identity"))?;
        let mut trimmed = raw.as_slice();
        while matches!(trimmed.last(), Some(b'\n' | b'\r')) {
            trimmed = &trimmed[..trimmed.len() - 1];
        }
        if trimmed.is_empty() || trimmed.len() > 128 {
            return Err(LauncherError::new("kernel boot identity is invalid"));
        }
        Ok(sha256_prefixed(trimmed))
    }

    fn unix_time_seconds() -> Result<u64> {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: value points to writable storage for one timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, value.as_mut_ptr()) } != 0 {
            return Err(errno_message("could not read realtime clock"));
        }
        // SAFETY: successful clock_gettime initialized value.
        let value = unsafe { value.assume_init() };
        u64::try_from(value.tv_sec)
            .map_err(|_| LauncherError::new("realtime clock is before the Unix epoch"))
    }

    fn build_authorization_request(
        verified: &VerifiedLaunch,
        launcher_nonce: String,
        boot_id_sha256: String,
    ) -> Result<LaunchAuthorizationRequest> {
        let release_provenance = verified
            .inputs
            .get("releaseProvenance")
            .ok_or_else(|| LauncherError::new("release provenance input is missing"))?;
        let reproducible_build = verified
            .inputs
            .get("reproducibleBuildVerification")
            .ok_or_else(|| LauncherError::new("reproducible build input is missing"))?;
        Ok(LaunchAuthorizationRequest {
            api_version: AUTHORIZATION_REQUEST_API_VERSION.to_string(),
            kind: AUTHORIZATION_REQUEST_KIND.to_string(),
            launcher_nonce,
            boot_id_sha256,
            launcher_sha256: verified.launcher.sha256.clone(),
            manifest_sha256: verified.manifest_receipt.sha256.clone(),
            release_provenance_sha256: release_provenance.sha256.clone(),
            provenance_digest: verified.provenance_digest.clone(),
            reproducible_build_verification_sha256: reproducible_build.sha256.clone(),
            source_tree_digest: verified.manifest.source_tree_digest.clone(),
            deployment_audience: verified.manifest.authorization.deployment_audience.clone(),
            deployment_identity_sha256: verified
                .manifest
                .authorization
                .deployment_identity_sha256
                .clone(),
            release_sequence: verified.manifest.authorization.release_sequence,
            rollback_epoch: verified.manifest.authorization.rollback_epoch,
        })
    }

    fn poll_socket(
        fd: RawFd,
        events: libc::c_short,
        deadline: Instant,
        timeout_code: &str,
    ) -> Result<()> {
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(LauncherError::new(format!(
                    "{timeout_code}: launch authority relay timed out"
                )));
            }
            let timeout_millis = remaining
                .as_millis()
                .min(AUTHORIZATION_TIMEOUT_MILLIS as u128)
                .max(1) as i32;
            // SAFETY: poll_fd points to one initialized poll descriptor.
            let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_millis) };
            if result > 0 {
                if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err(LauncherError::new(
                        "LAUTH_SOCKET_UNAVAILABLE: launch authority relay failed",
                    ));
                }
                if poll_fd.revents & events != 0 {
                    return Ok(());
                }
                return Err(LauncherError::new(
                    "LAUTH_SOCKET_UNAVAILABLE: launch authority relay returned invalid readiness",
                ));
            }
            if result == 0 {
                return Err(LauncherError::new(format!(
                    "{timeout_code}: launch authority relay timed out"
                )));
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(errno_message(
                    "LAUTH_SOCKET_UNAVAILABLE: could not poll launch authority relay",
                ));
            }
        }
    }

    fn connect_authority_socket(deadline: Instant) -> Result<OwnedFd> {
        let metadata = std::fs::symlink_metadata(AUTHORIZATION_SOCKET_PATH).map_err(|_| {
            LauncherError::new("LAUTH_SOCKET_UNAVAILABLE: launch authority socket is unavailable")
        })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o002 != 0
        {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: launch authority socket metadata is not trusted",
            ));
        }

        // SAFETY: socket arguments describe a Unix sequenced-packet socket.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw_fd < 0 {
            return Err(errno_message(
                "LAUTH_SOCKET_UNAVAILABLE: could not create launch authority socket",
            ));
        }
        // SAFETY: raw_fd is newly allocated and ownership transfers to OwnedFd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let path = AUTHORIZATION_SOCKET_PATH.as_bytes();
        if path.len() + 1
            > unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
                .sun_path
                .len()
        {
            return Err(LauncherError::new(
                "LAUTH_SOCKET_UNAVAILABLE: launch authority socket path is too long",
            ));
        }
        // SAFETY: sockaddr_un is valid when zero-initialized before its fields are assigned.
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, source) in address.sun_path.iter_mut().zip(path.iter().copied()) {
            *target = source as libc::c_char;
        }
        let address_length = (size_of::<libc::sa_family_t>() + path.len() + 1)
            .try_into()
            .map_err(|_| LauncherError::new("launch authority socket path length is invalid"))?;
        // SAFETY: address contains a NUL-terminated Unix socket path for address_length bytes.
        let connect_result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_length,
            )
        };
        if connect_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(LauncherError::new(format!(
                    "LAUTH_SOCKET_UNAVAILABLE: could not connect to launch authority relay: {error}"
                )));
            }
            poll_socket(fd.as_raw_fd(), libc::POLLOUT, deadline, "LAUTH_TIMEOUT")?;
            let mut socket_error: libc::c_int = 0;
            let mut socket_error_length = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: output pointers describe one socket error integer.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut socket_error_length,
                )
            } != 0
                || socket_error != 0
            {
                return Err(LauncherError::new(
                    "LAUTH_SOCKET_UNAVAILABLE: launch authority relay rejected the connection",
                ));
            }
        }

        let mut credentials = MaybeUninit::<libc::ucred>::uninit();
        let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: output pointers describe one ucred structure.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut credentials_length,
            )
        } != 0
            || credentials_length as usize != size_of::<libc::ucred>()
        {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: could not authenticate launch authority relay peer",
            ));
        }
        // SAFETY: successful getsockopt initialized credentials.
        let credentials = unsafe { credentials.assume_init() };
        if credentials.uid != 0 || credentials.gid != 0 {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: launch authority relay must run as root",
            ));
        }
        Ok(fd)
    }

    fn exchange_launch_authorization(
        request: LaunchAuthorizationRequest,
    ) -> Result<ReceiptLaunchAuthorization> {
        let request_bytes = canonical_json_bytes(&request)?;
        if request_bytes.len() > AUTHORIZATION_MAX_BYTES {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization request is too large",
            ));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(AUTHORIZATION_TIMEOUT_MILLIS as u64))
            .ok_or_else(|| LauncherError::new("launch authorization deadline overflow"))?;
        let key = compiled_authority_public_key()?;
        let fd = connect_authority_socket(deadline)?;
        poll_socket(fd.as_raw_fd(), libc::POLLOUT, deadline, "LAUTH_TIMEOUT")?;
        // SAFETY: request_bytes is readable and fd is a connected sequenced-packet socket.
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                request_bytes.as_ptr().cast(),
                request_bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 || sent as usize != request_bytes.len() {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization request was not sent atomically",
            ));
        }

        poll_socket(fd.as_raw_fd(), libc::POLLIN, deadline, "LAUTH_TIMEOUT")?;
        let mut response = vec![0u8; AUTHORIZATION_MAX_BYTES];
        // SAFETY: response is writable and MSG_TRUNC reports the complete packet length.
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                libc::MSG_TRUNC,
            )
        };
        if received <= 0 || received as usize > response.len() {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization response is empty or truncated",
            ));
        }
        response.truncate(received as usize);
        let envelope: LaunchAuthorizationEnvelope =
            serde_json::from_slice(&response).map_err(|_| {
                LauncherError::new(
                    "LAUTH_SCHEMA_INVALID: launch authorization response is invalid JSON",
                )
            })?;
        let canonical = canonical_json_bytes(&envelope)?;
        if canonical != response {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization response is not canonical JSON",
            ));
        }
        verify_launch_authorization(request, envelope, &key, unix_time_seconds()?)
    }

    fn build_receipt(
        verified: &VerifiedLaunch,
        launch_authorization: ReceiptLaunchAuthorization,
        preflight_argv: &[String],
        readiness_argv: &[String],
    ) -> Result<BootstrapReceipt> {
        Ok(BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: launch_authorization.request.launcher_nonce.clone(),
            boot_id_sha256: launch_authorization.request.boot_id_sha256.clone(),
            launcher: verified.launcher.clone(),
            manifest: verified.manifest_receipt.clone(),
            source_tree_digest: verified.manifest.source_tree_digest.clone(),
            launch_authorization,
            production_env: verified.production_env.clone(),
            python: ReceiptPython {
                path: verified.python.receipt.path.clone(),
                sha256: verified.python.receipt.sha256.clone(),
                metadata: verified.python.receipt.metadata.clone(),
                import_roots: verified
                    .import_roots
                    .iter()
                    .map(|root| root.receipt.clone())
                    .collect(),
            },
            scripts: ReceiptScripts {
                preflight: verified.preflight.receipt.clone(),
                runner: verified.runner.receipt.clone(),
            },
            compose_file: verified.compose_file.clone(),
            inputs: verified.inputs.clone(),
            argv: ReceiptArgv {
                preflight_sha256: argv_digest(preflight_argv)?,
                readiness_sha256: argv_digest(readiness_argv)?,
            },
            environment: environment_commitment()?,
        })
    }

    fn create_sealed_receipt(bytes: &[u8]) -> Result<OwnedFd> {
        let name = c"serverware-bootstrap-receipt";
        let mut file = create_sealable_memfd(name, "bootstrap receipt")?;
        file.write_all(bytes)
            .map_err(|_| LauncherError::new("could not write bootstrap receipt"))?;
        let file = seal_memfd(file, "bootstrap receipt")?;
        if file.as_raw_fd() == RECEIPT_FD {
            clear_cloexec(RECEIPT_FD)?;
            return Ok(file);
        }
        // SAFETY: dup3 atomically replaces the fixed descriptor and clears CLOEXEC.
        if unsafe { libc::dup3(file.as_raw_fd(), RECEIPT_FD, 0) } < 0 {
            return Err(errno_message(
                "could not install fixed bootstrap receipt descriptor",
            ));
        }
        // SAFETY: RECEIPT_FD is now uniquely owned independently of file.
        Ok(unsafe { OwnedFd::from_raw_fd(RECEIPT_FD) })
    }

    fn clear_cloexec(fd: RawFd) -> Result<()> {
        // SAFETY: fd is valid.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(errno_message(
                "could not inspect inherited descriptor flags",
            ));
        }
        // SAFETY: fd is valid and flags only clears FD_CLOEXEC.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
            return Err(errno_message("could not retain measured descriptor"));
        }
        Ok(())
    }

    fn close_range_segment(first: u32, last: u32) -> bool {
        if first > last {
            return true;
        }
        // SAFETY: close_range has no memory-safety preconditions.
        unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) == 0 }
    }

    fn close_unrelated_descriptors(keep: &[RawFd]) -> Result<()> {
        let mut retained = keep
            .iter()
            .copied()
            .filter(|fd| *fd >= 3)
            .collect::<Vec<_>>();
        retained.sort_unstable();
        retained.dedup();
        let mut first = 3u32;
        for fd in &retained {
            let fd = *fd as u32;
            if first < fd && !close_range_segment(first, fd - 1) {
                return close_unrelated_descriptors_fallback(&retained);
            }
            first = fd.saturating_add(1);
        }
        if !close_range_segment(first, u32::MAX) {
            return close_unrelated_descriptors_fallback(&retained);
        }
        Ok(())
    }

    fn close_unrelated_descriptors_fallback(keep: &[RawFd]) -> Result<()> {
        let entries = std::fs::read_dir("/proc/self/fd").map_err(|error| {
            LauncherError::new(format!(
                "could not enumerate inherited descriptors through /proc/self/fd: {error}"
            ))
        })?;
        let mut descriptors = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                LauncherError::new(format!(
                    "could not enumerate inherited descriptors through /proc/self/fd: {error}"
                ))
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                LauncherError::new("/proc/self/fd contained a non-UTF-8 descriptor name")
            })?;
            let fd = name.parse::<RawFd>().map_err(|_| {
                LauncherError::new("/proc/self/fd contained an invalid descriptor name")
            })?;
            if fd >= 3 {
                descriptors.push(fd);
            }
        }
        descriptors.sort_unstable();
        descriptors.dedup();
        for fd in descriptors {
            if !keep.contains(&fd) {
                // SAFETY: closing an invalid descriptor is harmless here.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    fn python_bootstrap(script_fd: RawFd, import_fds: &[RawFd]) -> String {
        let roots = import_fds
            .iter()
            .map(|fd| format!("'/proc/self/fd/{fd}'"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{PYTHON_BOOTSTRAP_PREFIX}fd={script_fd}\n\
             os.environ['SERVERWARE_EXECUTING_SCRIPT_FD']=str(fd)\n\
             sys.path[:]=[{roots}]\n\
             sys.path_importer_cache.clear()\n\
             sys.argv=sys.argv[1:]\n\
             os.lseek(fd,0,os.SEEK_SET)\n\
             size=os.fstat(fd).st_size\n\
             data=b''\n\
             while len(data)<size:\n data+=os.read(fd,min(65536,size-len(data)))\n\
             if len(data)!=size: raise RuntimeError('measured Python script changed while executing')\n\
             scope={{'__name__':'__main__','__file__':sys.argv[0],'__package__':None,'__cached__':None}}\n\
             exec(compile(data,sys.argv[0],'exec',dont_inherit=True),scope,scope)"
        )
    }

    fn cstring_vector(values: &[String], label: &str) -> Result<Vec<CString>> {
        values
            .iter()
            .map(|value| {
                CString::new(value.as_bytes())
                    .map_err(|_| LauncherError::new(format!("{label} contains NUL")))
            })
            .collect()
    }

    fn child_error(message: &str) -> ! {
        let prefix = b"serverware production launcher child error: ";
        // SAFETY: static and borrowed byte buffers are valid for their lengths.
        unsafe {
            libc::write(libc::STDERR_FILENO, prefix.as_ptr().cast(), prefix.len());
            libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
            libc::write(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1);
            libc::_exit(126);
        }
    }

    fn run_phase(
        python: &MeasuredFile,
        import_roots: &[MeasuredImportRoot],
        release_root_fd: RawFd,
        script: &MeasuredScript,
        script_argv: &[String],
        receipt_fd: RawFd,
        receipt_sha256: &str,
    ) -> Result<i32> {
        // SAFETY: fork is called from the single-threaded launcher before any worker threads exist.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(errno_message("could not fork production phase"));
        }
        if child == 0 {
            // SAFETY: a fixed restrictive umask has no memory-safety preconditions.
            unsafe { libc::umask(0o077) };
            let dev_null = c"/dev/null";
            // SAFETY: path is static and flags are valid.
            let stdin_fd =
                unsafe { libc::open(dev_null.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if stdin_fd < 0 {
                child_error("could not open /dev/null");
            }
            // SAFETY: descriptors are valid.
            if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
                child_error("could not sanitize stdin");
            }
            if stdin_fd > libc::STDERR_FILENO {
                // SAFETY: descriptor is no longer needed after dup2.
                unsafe { libc::close(stdin_fd) };
            }
            // SAFETY: release root descriptor is a verified directory.
            if unsafe { libc::fchdir(release_root_fd) } != 0 {
                child_error("could not enter release root");
            }

            let python_fd = python.file.as_raw_fd();
            let script_fd = script.snapshot.as_raw_fd();
            let import_fds = import_roots
                .iter()
                .map(|root| root.fd.as_raw_fd())
                .collect::<Vec<_>>();
            for fd in std::iter::once(python_fd)
                .chain(std::iter::once(script_fd))
                .chain(import_fds.iter().copied())
                .chain(std::iter::once(receipt_fd))
            {
                if clear_cloexec(fd).is_err() {
                    child_error("could not retain a measured descriptor");
                }
            }
            // Both phases share one open-file description; reset it before each exec.
            // SAFETY: receipt_fd is the verified sealed memfd.
            if unsafe { libc::lseek(receipt_fd, 0, libc::SEEK_SET) } != 0 {
                child_error("could not reset bootstrap receipt descriptor");
            }
            let mut keep = vec![python_fd, script_fd, receipt_fd];
            keep.extend(import_fds.iter().copied());
            if close_unrelated_descriptors(&keep).is_err() {
                child_error("could not close inherited descriptors");
            }

            let bootstrap = python_bootstrap(script_fd, &import_fds);
            let mut python_argv = vec![
                python.receipt.path.clone(),
                "-I".to_string(),
                "-S".to_string(),
                "-B".to_string(),
                "-u".to_string(),
                "-c".to_string(),
                bootstrap,
            ];
            python_argv.extend(script_argv.iter().cloned());
            let argv = match cstring_vector(&python_argv, "constructed argv") {
                Ok(value) => value,
                Err(_) => child_error("constructed argv is invalid"),
            };
            let argv_pointers = argv
                .iter()
                .map(|value| value.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let environment = fixed_environment(receipt_sha256)
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>();
            let environment = match cstring_vector(&environment, "fixed environment") {
                Ok(value) => value,
                Err(_) => child_error("fixed environment is invalid"),
            };
            let environment_pointers = environment
                .iter()
                .map(|value| value.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let empty = c"";
            // SAFETY: all pointers refer to live CString storage and python_fd is verified.
            unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    python_fd,
                    empty.as_ptr(),
                    argv_pointers.as_ptr(),
                    environment_pointers.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
            }
            child_error("descriptor-pinned Python execution failed");
        }

        let mut status = 0;
        loop {
            // SAFETY: child is a direct child PID and status points to writable memory.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            if waited == child {
                break;
            }
            if waited < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(errno_message("could not wait for production phase"));
        }
        if libc::WIFEXITED(status) {
            Ok(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Ok(128 + libc::WTERMSIG(status))
        } else {
            Err(LauncherError::new(
                "production phase ended in an unsupported process state",
            ))
        }
    }

    pub(super) fn run(cli: Cli) -> Result<i32> {
        // SAFETY: geteuid has no memory-safety preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(LauncherError::new(
                "production launcher must run with effective UID 0",
            ));
        }
        let verified = verify_launch(&cli)?;
        let authorization_request =
            build_authorization_request(&verified, random_launch_id()?, boot_id_digest()?)?;
        let launch_authorization = exchange_launch_authorization(authorization_request)?;
        revalidate_verified_launch(&cli, &verified)?;
        let authorization_statement = launch_authorization.envelope.statement.clone();
        let preflight_argv = build_preflight_argv(&verified.manifest);
        let readiness_argv = build_readiness_argv(&verified.manifest);
        let receipt = build_receipt(
            &verified,
            launch_authorization,
            &preflight_argv,
            &readiness_argv,
        )?;
        let receipt_bytes = canonical_json_bytes(&receipt)?;
        let receipt_sha256 = sha256_prefixed(&receipt_bytes);
        let receipt_fd = create_sealed_receipt(&receipt_bytes)?;

        require_authorization_current(&authorization_statement, unix_time_seconds()?)?;
        let preflight_status = run_phase(
            &verified.python,
            &verified.import_roots,
            verified.release_root_fd.as_raw_fd(),
            &verified.preflight,
            &preflight_argv,
            receipt_fd.as_raw_fd(),
            &receipt_sha256,
        )?;
        if preflight_status != 0 {
            return Ok(preflight_status);
        }
        revalidate_verified_launch(&cli, &verified)?;
        drop(verified.preflight);
        require_authorization_current(&authorization_statement, unix_time_seconds()?)?;
        run_phase(
            &verified.python,
            &verified.import_roots,
            verified.release_root_fd.as_raw_fd(),
            &verified.runner,
            &readiness_argv,
            receipt_fd.as_raw_fd(),
            &receipt_sha256,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const FD_FALLBACK_CHILD_ENV: &str = "SERVERWARE_TEST_FD_FALLBACK_CHILD";

        #[test]
        fn clear_cloexec_retains_descriptor_across_exec() {
            let mut descriptors = [-1; 2];
            // SAFETY: descriptors points to storage for both pipe descriptors.
            assert_eq!(
                unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
            let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
            // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
            let _write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };

            // SAFETY: read_fd is valid.
            let before = unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(before & libc::FD_CLOEXEC, 0);
            clear_cloexec(read_fd.as_raw_fd()).unwrap();
            // SAFETY: read_fd remains valid.
            let after = unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(after & libc::FD_CLOEXEC, 0);
        }

        #[test]
        fn proc_fd_fallback_ignores_a_reduced_soft_descriptor_limit() {
            if std::env::var_os(FD_FALLBACK_CHILD_ENV).is_none() {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::tests::proc_fd_fallback_ignores_a_reduced_soft_descriptor_limit",
                        "--nocapture",
                    ])
                    .env(FD_FALLBACK_CHILD_ENV, "1")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "isolated descriptor fallback test failed: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return;
            }

            let source = File::open("/dev/null").unwrap();
            let unrelated_fd = 256;
            let retained_fd = 257;
            let mut original_limit = MaybeUninit::<libc::rlimit>::uninit();
            // SAFETY: original_limit points to writable storage for one rlimit.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original_limit.as_mut_ptr()) },
                0
            );
            // SAFETY: successful getrlimit initialized original_limit.
            let original_limit = unsafe { original_limit.assume_init() };
            assert!(original_limit.rlim_max > retained_fd as libc::rlim_t);
            let raised_limit = libc::rlimit {
                rlim_cur: original_limit
                    .rlim_cur
                    .max((retained_fd + 1) as libc::rlim_t),
                rlim_max: original_limit.rlim_max,
            };
            // SAFETY: raised_limit does not exceed the existing hard limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised_limit) },
                0
            );
            // SAFETY: source is valid and the target descriptors are below the soft limit.
            assert_eq!(
                unsafe { libc::dup2(source.as_raw_fd(), unrelated_fd) },
                unrelated_fd
            );
            assert_eq!(
                unsafe { libc::dup2(source.as_raw_fd(), retained_fd) },
                retained_fd
            );

            let lowered_limit = libc::rlimit {
                rlim_cur: 64,
                rlim_max: original_limit.rlim_max,
            };
            // SAFETY: lowering the soft limit preserves the hard limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered_limit) },
                0
            );
            let mut keep = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .parse::<RawFd>()
                        .unwrap()
                })
                .filter(|fd| *fd >= 3 && *fd != unrelated_fd)
                .collect::<Vec<_>>();
            keep.sort_unstable();
            keep.dedup();
            close_unrelated_descriptors_fallback(&keep).unwrap();

            // SAFETY: fcntl only inspects descriptor validity.
            assert_eq!(unsafe { libc::fcntl(unrelated_fd, libc::F_GETFD) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
            assert!(unsafe { libc::fcntl(retained_fd, libc::F_GETFD) } >= 0);
            // SAFETY: restoring the original process limit and closing the raw duplicate are valid.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit) },
                0
            );
            unsafe { libc::close(retained_fd) };
        }

        #[test]
        fn sealed_script_snapshots_preserve_content_and_reject_mutation() {
            let expected = b"print('verified snapshot')\n";
            let mut snapshot =
                create_sealable_memfd(c"serverware-test-script-snapshot", "test script snapshot")
                    .unwrap();
            snapshot.write_all(expected).unwrap();
            let snapshot = seal_memfd(snapshot, "test script snapshot").unwrap();

            // SAFETY: snapshot is a valid sealed memfd.
            let seals = unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_GET_SEALS) };
            assert_eq!(seals & IMMUTABLE_MEMFD_SEALS, IMMUTABLE_MEMFD_SEALS);

            let mut snapshot = File::from(snapshot);
            let mut actual = Vec::new();
            snapshot.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, expected);
            let error = snapshot.write_all(b"mutated").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
    }
}

fn main() {
    let cli = match parse_cli(env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("serverware production launcher error: {error}");
            std::process::exit(2);
        }
    };

    #[cfg(target_os = "linux")]
    match linux::run(cli) {
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("serverware production launcher error: {error}");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        eprintln!("serverware production launcher error: launcher execution requires Linux");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn file(path: &str, character: char) -> Value {
        json!({"path": path, "sha256": digest(character)})
    }

    fn write_u16(target: &mut [u8], offset: usize, value: u16) {
        target[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(target: &mut [u8], offset: usize, value: u32) {
        target[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(target: &mut [u8], offset: usize, value: u64) {
        target[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_cpython_elf(machine: u16, symbol: &[u8], needed: &[u8]) -> Vec<u8> {
        let mut strings = vec![0];
        let symbol_name_offset = strings.len();
        strings.extend_from_slice(symbol);
        strings.push(0);
        let needed_offset = strings.len();
        strings.extend_from_slice(needed);
        strings.push(0);

        let program_offset = ELF64_HEADER_SIZE;
        let strings_offset = program_offset + ELF64_PROGRAM_HEADER_SIZE;
        let symbols_offset = strings_offset + strings.len();
        let symbols_size = ELF64_SYMBOL_SIZE * 2;
        let dynamic_offset = symbols_offset + symbols_size;
        let dynamic_size = ELF64_DYNAMIC_SIZE * 2;
        let sections_offset = dynamic_offset + dynamic_size;
        let mut value = vec![0u8; sections_offset + ELF64_SECTION_HEADER_SIZE * 4];
        value[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        write_u16(&mut value, 16, 3);
        write_u16(&mut value, 18, machine);
        write_u32(&mut value, 20, 1);
        write_u64(&mut value, 32, program_offset as u64);
        write_u64(&mut value, 40, sections_offset as u64);
        write_u16(&mut value, 52, ELF64_HEADER_SIZE as u16);
        write_u16(&mut value, 54, ELF64_PROGRAM_HEADER_SIZE as u16);
        write_u16(&mut value, 56, 1);
        write_u16(&mut value, 58, ELF64_SECTION_HEADER_SIZE as u16);
        write_u16(&mut value, 60, 4);
        value[strings_offset..strings_offset + strings.len()].copy_from_slice(&strings);
        write_u32(
            &mut value,
            symbols_offset + ELF64_SYMBOL_SIZE,
            symbol_name_offset as u32,
        );
        write_u64(&mut value, dynamic_offset, ELF_DYNAMIC_NEEDED);
        write_u64(&mut value, dynamic_offset + 8, needed_offset as u64);

        let mut section = |index: usize,
                           section_type: u32,
                           offset: usize,
                           size: usize,
                           link: u32,
                           entry_size: usize| {
            let base = sections_offset + index * ELF64_SECTION_HEADER_SIZE;
            write_u32(&mut value, base + 4, section_type);
            write_u64(&mut value, base + 24, offset as u64);
            write_u64(&mut value, base + 32, size as u64);
            write_u32(&mut value, base + 40, link);
            write_u64(&mut value, base + 48, 1);
            write_u64(&mut value, base + 56, entry_size as u64);
        };
        section(1, ELF_SECTION_STRTAB, strings_offset, strings.len(), 0, 0);
        section(
            2,
            ELF_SECTION_DYNSYM,
            symbols_offset,
            symbols_size,
            1,
            ELF64_SYMBOL_SIZE,
        );
        section(
            3,
            ELF_SECTION_DYNAMIC,
            dynamic_offset,
            dynamic_size,
            1,
            ELF64_DYNAMIC_SIZE,
        );
        value
    }

    fn manifest_json() -> Value {
        let root = "/opt/serverware/releases/release-a";
        json!({
            "apiVersion": LAUNCH_MANIFEST_API_VERSION,
            "kind": LAUNCH_MANIFEST_KIND,
            "releaseRoot": root,
            "stateDirectory": "/var/lib/serverware/production-proof",
            "sourceTreeDigest": digest('a'),
            "authorization": {
                "deploymentAudience": "prod.us-east-1.primary",
                "deploymentIdentitySha256": digest('0'),
                "releaseSequence": 42,
                "rollbackEpoch": 7
            },
            "productionEnv": file("/etc/serverware/production-readiness.env", 'b'),
            "python": {
                "path": format!("{root}/runtime/python/bin/python3"),
                "sha256": digest('c'),
                "importRoots": [
                    {"path": root, "sha256": digest('d')},
                    {"path": format!("{root}/runtime/python/lib/python3.11"), "sha256": digest('e')},
                    {"path": format!("{root}/runtime/python/lib/python3.11/lib-dynload"), "sha256": digest('f')},
                    {"path": format!("{root}/vendor"), "sha256": digest('1')}
                ]
            },
            "scripts": {
                "preflight": file(&format!("{root}/scripts/production_host_preflight.py"), 'e'),
                "runner": file(&format!("{root}/scripts/run_production_readiness.py"), 'f')
            },
            "composeFile": file(&format!("{root}/docker-compose.production.yml"), '1'),
            "inputs": {
                "productionImagesBuild": file(&format!("{root}/evidence/production-images-build.json"), '2'),
                "productionImagesEnv": file(&format!("{root}/evidence/production-images.env"), '3'),
                "productionImagesPublished": file(&format!("{root}/evidence/production-images-published.json"), '4'),
                "releaseProvenanceSummary": file(&format!("{root}/evidence/release-provenance-summary.json"), '5'),
                "releaseProvenance": file(&format!("{root}/evidence/release-provenance.json"), '6'),
                "imageSignaturesSummary": file(&format!("{root}/evidence/image-signatures-summary.json"), '7'),
                "imageSignatures": file(&format!("{root}/evidence/image-signatures.json"), '8'),
                "bench": file(&format!("{root}/evidence/bench.json"), '9'),
                "kmsMaterials": file(&format!("{root}/evidence/kms-materials.json"), 'a'),
                "policyBundle": file(&format!("{root}/evidence/policy-bundle.json"), 'b'),
                "policyTrustedPublicKey": file(&format!("{root}/evidence/policy.pem"), 'c'),
                "policyIdentityVerification": file(&format!("{root}/evidence/policy-identity.json"), 'd'),
                "policyActivationVerification": file(&format!("{root}/evidence/policy-activation.json"), 'e'),
                "policyActivationSignature": file(&format!("{root}/evidence/policy-activation.sig"), 'f'),
                "policyActivationTrustedPublicKey": file(&format!("{root}/evidence/policy-activation.pem"), '1'),
                "reproducibleBuildVerification": file(&format!("{root}/evidence/reproducible-build.json"), '2'),
                "reproducibleBuildSignature": file(&format!("{root}/evidence/reproducible-build.sig"), '3'),
                "reproducibleBuildTrustedPublicKey": file(&format!("{root}/evidence/reproducible-build.pem"), '4')
            },
            "outputs": {
                "configOut": "/var/lib/serverware/production-proof/readiness-config.json",
                "claimsFile": "/var/lib/serverware/production-proof/claims.json",
                "nitroEvidenceOut": "/var/lib/serverware/production-proof/nitro-evidence.json",
                "readinessOut": "/var/lib/serverware/production-proof/readiness.json",
                "completionProofOut": "/var/lib/serverware/production-proof/completion-proof.json",
                "proxyProofSummaryOut": "/var/lib/serverware/production-proof/proxy-proof-summary.json",
                "productionHostPreflight": "/var/lib/serverware/production-proof/host-preflight.json"
            }
        })
    }

    fn manifest() -> LaunchManifest {
        parse_manifest(&serde_json::to_vec(&manifest_json()).unwrap()).unwrap()
    }

    #[test]
    fn cli_is_closed_and_requires_exact_arguments() {
        let cli = parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/etc/serverware/launch.json"),
        ])
        .unwrap();
        assert_eq!(cli.manifest, Path::new("/etc/serverware/launch.json"));
        assert!(parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/x"),
            OsString::from("--manifest"),
            OsString::from("/y"),
        ])
        .is_err());
        assert!(parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/x"),
            OsString::from("--extra"),
            OsString::from("value"),
        ])
        .is_err());
    }

    #[test]
    fn digest_validation_is_lowercase_and_exact() {
        assert!(require_sha256(&digest('a'), "test").is_ok());
        assert!(require_sha256(&digest('A'), "test").is_err());
        assert!(require_sha256("sha256:abc", "test").is_err());
        assert!(require_sha256(&format!("sha256:{}g", "a".repeat(63)), "test").is_err());
        assert!(require_digest_match(&digest('a'), &digest('a'), "import root").is_ok());
        assert!(require_digest_match(&digest('a'), &digest('b'), "import root").is_err());
    }

    #[test]
    fn paths_and_output_names_are_normalized_and_confined() {
        assert!(require_normalized_absolute(Path::new("/opt/release"), "test").is_ok());
        assert!(require_normalized_absolute(Path::new("opt/release"), "test").is_err());
        assert!(require_normalized_absolute(Path::new("/opt/../etc"), "test").is_err());
        assert!(validate_output_path(
            Path::new("/var/lib/serverware/production-proof/proof.json"),
            Path::new("/var/lib/serverware/production-proof"),
            "test"
        )
        .is_ok());
        assert!(validate_output_path(
            Path::new("/var/lib/serverware/proof.json"),
            Path::new("/var/lib/serverware/production-proof"),
            "test"
        )
        .is_err());
        let mut value = manifest_json();
        value["inputs"]["bench"]["path"] = json!("/tmp/bench.json");
        assert!(parse_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn python_runtime_layout_is_exact_and_ordered() {
        assert!(parse_manifest(&serde_json::to_vec(&manifest_json()).unwrap()).is_ok());

        let mut missing = manifest_json();
        missing["python"]["importRoots"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(parse_manifest(&serde_json::to_vec(&missing).unwrap()).is_err());

        let mut reordered = manifest_json();
        reordered["python"]["importRoots"]
            .as_array_mut()
            .unwrap()
            .swap(1, 2);
        assert!(parse_manifest(&serde_json::to_vec(&reordered).unwrap()).is_err());

        let mut wrong_dynload = manifest_json();
        wrong_dynload["python"]["importRoots"][2]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/lib-dynload");
        assert!(parse_manifest(&serde_json::to_vec(&wrong_dynload).unwrap()).is_err());

        let mut noncanonical_version = manifest_json();
        noncanonical_version["python"]["importRoots"][1]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/python3.011");
        noncanonical_version["python"]["importRoots"][2]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/python3.011/lib-dynload");
        assert!(parse_manifest(&serde_json::to_vec(&noncanonical_version).unwrap()).is_err());

        let mut wrong_vendor = manifest_json();
        wrong_vendor["python"]["importRoots"][3]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/vendor");
        assert!(parse_manifest(&serde_json::to_vec(&wrong_vendor).unwrap()).is_err());

        let mut wrong_python = manifest_json();
        wrong_python["python"]["path"] = json!("/opt/serverware/releases/release-a/bin/python3");
        assert!(parse_manifest(&serde_json::to_vec(&wrong_python).unwrap()).is_err());
    }

    #[test]
    fn python_identity_requires_structured_cpython_elf() {
        let valid =
            minimal_cpython_elf(ELF_MACHINE_X86_64, b"Py_BytesMain", b"libpython3.11.so.1.0");
        assert!(validate_cpython_elf64(&valid, "python3.11").is_ok());
        assert!(validate_cpython_elf64(b"#!/usr/bin/python3\n", "python3.11").is_err());
        assert!(validate_cpython_elf64(b"arbitrary executable", "python3.11").is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(183, b"Py_BytesMain", b"libpython3.11.so.1.0"),
            "python3.11",
        )
        .is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(ELF_MACHINE_X86_64, b"main", b"libc.so.6"),
            "python3.11",
        )
        .is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(ELF_MACHINE_X86_64, b"Py_BytesMain", b"libpython3.12.so.1.0",),
            "python3.11",
        )
        .is_err());
    }

    #[test]
    fn typed_manifest_rejects_unknown_and_duplicate_fields() {
        let mut value = manifest_json();
        value["unexpected"] = json!(true);
        assert!(parse_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
        let raw = serde_json::to_string(&manifest_json()).unwrap();
        let duplicated = raw.replacen(
            "\"kind\":",
            "\"kind\":\"ProductionReadinessLaunch\",\"kind\":",
            1,
        );
        assert!(parse_manifest(duplicated.as_bytes()).is_err());
    }

    #[test]
    fn constructed_argv_is_closed_and_final() {
        let manifest = manifest();
        let preflight = build_preflight_argv(&manifest);
        let readiness = build_readiness_argv(&manifest);
        assert_eq!(
            preflight[0],
            manifest.scripts.preflight.path.to_string_lossy()
        );
        assert_eq!(readiness[0], manifest.scripts.runner.path.to_string_lossy());
        assert!(readiness
            .windows(2)
            .any(|pair| pair == ["--verification-mode", "final"]));
        for forbidden in [
            "--dry-run",
            "--config-only",
            "--claims-arg",
            "--skip-host-check",
        ] {
            assert!(!preflight.iter().any(|value| value == forbidden));
            assert!(!readiness.iter().any(|value| value == forbidden));
        }
        assert!(readiness.iter().all(|value| !value.starts_with("../")));
    }

    #[test]
    fn fixed_environment_has_only_the_contract_names() {
        let environment = fixed_environment(&digest('f'));
        let expected = BTreeSet::from([
            "LANG".to_string(),
            "LC_ALL".to_string(),
            "PATH".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_FD".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256".to_string(),
            "TZ".to_string(),
        ]);
        assert_eq!(
            environment.keys().cloned().collect::<BTreeSet<_>>(),
            expected
        );
        assert!(!environment.keys().any(|name| name.starts_with("LD_")));
        let commitment = environment_commitment().unwrap();
        assert_eq!(commitment.names, expected.into_iter().collect::<Vec<_>>());
        require_sha256(&commitment.sha256, "environment.sha256").unwrap();
    }

    #[test]
    fn authorization_is_nonce_bound_signed_and_time_limited() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let request = LaunchAuthorizationRequest {
            api_version: AUTHORIZATION_REQUEST_API_VERSION.to_string(),
            kind: AUTHORIZATION_REQUEST_KIND.to_string(),
            launcher_nonce: "1".repeat(64),
            boot_id_sha256: digest('2'),
            launcher_sha256: digest('3'),
            manifest_sha256: digest('4'),
            release_provenance_sha256: digest('5'),
            provenance_digest: digest('6'),
            reproducible_build_verification_sha256: digest('7'),
            source_tree_digest: digest('8'),
            deployment_audience: "prod.us-east-1.primary".to_string(),
            deployment_identity_sha256: digest('9'),
            release_sequence: 42,
            rollback_epoch: 7,
        };
        let mut envelope = LaunchAuthorizationEnvelope {
            api_version: AUTHORIZATION_API_VERSION.to_string(),
            kind: AUTHORIZATION_KIND.to_string(),
            statement: LaunchAuthorizationStatement {
                authorization_id: "a".repeat(64),
                authority_key_id: launch_authority_key_id(&verifying_key),
                request_sha256: authorization_request_digest(&request).unwrap(),
                issued_at_unix_seconds: 1_000,
                expires_at_unix_seconds: 1_030,
                use_limit: 1,
            },
            signature: String::new(),
        };
        envelope.signature = general_purpose::URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&authorization_signing_bytes(&envelope).unwrap())
                .to_bytes(),
        );
        let verified =
            verify_launch_authorization(request.clone(), envelope.clone(), &verifying_key, 1_001)
                .unwrap();
        assert_eq!(verified.request.launcher_nonce, "1".repeat(64));
        assert_eq!(verified.request_sha256, envelope.statement.request_sha256);

        let mut other_request = request.clone();
        other_request.launcher_nonce = "b".repeat(64);
        assert!(verify_launch_authorization(
            other_request,
            envelope.clone(),
            &verifying_key,
            1_001,
        )
        .unwrap_err()
        .to_string()
        .contains("LAUTH_REQUEST_MISMATCH"));
        assert!(
            verify_launch_authorization(request, envelope, &verifying_key, 1_030)
                .unwrap_err()
                .to_string()
                .contains("LAUTH_EXPIRED")
        );
    }

    #[test]
    fn authorization_currentness_uses_future_skew_and_strict_expiry() {
        let statement = LaunchAuthorizationStatement {
            authorization_id: "a".repeat(64),
            authority_key_id: digest('1'),
            request_sha256: digest('2'),
            issued_at_unix_seconds: 1_005,
            expires_at_unix_seconds: 1_010,
            use_limit: 1,
        };
        assert!(require_authorization_current(&statement, 1_000).is_ok());

        let mut too_far_future = statement.clone();
        too_far_future.issued_at_unix_seconds = 1_006;
        assert!(require_authorization_current(&too_far_future, 1_000)
            .unwrap_err()
            .to_string()
            .contains("LAUTH_FUTURE"));

        assert!(require_authorization_current(&statement, 1_009).is_ok());
        assert!(require_authorization_current(&statement, 1_010)
            .unwrap_err()
            .to_string()
            .contains("LAUTH_EXPIRED"));
    }

    #[test]
    fn receipt_json_is_canonical_sorted_compact_and_stable() {
        let metadata = ReceiptMetadata {
            device: 1,
            inode: 2,
            mode: 0o500,
            owner_uid: 0,
            owner_gid: 0,
            link_count: 1,
            size: 3,
            modified_unix_nanos: 4,
            changed_unix_nanos: 5,
        };
        let receipt_file = |path: &str, character| ReceiptFile {
            path: path.to_string(),
            sha256: digest(character),
            metadata: metadata.clone(),
        };
        let request = LaunchAuthorizationRequest {
            api_version: AUTHORIZATION_REQUEST_API_VERSION.to_string(),
            kind: AUTHORIZATION_REQUEST_KIND.to_string(),
            launcher_nonce: "a".repeat(64),
            boot_id_sha256: digest('b'),
            launcher_sha256: digest('c'),
            manifest_sha256: digest('d'),
            release_provenance_sha256: digest('e'),
            provenance_digest: digest('f'),
            reproducible_build_verification_sha256: digest('1'),
            source_tree_digest: digest('2'),
            deployment_audience: "prod.us-east-1.primary".to_string(),
            deployment_identity_sha256: digest('3'),
            release_sequence: 42,
            rollback_epoch: 7,
        };
        let envelope = LaunchAuthorizationEnvelope {
            api_version: AUTHORIZATION_API_VERSION.to_string(),
            kind: AUTHORIZATION_KIND.to_string(),
            statement: LaunchAuthorizationStatement {
                authorization_id: "9".repeat(64),
                authority_key_id: digest('4'),
                request_sha256: authorization_request_digest(&request).unwrap(),
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 120,
                use_limit: 1,
            },
            signature: general_purpose::URL_SAFE_NO_PAD.encode([5u8; 64]),
        };
        let launch_authorization = ReceiptLaunchAuthorization {
            request,
            request_sha256: envelope.statement.request_sha256.clone(),
            authorization_sha256: sha256_prefixed(&canonical_json_bytes(&envelope).unwrap()),
            envelope,
            verified_at_unix_seconds: 101,
        };
        let receipt = BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: "a".repeat(64),
            boot_id_sha256: digest('b'),
            launcher: receipt_file("/launcher", 'c'),
            manifest: receipt_file("/manifest", 'd'),
            source_tree_digest: digest('e'),
            launch_authorization,
            production_env: receipt_file("/env", 'f'),
            python: ReceiptPython {
                path: "/python".to_string(),
                sha256: digest('1'),
                metadata: metadata.clone(),
                import_roots: vec![ReceiptImportRoot {
                    path: "/imports".to_string(),
                    sha256: digest('2'),
                    metadata: metadata.clone(),
                }],
            },
            scripts: ReceiptScripts {
                preflight: receipt_file("/preflight", '3'),
                runner: receipt_file("/runner", '4'),
            },
            compose_file: receipt_file("/compose", '5'),
            inputs: BTreeMap::from([("bench".to_string(), receipt_file("/bench", '6'))]),
            argv: ReceiptArgv {
                preflight_sha256: digest('7'),
                readiness_sha256: digest('8'),
            },
            environment: environment_commitment().unwrap(),
        };
        let first = canonical_json_bytes(&receipt).unwrap();
        let second = canonical_json_bytes(&receipt).unwrap();
        assert_eq!(first, second);
        assert!(!first.ends_with(b"\n"));
        assert_eq!(first[0], b'{');
        assert!(String::from_utf8(first.clone())
            .unwrap()
            .starts_with("{\"apiVersion\":"));
        assert_eq!(sha256_prefixed(&first), sha256_prefixed(&second));
    }
}
