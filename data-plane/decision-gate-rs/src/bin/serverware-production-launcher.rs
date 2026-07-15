#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const LAUNCH_MANIFEST_API_VERSION: &str = "serverware.productionReadinessLaunch/v1";
const LAUNCH_MANIFEST_KIND: &str = "ProductionReadinessLaunch";
const RECEIPT_API_VERSION: &str = "serverware.bootstrapReceipt/v1";
const RECEIPT_KIND: &str = "ProductionBootstrapReceipt";
const RECEIPT_FD: i32 = 198;
const EXPECTED_CONTROL_PLANE_ID: &str = "65532";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MEASURED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const RECEIPT_SHA256_PLACEHOLDER: &str = "sha256:<bootstrap-receipt>";

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
    manifest_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchManifest {
    api_version: String,
    kind: String,
    release_root: PathBuf,
    state_directory: PathBuf,
    source_tree_digest: String,
    production_env: FileRecord,
    python: PythonRecord,
    scripts: ScriptsRecord,
    compose_file: FileRecord,
    inputs: Inputs,
    outputs: Outputs,
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
struct BootstrapReceipt {
    api_version: String,
    kind: String,
    launch_id: String,
    boot_id_sha256: String,
    launcher: ReceiptFile,
    manifest: ReceiptFile,
    source_tree_digest: String,
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
    let mut manifest_sha256 = None;

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
            "--manifest-sha256" => {
                if manifest_sha256.replace(value).is_some() {
                    return Err(LauncherError::new("duplicate --manifest-sha256 argument"));
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
    let manifest_sha256 =
        manifest_sha256.ok_or_else(|| LauncherError::new("missing --manifest-sha256 argument"))?;
    require_sha256(&manifest_sha256, "manifest digest")?;
    Ok(Cli {
        manifest,
        manifest_sha256,
    })
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

    if manifest.python.import_roots.is_empty() {
        return Err(LauncherError::new(
            "python.importRoots must contain at least one verified root",
        ));
    }
    let mut import_paths = BTreeSet::new();
    for (index, root) in manifest.python.import_roots.iter().enumerate() {
        let label = format!("python.importRoots[{index}]");
        require_at_or_below(&root.path, &manifest.release_root, &label)?;
        require_sha256(&root.sha256, &format!("{label}.sha256"))?;
        if !import_paths.insert(root.path.clone()) {
            return Err(LauncherError::new(
                "python.importRoots must not contain duplicate paths",
            ));
        }
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
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

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
        if digest != cli.manifest_sha256 {
            return Err(LauncherError::new("manifest digest does not match"));
        }
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
        let python = measure_file(&python_record, "python", true)?;
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
        for (name, record) in all_input_records(&manifest.inputs) {
            inputs.insert(name.to_string(), measure_file(record, name, false)?.receipt);
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
            release_root_fd,
        })
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

    fn build_receipt(
        verified: &VerifiedLaunch,
        preflight_argv: &[String],
        readiness_argv: &[String],
    ) -> Result<BootstrapReceipt> {
        Ok(BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: random_launch_id()?,
            boot_id_sha256: boot_id_digest()?,
            launcher: verified.launcher.clone(),
            manifest: verified.manifest_receipt.clone(),
            source_tree_digest: verified.manifest.source_tree_digest.clone(),
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
        // SAFETY: sysconf has no memory-safety preconditions.
        let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        if limit < 0 {
            return Err(LauncherError::new(
                "could not determine inherited descriptor limit",
            ));
        }
        let upper = usize::try_from(limit)
            .unwrap_or(i32::MAX as usize)
            .min(i32::MAX as usize) as RawFd;
        for fd in 3..upper {
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
        let preflight_argv = build_preflight_argv(&verified.manifest);
        let readiness_argv = build_readiness_argv(&verified.manifest);
        let receipt = build_receipt(&verified, &preflight_argv, &readiness_argv)?;
        let receipt_bytes = canonical_json_bytes(&receipt)?;
        let receipt_sha256 = sha256_prefixed(&receipt_bytes);
        let receipt_fd = create_sealed_receipt(&receipt_bytes)?;

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
        drop(verified.preflight);
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
    use serde_json::json;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn file(path: &str, character: char) -> Value {
        json!({"path": path, "sha256": digest(character)})
    }

    fn manifest_json() -> Value {
        let root = "/opt/serverware/releases/release-a";
        json!({
            "apiVersion": LAUNCH_MANIFEST_API_VERSION,
            "kind": LAUNCH_MANIFEST_KIND,
            "releaseRoot": root,
            "stateDirectory": "/var/lib/serverware/production-proof",
            "sourceTreeDigest": digest('a'),
            "productionEnv": file("/etc/serverware/production-readiness.env", 'b'),
            "python": {
                "path": format!("{root}/python/bin/python3"),
                "sha256": digest('c'),
                "importRoots": [{
                    "path": format!("{root}/python/lib"),
                    "sha256": digest('d')
                }]
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
            OsString::from("--manifest-sha256"),
            OsString::from(digest('a')),
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
            OsString::from("--manifest-sha256"),
            OsString::from(digest('a')),
        ])
        .is_err());
        assert!(parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/x"),
            OsString::from("--manifest-sha256"),
            OsString::from(digest('a')),
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
        let mut release_root_import = manifest_json();
        release_root_import["python"]["importRoots"][0]["path"] =
            release_root_import["releaseRoot"].clone();
        assert!(parse_manifest(&serde_json::to_vec(&release_root_import).unwrap()).is_ok());
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
        let receipt = BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: "a".repeat(64),
            boot_id_sha256: digest('b'),
            launcher: receipt_file("/launcher", 'c'),
            manifest: receipt_file("/manifest", 'd'),
            source_tree_digest: digest('e'),
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
