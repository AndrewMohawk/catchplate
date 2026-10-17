#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[cfg(target_os = "linux")]
#[path = "../plan_protocol.rs"]
mod plan_protocol;
#[cfg(target_os = "linux")]
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[cfg(target_os = "linux")]
#[path = "../docker_contract.rs"]
mod docker_contract;
#[cfg(target_os = "linux")]
#[path = "../docker_policy.rs"]
mod docker_policy;
#[cfg(target_os = "linux")]
#[path = "../readiness.rs"]
mod readiness;
#[cfg(target_os = "linux")]
#[path = "../runtime_evidence.rs"]
mod runtime_evidence;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("catchplate-coder-docker-proxy-v12: Linux is required");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("catchplate-coder-docker-proxy-v12: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::plan_protocol::{
        canonical_bytes, canonical_sha256_without_digest,
        sha256_bytes, AuthoritativeLaneState, LaneProxyRequest,
        LaneProxyResponse, ProxyDisposition, ExactBuildTuple, PinnedPull,
        MAX_FRAME_BYTES, PLAN_PROXY_PROTOCOL_VERSION,
    };
    use super::docker_contract::{
        DockerLaneDecodedPayloadV12, DockerLaneOperationV12,
        DockerLanePayloadContentV12,
        PrivateDindOperationDispositionV12,
        PrivateDindOperationRequestV12,
        PrivateDindOperationResponseV12,
    };
    use super::docker_policy::{
        GENERATION_LABEL_V12, LANE_LABEL_V12, OWNER_LABEL_V12,
        RESOURCE_LABEL_V12,
    };
    use super::receipt_contract_v12::{
        boottime_now_ns, canonical_json, parse_canonical_json,
        AuthorityFrameHeaderV12, AUTHORITY_FRAME_BYTES,
    };
    use base64::{
        engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
    };
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::mem;
    use std::os::fd::{
        AsRawFd, FromRawFd, OwnedFd, RawFd,
    };
    use std::os::unix::fs::{
        FileTypeExt, MetadataExt, OpenOptionsExt,
    };
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    const MAX_CONFIG_BYTES: usize = 256 * 1024;
    const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;
    const MAX_ATTACHED_FDS: usize = 8;

    struct Config {
        socket_path: PathBuf,
        socket_mode: u32,
        socket_gid: u32,
        lifecycle_socket: PathBuf,
        authorized_controller_uid: u32,
        lifecycle_root_signer_spki_sha256: [u8; 32],
        allowed_pinned_pulls: BTreeSet<Vec<u8>>,
        allowed_exact_builds: BTreeSet<Vec<u8>>,
    }

    pub fn run() -> Result<(), String> {
        let arguments =
            std::env::args_os().skip(1).collect::<Vec<_>>();
        if arguments.len() != 2 || arguments[0] != "--config" {
            return Err(
                "usage: catchplate-coder-docker-proxy-v12 --config ABSOLUTE_PATH"
                    .into(),
            );
        }
        if unsafe { libc::geteuid() } == 0 {
            return Err(
                "v12 Docker proxy must run as an unprivileged UID".into(),
            );
        }
        let config = load_config(Path::new(&arguments[1]))?;
        let listener = bind_seqpacket(&config)?;
        super::receipt_contract_v12::notify_systemd_v12(
            "docker-proxy-v12 fail-closed delegated-FD facade ready",
        )
        .map_err(|error| error.to_string())?;
        loop {
            let accepted = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if accepted < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("accept v12 lane proxy: {error}"));
            }
            let connection = unsafe { OwnedFd::from_raw_fd(accepted) };
            if let Err(error) = serve_connection(&config, connection) {
                eprintln!(
                    "catchplate-coder-docker-proxy-v12: connection destroyed: {error}"
                );
            }
        }
    }

    fn load_config(path: &Path) -> Result<Config, String> {
        if !path.is_absolute() {
            return Err("Docker proxy config path is not absolute".into());
        }
        let bytes = fs::read(path)
            .map_err(|error| format!("read Docker proxy config: {error}"))?;
        let metadata = fs::metadata(path)
            .map_err(|error| format!("stat Docker proxy config: {error}"))?;
        if bytes.is_empty()
            || bytes.len() > MAX_CONFIG_BYTES
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(
                "Docker proxy config ownership, mode, or size is invalid"
                    .into(),
            );
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "Docker proxy config is not UTF-8")?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or("Docker proxy config line lacks '='")?;
            if key.is_empty()
                || value.is_empty()
                || values
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err(
                    "Docker proxy config key is empty or duplicated".into(),
                );
            }
        }
        let required = |key: &str| {
            values
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| format!("Docker proxy config lacks {key}"))
        };
        if required("contract_version")? != "12"
            || required("request_contract")?
                != PLAN_PROXY_PROTOCOL_VERSION
            || required("response_contract")?
                != PLAN_PROXY_PROTOCOL_VERSION
            || required("proxy_privilege")? != "unprivileged"
            || required("root_lifecycle_ownership")? != "exclusive"
            || required("host_docker_socket_exposed")? != "false"
            || required("destroy_on_any_failure")? != "true"
            || required("socket_activation")?
                != "systemd-listen-fds"
            || required("unknown_route")? != "deny"
            || required("unknown_method")? != "deny"
            || required("unknown_query")? != "deny"
            || required("unknown_body_field")? != "deny"
            || required("unknown_target")? != "deny"
            || required("unknown_transition")? != "deny"
            || required("ownership_labels_are_advisory")? != "false"
            || required("privileged_ledger_is_authority")? != "true"
            || required("full_duplex_transport")? != "true"
            || required("preserve_half_close")? != "true"
            || required("build_operation_profile")?
                != "exact-build-only"
            || required("no_build_import_profile")?
                != "fresh-daemon-exact-controller-cas-digest-only"
            || required("ownership_label.namespace")?
                != OWNER_LABEL_V12
            || required("ownership_label.generation")?
                != GENERATION_LABEL_V12
            || required("ownership_label.lane")?
                != LANE_LABEL_V12
            || required("ownership_label.resource")?
                != RESOURCE_LABEL_V12
        {
            return Err(
                "Docker proxy config does not select the bounded v12 facade"
                    .into(),
            );
        }
        let socket_path = PathBuf::from(required("socket_path")?);
        let lifecycle_socket =
            PathBuf::from(required("lifecycle_socket")?);
        if !socket_path.is_absolute() || !lifecycle_socket.is_absolute() {
            return Err("Docker proxy sockets are not absolute".into());
        }
        let authorized_controller_uid = required(
            "authorized_controller_uid",
        )?
        .parse::<u32>()
        .map_err(|_| "authorized controller UID is not u32")?;
        let socket_gid = required("socket_gid")?
            .parse::<u32>()
            .map_err(|_| "Docker proxy socket GID is not u32")?;
        let (
            allowed_pinned_pulls,
            allowed_exact_builds,
            lifecycle_root_signer_spki_sha256,
        ) =
            validate_signed_policy_bindings(
                &values,
                &bytes,
                authorized_controller_uid,
                socket_gid,
            )?;
        Ok(Config {
            socket_path,
            lifecycle_socket,
            socket_mode: u32::from_str_radix(
                required("socket_mode")?,
                8,
            )
            .map_err(|_| "Docker proxy socket mode is not octal")?,
            socket_gid,
            authorized_controller_uid,
            lifecycle_root_signer_spki_sha256,
            allowed_pinned_pulls,
            allowed_exact_builds,
        })
    }

    fn validate_signed_policy_bindings(
        config: &BTreeMap<String, String>,
        config_bytes: &[u8],
        authorized_controller_uid: u32,
        socket_gid: u32,
    ) -> Result<
        (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>, [u8; 32]),
        String,
    > {
        let release_key = load_public_key(&path_value(
            config,
            "release_manifest_public_key",
        )?)?;
        let release_path = path_value(config, "release_manifest")?;
        let release_signature =
            path_value(config, "release_manifest_signature")?;
        let release_bytes = verify_signed_file(
            &release_path,
            &release_signature,
            &release_key,
            MAX_CONFIG_BYTES,
        )?;
        let release = parse_kv(&release_bytes)?;
        let lifecycle_root_signer_spki_sha256 = digest_value(
            &release,
            "lifecycle_privileged_authority_spki_sha256",
        )?;
        if required_value(&release, "manifest_version")? != "12"
            || required_value(&release, "trust_profile")?
                != "trusted-host-userspace-digest-no-ima"
            || digest_value(&release, "docker_proxy_config_sha256")?
                != sha256_bytes(config_bytes)
            || digest_value(
                &release,
                "config_generation_signature_sha256",
            )? != secure_digest(
                &path_value(
                    config,
                    "configuration_generation_signature",
                )?,
                MAX_CONFIG_BYTES,
            )?
        {
            return Err(
                "Docker proxy config or generation signature is not release-bound"
                    .into(),
            );
        }
        let configuration_key = load_public_key(&path_value(
            config,
            "configuration_authority_public_key",
        )?)?;
        let generation_path =
            path_value(config, "configuration_generation")?;
        let generation_bytes = verify_signed_file(
            &generation_path,
            &path_value(
                config,
                "configuration_generation_signature",
            )?,
            &configuration_key,
            MAX_CONFIG_BYTES,
        )?;
        if digest_value(
            &release,
            "config_generation_document_sha256",
        )? != sha256_bytes(&generation_bytes)
        {
            return Err(
                "Docker proxy configuration generation is not release-bound"
                    .into(),
            );
        }
        let generation = parse_kv(&generation_bytes)?;
        let executor_uid = parse_u32(config, "executor_uid")?;
        if executor_uid != parse_u32(config, "authorized_executor_uid")?
            || executor_uid
                != parse_u32(&release, "identity.executor.uid")?
            || executor_uid
                != parse_u32(&release, "private_dind.executor_uid")?
            || executor_uid
                != parse_u32(&generation, "identity.executor.uid")?
            || executor_uid
                != parse_u32(&generation, "private_dind.executor_uid")?
            || authorized_controller_uid
                != parse_u32(&release, "identity.controller.uid")?
            || socket_gid
                != parse_u32(&release, "group.docker_api.gid")?
            || unsafe { libc::geteuid() }
                != parse_u32(&release, "identity.docker_proxy.uid")?
            || required_value(
                &generation,
                "private_dind.global_docker_daemon",
            )? != "false"
            || required_value(
                &generation,
                "private_dind.host_docker_socket",
            )? != "false"
            || required_value(
                &generation,
                "private_dind.legacy_v11_lease",
            )? != "false"
        {
            return Err(
                "Docker proxy identities or private-DinD constraints differ from signed bindings"
                    .into(),
            );
        }

        let policy_path = path_value(config, "docker_policy")?;
        let policy_bytes =
            secure_read(&policy_path, MAX_POLICY_BYTES, 0)?;
        if digest_value(&release, "docker_policy_sha256")?
            != sha256_bytes(&policy_bytes)
        {
            return Err(
                "Docker policy descriptor is not release-bound".into(),
            );
        }
        let policy = parse_kv(&policy_bytes)?;
        for (key, expected) in [
            ("contract", "catchplate/controller-lane-capability/v12"),
            ("request_contract", PLAN_PROXY_PROTOCOL_VERSION),
            ("default", "deny"),
            (
                "enforcement",
                "compiled-rust-source-digest-bound-v12",
            ),
            ("executor_authority", "exact-signed-capability"),
            ("body_authority", "none"),
            ("host_docker_socket", "forbidden"),
            ("global_docker_daemon", "forbidden"),
            ("legacy_v11_lease", "forbidden"),
            (
                "ownership_authority",
                "root-ledger-and-exact-labels",
            ),
            ("ownership_label.namespace", OWNER_LABEL_V12),
            ("ownership_label.generation", GENERATION_LABEL_V12),
            ("ownership_label.lane", LANE_LABEL_V12),
            ("ownership_label.resource", RESOURCE_LABEL_V12),
        ] {
            if required_value(&policy, key)? != expected {
                return Err(format!(
                    "signed Docker policy differs from compiled enforcement at {key}"
                ));
            }
        }
        let ruleset_path = path_value(&policy, "ruleset_path")?;
        let pinned_path =
            path_value(&policy, "pinned_pull_set_path")?;
        let exact_path =
            path_value(&policy, "exact_build_tuple_set_path")?;
        for (path, policy_key, release_key) in [
            (
                &ruleset_path,
                "ruleset_sha256",
                "docker_api_rule_set_sha256",
            ),
            (
                &pinned_path,
                "pinned_pull_set_sha256",
                "pinned_pull_set_sha256",
            ),
            (
                &exact_path,
                "exact_build_tuple_set_sha256",
                "exact_build_tuple_set_sha256",
            ),
        ] {
            let actual = secure_digest(path, MAX_POLICY_BYTES)?;
            if actual != digest_value(&policy, policy_key)?
                || actual != digest_value(&release, release_key)?
            {
                return Err(format!(
                    "Docker policy asset differs from signed {release_key}"
                ));
            }
        }
        verify_compiled_ruleset(&ruleset_path)?;
        Ok((
            load_pinned_pull_set(&pinned_path)?,
            load_exact_build_set(&exact_path)?,
            lifecycle_root_signer_spki_sha256,
        ))
    }

    fn verify_compiled_ruleset(path: &Path) -> Result<(), String> {
        let bytes = secure_read(path, MAX_POLICY_BYTES, 0)?;
        let actual: Value =
            parse_canonical_json(&bytes, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?;
        let expected = json!({
            "archiveContract": {
                "format": "catchplate/docker-image-archive-set/v12",
                "importVerification":
                    "recanonicalize-and-require-byte-identity",
                "outerContainer": "canonical-ustar-v12",
                "producer":
                    "canonicalize_docker_image_archive_v12"
            },
            "compiledSources": {
                "dindLifecycleSha256": hex::encode(sha256_bytes(
                    include_bytes!("../dind_lifecycle.rs")
                )),
                "dockerContractSha256": hex::encode(sha256_bytes(
                    include_bytes!("../docker_contract.rs")
                )),
                "dockerPolicySha256": hex::encode(sha256_bytes(
                    include_bytes!("../docker_policy.rs")
                ))
            },
            "contract": "catchplate/docker-api-rules/v12",
            "default": "deny",
            "enforcement": "compiled-rust-source-digest-bound-v12",
            "operationProfiles": {
                "build": [
                    "createBuildDind", "pullPinned", "buildExact",
                    "createRunner", "runRepositoryBody", "stopRunner",
                    "exportOwnedOci", "destroyBuildDind",
                    "queryAuthoritativeState", "readinessProbe"
                ],
                "noBuild": [
                    "createNoBuildDind", "importSealedOci",
                    "createRunner", "createServices",
                    "runRepositoryBody", "stopRunner",
                    "destroyServices", "destroyNoBuildDind",
                    "queryAuthoritativeState", "readinessProbe"
                ]
            },
            "ownershipLabels": {
                "generation": GENERATION_LABEL_V12,
                "lane": LANE_LABEL_V12,
                "namespace": OWNER_LABEL_V12,
                "resource": RESOURCE_LABEL_V12
            },
            "version": 12
        });
        if actual != expected
            || canonical_json(&actual, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?
                != bytes
        {
            return Err(
                "signed Docker API ruleset differs from compiled v12 enforcement"
                    .into(),
            );
        }
        Ok(())
    }

    fn load_pinned_pull_set(
        path: &Path,
    ) -> Result<BTreeSet<Vec<u8>>, String> {
        let value = load_policy_document(
            path,
            "catchplate/pinned-pulls/v12",
            "pulls",
        )?;
        let entries = value
            .get("pulls")
            .and_then(Value::as_array)
            .ok_or("pinned pull policy lacks pulls")?;
        let mut result = BTreeSet::new();
        for entry in entries {
            let pull: PinnedPull =
                serde_json::from_value(entry.clone()).map_err(|_| {
                    "pinned pull policy entry is invalid".to_owned()
                })?;
            pull.validate().map_err(|error| error.to_string())?;
            if !result.insert(
                canonical_bytes(&pull)
                    .map_err(|error| error.to_string())?,
            ) {
                return Err(
                    "pinned pull policy contains a duplicate".into(),
                );
            }
        }
        if result.is_empty() {
            return Err("pinned pull policy is empty".into());
        }
        Ok(result)
    }

    fn load_exact_build_set(
        path: &Path,
    ) -> Result<BTreeSet<Vec<u8>>, String> {
        let value = load_policy_document(
            path,
            "catchplate/exact-build-tuples/v12",
            "builds",
        )?;
        let entries = value
            .get("builds")
            .and_then(Value::as_array)
            .ok_or("exact build policy lacks builds")?;
        let mut result = BTreeSet::new();
        for entry in entries {
            let exact: ExactBuildTuple =
                serde_json::from_value(entry.clone()).map_err(|_| {
                    "exact build policy entry is invalid".to_owned()
                })?;
            exact.validate().map_err(|error| error.to_string())?;
            if !result.insert(
                canonical_bytes(&exact)
                    .map_err(|error| error.to_string())?,
            ) {
                return Err(
                    "exact build policy contains a duplicate".into(),
                );
            }
        }
        if result.is_empty() {
            return Err("exact build policy is empty".into());
        }
        Ok(result)
    }

    fn load_policy_document(
        path: &Path,
        contract: &str,
        array_key: &str,
    ) -> Result<Value, String> {
        let bytes = secure_read(path, MAX_POLICY_BYTES, 0)?;
        let value: Value =
            parse_canonical_json(&bytes, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?;
        let object = value
            .as_object()
            .ok_or("Docker policy set is not an object")?;
        if object.len() != 3
            || value.get("contract").and_then(Value::as_str)
                != Some(contract)
            || value.get("version").and_then(Value::as_u64)
                != Some(12)
            || !value.get(array_key).is_some_and(Value::is_array)
            || canonical_json(&value, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?
                != bytes
        {
            return Err(
                "Docker policy set is not the exact canonical v12 shape"
                    .into(),
            );
        }
        Ok(value)
    }

    fn validate_request_policy_assets(
        config: &Config,
        operation: &DockerLaneOperationV12,
    ) -> Result<(), String> {
        let DockerLaneDecodedPayloadV12::Operation(payload) =
            &operation.decoded_payload
        else {
            return Ok(());
        };
        let validate_pull = |pull: &PinnedPull| {
            let bytes = canonical_bytes(pull)
                .map_err(|error| error.to_string())?;
            if config.allowed_pinned_pulls.contains(&bytes) {
                Ok(())
            } else {
                Err(
                    "lane request uses a pull absent from the signed pinned-pull set"
                        .to_owned(),
                )
            }
        };
        let validate_build = |exact: &ExactBuildTuple| {
            let bytes = canonical_bytes(exact)
                .map_err(|error| error.to_string())?;
            if !config.allowed_exact_builds.contains(&bytes) {
                return Err(
                    "lane request uses a build absent from the signed exact-build set"
                        .to_owned(),
                );
            }
            for pull in &exact.pinned_pulls {
                validate_pull(pull)?;
            }
            Ok(())
        };
        match &payload.content {
            DockerLanePayloadContentV12::CreateBuildDind {
                exact_build,
                ..
            }
            | DockerLanePayloadContentV12::BuildExact {
                exact_build,
            } => validate_build(exact_build),
            DockerLanePayloadContentV12::PullPinned { pull } => {
                validate_pull(pull)
            }
            _ => Ok(()),
        }
    }

    fn parse_kv(
        bytes: &[u8],
    ) -> Result<BTreeMap<String, String>, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "manifest is not UTF-8")?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) =
                line.split_once('=').ok_or("manifest line lacks '='")?;
            if key.is_empty()
                || value.is_empty()
                || values
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err("manifest key is empty or duplicated".into());
            }
        }
        Ok(values)
    }

    fn required_value<'a>(
        values: &'a BTreeMap<String, String>,
        key: &str,
    ) -> Result<&'a str, String> {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("manifest lacks {key}"))
    }

    fn parse_u32(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<u32, String> {
        required_value(values, key)?
            .parse::<u32>()
            .map_err(|_| format!("{key} is not u32"))
    }

    fn path_value(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<PathBuf, String> {
        let path = PathBuf::from(required_value(values, key)?);
        if !path.is_absolute() {
            return Err(format!("{key} is not absolute"));
        }
        Ok(path)
    }

    fn digest_value(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<[u8; 32], String> {
        let bytes = hex::decode(required_value(values, key)?)
            .map_err(|_| format!("{key} is not hexadecimal"))?;
        bytes
            .try_into()
            .map_err(|_| format!("{key} is not a 32-byte digest"))
    }

    fn secure_read(
        path: &Path,
        maximum: usize,
        owner: u32,
    ) -> Result<Vec<u8>, String> {
        if !path.is_absolute() {
            return Err("secure path is not absolute".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != owner
            || metadata.mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > maximum as u64
        {
            return Err(format!(
                "secure file metadata rejected: {}",
                path.display()
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != metadata.len() {
            return Err("secure file changed while read".into());
        }
        Ok(bytes)
    }

    fn secure_digest(
        path: &Path,
        maximum: usize,
    ) -> Result<[u8; 32], String> {
        Ok(sha256_bytes(&secure_read(path, maximum, 0)?))
    }

    fn load_public_key(path: &Path) -> Result<VerifyingKey, String> {
        let bytes = secure_read(path, 64 * 1024, 0)?;
        if bytes.len() == 32 {
            return VerifyingKey::from_bytes(
                &bytes
                    .try_into()
                    .map_err(|_| "public key length changed")?,
            )
            .map_err(|error| error.to_string());
        }
        VerifyingKey::from_public_key_pem(
            std::str::from_utf8(&bytes)
                .map_err(|_| "public key is not UTF-8")?,
        )
        .map_err(|error| error.to_string())
    }

    fn verify_signed_file(
        path: &Path,
        signature_path: &Path,
        key: &VerifyingKey,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        let bytes = secure_read(path, maximum, 0)?;
        let signature = secure_read(signature_path, 4096, 0)?;
        let signature = if signature.len() == 64 {
            signature
        } else {
            URL_SAFE_NO_PAD
                .decode(
                    std::str::from_utf8(&signature)
                        .map_err(|_| "signature is not UTF-8")?
                        .trim(),
                )
                .map_err(|_| "signature is not base64url")?
        };
        key.verify(
            &bytes,
            &Signature::from_slice(&signature)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|_| "signed document signature is invalid")?;
        Ok(bytes)
    }

    fn bind_seqpacket(config: &Config) -> Result<OwnedFd, String> {
        let listen_pid = std::env::var("LISTEN_PID")
            .map_err(|_| "Docker proxy requires LISTEN_PID")?
            .parse::<u32>()
            .map_err(|_| "Docker proxy LISTEN_PID is invalid")?;
        let listen_fds = std::env::var("LISTEN_FDS")
            .map_err(|_| "Docker proxy requires LISTEN_FDS")?
            .parse::<u32>()
            .map_err(|_| "Docker proxy LISTEN_FDS is invalid")?;
        if listen_pid != std::process::id() || listen_fds != 1 {
            return Err(
                "Docker proxy requires exactly one socket-activated listener"
                    .into(),
            );
        }
        let mut socket_type = 0i32;
        let mut socket_type_bytes =
            mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut socket_type as *mut i32 as *mut libc::c_void,
                &mut socket_type_bytes,
            )
        } != 0
            || socket_type != libc::SOCK_SEQPACKET
        {
            return Err(
                "Docker proxy activated listener is not SOCK_SEQPACKET"
                    .into(),
            );
        }
        let metadata = fs::symlink_metadata(&config.socket_path)
            .map_err(|error| {
                format!("stat Docker proxy activated socket: {error}")
            })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != config.socket_gid
            || metadata.mode() & 0o777 != config.socket_mode
        {
            return Err(
                "Docker proxy activated socket ownership or mode differs from config"
                    .into(),
            );
        }
        let duplicated =
            unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }

    fn serve_connection(
        config: &Config,
        connection: OwnedFd,
    ) -> Result<(), String> {
        let mut credential: libc::ucred = unsafe { mem::zeroed() };
        let mut length =
            mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                connection.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credential as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || credential.uid != config.authorized_controller_uid
        {
            return Err(
                "lane proxy connection is not controller-delegated".into(),
            );
        }
        let mut bound_capability = None;
        let mut bound_plan = None;
        let mut prior_sequence = 0u64;
        loop {
            let (bytes, fds) =
                receive_packet(connection.as_raw_fd())?;
            let request: LaneProxyRequest =
                serde_json::from_slice(&bytes)
                    .map_err(|error| error.to_string())?;
            if canonical_bytes(&request)
                .map_err(|error| error.to_string())?
                != bytes
            {
                return Err(
                    "lane proxy request is not canonical JSON".into(),
                );
            }
            request.validate().map_err(|error| error.to_string())?;
            if boottime_now_ns().map_err(|error| error.to_string())?
                >= request.deadline_boottime_ns
                || bound_capability
                    .is_some_and(|value| value != request.capability_sha256)
                || bound_plan.is_some_and(|value| value != request.plan_id)
                || request.sequence != prior_sequence.saturating_add(1)
            {
                drop(fds);
                return Err(
                    "lane proxy capability, plan, deadline, or sequence changed"
                        .into(),
                );
            }
            bound_capability = Some(request.capability_sha256);
            bound_plan = Some(request.plan_id);
            prior_sequence = request.sequence;
            let delegated_request:
                super::docker_contract::LaneProxyRequest =
                serde_json::from_slice(&bytes).map_err(|_| {
                    "lane proxy request differs from delegated v12 contract"
                        .to_owned()
                })?;
            let decoded = DockerLaneOperationV12::from_proxy_request(
                delegated_request.clone(),
                fds.len(),
            )
            .map_err(|error| error.to_string())?;
            validate_request_policy_assets(config, &decoded)?;
            let lifecycle_request = PrivateDindOperationRequestV12::seal(
                delegated_request,
                decoded.attached_fd_roles,
            )
            .map_err(|error| error.to_string())?;
            let lifecycle_bytes =
                super::docker_contract::canonical_plan_bytes(
                    &lifecycle_request,
                )
                .map_err(|error| error.to_string())?;
            let (root_bytes, returned_fds) = match lifecycle_rpc(
                config,
                &lifecycle_request,
                &lifecycle_bytes,
                fds,
            ) {
                Ok(response) => response,
                Err(error) => {
                    return Err(format!(
                        "private DinD delegated operation failed: {error}"
                    ));
                }
            };
            let root_response: PrivateDindOperationResponseV12 =
                serde_json::from_slice(&root_bytes).map_err(|_| {
                    "private DinD root response is not valid JSON".to_owned()
                })?;
            if super::docker_contract::canonical_plan_bytes(
                &root_response,
            )
            .map_err(|error| error.to_string())?
                != root_bytes
            {
                return Err(
                    "private DinD root response is not canonical".into(),
                );
            }
            root_response
                .validate_for(&lifecycle_request)
                .map_err(|error| error.to_string())?;
            if root_response.root_signer_spki_sha256
                != config.lifecycle_root_signer_spki_sha256
            {
                return Err(
                    "private DinD root response signer differs from the signed release pin"
                        .into(),
                );
            }
            if root_response.returned_fd_roles.len()
                != returned_fds.len()
            {
                return Err(
                    "private DinD root response FD count differs".into(),
                );
            }
            let disposition = match root_response.disposition {
                PrivateDindOperationDispositionV12::Applied => {
                    ProxyDisposition::Applied
                }
                PrivateDindOperationDispositionV12::AlreadyApplied => {
                    ProxyDisposition::AlreadyApplied
                }
                PrivateDindOperationDispositionV12::Rejected => {
                    ProxyDisposition::Rejected
                }
                PrivateDindOperationDispositionV12::OutcomeUnknown => {
                    ProxyDisposition::OutcomeUnknown
                }
            };
            let authoritative_state =
                serde_json::from_value(
                    serde_json::to_value(
                        root_response.authoritative_state,
                    )
                    .map_err(|_| {
                        "root authoritative state is not serializable"
                            .to_owned()
                    })?,
                )
                .map_err(|_| {
                    "root authoritative state differs from proxy contract"
                        .to_owned()
                })?;
            let result_sha256 = root_response.result_sha256;
            let terminal_destruction_receipt =
                root_response.terminal_destruction_receipt;
            let result = root_response.result;
            let mut response = LaneProxyResponse {
                protocol: PLAN_PROXY_PROTOCOL_VERSION.to_owned(),
                request_id: request.request_id,
                request_sha256: request.request_sha256,
                plan_id: request.plan_id,
                lane: request.lane,
                sequence: request.sequence,
                disposition,
                authoritative_state,
                result_sha256,
                result,
                terminal_destruction_receipt,
                response_sha256: [0; 32],
            };
            response.response_sha256 =
                canonical_sha256_without_digest(
                    &response,
                    |value| value.response_sha256 = [0; 32],
                )
                .map_err(|error| error.to_string())?;
            let response =
                canonical_bytes(&response).map_err(|error| error.to_string())?;
            send_packet_with_fds(
                connection.as_raw_fd(),
                &response,
                &returned_fds,
            )?;
        }
    }

    fn lifecycle_rpc(
        config: &Config,
        request: &PrivateDindOperationRequestV12,
        exact_request: &[u8],
        attached_fds: Vec<OwnedFd>,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
        let mut stream = UnixStream::connect(&config.lifecycle_socket)
            .map_err(|error| {
                format!("connect private DinD lifecycle: {error}")
            })?;
        let header = AuthorityFrameHeaderV12::for_payload(
            exact_request,
            request.proxy_request.deadline_boottime_ns,
            MAX_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?
        .encode(MAX_FRAME_BYTES)
        .map_err(|error| error.to_string())?;
        write_stream_header_with_fds(
            &mut stream,
            &header,
            &attached_fds,
        )?;
        stream
            .write_all(exact_request)
            .map_err(|error| error.to_string())?;
        read_stream_frame_with_fds(&mut stream, 1)
    }

    fn receive_packet(
        socket: RawFd,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
        let mut bytes = vec![0u8; MAX_FRAME_BYTES];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let control_bytes = unsafe {
            libc::CMSG_SPACE(
                (MAX_ATTACHED_FDS * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        };
        let mut control =
            vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        let count = unsafe {
            libc::recvmsg(
                socket,
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
            )
        };
        if count <= 0
            || count as usize > bytes.len()
            || message.msg_flags
                & (libc::MSG_TRUNC | libc::MSG_CTRUNC)
                != 0
        {
            return Err("lane proxy packet is truncated or empty".into());
        }
        let mut fds = Vec::new();
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            unsafe {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let bytes = (*header)
                        .cmsg_len
                        .saturating_sub(libc::CMSG_LEN(0) as usize);
                    if bytes % mem::size_of::<RawFd>() != 0 {
                        return Err(
                            "lane proxy SCM_RIGHTS payload is malformed"
                                .into(),
                        );
                    }
                    let count = bytes / mem::size_of::<RawFd>();
                    if count > MAX_ATTACHED_FDS {
                        return Err(
                            "lane proxy attached too many descriptors".into(),
                        );
                    }
                    let values =
                        libc::CMSG_DATA(header) as *const RawFd;
                    for index in 0..count {
                        let raw = *values.add(index);
                        if raw >= 0 {
                            fds.push(OwnedFd::from_raw_fd(raw));
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        bytes.truncate(count as usize);
        Ok((bytes, fds))
    }

    fn write_stream_header_with_fds(
        stream: &mut UnixStream,
        header: &[u8],
        fds: &[OwnedFd],
    ) -> Result<(), String> {
        if fds.is_empty() {
            return stream
                .write_all(header)
                .map_err(|error| error.to_string());
        }
        if fds.len() > MAX_ATTACHED_FDS {
            return Err(
                "private DinD request exceeded its FD bound".into(),
            );
        }
        let raw = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let control_bytes = unsafe {
            libc::CMSG_SPACE(
                (raw.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        };
        let mut control =
            vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
        let mut iov = libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&message);
            if cmsg.is_null() {
                return Err(
                    "private DinD request control is unavailable".into(),
                );
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(
                (raw.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize;
            std::ptr::copy_nonoverlapping(
                raw.as_ptr(),
                libc::CMSG_DATA(cmsg) as *mut RawFd,
                raw.len(),
            );
        }
        let sent = unsafe {
            libc::sendmsg(
                stream.as_raw_fd(),
                &message,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent <= 0 || sent as usize > header.len() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        stream
            .write_all(&header[sent as usize..])
            .map_err(|error| error.to_string())
    }

    fn read_stream_frame_with_fds(
        stream: &mut UnixStream,
        maximum_fds: usize,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
        let mut header = [0u8; AUTHORITY_FRAME_BYTES];
        let mut iov = libc::iovec {
            iov_base: header.as_mut_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        };
        let control_bytes = unsafe {
            libc::CMSG_SPACE(
                (maximum_fds.max(1) * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        };
        let mut control =
            vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        let count = unsafe {
            libc::recvmsg(
                stream.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count <= 0
            || count as usize > header.len()
            || message.msg_flags
                & (libc::MSG_TRUNC | libc::MSG_CTRUNC)
                != 0
        {
            return Err(
                "private DinD response frame is truncated".into(),
            );
        }
        let mut fds = Vec::new();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !cmsg.is_null() {
            unsafe {
                if (*cmsg).cmsg_level != libc::SOL_SOCKET
                    || (*cmsg).cmsg_type != libc::SCM_RIGHTS
                {
                    return Err(
                        "private DinD response control is unsupported"
                            .into(),
                    );
                }
                let bytes = (*cmsg)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize);
                let count = bytes / mem::size_of::<RawFd>();
                if bytes % mem::size_of::<RawFd>() != 0
                    || fds.len().saturating_add(count) > maximum_fds
                {
                    return Err(
                        "private DinD response FD set is invalid".into(),
                    );
                }
                let values = libc::CMSG_DATA(cmsg) as *const RawFd;
                for index in 0..count {
                    fds.push(OwnedFd::from_raw_fd(*values.add(index)));
                }
                cmsg = libc::CMSG_NXTHDR(&message, cmsg);
            }
        }
        if (count as usize) < header.len() {
            stream
                .read_exact(&mut header[count as usize..])
                .map_err(|error| error.to_string())?;
        }
        let decoded = AuthorityFrameHeaderV12::decode(
            &header,
            MAX_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let mut bytes = vec![0; decoded.payload_bytes as usize];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        if sha256_bytes(&bytes)
            != decoded
                .payload_sha256
                .decode()
                .map_err(|error| error.to_string())?
        {
            return Err(
                "private DinD response frame digest differs".into(),
            );
        }
        Ok((bytes, fds))
    }

    fn send_packet_with_fds(
        socket: RawFd,
        bytes: &[u8],
        fds: &[OwnedFd],
    ) -> Result<(), String> {
        if fds.is_empty() {
            let sent = unsafe {
                libc::send(
                    socket,
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent != bytes.len() as isize {
                return Err("lane proxy response was truncated".into());
            }
            return Ok(());
        }
        let raw = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let control_bytes = unsafe {
            libc::CMSG_SPACE(
                (raw.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        };
        let mut control =
            vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&message);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(
                (raw.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize;
            std::ptr::copy_nonoverlapping(
                raw.as_ptr(),
                libc::CMSG_DATA(cmsg) as *mut RawFd,
                raw.len(),
            );
        }
        let sent = unsafe {
            libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL)
        };
        if sent != bytes.len() as isize {
            return Err("lane proxy response was truncated".into());
        }
        Ok(())
    }
}
