#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[cfg(target_os = "linux")]
#[path = "../docker_contract.rs"]
mod docker_contract;
#[cfg(target_os = "linux")]
#[path = "../docker_policy.rs"]
mod docker_policy;
#[cfg(target_os = "linux")]
#[path = "../docker_ledger.rs"]
mod docker_ledger;
#[cfg(target_os = "linux")]
#[path = "../docker_transport.rs"]
mod docker_transport;
#[cfg(target_os = "linux")]
#[path = "../dind_lifecycle.rs"]
mod dind_lifecycle;
#[cfg(target_os = "linux")]
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("serverware-coder-docker-proxy-v11: Linux is required");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("serverware-coder-docker-proxy-v11: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_v12() -> std::result::Result<(), String> {
    linux::run().map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::coder_controller_v11::{
        constant_time_eq, digest_hex, now_unix_ms, sha256,
        sha256_exact_reader, ControllerError, Digest, Lane, Operation, Plan,
        PlanApiModeV11, PlanApiRequestV11, PlanApiResponseV11,
        PlanCapabilityRecordV11, Result, CONTROLLER_DOCKER_PROXY_SOCKET_PATH,
        CONTROLLER_PLAN_EXECUTOR_SOCKET_PATH, PLAN_API_REQUEST_BYTES,
        PLAN_API_RESPONSE_BYTES, PLAN_CAPABILITY_RECORD_BYTES,
    };
    use super::dind_lifecycle::{
        run_cleanup_helper_v11, DindLifecycleConfigV11,
        DindLifecycleV11,
    };
    use super::docker_contract::{
        boottime_now_ns_v11, AuthorizedDockerSignerV11,
        DockerApiRequestV11, DockerLaneCapabilityV11,
        DockerLaneProfileV11, DockerObjectStateV11,
        DockerResourceKindV11,
    };
    use super::docker_ledger::{
        observe_network_membership_v12, BeginMutationV11,
        DockerMutationRecordV11, DockerNetworkMembershipIntentV12,
        DockerObservedNetworkMembershipV12, DockerObservedObjectV11,
        DockerOwnershipLedgerV11, DockerReconcilerV11,
    };
    use super::docker_policy::{
        verify_build_context_spool_v11, DockerPolicyContextV11,
    };
    use super::docker_transport::{
        read_proxy_envelope_v11, relay_authorized_exchange_v11,
        release_spooled_response_v11,
    };
    use ed25519_dalek::VerifyingKey;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{
        FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Component, Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    const CONFIG_MAX_BYTES: u64 = 128 * 1024;
    const HTTP_HEADER_MAX_BYTES: usize = 64 * 1024;
    const HTTP_POLICY_BODY_MAX_BYTES: usize = 8 * 1024 * 1024;
    const HTTP_STREAM_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
    const EXECUTOR_PACKET_BYTES: usize =
        PLAN_API_REQUEST_BYTES + PLAN_CAPABILITY_RECORD_BYTES;
    const EXECUTOR_BACKLOG: libc::c_int = 8;
    const LOG_MAX_BYTES: u64 = 256 * 1024 * 1024;
    const DOCKER_START_TIMEOUT: Duration = Duration::from_secs(120);
    const RUNNER_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);
    const TERMINAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
    const MAX_PROXY_CONNECTIONS: usize = 64;
    const DOCKER_INFO_MAX_BYTES: u64 = 4 * 1024 * 1024;
    const PROC_RECORD_MAX_BYTES: u64 = 64 * 1024;

    static DOCKER_COMMAND_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone)]
    struct ExecutorConfig {
        executor_socket: PathBuf,
        proxy_socket: PathBuf,
        private_socket: PathBuf,
        state_root: PathBuf,
        source_root: PathBuf,
        artifact_root: PathBuf,
        client_uid: u32,
        client_gid: u32,
        dockerd_path: PathBuf,
        dockerd_sha256: Digest,
        docker_path: PathBuf,
        docker_sha256: Digest,
        nft_path: PathBuf,
        nft_sha256: Digest,
        pre_seal_rules: PathBuf,
        pre_seal_rules_sha256: Digest,
        post_seal_rules: PathBuf,
        post_seal_rules_sha256: Digest,
        runner_archive: PathBuf,
        runner_archive_sha256: Digest,
        runner_image: String,
        ledger_root: PathBuf,
        spool_root: PathBuf,
        lane_signer_public_key: PathBuf,
        lane_signer_principal_id: String,
        lane_signer_key_id: String,
        lane_signer_authorization_leaf_sha256: Digest,
        lane_signer_authorization_checkpoint_sha256: Digest,
        lane_signer_revocation_highwater: u64,
        lane_signer_not_before_boottime_ns: u64,
        lane_signer_not_after_boottime_ns: u64,
        request_signer_public_key: PathBuf,
        request_signer_principal_id: String,
        request_signer_key_id: String,
        request_signer_authorization_leaf_sha256: Digest,
        request_signer_authorization_checkpoint_sha256: Digest,
        request_signer_revocation_highwater: u64,
        request_signer_not_before_boottime_ns: u64,
        request_signer_not_after_boottime_ns: u64,
        lane_cgroup_root: PathBuf,
        lane_private_socket_root: PathBuf,
        oci_cas_root: PathBuf,
        oci_exporter_path: PathBuf,
        oci_exporter_sha256: Digest,
        docker_policy_sha256: Digest,
    }

    #[derive(Clone)]
    struct DaemonIdentity {
        pid: libc::pid_t,
        start_time_ticks: u64,
        socket_device: u64,
        socket_inode: u64,
        dockerd_sha256: Digest,
        daemon_id: String,
        identity_sha256: Digest,
    }

    struct DockerAuthority {
        child: Child,
        identity: DaemonIdentity,
        image_allowlist: BTreeSet<String>,
    }

    #[derive(Clone)]
    struct ActiveStage {
        lane: Lane,
        deadline_unix_ms: u64,
        runner_container_id: String,
        image_allowlist: BTreeSet<String>,
        request_sha256: Digest,
        request_nonce: Digest,
        daemon_identity_sha256: Digest,
        plan_capability_sha256: Digest,
        artifact_seal_sha256: Digest,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WorkflowState {
        Ready,
        BuildRunning,
        BuildSealed,
        UnitPassed,
        IntegrationPassed,
        E2ePassed,
        Terminal,
        Failed,
    }

    struct SharedState {
        workflow: WorkflowState,
        active: Option<ActiveStage>,
        authority: Option<DockerAuthority>,
        build_request_binding_sha256: Option<Digest>,
        artifact_seal_sha256: Option<Digest>,
        terminal_cleanup_sha256: Option<Digest>,
    }

    struct DockerAuthorityContext {
        ledger: Arc<DockerOwnershipLedgerV11>,
        lifecycle: Arc<DindLifecycleV11>,
        lane_signer: AuthorizedDockerSignerV11,
        request_signer: AuthorizedDockerSignerV11,
    }

    struct MountedOverlay {
        merged: PathBuf,
    }

    struct WorkflowFailureGuard<'a> {
        shared: &'a Mutex<SharedState>,
        armed: bool,
    }

    struct ProxyConnectionPermit {
        active: Arc<AtomicUsize>,
    }

    impl Drop for WorkflowFailureGuard<'_> {
        fn drop(&mut self) {
            if self.armed {
                if let Ok(mut state) = self.shared.lock() {
                    state.active = None;
                    state.workflow = WorkflowState::Failed;
                }
            }
        }
    }

    impl Drop for MountedOverlay {
        fn drop(&mut self) {
            let target = match c_path(&self.merged) {
                Ok(target) => target,
                Err(_) => return,
            };
            unsafe {
                libc::umount2(target.as_ptr(), libc::MNT_DETACH);
            }
        }
    }

    impl Drop for ProxyConnectionPermit {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub fn run() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(ControllerError::Rejected(
                "Docker authority must run as root",
            ));
        }
        unsafe {
            libc::umask(0o077);
        }
        require_verified_subreaper()?;
        let mut arguments = std::env::args();
        let _program = arguments.next();
        if arguments.next().as_deref()
            == Some("--dind-cleanup-helper-v11")
        {
            let ownership_root =
                arguments.next().ok_or(ControllerError::Invalid(
                    "cleanup helper ownership root is absent",
                ))?;
            let target = arguments.next().ok_or(
                ControllerError::Invalid(
                    "cleanup helper target is absent",
                ),
            )?;
            if arguments.next().is_some() {
                return Err(ControllerError::Invalid(
                    "cleanup helper received extra arguments",
                ));
            }
            return run_cleanup_helper_v11(
                Path::new(&ownership_root),
                Path::new(&target),
            );
        }
        let first_argument = std::env::args().nth(1);
        let mut arguments = std::env::args();
        let _program = arguments.next();
        if first_argument.as_deref() != Some("--config")
            || arguments.next().as_deref() != Some("--config")
        {
            return Err(ControllerError::Invalid(
                "usage: serverware-coder-docker-proxy --config PATH",
            ));
        }
        let config_path = arguments.next().ok_or(ControllerError::Invalid(
            "Docker authority config path is absent",
        ))?;
        if arguments.next().is_some() {
            return Err(ControllerError::Invalid(
                "Docker authority received extra arguments",
            ));
        }
        let config = Arc::new(load_config(Path::new(&config_path))?);
        prepare_runtime(&config)?;
        let ownership_ledger = Arc::new(
            DockerOwnershipLedgerV11::open(&config.ledger_root)?,
        );
        reconcile_startup_uncertain(
            &config,
            ownership_ledger.as_ref(),
        )?;
        let lane_lifecycle = Arc::new(DindLifecycleV11::open(
            DindLifecycleConfigV11 {
                state_root: config.state_root.join("lane-dind"),
                cgroup_root: config.lane_cgroup_root.clone(),
                private_socket_root:
                    config.lane_private_socket_root.clone(),
                oci_cas_root: config.oci_cas_root.clone(),
                dockerd_path: config.dockerd_path.clone(),
                dockerd_sha256: config.dockerd_sha256,
                docker_path: config.docker_path.clone(),
                docker_sha256: config.docker_sha256,
                oci_exporter_path:
                    config.oci_exporter_path.clone(),
                oci_exporter_sha256:
                    config.oci_exporter_sha256,
            },
            Arc::clone(&ownership_ledger),
        )?);
        let authority_context = Arc::new(DockerAuthorityContext {
            ledger: ownership_ledger,
            lifecycle: lane_lifecycle,
            lane_signer: load_authorized_signer(
                "controller-plan-executor",
                &config.lane_signer_public_key,
                &config.lane_signer_principal_id,
                &config.lane_signer_key_id,
                config.lane_signer_authorization_leaf_sha256,
                config
                    .lane_signer_authorization_checkpoint_sha256,
                config.lane_signer_revocation_highwater,
                config.lane_signer_not_before_boottime_ns,
                config.lane_signer_not_after_boottime_ns,
            )?,
            request_signer: load_authorized_signer(
                "controller-docker-request-authority",
                &config.request_signer_public_key,
                &config.request_signer_principal_id,
                &config.request_signer_key_id,
                config.request_signer_authorization_leaf_sha256,
                config
                    .request_signer_authorization_checkpoint_sha256,
                config.request_signer_revocation_highwater,
                config.request_signer_not_before_boottime_ns,
                config.request_signer_not_after_boottime_ns,
            )?,
        });
        apply_nft_rules(&config, false)?;
        let authority = start_disposable_dind(&config)?;
        let shared = Arc::new(Mutex::new(SharedState {
            workflow: WorkflowState::Ready,
            active: None,
            authority: Some(authority),
            build_request_binding_sha256: None,
            artifact_seal_sha256: None,
            terminal_cleanup_sha256: None,
        }));
        let proxy = bind_stream_socket(
            &config.proxy_socket,
            config.client_uid,
            config.client_gid,
            0o660,
        )?;
        let proxy_config = Arc::clone(&config);
        let proxy_shared = Arc::clone(&shared);
        let proxy_authority = Arc::clone(&authority_context);
        thread::Builder::new()
            .name("serverware-docker-policy-proxy".to_owned())
            .spawn(move || {
                serve_docker_proxy(
                    proxy,
                    proxy_config,
                    proxy_shared,
                    proxy_authority,
                );
            })
            .map_err(ControllerError::Io)?;

        let executor = bind_seqpacket_socket(
            &config.executor_socket,
            0,
            0,
            0o600,
            EXECUTOR_BACKLOG,
        )?;
        super::receipt_contract_v12::notify_systemd_v12(
            "docker-policy-authority-v12 ready",
        )
        .map_err(|error| {
            ControllerError::InvalidOwned(format!(
                "notify systemd readiness: {error}",
            ))
        })?;
        loop {
            let connection = accept_seqpacket(executor.as_raw_fd())?;
            require_root_peer(connection.as_raw_fd())?;
            let terminal = serve_plan_request(
                connection,
                Arc::clone(&config),
                Arc::clone(&shared),
            )?;
            if terminal {
                return Ok(());
            }
        }
    }

    fn require_verified_subreaper() -> Result<()> {
        if unsafe {
            libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                1,
                0,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut observed = 0;
        if unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &mut observed as *mut libc::c_int,
                0,
                0,
                0,
            )
        } != 0
            || observed != 1
        {
            return Err(ControllerError::Rejected(
                "Docker authority could not verify child-subreaper ownership",
            ));
        }
        Ok(())
    }

    fn load_config(path: &Path) -> Result<ExecutorConfig> {
        require_absolute_normalized(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > CONFIG_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "Docker authority config is not one immutable root-owned file",
            ));
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.iter().any(|byte| {
                *byte == 0 || (*byte < 0x20 && !matches!(*byte, b'\n'))
            })
        {
            return Err(ControllerError::Rejected(
                "Docker authority config contains noncanonical bytes",
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Invalid("config is not UTF-8"))?;
        let mut values = BTreeMap::<String, String>::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.trim() != line {
                return Err(ControllerError::Invalid(
                    "config lines must not have surrounding whitespace",
                ));
            }
            let (key, value) = line.split_once('=').ok_or(
                ControllerError::Invalid("config line lacks one equals sign"),
            )?;
            if key.is_empty()
                || value.is_empty()
                || key.bytes().any(|byte| {
                    !(byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.'))
                })
                || value.bytes().any(|byte| byte.is_ascii_whitespace())
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(ControllerError::Rejected(
                    "Docker authority config is duplicate or noncanonical",
                ));
            }
        }
        let take = |key: &str| -> Result<String> {
            values
                .get(key)
                .cloned()
                .ok_or_else(|| {
                    ControllerError::InvalidOwned(format!(
                        "missing Docker authority config key: {key}",
                    ))
                })
        };
        if take("version")? != "11" {
            return Err(ControllerError::Rejected(
                "Docker authority config version is not 11",
            ));
        }
        let config = ExecutorConfig {
            executor_socket: parse_path(&take("executor_socket")?)?,
            proxy_socket: parse_path(&take("proxy_socket")?)?,
            private_socket: parse_path(&take("private_socket")?)?,
            state_root: parse_path(&take("state_root")?)?,
            source_root: parse_path(&take("source_root")?)?,
            artifact_root: parse_path(&take("artifact_root")?)?,
            client_uid: parse_u32(&take("client_uid")?)?,
            client_gid: parse_u32(&take("client_gid")?)?,
            dockerd_path: parse_path(&take("dockerd_path")?)?,
            dockerd_sha256: parse_digest(&take("dockerd_sha256")?)?,
            docker_path: parse_path(&take("docker_path")?)?,
            docker_sha256: parse_digest(&take("docker_sha256")?)?,
            nft_path: parse_path(&take("nft_path")?)?,
            nft_sha256: parse_digest(&take("nft_sha256")?)?,
            pre_seal_rules: parse_path(&take("pre_seal_rules")?)?,
            pre_seal_rules_sha256: parse_digest(&take(
                "pre_seal_rules_sha256",
            )?)?,
            post_seal_rules: parse_path(&take("post_seal_rules")?)?,
            post_seal_rules_sha256: parse_digest(&take(
                "post_seal_rules_sha256",
            )?)?,
            runner_archive: parse_path(&take("runner_archive")?)?,
            runner_archive_sha256: parse_digest(&take(
                "runner_archive_sha256",
            )?)?,
            runner_image: take("runner_image")?,
            ledger_root: parse_path(&take("ledger_root")?)?,
            spool_root: parse_path(&take("spool_root")?)?,
            lane_signer_public_key: parse_path(&take(
                "lane_signer_public_key",
            )?)?,
            lane_signer_principal_id: take(
                "lane_signer_principal_id",
            )?,
            lane_signer_key_id: take("lane_signer_key_id")?,
            lane_signer_authorization_leaf_sha256: parse_digest(&take(
                "lane_signer_authorization_leaf_sha256",
            )?)?,
            lane_signer_authorization_checkpoint_sha256: parse_digest(
                &take(
                    "lane_signer_authorization_checkpoint_sha256",
                )?,
            )?,
            lane_signer_revocation_highwater: parse_u64(&take(
                "lane_signer_revocation_highwater",
            )?)?,
            lane_signer_not_before_boottime_ns: parse_u64(&take(
                "lane_signer_not_before_boottime_ns",
            )?)?,
            lane_signer_not_after_boottime_ns: parse_u64(&take(
                "lane_signer_not_after_boottime_ns",
            )?)?,
            request_signer_public_key: parse_path(&take(
                "request_signer_public_key",
            )?)?,
            request_signer_principal_id: take(
                "request_signer_principal_id",
            )?,
            request_signer_key_id: take("request_signer_key_id")?,
            request_signer_authorization_leaf_sha256: parse_digest(
                &take(
                    "request_signer_authorization_leaf_sha256",
                )?,
            )?,
            request_signer_authorization_checkpoint_sha256:
                parse_digest(&take(
                    "request_signer_authorization_checkpoint_sha256",
                )?)?,
            request_signer_revocation_highwater: parse_u64(&take(
                "request_signer_revocation_highwater",
            )?)?,
            request_signer_not_before_boottime_ns: parse_u64(&take(
                "request_signer_not_before_boottime_ns",
            )?)?,
            request_signer_not_after_boottime_ns: parse_u64(&take(
                "request_signer_not_after_boottime_ns",
            )?)?,
            lane_cgroup_root: parse_path(&take(
                "lane_cgroup_root",
            )?)?,
            lane_private_socket_root: parse_path(&take(
                "lane_private_socket_root",
            )?)?,
            oci_cas_root: parse_path(&take("oci_cas_root")?)?,
            oci_exporter_path: parse_path(&take(
                "oci_exporter_path",
            )?)?,
            oci_exporter_sha256: parse_digest(&take(
                "oci_exporter_sha256",
            )?)?,
            docker_policy_sha256: parse_digest(&take(
                "docker_policy_sha256",
            )?)?,
        };
        let expected: BTreeSet<&str> = [
            "version",
            "executor_socket",
            "proxy_socket",
            "private_socket",
            "state_root",
            "source_root",
            "artifact_root",
            "client_uid",
            "client_gid",
            "dockerd_path",
            "dockerd_sha256",
            "docker_path",
            "docker_sha256",
            "nft_path",
            "nft_sha256",
            "pre_seal_rules",
            "pre_seal_rules_sha256",
            "post_seal_rules",
            "post_seal_rules_sha256",
            "runner_archive",
            "runner_archive_sha256",
            "runner_image",
            "ledger_root",
            "spool_root",
            "lane_signer_public_key",
            "lane_signer_principal_id",
            "lane_signer_key_id",
            "lane_signer_authorization_leaf_sha256",
            "lane_signer_authorization_checkpoint_sha256",
            "lane_signer_revocation_highwater",
            "lane_signer_not_before_boottime_ns",
            "lane_signer_not_after_boottime_ns",
            "request_signer_public_key",
            "request_signer_principal_id",
            "request_signer_key_id",
            "request_signer_authorization_leaf_sha256",
            "request_signer_authorization_checkpoint_sha256",
            "request_signer_revocation_highwater",
            "request_signer_not_before_boottime_ns",
            "request_signer_not_after_boottime_ns",
            "lane_cgroup_root",
            "lane_private_socket_root",
            "oci_cas_root",
            "oci_exporter_path",
            "oci_exporter_sha256",
            "docker_policy_sha256",
        ]
        .into_iter()
        .collect();
        if values.keys().any(|key| !expected.contains(key.as_str())) {
            return Err(ControllerError::Rejected(
                "Docker authority config contains an unknown key",
            ));
        }
        if config.executor_socket
            != PathBuf::from(CONTROLLER_PLAN_EXECUTOR_SOCKET_PATH)
            || config.proxy_socket
                != PathBuf::from(CONTROLLER_DOCKER_PROXY_SOCKET_PATH)
            || config.private_socket
                != PathBuf::from("/run/serverware/private-docker-v11.sock")
            || config.state_root
                != PathBuf::from(
                    "/var/lib/serverware/coder-docker-proxy-v11",
                )
            || config.ledger_root
                != config.state_root.join("authority-ledger")
            || config.spool_root != config.state_root.join("spool")
            || config.lane_private_socket_root
                != config.state_root.join("lane-sockets")
            || config.oci_cas_root
                != config.state_root.join("oci-cas")
            || config.docker_policy_sha256 == [0; 32]
            || config.source_root == config.artifact_root
            || config.source_root.starts_with(&config.artifact_root)
            || config.artifact_root.starts_with(&config.source_root)
            || [
                &config.executor_socket,
                &config.proxy_socket,
                &config.private_socket,
                &config.state_root,
                &config.ledger_root,
                &config.spool_root,
                &config.lane_cgroup_root,
                &config.lane_private_socket_root,
                &config.oci_cas_root,
            ]
            .iter()
            .any(|protected| {
                protected.starts_with(&config.source_root)
                    || config.source_root.starts_with(protected)
                    || protected.starts_with(&config.artifact_root)
                    || config.artifact_root.starts_with(protected)
            })
            || !valid_digest_image_reference(&config.runner_image)
            || config.runner_image.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'/' | b':' | b'@' | b'.' | b'_' | b'-'
                    ))
            })
        {
            return Err(ControllerError::Rejected(
                "Docker authority config violates fixed v11 paths or image binding",
            ));
        }
        verify_file_digest(&config.dockerd_path, config.dockerd_sha256)?;
        verify_file_digest(&config.docker_path, config.docker_sha256)?;
        verify_file_digest(&config.nft_path, config.nft_sha256)?;
        verify_file_digest(
            &config.pre_seal_rules,
            config.pre_seal_rules_sha256,
        )?;
        verify_file_digest(
            &config.post_seal_rules,
            config.post_seal_rules_sha256,
        )?;
        verify_file_digest(
            &config.runner_archive,
            config.runner_archive_sha256,
        )?;
        verify_public_key_file(&config.lane_signer_public_key)?;
        verify_public_key_file(&config.request_signer_public_key)?;
        verify_file_digest(
            &config.oci_exporter_path,
            config.oci_exporter_sha256,
        )?;
        Ok(config)
    }

    fn prepare_runtime(config: &ExecutorConfig) -> Result<()> {
        require_directory(&config.source_root, None)?;
        require_directory(
            &config.artifact_root,
            Some((config.client_uid, config.client_gid)),
        )?;
        std::fs::create_dir_all(&config.state_root)?;
        std::fs::set_permissions(
            &config.state_root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let metadata = std::fs::symlink_metadata(&config.state_root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
        {
            return Err(ControllerError::Rejected(
                "Docker authority state root is not private root storage",
            ));
        }
        reconcile_stale_dind(config)?;
        for relative in [
            "dind-data",
            "dind-exec",
            "logs",
            "stages",
            "locks",
        ] {
            let path = config.state_root.join(relative);
            if path.exists() {
                remove_owned_tree(&config.state_root, &path)?;
            }
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        for path in [
            &config.ledger_root,
            &config.spool_root,
            &config.lane_private_socket_root,
            &config.oci_cas_root,
        ] {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o700),
            )?;
            require_directory(path, Some((0, 0)))?;
        }
        remove_socket_path(&config.executor_socket)?;
        remove_socket_path(&config.proxy_socket)?;
        remove_socket_path(&config.private_socket)?;
        Ok(())
    }

    fn reconcile_stale_dind(config: &ExecutorConfig) -> Result<()> {
        let pidfile = config.state_root.join("dockerd.pid");
        let pidfile_metadata = match std::fs::symlink_metadata(&pidfile) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let private_socket_exists =
            std::fs::symlink_metadata(&config.private_socket).is_ok();
        let Some(metadata) = pidfile_metadata else {
            if private_socket_exists {
                return Err(ControllerError::Rejected(
                    "stale private Docker socket lacks its controller pidfile",
                ));
            }
            return Ok(());
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > 32
        {
            return Err(ControllerError::Rejected(
                "stale Docker pidfile is not canonical root-owned state",
            ));
        }
        let pid_text = std::fs::read_to_string(&pidfile)?;
        let pid = pid_text
            .trim()
            .parse::<libc::pid_t>()
            .map_err(|_| {
                ControllerError::Invalid("stale Docker pidfile is invalid")
            })?;
        if pid <= 1 || pid == unsafe { libc::getpid() } {
            return Err(ControllerError::Rejected(
                "stale Docker pidfile identifies an unsafe process",
            ));
        }
        if std::fs::symlink_metadata(format!("/proc/{pid}")).is_ok() {
            verify_stale_dind_process(config, pid)?;
            let raw = unsafe {
                libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
            signal_pidfd(pidfd.as_raw_fd(), libc::SIGTERM)?;
            let graceful_deadline =
                Instant::now() + Duration::from_secs(10);
            if !wait_pidfd_exit(pidfd.as_raw_fd(), graceful_deadline)? {
                signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL)?;
                if !wait_pidfd_exit(
                    pidfd.as_raw_fd(),
                    Instant::now() + TERMINAL_CLEANUP_TIMEOUT,
                )? {
                    return Err(ControllerError::Rejected(
                        "stale disposable Docker daemon resisted bounded cleanup",
                    ));
                }
            }
        }
        std::fs::remove_file(pidfile)?;
        Ok(())
    }

    fn verify_stale_dind_process(
        config: &ExecutorConfig,
        pid: libc::pid_t,
    ) -> Result<()> {
        let mut status = Vec::new();
        File::open(format!("/proc/{pid}/status"))?
            .take(PROC_RECORD_MAX_BYTES + 1)
            .read_to_end(&mut status)?;
        if status.len() as u64 > PROC_RECORD_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "stale Docker process status exceeded its bound",
            ));
        }
        let status = std::str::from_utf8(&status).map_err(|_| {
            ControllerError::Invalid(
                "stale Docker process status is not UTF-8",
            )
        })?;
        let root_owned = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .is_some_and(|uids| {
                let values: Vec<&str> = uids.split_whitespace().collect();
                values.len() == 4 && values.iter().all(|value| *value == "0")
            });
        if !root_owned {
            return Err(ControllerError::Rejected(
                "stale Docker process is not root-owned",
            ));
        }
        let mut executable = File::open(format!("/proc/{pid}/exe"))?;
        let executable_metadata = executable.metadata()?;
        let executable_sha256 =
            sha256_exact_reader(&mut executable, executable_metadata.len())?;
        if !constant_time_eq(
            &executable_sha256,
            &config.dockerd_sha256,
        ) {
            return Err(ControllerError::Rejected(
                "stale Docker process executable is not the pinned daemon",
            ));
        }
        let mut command_line = Vec::new();
        File::open(format!("/proc/{pid}/cmdline"))?
            .take(PROC_RECORD_MAX_BYTES + 1)
            .read_to_end(&mut command_line)?;
        if command_line.len() as u64 > PROC_RECORD_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "stale Docker process command line exceeded its bound",
            ));
        }
        let arguments: Vec<&[u8]> = command_line
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect();
        let private_host =
            format!("unix://{}", config.private_socket.display());
        let data_root = config.state_root.join("dind-data");
        let exec_root = config.state_root.join("dind-exec");
        let pidfile = config.state_root.join("dockerd.pid");
        let has_pair = |key: &[u8], value: &[u8]| {
            arguments
                .windows(2)
                .any(|pair| pair[0] == key && pair[1] == value)
        };
        if arguments.first().copied()
            != Some(config.dockerd_path.as_os_str().as_bytes())
            || !has_pair(b"--host", private_host.as_bytes())
            || !has_pair(b"--data-root", data_root.as_os_str().as_bytes())
            || !has_pair(b"--exec-root", exec_root.as_os_str().as_bytes())
            || !has_pair(b"--pidfile", pidfile.as_os_str().as_bytes())
        {
            return Err(ControllerError::Rejected(
                "stale Docker process command line is outside controller ownership",
            ));
        }
        Ok(())
    }

    fn signal_pidfd(pidfd: RawFd, signal: libc::c_int) -> Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(())
    }

    fn wait_pidfd_exit(pidfd: RawFd, deadline: Instant) -> Result<bool> {
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now())
            else {
                return Ok(false);
            };
            let timeout_ms =
                remaining.as_millis().min(libc::c_int::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if result > 0 {
                return Ok(true);
            }
            if result == 0 {
                return Ok(false);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }

    fn start_disposable_dind(
        config: &ExecutorConfig,
    ) -> Result<DockerAuthority> {
        let log_path = config.state_root.join("logs/dockerd.log");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)?;
        let error_log = log.try_clone()?;
        let host = format!("unix://{}", config.private_socket.display());
        let data_root = config.state_root.join("dind-data");
        let exec_root = config.state_root.join("dind-exec");
        let pidfile = config.state_root.join("dockerd.pid");
        let mut command = Command::new(&config.dockerd_path);
        command
            .arg("--host")
            .arg(&host)
            .arg("--data-root")
            .arg(&data_root)
            .arg("--exec-root")
            .arg(&exec_root)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--live-restore=false")
            .arg("--userland-proxy=false")
            .arg("--log-driver=local")
            .arg("--label")
            .arg("com.serverware.coder-ci.disposable=true")
            .arg("--label")
            .arg("com.serverware.coder-ci.network=workspace-shared")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        let mut child = command.spawn()?;
        let deadline = Instant::now() + DOCKER_START_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(ControllerError::InvalidOwned(format!(
                    "disposable dockerd exited during startup: {status}",
                )));
            }
            if docker_ping(&config.private_socket).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                terminate_child(&mut child, TERMINAL_CLEANUP_TIMEOUT)?;
                return Err(ControllerError::Rejected(
                    "disposable dockerd did not become ready",
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
        std::fs::set_permissions(
            &config.private_socket,
            std::fs::Permissions::from_mode(0o600),
        )?;
        run_docker_command(
            config,
            [
                "load",
                "--input",
                config
                    .runner_archive
                    .to_str()
                    .ok_or(ControllerError::Invalid(
                        "runner archive path is not UTF-8",
                    ))?,
            ],
            DOCKER_START_TIMEOUT,
            "runner-load",
        )?;
        run_docker_command(
            config,
            ["image", "inspect", config.runner_image.as_str()],
            RUNNER_BOOTSTRAP_TIMEOUT,
            "runner-inspect",
        )?;
        let identity = measure_daemon(config, child.id() as libc::pid_t)?;
        Ok(DockerAuthority {
            child,
            identity,
            image_allowlist: BTreeSet::new(),
        })
    }

    fn apply_nft_rules(config: &ExecutorConfig, post_seal: bool) -> Result<()> {
        verify_file_digest(&config.nft_path, config.nft_sha256)?;
        let (rules, digest) = if post_seal {
            (&config.post_seal_rules, config.post_seal_rules_sha256)
        } else {
            (&config.pre_seal_rules, config.pre_seal_rules_sha256)
        };
        verify_file_digest(rules, digest)?;
        let status = Command::new(&config.nft_path)
            .arg("--check")
            .arg("--file")
            .arg(rules)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(ControllerError::Rejected(
                "pinned nftables policy did not pass a check-only load",
            ));
        }
        verify_file_digest(&config.nft_path, config.nft_sha256)?;
        let status = Command::new(&config.nft_path)
            .arg("--file")
            .arg(rules)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(ControllerError::Rejected(
                "pinned nftables policy could not be activated",
            ));
        }
        verify_file_digest(&config.nft_path, config.nft_sha256)?;
        verify_file_digest(rules, digest)?;
        Ok(())
    }

    fn serve_plan_request(
        connection: OwnedFd,
        config: Arc<ExecutorConfig>,
        shared: Arc<Mutex<SharedState>>,
    ) -> Result<bool> {
        let mut packet = [0u8; EXECUTOR_PACKET_BYTES];
        let count = unsafe {
            libc::recv(
                connection.as_raw_fd(),
                packet.as_mut_ptr() as *mut libc::c_void,
                packet.len(),
                libc::MSG_TRUNC,
            )
        };
        if count != EXECUTOR_PACKET_BYTES as isize {
            return Err(ControllerError::Rejected(
                "plan executor request is not one exact packet",
            ));
        }
        let request =
            PlanApiRequestV11::decode(&packet[..PLAN_API_REQUEST_BYTES])?;
        let capability = PlanCapabilityRecordV11::decode(
            &packet[PLAN_API_REQUEST_BYTES..],
        )?;
        validate_plan_binding(&request, &capability)?;
        let (response, terminal) = match request.mode {
            PlanApiModeV11::Bootstrap => (
                bootstrap_plan(&request, &capability, &config, &shared),
                false,
            ),
            PlanApiModeV11::Execute => {
                execute_plan(&request, &capability, &config, &shared)
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => PlanApiResponseV11::new(
                request.lane,
                request.request_sha256,
                request.request_nonce,
                request.expected_daemon_identity_sha256,
                sha256(error.to_string().as_bytes()),
                125,
            )?,
        };
        send_exact(connection.as_raw_fd(), &response.encode())?;
        Ok(terminal)
    }

    fn validate_plan_binding(
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
    ) -> Result<()> {
        if request.mode != capability.mode
            || request.lane != capability.lane
            || request.deadline_unix_ms != capability.deadline_unix_ms
            || sha256(&request.one_use_capability)
                != capability.capability_sha256
            || request.expected_daemon_identity_sha256
                != capability.daemon_identity_sha256
            || now_unix_ms()? >= request.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "plan executor request differs from its one-use capability",
            ));
        }
        Ok(())
    }

    fn bootstrap_plan(
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
    ) -> Result<PlanApiResponseV11> {
        verify_source_make_target(&config.source_root, request.lane.plan)?;
        verify_file_digest(&config.dockerd_path, config.dockerd_sha256)?;
        verify_file_digest(&config.docker_path, config.docker_sha256)?;
        verify_file_digest(
            &config.runner_archive,
            config.runner_archive_sha256,
        )?;
        {
            let guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected(
                    "Docker authority is terminal before bootstrap",
                ),
            )?;
            verify_daemon_identity(config, &authority.identity)?;
        }
        run_docker_command(
            config,
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                config.runner_image.as_str(),
                "/bin/sh",
                "-ec",
                "test -x /usr/bin/make && test -x /usr/bin/docker && docker compose version >/dev/null && test -x /usr/bin/python3 && test -x /usr/bin/curl",
            ],
            RUNNER_BOOTSTRAP_TIMEOUT,
            request.lane.plan.as_label(),
        )?;
        {
            let guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected(
                    "Docker authority is terminal after bootstrap",
                ),
            )?;
            verify_daemon_identity(config, &authority.identity)?;
        }
        let evidence = sha256(
            &[
                b"serverware/controller-plan-bootstrap/v11\0".as_slice(),
                request.request_sha256.as_slice(),
                capability.record_sha256.as_slice(),
                capability.artifact_seal_sha256.as_slice(),
                request.lane.plan.as_label().as_bytes(),
            ]
            .concat(),
        );
        PlanApiResponseV11::new(
            request.lane,
            request.request_sha256,
            request.request_nonce,
            request.expected_daemon_identity_sha256,
            evidence,
            0,
        )
    }

    fn execute_plan(
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
    ) -> (Result<PlanApiResponseV11>, bool) {
        let result = execute_plan_inner(request, capability, config, shared);
        let terminal = matches!(request.lane.plan, Plan::AttestationNoBuild)
            && result
                .as_ref()
                .map(|response| response.exit_status == 0)
                .unwrap_or(false);
        (result, terminal)
    }

    fn execute_plan_inner(
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
    ) -> Result<PlanApiResponseV11> {
        let expected_state = match request.lane.plan {
            Plan::Build => WorkflowState::Ready,
            Plan::UnitNoBuild => WorkflowState::BuildSealed,
            Plan::IntegrationNoBuild => WorkflowState::UnitPassed,
            Plan::E2eNoBuild => WorkflowState::IntegrationPassed,
            Plan::AttestationNoBuild => WorkflowState::E2ePassed,
        };
        {
            let mut guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            if guard.workflow != expected_state || guard.active.is_some() {
                return Err(ControllerError::Rejected(
                    "five-plan lifecycle is out of order or already active",
                ));
            }
            if request.lane.plan == Plan::Build {
                guard.workflow = WorkflowState::BuildRunning;
                guard.build_request_binding_sha256 =
                    Some(capability.request_binding_sha256);
            } else {
                match guard.artifact_seal_sha256 {
                    Some(seal)
                        if seal == capability.artifact_seal_sha256 => {}
                    None if request.lane.plan == Plan::UnitNoBuild => {}
                    _ => {
                        return Err(ControllerError::Rejected(
                            "no-build artifact seal differs from the first committed build",
                        ))
                    }
                }
            }
        }
        let mut failure_guard = WorkflowFailureGuard {
            shared,
            armed: true,
        };

        let overlay = if request.lane.operation == Operation::RunNoBuild {
            let mounted = mount_cas_overlay(
                config,
                capability.artifact_seal_sha256,
            )?;
            if request.lane.plan == Plan::UnitNoBuild {
                let mut guard = shared.lock().map_err(|_| {
                    ControllerError::Rejected(
                        "Docker authority state lock poisoned",
                    )
                })?;
                if guard.workflow != WorkflowState::BuildSealed
                    || guard.artifact_seal_sha256.is_some()
                {
                    return Err(ControllerError::Rejected(
                        "unit stage lost the first build-seal transition",
                    ));
                }
                guard.artifact_seal_sha256 =
                    Some(capability.artifact_seal_sha256);
            }
            Some(mounted)
        } else {
            None
        };
        let stage_artifact_root = overlay
            .as_ref()
            .map(|mounted| mounted.merged.as_path())
            .unwrap_or(config.artifact_root.as_path());
        if let Some(mounted) = &overlay {
            prepare_overlay_permissions(
                &mounted.merged,
                config.client_uid,
                config.client_gid,
            )?;
        }
        let target = fixed_make_target(request.lane.plan);
        let run_result = run_stage_container(
            config,
            shared,
            request,
            capability,
            stage_artifact_root,
            target,
        );
        drop(overlay);
        let (status, output_sha256) = match run_result {
            Ok(result) => result,
            Err(error) => {
                destroy_workflow_after_stage_failure(config, shared)?;
                failure_guard.armed = false;
                return Err(error);
            }
        };
        if status != 0 {
            destroy_workflow_after_stage_failure(config, shared)?;
            failure_guard.armed = false;
            return PlanApiResponseV11::new(
                request.lane,
                request.request_sha256,
                request.request_nonce,
                request.expected_daemon_identity_sha256,
                output_sha256,
                status,
            );
        }

        let mut terminal_cleanup = None;
        {
            let mut guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            guard.active = None;
            match request.lane.plan {
                Plan::Build => {
                    let authority = guard.authority.as_mut().ok_or(
                        ControllerError::Rejected(
                            "Docker authority vanished after build",
                        ),
                    )?;
                    verify_daemon_identity(config, &authority.identity)?;
                    authority.image_allowlist =
                        snapshot_image_allowlist(config)?;
                    if authority.image_allowlist.is_empty() {
                        guard.workflow = WorkflowState::Failed;
                        return Err(ControllerError::Rejected(
                            "build produced no sealed Docker image identities",
                        ));
                    }
                    apply_nft_rules(config, true)?;
                    guard.workflow = WorkflowState::BuildSealed;
                }
                Plan::UnitNoBuild => {
                    guard.workflow = WorkflowState::UnitPassed;
                }
                Plan::IntegrationNoBuild => {
                    guard.workflow = WorkflowState::IntegrationPassed;
                }
                Plan::E2eNoBuild => {
                    guard.workflow = WorkflowState::E2ePassed;
                }
                Plan::AttestationNoBuild => {
                    let cleanup = destroy_disposable_dind(config, &mut guard)?;
                    guard.terminal_cleanup_sha256 = Some(cleanup);
                    guard.workflow = WorkflowState::Terminal;
                    terminal_cleanup = Some(cleanup);
                }
            }
        }
        failure_guard.armed = false;
        let evidence = sha256(
            &[
                b"serverware/controller-plan-execution/v11\0".as_slice(),
                request.request_sha256.as_slice(),
                capability.record_sha256.as_slice(),
                capability.request_binding_sha256.as_slice(),
                capability.artifact_seal_sha256.as_slice(),
                output_sha256.as_slice(),
                terminal_cleanup.unwrap_or([0; 32]).as_slice(),
                request.lane.plan.as_label().as_bytes(),
            ]
            .concat(),
        );
        PlanApiResponseV11::new(
            request.lane,
            request.request_sha256,
            request.request_nonce,
            request.expected_daemon_identity_sha256,
            evidence,
            0,
        )
    }

    fn destroy_workflow_after_stage_failure(
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
    ) -> Result<()> {
        let mut guard = shared.lock().map_err(|_| {
            ControllerError::Rejected(
                "Docker workflow state lock poisoned during failure cleanup",
            )
        })?;
        guard.active = None;
        guard.workflow = WorkflowState::Failed;
        if guard.authority.is_some() {
            let cleanup = destroy_disposable_dind(config, &mut guard)?;
            guard.terminal_cleanup_sha256 = Some(cleanup);
        }
        Ok(())
    }

    fn run_stage_container(
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
        artifact_root: &Path,
        make_target: &str,
    ) -> Result<(i32, Digest)> {
        let remaining = request
            .deadline_unix_ms
            .checked_sub(now_unix_ms()?)
            .ok_or(ControllerError::Rejected(
                "stage deadline expired before runner creation",
            ))?;
        let timeout = Duration::from_millis(remaining);
        let suffix = &digest_hex(&request.request_sha256)[..24];
        let container_name = format!("serverware-controller-stage-{suffix}");
        let lock_root = config.state_root.join("locks");
        let source_mount = format!(
            "{}:{}:ro",
            path_text(&config.source_root)?,
            path_text(&config.source_root)?,
        );
        let artifact_mount = format!(
            "{}:{}:rw",
            path_text(artifact_root)?,
            path_text(&config.artifact_root)?,
        );
        let lock_mount =
            format!("{}:/run/lock:ro", path_text(&lock_root)?);
        let user = format!("{}:{}", config.client_uid, config.client_gid);
        let artifact_env = format!(
            "SERVERWARE_CONTROLLER_ARTIFACT_ROOT={}",
            path_text(&config.artifact_root)?,
        );
        let runtime_tmpfs_mount = format!(
            "type=tmpfs,destination=/run/user/{},tmpfs-mode=0700",
            config.client_uid,
        );
        let create = run_docker_command_capture(
            config,
            [
                "create",
                "--name",
                container_name.as_str(),
                "--network",
                "none",
                "--user",
                user.as_str(),
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "4096",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=2g,mode=1777",
                "--mount",
                runtime_tmpfs_mount.as_str(),
                "--volume",
                source_mount.as_str(),
                "--volume",
                artifact_mount.as_str(),
                "--volume",
                lock_mount.as_str(),
                "--workdir",
                path_text(&config.source_root)?,
                "--env",
                artifact_env.as_str(),
                "--env",
                "HOME=/tmp",
                config.runner_image.as_str(),
                "/usr/bin/make",
                "--no-print-directory",
                make_target,
            ],
            timeout.min(RUNNER_BOOTSTRAP_TIMEOUT),
            "stage-create",
        )?;
        let container_id = String::from_utf8(create)
            .map_err(|_| {
                ControllerError::Invalid("runner container ID is not UTF-8")
            })?
            .trim()
            .to_owned();
        if container_id.len() < 12
            || container_id.len() > 64
            || !container_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControllerError::Rejected(
                "runner container ID is noncanonical",
            ));
        }
        {
            let mut guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected("Docker authority is absent"),
            )?;
            verify_daemon_identity(config, &authority.identity)?;
            guard.active = Some(ActiveStage {
                lane: request.lane,
                deadline_unix_ms: request.deadline_unix_ms,
                runner_container_id: container_id.clone(),
                image_allowlist: authority.image_allowlist.clone(),
                request_sha256: request.request_sha256,
                request_nonce: request.request_nonce,
                daemon_identity_sha256:
                    request.expected_daemon_identity_sha256,
                plan_capability_sha256: sha256(
                    &request.one_use_capability,
                ),
                artifact_seal_sha256:
                    capability.artifact_seal_sha256,
            });
        }
        let output = run_docker_command_capture_status(
            config,
            ["start", "--attach", container_id.as_str()],
            timeout,
            request.lane.plan.as_label(),
        );
        let identity_after_start = {
            let guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected("Docker authority is absent"),
            )?;
            verify_daemon_identity(config, &authority.identity)
        };
        let remove = run_docker_command(
            config,
            ["rm", "--force", "--volumes", container_id.as_str()],
            TERMINAL_CLEANUP_TIMEOUT,
            "stage-remove",
        );
        let identity_after_remove = {
            let guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected("Docker authority is absent"),
            )?;
            verify_daemon_identity(config, &authority.identity)
        };
        identity_after_start?;
        remove?;
        identity_after_remove?;
        let (status, output) = output?;
        Ok((exit_code(status), sha256(&output)))
    }

    fn mount_cas_overlay(
        config: &ExecutorConfig,
        seal: Digest,
    ) -> Result<MountedOverlay> {
        let seal_hex = digest_hex(&seal);
        let lower = PathBuf::from(
            "/var/lib/serverware/coder-controller-v11/cas/sha256",
        )
        .join(&seal_hex)
        .join("partition-0000");
        require_directory(&lower, Some((0, 0)))?;
        let root = config.state_root.join("stages").join(&seal_hex);
        std::fs::create_dir_all(&root)?;
        let upper = root.join("upper");
        let work = root.join("work");
        let merged = root.join("merged");
        for path in [&upper, &work, &merged] {
            std::fs::create_dir_all(path)?;
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
            {
                return Err(ControllerError::Rejected(
                    "CAS overlay path is not controller-owned",
                ));
            }
        }
        verify_same_filesystem(&upper, &work)?;
        let options = CString::new(format!(
            "lowerdir={},upperdir={},workdir={}",
            path_text(&lower)?,
            path_text(&upper)?,
            path_text(&work)?,
        ))
        .map_err(|_| ControllerError::Invalid("overlay options contain NUL"))?;
        let source = CString::new("overlay").unwrap();
        let filesystem = CString::new("overlay").unwrap();
        let target = c_path(&merged)?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NODEV | libc::MS_NOSUID,
                options.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(MountedOverlay { merged })
    }

    fn prepare_overlay_permissions(
        root: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        let marker = root.join(".serverware-overlay-prepared-v11");
        if marker.is_file() {
            let metadata = std::fs::symlink_metadata(&marker)?;
            if metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.mode() & 0o777 == 0o400
            {
                return Ok(());
            }
            return Err(ControllerError::Rejected(
                "CAS overlay preparation marker is unsafe",
            ));
        }
        let mut pending = vec![root.to_path_buf()];
        let mut ordered = Vec::new();
        while let Some(path) = pending.pop() {
            if ordered.len() >= 1_000_000 {
                return Err(ControllerError::Rejected(
                    "CAS overlay permission preparation exceeded its entry bound",
                ));
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                chown_path(&path, uid, gid, true)?;
                continue;
            }
            if !metadata.is_dir() && !metadata.is_file() {
                return Err(ControllerError::Rejected(
                    "CAS overlay contains a special file",
                ));
            }
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            }
            ordered.push((path, metadata.is_dir(), metadata.mode()));
        }
        for (path, directory, mode) in ordered.into_iter().rev() {
            chown_path(&path, uid, gid, false)?;
            let writable_mode = if directory {
                (mode & 0o555) | 0o700
            } else {
                (mode & 0o555) | 0o600
            };
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(writable_mode),
            )?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&marker)?;
        file.write_all(b"serverware/controller-cas-overlay/v11\n")?;
        file.sync_all()?;
        chown_path(&marker, uid, gid, false)?;
        File::open(root)?.sync_all()?;
        Ok(())
    }

    fn chown_path(
        path: &Path,
        uid: u32,
        gid: u32,
        no_follow: bool,
    ) -> Result<()> {
        let path = c_path(path)?;
        let result = if no_follow {
            unsafe { libc::lchown(path.as_ptr(), uid, gid) }
        } else {
            unsafe { libc::chown(path.as_ptr(), uid, gid) }
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn destroy_disposable_dind(
        config: &ExecutorConfig,
        state: &mut SharedState,
    ) -> Result<Digest> {
        let mut authority = state.authority.take().ok_or(
            ControllerError::Rejected(
                "terminal cleanup lacks the disposable daemon",
            ),
        )?;
        verify_daemon_identity(config, &authority.identity)?;
        terminate_child(&mut authority.child, TERMINAL_CLEANUP_TIMEOUT)?;
        remove_socket_path(&config.private_socket)?;
        remove_socket_path(&config.proxy_socket)?;
        if process_start_time(authority.identity.pid).is_ok()
            || config.private_socket.exists()
            || config.proxy_socket.exists()
        {
            return Err(ControllerError::Rejected(
                "terminal cleanup did not destroy daemon and sockets",
            ));
        }
        let data = config.state_root.join("dind-data");
        let exec = config.state_root.join("dind-exec");
        remove_owned_tree(&config.state_root, &data)?;
        remove_owned_tree(&config.state_root, &exec)?;
        let evidence = sha256(
            &[
                b"serverware/disposable-dind-destroyed/v11\0".as_slice(),
                authority.identity.identity_sha256.as_slice(),
                config.private_socket.as_os_str().as_bytes(),
                config.proxy_socket.as_os_str().as_bytes(),
            ]
            .concat(),
        );
        Ok(evidence)
    }

    fn serve_docker_proxy(
        listener: UnixListener,
        config: Arc<ExecutorConfig>,
        shared: Arc<Mutex<SharedState>>,
        authority: Arc<DockerAuthorityContext>,
    ) {
        let active_connections = Arc::new(AtomicUsize::new(0));
        for incoming in listener.incoming() {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = destroy_authority_on_proxy_error(
                        &config,
                        &shared,
                        &authority,
                        sha256(error.to_string().as_bytes()),
                    );
                    return;
                }
            };
            let accepted = active_connections.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| {
                    (current < MAX_PROXY_CONNECTIONS)
                        .then_some(current + 1)
                },
            );
            if accepted.is_err() {
                drop(stream);
                let _ = destroy_authority_on_proxy_error(
                    &config,
                    &shared,
                    &authority,
                    sha256(
                        b"serverware/docker-proxy-connection-bound/v11",
                    ),
                );
                return;
            }
            let task_config = Arc::clone(&config);
            let task_shared = Arc::clone(&shared);
            let task_authority = Arc::clone(&authority);
            let active = Arc::clone(&active_connections);
            if thread::Builder::new()
                .name("serverware-docker-proxy-connection".to_owned())
                .spawn(move || {
                    let _permit = ProxyConnectionPermit { active };
                    if let Err(error) = proxy_one_request(
                        stream,
                        &task_config,
                        &task_shared,
                        &task_authority,
                    ) {
                        let _ = destroy_authority_on_proxy_error(
                            &task_config,
                            &task_shared,
                            &task_authority,
                            sha256(error.to_string().as_bytes()),
                        );
                    }
                })
                .is_err()
            {
                active_connections.fetch_sub(1, Ordering::AcqRel);
                let _ = destroy_authority_on_proxy_error(
                    &config,
                    &shared,
                    &authority,
                    sha256(
                        b"serverware/docker-proxy-thread-start-failed/v11",
                    ),
                );
                return;
            }
        }
    }

    fn proxy_one_request(
        mut client: UnixStream,
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
        authority: &DockerAuthorityContext,
    ) -> Result<()> {
        let peer = stream_peer(&client)?;
        if peer.uid != config.client_uid || peer.gid != config.client_gid {
            return Err(ControllerError::Rejected(
                "Docker proxy peer credential is not the configured runner",
            ));
        }
        let start_time = process_start_time(peer.pid)?;
        let active = {
            let guard = shared.lock().map_err(|_| {
                ControllerError::Rejected("Docker authority state lock poisoned")
            })?;
            let active = guard.active.clone().ok_or(
                ControllerError::Rejected(
                    "Docker proxy has no active fixed-plan lease",
                ),
            )?;
            let authority = guard.authority.as_ref().ok_or(
                ControllerError::Rejected(
                    "Docker proxy daemon is terminal",
                ),
            )?;
            verify_daemon_identity(config, &authority.identity)?;
            active
        };
        let remaining = active
            .deadline_unix_ms
            .checked_sub(now_unix_ms()?)
            .ok_or(ControllerError::Rejected(
                "Docker proxy stage deadline expired",
            ))?;
        let absolute_deadline_boottime_ns = boottime_now_ns_v11()?
            .checked_add(remaining.saturating_mul(1_000_000))
            .ok_or(ControllerError::Invalid(
                "Docker proxy BOOTTIME deadline overflowed",
            ))?;
        let (
            mut envelope,
            (
                capability,
                request,
                operation_deadline,
                _lane_operation_lease,
            ),
        ) = read_proxy_envelope_v11(
            &mut client,
            &config.spool_root,
            absolute_deadline_boottime_ns,
            HTTP_STREAM_MAX_BYTES,
            |header, capability_bytes, request_bytes, http| {
                let now_boottime_ns = boottime_now_ns_v11()?;
                let capability =
                    DockerLaneCapabilityV11::parse_and_verify(
                        capability_bytes,
                        &authority.lane_signer,
                        now_boottime_ns,
                    )?;
                if sha256(&capability.canonical_sha256)
                    != active.plan_capability_sha256
                    || capability.deadline_boottime_ns
                        > absolute_deadline_boottime_ns
                    || capability.artifact_seal_sha256
                        != active.artifact_seal_sha256
                    || capability.policy_sha256
                        != config.docker_policy_sha256
                    || !lane_profile_matches(
                        active.lane,
                        capability.profile,
                    )
                {
                    return Err(ControllerError::Rejected(
                        "signed Docker capability differs from the active controller lane",
                    ));
                }
                let request = DockerApiRequestV11::parse_and_verify(
                    request_bytes,
                    &authority.request_signer,
                    &capability,
                    now_boottime_ns,
                )?;
                if request.stream_mode != header.stream_mode {
                    return Err(ControllerError::Rejected(
                        "Docker proxy envelope stream mode differs from the signed request",
                    ));
                }
                request.verify_wire_binding(
                    &http.method,
                    &http.normalized_route,
                    &http.canonical_query,
                    header.body_sha256,
                    header.body_bytes,
                )?;
                let duration_ns = request
                    .limits
                    .max_duration_ms
                    .checked_mul(1_000_000)
                    .ok_or(ControllerError::Invalid(
                        "Docker signed duration overflowed",
                    ))?;
                let operation_deadline = request
                    .deadline_boottime_ns
                    .min(now_boottime_ns.checked_add(duration_ns).ok_or(
                        ControllerError::Invalid(
                            "Docker operation deadline overflowed",
                        ),
                    )?);
                let lane_operation_lease =
                    authority.ledger.acquire_lane_operation(
                        &request.owner_namespace,
                        &request.lane_id,
                        operation_deadline,
                    )?;
                Ok((
                    (
                        capability,
                        request,
                        operation_deadline,
                        lane_operation_lease,
                    ),
                    operation_deadline,
                ))
            },
        )?;
        if let Some((response_path, response_bytes, response_sha256)) =
            authority.ledger.exact_replay(&request)?
        {
            return release_spooled_response_v11(
                &mut client,
                &response_path,
                response_bytes,
                response_sha256,
                operation_deadline,
            );
        }
        let policy_body = if envelope.body.length()
            <= HTTP_POLICY_BODY_MAX_BYTES as u64
        {
            let mut file = envelope.body.file()?;
            let mut body =
                Vec::with_capacity(envelope.body.length() as usize);
            file.read_to_end(&mut body)?;
            body
        } else {
            vec![0]
        };
        let policy = DockerPolicyContextV11 {
            capability: &capability,
            ownership: authority.ledger.as_ref(),
        };
        if request.profile == DockerLaneProfileV11::Build
            && request.normalized_route == "/build"
        {
            verify_build_context_spool_v11(
                envelope.body.path(),
                request.body_sha256,
                capability.build_tuple.as_ref().ok_or(
                    ControllerError::Rejected(
                        "build request lacks its exact build tuple",
                    ),
                )?,
                &capability.allowed_pinned_pulls,
            )?;
        }
        let decision = policy.authorize(&request, &policy_body)?;
        let prepared = if decision.mutating {
            match authority
                .ledger
                .begin_mutation(
                    &request,
                    &decision.required_owner_labels,
                    capability.limits.max_objects.ok_or(
                        ControllerError::Rejected(
                            "Docker lane capability lacks its object bound",
                        ),
                    )?,
                    capability.sequence_start,
                )?
            {
                BeginMutationV11::Prepared(prepared) => Some(prepared),
                BeginMutationV11::ExactReplay {
                    response_path,
                    response_bytes,
                    response_sha256,
                    ..
                } => {
                    return release_spooled_response_v11(
                        &mut client,
                        &response_path,
                        response_bytes,
                        response_sha256,
                        operation_deadline,
                    );
                }
                BeginMutationV11::RequiresReconciliation(record) => {
                    let lane_private_socket = authority
                        .lifecycle
                        .ensure_lane_generation(
                            &capability,
                            operation_deadline,
                        )?;
                    let mut lane_config = config.clone();
                    lane_config.private_socket = lane_private_socket;
                    let reconciler = ExistingDaemonReconciler {
                        config: &lane_config,
                    };
                    let terminal = authority.ledger.reconcile_unknown(
                        &record.request_id,
                        &reconciler,
                        operation_deadline,
                    )?;
                    if terminal.status
                        != super::docker_ledger::DockerMutationStatusV11::Applied
                    {
                        destroy_failed_lane(
                            config,
                            shared,
                            authority,
                            &capability,
                            sha256(
                                b"serverware/docker-reconciliation-not-applied/v11",
                            ),
                        )?;
                        return Err(ControllerError::Rejected(
                            "Docker uncertain mutation did not reconcile to APPLIED",
                        ));
                    }
                    return Err(ControllerError::Rejected(
                        "Docker reconciled mutation requires exact-byte retrieval before retry",
                    ));
                }
            }
        } else {
            authority.ledger.commit_read_sequence(
                &request,
                capability.sequence_start,
            )?;
            None
        };
        let lane_private_socket =
            authority
                .lifecycle
                .ensure_lane_generation(&capability, operation_deadline)?;
        let mut daemon = UnixStream::connect(&lane_private_socket)?;
        let receipt = match relay_authorized_exchange_v11(
            &mut client,
            &mut daemon,
            &envelope,
            &config.spool_root,
            &request.limits,
            operation_deadline,
            !decision.mutating,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(prepared) = prepared {
                    let reason = sha256(error.to_string().as_bytes());
                    let request_id =
                        prepared.record.request_id.clone();
                    let _ =
                        authority.ledger.mark_unknown(prepared, reason);
                    let _ = reconcile_uncertain_before_destroy(
                        config,
                        authority,
                        &request_id,
                        &lane_private_socket,
                        operation_deadline,
                    );
                    let _ = destroy_failed_lane(
                        config,
                        shared,
                        authority,
                        &capability,
                        reason,
                    );
                }
                return Err(error);
            }
        };
        if !decision.mutating {
            std::fs::remove_file(&receipt.response_path)?;
            return Ok(());
        }
        let prepared = prepared.ok_or(ControllerError::Rejected(
            "Docker mutating decision lacks durable intent",
        ))?;
        if !(200..300).contains(&receipt.status_code) {
            let reason = sha256(
                &[
                    b"serverware/docker-terminal-http-error/v11\0".as_slice(),
                    &receipt.status_code.to_be_bytes(),
                    receipt.response_sha256.as_slice(),
                ]
                .concat(),
            );
            let request_id = prepared.record.request_id.clone();
            authority.ledger.mark_unknown(prepared, reason)?;
            let _ = reconcile_uncertain_before_destroy(
                config,
                authority,
                &request_id,
                &lane_private_socket,
                operation_deadline,
            );
            destroy_failed_lane(
                config,
                shared,
                authority,
                &capability,
                reason,
            )?;
            return Err(ControllerError::Rejected(
                "Docker mutation returned a non-success status and destroyed the lane",
            ));
        }
        let engine_id = match extract_response_engine_id(
            &receipt.response_path,
            receipt.response_bytes,
            decision.response_engine_id_pointer,
        ) {
            Ok(engine_id) => engine_id,
            Err(error) => {
                let reason = sha256(error.to_string().as_bytes());
                let request_id =
                    prepared.record.request_id.clone();
                authority
                    .ledger
                    .mark_unknown(prepared.clone(), reason)?;
                let _ = reconcile_uncertain_before_destroy(
                    config,
                    authority,
                    &request_id,
                    &lane_private_socket,
                    operation_deadline,
                );
                destroy_failed_lane(
                    config,
                    shared,
                    authority,
                    &capability,
                    reason,
                )?;
                return Err(error);
            }
        };
        if boottime_now_ns_v11()? >= operation_deadline
            || process_start_time(peer.pid)? != start_time
        {
            let reason = sha256(
                b"serverware/docker-request-authority-peer-changed/v11",
            );
            let request_id = prepared.record.request_id.clone();
            authority
                .ledger
                .mark_unknown(prepared.clone(), reason)?;
            let _ = reconcile_uncertain_before_destroy(
                config,
                authority,
                &request_id,
                &lane_private_socket,
                operation_deadline,
            );
            destroy_failed_lane(
                config,
                shared,
                authority,
                &capability,
                reason,
            )?;
            return Err(ControllerError::Rejected(
                "Docker request authority process identity changed",
            ));
        }
        if let Err(error) = authority.ledger.commit_applied_spool(
            prepared.clone(),
            &receipt.response_path,
            receipt.response_bytes,
            receipt.response_sha256,
            engine_id.as_deref(),
        ) {
            let reason = sha256(error.to_string().as_bytes());
            let request_id = prepared.record.request_id.clone();
            let _ = authority.ledger.mark_unknown(prepared, reason);
            let _ = reconcile_uncertain_before_destroy(
                config,
                authority,
                &request_id,
                &lane_private_socket,
                operation_deadline,
            );
            destroy_failed_lane(
                config,
                shared,
                authority,
                &capability,
                reason,
            )?;
            return Err(error);
        }
        let lifecycle_result = if request.sequence
            == capability.sequence_end
            && capability.profile == DockerLaneProfileV11::Build
        {
            authority
                .lifecycle
                .seal_build_to_cas(&capability, operation_deadline)
                .map(|_| ())
        } else if request.sequence == capability.sequence_end
            && capability.profile != DockerLaneProfileV11::Build
        {
            authority.lifecycle.finish_no_build(
                &capability.owner_namespace,
                &capability.daemon_generation,
            )
        } else {
            Ok(())
        };
        if let Err(error) = lifecycle_result {
            let reason = sha256(error.to_string().as_bytes());
            let _ = destroy_failed_lane(
                config,
                shared,
                authority,
                &capability,
                reason,
            );
            return Err(error);
        }
        release_spooled_response_v11(
            &mut client,
            &receipt.response_path,
            receipt.response_bytes,
            receipt.response_sha256,
            operation_deadline,
        )?;
        std::fs::remove_file(&receipt.response_path)?;
        envelope.body.remove()?;
        Ok(())
    }

    fn reconcile_uncertain_before_destroy(
        config: &ExecutorConfig,
        authority: &DockerAuthorityContext,
        request_id: &str,
        lane_private_socket: &Path,
        deadline_boottime_ns: u64,
    ) -> Result<()> {
        if boottime_now_ns_v11()? >= deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "Docker reconciliation deadline expired before exact query",
            ));
        }
        let mut lane_config = config.clone();
        lane_config.private_socket = lane_private_socket.to_path_buf();
        let reconciler = ExistingDaemonReconciler {
            config: &lane_config,
        };
        authority
            .ledger
            .reconcile_unknown(
                request_id,
                &reconciler,
                deadline_boottime_ns,
            )
            .map(|_| ())
    }

    fn reconcile_startup_uncertain(
        config: &ExecutorConfig,
        ledger: &DockerOwnershipLedgerV11,
    ) -> Result<()> {
        for record in ledger.startup_uncertain_mutations()? {
            if boottime_now_ns_v11()? >= record.deadline_boottime_ns {
                continue;
            }
            let mut lane_config = config.clone();
            lane_config.private_socket = config
                .lane_private_socket_root
                .join(format!(
                    "{}--{}.sock",
                    record.owner_namespace,
                    record.daemon_generation,
                ));
            let reconciler = ExistingDaemonReconciler {
                config: &lane_config,
            };
            let _ = ledger.reconcile_unknown(
                &record.request_id,
                &reconciler,
                record.deadline_boottime_ns,
            );
        }
        Ok(())
    }

    fn lane_profile_matches(
        lane: Lane,
        profile: DockerLaneProfileV11,
    ) -> bool {
        matches!(
            (lane.plan, profile),
            (Plan::Build, DockerLaneProfileV11::Build)
                | (
                    Plan::UnitNoBuild,
                    DockerLaneProfileV11::UnitNoBuild
                )
                | (
                    Plan::IntegrationNoBuild,
                    DockerLaneProfileV11::IntegrationNoBuild
                )
                | (
                    Plan::E2eNoBuild,
                    DockerLaneProfileV11::E2eNoBuild
                )
                | (
                    Plan::AttestationNoBuild,
                    DockerLaneProfileV11::AttestationNoBuild
                )
        )
    }

    fn destroy_failed_lane(
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
        authority: &DockerAuthorityContext,
        capability: &DockerLaneCapabilityV11,
        reason_sha256: Digest,
    ) -> Result<()> {
        let lifecycle_result = authority.lifecycle.fail_lane(
            &capability.owner_namespace,
            &capability.daemon_generation,
            reason_sha256,
        );
        let mut guard = shared.lock().map_err(|_| {
            ControllerError::Rejected(
                "Docker authority state lock poisoned during destruction",
            )
        })?;
        guard.workflow = WorkflowState::Failed;
        guard.active = None;
        if guard.authority.is_some() {
            let _ = destroy_disposable_dind(config, &mut guard)?;
        }
        lifecycle_result
    }

    fn destroy_authority_on_proxy_error(
        config: &ExecutorConfig,
        shared: &Mutex<SharedState>,
        authority: &DockerAuthorityContext,
        reason_sha256: Digest,
    ) -> Result<()> {
        let lifecycle_result =
            authority.lifecycle.fail_all(reason_sha256);
        let mut guard = shared.lock().map_err(|_| {
            ControllerError::Rejected(
                "Docker authority state lock poisoned during emergency destruction",
            )
        })?;
        guard.workflow = WorkflowState::Failed;
        guard.active = None;
        if guard.authority.is_some() {
            let _ = destroy_disposable_dind(config, &mut guard)?;
        }
        lifecycle_result
    }

    fn extract_response_engine_id(
        path: &Path,
        response_bytes: u64,
        pointer: Option<&str>,
    ) -> Result<Option<String>> {
        let Some(pointer) = pointer else {
            return Ok(None);
        };
        if response_bytes > HTTP_POLICY_BODY_MAX_BYTES as u64 {
            return Err(ControllerError::Rejected(
                "Docker create response exceeds its policy parsing bound",
            ));
        }
        let mut bytes = Vec::with_capacity(response_bytes as usize);
        File::open(path)?.read_to_end(&mut bytes)?;
        let end = header_end(&bytes).ok_or(ControllerError::Rejected(
            "Docker create response lacks a complete header",
        ))?;
        let body = &bytes[end + 4..];
        let value: Value = serde_json::from_slice(body).map_err(|_| {
            ControllerError::Invalid(
                "Docker create response body is not JSON",
            )
        })?;
        let engine_id = value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(ControllerError::Rejected(
                "Docker create response lacks its exact engine ID",
            ))?;
        if engine_id.is_empty()
            || engine_id.len() > 512
            || engine_id.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'.' | b'_' | b':' | b'@' | b'/' | b'-'
                    ))
            })
        {
            return Err(ControllerError::Rejected(
                "Docker create response engine ID is noncanonical",
            ));
        }
        Ok(Some(engine_id.to_owned()))
    }

    struct ExistingDaemonReconciler<'a> {
        config: &'a ExecutorConfig,
    }

    impl DockerReconcilerV11 for ExistingDaemonReconciler<'_> {
        fn query_exact(
            &self,
            record: &DockerMutationRecordV11,
            deadline_boottime_ns: u64,
        ) -> Result<DockerObservedObjectV11> {
            let remaining_ns = deadline_boottime_ns
                .checked_sub(boottime_now_ns_v11()?)
                .ok_or(ControllerError::Rejected(
                    "Docker reconciliation deadline expired",
                ))?;
            let timeout = Duration::from_nanos(remaining_ns);
            let kind = match record.kind {
                DockerResourceKindV11::Container => "container",
                DockerResourceKindV11::Network => "network",
                DockerResourceKindV11::Volume => "volume",
                DockerResourceKindV11::Image
                | DockerResourceKindV11::Build => "image",
                _ => {
                    return Err(ControllerError::Rejected(
                        "Docker UNKNOWN target kind has no exact reconciliation query",
                    ))
                }
            };
            let (engine_id, output) = if let Some(engine_id) =
                record.engine_id.as_deref()
            {
                (
                    Some(engine_id.to_owned()),
                    run_docker_command_capture(
                        self.config,
                        [kind, "inspect", engine_id],
                        timeout,
                        "reconcile-inspect",
                    )
                    .ok(),
                )
            } else {
                let owner_filter = format!(
                    "label=com.serverware.controller.owner-namespace={}",
                    record.owner_namespace
                );
                let generation_filter = format!(
                    "label=com.serverware.controller.daemon-generation={}",
                    record.daemon_generation
                );
                let logical_filter = format!(
                    "label=com.serverware.controller.logical-id={}",
                    record.logical_id
                );
                let mut arguments = vec![
                    kind,
                    "ls",
                    "--no-trunc",
                    "--filter",
                    owner_filter.as_str(),
                    "--filter",
                    generation_filter.as_str(),
                    "--filter",
                    logical_filter.as_str(),
                    "--format",
                    "{{.ID}}",
                ];
                if matches!(kind, "container" | "image") {
                    arguments.insert(2, "--all");
                }
                let output = run_docker_command_capture(
                    self.config,
                    arguments,
                    timeout,
                    "reconcile-list",
                )?;
                let identifiers: Vec<&str> = std::str::from_utf8(&output)
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "Docker reconciliation list is not UTF-8",
                        )
                    })?
                    .lines()
                    .filter(|line| !line.is_empty())
                    .collect();
                if identifiers.len() > 1 {
                    return Err(ControllerError::Rejected(
                        "Docker reconciliation found multiple owner objects",
                    ));
                }
                if let Some(engine_id) = identifiers.first() {
                    (
                        Some((*engine_id).to_owned()),
                        Some(run_docker_command_capture(
                            self.config,
                            [kind, "inspect", *engine_id],
                            timeout,
                            "reconcile-inspect",
                        )?),
                    )
                } else {
                    (None, None)
                }
            };
            let Some(output) = output else {
                return Ok(DockerObservedObjectV11 {
                    exists: false,
                    engine_id: None,
                    state: DockerObjectStateV11::Destroyed,
                    labels: BTreeMap::new(),
                    observation_sha256: sha256(
                        &[
                            b"serverware/docker-reconcile-absent/v11\0"
                                .as_slice(),
                            record.request_sha256.as_slice(),
                        ]
                        .concat(),
                    ),
                });
            };
            let value: Value =
                serde_json::from_slice(&output).map_err(|_| {
                    ControllerError::Invalid(
                        "Docker reconciliation inspect output is not JSON",
                    )
                })?;
            let inspected = value
                .as_array()
                .and_then(|values| {
                    (values.len() == 1).then(|| &values[0])
                })
                .ok_or(ControllerError::Rejected(
                    "Docker reconciliation inspect result is not singular",
                ))?;
            let labels = inspected
                .pointer("/Config/Labels")
                .or_else(|| inspected.pointer("/Labels"))
                .and_then(Value::as_object)
                .ok_or(ControllerError::Rejected(
                    "Docker reconciliation object lacks owner labels",
                ))?
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_owned()))
                        .ok_or(ControllerError::Invalid(
                            "Docker reconciliation label is not a string",
                        ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let state = inspected
                .pointer("/State/Running")
                .and_then(Value::as_bool)
                .map(|running| {
                    if running {
                        DockerObjectStateV11::Running
                    } else {
                        DockerObjectStateV11::Exited
                    }
                })
                .unwrap_or(DockerObjectStateV11::Created);
            Ok(DockerObservedObjectV11 {
                exists: true,
                engine_id,
                state,
                labels,
                observation_sha256: sha256(&output),
            })
        }

        fn query_network_membership(
            &self,
            _record: &DockerMutationRecordV11,
            membership: &DockerNetworkMembershipIntentV12,
            deadline_boottime_ns: u64,
        ) -> Result<DockerObservedNetworkMembershipV12> {
            let remaining_ns = deadline_boottime_ns
                .checked_sub(boottime_now_ns_v11()?)
                .ok_or(ControllerError::Rejected(
                    "Docker network-membership reconciliation deadline expired",
                ))?;
            let output = run_docker_command_capture(
                self.config,
                [
                    "network",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    membership.network_engine_id.as_str(),
                ],
                Duration::from_nanos(remaining_ns),
                "reconcile-network-membership",
            )?;
            observe_network_membership_v12(&output, membership)
        }
    }

    struct HttpRequest {
        method: String,
        path: String,
        body: Vec<u8>,
        raw: Vec<u8>,
        framing: RequestBodyFraming,
    }

    enum RequestBodyFraming {
        None,
        ContentLength(usize),
        Chunked(Vec<u8>),
    }

    fn read_http_request(stream: &mut UnixStream) -> Result<HttpRequest> {
        let mut raw = read_until_header(stream, HTTP_HEADER_MAX_BYTES)?;
        let header_end = header_end(&raw).ok_or(ControllerError::Invalid(
            "Docker HTTP request header is incomplete",
        ))?;
        let header_text = std::str::from_utf8(&raw[..header_end])
            .map_err(|_| ControllerError::Invalid("Docker HTTP header is not UTF-8"))?;
        let first = header_text
            .lines()
            .next()
            .ok_or(ControllerError::Invalid("Docker HTTP request line is absent"))?;
        let mut fields = first.split(' ');
        let method = fields
            .next()
            .ok_or(ControllerError::Invalid("Docker HTTP method is absent"))?
            .to_owned();
        let path = fields
            .next()
            .ok_or(ControllerError::Invalid("Docker HTTP path is absent"))?
            .to_owned();
        if fields.next().is_none()
            || fields.next().is_some()
            || !matches!(
                method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "DELETE"
            )
            || !path.starts_with('/')
            || path.contains('\\')
            || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ControllerError::Rejected(
                "Docker HTTP request line is noncanonical",
            ));
        }
        let mut content_length = None;
        let mut chunked = false;
        for line in header_text.lines().skip(1) {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or(
                ControllerError::Invalid("Docker HTTP header lacks a colon"),
            )?;
            if name.eq_ignore_ascii_case("content-length") {
                if content_length
                    .replace(value.trim().parse::<usize>().map_err(|_| {
                        ControllerError::Invalid(
                            "Docker HTTP content length is invalid",
                        )
                    })?)
                    .is_some()
                {
                    return Err(ControllerError::Rejected(
                        "Docker HTTP content length is duplicated",
                    ));
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if value.trim().eq_ignore_ascii_case("chunked") {
                    chunked = true;
                } else {
                    return Err(ControllerError::Rejected(
                        "unsupported Docker HTTP transfer encoding",
                    ));
                }
            }
        }
        if content_length.is_some() && chunked {
            return Err(ControllerError::Rejected(
                "Docker HTTP request is both length-delimited and chunked",
            ));
        }
        let body_offset = header_end + 4;
        let normalized_path = normalized_api_path(&path)?;
        let policy_body_required = normalized_path == "/containers/create"
            || (normalized_path.starts_with("/containers/")
                && terminal_component(normalized_path) == "exec");
        let (body, framing) = if let Some(length) = content_length {
            if length > HTTP_STREAM_MAX_BYTES as usize {
                return Err(ControllerError::Rejected(
                    "Docker HTTP request body exceeds the fixed bound",
                ));
            }
            let expected = body_offset
                .checked_add(length)
                .ok_or(ControllerError::Invalid(
                    "Docker HTTP request length overflow",
                ))?;
            if raw.len() > expected {
                return Err(ControllerError::Rejected(
                    "Docker HTTP request contains pipelined bytes",
                ));
            }
            if policy_body_required {
                if length > HTTP_POLICY_BODY_MAX_BYTES {
                    return Err(ControllerError::Rejected(
                        "Docker policy JSON exceeds its fixed bound",
                    ));
                }
                while raw.len() < expected {
                    let mut buffer = [0u8; 64 * 1024];
                    let count = stream.read(&mut buffer)?;
                    if count == 0 {
                        return Err(ControllerError::Rejected(
                            "Docker HTTP request body is truncated",
                        ));
                    }
                    raw.extend_from_slice(&buffer[..count]);
                }
                (raw[body_offset..].to_vec(), RequestBodyFraming::None)
            } else {
                (
                    Vec::new(),
                    RequestBodyFraming::ContentLength(expected - raw.len()),
                )
            }
        } else if chunked {
            if policy_body_required {
                return Err(ControllerError::Rejected(
                    "Docker policy JSON must use canonical Content-Length framing",
                ));
            }
            let prefix = raw.split_off(body_offset);
            (Vec::new(), RequestBodyFraming::Chunked(prefix))
        } else if raw.len() != body_offset {
            return Err(ControllerError::Rejected(
                "Docker HTTP request has an unframed body",
            ));
        } else {
            (Vec::new(), RequestBodyFraming::None)
        };
        Ok(HttpRequest {
            method,
            path,
            body,
            raw,
            framing,
        })
    }

    fn relay_request_body(
        client: &mut UnixStream,
        daemon: &mut UnixStream,
        framing: RequestBodyFraming,
    ) -> Result<()> {
        match framing {
            RequestBodyFraming::None => Ok(()),
            RequestBodyFraming::ContentLength(mut remaining) => {
                let mut buffer = [0u8; 64 * 1024];
                while remaining > 0 {
                    let wanted = remaining.min(buffer.len());
                    let count = client.read(&mut buffer[..wanted])?;
                    if count == 0 {
                        return Err(ControllerError::Rejected(
                            "Docker request body is truncated",
                        ));
                    }
                    daemon.write_all(&buffer[..count])?;
                    remaining -= count;
                }
                Ok(())
            }
            RequestBodyFraming::Chunked(prefix) => {
                relay_chunked_request(client, daemon, prefix)
            }
        }
    }

    struct PrefixReader<'a> {
        prefix: std::io::Cursor<Vec<u8>>,
        stream: &'a mut UnixStream,
    }

    impl Read for PrefixReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.prefix.position() < self.prefix.get_ref().len() as u64 {
                return self.prefix.read(output);
            }
            self.stream.read(output)
        }
    }

    fn relay_chunked_request(
        client: &mut UnixStream,
        daemon: &mut UnixStream,
        prefix: Vec<u8>,
    ) -> Result<()> {
        let mut reader = PrefixReader {
            prefix: std::io::Cursor::new(prefix),
            stream: client,
        };
        let mut aggregate = 0u64;
        loop {
            let line = read_crlf_line(&mut reader, 1024)?;
            daemon.write_all(&line)?;
            aggregate = aggregate
                .checked_add(line.len() as u64)
                .ok_or(ControllerError::Invalid(
                    "chunked Docker request length overflow",
                ))?;
            let line_text = std::str::from_utf8(&line[..line.len() - 2])
                .map_err(|_| {
                    ControllerError::Invalid(
                        "chunked Docker request size is not UTF-8",
                    )
                })?;
            let size = u64::from_str_radix(
                line_text.split(';').next().unwrap_or(""),
                16,
            )
            .map_err(|_| {
                ControllerError::Invalid(
                    "chunked Docker request size is invalid",
                )
            })?;
            aggregate = aggregate
                .checked_add(size)
                .and_then(|value| {
                    value.checked_add(if size == 0 { 0 } else { 2 })
                })
                .ok_or(ControllerError::Invalid(
                    "chunked Docker request length overflow",
                ))?;
            if aggregate > HTTP_STREAM_MAX_BYTES {
                return Err(ControllerError::Rejected(
                    "chunked Docker request exceeded its fixed bound",
                ));
            }
            if size == 0 {
                loop {
                    let trailer = read_crlf_line(&mut reader, 8192)?;
                    daemon.write_all(&trailer)?;
                    aggregate = aggregate
                        .checked_add(trailer.len() as u64)
                        .ok_or(ControllerError::Invalid(
                            "chunked Docker trailer length overflow",
                        ))?;
                    if aggregate > HTTP_STREAM_MAX_BYTES {
                        return Err(ControllerError::Rejected(
                            "chunked Docker trailers exceeded the fixed bound",
                        ));
                    }
                    if trailer == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            copy_exact_bounded(&mut reader, daemon, size)?;
            let mut delimiter = [0u8; 2];
            reader.read_exact(&mut delimiter)?;
            if delimiter != *b"\r\n" {
                return Err(ControllerError::Rejected(
                    "chunked Docker request lacks its data delimiter",
                ));
            }
            daemon.write_all(&delimiter)?;
        }
    }

    fn read_crlf_line<R: Read>(
        reader: &mut R,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        while line.len() < maximum {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                return Ok(line);
            }
        }
        Err(ControllerError::Rejected(
            "chunked Docker line exceeded its fixed bound",
        ))
    }

    fn copy_exact_bounded<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        mut remaining: u64,
    ) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            let count = reader.read(&mut buffer[..wanted])?;
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "chunked Docker data is truncated",
                ));
            }
            writer.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        Ok(())
    }

    fn enforce_docker_policy(
        request: &HttpRequest,
        lane: Lane,
        image_allowlist: &BTreeSet<String>,
    ) -> Result<bool> {
        let path = normalized_api_path(&request.path)?;
        let mutating = request.method != "GET" && request.method != "HEAD";
        if !mutating {
            return Ok(false);
        }
        if path == "/auth"
            || path.starts_with("/plugins")
            || path.starts_with("/swarm")
            || path.starts_with("/nodes")
            || path.starts_with("/secrets")
            || path.starts_with("/configs")
            || path.starts_with("/services")
        {
            return Err(ControllerError::Rejected(
                "Docker authority endpoint is never exposed",
            ));
        }
        if path == "/containers/create" {
            enforce_container_create_body(
                &request.body,
                if lane.operation == Operation::RunNoBuild {
                    Some(image_allowlist)
                } else {
                    None
                },
            )?;
        } else if path.starts_with("/containers/")
            && terminal_component(path) == "exec"
        {
            enforce_exec_create_body(&request.body)?;
        }
        if lane.operation == Operation::Build {
            return Ok(true);
        }
        let forbidden = path == "/build"
            || path.starts_with("/build/")
            || path == "/images/create"
            || path == "/images/load"
            || path == "/commit"
            || path == "/system/prune"
            || path.ends_with("/tag")
            || path.ends_with("/push")
            || path.starts_with("/images/prune")
            || (request.method == "DELETE" && path.starts_with("/images/"));
        if forbidden {
            return Err(ControllerError::Rejected(
                "post-seal Docker preparation mutation is denied",
            ));
        }
        let allowed = path == "/containers/create"
            || path == "/networks/create"
            || path == "/volumes/create"
            || (path.starts_with("/containers/")
                && matches!(
                    terminal_component(path),
                    "start"
                        | "stop"
                        | "kill"
                        | "wait"
                        | "rename"
                        | "exec"
                        | "archive"
                ))
            || (path.starts_with("/exec/")
                && matches!(terminal_component(path), "start" | "resize"))
            || (path.starts_with("/networks/")
                && matches!(
                    terminal_component(path),
                    "connect" | "disconnect"
                ))
            || (request.method == "DELETE"
                && (path.starts_with("/containers/")
                    || path.starts_with("/networks/")
                    || path.starts_with("/volumes/")));
        if !allowed {
            return Err(ControllerError::Rejected(
                "post-seal Docker mutation is outside the fixed operation set",
            ));
        }
        Ok(true)
    }

    fn enforce_container_create_body(
        body: &[u8],
        image_allowlist: Option<&BTreeSet<String>>,
    ) -> Result<()> {
        if body.is_empty() {
            return Err(ControllerError::Rejected(
                "container create body is absent or exceeds policy bounds",
            ));
        }
        let value: Value = serde_json::from_slice(body).map_err(|_| {
            ControllerError::Invalid("container create body is not JSON")
        })?;
        let object = value.as_object().ok_or(ControllerError::Invalid(
            "container create body is not an object",
        ))?;
        if let Some(allowlist) = image_allowlist {
            let image = object
                .get("Image")
                .and_then(Value::as_str)
                .ok_or(ControllerError::Rejected(
                    "post-seal container image is absent",
                ))?;
            if !allowlist.contains(image) {
                return Err(ControllerError::Rejected(
                    "post-seal container image is outside the sealed build inventory",
                ));
            }
        }
        let host = object
            .get("HostConfig")
            .and_then(Value::as_object)
            .ok_or(ControllerError::Rejected(
                "container create lacks HostConfig",
            ))?;
        let nonempty_array = |name: &str| {
            host.get(name)
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
        };
        let nonempty_string = |name: &str| {
            host.get(name)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        };
        if host.get("Privileged").and_then(Value::as_bool) == Some(true)
            || nonempty_array("Binds")
            || nonempty_array("Devices")
            || nonempty_array("DeviceCgroupRules")
            || nonempty_array("DeviceRequests")
            || nonempty_array("CapAdd")
            || nonempty_array("VolumesFrom")
            || nonempty_string("PidMode")
            || nonempty_string("IpcMode")
            || host.get("UsernsMode").and_then(Value::as_str) == Some("host")
            || host.get("CgroupnsMode").and_then(Value::as_str) == Some("host")
            || host
                .get("NetworkMode")
                .and_then(Value::as_str)
                .is_some_and(|mode| {
                    mode == "host" || mode.starts_with("container:")
                })
            || host
                .get("SecurityOpt")
                .and_then(Value::as_array)
                .is_some_and(|options| {
                    options.iter().any(|option| {
                        option.as_str().is_none_or(|option| {
                            matches!(
                                option,
                                "seccomp=unconfined"
                                    | "apparmor=unconfined"
                                    | "label=disable"
                                    | "systempaths=unconfined"
                            )
                        })
                    })
                })
        {
            return Err(ControllerError::Rejected(
                "privileged, host, device, capability, or namespace container access is denied",
            ));
        }
        if object
            .get("Mounts")
            .and_then(Value::as_array)
            .is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    !matches!(
                        mount.get("Type").and_then(Value::as_str),
                        Some("volume" | "tmpfs")
                    )
                        || mount.get("Source").and_then(Value::as_str).is_some_and(
                            |source| source.starts_with('/'),
                        )
                })
            })
        {
            return Err(ControllerError::Rejected(
                "container bind or host-path mount is denied",
            ));
        }
        Ok(())
    }

    fn enforce_exec_create_body(body: &[u8]) -> Result<()> {
        if body.is_empty() {
            return Err(ControllerError::Rejected(
                "container exec body is absent or exceeds policy bounds",
            ));
        }
        let value: Value = serde_json::from_slice(body).map_err(|_| {
            ControllerError::Invalid("container exec body is not JSON")
        })?;
        let object = value.as_object().ok_or(ControllerError::Invalid(
            "container exec body is not an object",
        ))?;
        if object.get("Privileged").and_then(Value::as_bool) == Some(true)
            || object
                .get("User")
                .and_then(Value::as_str)
                .is_some_and(|user| {
                    matches!(user, "0" | "root" | "0:0" | "root:root")
                })
        {
            return Err(ControllerError::Rejected(
                "privileged or explicit root Docker exec is denied",
            ));
        }
        Ok(())
    }

    fn normalized_api_path(path: &str) -> Result<&str> {
        let without_query = path.split('?').next().unwrap_or(path);
        if without_query.contains('%') || without_query.contains("//") {
            return Err(ControllerError::Rejected(
                "Docker API path encoding is noncanonical",
            ));
        }
        let mut components = without_query.split('/').filter(|part| !part.is_empty());
        if components
            .next()
            .is_some_and(|part| {
                part.starts_with('v')
                    && part[1..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
        {
            let offset = without_query
                .find('/')
                .and_then(|first| {
                    without_query[first + 1..]
                        .find('/')
                        .map(|next| first + next + 1)
                })
                .ok_or(ControllerError::Invalid(
                    "versioned Docker API path has no operation",
                ))?;
            return Ok(&without_query[offset..]);
        }
        Ok(without_query)
    }

    fn verify_stage_client(
        pid: libc::pid_t,
        start_time: u64,
        active: &ActiveStage,
    ) -> Result<()> {
        if process_start_time(pid)? != start_time
            || now_unix_ms()? >= active.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "Docker client identity or deadline is no longer live",
            ));
        }
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        if !cgroup
            .lines()
            .any(|line| line.contains(&active.runner_container_id))
        {
            return Err(ControllerError::Rejected(
                "Docker client is outside the exact active runner cgroup",
            ));
        }
        Ok(())
    }

    fn measure_daemon(
        config: &ExecutorConfig,
        pid: libc::pid_t,
    ) -> Result<DaemonIdentity> {
        let metadata = std::fs::symlink_metadata(&config.private_socket)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
        {
            return Err(ControllerError::Rejected(
                "private Docker socket is not root-private",
            ));
        }
        let daemon_id = docker_info_id(config)?;
        let start_time_ticks = process_start_time(pid)?;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"serverware/disposable-dind-identity/v11\0");
        canonical.extend_from_slice(&pid.to_be_bytes());
        canonical.extend_from_slice(&start_time_ticks.to_be_bytes());
        canonical.extend_from_slice(&metadata.dev().to_be_bytes());
        canonical.extend_from_slice(&metadata.ino().to_be_bytes());
        canonical.extend_from_slice(&config.dockerd_sha256);
        canonical.extend_from_slice(daemon_id.as_bytes());
        Ok(DaemonIdentity {
            pid,
            start_time_ticks,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            dockerd_sha256: config.dockerd_sha256,
            daemon_id,
            identity_sha256: sha256(&canonical),
        })
    }

    fn verify_daemon_identity(
        config: &ExecutorConfig,
        expected: &DaemonIdentity,
    ) -> Result<()> {
        verify_file_digest(&config.dockerd_path, expected.dockerd_sha256)?;
        let metadata = std::fs::symlink_metadata(&config.private_socket)?;
        if !metadata.file_type().is_socket()
            || metadata.dev() != expected.socket_device
            || metadata.ino() != expected.socket_inode
            || process_start_time(expected.pid)? != expected.start_time_ticks
            || docker_info_id(config)? != expected.daemon_id
        {
            return Err(ControllerError::Rejected(
                "disposable Docker daemon or socket identity changed",
            ));
        }
        Ok(())
    }

    fn snapshot_image_allowlist(
        config: &ExecutorConfig,
    ) -> Result<BTreeSet<String>> {
        let bytes = run_docker_command_capture(
            config,
            [
                "image",
                "ls",
                "--no-trunc",
                "--digests",
                "--format",
                "{{.ID}}|{{.Repository}}:{{.Tag}}|{{.Repository}}@{{.Digest}}",
            ],
            RUNNER_BOOTSTRAP_TIMEOUT,
            "image-seal",
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Invalid("image seal is not UTF-8"))?;
        let mut result = BTreeSet::new();
        for line in text.lines() {
            for value in line.split('|') {
                if !value.is_empty()
                    && !value.ends_with(":<none>")
                    && !value.ends_with("@<none>")
                {
                    result.insert(value.to_owned());
                }
            }
        }
        Ok(result)
    }

    fn docker_info_id(config: &ExecutorConfig) -> Result<String> {
        let mut stream = UnixStream::connect(&config.private_socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(
            b"GET /info HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n",
        )?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = Vec::new();
        stream
            .take(DOCKER_INFO_MAX_BYTES + 1)
            .read_to_end(&mut response)?;
        if response.len() as u64 > DOCKER_INFO_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "Docker daemon identity response exceeded its bound",
            ));
        }
        let body = decode_http_response_body(&response, 200)?;
        let value = serde_json::from_slice::<Value>(&body)
            .map_err(|_| {
                ControllerError::Invalid(
                    "Docker daemon identity response is not JSON",
                )
            })?
            .get("ID")
            .and_then(Value::as_str)
            .ok_or(ControllerError::Rejected(
                "Docker daemon identity response lacks ID",
            ))?
            .to_owned();
        if value.is_empty()
            || value.len() > 128
            || value.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric()
                    || matches!(byte, b':' | b'-' | b'_'))
            })
        {
            return Err(ControllerError::Rejected(
                "Docker daemon ID is noncanonical",
            ));
        }
        Ok(value)
    }

    fn decode_http_response_body(
        response: &[u8],
        expected_status: u16,
    ) -> Result<Vec<u8>> {
        let header_end = header_end(response).ok_or(
            ControllerError::Invalid(
                "Docker HTTP response header is incomplete",
            ),
        )?;
        let header = std::str::from_utf8(&response[..header_end]).map_err(
            |_| ControllerError::Invalid(
                "Docker HTTP response header is not UTF-8",
            ),
        )?;
        let status = header
            .lines()
            .next()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ControllerError::Invalid(
                "Docker HTTP response status is invalid",
            ))?;
        if status != expected_status {
            return Err(ControllerError::Rejected(
                "Docker HTTP response status is unexpected",
            ));
        }
        let mut content_length = None;
        let mut chunked = false;
        for line in header.lines().skip(1) {
            let (name, value) = line.split_once(':').ok_or(
                ControllerError::Invalid(
                    "Docker HTTP response header lacks a colon",
                ),
            )?;
            if name.eq_ignore_ascii_case("content-length") {
                if content_length
                    .replace(value.trim().parse::<usize>().map_err(|_| {
                        ControllerError::Invalid(
                            "Docker HTTP response content length is invalid",
                        )
                    })?)
                    .is_some()
                {
                    return Err(ControllerError::Rejected(
                        "Docker HTTP response content length is duplicated",
                    ));
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if !value.trim().eq_ignore_ascii_case("chunked") || chunked {
                    return Err(ControllerError::Rejected(
                        "Docker HTTP response transfer encoding is unsupported",
                    ));
                }
                chunked = true;
            }
        }
        if content_length.is_some() && chunked {
            return Err(ControllerError::Rejected(
                "Docker HTTP response has ambiguous framing",
            ));
        }
        let body = &response[header_end + 4..];
        let decoded = if let Some(length) = content_length {
            if length != body.len() {
                return Err(ControllerError::Rejected(
                    "Docker HTTP response length differs from its framing",
                ));
            }
            body.to_vec()
        } else if chunked {
            decode_chunked_response_body(body)?
        } else {
            body.to_vec()
        };
        if decoded.len() as u64 > DOCKER_INFO_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "Docker HTTP response body exceeded its bound",
            ));
        }
        Ok(decoded)
    }

    fn decode_chunked_response_body(encoded: &[u8]) -> Result<Vec<u8>> {
        let mut cursor = 0usize;
        let mut decoded = Vec::new();
        loop {
            let line_end = encoded[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|position| cursor + position)
                .ok_or(ControllerError::Rejected(
                    "chunked Docker response size line is truncated",
                ))?;
            if line_end - cursor > 1024 {
                return Err(ControllerError::Rejected(
                    "chunked Docker response size line exceeded its bound",
                ));
            }
            let size_text = std::str::from_utf8(&encoded[cursor..line_end])
                .map_err(|_| {
                    ControllerError::Invalid(
                        "chunked Docker response size is not UTF-8",
                    )
                })?;
            let size = usize::from_str_radix(
                size_text.split(';').next().unwrap_or(""),
                16,
            )
            .map_err(|_| {
                ControllerError::Invalid(
                    "chunked Docker response size is invalid",
                )
            })?;
            cursor = line_end + 2;
            if size == 0 {
                loop {
                    let trailer_end = encoded[cursor..]
                        .windows(2)
                        .position(|window| window == b"\r\n")
                        .map(|position| cursor + position)
                        .ok_or(ControllerError::Rejected(
                            "chunked Docker response trailer is truncated",
                        ))?;
                    if trailer_end == cursor {
                        cursor += 2;
                        if cursor != encoded.len() {
                            return Err(ControllerError::Rejected(
                                "chunked Docker response has trailing bytes",
                            ));
                        }
                        return Ok(decoded);
                    }
                    if trailer_end - cursor > 8192 {
                        return Err(ControllerError::Rejected(
                            "chunked Docker response trailer exceeded its bound",
                        ));
                    }
                    cursor = trailer_end + 2;
                }
            }
            let data_end = cursor
                .checked_add(size)
                .ok_or(ControllerError::Invalid(
                    "chunked Docker response length overflow",
                ))?;
            let delimiter_end =
                data_end.checked_add(2).ok_or(ControllerError::Invalid(
                    "chunked Docker response delimiter overflow",
                ))?;
            if delimiter_end > encoded.len()
                || &encoded[data_end..delimiter_end] != b"\r\n"
            {
                return Err(ControllerError::Rejected(
                    "chunked Docker response data is truncated",
                ));
            }
            decoded.extend_from_slice(&encoded[cursor..data_end]);
            if decoded.len() as u64 > DOCKER_INFO_MAX_BYTES {
                return Err(ControllerError::Rejected(
                    "chunked Docker response body exceeded its bound",
                ));
            }
            cursor = delimiter_end;
        }
    }

    fn docker_ping(path: &Path) -> Result<()> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(
            b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n",
        )?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = Vec::new();
        stream.take(4097).read_to_end(&mut response)?;
        if response.len() > 4096
            || !response.starts_with(b"HTTP/1.1 200")
            || !response.windows(2).any(|window| window == b"OK")
        {
            return Err(ControllerError::Rejected(
                "disposable Docker ping failed",
            ));
        }
        Ok(())
    }

    fn run_docker_command<'a, I>(
        config: &ExecutorConfig,
        arguments: I,
        timeout: Duration,
        label: &str,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let (status, _) =
            run_docker_command_capture_status(config, arguments, timeout, label)?;
        if !status.success() {
            return Err(ControllerError::InvalidOwned(format!(
                "controller Docker operation {label} failed: {status}",
            )));
        }
        Ok(())
    }

    fn run_docker_command_capture<'a, I>(
        config: &ExecutorConfig,
        arguments: I,
        timeout: Duration,
        label: &str,
    ) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let (status, output) =
            run_docker_command_capture_status(config, arguments, timeout, label)?;
        if !status.success() {
            return Err(ControllerError::InvalidOwned(format!(
                "controller Docker operation {label} failed: {status}",
            )));
        }
        Ok(output)
    }

    fn run_docker_command_capture_status<'a, I>(
        config: &ExecutorConfig,
        arguments: I,
        timeout: Duration,
        label: &str,
    ) -> Result<(ExitStatus, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a str>,
    {
        verify_file_digest(&config.docker_path, config.docker_sha256)?;
        let output_path = config
            .state_root
            .join("logs")
            .join(format!(
                "{}-{}-{}.log",
                sanitize_label(label),
                now_unix_ms()?,
                DOCKER_COMMAND_SEQUENCE.fetch_add(1, Ordering::AcqRel),
            ));
        let output_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)?;
        let error_file = output_file.try_clone()?;
        let mut child = Command::new(&config.docker_path);
        child
            .arg("--host")
            .arg(format!("unix://{}", config.private_socket.display()))
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output_file.try_clone()?))
            .stderr(Stdio::from(error_file));
        let mut child = child.spawn()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ControllerError::Invalid("Docker command deadline overflow"))?;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                terminate_child(&mut child, TERMINAL_CLEANUP_TIMEOUT)?;
                return Err(ControllerError::Rejected(
                    "controller Docker operation exceeded its deadline",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        };
        verify_file_digest(&config.docker_path, config.docker_sha256)?;
        let length = output_file.metadata()?.len();
        if length > LOG_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "controller Docker operation output exceeded its bound",
            ));
        }
        let mut reader = output_file;
        reader.seek(SeekFrom::Start(0))?;
        let mut output = Vec::with_capacity(length as usize);
        reader.read_to_end(&mut output)?;
        Ok((status, output))
    }

    fn fixed_make_target(plan: Plan) -> &'static str {
        match plan {
            Plan::Build => "coder-controller-build-execute",
            Plan::UnitNoBuild => "coder-controller-unit-execute",
            Plan::IntegrationNoBuild => {
                "coder-controller-integration-execute"
            }
            Plan::E2eNoBuild => "coder-controller-e2e-execute",
            Plan::AttestationNoBuild => {
                "coder-controller-attestation-execute"
            }
        }
    }

    fn verify_source_make_target(source: &Path, plan: Plan) -> Result<()> {
        let makefile = source.join("Makefile");
        let metadata = std::fs::symlink_metadata(&makefile)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err(ControllerError::Rejected(
                "source Makefile is not one bounded regular file",
            ));
        }
        let bytes = std::fs::read(makefile)?;
        let target = fixed_make_target(plan);
        if !bytes
            .split(|byte| *byte == b'\n')
            .filter_map(|line| line.splitn(2, |byte| *byte == b':').next())
            .any(|targets| {
                targets
                    .split(|byte| byte.is_ascii_whitespace())
                    .any(|candidate| candidate == target.as_bytes())
            })
        {
            return Err(ControllerError::Rejected(
                "fixed plan Make target is absent",
            ));
        }
        Ok(())
    }

    fn bind_stream_socket(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<UnixListener> {
        remove_socket_path(path)?;
        let listener = UnixListener::bind(path)?;
        set_socket_identity(path, uid, gid, mode)?;
        Ok(listener)
    }

    fn bind_seqpacket_socket(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        backlog: libc::c_int,
    ) -> Result<OwnedFd> {
        remove_socket_path(path)?;
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let (address, length) = socket_address(path)?;
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                &address as *const libc::sockaddr_un
                    as *const libc::sockaddr,
                length,
            )
        } != 0
            || unsafe { libc::listen(socket.as_raw_fd(), backlog) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        set_socket_identity(path, uid, gid, mode)?;
        Ok(socket)
    }

    fn accept_seqpacket(listener: RawFd) -> Result<OwnedFd> {
        let raw = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn require_root_peer(socket: RawFd) -> Result<()> {
        let mut peer: libc::ucred = unsafe { mem::zeroed() };
        let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut peer as *mut libc::ucred as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || length as usize != mem::size_of::<libc::ucred>()
            || peer.uid != 0
            || peer.gid != 0
            || process_start_time(peer.pid).is_err()
        {
            return Err(ControllerError::Rejected(
                "plan executor peer is not one live root process",
            ));
        }
        Ok(())
    }

    fn stream_peer(stream: &UnixStream) -> Result<libc::ucred> {
        let mut peer: libc::ucred = unsafe { mem::zeroed() };
        let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut peer as *mut libc::ucred as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || length as usize != mem::size_of::<libc::ucred>()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(peer)
    }

    fn send_exact(fd: RawFd, bytes: &[u8]) -> Result<()> {
        let sent = unsafe {
            libc::send(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != bytes.len() as isize {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn set_socket_identity(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<()> {
        let path = c_path(path)?;
        if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0
            || unsafe { libc::chmod(path.as_ptr(), mode) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn socket_address(
        path: &Path,
    ) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
        let bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
            return Err(ControllerError::Invalid("socket path is invalid"));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        Ok((
            address,
            (mem::size_of::<libc::sa_family_t>() + bytes.len() + 1)
                as libc::socklen_t,
        ))
    }

    fn read_http_head(stream: &mut UnixStream) -> Result<Vec<u8>> {
        read_until_header(stream, HTTP_HEADER_MAX_BYTES)
    }

    fn read_until_header(
        stream: &mut UnixStream,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while header_end(&bytes).is_none() {
            if bytes.len() >= maximum {
                return Err(ControllerError::Rejected(
                    "Docker HTTP header exceeded its bound",
                ));
            }
            let mut buffer = [0u8; 4096];
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "Docker HTTP peer closed before a complete header",
                ));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok(bytes)
    }

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn terminal_component(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or("")
    }

    fn process_start_time(pid: libc::pid_t) -> Result<u64> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let end = text.rfind(')').ok_or(ControllerError::Invalid(
            "process stat command field is malformed",
        ))?;
        let fields: Vec<&str> = text[end + 1..].split_whitespace().collect();
        fields
            .get(19)
            .ok_or(ControllerError::Invalid(
                "process stat start-time field is absent",
            ))?
            .parse::<u64>()
            .map_err(|_| {
                ControllerError::Invalid("process start time is invalid")
            })
    }

    fn terminate_child(child: &mut Child, timeout: Duration) -> Result<()> {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn exit_code(status: ExitStatus) -> i32 {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(127))
    }

    fn verify_file_digest(path: &Path, expected: Digest) -> Result<()> {
        require_absolute_normalized(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(ControllerError::Rejected(
                "pinned controller input is not immutable root-owned data",
            ));
        }
        let mut file = File::open(path)?;
        let digest = sha256_exact_reader(&mut file, metadata.len())?;
        if !constant_time_eq(&digest, &expected) {
            return Err(ControllerError::Rejected(
                "pinned controller input digest changed",
            ));
        }
        Ok(())
    }

    fn require_directory(
        path: &Path,
        owner: Option<(u32, u32)>,
    ) -> Result<()> {
        require_absolute_normalized(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || owner.is_some_and(|(uid, gid)| {
                metadata.uid() != uid || metadata.gid() != gid
            })
            || metadata.mode() & 0o002 != 0
        {
            return Err(ControllerError::Rejected(
                "controller directory identity is unsafe",
            ));
        }
        Ok(())
    }

    fn remove_owned_tree(root: &Path, path: &Path) -> Result<()> {
        if !path.starts_with(root) || path == root {
            return Err(ControllerError::Rejected(
                "refusing cleanup outside the controller state root",
            ));
        }
        if !path.exists() {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 {
            return Err(ControllerError::Rejected(
                "refusing cleanup of non-controller-owned state",
            ));
        }
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    fn remove_socket_path(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(ControllerError::Rejected(
                "refusing to replace a non-controller socket path",
            ));
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn verify_same_filesystem(left: &Path, right: &Path) -> Result<()> {
        let left = std::fs::symlink_metadata(left)?;
        let right = std::fs::symlink_metadata(right)?;
        if left.dev() != right.dev() {
            return Err(ControllerError::Rejected(
                "overlay upper and work directories are on different filesystems",
            ));
        }
        Ok(())
    }

    fn parse_path(value: &str) -> Result<PathBuf> {
        let path = PathBuf::from(value);
        require_absolute_normalized(&path)?;
        Ok(path)
    }

    fn require_absolute_normalized(path: &Path) -> Result<()> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir
                        | Component::ParentDir
                        | Component::Prefix(_)
                )
            })
        {
            return Err(ControllerError::Rejected(
                "controller path is not absolute and normalized",
            ));
        }
        Ok(())
    }

    fn parse_u32(value: &str) -> Result<u32> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ControllerError::Invalid(
                "controller numeric config is invalid",
            ));
        }
        value.parse::<u32>().map_err(|_| {
            ControllerError::Invalid("controller numeric config is out of range")
        })
    }

    fn parse_u64(value: &str) -> Result<u64> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ControllerError::Invalid(
                "controller numeric config is invalid",
            ));
        }
        value.parse::<u64>().map_err(|_| {
            ControllerError::Invalid(
                "controller numeric config is out of range",
            )
        })
    }

    fn verify_public_key_file(path: &Path) -> Result<()> {
        require_absolute_normalized(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() != 32
        {
            return Err(ControllerError::Rejected(
                "Docker authority public key is not one private root-owned raw Ed25519 key",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn load_authorized_signer(
        role: &'static str,
        path: &Path,
        principal_id: &str,
        key_id: &str,
        authorization_leaf_sha256: Digest,
        authorization_checkpoint_sha256: Digest,
        revocation_highwater: u64,
        not_before_boottime_ns: u64,
        not_after_boottime_ns: u64,
    ) -> Result<AuthorizedDockerSignerV11> {
        verify_public_key_file(path)?;
        let bytes = std::fs::read(path)?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            ControllerError::Invalid(
                "Docker authority Ed25519 key length is invalid",
            )
        })?;
        let signer = AuthorizedDockerSignerV11 {
            role,
            principal_id: principal_id.to_owned(),
            key_id: key_id.to_owned(),
            verifying_key: VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| {
                    ControllerError::Invalid(
                        "Docker authority Ed25519 key is invalid",
                    )
                })?,
            authorization_leaf_sha256,
            authorization_checkpoint_sha256,
            revocation_highwater,
            not_before_boottime_ns,
            not_after_boottime_ns,
        };
        signer.validate(boottime_now_ns_v11()?)?;
        Ok(signer)
    }

    fn parse_digest(value: &str) -> Result<Digest> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControllerError::Invalid(
                "controller digest is not lowercase SHA-256",
            ));
        }
        let decoded = hex::decode(value)
            .map_err(|_| ControllerError::Invalid("controller digest is invalid"))?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&decoded);
        if digest == [0; 32] {
            return Err(ControllerError::Rejected(
                "controller digest must not be zero",
            ));
        }
        Ok(digest)
    }

    fn valid_digest_image_reference(value: &str) -> bool {
        let Some((name, digest)) = value.rsplit_once("@sha256:") else {
            return false;
        };
        !name.is_empty()
            && digest.len() == 64
            && digest.bytes().all(|byte| {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
    }

    fn path_text(path: &Path) -> Result<&str> {
        path.to_str()
            .ok_or(ControllerError::Invalid("controller path is not UTF-8"))
    }

    fn c_path(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("controller path contains NUL"))
    }

    fn sanitize_label(label: &str) -> String {
        label
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || byte == b'-' {
                    byte as char
                } else {
                    '_'
                }
            })
            .collect()
    }
}
