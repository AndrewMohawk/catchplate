#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "{}: Linux pidfd/memfd/cgroup/SOCK_SEQPACKET support is required",
        "catchplate-coder-controller-v11"
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("{}: {error}", coder_controller_v11::PROTOCOL_NAME);
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::coder_controller_v11::{
        digest_hex, ed25519_spki_der_sha256_v11, now_unix_ms, peer_binding,
        sha256, sha256_exact_reader,
        trusted_host_direct_containment_evidence_sha256,
        trusted_host_direct_release_evidence_sha256,
        trusted_host_direct_supervisor_registration_sha256,
        trusted_host_supervisor_state_machine_sha256, AttestationScope,
        AcceptanceTicketRequestV11, AcceptanceTicketV11,
        CanonicalControllerReceiptV11, CanonicalControllerRequestV11,
        CanonicalFrameKindV11,
        CanonicalPreallocationFrameV11, ClientSubmission,
        ContainmentEvidenceSink,
        ControllerError, ControllerReceiptBody, Digest, FrameKind, HelloEnvelope, HelloResponse,
        EvidenceReference, ImmutableControllerConfig, Lane, LinuxChildSupervisorBoundary,
        LaunchClosureMemberV11, LaunchContractV11, LaunchFileIdentityV11,
        NativeContainmentDecision, NativeTrustedHostDirectReleaseDecision,
        NativeTrustedHostDirectSupervisorDecision,
        PinnedTrustedHostDirectSupervisorVerifier, PreallocationFrame, Plan,
        Operation, PlanApiModeV11, PlanApiRequestV11, PlanApiResponseV11,
        PlanCapabilityRecordV11,
        RawContainmentTerminal, RawSupervisorPreparedExecution,
        RawSupervisorReleaseEvidence, RawTrustedHostDirectSupervisorRegistration,
        ReceiptAuthorityRequestV11,
        ReceiptTerminal, Result, SignedControllerReceipt, SignedTrustedTime,
        TrustedHostDirectSupervisorStateMachine,
        TrustedHostSupervisorStateMachineMeasurements, TrustedPlanManifestV11,
        VerifiedNoBuildKernelCapability, VerifiedPreExecution,
        VerifiedSupervisorExecutionGate,
        VerifiedTrustedHostDirectContainmentCapability,
        VerifiedTrustedHostDirectReleaseCapability,
        VerifiedTrustedHostDirectSupervisorGate, FIXED_FRAME_BYTES, FIXED_PLAN_ORDER,
        format_rfc3339_seconds_v11, ACCEPTANCE_TICKET_BYTES,
        ACCEPTANCE_TICKET_REQUEST_BYTES, PROTOCOL_NAME, RECEIPT_MAX_BYTES,
        FINAL_VERDICT_PUBLIC_KEY_PATH, RECEIPT_PUBLIC_KEY_PATH,
        REQUESTER_PUBLIC_KEY_PATH, REQUESTER_SIGNING_KEY_PATH,
        LAUNCHER_INSTALL_PATH,
        CONTROLLER_PLAN_API_SOCKET_PATH,
        CONTROLLER_PLAN_EXECUTOR_SOCKET_PATH,
        CONTROLLER_RECEIPT_AUTHORITY_SOCKET_PATH,
        REQUEST_MAX_BYTES, SIGNED_CONTROLLER_RECEIPT_BYTES,
        PLAN_API_REQUEST_BYTES, PLAN_API_RESPONSE_BYTES,
        PLAN_CAPABILITY_RECORD_BYTES,
        TRUSTED_PLAN_MANIFEST_BYTES,
        TRUSTED_PLAN_MANIFEST_PATH, DEFAULT_SOCKET_PATH,
    };
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use sha2::{Digest as ShaDigestTrait, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const SCM_PIDFD_VALUE: libc::c_int = 0x04;
    const SO_PASSPIDFD_VALUE: libc::c_int = 76;
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
    const FS_IOC_SETFLAGS: libc::c_ulong = 0x40086602;
    const FS_IOC_GETVERSION: libc::c_ulong = 0x80087601;
    const FS_IMMUTABLE_FL: libc::c_uint = 0x00000010;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const CONFIG_MAX_BYTES: u64 = 64 * 1024;
    const CONTROL_BYTES: usize = 512;
    const NONCE_WINDOW_MAX: usize = 4096;
    const NONCE_WINDOW_PER_PEER_MAX: usize = 32;
    const HELLO_NONCE_TTL_MS: u64 = 10_000;
    const PROVIDER_MAX_BYTES: usize = 8 * 1024 * 1024;
    const ACTION_OUTPUT_MAX_BYTES: usize = 4 * 1024 * 1024;
    const STATE_RECORD_MAX_BYTES: u64 = 4 * 1024 * 1024;
    const BROKER_REQUEST_BYTES: usize =
        FIXED_FRAME_BYTES + ClientSubmission::ENCODED_BYTES + 48;
    const BROKER_RESPONSE_MAX_BYTES: usize = 8192;
    const PLAN_PROXY_REQUEST_BYTES: usize =
        PLAN_API_REQUEST_BYTES + PLAN_CAPABILITY_RECORD_BYTES;
    const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
    const AT_RECURSIVE_FLAG: libc::c_int = 0x8000;
    const MOUNT_ATTR_RDONLY_FLAG: u64 = 0x0000_0001;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAP_AMBIENT_VALUE: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL_VALUE: libc::c_ulong = 4;
    const PR_SET_SECCOMP_VALUE: libc::c_int = 22;
    const SECCOMP_MODE_FILTER_VALUE: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS_VALUE: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO_VALUE: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW_VALUE: u32 = 0x7fff_0000;
    const LANDLOCK_CREATE_RULESET_VERSION_VALUE: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH_VALUE: u32 = 1;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const REQUIRED_PLAN_LABELS: [&str; 5] = [
        "catchplate-build-v1",
        "catchplate-unit-no-build-v1",
        "catchplate-integration-no-build-v1",
        "catchplate-e2e-no-build-v1",
        "catchplate-attestation-no-build-v1",
    ];
    const MANDATORY_DENIED_SOCKET_PATHS: [&str; 8] = [
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/run/crio/crio.sock",
        "/var/run/crio/crio.sock",
    ];

    #[repr(C, align(16))]
    struct AlignedControl {
        bytes: [u8; CONTROL_BYTES],
    }

    impl AlignedControl {
        fn zeroed() -> Self {
            Self {
                bytes: [0; CONTROL_BYTES],
            }
        }
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
        reserved: u32,
    }

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    struct ReceivedPacket {
        frame: [u8; FIXED_FRAME_BYTES],
        memfd: OwnedFd,
        pidfd: OwnedFd,
        peer: libc::ucred,
        pidfd_identity: String,
        peer_start_time_ticks: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ControllerMode {
        DisabledDevHello,
        TrustedHostV11,
    }

    struct ParsedDaemonConfig {
        transport: ImmutableControllerConfig,
        mode: ControllerMode,
        production: Option<TrustedHostSettings>,
    }

    struct TrustedHostSettings {
        state_dir: PathBuf,
        source_root: PathBuf,
        signing_key_path: PathBuf,
        public_key_path: PathBuf,
        requester_public_key_path: PathBuf,
        final_verdict_public_key_path: PathBuf,
        cgroup_root: PathBuf,
        trust_epoch: u64,
        revocation_epoch: u64,
        deadlines_ms: BTreeMap<Plan, u64>,
        plans: BTreeMap<Plan, PlanSpec>,
        artifact_paths: Vec<PathBuf>,
        denied_socket_paths: Vec<PathBuf>,
    }

    #[derive(Default)]
    struct PlanSpecBuilder {
        executable: Option<PathBuf>,
        cwd: Option<PathBuf>,
        configuration_sha256: Option<Digest>,
        args: BTreeMap<usize, String>,
        env: BTreeMap<String, String>,
        closure: BTreeMap<usize, (bool, PathBuf)>,
    }

    struct PlanSpec {
        executable: PathBuf,
        cwd: PathBuf,
        configuration_sha256: Digest,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        closure: Vec<(bool, PathBuf)>,
    }

    struct ControllerDaemon {
        config: ImmutableControllerConfig,
        mode: RuntimeMode,
        nonces: NonceWindow,
        tickets: TicketWindow,
        limiter: Arc<ConnectionLimiter>,
        readiness: Arc<ReadinessState>,
    }

    enum RuntimeMode {
        DisabledDevHello,
        TrustedHost(TrustedHostBroker),
    }

    struct TrustedHostBroker {
        channel: Mutex<OwnedFd>,
        pid: libc::pid_t,
        pidfd: OwnedFd,
        requester_verifying_key: VerifyingKey,
        receipt_verifying_key: VerifyingKey,
        final_verdict_verifying_key: VerifyingKey,
        ticket_signing_key: SigningKey,
        internal_submission_signing_key: SigningKey,
        lane_deadlines_ms: BTreeMap<Plan, u64>,
        config_sha256: Digest,
        daemon_identity_sha256: Digest,
        readiness: Arc<ReadinessState>,
    }

    struct ReadinessState {
        ready: AtomicBool,
        reason: Mutex<Option<String>>,
    }

    impl ReadinessState {
        fn new() -> Self {
            Self {
                ready: AtomicBool::new(false),
                reason: Mutex::new(Some("pre-ready probes have not completed".to_owned())),
            }
        }

        fn mark_ready(&self) -> Result<()> {
            let mut reason = self
                .reason
                .lock()
                .map_err(|_| ControllerError::Rejected("readiness lock poisoned"))?;
            *reason = None;
            self.ready.store(true, Ordering::Release);
            Ok(())
        }

        fn hard_unready(&self, reason: impl Into<String>) {
            self.ready.store(false, Ordering::Release);
            if let Ok(mut current) = self.reason.lock() {
                *current = Some(reason.into());
            }
        }

        fn require_ready(&self) -> Result<()> {
            if self.ready.load(Ordering::Acquire) {
                return Ok(());
            }
            let reason = self
                .reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone())
                .unwrap_or_else(|| "readiness reason is unavailable".to_owned());
            Err(ControllerError::Unready(vec![reason]))
        }

        fn summary(&self) -> String {
            if self.ready.load(Ordering::Acquire) {
                return "READY".to_owned();
            }
            self.reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone())
                .map(|reason| format!("UNREADY {reason}"))
                .unwrap_or_else(|| "UNREADY readiness lock poisoned".to_owned())
        }
    }

    struct NonceWindow {
        entries: Mutex<BTreeMap<(Digest, Digest), u64>>,
    }

    impl NonceWindow {
        fn new() -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
            }
        }

        fn consume_valid(
            &self,
            peer_binding_sha256: Digest,
            nonce_sha256: Digest,
            transport_deadline_unix_ms: u64,
            now_ms: u64,
        ) -> Result<()> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| ControllerError::Rejected("nonce window lock poisoned"))?;
            entries.retain(|_, expiry| *expiry > now_ms);
            let key = (peer_binding_sha256, nonce_sha256);
            if entries.contains_key(&key) {
                return Err(ControllerError::Rejected("peer-scoped hello nonce replay"));
            }
            if entries
                .keys()
                .filter(|(peer, _)| peer == &peer_binding_sha256)
                .count()
                >= NONCE_WINDOW_PER_PEER_MAX
            {
                return Err(ControllerError::Unready(vec![
                    "peer hello nonce quota is full".to_owned(),
                ]));
            }
            if entries.len() >= NONCE_WINDOW_MAX {
                return Err(ControllerError::Unready(vec![
                    "valid hello nonce window is full".to_owned(),
                ]));
            }
            let server_expiry = now_ms.saturating_add(HELLO_NONCE_TTL_MS);
            entries.insert(key, transport_deadline_unix_ms.min(server_expiry));
            Ok(())
        }
    }

    struct TicketWindow {
        entries: Mutex<BTreeMap<(Digest, Digest), AcceptanceTicketV11>>,
    }

    impl TicketWindow {
        fn new() -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
            }
        }

        fn issue(
            &self,
            peer_binding_sha256: Digest,
            ticket: AcceptanceTicketV11,
            now_ms: u64,
        ) -> Result<()> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| ControllerError::Rejected("ticket window lock poisoned"))?;
            entries.retain(|_, current| {
                current.frame_deadline_unix_ms > now_ms
            });
            let key = (peer_binding_sha256, sha256(&ticket.raw_nonce));
            if entries.contains_key(&key) {
                return Err(ControllerError::Rejected(
                    "peer-scoped acceptance ticket nonce replay",
                ));
            }
            if entries
                .keys()
                .filter(|(peer, _)| peer == &peer_binding_sha256)
                .count()
                >= NONCE_WINDOW_PER_PEER_MAX
                || entries.len() >= NONCE_WINDOW_MAX
            {
                return Err(ControllerError::Unready(vec![
                    "acceptance ticket window is full".to_owned(),
                ]));
            }
            entries.insert(key, ticket);
            Ok(())
        }

        fn consume(
            &self,
            peer_binding_sha256: Digest,
            nonce_sha256: Digest,
            accepted_at: &str,
            lane: Lane,
            now_ms: u64,
        ) -> Result<AcceptanceTicketV11> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| ControllerError::Rejected("ticket window lock poisoned"))?;
            entries.retain(|_, current| {
                current.frame_deadline_unix_ms > now_ms
            });
            let ticket = entries
                .remove(&(peer_binding_sha256, nonce_sha256))
                .ok_or(ControllerError::Rejected(
                    "canonical request lacks a live controller acceptance ticket",
                ))?;
            if ticket.lane != lane
                || ticket.peer_binding_sha256 != peer_binding_sha256
                || ticket.frame_deadline_unix_ms < now_ms
                || format_rfc3339_seconds_v11(ticket.accepted_at_unix_ms)?
                    != accepted_at
            {
                return Err(ControllerError::Rejected(
                    "canonical request acceptance ticket binding differs",
                ));
            }
            Ok(ticket)
        }
    }

    struct ConnectionLimiter {
        active: AtomicUsize,
        maximum: usize,
    }

    impl ConnectionLimiter {
        fn new(maximum: usize) -> Self {
            Self {
                active: AtomicUsize::new(0),
                maximum,
            }
        }

        fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
            let mut current = self.active.load(Ordering::Acquire);
            loop {
                if current >= self.maximum {
                    return None;
                }
                match self.active.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        return Some(ConnectionPermit {
                            limiter: Arc::clone(self),
                        })
                    }
                    Err(observed) => current = observed,
                }
            }
        }
    }

    struct ConnectionPermit {
        limiter: Arc<ConnectionLimiter>,
    }

    impl Drop for ConnectionPermit {
        fn drop(&mut self) {
            self.limiter.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub fn run() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(ControllerError::Rejected("controller daemon must run as root"));
        }
        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error().into());
        }
        probe_linux_requirements()?;
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let arguments: Vec<String> = std::env::args().collect();
        if arguments.len() == 3
            && arguments[1] == "--provision-trusted-host"
        {
            return provision_trusted_host(Path::new(&arguments[2]));
        }
        if arguments.len() != 3 || arguments[1] != "--config" {
            return Err(ControllerError::Invalid(
                "usage: catchplate-coder-controller --config /root-owned/immutable/config | --provision-trusted-host /root-owned/config",
            ));
        }
        let parsed = load_immutable_config(Path::new(&arguments[2]))?;
        parsed.transport.validate_disabled()?;
        let readiness = Arc::new(ReadinessState::new());
        let mode = match (parsed.mode, parsed.production) {
            (ControllerMode::DisabledDevHello, None) => RuntimeMode::DisabledDevHello,
            (ControllerMode::TrustedHostV11, Some(settings)) => {
                let production = TrustedHostProduction::construct(
                    &parsed.transport,
                    settings,
                    Arc::clone(&readiness),
                )?;
                let broker = TrustedHostBroker::spawn(
                    production,
                    Arc::clone(&readiness),
                )?;
                readiness.mark_ready()?;
                RuntimeMode::TrustedHost(broker)
            }
            _ => {
                return Err(ControllerError::Invalid(
                    "controller mode and production configuration disagree",
                ))
            }
        };
        let daemon = Arc::new(ControllerDaemon {
            limiter: Arc::new(ConnectionLimiter::new(parsed.transport.max_connections)),
            config: parsed.transport,
            nonces: NonceWindow::new(),
            tickets: TicketWindow::new(),
            mode,
            readiness,
        });
        let listener = bind_socket(&daemon.config)?;
        loop {
            let connection = accept_socket(listener.as_raw_fd())?;
            let permit = match daemon.limiter.try_acquire() {
                Some(permit) => permit,
                None => continue,
            };
            let daemon = Arc::clone(&daemon);
            let spawn = std::thread::Builder::new()
                .name("catchplate-controller-connection".to_owned())
                .spawn(move || {
                    let _permit = permit;
                    if let Err(error) = serve_one(connection, &daemon) {
                        eprintln!("{PROTOCOL_NAME}: connection rejected: {error}");
                    }
                });
            if let Err(error) = spawn {
                eprintln!("{PROTOCOL_NAME}: connection thread rejected: {error}");
            }
        }
    }

    fn serve_one(connection: OwnedFd, daemon: &ControllerDaemon) -> Result<()> {
        poll_for(
            connection.as_raw_fd(),
            libc::POLLIN,
            daemon.config.first_frame_timeout_ms,
        )?;
        let packet = receive_frame_nonblocking(connection.as_raw_fd())?;
        verify_peer(&packet, &daemon.config)?;
        let binding = peer_binding(
            packet.peer.pid as u32,
            packet.peer.uid,
            packet.peer.gid,
            &packet.pidfd_identity,
        );
        if &packet.frame[0..24] == b"CATCHPLATE-CONTROLLER\0\0\0" {
            return serve_canonical_request(
                connection.as_raw_fd(),
                daemon,
                packet,
                binding,
            );
        }
        let frame = PreallocationFrame::decode(&packet.frame)?;
        frame.verify_before_body(&binding, now_unix_ms()?)?;
        let expected_bytes = match frame.kind {
            FrameKind::Hello
                if frame.declared_envelope_bytes
                    == ACCEPTANCE_TICKET_REQUEST_BYTES as u64 =>
            {
                ACCEPTANCE_TICKET_REQUEST_BYTES
            }
            FrameKind::Hello => HelloEnvelope::ENCODED_BYTES,
            FrameKind::Request => ClientSubmission::ENCODED_BYTES,
            FrameKind::Receipt | FrameKind::Error => {
                return Err(ControllerError::Rejected(
                    "client cannot submit receipt or error frames",
                ))
            }
        };
        if frame.declared_canonical_bytes != expected_bytes as u64
            || frame.declared_envelope_bytes != expected_bytes as u64
        {
            return Err(ControllerError::Invalid(
                "request declares an unexpected canonical byte count",
            ));
        }
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            frame.declared_envelope_bytes,
        )?;
        let actual_digest =
            digest_memfd(packet.memfd.as_raw_fd(), frame.declared_envelope_bytes)?;
        frame.verify_envelope_digest(&actual_digest)?;
        let mut canonical = vec![0u8; expected_bytes];
        pread_exact(packet.memfd.as_raw_fd(), &mut canonical)?;
        match frame.kind {
            FrameKind::Hello => {
                if canonical.len() == ACCEPTANCE_TICKET_REQUEST_BYTES {
                    let production = match &daemon.mode {
                        RuntimeMode::DisabledDevHello => {
                            return Err(ControllerError::Unready(vec![
                                "disabled/dev mode cannot issue production acceptance tickets"
                                    .to_owned(),
                            ]))
                        }
                        RuntimeMode::TrustedHost(production) => production,
                    };
                    let request =
                        AcceptanceTicketRequestV11::decode(&canonical)?;
                    frame.verify_raw_nonce(&request.raw_nonce)?;
                    if request.peer_binding_sha256 != binding
                        || frame.request_id != request.request_sha256
                    {
                        return Err(ControllerError::Rejected(
                            "acceptance ticket transport binding differs",
                        ));
                    }
                    daemon.nonces.consume_valid(
                        binding,
                        frame.nonce_sha256,
                        frame.deadline_unix_ms,
                        now_unix_ms()?,
                    )?;
                    daemon.readiness.require_ready()?;
                    return serve_acceptance_ticket(
                        connection.as_raw_fd(),
                        daemon,
                        production,
                        &frame,
                        request,
                        binding,
                    );
                }
                let hello = HelloEnvelope::decode(&canonical)?;
                frame.verify_raw_nonce(&hello.raw_nonce)?;
                if hello.request_id != frame.request_id {
                    return Err(ControllerError::Rejected(
                        "hello frame/request ID mismatch",
                    ));
                }
                daemon.nonces.consume_valid(
                    binding,
                    frame.nonce_sha256,
                    frame.deadline_unix_ms,
                    now_unix_ms()?,
                )?;
                serve_hello(connection.as_raw_fd(), daemon, &frame, hello)
            }
            FrameKind::Request => {
                Err(ControllerError::Rejected(
                    "production requests require the canonical JSON v11 wire contract",
                ))
            }
            FrameKind::Receipt | FrameKind::Error => unreachable!(),
        }
    }

    fn serve_acceptance_ticket(
        socket: RawFd,
        daemon: &ControllerDaemon,
        production: &TrustedHostBroker,
        transport_frame: &PreallocationFrame,
        request: AcceptanceTicketRequestV11,
        binding: Digest,
    ) -> Result<()> {
        let accepted_at_unix_ms = now_unix_ms()? / 1_000 * 1_000;
        let frame_deadline_unix_ms = accepted_at_unix_ms
            .checked_add(30_000)
            .ok_or(ControllerError::Invalid(
                "acceptance frame deadline overflow",
            ))?;
        let configured_lane_ms = *production
            .lane_deadlines_ms
            .get(&request.lane.plan)
            .ok_or(ControllerError::Rejected(
                "acceptance ticket lane deadline is absent",
            ))?;
        let request_deadline_unix_ms = accepted_at_unix_ms
            .checked_add(
                configured_lane_ms.min(request.requested_timeout_ms),
            )
            .ok_or(ControllerError::Invalid(
                "acceptance request deadline overflow",
            ))?;
        let ticket = AcceptanceTicketV11::sign(
            &request,
            accepted_at_unix_ms,
            frame_deadline_unix_ms,
            request_deadline_unix_ms,
            production.config_sha256,
            &production.ticket_signing_key,
        )?;
        daemon
            .tickets
            .issue(binding, ticket.clone(), accepted_at_unix_ms)?;
        send_response(
            socket,
            FrameKind::Hello,
            None,
            &ticket.encode(),
            &request.raw_nonce,
            request.request_sha256,
            transport_frame.deadline_unix_ms,
            "catchplate-controller-acceptance-ticket-v11",
        )
    }

    fn serve_canonical_request(
        socket: RawFd,
        daemon: &ControllerDaemon,
        packet: ReceivedPacket,
        binding: Digest,
    ) -> Result<()> {
        let production = match &daemon.mode {
            RuntimeMode::DisabledDevHello => {
                return Err(ControllerError::Unready(vec![
                    "disabled/dev mode accepts hello only".to_owned(),
                ]))
            }
            RuntimeMode::TrustedHost(production) => production,
        };
        let received_at = now_unix_ms()?;
        let frame = CanonicalPreallocationFrameV11::decode(&packet.frame)?;
        if frame.kind != CanonicalFrameKindV11::Request {
            return Err(ControllerError::Rejected(
                "client cannot submit a canonical receipt frame",
            ));
        }
        frame.verify_receive_deadline(received_at)?;
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            frame.declared_canonical_bytes,
        )?;
        let canonical = read_memfd_bounded(
            packet.memfd,
            frame.declared_canonical_bytes,
            REQUEST_MAX_BYTES,
        )?;
        let request = CanonicalControllerRequestV11::parse_and_verify(
            canonical,
            &frame,
            &production.requester_verifying_key,
            ed25519_spki_der_sha256_v11(
                &production.requester_verifying_key,
            ),
            None,
        )?;
        let ticket = daemon.tickets.consume(
            binding,
            frame.frame_nonce_sha256,
            &request.accepted_at,
            request.lane,
            received_at,
        )?;
        if ticket.frame_deadline_unix_ms
                != frame.frame_deadline_unix_ms
            || ticket.request_deadline_unix_ms
                != request.deadline_unix_ms
            || ticket.config_sha256 != production.config_sha256
        {
            return Err(ControllerError::Rejected(
                "canonical request differs from its controller acceptance ticket",
            ));
        }
        daemon.readiness.require_ready()?;
        let submission = ClientSubmission::sign_internal(
            request.lane,
            request.raw_nonce,
            request.request_id,
            request.deadline_unix_ms,
            production.config_sha256,
            binding,
            request.request_envelope_sha256,
            request.plan_configuration_sha256,
            request.source_tree_sha256,
            &production.internal_submission_signing_key,
        )?;
        let internal_bytes = submission.encode();
        let internal_frame = PreallocationFrame::new(
            FrameKind::Request,
            Some(request.lane),
            internal_bytes.len() as u64,
            &internal_bytes,
            &request.raw_nonce,
            binding,
            request.request_id,
            request.deadline_unix_ms,
        )?;
        let receipt = production.execute(
            &submission,
            &internal_frame,
            binding,
            packet.peer_start_time_ticks,
            packet.peer.uid,
            packet.peer.gid,
        )?;
        send_canonical_production_receipt(
            socket,
            production,
            &frame,
            &request,
            &receipt,
        )
    }

    fn send_canonical_production_receipt(
        socket: RawFd,
        production: &TrustedHostBroker,
        request_frame: &CanonicalPreallocationFrameV11,
        request: &CanonicalControllerRequestV11,
        terminal_evidence: &[u8],
    ) -> Result<()> {
        if terminal_evidence.len() != SIGNED_CONTROLLER_RECEIPT_BYTES {
            return Err(ControllerError::Rejected(
                "broker terminal evidence is not the fixed signed v11 evidence record",
            ));
        }
        let canonical_request = request.exact_bytes();
        let authority_request = ReceiptAuthorityRequestV11::new(
            request.lane,
            request.deadline_unix_ms,
            canonical_request.len() as u64,
            terminal_evidence.len() as u64,
            request.request_envelope_sha256,
            request_frame.frame_nonce_sha256,
            sha256(canonical_request),
            sha256(terminal_evidence),
            production.daemon_identity_sha256,
        )?;
        let mut bundle = Vec::with_capacity(
            canonical_request.len() + terminal_evidence.len(),
        );
        bundle.extend_from_slice(canonical_request);
        bundle.extend_from_slice(terminal_evidence);
        let bundle_memfd = create_sealed_memfd(
            "catchplate-receipt-authority-input-v11",
            &bundle,
        )?;
        let authority = connect_root_seqpacket(
            Path::new(CONTROLLER_RECEIPT_AUTHORITY_SOCKET_PATH),
            request.deadline_unix_ms,
        )?;
        send_frame_with_memfd(
            authority.as_raw_fd(),
            &authority_request.encode(),
            bundle_memfd.as_raw_fd(),
        )?;
        poll_until_deadline(
            authority.as_raw_fd(),
            libc::POLLIN,
            request.deadline_unix_ms,
        )?;
        let packet = receive_frame_nonblocking(authority.as_raw_fd())?;
        require_live_root_peer(&packet)?;
        let receipt_frame =
            CanonicalPreallocationFrameV11::decode(&packet.frame)?;
        if receipt_frame.kind != CanonicalFrameKindV11::Receipt {
            return Err(ControllerError::Rejected(
                "receipt authority returned a non-receipt frame",
            ));
        }
        receipt_frame.verify_receive_deadline(now_unix_ms()?)?;
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            receipt_frame.declared_canonical_bytes,
        )?;
        let receipt_bytes = read_memfd_bounded(
            packet.memfd,
            receipt_frame.declared_canonical_bytes,
            RECEIPT_MAX_BYTES,
        )?;
        let receipt = CanonicalControllerReceiptV11::parse_and_verify(
            receipt_bytes,
            &receipt_frame,
            &production.receipt_verifying_key,
            ed25519_spki_der_sha256_v11(
                &production.receipt_verifying_key,
            ),
            &production.final_verdict_verifying_key,
            ed25519_spki_der_sha256_v11(
                &production.final_verdict_verifying_key,
            ),
            request.request_envelope_sha256,
            request_frame.frame_nonce_sha256,
        )?;
        let response_memfd = create_sealed_memfd(
            "catchplate-controller-canonical-receipt-v11",
            receipt.exact_bytes(),
        )?;
        poll_until_deadline(
            socket,
            libc::POLLOUT,
            request.deadline_unix_ms,
        )?;
        send_frame_with_memfd(
            socket,
            &receipt_frame.encode()?,
            response_memfd.as_raw_fd(),
        )
    }

    fn require_live_root_peer(packet: &ReceivedPacket) -> Result<()> {
        if packet.peer.uid != 0
            || packet.peer.gid != 0
            || packet.pidfd_identity != format!("pid:{}", packet.peer.pid)
            || !pidfd_poll_live(packet.pidfd.as_raw_fd())?
            || proc_start_time_ticks(packet.peer.pid)?
                != packet.peer_start_time_ticks
        {
            return Err(ControllerError::Rejected(
                "receipt authority peer is not one live root process",
            ));
        }
        Ok(())
    }

    fn connect_root_seqpacket(
        path: &Path,
        deadline_unix_ms: u64,
    ) -> Result<OwnedFd> {
        validate_absolute_normalized_path(path)?;
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET
                    | libc::SOCK_CLOEXEC
                    | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        enable_pass_pidfd(socket.as_raw_fd())?;
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty()
            || path_bytes.len() >= address.sun_path.len()
        {
            return Err(ControllerError::Invalid(
                "root seqpacket path is invalid",
            ));
        }
        for (slot, byte) in address.sun_path.iter_mut().zip(path_bytes) {
            *slot = *byte as libc::c_char;
        }
        let length = (mem::size_of::<libc::sa_family_t>()
            + path_bytes.len()
            + 1) as libc::socklen_t;
        let connected = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &address as *const libc::sockaddr_un
                    as *const libc::sockaddr,
                length,
            )
        };
        if connected != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error.into());
            }
            poll_until_deadline(
                socket.as_raw_fd(),
                libc::POLLOUT,
                deadline_unix_ms,
            )?;
            let mut pending = 0;
            let mut pending_length =
                mem::size_of::<libc::c_int>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut pending as *mut libc::c_int
                        as *mut libc::c_void,
                    &mut pending_length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if pending != 0 {
                return Err(
                    std::io::Error::from_raw_os_error(pending).into(),
                );
            }
        }
        let peer = socket_peer(socket.as_raw_fd())?;
        if peer.uid != 0 || peer.gid != 0 {
            return Err(ControllerError::Rejected(
                "root seqpacket peer credentials differ",
            ));
        }
        Ok(socket)
    }

    fn serve_hello(
        socket: RawFd,
        daemon: &ControllerDaemon,
        frame: &PreallocationFrame,
        hello: HelloEnvelope,
    ) -> Result<()> {
        let mode = match &daemon.mode {
            RuntimeMode::DisabledDevHello => "UNREADY disabled/dev hello only",
            RuntimeMode::TrustedHost(_) => "measured trusted-host production; no TEE or hardware attestation",
        };
        let response = HelloResponse {
            raw_nonce: hello.raw_nonce,
            request_id: hello.request_id,
            message: format!(
                "{PROTOCOL_NAME}: {} {mode}; config={}",
                daemon.readiness.summary(),
                digest_hex(&daemon.config.config_sha256)
            ),
        }
        .encode()?;
        send_response(
            socket,
            FrameKind::Hello,
            None,
            &response,
            &hello.raw_nonce,
            hello.request_id,
            frame.deadline_unix_ms,
            "catchplate-controller-hello-v11",
        )
    }

    fn send_production_receipt(
        socket: RawFd,
        request_frame: &PreallocationFrame,
        submission: &ClientSubmission,
        receipt: Vec<u8>,
    ) -> Result<()> {
        if receipt.len() != SIGNED_CONTROLLER_RECEIPT_BYTES
            || receipt.len() as u64 > RECEIPT_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "signed production receipt is not the fixed v11 length",
            ));
        }
        send_response(
            socket,
            FrameKind::Receipt,
            Some(submission.lane),
            &receipt,
            &submission.raw_nonce,
            submission.request_id,
            request_frame.deadline_unix_ms,
            "catchplate-controller-receipt-v11",
        )
    }

    fn send_response(
        socket: RawFd,
        kind: FrameKind,
        lane: Option<Lane>,
        bytes: &[u8],
        raw_nonce: &Digest,
        request_id: Digest,
        deadline_unix_ms: u64,
        memfd_name: &str,
    ) -> Result<()> {
        let response_frame = PreallocationFrame::new(
            kind,
            lane,
            bytes.len() as u64,
            bytes,
            raw_nonce,
            binding_for_self()?,
            request_id,
            deadline_unix_ms,
        )?;
        let response_memfd = create_sealed_memfd(memfd_name, bytes)?;
        poll_until_deadline(socket, libc::POLLOUT, deadline_unix_ms)?;
        send_frame_with_memfd(
            socket,
            &response_frame.encode(),
            response_memfd.as_raw_fd(),
        )
    }

    fn load_immutable_config(path: &Path) -> Result<ParsedDaemonConfig> {
        if !path.is_absolute() {
            return Err(ControllerError::Invalid("config path must be absolute"));
        }
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("config path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path_c.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        let secret_mode_invalid = metadata.mode() & 0o077 != 0;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || secret_mode_invalid
            || metadata.nlink() != 1
            || metadata.len() > CONFIG_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "config FD is not one small root-owned nonwritable regular file",
            ));
        }
        let mut flags: libc::c_uint = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) } != 0
            || flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "config FD lacks the filesystem immutable flag",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(CONFIG_MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > CONFIG_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "config changed or was truncated while reading the opened object",
            ));
        }
        let config_sha256 = sha256(&bytes);
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Invalid("config is not UTF-8"))?;
        parse_config(text, config_sha256)
    }

    fn provision_trusted_host(path: &Path) -> Result<()> {
        let bytes = read_root_provision_file(path, CONFIG_MAX_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Invalid("config is not UTF-8"))?;
        let parsed = parse_config(text, sha256(&bytes))?;
        let settings = parsed.production.ok_or(ControllerError::Invalid(
            "provisioning requires trusted-host-v11 mode",
        ))?;
        if settings.public_key_path != PathBuf::from(RECEIPT_PUBLIC_KEY_PATH)
            || settings.requester_public_key_path
                != PathBuf::from(REQUESTER_PUBLIC_KEY_PATH)
            || settings.final_verdict_public_key_path
                != PathBuf::from(FINAL_VERDICT_PUBLIC_KEY_PATH)
        {
            return Err(ControllerError::Rejected(
                "provisioning key paths differ from fixed trust paths",
            ));
        }
        let receipt_seed =
            read_root_provision_file(&settings.signing_key_path, 32)?;
        let final_verdict_public = read_root_provision_file(
            &settings.final_verdict_public_key_path,
            32,
        )?;
        let requester_seed = read_root_provision_file(
            Path::new(REQUESTER_SIGNING_KEY_PATH),
            32,
        )?;
        if receipt_seed.len() != 32
            || requester_seed.len() != 32
            || final_verdict_public.len() != 32
        {
            return Err(ControllerError::Rejected(
                "provisioning Ed25519 seeds must be exactly 32 bytes",
            ));
        }
        let mut receipt_secret = [0u8; 32];
        receipt_secret.copy_from_slice(&receipt_seed);
        let receipt_signing = SigningKey::from_bytes(&receipt_secret);
        receipt_secret.fill(0);
        let mut requester_secret = [0u8; 32];
        requester_secret.copy_from_slice(&requester_seed);
        let requester_signing = SigningKey::from_bytes(&requester_secret);
        requester_secret.fill(0);
        let receipt_public = *receipt_signing.verifying_key().as_bytes();
        let requester_public = *requester_signing.verifying_key().as_bytes();
        write_new_root_file(
            &settings.public_key_path,
            &receipt_public,
            0o444,
        )?;
        write_new_root_file(
            &settings.requester_public_key_path,
            &requester_public,
            0o444,
        )?;
        let mut plans = BTreeMap::new();
        for (plan, specification) in settings.plans {
            plans.insert(plan, FixedLaunchPlan::open(plan, specification)?);
        }
        validate_fixed_plan_separation(&plans)?;
        let identities = std::array::from_fn(|index| {
            plans
                .get(&FIXED_PLAN_ORDER[index])
                .map(|plan| plan.command_identity_sha256)
                .unwrap_or([0; 32])
        });
        let manifest =
            TrustedPlanManifestV11::new(parsed.transport.config_sha256, identities)?;
        let manifest_bytes = manifest.encode()?;
        write_new_root_file(
            Path::new(TRUSTED_PLAN_MANIFEST_PATH),
            &manifest_bytes,
            0o444,
        )?;
        for (target, expected) in [
            (
                Path::new(RECEIPT_PUBLIC_KEY_PATH),
                receipt_public.as_slice(),
            ),
            (
                Path::new(REQUESTER_PUBLIC_KEY_PATH),
                requester_public.as_slice(),
            ),
        ] {
            if std::fs::read(target)?.as_slice() != expected {
                return Err(ControllerError::Rejected(
                    "provisioned key readback differs",
                ));
            }
        }
        if TrustedPlanManifestV11::decode(
            &std::fs::read(TRUSTED_PLAN_MANIFEST_PATH)?,
        )? != manifest
        {
            return Err(ControllerError::Rejected(
                "provisioned trust manifest readback differs",
            ));
        }
        Ok(())
    }

    fn read_root_provision_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
        validate_absolute_normalized_path(path)?;
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("provision path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path_c.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(ControllerError::Rejected(
                "provision input is not one bounded root-owned nonwritable regular file",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(ControllerError::Rejected(
                "provision input changed during read",
            ));
        }
        Ok(bytes)
    }

    fn write_new_root_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        validate_absolute_normalized_path(path)?;
        let parent = path.parent().ok_or(ControllerError::Invalid(
            "provision output parent is absent",
        ))?;
        let name = path.file_name().ok_or(ControllerError::Invalid(
            "provision output name is absent",
        ))?;
        let parent_fd = open_canonical_directory(parent, false)?;
        verify_root_owned_directory(parent_fd.as_raw_fd(), false)?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| ControllerError::Invalid("provision output name contains NUL"))?;
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                mode,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let output = unsafe { OwnedFd::from_raw_fd(raw) };
        write_all_fd(output.as_raw_fd(), bytes)?;
        if unsafe { libc::fchmod(output.as_raw_fd(), mode) } != 0
            || unsafe { libc::fsync(output.as_raw_fd()) } != 0
            || unsafe { libc::fsync(parent_fd.as_raw_fd()) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn parse_config(text: &str, config_sha256: Digest) -> Result<ParsedDaemonConfig> {
        let mut singletons = BTreeMap::<String, String>::new();
        let mut allowed_uids = BTreeSet::new();
        let mut allowed_gids = BTreeSet::new();
        let mut artifact_paths = BTreeSet::new();
        let mut denied_socket_paths = BTreeSet::new();
        let mut plan_builders = BTreeMap::<Plan, PlanSpecBuilder>::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(ControllerError::Invalid("invalid config line"))?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "allow_uid" => {
                    allowed_uids.insert(parse_u32(value, "invalid allow_uid")?);
                }
                "allow_gid" => {
                    allowed_gids.insert(parse_u32(value, "invalid allow_gid")?);
                }
                "mode"
                | "socket_path"
                | "socket_uid"
                | "socket_gid"
                | "socket_mode"
                | "max_connections"
                | "first_frame_timeout_ms"
                | "state_dir"
                | "source_root"
                | "signing_key_path"
                | "public_key_path"
                | "requester_public_key_path"
                | "final_verdict_public_key_path"
                | "cgroup_root"
                | "trust_epoch"
                | "revocation_epoch"
                | "deadline.catchplate-build-v1.ms"
                | "deadline.catchplate-unit-no-build-v1.ms"
                | "deadline.catchplate-integration-no-build-v1.ms"
                | "deadline.catchplate-e2e-no-build-v1.ms"
                | "deadline.catchplate-attestation-no-build-v1.ms" => {
                    if singletons
                        .insert(key.to_owned(), value.to_owned())
                        .is_some()
                    {
                        return Err(ControllerError::Invalid("duplicate config key"));
                    }
                }
                "artifact_path" => {
                    if !artifact_paths.insert(PathBuf::from(value)) {
                        return Err(ControllerError::Invalid("duplicate artifact_path"));
                    }
                }
                "denied_socket_path" => {
                    if !denied_socket_paths.insert(PathBuf::from(value)) {
                        return Err(ControllerError::Invalid(
                            "duplicate denied_socket_path",
                        ));
                    }
                }
                _ if key.starts_with("plan.") => {
                    parse_plan_config_key(key, value, &mut plan_builders)?;
                }
                _ => return Err(ControllerError::Invalid("unknown config key")),
            }
        }
        let mode = match singleton(&singletons, "mode")? {
            "disabled-dev-hello" => ControllerMode::DisabledDevHello,
            "trusted-host-v11" => ControllerMode::TrustedHostV11,
            _ => return Err(ControllerError::Invalid("unsupported controller mode")),
        };
        let socket_path = PathBuf::from(singleton(&singletons, "socket_path")?);
        let socket_uid = parse_u32(singleton(&singletons, "socket_uid")?, "invalid socket_uid")?;
        let socket_gid = parse_u32(singleton(&singletons, "socket_gid")?, "invalid socket_gid")?;
        let socket_mode = u32::from_str_radix(
            singleton(&singletons, "socket_mode")?
                .strip_prefix("0o")
                .unwrap_or(singleton(&singletons, "socket_mode")?),
            8,
        )
        .map_err(|_| ControllerError::Invalid("invalid socket_mode"))?;
        let max_connections = singleton(&singletons, "max_connections")?
            .parse::<usize>()
            .map_err(|_| ControllerError::Invalid("invalid max_connections"))?;
        let first_frame_timeout_ms = singleton(&singletons, "first_frame_timeout_ms")?
            .parse::<u64>()
            .map_err(|_| ControllerError::Invalid("invalid first_frame_timeout_ms"))?;
        let transport = ImmutableControllerConfig {
            config_sha256,
            socket_path,
            socket_uid,
            socket_gid,
            socket_mode,
            allowed_uids,
            allowed_gids,
            max_connections,
            first_frame_timeout_ms,
        };
        let production = match mode {
            ControllerMode::DisabledDevHello => {
                if !plan_builders.is_empty()
                    || !artifact_paths.is_empty()
                    || !denied_socket_paths.is_empty()
                    || singletons.contains_key("state_dir")
                {
                    return Err(ControllerError::Invalid(
                        "disabled mode cannot carry production configuration",
                    ));
                }
                None
            }
            ControllerMode::TrustedHostV11 => {
                let mut deadlines_ms = BTreeMap::new();
                for label in REQUIRED_PLAN_LABELS {
                    let plan = plan_from_label(label)?;
                    let key = format!("deadline.{label}.ms");
                    let value = singleton(&singletons, &key)?
                        .parse::<u64>()
                        .map_err(|_| ControllerError::Invalid("invalid lane deadline"))?;
                    if !(1_000..=24 * 60 * 60 * 1_000).contains(&value) {
                        return Err(ControllerError::Invalid(
                            "lane deadline is outside the trusted-host bound",
                        ));
                    }
                    deadlines_ms.insert(plan, value);
                }
                let mut plans = BTreeMap::new();
                for label in REQUIRED_PLAN_LABELS {
                    let plan = plan_from_label(label)?;
                    let builder = plan_builders
                        .remove(&plan)
                        .ok_or(ControllerError::Invalid("fixed plan is absent"))?;
                    plans.insert(plan, finish_plan_spec(builder)?);
                }
                if !plan_builders.is_empty() || artifact_paths.is_empty() {
                    return Err(ControllerError::Invalid(
                        "production requires exactly five plans and artifact paths",
                    ));
                }
                Some(TrustedHostSettings {
                    state_dir: absolute_config_path(&singletons, "state_dir")?,
                    source_root: absolute_config_path(&singletons, "source_root")?,
                    signing_key_path: absolute_config_path(&singletons, "signing_key_path")?,
                    public_key_path: absolute_config_path(&singletons, "public_key_path")?,
                    requester_public_key_path: absolute_config_path(
                        &singletons,
                        "requester_public_key_path",
                    )?,
                    final_verdict_public_key_path: absolute_config_path(
                        &singletons,
                        "final_verdict_public_key_path",
                    )?,
                    cgroup_root: absolute_config_path(&singletons, "cgroup_root")?,
                    trust_epoch: parse_nonzero_u64(&singletons, "trust_epoch")?,
                    revocation_epoch: parse_nonzero_u64(&singletons, "revocation_epoch")?,
                    deadlines_ms,
                    plans,
                    artifact_paths: artifact_paths.into_iter().collect(),
                    denied_socket_paths: denied_socket_paths.into_iter().collect(),
                })
            }
        };
        Ok(ParsedDaemonConfig {
            transport,
            mode,
            production,
        })
    }

    fn parse_plan_config_key(
        key: &str,
        value: &str,
        plans: &mut BTreeMap<Plan, PlanSpecBuilder>,
    ) -> Result<()> {
        let rest = key
            .strip_prefix("plan.")
            .ok_or(ControllerError::Invalid("invalid plan config key"))?;
        let (label, field) = rest
            .split_once('.')
            .ok_or(ControllerError::Invalid("invalid plan config key"))?;
        let plan = plan_from_label(label)?;
        let builder = plans.entry(plan).or_default();
        match field {
            "executable" => {
                if builder.executable.replace(PathBuf::from(value)).is_some() {
                    return Err(ControllerError::Invalid("duplicate plan executable"));
                }
            }
            "cwd" => {
                if builder.cwd.replace(PathBuf::from(value)).is_some() {
                    return Err(ControllerError::Invalid("duplicate plan cwd"));
                }
            }
            "configuration_sha256" => {
                let digest = parse_config_digest(value)?;
                if builder.configuration_sha256.replace(digest).is_some() {
                    return Err(ControllerError::Invalid(
                        "duplicate plan configuration digest",
                    ));
                }
            }
            _ if field.starts_with("arg.") => {
                let index = field[4..]
                    .parse::<usize>()
                    .map_err(|_| ControllerError::Invalid("invalid plan argument index"))?;
                if index > 4096 || builder.args.insert(index, value.to_owned()).is_some() {
                    return Err(ControllerError::Invalid(
                        "duplicate or excessive plan argument",
                    ));
                }
            }
            _ if field.starts_with("env.") => {
                let name = &field[4..];
                if !valid_environment_name(name)
                    || builder
                        .env
                        .insert(name.to_owned(), value.to_owned())
                        .is_some()
                {
                    return Err(ControllerError::Invalid(
                        "invalid or duplicate plan environment entry",
                    ));
                }
            }
            _ if field.starts_with("closure.exec.")
                || field.starts_with("closure.read.") =>
            {
                let executable = field.starts_with("closure.exec.");
                let index_text = if executable {
                    &field["closure.exec.".len()..]
                } else {
                    &field["closure.read.".len()..]
                };
                let index = index_text.parse::<usize>().map_err(|_| {
                    ControllerError::Invalid("invalid closure member index")
                })?;
                if index > 4096
                    || builder
                        .closure
                        .insert(index, (executable, PathBuf::from(value)))
                        .is_some()
                {
                    return Err(ControllerError::Invalid(
                        "duplicate or excessive closure member",
                    ));
                }
            }
            _ => return Err(ControllerError::Invalid("unknown plan config field")),
        }
        Ok(())
    }

    fn parse_config_digest(value: &str) -> Result<Digest> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControllerError::Invalid(
                "plan configuration digest must be lowercase SHA-256",
            ));
        }
        let mut digest = [0u8; 32];
        for (index, output) in digest.iter_mut().enumerate() {
            let high = config_hex_nibble(value.as_bytes()[index * 2])?;
            let low = config_hex_nibble(value.as_bytes()[index * 2 + 1])?;
            *output = high << 4 | low;
        }
        if digest == [0; 32] {
            return Err(ControllerError::Invalid(
                "plan configuration digest must not be zero",
            ));
        }
        Ok(digest)
    }

    fn config_hex_nibble(value: u8) -> Result<u8> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(ControllerError::Invalid(
                "plan configuration digest contains non-hexadecimal bytes",
            )),
        }
    }

    fn finish_plan_spec(builder: PlanSpecBuilder) -> Result<PlanSpec> {
        let executable = builder
            .executable
            .ok_or(ControllerError::Invalid("plan executable is absent"))?;
        let cwd = builder
            .cwd
            .ok_or(ControllerError::Invalid("plan cwd is absent"))?;
        let configuration_sha256 = builder
            .configuration_sha256
            .ok_or(ControllerError::Invalid(
                "plan configuration digest is absent",
            ))?;
        if !executable.is_absolute() || !cwd.is_absolute() || builder.args.is_empty() {
            return Err(ControllerError::Invalid(
                "plan executable/cwd/argv are incomplete",
            ));
        }
        let mut args = Vec::with_capacity(builder.args.len());
        for (expected, (actual, value)) in builder.args.into_iter().enumerate() {
            if actual != expected || value.as_bytes().contains(&0) {
                return Err(ControllerError::Invalid(
                    "plan argv indices are not contiguous or contain NUL",
                ));
            }
            args.push(value);
        }
        if builder
            .env
            .iter()
            .any(|(name, value)| name.as_bytes().contains(&0) || value.as_bytes().contains(&0))
        {
            return Err(ControllerError::Invalid("plan environment contains NUL"));
        }
        if builder.closure.is_empty() {
            return Err(ControllerError::Invalid(
                "plan executable closure is absent",
            ));
        }
        let mut closure = Vec::with_capacity(builder.closure.len());
        let mut closure_paths = BTreeSet::new();
        for (expected, (actual, member)) in
            builder.closure.into_iter().enumerate()
        {
            if actual != expected
                || !member.1.is_absolute()
                || !closure_paths.insert(member.1.clone())
            {
                return Err(ControllerError::Invalid(
                    "plan closure indices/paths are not contiguous, unique, and absolute",
                ));
            }
            closure.push(member);
        }
        if !closure
            .iter()
            .any(|(is_executable, path)| *is_executable && path == &executable)
        {
            return Err(ControllerError::Invalid(
                "plan closure does not contain its primary executable",
            ));
        }
        Ok(PlanSpec {
            executable,
            cwd,
            configuration_sha256,
            args,
            env: builder.env,
            closure,
        })
    }

    fn plan_from_label(label: &str) -> Result<Plan> {
        match label {
            "catchplate-build-v1" => Ok(Plan::Build),
            "catchplate-unit-no-build-v1" => Ok(Plan::UnitNoBuild),
            "catchplate-integration-no-build-v1" => Ok(Plan::IntegrationNoBuild),
            "catchplate-e2e-no-build-v1" => Ok(Plan::E2eNoBuild),
            "catchplate-attestation-no-build-v1" => Ok(Plan::AttestationNoBuild),
            _ => Err(ControllerError::Invalid("plan is outside the fixed v11 table")),
        }
    }

    fn valid_environment_name(name: &str) -> bool {
        !name.is_empty()
            && name != "LD_PRELOAD"
            && name != "LD_LIBRARY_PATH"
            && name
                .bytes()
                .enumerate()
                .all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
    }

    fn absolute_config_path(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<PathBuf> {
        let path = PathBuf::from(singleton(values, key)?);
        validate_absolute_normalized_path(&path)?;
        Ok(path)
    }

    fn parse_nonzero_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64> {
        let value = singleton(values, key)?
            .parse::<u64>()
            .map_err(|_| ControllerError::Invalid("invalid production epoch"))?;
        if value == 0 {
            return Err(ControllerError::Invalid("production epoch must be nonzero"));
        }
        Ok(value)
    }

    fn singleton<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
        values
            .get(key)
            .map(String::as_str)
            .ok_or(ControllerError::Invalid("required config key is absent"))
    }

    fn parse_u32(value: &str, message: &'static str) -> Result<u32> {
        value
            .parse::<u32>()
            .map_err(|_| ControllerError::Invalid(message))
    }

    fn bind_socket(config: &ImmutableControllerConfig) -> Result<OwnedFd> {
        let parent = config
            .socket_path
            .parent()
            .ok_or(ControllerError::Invalid("socket path has no parent"))?;
        verify_socket_ancestor_chain(parent)?;
        match std::fs::symlink_metadata(&config.socket_path) {
            Ok(_) => {
                return Err(ControllerError::Rejected(
                    "controller refuses to replace an existing socket path",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
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
        enable_pass_pidfd(socket.as_raw_fd())?;
        let path_bytes = config.socket_path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if path_bytes.len() >= address.sun_path.len() {
            return Err(ControllerError::Invalid("socket path is too long"));
        }
        for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
            *destination = *source as libc::c_char;
        }
        let length =
            (mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let path_c = CString::new(path_bytes)
            .map_err(|_| ControllerError::Invalid("socket path contains NUL"))?;
        if unsafe { libc::chown(path_c.as_ptr(), config.socket_uid, config.socket_gid) } != 0
            || unsafe { libc::chmod(path_c.as_ptr(), config.socket_mode as libc::mode_t) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let bound = std::fs::symlink_metadata(&config.socket_path)?;
        if !bound.file_type().is_socket()
            || bound.uid() != config.socket_uid
            || bound.gid() != config.socket_gid
            || bound.permissions().mode() & 0o777 != config.socket_mode
        {
            return Err(ControllerError::Rejected(
                "bound socket ownership or mode does not match immutable config",
            ));
        }
        if unsafe { libc::listen(socket.as_raw_fd(), config.max_connections as libc::c_int) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(socket)
    }

    fn verify_socket_ancestor_chain(parent: &Path) -> Result<()> {
        if !parent.is_absolute()
            || parent.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir
                        | std::path::Component::ParentDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(ControllerError::Rejected(
                "socket ancestor chain is not absolute and canonical",
            ));
        }
        for ancestor in parent.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(ControllerError::Rejected(
                    "socket ancestor is not a root-owned nonwritable directory",
                ));
            }
        }
        Ok(())
    }

    fn accept_socket(listener: RawFd) -> Result<OwnedFd> {
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
        let connection = unsafe { OwnedFd::from_raw_fd(raw) };
        enable_pass_pidfd(connection.as_raw_fd())?;
        Ok(connection)
    }

    fn enable_pass_pidfd(fd: RawFd) -> Result<()> {
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_PASSPIDFD_VALUE,
                &enabled as *const _ as *const libc::c_void,
                mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn verify_peer(packet: &ReceivedPacket, config: &ImmutableControllerConfig) -> Result<()> {
        if !config.allowed_uids.contains(&packet.peer.uid)
            || !config.allowed_gids.contains(&packet.peer.gid)
        {
            return Err(ControllerError::Rejected("peer UID/GID is not allowed"));
        }
        if packet.pidfd_identity != format!("pid:{}", packet.peer.pid) {
            return Err(ControllerError::Rejected(
                "SCM_PIDFD and SO_PEERCRED identify different processes",
            ));
        }
        let poll_live = pidfd_poll_live(packet.pidfd.as_raw_fd())?;
        let current_start = proc_start_time_ticks(packet.peer.pid)?;
        if !poll_live || current_start != packet.peer_start_time_ticks {
            return Err(ControllerError::Rejected(
                "peer pidfd/start-time join is no longer live",
            ));
        }
        let signal_probe = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                packet.pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if signal_probe != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM)
                || !pidfd_poll_live(packet.pidfd.as_raw_fd())?
                || proc_start_time_ticks(packet.peer.pid)? != packet.peer_start_time_ticks
            {
                return Err(ControllerError::Rejected("peer pidfd is not live"));
            }
        }
        Ok(())
    }

    fn receive_frame_nonblocking(socket: RawFd) -> Result<ReceivedPacket> {
        let mut frame = [0u8; FIXED_FRAME_BYTES];
        let mut iov = libc::iovec {
            iov_base: frame.as_mut_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        let mut control = AlignedControl::zeroed();
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control.bytes.len();
        let count = unsafe {
            libc::recvmsg(
                socket,
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // recvmsg has installed all delivered descriptors by this point. Own
        // every visible descriptor before inspecting packet length, flags,
        // ancillary shape, or cardinality so every rejection path closes them.
        let ancillary = own_all_descriptors(&message);
        if count != FIXED_FRAME_BYTES as isize
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(ControllerError::Invalid("invalid first frame or ancillary truncation"));
        }
        if ancillary.invalid || ancillary.rights.len() != 1 || ancillary.pidfds.len() != 1 {
            return Err(ControllerError::Rejected(
                "exactly one SCM_RIGHTS memfd and one kernel SCM_PIDFD are required",
            ));
        }
        let mut rights = ancillary.rights;
        let mut pidfds = ancillary.pidfds;
        let memfd = rights.pop().unwrap();
        let pidfd = pidfds.pop().unwrap();
        let peer = socket_peer(socket)?;
        let pidfd_identity = pidfd_identity(pidfd.as_raw_fd())?;
        let peer_start_time_ticks = proc_start_time_ticks(peer.pid)?;
        Ok(ReceivedPacket {
            frame,
            memfd,
            pidfd,
            peer,
            pidfd_identity,
            peer_start_time_ticks,
        })
    }

    struct AncillaryOwnership {
        rights: Vec<OwnedFd>,
        pidfds: Vec<OwnedFd>,
        invalid: bool,
    }

    fn own_all_descriptors(message: &libc::msghdr) -> AncillaryOwnership {
        let mut output = AncillaryOwnership {
            rights: Vec::new(),
            pidfds: Vec::new(),
            invalid: false,
        };
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(message);
            while !header.is_null() {
                let minimum = libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_len < minimum {
                    output.invalid = true;
                    break;
                }
                let data_bytes = (*header).cmsg_len - minimum;
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && ((*header).cmsg_type == libc::SCM_RIGHTS
                        || (*header).cmsg_type == SCM_PIDFD_VALUE)
                {
                    if data_bytes == 0 || data_bytes % mem::size_of::<RawFd>() != 0 {
                        output.invalid = true;
                    }
                    let count = data_bytes / mem::size_of::<RawFd>();
                    let data = libc::CMSG_DATA(header) as *const RawFd;
                    for index in 0..count {
                        let raw = std::ptr::read_unaligned(data.add(index));
                        if raw < 0 {
                            output.invalid = true;
                            continue;
                        }
                        let owned = OwnedFd::from_raw_fd(raw);
                        if (*header).cmsg_type == libc::SCM_RIGHTS {
                            output.rights.push(owned);
                        } else {
                            output.pidfds.push(owned);
                        }
                    }
                } else {
                    output.invalid = true;
                }
                header = libc::CMSG_NXTHDR(message, header);
            }
        }
        output
    }

    fn socket_peer(socket: RawFd) -> Result<libc::ucred> {
        let mut peer = MaybeUninit::<libc::ucred>::uninit();
        let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr() as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || length as usize != mem::size_of::<libc::ucred>()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { peer.assume_init() })
    }

    fn pidfd_identity(pidfd: RawFd) -> Result<String> {
        let contents = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}"))?;
        let pid = contents
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t"))
            .ok_or(ControllerError::Invalid("pidfd has no kernel PID identity"))?;
        Ok(format!("pid:{pid}"))
    }

    fn proc_start_time_ticks(pid: libc::pid_t) -> Result<u64> {
        let bytes = read_bounded_file(Path::new(&format!("/proc/{pid}/stat")), 64 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Rejected("process stat is not UTF-8"))?;
        let close = text
            .rfind(')')
            .ok_or(ControllerError::Rejected("process stat has no comm terminator"))?;
        text[close + 1..]
            .split_ascii_whitespace()
            .nth(19)
            .ok_or(ControllerError::Rejected("process stat lacks start time"))?
            .parse::<u64>()
            .map_err(|_| ControllerError::Rejected("process start time is invalid"))
    }

    fn proc_parent_pid(pid: libc::pid_t) -> Result<libc::pid_t> {
        let bytes =
            read_bounded_file(Path::new(&format!("/proc/{pid}/stat")), 64 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Rejected("process stat is not UTF-8"))?;
        let close = text
            .rfind(')')
            .ok_or(ControllerError::Rejected(
                "process stat has no comm terminator",
            ))?;
        text[close + 1..]
            .split_ascii_whitespace()
            .nth(1)
            .ok_or(ControllerError::Rejected(
                "process stat lacks parent PID",
            ))?
            .parse::<libc::pid_t>()
            .map_err(|_| ControllerError::Rejected(
                "process parent PID is invalid",
            ))
    }

    fn pidfd_poll_live(pidfd: RawFd) -> Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(result == 0
            && descriptor.revents
                & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                == 0)
    }

    fn verify_sealed_memfd(fd: RawFd, expected_len: u64) -> Result<()> {
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if seals < 0 || seals & required != required {
            return Err(ControllerError::Rejected("payload is not a fully sealed memfd"));
        }
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_size < 0 || stat.st_size as u64 != expected_len || stat.st_nlink != 0 {
            return Err(ControllerError::Rejected("memfd identity or length mismatch"));
        }
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
        if !target.as_os_str().as_bytes().starts_with(b"/memfd:") {
            return Err(ControllerError::Rejected("payload descriptor is not a memfd"));
        }
        Ok(())
    }

    fn duplicate_fd(fd: RawFd) -> Result<OwnedFd> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    fn digest_memfd(fd: RawFd, length: u64) -> Result<Digest> {
        let mut file = File::from(duplicate_fd(fd)?);
        file.seek(SeekFrom::Start(0))?;
        sha256_exact_reader(&mut file, length)
    }

    fn pread_exact(fd: RawFd, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let count = unsafe {
                libc::pread(
                    fd,
                    bytes[offset..].as_mut_ptr() as *mut libc::c_void,
                    bytes.len() - offset,
                    offset as libc::off_t,
                )
            };
            if count <= 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            offset += count as usize;
        }
        Ok(())
    }

    fn read_memfd_bounded(
        memfd: OwnedFd,
        length: u64,
        maximum: u64,
    ) -> Result<Vec<u8>> {
        if length == 0 || length > maximum || length > usize::MAX as u64 {
            return Err(ControllerError::Rejected(
                "sealed memfd length exceeds the canonical v11 bound",
            ));
        }
        let mut file = File::from(memfd);
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(length).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length {
            return Err(ControllerError::Invalid(
                "sealed canonical memfd is truncated",
            ));
        }
        Ok(bytes)
    }

    fn create_sealed_memfd(name: &str, bytes: &[u8]) -> Result<OwnedFd> {
        let name =
            CString::new(name).map_err(|_| ControllerError::Invalid("memfd name has NUL"))?;
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let memfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut duplicate = File::from(duplicate_fd(memfd.as_raw_fd())?);
        duplicate.write_all(bytes)?;
        duplicate.flush()?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(memfd)
    }

    fn binding_for_self() -> Result<Digest> {
        let pid = unsafe { libc::getpid() };
        let pidfd = pidfd_open(pid)?;
        let identity = pidfd_identity(pidfd.as_raw_fd())?;
        Ok(peer_binding(
            pid as u32,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &identity,
        ))
    }

    fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn send_frame_with_memfd(
        socket: RawFd,
        frame: &[u8; FIXED_FRAME_BYTES],
        memfd: RawFd,
    ) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        let mut control = AlignedControl::zeroed();
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as libc::c_uint) as usize };
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(ControllerError::Invalid("cannot construct SCM_RIGHTS"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(mem::size_of::<RawFd>() as libc::c_uint) as usize;
            *(libc::CMSG_DATA(header) as *mut RawFd) = memfd;
            if libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
                != FIXED_FRAME_BYTES as isize
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    fn poll_for(fd: RawFd, events: libc::c_short, timeout_ms: u64) -> Result<()> {
        let end = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or(ControllerError::Rejected("transport timeout overflow"))?;
        loop {
            let now = Instant::now();
            if now >= end {
                return Err(ControllerError::Rejected("transport poll timed out"));
            }
            let remaining = end.duration_since(now).as_millis().max(1);
            let mut pollfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let timeout = remaining.min(i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if result != 1
                || pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                || pollfd.revents & events == 0
            {
                return Err(ControllerError::Rejected(
                    "transport poll failed or timed out",
                ));
            }
            return Ok(());
        }
    }

    fn poll_until_deadline(
        fd: RawFd,
        events: libc::c_short,
        deadline_unix_ms: u64,
    ) -> Result<()> {
        loop {
            let now = now_unix_ms()?;
            if deadline_unix_ms <= now {
                return Err(ControllerError::Rejected("transport deadline expired"));
            }
            match poll_for(fd, events, deadline_unix_ms - now) {
                Ok(()) => return Ok(()),
                Err(ControllerError::Io(error))
                    if error.raw_os_error() == Some(libc::EINTR) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        generation: u64,
        mode: u32,
        owner_uid: u32,
        size: u64,
    }

    struct FixedLaunchPlan {
        plan: Plan,
        executable_path: PathBuf,
        executable_opath: OwnedFd,
        executable_read: OwnedFd,
        executable_identity: FileIdentity,
        executable_sha256: Digest,
        cwd_path: PathBuf,
        cwd_fd: OwnedFd,
        cwd_identity: FileIdentity,
        argv: Vec<CString>,
        env: Vec<CString>,
        executable_closure: Vec<ExecutableClosureMember>,
        executable_closure_sha256: Digest,
        sandbox_profile_sha256: Digest,
        configuration_sha256: Digest,
        command_identity_sha256: Digest,
    }

    struct ExecutableClosureMember {
        path: PathBuf,
        executable: bool,
        opath: OwnedFd,
        read: OwnedFd,
        identity: FileIdentity,
        content_sha256: Digest,
    }

    struct HostLaunchRootGuard {
        path: PathBuf,
        cleaned: bool,
    }

    impl HostLaunchRootGuard {
        fn new(pid: libc::pid_t, command_identity_sha256: Digest) -> Self {
            let launch_id = command_identity_sha256
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            Self {
                path: PathBuf::from(format!(
                    "/run/catchplate/controller-launch-root-{pid}-{launch_id}",
                )),
                cleaned: false,
            }
        }

        fn cleanup(&mut self) -> Result<()> {
            match std::fs::symlink_metadata(&self.path) {
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    self.cleaned = true;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
                Ok(metadata)
                    if metadata.file_type().is_dir()
                        && metadata.uid() == 0
                        && metadata.mode() & 0o022 == 0 => {}
                Ok(_) => {
                    return Err(ControllerError::Rejected(
                        "host launch root identity is unsafe",
                    ))
                }
            }
            std::fs::remove_dir(&self.path)?;
            self.cleaned = true;
            Ok(())
        }
    }

    impl Drop for HostLaunchRootGuard {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = std::fs::remove_dir(&self.path);
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TreeManifestEntry {
        relative_path: Vec<u8>,
        kind: u8,
        device: u64,
        inode: u64,
        generation: u64,
        size: u64,
        mode: u32,
        owner_uid: u32,
        owner_gid: u32,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
        content_sha256: Digest,
    }

    #[derive(Clone)]
    struct CanonicalTreeManifest {
        root: PathBuf,
        entries: Vec<TreeManifestEntry>,
        manifest_sha256: Digest,
    }

    #[derive(Clone)]
    struct CachedTreeManifest {
        fanotify_generation: u64,
        manifest: CanonicalTreeManifest,
    }

    struct FanotifyDriftTracker {
        descriptor: OwnedFd,
        sequence: AtomicU64,
        roots: Mutex<BTreeMap<PathBuf, u64>>,
        drain_lock: Mutex<()>,
    }

    impl FanotifyDriftTracker {
        fn new(roots: &[PathBuf]) -> Result<Self> {
            let raw = unsafe {
                libc::fanotify_init(
                    (libc::FAN_CLOEXEC
                        | libc::FAN_NONBLOCK
                        | libc::FAN_CLASS_NOTIF) as libc::c_uint,
                    (libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_LARGEFILE) as libc::c_uint,
                )
            };
            if raw < 0 {
                return Err(ControllerError::Unready(vec![format!(
                    "fanotify initialization failed: {}",
                    std::io::Error::last_os_error(),
                )]));
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            let mask = libc::FAN_CLOSE_WRITE
                | libc::FAN_CREATE
                | libc::FAN_DELETE
                | libc::FAN_MOVED_FROM
                | libc::FAN_MOVED_TO
                | libc::FAN_ATTRIB
                | libc::FAN_DELETE_SELF
                | libc::FAN_MOVE_SELF;
            let mut marked_devices = BTreeSet::new();
            for root in roots {
                validate_absolute_normalized_path(root)?;
                let metadata = std::fs::metadata(root)?;
                if !metadata.is_dir() {
                    return Err(ControllerError::Rejected(
                        "fanotify root is not a directory",
                    ));
                }
                if !marked_devices.insert(metadata.dev()) {
                    continue;
                }
                let root_c = CString::new(root.as_os_str().as_bytes())
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "fanotify root contains NUL",
                        )
                    })?;
                if unsafe {
                    libc::fanotify_mark(
                        descriptor.as_raw_fd(),
                        (libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT)
                            as libc::c_uint,
                        mask,
                        libc::AT_FDCWD,
                        root_c.as_ptr(),
                    )
                } != 0
                {
                    return Err(ControllerError::Unready(vec![format!(
                        "fanotify mount mark failed for {}: {}",
                        root.display(),
                        std::io::Error::last_os_error(),
                    )]));
                }
            }
            Ok(Self {
                descriptor,
                sequence: AtomicU64::new(1),
                roots: Mutex::new(
                    roots
                        .iter()
                        .cloned()
                        .map(|root| (root, 1))
                        .collect(),
                ),
                drain_lock: Mutex::new(()),
            })
        }

        fn current_generation(&self, root: &Path) -> Result<u64> {
            let _drain = self.drain_lock.lock().map_err(|_| {
                ControllerError::Unready(vec![
                    "fanotify drain lock is poisoned".to_owned(),
                ])
            })?;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = unsafe {
                    libc::read(
                        self.descriptor.as_raw_fd(),
                        buffer.as_mut_ptr() as *mut libc::c_void,
                        buffer.len(),
                    )
                };
                if count > 0 {
                    self.attribute_fanotify_events(
                        &buffer[..count as usize],
                    )?;
                    continue;
                }
                if count == 0 {
                    return Err(ControllerError::Unready(vec![
                        "fanotify descriptor closed unexpectedly".to_owned(),
                    ]));
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
                ) {
                    break;
                }
                return Err(error.into());
            }
            let generations = self.roots.lock().map_err(|_| {
                ControllerError::Unready(vec![
                    "fanotify root generation lock is poisoned"
                        .to_owned(),
                ])
            })?;
            generations
                .iter()
                .filter(|(tracked, _)| {
                    root == tracked.as_path() || root.starts_with(tracked)
                })
                .max_by_key(|(tracked, _)| {
                    tracked.components().count()
                })
                .map(|(_, generation)| *generation)
                .ok_or(ControllerError::Rejected(
                    "tree observer root is outside fanotify tracking",
                ))
        }

        fn attribute_fanotify_events(&self, bytes: &[u8]) -> Result<()> {
            const METADATA_BYTES: usize = 24;
            const METADATA_VERSION: u8 = 3;
            const FAN_NOFD: i32 = -1;
            let mut cursor = 0usize;
            let mut changed = BTreeSet::new();
            let mut invalidate_all = false;
            while cursor < bytes.len() {
                let header = bytes
                    .get(cursor..cursor + METADATA_BYTES)
                    .ok_or(ControllerError::Rejected(
                        "fanotify event metadata is truncated",
                    ))?;
                let event_len = u32::from_ne_bytes(
                    header[0..4].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "invalid fanotify event length",
                        )
                    })?,
                ) as usize;
                let metadata_len = u16::from_ne_bytes(
                    header[6..8].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "invalid fanotify metadata length",
                        )
                    })?,
                ) as usize;
                let mask = u64::from_ne_bytes(
                    header[8..16].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "invalid fanotify event mask",
                        )
                    })?,
                );
                let event_fd = i32::from_ne_bytes(
                    header[16..20].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "invalid fanotify event descriptor",
                        )
                    })?,
                );
                if header[4] != METADATA_VERSION
                    || header[5] != 0
                    || event_len < METADATA_BYTES
                    || metadata_len != METADATA_BYTES
                    || cursor
                        .checked_add(event_len)
                        .is_none_or(|end| end > bytes.len())
                {
                    if event_fd >= 0 {
                        unsafe {
                            libc::close(event_fd);
                        }
                    }
                    return Err(ControllerError::Rejected(
                        "fanotify event metadata is noncanonical",
                    ));
                }
                if mask & libc::FAN_Q_OVERFLOW != 0
                    || event_fd == FAN_NOFD
                {
                    invalidate_all = true;
                } else if event_fd >= 0 {
                    let path = std::fs::read_link(format!(
                        "/proc/self/fd/{event_fd}",
                    ));
                    unsafe {
                        libc::close(event_fd);
                    }
                    match path {
                        Ok(path) => {
                            changed.insert(path);
                        }
                        Err(_) => invalidate_all = true,
                    }
                }
                cursor += event_len;
            }
            let generation =
                self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
            let mut roots = self.roots.lock().map_err(|_| {
                ControllerError::Unready(vec![
                    "fanotify root generation lock is poisoned"
                        .to_owned(),
                ])
            })?;
            if invalidate_all {
                for value in roots.values_mut() {
                    *value = generation;
                }
                return Ok(());
            }
            for changed_path in changed {
                let mut attributed = false;
                for (tracked, value) in roots.iter_mut() {
                    if changed_path == *tracked
                        || changed_path.starts_with(tracked)
                    {
                        *value = generation;
                        attributed = true;
                    }
                }
                if !attributed {
                    for value in roots.values_mut() {
                        *value = generation;
                    }
                }
            }
            Ok(())
        }
    }

    struct StateStore {
        root: OwnedFd,
        acceptance: OwnedFd,
        builds: OwnedFd,
        evidence: OwnedFd,
        orphan_journal: OwnedFd,
        root_path: PathBuf,
    }

    struct CgroupRoot {
        directory: OwnedFd,
        path: PathBuf,
    }

    struct TrustedHostProduction {
        config_sha256: Digest,
        source_root: PathBuf,
        source_root_fd: OwnedFd,
        source_root_identity_sha256: Digest,
        state: StateStore,
        cgroup: CgroupRoot,
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
        requester_verifying_key: VerifyingKey,
        final_verdict_verifying_key: VerifyingKey,
        key_id_sha256: Digest,
        requester_key_id_sha256: Digest,
        launcher_opath: OwnedFd,
        launcher_read: OwnedFd,
        launcher_identity: FileIdentity,
        launcher_sha256: Digest,
        plans: BTreeMap<Plan, FixedLaunchPlan>,
        deadlines_ms: BTreeMap<Plan, u64>,
        artifact_paths: Vec<PathBuf>,
        denied_socket_paths: Vec<PathBuf>,
        trusted_plan_table_sha256: Digest,
        trusted_plan_manifest_sha256: Digest,
        provider_measurement_sha256: Digest,
        attestation_scope_measurement_sha256: Digest,
        daemon_executable_sha256: Digest,
        controller_process_identity_sha256: Digest,
        frontend_pid: libc::pid_t,
        frontend_pidfd: OwnedFd,
        orphan_journal_identity_sha256: Digest,
        boot_id_sha256: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
        readiness_uid: u32,
        readiness_gid: u32,
        action_counter: AtomicU64,
        readiness: Arc<ReadinessState>,
        execution_lock: Mutex<()>,
        queued_executions: AtomicUsize,
        maximum_queued_executions: usize,
        tree_manifest_cache:
            Mutex<BTreeMap<PathBuf, CachedTreeManifest>>,
        tree_drift_tracker: FanotifyDriftTracker,
        io_deadline: Mutex<Option<Instant>>,
        cleanup_reserve_deadline: Mutex<Option<Instant>>,
        quarantine_active: AtomicBool,
        plan_capabilities:
            Mutex<BTreeMap<Digest, PlanCapabilityLease>>,
    }

    struct PlanCapabilityLease {
        record: PlanCapabilityRecordV11,
        peer_uid: u32,
        peer_gid: u32,
    }

    impl TrustedHostBroker {
        fn spawn(
            production: TrustedHostProduction,
            readiness: Arc<ReadinessState>,
        ) -> Result<Self> {
            let mut channels = [-1; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    channels.as_mut_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let parent_channel = unsafe { OwnedFd::from_raw_fd(channels[0]) };
            let child_channel = unsafe { OwnedFd::from_raw_fd(channels[1]) };
            let requester_verifying_key =
                production.requester_verifying_key.clone();
            let receipt_verifying_key =
                production.verifying_key.clone();
            let final_verdict_verifying_key =
                production.final_verdict_verifying_key.clone();
            let ticket_signing_key = production.signing_key.clone();
            let internal_submission_signing_key =
                SigningKey::from_bytes(&random_digest_worker_only()?);
            let internal_submission_verifying_key =
                internal_submission_signing_key.verifying_key();
            let lane_deadlines_ms = production.deadlines_ms.clone();
            let config_sha256 = production.config_sha256;
            let daemon_identity_sha256 =
                production.controller_process_identity_sha256;
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if pid == 0 {
                drop(parent_channel);
                let code =
                    broker_execution_main(
                        child_channel.as_raw_fd(),
                        production,
                        internal_submission_verifying_key,
                    );
                unsafe { libc::_exit(code) };
            }
            drop(child_channel);
            let pidfd = pidfd_open(pid)?;
            if pidfd_identity(pidfd.as_raw_fd())? != format!("pid:{pid}") {
                let _ = signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
                let _ = reap_pid_bounded(
                    pid,
                    Instant::now() + Duration::from_secs(2),
                );
                return Err(ControllerError::Rejected(
                    "execution broker pidfd identity mismatch",
                ));
            }
            if let Err(error) = poll_for(
                parent_channel.as_raw_fd(),
                libc::POLLIN,
                5 * 60 * 1_000,
            ) {
                let _ = signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
                let _ = reap_pid_bounded(
                    pid,
                    Instant::now() + Duration::from_secs(2),
                );
                return Err(error);
            }
            let mut startup = [0u8; BROKER_RESPONSE_MAX_BYTES];
            let startup_count = match recv_seqpacket_exact_or_eof(
                parent_channel.as_raw_fd(),
                &mut startup,
            ) {
                Ok(count) => count,
                Err(error) => {
                    let _ =
                        signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
                    let _ = reap_pid_bounded(
                        pid,
                        Instant::now() + Duration::from_secs(2),
                    );
                    return Err(error);
                }
            };
            if startup_count < 5 {
                let _ = signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
                let _ = reap_pid_bounded(
                    pid,
                    Instant::now() + Duration::from_secs(2),
                );
                return Err(ControllerError::Unready(vec![
                    "execution broker startup response is truncated"
                        .to_owned(),
                ]));
            }
            let startup_length = u32::from_be_bytes(
                startup[1..5]
                    .try_into()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "invalid broker startup response length",
                        )
                    })?,
            ) as usize;
            if startup_count != startup_length + 5
                || startup[0] != 0
                || startup_length != 0
            {
                let message = String::from_utf8_lossy(
                    startup.get(5..startup_count).unwrap_or_default(),
                )
                .into_owned();
                let _ = signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
                let _ = reap_pid_bounded(
                    pid,
                    Instant::now() + Duration::from_secs(2),
                );
                return Err(ControllerError::Unready(vec![format!(
                    "execution broker startup failed: {message}",
                )]));
            }
            Ok(Self {
                channel: Mutex::new(parent_channel),
                pid,
                pidfd,
                requester_verifying_key,
                receipt_verifying_key,
                final_verdict_verifying_key,
                ticket_signing_key,
                internal_submission_signing_key,
                lane_deadlines_ms,
                config_sha256,
                daemon_identity_sha256,
                readiness,
            })
        }

        fn execute(
            &self,
            submission: &ClientSubmission,
            frame: &PreallocationFrame,
            peer_binding_sha256: Digest,
            peer_start_time_ticks: u64,
            peer_uid: u32,
            peer_gid: u32,
        ) -> Result<Vec<u8>> {
            if !pidfd_poll_live(self.pidfd.as_raw_fd())? {
                let reason = format!(
                    "single-thread execution broker {} is not live",
                    self.pid
                );
                self.readiness.hard_unready(reason.clone());
                return Err(ControllerError::Unready(vec![reason]));
            }
            let mut channel = loop {
                if now_unix_ms()? >= frame.deadline_unix_ms {
                    return Err(ControllerError::Rejected(
                        "request expired before execution-broker admission",
                    ));
                }
                match self.channel.try_lock() {
                    Ok(channel) => break channel,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        let reason =
                            "execution-broker admission lock is poisoned";
                        self.readiness.hard_unready(reason);
                        return Err(ControllerError::Unready(vec![
                            reason.to_owned(),
                        ]));
                    }
                }
            };
            let mut request = [0u8; BROKER_REQUEST_BYTES];
            request[..FIXED_FRAME_BYTES].copy_from_slice(&frame.encode());
            let submission_offset = FIXED_FRAME_BYTES;
            request[submission_offset
                ..submission_offset + ClientSubmission::ENCODED_BYTES]
                .copy_from_slice(&submission.encode());
            let binding_offset =
                submission_offset + ClientSubmission::ENCODED_BYTES;
            request[binding_offset..binding_offset + 32]
                .copy_from_slice(&peer_binding_sha256);
            request[binding_offset + 32..binding_offset + 40]
                .copy_from_slice(&peer_start_time_ticks.to_be_bytes());
            request[binding_offset + 40..binding_offset + 44]
                .copy_from_slice(&peer_uid.to_be_bytes());
            request[binding_offset + 44..binding_offset + 48]
                .copy_from_slice(&peer_gid.to_be_bytes());
            send_seqpacket_exact(channel.as_raw_fd(), &request)?;
            poll_until_deadline(
                channel.as_raw_fd(),
                libc::POLLIN,
                frame.deadline_unix_ms,
            )?;
            let mut response = [0u8; BROKER_RESPONSE_MAX_BYTES];
            let count = recv_seqpacket_exact_or_eof(
                channel.as_raw_fd(),
                &mut response,
            )?;
            if count < 5 {
                let reason = "execution broker returned a truncated response";
                self.readiness.hard_unready(reason);
                return Err(ControllerError::Unready(vec![
                    reason.to_owned(),
                ]));
            }
            let length = u32::from_be_bytes(
                response[1..5]
                    .try_into()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "invalid broker response length",
                        )
                    })?,
            ) as usize;
            if length > BROKER_RESPONSE_MAX_BYTES - 5
                || count != length + 5
            {
                let reason =
                    "execution broker response length is noncanonical";
                self.readiness.hard_unready(reason);
                return Err(ControllerError::Unready(vec![
                    reason.to_owned(),
                ]));
            }
            let payload = &response[5..count];
            match response[0] {
                0 if payload.len() == SIGNED_CONTROLLER_RECEIPT_BYTES => {
                    Ok(payload.to_vec())
                }
                1 => Err(ControllerError::InvalidOwned(format!(
                    "single-thread execution broker rejected request: {}",
                    String::from_utf8_lossy(payload)
                ))),
                _ => {
                    let reason =
                        "execution broker returned an invalid typed response";
                    self.readiness.hard_unready(reason);
                    Err(ControllerError::Unready(vec![reason.to_owned()]))
                }
            }
        }
    }

    fn broker_execution_main(
        channel: RawFd,
        production: TrustedHostProduction,
        internal_submission_verifying_key: VerifyingKey,
    ) -> i32 {
        if unsafe {
            libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                1,
                0,
                0,
                0,
            )
        } != 0
        {
            return 125;
        }
        let mut broker_subreaper = 0;
        if unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &mut broker_subreaper as *mut libc::c_int,
                0,
                0,
                0,
            )
        } != 0
            || broker_subreaper != 1
        {
            return 125;
        }
        let production = Arc::new(production);
        let startup = (|| -> Result<()> {
            start_controller_plan_api(Arc::clone(&production))?;
            production.pre_ready_probe()
        })();
        let (startup_kind, startup_payload) = match startup {
            Ok(()) => (0u8, Vec::new()),
            Err(error) => {
                let mut message = error.to_string().into_bytes();
                message.truncate(BROKER_RESPONSE_MAX_BYTES - 5);
                (1u8, message)
            }
        };
        let mut startup_response = [0u8; BROKER_RESPONSE_MAX_BYTES];
        startup_response[0] = startup_kind;
        startup_response[1..5].copy_from_slice(
            &(startup_payload.len() as u32).to_be_bytes(),
        );
        startup_response[5..5 + startup_payload.len()]
            .copy_from_slice(&startup_payload);
        if send_seqpacket_exact(
            channel,
            &startup_response[..5 + startup_payload.len()],
        )
        .is_err()
        {
            return 125;
        }
        if startup_kind != 0 {
            return 125;
        }
        loop {
            let mut request = [0u8; BROKER_REQUEST_BYTES];
            let count = match recv_seqpacket_exact_or_eof(channel, &mut request) {
                Ok(0) => return 0,
                Ok(count) if count == BROKER_REQUEST_BYTES => count,
                _ => return 125,
            };
            if count != BROKER_REQUEST_BYTES {
                return 125;
            }
            let mut frame_bytes = [0u8; FIXED_FRAME_BYTES];
            frame_bytes.copy_from_slice(&request[..FIXED_FRAME_BYTES]);
            let result = (|| -> Result<Vec<u8>> {
                let frame = PreallocationFrame::decode(&frame_bytes)?;
                let submission_offset = FIXED_FRAME_BYTES;
                let submission_end =
                    submission_offset + ClientSubmission::ENCODED_BYTES;
                let submission = ClientSubmission::decode_and_verify(
                    &request[submission_offset..submission_end],
                    &internal_submission_verifying_key,
                    frame.deadline_unix_ms,
                    production.config_sha256,
                    frame.peer_binding_sha256,
                )?;
                let binding_offset = submission_end;
                let mut peer_binding_sha256 = [0u8; 32];
                peer_binding_sha256.copy_from_slice(
                    &request[binding_offset..binding_offset + 32],
                );
                let peer_start_time_ticks = u64::from_be_bytes(
                    request[binding_offset + 32..binding_offset + 40]
                        .try_into()
                        .map_err(|_| {
                            ControllerError::Invalid(
                                "invalid broker peer start time",
                            )
                        })?,
                );
                let peer_uid = u32::from_be_bytes(
                    request[binding_offset + 40..binding_offset + 44]
                        .try_into()
                        .map_err(|_| {
                            ControllerError::Invalid(
                                "invalid broker peer uid",
                            )
                        })?,
                );
                let peer_gid = u32::from_be_bytes(
                    request[binding_offset + 44..binding_offset + 48]
                        .try_into()
                        .map_err(|_| {
                            ControllerError::Invalid(
                                "invalid broker peer gid",
                            )
                        })?,
                );
                if frame.kind != FrameKind::Request
                    || frame.lane != Some(submission.lane)
                    || frame.request_id != submission.request_id
                    || frame.peer_binding_sha256 != peer_binding_sha256
                {
                    return Err(ControllerError::Rejected(
                        "broker request lost exact transport binding",
                    ));
                }
                production.execute(
                    &submission,
                    &frame,
                    peer_binding_sha256,
                    peer_start_time_ticks,
                    peer_uid,
                    peer_gid,
                )
            })();
            let mut response = [0u8; BROKER_RESPONSE_MAX_BYTES];
            let (kind, payload): (u8, Vec<u8>) = match result {
                Ok(receipt) => (0, receipt),
                Err(error) => {
                    let mut message = error.to_string().into_bytes();
                    message.truncate(BROKER_RESPONSE_MAX_BYTES - 5);
                    (1, message)
                }
            };
            response[0] = kind;
            response[1..5]
                .copy_from_slice(&(payload.len() as u32).to_be_bytes());
            response[5..5 + payload.len()].copy_from_slice(&payload);
            if send_seqpacket_exact(channel, &response[..5 + payload.len()])
                .is_err()
            {
                return 125;
            }
        }
    }

    fn start_controller_plan_api(
        production: Arc<TrustedHostProduction>,
    ) -> Result<()> {
        let listener = bind_plain_seqpacket_socket(
            Path::new(CONTROLLER_PLAN_API_SOCKET_PATH),
            0,
            production.readiness_gid,
            0o660,
            8,
        )?;
        let readiness = Arc::clone(&production.readiness);
        std::thread::Builder::new()
            .name("catchplate-controller-plan-api".to_owned())
            .spawn(move || loop {
                let connection = match accept_plain_seqpacket(
                    listener.as_raw_fd(),
                ) {
                    Ok(connection) => connection,
                    Err(error) => {
                        readiness.hard_unready(format!(
                            "controller plan API accept failed: {error}",
                        ));
                        return;
                    }
                };
                if let Err(error) =
                    serve_controller_plan_api(connection, &production)
                {
                    eprintln!(
                        "{PROTOCOL_NAME}: plan API request rejected: {error}",
                    );
                }
            })
            .map_err(ControllerError::Io)?;
        Ok(())
    }

    fn serve_controller_plan_api(
        connection: OwnedFd,
        production: &TrustedHostProduction,
    ) -> Result<()> {
        let mut bytes = [0u8; PLAN_API_REQUEST_BYTES];
        let count = unsafe {
            libc::recv(
                connection.as_raw_fd(),
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                libc::MSG_TRUNC,
            )
        };
        if count != PLAN_API_REQUEST_BYTES as isize {
            return Err(ControllerError::Rejected(
                "plan API request is not one exact bounded packet",
            ));
        }
        let request = PlanApiRequestV11::decode(&bytes)?;
        let peer = socket_peer(connection.as_raw_fd())?;
        let peer_pidfd = pidfd_open(peer.pid)?;
        let peer_start = proc_start_time_ticks(peer.pid)?;
        if !pidfd_poll_live(peer_pidfd.as_raw_fd())?
            || proc_start_time_ticks(peer.pid)? != peer_start
            || now_unix_ms()? >= request.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "plan API peer or request deadline is not live",
            ));
        }
        let lease = production.consume_plan_capability(
            &request,
            peer.uid,
            peer.gid,
        )?;
        let response = match relay_plan_to_controller_proxy(
            &request,
            &lease.record,
        ) {
            Ok(response) => response,
            Err(error) => PlanApiResponseV11::new(
                request.lane,
                request.request_sha256,
                request.request_nonce,
                production.controller_process_identity_sha256,
                sha256(error.to_string().as_bytes()),
                125,
            )?,
        };
        if response.lane != request.lane
            || response.request_sha256 != request.request_sha256
            || response.request_nonce != request.request_nonce
            || response.daemon_identity_sha256
                != production.controller_process_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "controller proxy response lost its exact plan binding",
            ));
        }
        send_seqpacket_exact(connection.as_raw_fd(), &response.encode())
    }

    fn relay_plan_to_controller_proxy(
        request: &PlanApiRequestV11,
        capability: &PlanCapabilityRecordV11,
    ) -> Result<PlanApiResponseV11> {
        let proxy = connect_plain_root_seqpacket(
            Path::new(CONTROLLER_PLAN_EXECUTOR_SOCKET_PATH),
            request.deadline_unix_ms,
        )?;
        let mut packet = [0u8; PLAN_PROXY_REQUEST_BYTES];
        packet[..PLAN_API_REQUEST_BYTES]
            .copy_from_slice(&request.encode());
        packet[PLAN_API_REQUEST_BYTES..]
            .copy_from_slice(&capability.encode());
        send_seqpacket_exact(proxy.as_raw_fd(), &packet)?;
        poll_until_deadline(
            proxy.as_raw_fd(),
            libc::POLLIN,
            request.deadline_unix_ms,
        )?;
        let mut response = [0u8; PLAN_API_RESPONSE_BYTES];
        let count = unsafe {
            libc::recv(
                proxy.as_raw_fd(),
                response.as_mut_ptr() as *mut libc::c_void,
                response.len(),
                libc::MSG_TRUNC,
            )
        };
        if count != PLAN_API_RESPONSE_BYTES as isize {
            return Err(ControllerError::Rejected(
                "controller Docker proxy returned a noncanonical packet",
            ));
        }
        let peer = socket_peer(proxy.as_raw_fd())?;
        let peer_pidfd = pidfd_open(peer.pid)?;
        let peer_start = proc_start_time_ticks(peer.pid)?;
        if peer.uid != 0
            || peer.gid != 0
            || !pidfd_poll_live(peer_pidfd.as_raw_fd())?
            || proc_start_time_ticks(peer.pid)? != peer_start
        {
            return Err(ControllerError::Rejected(
                "controller Docker proxy peer is not one live root process",
            ));
        }
        PlanApiResponseV11::decode(&response)
    }

    fn bind_plain_seqpacket_socket(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        backlog: libc::c_int,
    ) -> Result<OwnedFd> {
        validate_absolute_normalized_path(path)?;
        let parent = path.parent().ok_or(ControllerError::Invalid(
            "plain socket path has no parent",
        ))?;
        verify_socket_ancestor_chain(parent)?;
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(ControllerError::Rejected(
                    "controller refuses to replace an existing plain socket",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
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
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.len() >= address.sun_path.len() {
            return Err(ControllerError::Invalid(
                "plain socket path is too long",
            ));
        }
        for (destination, source) in
            address.sun_path.iter_mut().zip(path_bytes)
        {
            *destination = *source as libc::c_char;
        }
        let length = (mem::size_of::<libc::sa_family_t>()
            + path_bytes.len()
            + 1) as libc::socklen_t;
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let path_c = CString::new(path_bytes).map_err(|_| {
            ControllerError::Invalid("plain socket path contains NUL")
        })?;
        if unsafe { libc::chown(path_c.as_ptr(), uid, gid) } != 0
            || unsafe { libc::chmod(path_c.as_ptr(), mode) } != 0
            || unsafe { libc::listen(socket.as_raw_fd(), backlog) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.gid() != gid
            || metadata.mode() & 0o777 != mode
        {
            return Err(ControllerError::Rejected(
                "plain socket ownership or mode differs",
            ));
        }
        Ok(socket)
    }

    fn accept_plain_seqpacket(listener: RawFd) -> Result<OwnedFd> {
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

    fn connect_plain_root_seqpacket(
        path: &Path,
        deadline_unix_ms: u64,
    ) -> Result<OwnedFd> {
        validate_absolute_normalized_path(path)?;
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET
                    | libc::SOCK_CLOEXEC
                    | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.len() >= address.sun_path.len() {
            return Err(ControllerError::Invalid(
                "plain root socket path is too long",
            ));
        }
        for (destination, source) in
            address.sun_path.iter_mut().zip(path_bytes)
        {
            *destination = *source as libc::c_char;
        }
        let length = (mem::size_of::<libc::sa_family_t>()
            + path_bytes.len()
            + 1) as libc::socklen_t;
        if unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error.into());
            }
            poll_until_deadline(
                socket.as_raw_fd(),
                libc::POLLOUT,
                deadline_unix_ms,
            )?;
            let mut pending = 0;
            let mut pending_length =
                mem::size_of::<libc::c_int>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut pending as *mut libc::c_int
                        as *mut libc::c_void,
                    &mut pending_length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if pending != 0 {
                return Err(
                    std::io::Error::from_raw_os_error(pending).into(),
                );
            }
        }
        let peer = socket_peer(socket.as_raw_fd())?;
        if peer.uid != 0 || peer.gid != 0 {
            return Err(ControllerError::Rejected(
                "plain root socket peer credentials differ",
            ));
        }
        Ok(socket)
    }

    fn send_seqpacket_exact(fd: RawFd, bytes: &[u8]) -> Result<()> {
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

    fn recv_seqpacket_exact_or_eof(
        fd: RawFd,
        bytes: &mut [u8],
    ) -> Result<usize> {
        let count = unsafe {
            libc::recv(
                fd,
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                libc::MSG_TRUNC,
            )
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if count as usize > bytes.len() {
            return Err(ControllerError::Rejected(
                "execution broker packet exceeded its fixed bound",
            ));
        }
        Ok(count as usize)
    }

    impl TrustedHostProduction {
        fn construct(
            transport: &ImmutableControllerConfig,
            settings: TrustedHostSettings,
            readiness: Arc<ReadinessState>,
        ) -> Result<Self> {
            if transport.socket_path != PathBuf::from(DEFAULT_SOCKET_PATH) {
                return Err(ControllerError::Rejected(
                    "trusted-host socket path must match the fixed v11 client path",
                ));
            }
            if settings.public_key_path != PathBuf::from(RECEIPT_PUBLIC_KEY_PATH) {
                return Err(ControllerError::Rejected(
                    "trusted-host public key path must match the fixed v11 client trust anchor",
                ));
            }
            if settings.requester_public_key_path
                != PathBuf::from(REQUESTER_PUBLIC_KEY_PATH)
            {
                return Err(ControllerError::Rejected(
                    "requester public key path must match the fixed v11 trust anchor",
                ));
            }
            if settings.final_verdict_public_key_path
                != PathBuf::from(FINAL_VERDICT_PUBLIC_KEY_PATH)
            {
                return Err(ControllerError::Rejected(
                    "final-verdict public key path must match the fixed v11 trust anchor",
                ));
            }
            if transport.allowed_uids.contains(&0) || transport.allowed_gids.contains(&0) {
                return Err(ControllerError::Rejected(
                    "trusted-host production cannot authorize root UID or root GID workloads",
                ));
            }
            let readiness_uid = *transport
                .allowed_uids
                .iter()
                .next()
                .ok_or(ControllerError::Rejected(
                    "trusted-host readiness lacks an authorized UID",
                ))?;
            let readiness_gid = *transport
                .allowed_gids
                .iter()
                .next()
                .ok_or(ControllerError::Rejected(
                    "trusted-host readiness lacks an authorized GID",
                ))?;
            validate_absolute_normalized_path(&settings.state_dir)?;
            validate_absolute_normalized_path(&settings.source_root)?;
            validate_absolute_normalized_path(&settings.cgroup_root)?;
            let state = StateStore::open(&settings.state_dir)?;
            let orphan_journal_identity = directory_identity(
                state.orphan_journal.as_raw_fd(),
            )?;
            let orphan_journal_identity_sha256 = identity_digest(
                b"orphan-journal",
                &settings.state_dir.join("orphan-journal"),
                &orphan_journal_identity,
            );
            let source_root_fd = open_canonical_directory(&settings.source_root, false)?;
            let source_identity = directory_identity(source_root_fd.as_raw_fd())?;
            let source_root_identity_sha256 =
                identity_digest(b"source-root", &settings.source_root, &source_identity);
            let cgroup_directory = open_canonical_directory(&settings.cgroup_root, false)?;
            verify_root_owned_directory(cgroup_directory.as_raw_fd(), false)?;
            let cgroup = CgroupRoot {
                directory: cgroup_directory,
                path: settings.cgroup_root.clone(),
            };
            let boot_id = read_bounded_file(
                Path::new("/proc/sys/kernel/random/boot_id"),
                128,
            )?;
            if boot_id.is_empty() {
                return Err(ControllerError::Rejected(
                    "kernel boot identity is unavailable",
                ));
            }
            let boot_id_sha256 = sha256(&boot_id);

            let mut signing_bytes =
                read_immutable_root_file(&settings.signing_key_path, 32, true)?;
            let public_bytes =
                read_immutable_root_file(&settings.public_key_path, 32, false)?;
            if signing_bytes.len() != 32 || public_bytes.len() != 32 {
                return Err(ControllerError::Rejected(
                    "Ed25519 key files must contain exactly 32 raw bytes",
                ));
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&signing_bytes);
            let signing_key = SigningKey::from_bytes(&secret);
            secret.fill(0);
            signing_bytes.fill(0);
            let mut public = [0u8; 32];
            public.copy_from_slice(&public_bytes);
            let verifying_key = VerifyingKey::from_bytes(&public)
                .map_err(|_| ControllerError::Rejected("invalid Ed25519 public key"))?;
            if signing_key.verifying_key().as_bytes() != verifying_key.as_bytes() {
                return Err(ControllerError::Rejected(
                    "raw signing key does not match configured public key",
                ));
            }
            let key_id_sha256 = sha256(verifying_key.as_bytes());
            let requester_public_bytes = read_immutable_root_file(
                &settings.requester_public_key_path,
                32,
                false,
            )?;
            let mut requester_public = [0u8; 32];
            requester_public.copy_from_slice(&requester_public_bytes);
            let requester_verifying_key =
                VerifyingKey::from_bytes(&requester_public).map_err(|_| {
                    ControllerError::Rejected(
                        "invalid requester Ed25519 public key",
                    )
                })?;
            let requester_key_id_sha256 =
                sha256(requester_verifying_key.as_bytes());
            let final_verdict_public_bytes = read_immutable_root_file(
                &settings.final_verdict_public_key_path,
                32,
                false,
            )?;
            let mut final_verdict_public = [0u8; 32];
            final_verdict_public
                .copy_from_slice(&final_verdict_public_bytes);
            let final_verdict_verifying_key =
                VerifyingKey::from_bytes(&final_verdict_public).map_err(
                    |_| {
                        ControllerError::Rejected(
                            "invalid final-verdict Ed25519 public key",
                        )
                    },
                )?;
            if final_verdict_verifying_key.as_bytes()
                == requester_verifying_key.as_bytes()
                || final_verdict_verifying_key.as_bytes()
                    == verifying_key.as_bytes()
            {
                return Err(ControllerError::Rejected(
                    "final-verdict, requester, and receipt keys must be distinct",
                ));
            }
            let launcher_path = Path::new(LAUNCHER_INSTALL_PATH);
            let launcher_opath =
                open_canonical_path(launcher_path, libc::O_PATH, false)?;
            let launcher_read =
                open_canonical_path(launcher_path, libc::O_RDONLY, false)?;
            let launcher_identity =
                regular_file_identity(launcher_read.as_raw_fd(), true)?;
            require_immutable_closure_file(launcher_read.as_raw_fd())?;
            require_static_elf(launcher_read.as_raw_fd())?;
            let launcher_opath_identity =
                regular_file_identity_with_generation(
                    launcher_opath.as_raw_fd(),
                    true,
                    launcher_identity.generation,
                )?;
            if launcher_opath_identity != launcher_identity {
                return Err(ControllerError::Rejected(
                    "controller launcher O_PATH/read identities disagree",
                ));
            }
            let launcher_sha256 = digest_regular_fd(
                launcher_read.as_raw_fd(),
                launcher_identity.size,
            )?;

            let mut artifact_paths = Vec::new();
            for path in settings.artifact_paths {
                validate_absolute_normalized_path(&path)?;
                if path.starts_with(&settings.source_root)
                    || settings.source_root.starts_with(&path)
                {
                    return Err(ControllerError::Rejected(
                        "artifact path must not overlap the read-only source_root",
                    ));
                }
                artifact_paths.push(path);
            }
            artifact_paths.sort();
            let mut drift_roots = vec![settings.source_root.clone()];
            drift_roots.extend(artifact_paths.iter().cloned());
            drift_roots.push(state.root_path.clone());
            let tree_drift_tracker =
                FanotifyDriftTracker::new(&drift_roots)?;

            let mut denied = BTreeSet::new();
            for path in MANDATORY_DENIED_SOCKET_PATHS {
                denied.insert(PathBuf::from(path));
            }
            for path in settings.denied_socket_paths {
                validate_absolute_normalized_path(&path)?;
                denied.insert(path);
            }
            let denied_socket_paths: Vec<PathBuf> = denied.into_iter().collect();

            let mut plans = BTreeMap::new();
            for (plan, specification) in settings.plans {
                plans.insert(plan, FixedLaunchPlan::open(plan, specification)?);
            }
            validate_fixed_plan_separation(&plans)?;
            let trusted_plan_manifest = TrustedPlanManifestV11::new(
                transport.config_sha256,
                [
                    plans
                        .get(&Plan::Build)
                        .ok_or(ControllerError::Invalid("build plan is absent"))?
                        .command_identity_sha256,
                    plans
                        .get(&Plan::UnitNoBuild)
                        .ok_or(ControllerError::Invalid("unit plan is absent"))?
                        .command_identity_sha256,
                    plans
                        .get(&Plan::IntegrationNoBuild)
                        .ok_or(ControllerError::Invalid("integration plan is absent"))?
                        .command_identity_sha256,
                    plans
                        .get(&Plan::E2eNoBuild)
                        .ok_or(ControllerError::Invalid("e2e plan is absent"))?
                        .command_identity_sha256,
                    plans
                        .get(&Plan::AttestationNoBuild)
                        .ok_or(ControllerError::Invalid("attestation plan is absent"))?
                        .command_identity_sha256,
                ],
            )?;
            let trusted_plan_table_sha256 = trusted_plan_manifest.table_sha256;
            let trusted_plan_manifest_sha256 =
                trusted_plan_manifest.manifest_sha256()?;
            let pinned_manifest_bytes = read_immutable_root_file(
                Path::new(TRUSTED_PLAN_MANIFEST_PATH),
                TRUSTED_PLAN_MANIFEST_BYTES as u64,
                false,
            )?;
            let pinned_manifest =
                TrustedPlanManifestV11::decode(&pinned_manifest_bytes)?;
            if pinned_manifest != trusted_plan_manifest {
                return Err(ControllerError::Rejected(
                    "fixed client trust manifest differs from configured launch plans",
                ));
            }

            let mut provider = Vec::new();
            provider.extend_from_slice(b"catchplate/trusted-host-provider/v11\0");
            provider.extend_from_slice(&transport.config_sha256);
            provider.extend_from_slice(&trusted_plan_table_sha256);
            provider.extend_from_slice(&trusted_plan_manifest_sha256);
            provider.extend_from_slice(&source_root_identity_sha256);
            provider.extend_from_slice(&key_id_sha256);
            provider.extend_from_slice(&requester_key_id_sha256);
            provider.extend_from_slice(&launcher_sha256);
            provider.extend_from_slice(&settings.trust_epoch.to_be_bytes());
            provider.extend_from_slice(&settings.revocation_epoch.to_be_bytes());
            provider.extend_from_slice(
                AttestationScope::TrustedHostNoTee.exact_label().as_bytes(),
            );
            provider.push(0);
            for plan in plans.values() {
                provider.extend_from_slice(plan.plan.as_label().as_bytes());
                provider.push(0);
                provider.extend_from_slice(&plan.command_identity_sha256);
            }
            for path in &artifact_paths {
                provider.extend_from_slice(path.as_os_str().as_bytes());
                provider.push(0);
            }
            for path in &denied_socket_paths {
                provider.extend_from_slice(path.as_os_str().as_bytes());
                provider.push(0);
            }
            let self_path = std::fs::read_link("/proc/self/exe")?;
            validate_absolute_normalized_path(&self_path)?;
            let self_measurement = measure_open_file(&self_path, true)?;
            let daemon_executable_sha256 = self_measurement.1;
            let controller_pid = unsafe { libc::getpid() };
            let controller_pidfd = pidfd_open(controller_pid)?;
            let controller_start_time = proc_start_time_ticks(controller_pid)?;
            let controller_pidfd_identity =
                pidfd_identity(controller_pidfd.as_raw_fd())?;
            let mut controller_identity = Vec::new();
            controller_identity.extend_from_slice(
                b"catchplate/controller-process-identity/v11\0",
            );
            controller_identity.extend_from_slice(&controller_pid.to_be_bytes());
            controller_identity
                .extend_from_slice(&controller_start_time.to_be_bytes());
            controller_identity
                .extend_from_slice(controller_pidfd_identity.as_bytes());
            let controller_process_identity_sha256 =
                sha256(&controller_identity);
            provider.extend_from_slice(&self_measurement.1);
            provider.extend_from_slice(&controller_process_identity_sha256);
            provider.extend_from_slice(&orphan_journal_identity_sha256);
            provider.extend_from_slice(&boot_id_sha256);
            let provider_measurement_sha256 = sha256(&provider);
            let mut scope_measurement = Vec::new();
            scope_measurement
                .extend_from_slice(b"catchplate/trusted-host-attestation-scope/v11\0");
            scope_measurement.extend_from_slice(
                AttestationScope::TrustedHostNoTee.exact_label().as_bytes(),
            );
            scope_measurement.push(0);
            scope_measurement.extend_from_slice(&transport.config_sha256);
            scope_measurement.extend_from_slice(&provider_measurement_sha256);
            scope_measurement.extend_from_slice(&key_id_sha256);
            scope_measurement.extend_from_slice(&self_measurement.1);
            let attestation_scope_measurement_sha256 = sha256(&scope_measurement);

            Ok(Self {
                config_sha256: transport.config_sha256,
                source_root: settings.source_root,
                source_root_fd,
                source_root_identity_sha256,
                state,
                cgroup,
                signing_key,
                verifying_key,
                requester_verifying_key,
                final_verdict_verifying_key,
                key_id_sha256,
                requester_key_id_sha256,
                launcher_opath,
                launcher_read,
                launcher_identity,
                launcher_sha256,
                plans,
                deadlines_ms: settings.deadlines_ms,
                artifact_paths,
                denied_socket_paths,
                trusted_plan_table_sha256,
                trusted_plan_manifest_sha256,
                provider_measurement_sha256,
                attestation_scope_measurement_sha256,
                daemon_executable_sha256,
                controller_process_identity_sha256,
                frontend_pid: controller_pid,
                frontend_pidfd: controller_pidfd,
                orphan_journal_identity_sha256,
                boot_id_sha256,
                trust_epoch: settings.trust_epoch,
                revocation_epoch: settings.revocation_epoch,
                readiness_uid,
                readiness_gid,
                action_counter: AtomicU64::new(1),
                readiness,
                execution_lock: Mutex::new(()),
                queued_executions: AtomicUsize::new(0),
                maximum_queued_executions:
                    transport.max_connections.saturating_sub(1).max(1),
                tree_manifest_cache: Mutex::new(BTreeMap::new()),
                tree_drift_tracker,
                io_deadline: Mutex::new(None),
                cleanup_reserve_deadline: Mutex::new(None),
                quarantine_active: AtomicBool::new(false),
                plan_capabilities: Mutex::new(BTreeMap::new()),
            })
        }

        fn pre_ready_probe(&self) -> Result<()> {
            let probe_deadline =
                Instant::now() + Duration::from_secs(5 * 60);
            let _io_deadline = self.enter_lane_io_deadline(probe_deadline)?;
            let cgroup_root = self.cgroup.path.clone();
            let cgroup_directory = self.cgroup.directory.as_raw_fd();
            let journal_root =
                self.state.root_path.join("orphan-journal");
            let journal_directory =
                self.state.orphan_journal.as_raw_fd();
            let reconciliation = self.run_bytes_worker(
                "startup-reconciliation",
                PROVIDER_MAX_BYTES,
                move || {
                    reconcile_startup_worker(
                        &cgroup_root,
                        cgroup_directory,
                        &journal_root,
                        journal_directory,
                        probe_deadline,
                    )
                },
            )?;
            if !reconciliation.starts_with(
                b"catchplate/startup-reconciliation/v11\0",
            ) {
                return Err(ControllerError::Unready(vec![
                    "startup reconciliation returned noncanonical evidence"
                        .to_owned(),
                ]));
            }
            self.verify_trusted_plan_table_bounded()?;
            let direct_measurements =
                self.direct_supervisor_measurements(&[])?;
            if trusted_host_supervisor_state_machine_sha256(
                &direct_measurements,
            ) == [0; 32]
            {
                return Err(ControllerError::Unready(vec![
                    "shared direct supervisor measurement probe failed"
                        .to_owned(),
                ]));
            }
            let (probe_cgroup_name, probe_cgroup) =
                self.create_action_cgroup("pre-ready-cgroup-kill")?;
            write_control_file(probe_cgroup.as_raw_fd(), "cgroup.kill", b"1\n")?;
            drop(probe_cgroup);
            self.remove_reserved_cgroup(
                &probe_cgroup_name,
                "pre-ready cgroup.kill probe cleanup",
            )?;

            for plan_id in FIXED_PLAN_ORDER {
                let plan = self.plans.get(&plan_id).ok_or(
                    ControllerError::Rejected(
                        "five-plan compatibility probe lacks a plan",
                    ),
                )?;
                let contract = self.launch_contract(
                    plan,
                    self.readiness_uid,
                    self.readiness_gid,
                    plan_id != Plan::Build,
                    now_unix_ms()?.saturating_add(30_000),
                    true,
                    sha256(
                        &[
                            b"catchplate/readiness-request/v11\0"
                                .as_slice(),
                            plan.command_identity_sha256.as_slice(),
                        ]
                        .concat(),
                    ),
                    sha256(
                        &[
                            b"catchplate/readiness-artifact-seal/v11\0"
                                .as_slice(),
                            plan.executable_closure_sha256.as_slice(),
                        ]
                        .concat(),
                    ),
                )?;
                let contract_bytes = contract.encode()?;
                let contract_memfd = create_sealed_memfd(
                    "catchplate-controller-readiness-launch-v11",
                    &contract_bytes,
                )?;
                verify_sealed_memfd(
                    contract_memfd.as_raw_fd(),
                    contract_bytes.len() as u64,
                )?;
                let launcher_fd = self.launcher_opath.as_raw_fd();
                let mut child = self.spawn_registered_isolated(
                    "pre-ready-plan-compatibility",
                    move |_output| {
                        exec_controller_launcher_mode(
                            launcher_fd,
                            contract_memfd.as_raw_fd(),
                            false,
                        )
                    },
                )?;
                if let Err(error) = Self::release_child(&mut child) {
                    self.cleanup_registered_child(
                        &mut child,
                        None,
                        true,
                        true,
                    )?;
                    self.quarantine(&format!(
                        "five-plan compatibility release failed: {error}"
                    ))?;
                    return Err(error);
                }
                let outcome =
                    self.collect_child(child, probe_deadline, 4096, None)?;
                if !wait_status_success(outcome.wait_status)
                    || outcome.timed_out
                    || !outcome.cleanup_proved
                {
                    let reason = format!(
                        "{} launcher/closure compatibility probe failed",
                        plan_id.as_label()
                    );
                    self.quarantine(&reason)?;
                    return Err(ControllerError::Unready(vec![reason]));
                }
            }

            let journal_base =
                self.next_action_name("pre-ready-watchdog-journal")?;
            let journal_name = CString::new(format!(
                "{}.journal",
                journal_base.to_string_lossy(),
            ))
            .map_err(|_| {
                ControllerError::Invalid(
                    "probe journal name contains NUL",
                )
            })?;
            let journal_directory = self.state.orphan_journal.as_raw_fd();
            let mut journal_child = self.spawn_registered_with_policy(
                "pre-ready-watchdog-journal",
                false,
                move |output| {
                    let record = b"catchplate/pre-ready-watchdog-journal/v11";
                    if write_durable_journal(
                        journal_directory,
                        &journal_name,
                        record,
                    )
                    .is_ok()
                        && write_all_fd(output, record).is_ok()
                    {
                        0
                    } else {
                        125
                    }
                },
            )?;
            if let Err(error) = Self::release_child(&mut journal_child) {
                self.cleanup_registered_child(
                    &mut journal_child,
                    None,
                    true,
                    true,
                )?;
                self.quarantine(&format!(
                    "pre-ready watchdog journal release failed: {error}"
                ))?;
                return Err(error);
            }
            let journal_outcome = self.collect_child(
                journal_child,
                probe_deadline,
                4096,
                None,
            )?;
            if !wait_status_success(journal_outcome.wait_status)
                || journal_outcome.timed_out
                || !journal_outcome.cleanup_proved
            {
                return Err(ControllerError::Unready(vec![
                    "watchdog durable journal probe failed".to_owned(),
                ]));
            }
            self.persist_evidence(
                b"catchplate/pre-ready-fs-immutable-evidence/v11",
            )?;
            Ok(())
        }
    }

    impl FixedLaunchPlan {
        fn open(plan: Plan, specification: PlanSpec) -> Result<Self> {
            validate_absolute_normalized_path(&specification.executable)?;
            validate_absolute_normalized_path(&specification.cwd)?;
            if specification.closure.len() != 1
                || specification.closure[0]
                    != (true, specification.executable.clone())
            {
                return Err(ControllerError::Rejected(
                    "v11 plans require one exact static primary and forbid interpreter, loader, DSO, script, module, subprocess, and JIT closures",
                ));
            }
            let executable_opath =
                open_canonical_path(&specification.executable, libc::O_PATH, false)?;
            let executable_read =
                open_canonical_path(&specification.executable, libc::O_RDONLY, false)?;
            let read_identity = regular_file_identity(executable_read.as_raw_fd(), true)?;
            require_static_elf(executable_read.as_raw_fd())?;
            let opath_identity = regular_file_identity_with_generation(
                executable_opath.as_raw_fd(),
                true,
                read_identity.generation,
            )?;
            if opath_identity != read_identity {
                return Err(ControllerError::Rejected(
                    "retained executable O_PATH/read descriptors disagree",
                ));
            }
            let executable_sha256 =
                digest_regular_fd(executable_read.as_raw_fd(), read_identity.size)?;
            let cwd_fd = open_canonical_directory(&specification.cwd, false)?;
            let cwd_identity = directory_identity(cwd_fd.as_raw_fd())?;
            let mut executable_closure = Vec::new();
            let mut closure_canonical = Vec::new();
            closure_canonical.extend_from_slice(
                b"catchplate/executable-closure/v11\0",
            );
            closure_canonical.extend_from_slice(plan.as_label().as_bytes());
            closure_canonical.push(0);
            for (is_executable, path) in &specification.closure {
                validate_absolute_normalized_path(path)?;
                let opath = open_canonical_path(path, libc::O_PATH, false)?;
                let read = open_canonical_path(path, libc::O_RDONLY, false)?;
                let identity =
                    regular_file_identity(read.as_raw_fd(), *is_executable)?;
                require_immutable_closure_file(read.as_raw_fd())?;
                let opath_identity = regular_file_identity_with_generation(
                    opath.as_raw_fd(),
                    *is_executable,
                    identity.generation,
                )?;
                if identity != opath_identity {
                    return Err(ControllerError::Rejected(
                        "closure O_PATH/read descriptors disagree",
                    ));
                }
                if plan != Plan::Build
                    && *is_executable
                    && forbidden_no_build_tool(path)
                {
                    return Err(ControllerError::Rejected(
                        "no-build executable closure contains a build tool",
                    ));
                }
                let content_sha256 =
                    digest_regular_fd(read.as_raw_fd(), identity.size)?;
                closure_canonical.push(u8::from(*is_executable));
                closure_canonical
                    .extend_from_slice(path.as_os_str().as_bytes());
                closure_canonical.push(0);
                append_file_identity(&mut closure_canonical, &identity);
                closure_canonical.extend_from_slice(&content_sha256);
                executable_closure.push(ExecutableClosureMember {
                    path: path.clone(),
                    executable: *is_executable,
                    opath,
                    read,
                    identity,
                    content_sha256,
                });
            }
            let executable_closure_sha256 = sha256(&closure_canonical);
            let mut sandbox_profile = Vec::new();
            sandbox_profile.extend_from_slice(
                b"catchplate/controller-sandbox-profile/v11\0",
            );
            sandbox_profile.extend_from_slice(plan.as_label().as_bytes());
            sandbox_profile.extend_from_slice(&executable_closure_sha256);
            sandbox_profile.extend_from_slice(if plan == Plan::Build {
                b"source-ro;artifacts-rw;private-run;private-loopback;tmp-noexec"
            } else {
                b"source-ro;artifacts-ro;private-run;private-loopback;tmp-noexec"
            });
            let sandbox_profile_sha256 = sha256(&sandbox_profile);
            let mut argv = Vec::with_capacity(specification.args.len());
            for value in specification.args {
                argv.push(
                    CString::new(value)
                        .map_err(|_| ControllerError::Invalid("plan argv contains NUL"))?,
                );
            }
            let expected_operation = if plan == Plan::Build {
                "--operation=build"
            } else {
                "--operation=runNoBuild"
            };
            let expected_plan = format!("--plan={}", plan.as_label());
            if argv.len() != 4
                || argv[0].as_bytes()
                    != specification.executable.as_os_str().as_bytes()
                || argv[1].as_bytes() != b"execute-v11"
                || argv[2].as_bytes() != expected_operation.as_bytes()
                || argv[3].as_bytes() != expected_plan.as_bytes()
            {
                return Err(ControllerError::Rejected(
                    "fixed plan argv must be the exact execute-v11 plan API invocation",
                ));
            }
            let mut env_values = specification.env;
            env_values.insert(
                "CATCHPLATE_CONTROLLER_PLAN".to_owned(),
                plan.as_label().to_owned(),
            );
            env_values.insert(
                "CATCHPLATE_CONTROLLER_NO_BUILD".to_owned(),
                if plan == Plan::Build { "0" } else { "1" }.to_owned(),
            );
            let mut env = Vec::with_capacity(env_values.len());
            for (key, value) in env_values {
                env.push(
                    CString::new(format!("{key}={value}"))
                        .map_err(|_| ControllerError::Invalid("plan environment contains NUL"))?,
                );
            }
            let mut canonical = Vec::new();
            canonical.extend_from_slice(b"catchplate/fixed-launch/v11\0");
            canonical.extend_from_slice(plan.as_label().as_bytes());
            canonical.push(0);
            canonical.extend_from_slice(specification.executable.as_os_str().as_bytes());
            canonical.push(0);
            append_file_identity(&mut canonical, &opath_identity);
            canonical.extend_from_slice(&executable_sha256);
            canonical.extend_from_slice(specification.cwd.as_os_str().as_bytes());
            canonical.push(0);
            append_file_identity(&mut canonical, &cwd_identity);
            for value in &argv {
                canonical.extend_from_slice(value.as_bytes());
                canonical.push(0);
            }
            canonical.push(0xff);
            for value in &env {
                canonical.extend_from_slice(value.as_bytes());
                canonical.push(0);
            }
            canonical.extend_from_slice(&executable_closure_sha256);
            canonical.extend_from_slice(&sandbox_profile_sha256);
            canonical.extend_from_slice(&specification.configuration_sha256);
            let command_identity_sha256 = sha256(&canonical);
            Ok(Self {
                plan,
                executable_path: specification.executable,
                executable_opath,
                executable_read,
                executable_identity: opath_identity,
                executable_sha256,
                cwd_path: specification.cwd,
                cwd_fd,
                cwd_identity,
                argv,
                env,
                executable_closure,
                executable_closure_sha256,
                sandbox_profile_sha256,
                configuration_sha256: specification.configuration_sha256,
                command_identity_sha256,
            })
        }
    }

    fn validate_fixed_plan_separation(
        plans: &BTreeMap<Plan, FixedLaunchPlan>,
    ) -> Result<()> {
        if plans.len() != REQUIRED_PLAN_LABELS.len() {
            return Err(ControllerError::Rejected(
                "trusted-host plan table is incomplete",
            ));
        }
        let build = plans
            .get(&Plan::Build)
            .ok_or(ControllerError::Invalid("build plan is absent"))?;
        let build_executables: Vec<_> = build
            .executable_closure
            .iter()
            .filter(|member| member.executable)
            .map(|member| {
                (
                    &member.path,
                    &member.identity,
                    member.content_sha256,
                )
            })
            .collect();
        for plan_id in [
            Plan::UnitNoBuild,
            Plan::IntegrationNoBuild,
            Plan::E2eNoBuild,
            Plan::AttestationNoBuild,
        ] {
            let current = plans
                .get(&plan_id)
                .ok_or(ControllerError::Invalid("no-build plan is absent"))?;
            if current.command_identity_sha256
                == build.command_identity_sha256
            {
                return Err(ControllerError::Rejected(
                    "no-build lane aliases the build command identity",
                ));
            }
            for member in current
                .executable_closure
                .iter()
                .filter(|member| member.executable)
            {
                if build_executables.iter().any(
                    |(path, identity, content)| {
                        &member.path == *path
                            || (&member.identity == *identity
                                && member.content_sha256 == *content)
                    },
                ) {
                    return Err(ControllerError::Rejected(
                        "no-build executable closure contains a build-lane executable",
                    ));
                }
            }
        }
        Ok(())
    }

    fn forbidden_no_build_tool(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return true;
        };
        matches!(
            name,
            "cargo"
                | "rustc"
                | "gcc"
                | "g++"
                | "cc"
                | "c++"
                | "clang"
                | "clang++"
                | "ld"
                | "ld.lld"
                | "make"
                | "cmake"
                | "ninja"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "go"
                | "javac"
        )
    }

    impl StateStore {
        fn open(path: &Path) -> Result<Self> {
            let root = open_canonical_directory(path, false)?;
            verify_root_owned_directory(root.as_raw_fd(), true)?;
            let acceptance = open_or_create_private_directory(root.as_raw_fd(), "acceptance")?;
            let builds = open_or_create_private_directory(root.as_raw_fd(), "builds")?;
            let evidence = open_or_create_private_directory(root.as_raw_fd(), "evidence")?;
            let orphan_journal =
                open_or_create_private_directory(root.as_raw_fd(), "orphan-journal")?;
            Ok(Self {
                root,
                acceptance,
                builds,
                evidence,
                orphan_journal,
                root_path: path.to_path_buf(),
            })
        }
    }

    fn validate_absolute_normalized_path(path: &Path) -> Result<()> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir
                        | std::path::Component::ParentDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(ControllerError::Rejected(
                "configured path is not absolute and normalized",
            ));
        }
        Ok(())
    }

    fn open_canonical_path(path: &Path, access: libc::c_int, directory: bool) -> Result<OwnedFd> {
        validate_absolute_normalized_path(path)?;
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("configured path contains NUL"))?;
        let mut flags = access | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        if directory {
            flags |= libc::O_DIRECTORY;
        }
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path_c.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let resolved = std::fs::read_link(format!("/proc/self/fd/{raw}"))?;
        if resolved != path {
            return Err(ControllerError::Rejected(
                "configured path is not its canonical retained object path",
            ));
        }
        Ok(fd)
    }

    fn open_canonical_directory(path: &Path, private: bool) -> Result<OwnedFd> {
        let directory = open_canonical_path(path, libc::O_RDONLY, true)?;
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ControllerError::Rejected(
                "retained path is not a directory",
            ));
        }
        if private {
            verify_root_owned_directory(directory.as_raw_fd(), true)?;
        }
        Ok(directory)
    }

    fn verify_root_owned_directory(fd: RawFd, private: bool) -> Result<()> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let required_mode = if private { 0o077 } else { 0o022 };
        if stat.st_uid != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_mode & required_mode != 0
        {
            return Err(ControllerError::Rejected(
                "retained directory ownership or mode is unsafe",
            ));
        }
        Ok(())
    }

    fn open_or_create_private_directory(parent: RawFd, name: &str) -> Result<OwnedFd> {
        let name_c =
            CString::new(name).map_err(|_| ControllerError::Invalid("state name contains NUL"))?;
        let created = unsafe { libc::mkdirat(parent, name_c.as_ptr(), 0o700) };
        if created != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error.into());
            }
        }
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent,
                name_c.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory = unsafe { OwnedFd::from_raw_fd(raw) };
        verify_root_owned_directory(directory.as_raw_fd(), true)?;
        Ok(directory)
    }

    fn read_immutable_root_file(path: &Path, expected: u64, secret: bool) -> Result<Vec<u8>> {
        let fd = open_canonical_path(path, libc::O_RDONLY, false)?;
        let identity = regular_file_identity(fd.as_raw_fd(), false)?;
        if identity.owner_uid != 0
            || identity.size != expected
            || identity.mode & 0o022 != 0
            || (secret && identity.mode & 0o077 != 0)
        {
            return Err(ControllerError::Rejected(
                "key file ownership, mode, or size is unsafe",
            ));
        }
        let mut flags: libc::c_uint = 0;
        if unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) } != 0
            || flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "key file lacks filesystem immutable protection",
            ));
        }
        let mut bytes = vec![0u8; expected as usize];
        pread_exact(fd.as_raw_fd(), &mut bytes)?;
        Ok(bytes)
    }

    fn regular_file_identity(fd: RawFd, require_executable: bool) -> Result<FileIdentity> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_size < 0
            || (require_executable && stat.st_mode & 0o111 == 0)
            || (require_executable && (stat.st_uid != 0 || stat.st_mode & 0o022 != 0))
        {
            return Err(ControllerError::Rejected(
                "retained regular file identity is unsafe",
            ));
        }
        let mut generation: libc::c_long = 0;
        if unsafe { libc::ioctl(fd, FS_IOC_GETVERSION, &mut generation) } != 0
            || generation < 0
        {
            return Err(ControllerError::Rejected(
                "filesystem generation is unavailable for retained file",
            ));
        }
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            generation: generation as u64,
            mode: stat.st_mode,
            owner_uid: stat.st_uid,
            size: stat.st_size as u64,
        })
    }

    fn require_immutable_closure_file(fd: RawFd) -> Result<()> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        let mut flags: libc::c_uint = 0;
        if unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || stat.st_nlink != 1
            || unsafe {
                libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags)
            } != 0
            || flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "plan closure member is not one root-owned immutable nonwritable file",
            ));
        }
        Ok(())
    }

    fn require_static_elf(fd: RawFd) -> Result<()> {
        let mut header = [0u8; 64];
        pread_exact(fd, &mut header)?;
        if header[0..4] != *b"\x7fELF"
            || header[4] != 2
            || header[5] != 1
            || header[6] != 1
        {
            return Err(ControllerError::Rejected(
                "privileged launcher is not a canonical 64-bit little-endian ELF",
            ));
        }
        let program_offset = u64::from_le_bytes(
            header[32..40]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program offset",
                ))?,
        );
        let program_entry_size = u16::from_le_bytes(
            header[54..56]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program entry size",
                ))?,
        ) as u64;
        let program_count = u16::from_le_bytes(
            header[56..58]
                .try_into()
                .map_err(|_| ControllerError::Invalid(
                    "invalid ELF program count",
                ))?,
        ) as u64;
        if program_entry_size < 56 || program_count == 0
            || program_count > 1024
        {
            return Err(ControllerError::Rejected(
                "privileged launcher ELF program table is invalid",
            ));
        }
        for index in 0..program_count {
            let offset = program_offset
                .checked_add(index.checked_mul(program_entry_size).ok_or(
                    ControllerError::Invalid(
                        "ELF program table multiplication overflow",
                    ),
                )?)
                .ok_or(ControllerError::Invalid(
                    "ELF program table offset overflow",
                ))?;
            let mut entry = [0u8; 56];
            pread_exact_at(fd, &mut entry, offset)?;
            let kind = u32::from_le_bytes(
                entry[0..4]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid(
                        "invalid ELF program type",
                    ))?,
            );
            if kind == 3 {
                return Err(ControllerError::Rejected(
                    "privileged launcher must be statically linked and have no PT_INTERP",
                ));
            }
        }
        Ok(())
    }

    fn pread_exact_at(
        fd: RawFd,
        bytes: &mut [u8],
        base_offset: u64,
    ) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let absolute = base_offset
                .checked_add(offset as u64)
                .ok_or(ControllerError::Invalid(
                    "pread offset overflow",
                ))?;
            let absolute: libc::off_t = absolute.try_into().map_err(|_| {
                ControllerError::Invalid("pread offset exceeds off_t")
            })?;
            let count = unsafe {
                libc::pread(
                    fd,
                    bytes[offset..].as_mut_ptr()
                        as *mut libc::c_void,
                    bytes.len() - offset,
                    absolute,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "ELF program table is truncated",
                ));
            }
            offset += count as usize;
        }
        Ok(())
    }

    fn regular_file_identity_with_generation(
        fd: RawFd,
        require_executable: bool,
        generation: u64,
    ) -> Result<FileIdentity> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_size < 0
            || (require_executable && stat.st_mode & 0o111 == 0)
            || (require_executable && (stat.st_uid != 0 || stat.st_mode & 0o022 != 0))
        {
            return Err(ControllerError::Rejected(
                "retained O_PATH regular file identity is unsafe",
            ));
        }
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            generation,
            mode: stat.st_mode,
            owner_uid: stat.st_uid,
            size: stat.st_size as u64,
        })
    }

    fn directory_identity(fd: RawFd) -> Result<FileIdentity> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ControllerError::Rejected(
                "retained cwd/source object is not a directory",
            ));
        }
        let mut generation: libc::c_long = 0;
        if unsafe { libc::ioctl(fd, FS_IOC_GETVERSION, &mut generation) } != 0
            || generation < 0
        {
            return Err(ControllerError::Rejected(
                "filesystem generation is unavailable for retained directory",
            ));
        }
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            generation: generation as u64,
            mode: stat.st_mode,
            owner_uid: stat.st_uid,
            size: 0,
        })
    }

    fn append_file_identity(output: &mut Vec<u8>, identity: &FileIdentity) {
        output.extend_from_slice(&identity.device.to_be_bytes());
        output.extend_from_slice(&identity.inode.to_be_bytes());
        output.extend_from_slice(&identity.generation.to_be_bytes());
        output.extend_from_slice(&identity.mode.to_be_bytes());
        output.extend_from_slice(&identity.owner_uid.to_be_bytes());
        output.extend_from_slice(&identity.size.to_be_bytes());
    }

    fn identity_digest(label: &[u8], path: &Path, identity: &FileIdentity) -> Digest {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(label);
        canonical.push(0);
        canonical.extend_from_slice(path.as_os_str().as_bytes());
        canonical.push(0);
        append_file_identity(&mut canonical, identity);
        sha256(&canonical)
    }

    fn digest_regular_fd(fd: RawFd, length: u64) -> Result<Digest> {
        let mut file = File::from(duplicate_fd(fd)?);
        file.seek(SeekFrom::Start(0))?;
        sha256_exact_reader(&mut file, length)
    }

    fn measure_open_file(path: &Path, require_root_executable: bool) -> Result<(FileIdentity, Digest)> {
        let fd = open_canonical_path(path, libc::O_RDONLY, false)?;
        let identity = regular_file_identity(fd.as_raw_fd(), require_root_executable)?;
        if require_root_executable {
            require_immutable_closure_file(fd.as_raw_fd())?;
        }
        let digest = digest_regular_fd(fd.as_raw_fd(), identity.size)?;
        Ok((identity, digest))
    }

    #[derive(Clone)]
    struct RequestContext {
        request_id: Digest,
        exact_signed_request_sha256: Digest,
        nonce_sha256: Digest,
        peer_binding_sha256: Digest,
        transport_deadline_unix_ms: u64,
        lane_deadline_ms: u64,
        source_sha256: Digest,
        current_command_sha256: Digest,
        original_build_command_sha256: Digest,
        config_sha256: Digest,
        provider_measurement_sha256: Digest,
        source_root_identity_sha256: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
    }

    impl RequestContext {
        fn canonical(&self, plan: Plan) -> Vec<u8> {
            let mut output = Vec::new();
            output.extend_from_slice(b"catchplate/request-binding/v11\0");
            output.extend_from_slice(plan.as_label().as_bytes());
            output.push(0);
            output.extend_from_slice(&self.request_id);
            output.extend_from_slice(&self.exact_signed_request_sha256);
            output.extend_from_slice(&self.nonce_sha256);
            output.extend_from_slice(&self.peer_binding_sha256);
            output.extend_from_slice(&self.transport_deadline_unix_ms.to_be_bytes());
            output.extend_from_slice(&self.lane_deadline_ms.to_be_bytes());
            output.extend_from_slice(&self.source_sha256);
            output.extend_from_slice(&self.current_command_sha256);
            output.extend_from_slice(&self.original_build_command_sha256);
            output.extend_from_slice(&self.config_sha256);
            output.extend_from_slice(&self.provider_measurement_sha256);
            output.extend_from_slice(&self.source_root_identity_sha256);
            output.extend_from_slice(&self.trust_epoch.to_be_bytes());
            output.extend_from_slice(&self.revocation_epoch.to_be_bytes());
            output
        }

        fn binding_sha256(&self, plan: Plan) -> Digest {
            sha256(&self.canonical(plan))
        }
    }

    struct VerifiedAcceptanceLease {
        fence: u64,
        identity_sha256: Digest,
        generation: u64,
        claim_sha256: Digest,
        request_binding_sha256: Digest,
    }

    enum AcceptanceDecision {
        New(VerifiedAcceptanceLease),
        Replay(Vec<u8>),
        InFlight(VerifiedAcceptanceLease),
    }

    #[derive(Clone)]
    struct VerifiedBuildReservation {
        fence: u64,
        identity_sha256: Digest,
        generation: u64,
        source_sha256: Digest,
        original_build_command_sha256: Digest,
        record_sha256: Digest,
    }

    struct CommittedBuildRecord {
        reservation: VerifiedBuildReservation,
        artifact_closure_sha256: Digest,
        commit_sha256: Digest,
    }

    struct CommittedBuildTerminal {
        reservation: VerifiedBuildReservation,
        terminal: ReceiptTerminal,
        evidence_sha256: Digest,
        commit_sha256: Digest,
    }

    enum BuildDecision {
        Reserved(VerifiedBuildReservation),
        Existing(CommittedBuildRecord),
        InFlight(VerifiedBuildReservation),
        Terminal(CommittedBuildTerminal),
    }

    impl TrustedHostProduction {
        fn random_digest_bounded(&self, label: &str) -> Result<Digest> {
            let bytes = self.run_bytes_worker(label, 32, || {
                Ok(random_digest_worker_only()?.to_vec())
            })?;
            if bytes.len() != 32 {
                return Err(ControllerError::Rejected(
                    "bounded entropy worker returned an invalid length",
                ));
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes);
            Ok(digest)
        }

        fn sign_blob(&self, payload: &[u8]) -> Result<Vec<u8>> {
            if payload.len() > RECEIPT_MAX_BYTES as usize - 112 {
                return Err(ControllerError::Rejected("signed payload is too large"));
            }
            let signature = self.signing_key.sign(payload);
            self.verifying_key
                .verify(payload, &signature)
                .map_err(|_| ControllerError::Rejected("local Ed25519 self-verification failed"))?;
            let mut output = Vec::with_capacity(16 + payload.len() + 96);
            output.extend_from_slice(b"SWEDSG11");
            output.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            output.extend_from_slice(payload);
            output.extend_from_slice(self.verifying_key.as_bytes());
            output.extend_from_slice(&signature.to_bytes());
            Ok(output)
        }

        fn verify_blob<'a>(&self, encoded: &'a [u8]) -> Result<&'a [u8]> {
            if encoded.len() < 16 + 32 + 64 || &encoded[0..8] != b"SWEDSG11" {
                return Err(ControllerError::Rejected("invalid signed state wrapper"));
            }
            let payload_len = u64::from_be_bytes(
                encoded[8..16]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid("invalid signed length"))?,
            ) as usize;
            if payload_len > STATE_RECORD_MAX_BYTES as usize
                || encoded.len() != 16 + payload_len + 32 + 64
            {
                return Err(ControllerError::Rejected("signed wrapper length mismatch"));
            }
            let payload = &encoded[16..16 + payload_len];
            let public = &encoded[16 + payload_len..16 + payload_len + 32];
            if public != self.verifying_key.as_bytes() {
                return Err(ControllerError::Rejected(
                    "signed wrapper uses an unconfigured public key",
                ));
            }
            let mut signature_bytes = [0u8; 64];
            signature_bytes.copy_from_slice(&encoded[16 + payload_len + 32..]);
            let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
            self.verifying_key
                .verify(payload, &signature)
                .map_err(|_| ControllerError::Rejected("Ed25519 state signature failed"))?;
            Ok(payload)
        }

        fn load_current_acceptance_lease(
            &self,
            plan: Plan,
            request: &RequestContext,
        ) -> Result<VerifiedAcceptanceLease> {
            let stem = digest_hex(&request.request_id);
            let claim_name = format!("{stem}.claim");
            let claim = self.read_required_state_bounded(
                self.state.acceptance.as_raw_fd(),
                &claim_name,
            )?;
            let payload = self.verify_blob(&claim)?;
            parse_acceptance_claim(
                payload,
                request.binding_sha256(plan),
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )
        }

        fn verify_current_receipt_build_binding(
            &self,
            body: &ControllerReceiptBody,
        ) -> Result<()> {
            let absent = body.build_fence == 0
                && body.build_reservation_generation == 0
                && body.committed_build_command_sha256 == [0; 32]
                && body.build_reservation_identity_sha256 == [0; 32];
            if absent {
                if body.terminal == ReceiptTerminal::Success {
                    return Err(ControllerError::Rejected(
                        "successful receipt has no current build reservation binding",
                    ));
                }
                return Ok(());
            }
            let name = format!(
                "{}.reservation",
                digest_hex(&body.observed_source_sha256)
            );
            let bytes =
                self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
            let payload = self.verify_blob(&bytes)?;
            let reservation = parse_build_reservation(
                payload,
                body.observed_source_sha256,
                body.committed_build_command_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?;
            if reservation.fence != body.build_fence
                || reservation.identity_sha256
                    != body.build_reservation_identity_sha256
                || reservation.generation != body.build_reservation_generation
            {
                return Err(ControllerError::Rejected(
                    "receipt does not exact-bind the current build reservation",
                ));
            }
            if body.terminal == ReceiptTerminal::Success {
                let committed = self.require_build_success(
                    body.observed_source_sha256,
                    body.committed_build_command_sha256,
                )?;
                if committed.reservation.fence != reservation.fence
                    || committed.reservation.identity_sha256
                        != reservation.identity_sha256
                    || committed.reservation.generation != reservation.generation
                {
                    return Err(ControllerError::Rejected(
                        "successful receipt does not exact-bind committed current reservation",
                    ));
                }
            }
            Ok(())
        }

        fn verify_trusted_plan_table(&self) -> Result<()> {
            require_immutable_closure_file(
                self.launcher_read.as_raw_fd(),
            )?;
            let launcher_identity = regular_file_identity_with_generation(
                self.launcher_opath.as_raw_fd(),
                true,
                self.launcher_identity.generation,
            )?;
            let launcher_sha256 = digest_regular_fd(
                self.launcher_read.as_raw_fd(),
                self.launcher_identity.size,
            )?;
            if launcher_identity != self.launcher_identity
                || launcher_sha256 != self.launcher_sha256
            {
                return Err(ControllerError::Rejected(
                    "retained controller launcher identity or content changed",
                ));
            }
            let mut identities = [[0u8; 32]; 5];
            for (index, plan) in FIXED_PLAN_ORDER.iter().enumerate() {
                let fixed = self
                    .plans
                    .get(plan)
                    .ok_or(ControllerError::Rejected(
                        "trusted five-plan table is incomplete",
                    ))?;
                if verify_fixed_plan(fixed)? != fixed.command_identity_sha256 {
                    return Err(ControllerError::Rejected(
                        "trusted five-plan retained launch changed",
                    ));
                }
                identities[index] = fixed.command_identity_sha256;
            }
            let manifest =
                TrustedPlanManifestV11::new(self.config_sha256, identities)?;
            if manifest.table_sha256 != self.trusted_plan_table_sha256 {
                return Err(ControllerError::Rejected(
                    "trusted five-plan table digest changed",
                ));
            }
            if manifest.manifest_sha256()?
                != self.trusted_plan_manifest_sha256
            {
                return Err(ControllerError::Rejected(
                    "trusted five-plan canonical manifest digest changed",
                ));
            }
            let pinned_bytes = read_immutable_root_file(
                Path::new(TRUSTED_PLAN_MANIFEST_PATH),
                TRUSTED_PLAN_MANIFEST_BYTES as u64,
                false,
            )?;
            if TrustedPlanManifestV11::decode(&pinned_bytes)? != manifest {
                return Err(ControllerError::Rejected(
                    "fixed client trust manifest changed or differs from retained plans",
                ));
            }
            let pinned_public_key = read_immutable_root_file(
                Path::new(RECEIPT_PUBLIC_KEY_PATH),
                32,
                false,
            )?;
            if pinned_public_key.as_slice()
                != &self.verifying_key.as_bytes()[..]
            {
                return Err(ControllerError::Rejected(
                    "fixed client receipt public key changed",
                ));
            }
            let pinned_requester_key = read_immutable_root_file(
                Path::new(REQUESTER_PUBLIC_KEY_PATH),
                32,
                false,
            )?;
            if pinned_requester_key.as_slice()
                != &self.requester_verifying_key.as_bytes()[..]
                || sha256(&pinned_requester_key)
                    != self.requester_key_id_sha256
            {
                return Err(ControllerError::Rejected(
                    "fixed requester public key changed",
                ));
            }
            Ok(())
        }

        fn verify_trusted_plan_table_bounded(&self) -> Result<()> {
            let expected = self.trusted_plan_table_sha256;
            let measured = self.run_digest_provider(
                "trusted-five-plan-table-verifier",
                bounded_provider_timeout(self.current_io_deadline()?)?,
                || {
                    self.verify_trusted_plan_table()?;
                    Ok(expected)
                },
            )?;
            if measured != expected {
                return Err(ControllerError::Rejected(
                    "bounded trusted five-plan verifier returned another digest",
                ));
            }
            Ok(())
        }

        fn verify_persisted_evidence(&self, expected: Digest) -> Result<()> {
            let name = format!("{}.evidence", digest_hex(&expected));
            let directory = self.state.evidence.as_raw_fd();
            let evidence = self.run_bytes_worker(
                "immutable-evidence-read",
                PROVIDER_MAX_BYTES,
                move || {
                    require_immutable_state_file(directory, &name)?;
                    read_required_state_file(directory, &name)
                },
            )?;
            if sha256(&evidence) != expected {
                return Err(ControllerError::Rejected(
                    "signed receipt evidence is absent or does not match immutable store",
                ));
            }
            Ok(())
        }

        fn verify_receipt_for_request(
            &self,
            encoded: &[u8],
            lane: Lane,
            request: &RequestContext,
            lease: &VerifiedAcceptanceLease,
        ) -> Result<ControllerReceiptBody> {
            if encoded.len() != SIGNED_CONTROLLER_RECEIPT_BYTES {
                return Err(ControllerError::Rejected(
                    "durable receipt is not the fixed shared v11 length",
                ));
            }
            if lease.request_binding_sha256 != request.binding_sha256(lane.plan) {
                return Err(ControllerError::Rejected(
                    "receipt acceptance lease does not bind the current request",
                ));
            }
            self.verify_trusted_plan_table_bounded()?;
            let signed = SignedControllerReceipt::decode(encoded)?;
            let verified = signed.verify_for_request(
                &self.verifying_key,
                lane,
                request.request_id,
                request.binding_sha256(lane.plan),
                request.nonce_sha256,
                request.transport_deadline_unix_ms,
                self.trusted_plan_table_sha256,
            )?;
            let body = verified.body();
            if body.attestation_scope != AttestationScope::TrustedHostNoTee
                || body.exact_signed_request_sha256
                    != request.binding_sha256(lane.plan)
                || body.observed_source_sha256 != request.source_sha256
                || body.current_lane_command_sha256
                    != request.current_command_sha256
                || body.acceptance_fence != lease.fence
                || body.acceptance_generation != lease.generation
                || body.acceptance_identity_sha256 != lease.identity_sha256
                || body.config_sha256 != request.config_sha256
                || body.config_sha256 != self.config_sha256
                || body.provider_manifest_sha256
                    != request.provider_measurement_sha256
                || body.provider_manifest_sha256
                    != self.provider_measurement_sha256
                || body.fixed_plan_manifest_sha256
                    != self.trusted_plan_table_sha256
                || body.attestation_scope_measurement_sha256
                    != self.attestation_scope_measurement_sha256
            {
                return Err(ControllerError::Rejected(
                    "signed receipt trust/request/acceptance binding is invalid",
                ));
            }
            let build_binding_present = body.build_fence != 0
                || body.build_reservation_generation != 0
                || body.committed_build_command_sha256 != [0; 32]
                || body.build_reservation_identity_sha256 != [0; 32];
            if build_binding_present
                && body.committed_build_command_sha256
                    != request.original_build_command_sha256
            {
                return Err(ControllerError::Rejected(
                    "signed receipt does not bind the original build command",
                ));
            }
            self.verify_current_receipt_build_binding(body)?;
            self.verify_persisted_evidence(body.terminal_evidence_sha256)?;
            self.verify_persisted_evidence(body.evidence_closure_sha256)?;
            Ok(body.clone())
        }

        fn verify_exact_receipt(
            &self,
            encoded: &[u8],
            request: &RequestContext,
            lease: &VerifiedAcceptanceLease,
            expected: &ControllerReceiptBody,
        ) -> Result<()> {
            let body =
                self.verify_receipt_for_request(encoded, expected.lane, request, lease)?;
            if &body != expected {
                return Err(ControllerError::Rejected(
                    "signed receipt differs from the exact committed receipt body",
                ));
            }
            Ok(())
        }

        fn acceptance_decision(
            &self,
            lane: Lane,
            request: &RequestContext,
        ) -> Result<AcceptanceDecision> {
            let plan = lane.plan;
            let stem = digest_hex(&request.request_id);
            let receipt_name = format!("{stem}.receipt");
            if let Some(receipt) = self.read_optional_state_bounded(
                self.state.acceptance.as_raw_fd(),
                &receipt_name,
            )?
            {
                let lease = self.load_current_acceptance_lease(plan, request)?;
                self.verify_receipt_for_request(&receipt, lane, request, &lease)?;
                return Ok(AcceptanceDecision::Replay(receipt));
            }
            let claim_name = format!("{stem}.claim");
            if let Some(claim) = self.read_optional_state_bounded(
                self.state.acceptance.as_raw_fd(),
                &claim_name,
            )?
            {
                let payload = self.verify_blob(&claim)?;
                return Ok(AcceptanceDecision::InFlight(parse_acceptance_claim(
                    payload,
                    request.binding_sha256(plan),
                    self.trust_epoch,
                    self.revocation_epoch,
                    self.config_sha256,
                    self.provider_measurement_sha256,
                )?));
            }
            let randomness =
                self.random_digest_bounded("acceptance-fence-entropy")?;
            let fence = u64::from_be_bytes(
                randomness[0..8]
                    .try_into()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "acceptance fence conversion failed",
                        )
                    })?,
            ) | 1;
            let generation = 1;
            let request_binding_sha256 = request.binding_sha256(plan);
            let mut identity_input = Vec::new();
            identity_input.extend_from_slice(b"catchplate/acceptance-identity/v11\0");
            identity_input.extend_from_slice(&request_binding_sha256);
            identity_input.extend_from_slice(&fence.to_be_bytes());
            identity_input.extend_from_slice(&randomness);
            let identity_sha256 = sha256(&identity_input);
            let payload = acceptance_claim_payload(
                request_binding_sha256,
                fence,
                identity_sha256,
                generation,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            );
            let signed = self.sign_blob(&payload)?;
            if !self.create_state_exclusive_bounded(
                self.state.acceptance.as_raw_fd(),
                &claim_name,
                &signed,
            )? {
                if let Some(receipt) = self.read_optional_state_bounded(
                    self.state.acceptance.as_raw_fd(),
                    &receipt_name,
                )?
                {
                    let lease = self.load_current_acceptance_lease(plan, request)?;
                    self.verify_receipt_for_request(
                        &receipt,
                        lane,
                        request,
                        &lease,
                    )?;
                    return Ok(AcceptanceDecision::Replay(receipt));
                }
                let claim = self.read_required_state_bounded(
                    self.state.acceptance.as_raw_fd(),
                    &claim_name,
                )?;
                let payload = self.verify_blob(&claim)?;
                return Ok(AcceptanceDecision::InFlight(parse_acceptance_claim(
                    payload,
                    request_binding_sha256,
                    self.trust_epoch,
                    self.revocation_epoch,
                    self.config_sha256,
                    self.provider_measurement_sha256,
                )?));
            }
            let readback = self.read_required_state_bounded(
                self.state.acceptance.as_raw_fd(),
                &claim_name,
            )?;
            let verified = self.verify_blob(&readback)?;
            if verified != payload {
                return Err(ControllerError::Rejected(
                    "acceptance claim readback differs from signed claim",
                ));
            }
            let lease = parse_acceptance_claim(
                verified,
                request_binding_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?;
            Ok(AcceptanceDecision::New(lease))
        }

        fn commit_acceptance_receipt(
            &self,
            request: &RequestContext,
            lease: &VerifiedAcceptanceLease,
            expected: &ControllerReceiptBody,
            receipt: &[u8],
        ) -> Result<Vec<u8>> {
            let current =
                self.load_current_acceptance_lease(expected.lane.plan, request)?;
            if current.fence != lease.fence
                || current.identity_sha256 != lease.identity_sha256
                || current.generation != lease.generation
                || current.claim_sha256 != lease.claim_sha256
            {
                return Err(ControllerError::Rejected(
                    "acceptance lease changed before durable receipt commit",
                ));
            }
            self.verify_exact_receipt(receipt, request, lease, expected)?;
            let name = format!("{}.receipt", digest_hex(&request.request_id));
            if self.create_state_exclusive_bounded(
                self.state.acceptance.as_raw_fd(),
                &name,
                receipt,
            )? {
                let committed = self.read_required_state_bounded(
                    self.state.acceptance.as_raw_fd(),
                    &name,
                )?;
                self.verify_exact_receipt(&committed, request, lease, expected)?;
                return Ok(committed);
            }
            let committed =
                self.read_required_state_bounded(self.state.acceptance.as_raw_fd(), &name)?;
            self.verify_exact_receipt(&committed, request, lease, expected)?;
            Ok(committed)
        }

        fn reserve_build(
            &self,
            source_sha256: Digest,
            build_command_sha256: Digest,
        ) -> Result<BuildDecision> {
            let stem = digest_hex(&source_sha256);
            let success_name = format!("{stem}.success");
            if let Some(success) = self.read_optional_state_bounded(
                self.state.builds.as_raw_fd(),
                &success_name,
            )?
            {
                return Ok(BuildDecision::Existing(self.parse_build_success(
                    source_sha256,
                    build_command_sha256,
                    &success,
                )?));
            }
            let terminal_name = format!("{stem}.terminal");
            if let Some(terminal) = self.read_optional_state_bounded(
                self.state.builds.as_raw_fd(),
                &terminal_name,
            )? {
                let reservation_name = format!("{stem}.reservation");
                let reservation = self.read_required_state_bounded(
                    self.state.builds.as_raw_fd(),
                    &reservation_name,
                )?;
                let payload = self.verify_blob(&reservation)?;
                let reservation = parse_build_reservation(
                    payload,
                    source_sha256,
                    build_command_sha256,
                    self.trust_epoch,
                    self.revocation_epoch,
                    self.config_sha256,
                    self.provider_measurement_sha256,
                )?;
                return Ok(BuildDecision::Terminal(
                    self.parse_build_terminal(&reservation, &terminal)?,
                ));
            }
            let reservation_name = format!("{stem}.reservation");
            if let Some(reservation) = self.read_optional_state_bounded(
                self.state.builds.as_raw_fd(),
                &reservation_name,
            )? {
                let payload = self.verify_blob(&reservation)?;
                return Ok(BuildDecision::InFlight(parse_build_reservation(
                    payload,
                    source_sha256,
                    build_command_sha256,
                    self.trust_epoch,
                    self.revocation_epoch,
                    self.config_sha256,
                    self.provider_measurement_sha256,
                )?));
            }
            let randomness =
                self.random_digest_bounded("build-reservation-fence-entropy")?;
            let fence = u64::from_be_bytes(
                randomness[0..8]
                    .try_into()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "build fence conversion failed",
                        )
                    })?,
            ) | 1;
            let generation = 1;
            let mut identity_input = Vec::new();
            identity_input.extend_from_slice(b"catchplate/build-reservation/v11\0");
            identity_input.extend_from_slice(&source_sha256);
            identity_input.extend_from_slice(&build_command_sha256);
            identity_input.extend_from_slice(&fence.to_be_bytes());
            identity_input.extend_from_slice(&randomness);
            let identity_sha256 = sha256(&identity_input);
            let payload = build_reservation_payload(
                source_sha256,
                build_command_sha256,
                fence,
                identity_sha256,
                generation,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            );
            let signed = self.sign_blob(&payload)?;
            if !self.create_state_exclusive_bounded(
                self.state.builds.as_raw_fd(),
                &reservation_name,
                &signed,
            )? {
                let reservation = self.read_required_state_bounded(
                    self.state.builds.as_raw_fd(),
                    &reservation_name,
                )?;
                let payload = self.verify_blob(&reservation)?;
                return Ok(BuildDecision::InFlight(parse_build_reservation(
                    payload,
                    source_sha256,
                    build_command_sha256,
                    self.trust_epoch,
                    self.revocation_epoch,
                    self.config_sha256,
                    self.provider_measurement_sha256,
                )?));
            }
            let readback = self.read_required_state_bounded(
                self.state.builds.as_raw_fd(),
                &reservation_name,
            )?;
            let verified = self.verify_blob(&readback)?;
            if verified != payload {
                return Err(ControllerError::Rejected(
                    "build reservation readback differs from signed reservation",
                ));
            }
            Ok(BuildDecision::Reserved(parse_build_reservation(
                verified,
                source_sha256,
                build_command_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?))
        }

        fn commit_build_success(
            &self,
            reservation: &VerifiedBuildReservation,
            artifact_closure_sha256: Digest,
        ) -> Result<CommittedBuildRecord> {
            self.reverify_current_build_reservation(reservation)?;
            let payload = build_success_payload(
                reservation,
                artifact_closure_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            );
            let signed = self.sign_blob(&payload)?;
            let name = format!("{}.success", digest_hex(&reservation.source_sha256));
            if !self.create_state_exclusive_bounded(
                self.state.builds.as_raw_fd(),
                &name,
                &signed,
            )? {
                let existing =
                    self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
                return self.parse_build_success(
                    reservation.source_sha256,
                    reservation.original_build_command_sha256,
                    &existing,
                );
            }
            let readback =
                self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
            let committed = self.parse_build_success(
                reservation.source_sha256,
                reservation.original_build_command_sha256,
                &readback,
            )?;
            if committed.reservation.fence != reservation.fence
                || committed.reservation.identity_sha256 != reservation.identity_sha256
                || committed.reservation.generation != reservation.generation
            {
                return Err(ControllerError::Rejected(
                    "committed build success does not exact-bind current reservation",
                ));
            }
            Ok(committed)
        }

        fn commit_build_terminal(
            &self,
            reservation: &VerifiedBuildReservation,
            terminal: ReceiptTerminal,
            evidence_sha256: Digest,
        ) -> Result<CommittedBuildTerminal> {
            if terminal == ReceiptTerminal::Success
                || evidence_sha256 == [0; 32]
            {
                return Err(ControllerError::Rejected(
                    "build terminal CAS requires exact Failure/Unknown evidence",
                ));
            }
            self.reverify_current_build_reservation(reservation)?;
            let mut payload = Vec::new();
            payload.extend_from_slice(b"SWBTERM1");
            payload.push(terminal as u8);
            payload.extend_from_slice(&reservation.record_sha256);
            payload.extend_from_slice(&reservation.fence.to_be_bytes());
            payload.extend_from_slice(&reservation.identity_sha256);
            payload.extend_from_slice(&reservation.generation.to_be_bytes());
            payload.extend_from_slice(&evidence_sha256);
            payload.extend_from_slice(&self.trust_epoch.to_be_bytes());
            payload.extend_from_slice(&self.revocation_epoch.to_be_bytes());
            let signed = self.sign_blob(&payload)?;
            let name = format!("{}.terminal", digest_hex(&reservation.source_sha256));
            if !self.create_state_exclusive_bounded(
                self.state.builds.as_raw_fd(),
                &name,
                &signed,
            )? {
                let existing =
                    self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
                if existing != signed {
                    return Err(ControllerError::Rejected(
                        "committed build terminal differs from current terminal",
                    ));
                }
            }
            let committed =
                self.read_required_state_bounded(
                    self.state.builds.as_raw_fd(),
                    &name,
                )?;
            self.parse_build_terminal(reservation, &committed)
        }

        fn parse_build_terminal(
            &self,
            reservation: &VerifiedBuildReservation,
            signed: &[u8],
        ) -> Result<CommittedBuildTerminal> {
            let payload = self.verify_blob(signed)?;
            if payload.len() != 137 || &payload[0..8] != b"SWBTERM1" {
                return Err(ControllerError::Rejected(
                    "invalid committed build terminal",
                ));
            }
            let terminal = match payload[8] {
                value if value == ReceiptTerminal::Failure as u8 => {
                    ReceiptTerminal::Failure
                }
                value if value == ReceiptTerminal::Unknown as u8 => {
                    ReceiptTerminal::Unknown
                }
                _ => {
                    return Err(ControllerError::Rejected(
                        "committed build terminal lost Failure/Unknown fidelity",
                    ))
                }
            };
            let evidence_sha256 = copy_digest_at(payload, 89)?;
            if copy_digest_at(payload, 9)? != reservation.record_sha256
                || read_u64_at(payload, 41)? != reservation.fence
                || copy_digest_at(payload, 49)?
                    != reservation.identity_sha256
                || read_u64_at(payload, 81)? != reservation.generation
                || evidence_sha256 == [0; 32]
                || read_u64_at(payload, 121)? != self.trust_epoch
                || read_u64_at(payload, 129)? != self.revocation_epoch
            {
                return Err(ControllerError::Rejected(
                    "committed build terminal does not exact-bind the current reservation",
                ));
            }
            self.reverify_current_build_reservation(reservation)?;
            Ok(CommittedBuildTerminal {
                reservation: reservation.clone(),
                terminal,
                evidence_sha256,
                commit_sha256: sha256(payload),
            })
        }

        fn require_build_success(
            &self,
            source_sha256: Digest,
            build_command_sha256: Digest,
        ) -> Result<CommittedBuildRecord> {
            let name = format!("{}.success", digest_hex(&source_sha256));
            let bytes =
                self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
            self.parse_build_success(source_sha256, build_command_sha256, &bytes)
        }

        fn current_build_binding_if_any(
            &self,
            source_sha256: Digest,
            build_command_sha256: Digest,
            terminal_evidence_sha256: Digest,
        ) -> Result<Option<CommittedBuildRecord>> {
            let success_name = format!("{}.success", digest_hex(&source_sha256));
            if let Some(success) = self.read_optional_state_bounded(
                self.state.builds.as_raw_fd(),
                &success_name,
            )?
            {
                return self
                    .parse_build_success(
                        source_sha256,
                        build_command_sha256,
                        &success,
                    )
                    .map(Some);
            }
            let reservation_name =
                format!("{}.reservation", digest_hex(&source_sha256));
            let Some(reservation) = self.read_optional_state_bounded(
                self.state.builds.as_raw_fd(),
                &reservation_name,
            )? else {
                return Ok(None);
            };
            let payload = self.verify_blob(&reservation)?;
            let reservation = parse_build_reservation(
                payload,
                source_sha256,
                build_command_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?;
            self.reverify_current_build_reservation(&reservation)?;
            let terminal_name =
                format!("{}.terminal", digest_hex(&source_sha256));
            let terminal = if let Some(existing) =
                self.read_optional_state_bounded(
                    self.state.builds.as_raw_fd(),
                    &terminal_name,
                )?
            {
                self.parse_build_terminal(&reservation, &existing)?
            } else {
                self.commit_build_terminal(
                    &reservation,
                    ReceiptTerminal::Unknown,
                    terminal_evidence_sha256,
                )?
            };
            Ok(Some(CommittedBuildRecord {
                reservation: terminal.reservation,
                artifact_closure_sha256: [0; 32],
                commit_sha256: terminal.commit_sha256,
            }))
        }

        fn parse_build_success(
            &self,
            source_sha256: Digest,
            build_command_sha256: Digest,
            signed: &[u8],
        ) -> Result<CommittedBuildRecord> {
            let payload = self.verify_blob(signed)?;
            let record = parse_build_success(
                payload,
                source_sha256,
                build_command_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?;
            self.reverify_current_build_reservation(&record.reservation)?;
            Ok(record)
        }

        fn reverify_current_build_reservation(
            &self,
            expected: &VerifiedBuildReservation,
        ) -> Result<()> {
            let name = format!("{}.reservation", digest_hex(&expected.source_sha256));
            let bytes =
                self.read_required_state_bounded(self.state.builds.as_raw_fd(), &name)?;
            let payload = self.verify_blob(&bytes)?;
            let current = parse_build_reservation(
                payload,
                expected.source_sha256,
                expected.original_build_command_sha256,
                self.trust_epoch,
                self.revocation_epoch,
                self.config_sha256,
                self.provider_measurement_sha256,
            )?;
            if current.fence != expected.fence
                || current.identity_sha256 != expected.identity_sha256
                || current.generation != expected.generation
                || current.record_sha256 != expected.record_sha256
            {
                return Err(ControllerError::Rejected(
                    "current build reservation fence/identity/generation changed",
                ));
            }
            Ok(())
        }
    }

    fn acceptance_claim_payload(
        request_binding_sha256: Digest,
        fence: u64,
        identity_sha256: Digest,
        generation: u64,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SWACPT11");
        payload.extend_from_slice(&request_binding_sha256);
        payload.extend_from_slice(&fence.to_be_bytes());
        payload.extend_from_slice(&identity_sha256);
        payload.extend_from_slice(&generation.to_be_bytes());
        payload.extend_from_slice(&trust_epoch.to_be_bytes());
        payload.extend_from_slice(&revocation_epoch.to_be_bytes());
        payload.extend_from_slice(&config_sha256);
        payload.extend_from_slice(&provider_sha256);
        payload
    }

    fn parse_acceptance_claim(
        payload: &[u8],
        expected_binding: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Result<VerifiedAcceptanceLease> {
        if payload.len() != 168 || &payload[0..8] != b"SWACPT11" {
            return Err(ControllerError::Rejected("invalid acceptance claim"));
        }
        let request_binding_sha256 = copy_digest_at(payload, 8)?;
        let fence = read_u64_at(payload, 40)?;
        let identity_sha256 = copy_digest_at(payload, 48)?;
        let generation = read_u64_at(payload, 80)?;
        if request_binding_sha256 != expected_binding
            || fence == 0
            || identity_sha256 == [0; 32]
            || generation == 0
            || read_u64_at(payload, 88)? != trust_epoch
            || read_u64_at(payload, 96)? != revocation_epoch
            || copy_digest_at(payload, 104)? != config_sha256
            || copy_digest_at(payload, 136)? != provider_sha256
        {
            return Err(ControllerError::Rejected(
                "acceptance claim trust/revocation/fence binding is invalid",
            ));
        }
        Ok(VerifiedAcceptanceLease {
            fence,
            identity_sha256,
            generation,
            claim_sha256: sha256(payload),
            request_binding_sha256,
        })
    }

    fn build_reservation_payload(
        source_sha256: Digest,
        build_command_sha256: Digest,
        fence: u64,
        identity_sha256: Digest,
        generation: u64,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SWBRES11");
        payload.extend_from_slice(&source_sha256);
        payload.extend_from_slice(&build_command_sha256);
        payload.extend_from_slice(&fence.to_be_bytes());
        payload.extend_from_slice(&identity_sha256);
        payload.extend_from_slice(&generation.to_be_bytes());
        payload.extend_from_slice(&trust_epoch.to_be_bytes());
        payload.extend_from_slice(&revocation_epoch.to_be_bytes());
        payload.extend_from_slice(&config_sha256);
        payload.extend_from_slice(&provider_sha256);
        payload
    }

    fn parse_build_reservation(
        payload: &[u8],
        expected_source: Digest,
        expected_command: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Result<VerifiedBuildReservation> {
        if payload.len() != 200 || &payload[0..8] != b"SWBRES11" {
            return Err(ControllerError::Rejected("invalid build reservation"));
        }
        let source_sha256 = copy_digest_at(payload, 8)?;
        let original_build_command_sha256 = copy_digest_at(payload, 40)?;
        let fence = read_u64_at(payload, 72)?;
        let identity_sha256 = copy_digest_at(payload, 80)?;
        let generation = read_u64_at(payload, 112)?;
        if source_sha256 != expected_source
            || original_build_command_sha256 != expected_command
            || fence == 0
            || identity_sha256 == [0; 32]
            || generation == 0
            || read_u64_at(payload, 120)? != trust_epoch
            || read_u64_at(payload, 128)? != revocation_epoch
            || copy_digest_at(payload, 136)? != config_sha256
            || copy_digest_at(payload, 168)? != provider_sha256
        {
            return Err(ControllerError::Rejected(
                "build reservation trust/revocation/fence binding is invalid",
            ));
        }
        Ok(VerifiedBuildReservation {
            fence,
            identity_sha256,
            generation,
            source_sha256,
            original_build_command_sha256,
            record_sha256: sha256(payload),
        })
    }

    fn build_success_payload(
        reservation: &VerifiedBuildReservation,
        artifact_closure_sha256: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SWBSUC11");
        payload.extend_from_slice(&reservation.record_sha256);
        payload.extend_from_slice(&reservation.source_sha256);
        payload.extend_from_slice(&reservation.original_build_command_sha256);
        payload.extend_from_slice(&reservation.fence.to_be_bytes());
        payload.extend_from_slice(&reservation.identity_sha256);
        payload.extend_from_slice(&reservation.generation.to_be_bytes());
        payload.extend_from_slice(&artifact_closure_sha256);
        payload.extend_from_slice(&trust_epoch.to_be_bytes());
        payload.extend_from_slice(&revocation_epoch.to_be_bytes());
        payload.extend_from_slice(&config_sha256);
        payload.extend_from_slice(&provider_sha256);
        payload
    }

    fn parse_build_success(
        payload: &[u8],
        expected_source: Digest,
        expected_command: Digest,
        trust_epoch: u64,
        revocation_epoch: u64,
        config_sha256: Digest,
        provider_sha256: Digest,
    ) -> Result<CommittedBuildRecord> {
        if payload.len() != 264 || &payload[0..8] != b"SWBSUC11" {
            return Err(ControllerError::Rejected("invalid committed build success"));
        }
        let record_sha256 = copy_digest_at(payload, 8)?;
        let source_sha256 = copy_digest_at(payload, 40)?;
        let original_build_command_sha256 = copy_digest_at(payload, 72)?;
        let fence = read_u64_at(payload, 104)?;
        let identity_sha256 = copy_digest_at(payload, 112)?;
        let generation = read_u64_at(payload, 144)?;
        let artifact_closure_sha256 = copy_digest_at(payload, 152)?;
        if source_sha256 != expected_source
            || original_build_command_sha256 != expected_command
            || fence == 0
            || identity_sha256 == [0; 32]
            || generation == 0
            || artifact_closure_sha256 == [0; 32]
            || read_u64_at(payload, 184)? != trust_epoch
            || read_u64_at(payload, 192)? != revocation_epoch
            || copy_digest_at(payload, 200)? != config_sha256
            || copy_digest_at(payload, 232)? != provider_sha256
        {
            return Err(ControllerError::Rejected(
                "committed build success binding is invalid",
            ));
        }
        let reservation = VerifiedBuildReservation {
            fence,
            identity_sha256,
            generation,
            source_sha256,
            original_build_command_sha256,
            record_sha256,
        };
        let expected_record = build_reservation_payload(
            source_sha256,
            original_build_command_sha256,
            fence,
            identity_sha256,
            generation,
            trust_epoch,
            revocation_epoch,
            config_sha256,
            provider_sha256,
        );
        if sha256(&expected_record) != record_sha256 {
            return Err(ControllerError::Rejected(
                "committed build success reservation digest is invalid",
            ));
        }
        Ok(CommittedBuildRecord {
            reservation,
            artifact_closure_sha256,
            commit_sha256: sha256(payload),
        })
    }

    fn copy_digest_at(bytes: &[u8], offset: usize) -> Result<Digest> {
        if offset.checked_add(32).map_or(true, |end| end > bytes.len()) {
            return Err(ControllerError::Invalid("digest offset exceeds record"));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[offset..offset + 32]);
        Ok(digest)
    }

    fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
        if offset.checked_add(8).map_or(true, |end| end > bytes.len()) {
            return Err(ControllerError::Invalid("integer offset exceeds record"));
        }
        Ok(u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| ControllerError::Invalid("invalid integer record"))?,
        ))
    }

    fn random_digest_worker_only() -> Result<Digest> {
        let mut bytes = [0u8; 32];
        let count = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes.as_mut_ptr(),
                bytes.len(),
                0,
            )
        };
        if count != bytes.len() as libc::c_long {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(bytes)
    }

    fn state_name_c(name: &str) -> Result<CString> {
        if name.is_empty()
            || name.len() > 160
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        {
            return Err(ControllerError::Invalid("state filename is unsafe"));
        }
        CString::new(name).map_err(|_| ControllerError::Invalid("state filename contains NUL"))
    }

    fn create_state_file_exclusive(directory: RawFd, name: &str, bytes: &[u8]) -> Result<bool> {
        if bytes.len() as u64 > STATE_RECORD_MAX_BYTES {
            return Err(ControllerError::Rejected("state record exceeds bound"));
        }
        let name = state_name_c(name)?;
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                return Ok(false);
            }
            return Err(error.into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.sync_all()?;
        if unsafe { libc::fsync(directory) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(true)
    }

    fn read_optional_state_file(directory: RawFd, name: &str) -> Result<Option<Vec<u8>>> {
        let name = state_name_c(name)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory,
                name.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(error.into());
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() > STATE_RECORD_MAX_BYTES
        {
            return Err(ControllerError::Rejected("state record identity is unsafe"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(STATE_RECORD_MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(ControllerError::Rejected("state record changed during read"));
        }
        Ok(Some(bytes))
    }

    fn read_required_state_file(directory: RawFd, name: &str) -> Result<Vec<u8>> {
        read_optional_state_file(directory, name)?
            .ok_or(ControllerError::Rejected("required durable state record is absent"))
    }

    fn require_immutable_state_file(directory: RawFd, name: &str) -> Result<()> {
        let name = state_name_c(name)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory,
                name.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut flags: libc::c_uint = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) } != 0
            || flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "evidence record lacks filesystem immutable protection",
            ));
        }
        Ok(())
    }

    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    struct RegisteredChild {
        pid: libc::pid_t,
        pidfd: OwnedFd,
        process_group: libc::pid_t,
        cgroup_directory: OwnedFd,
        cgroup_name: CString,
        barrier: Option<OwnedFd>,
        output: OwnedFd,
        start_time_ticks: u64,
    }

    struct ActionOutcome {
        wait_status: i32,
        output: Vec<u8>,
        timed_out: bool,
        cleanup_proved: bool,
    }

    struct RegisteredWatchdog {
        child: RegisteredChild,
        control: OwnedFd,
        acknowledgement: OwnedFd,
        armed_journal_name: String,
        closure_journal_name: String,
        armed_record_sha256: Digest,
    }

    struct LaneIoDeadlineGuard<'a> {
        io_slot: &'a Mutex<Option<Instant>>,
        cleanup_slot: &'a Mutex<Option<Instant>>,
    }

    struct QuarantineGuard<'a> {
        active: &'a AtomicBool,
    }

    struct ExecutionQueuePermit<'a> {
        queued: &'a AtomicUsize,
    }

    impl Drop for ExecutionQueuePermit<'_> {
        fn drop(&mut self) {
            self.queued.fetch_sub(1, Ordering::AcqRel);
        }
    }

    impl Drop for LaneIoDeadlineGuard<'_> {
        fn drop(&mut self) {
            if let Ok(mut deadline) = self.io_slot.lock() {
                *deadline = None;
            }
            if let Ok(mut deadline) = self.cleanup_slot.lock() {
                *deadline = None;
            }
        }
    }

    impl Drop for QuarantineGuard<'_> {
        fn drop(&mut self) {
            self.active.store(false, Ordering::Release);
        }
    }

    struct ExecutionOutcome {
        terminal: ReceiptTerminal,
        exit_status: i32,
        evidence_sha256: Digest,
        reason: String,
    }

    struct PinnedDirectSupervisorVerifier {
        registration_binding_sha256: Digest,
        shared_state_machine_identity_sha256: Digest,
        shared_state_machine_measurement_reference_sha256: Digest,
        request_sha256: Digest,
        config_sha256: Digest,
        fixed_plan_manifest_sha256: Digest,
        current_lane_command_identity_sha256: Digest,
        deadline_unix_ms: u64,
        registered_child_identity_reference_sha256: Digest,
        child_held_reference_sha256: Digest,
        pidfd_identity_reference_sha256: Digest,
        cgroup_identity_reference_sha256: Digest,
        controller_parent_reaper_reference_sha256: Digest,
        independent_watchdog_reference_sha256: Digest,
        durable_orphan_journal_reference_sha256: Digest,
    }

    impl PinnedTrustedHostDirectSupervisorVerifier
        for PinnedDirectSupervisorVerifier
    {
        fn verify_direct_registration(
            &self,
            registration: &RawTrustedHostDirectSupervisorRegistration,
            shared_state_machine_identity_sha256: Digest,
            shared_state_machine_measurement: &EvidenceReference,
        ) -> Result<NativeTrustedHostDirectSupervisorDecision> {
            let exact_opaque_registration =
                registration.registration_binding_sha256
                    == self.registration_binding_sha256
                    && registration.registration_binding_sha256
                        == trusted_host_direct_supervisor_registration_sha256(
                            registration,
                        )
                    && registration.exact_registration.object_sha256
                        == registration.registration_binding_sha256;
            let measured_shared_state_machine =
                shared_state_machine_identity_sha256
                    == self.shared_state_machine_identity_sha256
                    && shared_state_machine_measurement.reference_sha256
                        == self
                            .shared_state_machine_measurement_reference_sha256
                    && shared_state_machine_measurement.object_sha256
                        == shared_state_machine_identity_sha256;
            let exact_config_manifest_command_and_deadline =
                registration.request_sha256 == self.request_sha256
                    && registration.config_sha256 == self.config_sha256
                    && registration.fixed_plan_manifest_sha256
                        == self.fixed_plan_manifest_sha256
                    && registration.current_lane_command_identity_sha256
                        == self.current_lane_command_identity_sha256
                    && registration.deadline_unix_ms == self.deadline_unix_ms;
            let child_held_before_execution =
                registration.child_held_before_execution.reference_sha256
                    == self.child_held_reference_sha256;
            let registered_child_and_pidfd_identity =
                registration.registered_child_identity.reference_sha256
                    == self.registered_child_identity_reference_sha256
                    && registration.pidfd_identity.reference_sha256
                        == self.pidfd_identity_reference_sha256
                    && registration.cgroup_identity.reference_sha256
                        == self.cgroup_identity_reference_sha256;
            let controller_sole_parent_and_reaper =
                registration.controller_parent_reaper.reference_sha256
                    == self.controller_parent_reaper_reference_sha256;
            let independent_watchdog_non_parent_non_reaper =
                registration.independent_watchdog_authority.reference_sha256
                    == self.independent_watchdog_reference_sha256;
            let durable_orphan_journal_armed =
                registration.durable_orphan_journal.reference_sha256
                    == self.durable_orphan_journal_reference_sha256;
            let no_release_before_authorization =
                child_held_before_execution
                    && registration.child_held_before_execution.object_sha256
                        != [0; 32];
            let mut decision = Vec::new();
            decision.extend_from_slice(
                b"catchplate/pinned-direct-supervisor-decision/v11\0",
            );
            decision.extend_from_slice(
                &registration.registration_binding_sha256,
            );
            decision.extend_from_slice(&shared_state_machine_identity_sha256);
            for value in [
                exact_opaque_registration,
                measured_shared_state_machine,
                exact_config_manifest_command_and_deadline,
                child_held_before_execution,
                registered_child_and_pidfd_identity,
                controller_sole_parent_and_reaper,
                independent_watchdog_non_parent_non_reaper,
                durable_orphan_journal_armed,
                no_release_before_authorization,
            ] {
                decision.push(u8::from(value));
            }
            Ok(NativeTrustedHostDirectSupervisorDecision {
                exact_opaque_registration,
                measured_shared_state_machine,
                exact_config_manifest_command_and_deadline,
                child_held_before_execution,
                registered_child_and_pidfd_identity,
                controller_sole_parent_and_reaper,
                independent_watchdog_non_parent_non_reaper,
                durable_orphan_journal_armed,
                no_release_before_authorization,
                decision_sha256: sha256(&decision),
            })
        }

        fn verify_direct_release(
            &self,
            _gate: &VerifiedTrustedHostDirectSupervisorGate,
            _release: &RawSupervisorReleaseEvidence,
        ) -> Result<NativeTrustedHostDirectReleaseDecision> {
            Err(ControllerError::Unready(vec![
                "trusted-host production uses the shared sealed capability release route"
                    .to_owned(),
            ]))
        }

        fn verify_direct_containment(
            &self,
            _registration: &RawTrustedHostDirectSupervisorRegistration,
            _authorization_sha256: Digest,
            _terminal: &RawContainmentTerminal,
        ) -> Result<NativeContainmentDecision> {
            Err(ControllerError::Unready(vec![
                "trusted-host production uses the shared sealed capability containment route"
                    .to_owned(),
            ]))
        }
    }

    impl TrustedHostProduction {
        fn cleanup_deadline(&self) -> Instant {
            self.cleanup_reserve_deadline
                .lock()
                .ok()
                .and_then(|deadline| *deadline)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(30))
        }

        fn next_action_name(&self, label: &str) -> Result<CString> {
            let sequence = self.action_counter.fetch_add(1, Ordering::AcqRel);
            let label_digest = sha256(label.as_bytes());
            let mut entropy = [0u8; 16];
            let entropy_count = unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    entropy.as_mut_ptr(),
                    entropy.len(),
                    libc::GRND_NONBLOCK,
                )
            };
            if entropy_count != entropy.len() as libc::c_long {
                return Err(ControllerError::Unready(vec![
                    "nonblocking kernel entropy unavailable for collision-resistant action ID"
                        .to_owned(),
                ]));
            }
            let entropy_sha256 = sha256(&entropy);
            CString::new(format!(
                "v11-{}-{}-{sequence}-{}",
                &digest_hex(&self.boot_id_sha256)[..16],
                &digest_hex(&entropy_sha256)[..32],
                &digest_hex(&label_digest)[..16],
            ))
            .map_err(|_| ControllerError::Invalid("action cgroup name contains NUL"))
        }

        fn remove_reserved_cgroup(
            &self,
            name: &CString,
            context: &str,
        ) -> Result<()> {
            if unsafe {
                libc::unlinkat(
                    self.cgroup.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } == 0
            {
                return Ok(());
            }
            let reason = format!("{context}; reserved cgroup removal failed");
            self.quarantine(&reason)?;
            Err(ControllerError::Unready(vec![reason]))
        }

        fn create_action_cgroup(&self, label: &str) -> Result<(CString, OwnedFd)> {
            let name = self.next_action_name(label)?;
            if unsafe { libc::mkdirat(self.cgroup.directory.as_raw_fd(), name.as_ptr(), 0o700) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let how = OpenHow {
                flags: (libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW) as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            };
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    self.cgroup.directory.as_raw_fd(),
                    name.as_ptr(),
                    &how,
                    mem::size_of::<OpenHow>(),
                ) as RawFd
            };
            if raw < 0 {
                let open_error = std::io::Error::last_os_error();
                self.remove_reserved_cgroup(
                    &name,
                    "opening newly created action cgroup failed",
                )?;
                return Err(open_error.into());
            }
            let directory = unsafe { OwnedFd::from_raw_fd(raw) };
            if let Err(error) = verify_root_owned_directory(directory.as_raw_fd(), false) {
                drop(directory);
                self.remove_reserved_cgroup(
                    &name,
                    "new action cgroup ownership verification failed",
                )?;
                return Err(error);
            }
            if let Err(error) = write_control_file(directory.as_raw_fd(), "pids.max", b"4096\n") {
                drop(directory);
                self.remove_reserved_cgroup(
                    &name,
                    "new action cgroup limit installation failed",
                )?;
                return Err(error);
            }
            Ok((name, directory))
        }

        fn cleanup_preclone_reservation(
            &self,
            cgroup_name: &CString,
            cgroup_directory: &OwnedFd,
            reason: &str,
        ) -> Result<()> {
            let mut failures = Vec::new();
            if let Err(error) = write_control_file(
                cgroup_directory.as_raw_fd(),
                "cgroup.kill",
                b"1\n",
            ) {
                failures.push(format!("reserved cgroup.kill: {error}"));
            }
            match read_bounded_control_file(
                cgroup_directory.as_raw_fd(),
                "cgroup.procs",
                4 * 1024 * 1024,
            ) {
                Ok(procs) if procs.iter().all(u8::is_ascii_whitespace) => {}
                Ok(_) => failures.push(
                    "pre-clone reserved cgroup unexpectedly contains a process"
                        .to_owned(),
                ),
                Err(error) => failures.push(format!(
                    "pre-clone reserved cgroup emptiness probe: {error}"
                )),
            }
            if unsafe {
                libc::unlinkat(
                    self.cgroup.directory.as_raw_fd(),
                    cgroup_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                failures.push(format!(
                    "pre-clone reserved cgroup removal: {}",
                    std::io::Error::last_os_error()
                ));
            }
            self.readiness.hard_unready(reason.to_owned());
            if let Err(error) = self.quarantine(reason) {
                failures.push(format!("durable quarantine: {error}"));
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(ControllerError::Unready(vec![format!(
                    "{reason}; {}",
                    failures.join("; ")
                )]))
            }
        }

        fn cleanup_unregistered_child(
            &self,
            cgroup_name: &CString,
            cgroup_directory: &OwnedFd,
            pid: libc::pid_t,
            pidfd: Option<&OwnedFd>,
        ) -> Result<()> {
            let mut failures = Vec::<String>::new();
            if let Some(pidfd) = pidfd {
                match pidfd_identity(pidfd.as_raw_fd()) {
                    Ok(identity) if identity == format!("pid:{pid}") => {}
                    Ok(identity) => failures.push(format!(
                        "pidfd identity mismatch: expected pid:{pid}, observed {identity}"
                    )),
                    Err(error) => failures.push(format!(
                        "pidfd identity probe failed: {error}"
                    )),
                }
                if let Err(error) = pidfd_poll_live(pidfd.as_raw_fd()) {
                    failures.push(format!("pidfd liveness probe failed: {error}"));
                }
                let observed_pgid = unsafe { libc::getpgid(pid) };
                let process_group_identity_proved = if observed_pgid < 0 {
                    let error = std::io::Error::last_os_error();
                    failures.push(format!(
                        "process-group identity probe failed: {error}"
                    ));
                    false
                } else if observed_pgid != pid {
                    failures.push(format!(
                        "process-group identity mismatch: expected {pid}, observed {observed_pgid}"
                    ));
                    false
                } else {
                    true
                };
                if process_group_identity_proved
                    && unsafe { libc::killpg(pid, libc::SIGKILL) } != 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        failures.push(format!("process-group kill failed: {error}"));
                    }
                }
                if let Err(error) =
                    signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL)
                {
                    failures.push(format!("pidfd kill failed: {error}"));
                }
            } else {
                let observed_pgid = unsafe { libc::getpgid(pid) };
                let process_group_identity_proved = if observed_pgid < 0 {
                    failures.push(format!(
                        "process-group identity probe before pidfd registration failed: {}",
                        std::io::Error::last_os_error()
                    ));
                    false
                } else if observed_pgid != pid {
                    failures.push(format!(
                        "process-group identity mismatch before pidfd registration: expected {pid}, observed {observed_pgid}"
                    ));
                    false
                } else {
                    true
                };
                if process_group_identity_proved
                    && unsafe { libc::killpg(pid, libc::SIGKILL) } != 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        failures.push(format!(
                            "process-group kill before pidfd registration failed: {error}"
                        ));
                    }
                }
                if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        failures.push(format!(
                            "PID kill before pidfd registration failed: {error}"
                        ));
                    }
                }
            }
            if let Err(error) =
                write_control_file(cgroup_directory.as_raw_fd(), "cgroup.kill", b"1\n")
            {
                failures.push(format!("cgroup.kill failed: {error}"));
            }
            match reap_pid_bounded(pid, self.cleanup_deadline()) {
                Ok(Some(_)) => {}
                Ok(None) => failures.push(
                    "bounded child reap returned no owned child status".to_owned(),
                ),
                Err(error) => failures.push(format!(
                    "bounded child reap failed: {error}"
                )),
            }
            if unsafe {
                libc::unlinkat(
                    self.cgroup.directory.as_raw_fd(),
                    cgroup_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                failures.push(format!(
                    "cgroup quarantine removal failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if failures.is_empty() {
                self.quarantine(
                    "child registration failed after clone3; cleanup was proved",
                )?;
                return Ok(());
            }
            let reason = format!(
                "unregistered child cleanup was unproved: {}",
                failures.join(", ")
            );
            self.readiness.hard_unready(reason.clone());
            self.quarantine(&reason)?;
            Err(ControllerError::Unready(vec![reason]))
        }

        fn spawn_registered<F>(&self, label: &str, child_body: F) -> Result<RegisteredChild>
        where
            F: FnOnce(RawFd) -> i32,
        {
            self.spawn_registered_with_policy(label, true, child_body)
        }

        fn spawn_registered_with_policy<F>(
            &self,
            label: &str,
            parent_death_signal: bool,
            child_body: F,
        ) -> Result<RegisteredChild>
        where
            F: FnOnce(RawFd) -> i32,
        {
            self.spawn_registered_with_namespaces(
                label,
                parent_death_signal,
                false,
                true,
                child_body,
            )
        }

        fn spawn_registered_active<F>(
            &self,
            label: &str,
            child_body: F,
        ) -> Result<RegisteredChild>
        where
            F: FnOnce(RawFd) -> i32,
        {
            self.spawn_registered_with_namespaces(
                label,
                false,
                false,
                false,
                child_body,
            )
        }

        fn spawn_registered_isolated<F>(
            &self,
            label: &str,
            child_body: F,
        ) -> Result<RegisteredChild>
        where
            F: FnOnce(RawFd) -> i32,
        {
            self.spawn_registered_with_namespaces(
                label,
                true,
                true,
                true,
                child_body,
            )
        }

        fn spawn_registered_with_namespaces<F>(
            &self,
            label: &str,
            parent_death_signal: bool,
            isolated_identity_namespaces: bool,
            start_held: bool,
            child_body: F,
        ) -> Result<RegisteredChild>
        where
            F: FnOnce(RawFd) -> i32,
        {
            let (cgroup_name, cgroup_directory) =
                match self.create_action_cgroup(label) {
                    Ok(cgroup) => cgroup,
                    Err(error) => {
                        let reason = format!(
                            "{label} cgroup reservation failed before clone3: {error}"
                        );
                        self.readiness.hard_unready(reason.clone());
                        if !self.quarantine_active.load(Ordering::Acquire) {
                            self.quarantine(&reason)?;
                        }
                        return Err(error);
                    }
                };
            let (output_read, output_write) = match pipe_cloexec() {
                Ok(pipe) => pipe,
                Err(error) => {
                    let reason = format!(
                        "{label} output-pipe allocation failed after cgroup reservation: {error}"
                    );
                    self.cleanup_preclone_reservation(
                        &cgroup_name,
                        &cgroup_directory,
                        &reason,
                    )?;
                    return Err(error);
                }
            };
            let (barrier_read, barrier_write) = match pipe_cloexec() {
                Ok(pipe) => pipe,
                Err(error) => {
                    let reason = format!(
                        "{label} barrier-pipe allocation failed after cgroup reservation: {error}"
                    );
                    self.cleanup_preclone_reservation(
                        &cgroup_name,
                        &cgroup_directory,
                        &reason,
                    )?;
                    return Err(error);
                }
            };
            let mut pidfd_raw: RawFd = -1;
            let mut arguments = CloneArgs {
                flags: CLONE_PIDFD_FLAG
                    | if isolated_identity_namespaces {
                        libc::CLONE_NEWPID as u64 | libc::CLONE_NEWUSER as u64
                    } else {
                        0
                    },
                pidfd: (&mut pidfd_raw as *mut RawFd) as u64,
                exit_signal: libc::SIGCHLD as u64,
                ..CloneArgs::default()
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    &mut arguments,
                    mem::size_of::<CloneArgs>(),
                ) as libc::pid_t
            };
            if result < 0 {
                let clone_error = std::io::Error::last_os_error();
                let removed = unsafe {
                    libc::unlinkat(
                        self.cgroup.directory.as_raw_fd(),
                        cgroup_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                } == 0;
                let reason = if removed {
                    format!("clone3 launch failed before child creation: {clone_error}")
                } else {
                    format!(
                        "clone3 launch failed and its reserved cgroup could not be removed: {clone_error}"
                    )
                };
                self.readiness.hard_unready(reason.clone());
                self.quarantine(&reason)?;
                return Err(clone_error.into());
            }
            if result == 0 {
                unsafe {
                    libc::close(output_read.as_raw_fd());
                    libc::close(barrier_write.as_raw_fd());
                    if libc::setpgid(0, 0) != 0
                        || (parent_death_signal
                            && libc::prctl(
                                libc::PR_SET_PDEATHSIG,
                                libc::SIGKILL,
                                0,
                                0,
                                0,
                            ) != 0)
                        || (parent_death_signal && libc::getppid() == 1)
                    {
                        libc::_exit(125);
                    }
                    let mut release = [0u8; 1];
                    loop {
                        let count = libc::read(
                            barrier_read.as_raw_fd(),
                            release.as_mut_ptr() as *mut libc::c_void,
                            1,
                        );
                        if count == 1 || (!start_held && count == 0) {
                            break;
                        }
                        if count < 0
                            && std::io::Error::last_os_error().raw_os_error()
                                == Some(libc::EINTR)
                        {
                            continue;
                        }
                        libc::_exit(125);
                    }
                    libc::close(barrier_read.as_raw_fd());
                    let code = child_body(output_write.as_raw_fd());
                    libc::_exit(code);
                }
            }
            drop(output_write);
            drop(barrier_read);
            if pidfd_raw < 0 {
                self.cleanup_unregistered_child(
                    &cgroup_name,
                    &cgroup_directory,
                    result,
                    None,
                )?;
                return Err(ControllerError::Rejected(
                    "clone3 did not return an authoritative pidfd",
                ));
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
            let joined_identity = pidfd_identity(pidfd.as_raw_fd());
            if joined_identity
                .as_ref()
                .map(|identity| identity != &format!("pid:{result}"))
                .unwrap_or(true)
            {
                self.cleanup_unregistered_child(
                    &cgroup_name,
                    &cgroup_directory,
                    result,
                    Some(&pidfd),
                )?;
                return Err(ControllerError::Rejected(
                    "clone3 pidfd does not identify direct child",
                ));
            }
            if isolated_identity_namespaces {
                if let Err(error) = install_identity_user_namespace_maps(result) {
                    self.cleanup_unregistered_child(
                        &cgroup_name,
                        &cgroup_directory,
                        result,
                        Some(&pidfd),
                    )?;
                    return Err(error);
                }
            }
            if unsafe { libc::setpgid(result, result) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EACCES) {
                    self.cleanup_unregistered_child(
                        &cgroup_name,
                        &cgroup_directory,
                        result,
                        Some(&pidfd),
                    )?;
                    return Err(error.into());
                }
            }
            if let Err(error) = write_control_file(
                cgroup_directory.as_raw_fd(),
                "cgroup.procs",
                format!("{result}\n").as_bytes(),
            ) {
                self.cleanup_unregistered_child(
                    &cgroup_name,
                    &cgroup_directory,
                    result,
                    Some(&pidfd),
                )?;
                return Err(error);
            }
            let cgroup = match read_bounded_control_file(
                cgroup_directory.as_raw_fd(),
                "cgroup.procs",
                64 * 1024,
            ) {
                Ok(cgroup) => cgroup,
                Err(error) => {
                    self.cleanup_unregistered_child(
                        &cgroup_name,
                        &cgroup_directory,
                        result,
                        Some(&pidfd),
                    )?;
                    return Err(error);
                }
            };
            let expected_pid = result.to_string();
            if !std::str::from_utf8(&cgroup)
                .ok()
                .map(|text| text.lines().any(|line| line == expected_pid.as_str()))
                .unwrap_or(false)
            {
                self.cleanup_unregistered_child(
                    &cgroup_name,
                    &cgroup_directory,
                    result,
                    Some(&pidfd),
                )?;
                return Err(ControllerError::Rejected(
                    "direct child did not join its controller-owned cgroup",
                ));
            }
            let start_time_ticks = match proc_start_time_ticks(result) {
                Ok(start) => start,
                Err(error) => {
                    self.cleanup_unregistered_child(
                        &cgroup_name,
                        &cgroup_directory,
                        result,
                        Some(&pidfd),
                    )?;
                    return Err(error);
                }
            };
            let mut registered = RegisteredChild {
                pid: result,
                pidfd,
                process_group: result,
                cgroup_directory,
                cgroup_name,
                barrier: Some(barrier_write),
                output: output_read,
                start_time_ticks,
            };
            if !start_held {
                if let Err(error) = Self::release_child(&mut registered) {
                    let cleanup = self.cleanup_registered_child(
                        &mut registered,
                        None,
                        true,
                        true,
                    );
                    let reason = format!(
                        "{label} active child registration release failed: {error}"
                    );
                    let quarantine = self.quarantine(&reason);
                    return Err(ControllerError::Unready(vec![format!(
                        "{reason}; cleanup={}; quarantine={}",
                        cleanup
                            .err()
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "ok".to_owned()),
                        quarantine
                            .err()
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "ok".to_owned()),
                    )]));
                }
            }
            Ok(registered)
        }

        fn release_child(child: &mut RegisteredChild) -> Result<()> {
            let barrier = child
                .barrier
                .take()
                .ok_or(ControllerError::Rejected("child barrier already released"))?;
            write_all_fd(barrier.as_raw_fd(), b"R")?;
            drop(barrier);
            Ok(())
        }

        fn verify_workload_capability_binding(
            child: &RegisteredChild,
            gate: &VerifiedTrustedHostDirectSupervisorGate,
            expected_held: Option<bool>,
        ) -> Result<()> {
            if gate.authorization_sha256() == [0; 32]
                || gate.registration_binding_sha256() == [0; 32]
            {
                return Err(ControllerError::Rejected(
                    "workload operation lacks a shared verified supervisor capability",
                ));
            }
            if expected_held
                .map(|held| child.barrier.is_some() != held)
                .unwrap_or(false)
            {
                return Err(ControllerError::Rejected(
                    "workload release-barrier phase differs from sealed capability use",
                ));
            }
            let registration = gate.registration();
            let workload_pidfd_identity = format!("pid:{}", child.pid);
            let workload_cgroup_identity =
                directory_identity(child.cgroup_directory.as_raw_fd())?;

            let mut child_identity = Vec::new();
            child_identity.extend_from_slice(
                b"catchplate/direct-registered-child/v11\0",
            );
            child_identity.extend_from_slice(&child.pid.to_be_bytes());
            child_identity
                .extend_from_slice(&child.start_time_ticks.to_be_bytes());
            child_identity
                .extend_from_slice(&child.process_group.to_be_bytes());
            child_identity.extend_from_slice(
                workload_pidfd_identity.as_bytes(),
            );
            append_file_identity(
                &mut child_identity,
                &workload_cgroup_identity,
            );

            let mut cgroup_identity = Vec::new();
            cgroup_identity.extend_from_slice(
                b"catchplate/direct-cgroup/v11\0",
            );
            cgroup_identity.extend_from_slice(child.cgroup_name.as_bytes());
            append_file_identity(
                &mut cgroup_identity,
                &workload_cgroup_identity,
            );

            if sha256(&child_identity)
                    != registration.registered_child_identity.object_sha256
                || sha256(&cgroup_identity)
                    != registration.cgroup_identity.object_sha256
            {
                return Err(ControllerError::Rejected(
                    "private registered workload differs from the sealed supervisor registration",
                ));
            }
            if child.barrier.is_some() {
                let mut held = Vec::new();
                held.extend_from_slice(
                    b"catchplate/direct-held-child/v11\0",
                );
                held.extend_from_slice(&child.pid.to_be_bytes());
                held.extend_from_slice(
                    &child.start_time_ticks.to_be_bytes(),
                );
                held.extend_from_slice(
                    b"barrier-retained-before-shared-gate",
                );
                if sha256(&held)
                    != registration
                        .child_held_before_execution
                        .object_sha256
                {
                    return Err(ControllerError::Rejected(
                        "held workload differs from the sealed supervisor registration",
                    ));
                }
            }
            Ok(())
        }

        fn release_verified_workload(
            child: &mut RegisteredChild,
            capability: &VerifiedTrustedHostDirectReleaseCapability<'_>,
        ) -> Result<()> {
            Self::verify_workload_capability_binding(
                child,
                capability.gate(),
                Some(true),
            )?;
            Self::release_child(child)
        }

        fn collect_verified_workload(
            &self,
            child: RegisteredChild,
            deadline: Instant,
            output_limit: usize,
            external_cgroup_kill: Option<(RawFd, RawFd)>,
            capability: &VerifiedTrustedHostDirectContainmentCapability,
        ) -> Result<ActionOutcome> {
            Self::verify_workload_capability_binding(
                &child,
                capability.gate(),
                Some(false),
            )?;
            self.collect_child(
                child,
                deadline,
                output_limit,
                external_cgroup_kill,
            )
        }

        fn collect_child(
            &self,
            mut child: RegisteredChild,
            deadline: Instant,
            output_limit: usize,
            external_cgroup_kill: Option<(RawFd, RawFd)>,
        ) -> Result<ActionOutcome> {
            if let Err(error) = set_nonblocking(child.output.as_raw_fd()) {
                let mut failures = vec![format!("child output nonblocking setup: {error}")];
                let mut watchdog_kill_proved = false;
                if let Some((control, acknowledgement)) = external_cgroup_kill {
                    match signal_watchdog_and_wait(
                        control,
                        acknowledgement,
                        b'K',
                        self.cleanup_deadline(),
                    ) {
                        Ok(()) => watchdog_kill_proved = true,
                        Err(control_error) => failures.push(format!(
                            "watchdog quarantine signal: {control_error}"
                        )),
                    }
                }
                if let Err(cleanup_error) = self.cleanup_registered_child(
                    &mut child,
                    None,
                    true,
                    !watchdog_kill_proved,
                ) {
                    failures.push(format!("child cleanup: {cleanup_error}"));
                }
                return Err(ControllerError::Unready(vec![failures.join("; ")]));
            }
            let mut output = Vec::new();
            let mut wait_status = None;
            let mut timed_out = false;
            let mut collection_error = None;
            loop {
                if let Err(error) = drain_nonblocking(
                    child.output.as_raw_fd(),
                    &mut output,
                    output_limit,
                ) {
                    collection_error = Some(error);
                    break;
                }
                if wait_status.is_some() {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    timed_out = true;
                    break;
                }
                let remaining = deadline.duration_since(now).as_millis().max(1);
                let mut descriptors = [
                    libc::pollfd {
                        fd: child.pidfd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: child.output.as_raw_fd(),
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                ];
                let result = unsafe {
                    libc::poll(
                        descriptors.as_mut_ptr(),
                        descriptors.len() as libc::nfds_t,
                        remaining.min(250).min(i32::MAX as u128) as i32,
                    )
                };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    collection_error = Some(error.into());
                    break;
                }
                if descriptors[0].revents & libc::POLLIN != 0 {
                    match reap_pid_bounded(
                        child.pid,
                        self.cleanup_deadline(),
                    ) {
                        Ok(status) => wait_status = status,
                        Err(error) => {
                            collection_error = Some(error);
                            break;
                        }
                    }
                }
            }
            let force = timed_out || collection_error.is_some();
            let mut watchdog_closure_proved = false;
            if let Some((control, acknowledgement)) = external_cgroup_kill {
                let command = if force { b'K' } else { b'C' };
                match signal_watchdog_and_wait(
                    control,
                    acknowledgement,
                    command,
                    self.cleanup_deadline(),
                ) {
                    Ok(()) => watchdog_closure_proved = true,
                    Err(error) => {
                        self.readiness.hard_unready(format!(
                            "workload watchdog control failed: {error}"
                        ));
                        if collection_error.is_none() {
                            collection_error = Some(error);
                        }
                    }
                }
            }
            let cleanup_result =
                self.cleanup_registered_child(
                    &mut child,
                    wait_status,
                    force,
                    external_cgroup_kill.is_none()
                        || !watchdog_closure_proved,
                );
            let (status, cleanup_proved) = match cleanup_result {
                Ok(result) => result,
                Err(error) => {
                    return Err(collection_error.unwrap_or(error));
                }
            };
            if let Err(error) =
                drain_nonblocking(child.output.as_raw_fd(), &mut output, output_limit)
            {
                if collection_error.is_none() {
                    collection_error = Some(error);
                }
            }
            if let Some(error) = collection_error {
                return Err(error);
            }
            Ok(ActionOutcome {
                wait_status: status,
                output,
                timed_out,
                cleanup_proved,
            })
        }

        fn cleanup_registered_child(
            &self,
            child: &mut RegisteredChild,
            mut wait_status: Option<i32>,
            force: bool,
            controller_cgroup_kill: bool,
        ) -> Result<(i32, bool)> {
            let mut failures = Vec::<String>::new();
            let (live, liveness_proved) =
                match pidfd_poll_live(child.pidfd.as_raw_fd()) {
                Ok(live) => (live, true),
                Err(error) => {
                    failures.push(format!(
                        "registered child pidfd liveness probe failed: {error}"
                    ));
                    (true, false)
                }
            };
            let start_time_identity_proved = if live {
                match proc_start_time_ticks(child.pid) {
                    Ok(start) if start == child.start_time_ticks => true,
                    Ok(start) => {
                        failures.push(format!(
                            "registered child start-time identity mismatch: expected {}, observed {start}",
                            child.start_time_ticks
                        ));
                        false
                    }
                    Err(error) => {
                        failures.push(format!(
                            "registered child start-time identity probe failed: {error}"
                        ));
                        false
                    }
                }
            } else {
                false
            };
            if force {
                let process_group_identity_proved = if live {
                    let observed_pgid = unsafe { libc::getpgid(child.pid) };
                    if observed_pgid < 0 {
                        failures.push(format!(
                            "registered child process-group identity probe failed: {}",
                            std::io::Error::last_os_error()
                        ));
                        false
                    } else if observed_pgid != child.process_group {
                        failures.push(format!(
                            "registered child process-group identity mismatch: expected {}, observed {observed_pgid}",
                            child.process_group
                        ));
                        false
                    } else {
                        true
                    }
                } else {
                    false
                };
                if liveness_proved
                    && live
                    && start_time_identity_proved
                    && process_group_identity_proved
                    && unsafe {
                        libc::killpg(child.process_group, libc::SIGKILL)
                    } != 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        failures.push(format!(
                            "registered child process-group kill failed: {error}"
                        ));
                    }
                }
                if let Err(error) =
                    signal_pidfd(child.pidfd.as_raw_fd(), libc::SIGKILL)
                {
                    failures.push(format!(
                        "registered child pidfd kill failed: {error}"
                    ));
                }
            }
            if controller_cgroup_kill {
                if let Err(error) = write_control_file(
                    child.cgroup_directory.as_raw_fd(),
                    "cgroup.kill",
                    b"1\n",
                )
                {
                    failures.push(format!(
                        "registered child cgroup.kill failed: {error}"
                    ));
                }
            }
            if wait_status.is_none() {
                match reap_pid_bounded(child.pid, self.cleanup_deadline()) {
                    Ok(Some(status)) => wait_status = Some(status),
                    Ok(None) => failures.push(
                        "registered child bounded reap returned no owned child status"
                            .to_owned(),
                    ),
                    Err(error) => failures.push(format!(
                        "registered child bounded reap failed: {error}"
                    )),
                }
            }
            if wait_status.is_none() {
                failures.push(
                    "registered child has no terminal wait status".to_owned(),
                );
            }
            let empty_deadline = self.cleanup_deadline();
            let mut cgroup_empty = false;
            while Instant::now() < empty_deadline {
                let events = read_bounded_control_file(
                    child.cgroup_directory.as_raw_fd(),
                    "cgroup.events",
                    64 * 1024,
                );
                let procs = read_bounded_control_file(
                    child.cgroup_directory.as_raw_fd(),
                    "cgroup.procs",
                    4 * 1024 * 1024,
                );
                if let (Ok(events), Ok(procs)) = (events, procs) {
                    let populated_zero = std::str::from_utf8(&events)
                        .ok()
                        .and_then(|text| {
                            text.lines()
                                .find_map(|line| line.strip_prefix("populated "))
                        })
                        == Some("0");
                    if populated_zero && procs.iter().all(u8::is_ascii_whitespace) {
                        cgroup_empty = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !cgroup_empty {
                failures.push(
                    "registered child cgroup emptiness was not proved".to_owned(),
                );
            }
            drop(child.barrier.take());
            if unsafe {
                libc::unlinkat(
                    self.cgroup.directory.as_raw_fd(),
                    child.cgroup_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                failures.push(format!(
                    "registered child cgroup removal failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if !failures.is_empty() {
                let reason = format!(
                    "registered child {} cleanup ownership could not be proved: {}",
                    child.pid,
                    failures.join(", ")
                );
                self.readiness.hard_unready(reason.clone());
                self.quarantine(&reason)?;
                return Err(ControllerError::Unready(vec![reason]));
            }
            Ok((wait_status.unwrap_or(-1), true))
        }

        fn enter_lane_io_deadline(
            &self,
            deadline: Instant,
        ) -> Result<LaneIoDeadlineGuard<'_>> {
            let mut current = self
                .io_deadline
                .lock()
                .map_err(|_| ControllerError::Rejected("I/O deadline lock poisoned"))?;
            if current.is_some() {
                return Err(ControllerError::Rejected(
                    "lane I/O deadline is already active",
                ));
            }
            *current = Some(deadline);
            drop(current);
            let cleanup_deadline = deadline
                .checked_add(Duration::from_secs(60))
                .ok_or(ControllerError::Rejected(
                    "independent cleanup reserve deadline overflow",
                ))?;
            let mut cleanup = self
                .cleanup_reserve_deadline
                .lock()
                .map_err(|_| {
                    ControllerError::Rejected(
                        "cleanup reserve deadline lock poisoned",
                    )
                })?;
            if cleanup.is_some() {
                if let Ok(mut current) = self.io_deadline.lock() {
                    *current = None;
                }
                return Err(ControllerError::Rejected(
                    "cleanup reserve deadline is already active",
                ));
            }
            *cleanup = Some(cleanup_deadline);
            drop(cleanup);
            Ok(LaneIoDeadlineGuard {
                io_slot: &self.io_deadline,
                cleanup_slot: &self.cleanup_reserve_deadline,
            })
        }

        fn current_io_deadline(&self) -> Result<Instant> {
            let current = self
                .io_deadline
                .lock()
                .map_err(|_| ControllerError::Rejected("I/O deadline lock poisoned"))?;
            Ok(current.unwrap_or_else(|| Instant::now() + Duration::from_secs(30)))
        }

        fn run_bytes_worker<F>(
            &self,
            label: &str,
            maximum: usize,
            work: F,
        ) -> Result<Vec<u8>>
        where
            F: FnOnce() -> Result<Vec<u8>>,
        {
            self.run_bytes_worker_with_closed_fds(
                label,
                maximum,
                &[],
                work,
            )
        }

        fn run_bytes_worker_with_closed_fds<F>(
            &self,
            label: &str,
            maximum: usize,
            foreign_authority_fds: &[RawFd],
            work: F,
        ) -> Result<Vec<u8>>
        where
            F: FnOnce() -> Result<Vec<u8>>,
        {
            let deadline = self.current_io_deadline()?;
            let foreign_authority_fds = foreign_authority_fds.to_vec();
            let mut child = self.spawn_registered(label, move |output| {
                for fd in foreign_authority_fds {
                    if unsafe { libc::close(fd) } != 0 {
                        return 124;
                    }
                }
                match work() {
                    Ok(bytes) if bytes.len() <= maximum => {
                        let mut header = Vec::with_capacity(10);
                        header.extend_from_slice(b"OK");
                        header.extend_from_slice(
                            &(bytes.len() as u64).to_be_bytes(),
                        );
                        if write_all_fd(output, &header).is_ok()
                            && write_all_fd(output, &bytes).is_ok()
                        {
                            0
                        } else {
                            124
                        }
                    }
                    Ok(_) => 123,
                    Err(error) => {
                        let message = error.to_string();
                        if write_all_fd(
                            output,
                            &message.as_bytes()[..message.len().min(4096)],
                        )
                        .is_ok()
                        {
                            123
                        } else {
                            124
                        }
                    }
                }
            })?;
            if let Err(error) = Self::release_child(&mut child) {
                self.cleanup_registered_child(&mut child, None, true, true)?;
                self.quarantine(&format!(
                    "{label} bounded I/O worker release failed: {error}"
                ))?;
                return Err(error);
            }
            let outcome = self.collect_child(
                child,
                deadline,
                maximum.saturating_add(10),
                None,
            )?;
            if outcome.timed_out || !outcome.cleanup_proved {
                return Err(ControllerError::Unready(vec![format!(
                    "{label} I/O worker timed out or cleanup was unproved"
                )]));
            }
            if !wait_status_success(outcome.wait_status)
                || outcome.output.len() < 10
                || &outcome.output[0..2] != b"OK"
            {
                return Err(ControllerError::Rejected(
                    "bounded I/O worker returned an invalid result",
                ));
            }
            let length = u64::from_be_bytes(
                outcome.output[2..10]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid("invalid I/O worker length"))?,
            ) as usize;
            if length > maximum || outcome.output.len() != 10 + length {
                return Err(ControllerError::Rejected(
                    "bounded I/O worker result length is invalid",
                ));
            }
            Ok(outcome.output[10..].to_vec())
        }

        fn read_optional_state_bounded(
            &self,
            directory: RawFd,
            name: &str,
        ) -> Result<Option<Vec<u8>>> {
            let name = name.to_owned();
            let bytes = self.run_bytes_worker(
                "state-read",
                STATE_RECORD_MAX_BYTES as usize + 1,
                move || match read_optional_state_file(directory, &name)? {
                    Some(bytes) => {
                        let mut result = Vec::with_capacity(bytes.len() + 1);
                        result.push(1);
                        result.extend_from_slice(&bytes);
                        Ok(result)
                    }
                    None => Ok(vec![0]),
                },
            )?;
            match bytes.first() {
                Some(0) if bytes.len() == 1 => Ok(None),
                Some(1) => Ok(Some(bytes[1..].to_vec())),
                _ => Err(ControllerError::Rejected(
                    "bounded state read returned invalid presence marker",
                )),
            }
        }

        fn read_required_state_bounded(
            &self,
            directory: RawFd,
            name: &str,
        ) -> Result<Vec<u8>> {
            self.read_optional_state_bounded(directory, name)?
                .ok_or(ControllerError::Rejected(
                    "required durable state record is absent",
                ))
        }

        fn create_state_exclusive_bounded(
            &self,
            directory: RawFd,
            name: &str,
            bytes: &[u8],
        ) -> Result<bool> {
            let name = name.to_owned();
            let bytes = bytes.to_vec();
            let result = self.run_bytes_worker(
                "state-create-fsync",
                1,
                move || {
                    Ok(vec![u8::from(create_state_file_exclusive(
                        directory,
                        &name,
                        &bytes,
                    )?)])
                },
            )?;
            match result.as_slice() {
                [0] => Ok(false),
                [1] => Ok(true),
                _ => Err(ControllerError::Rejected(
                    "bounded state create returned invalid result",
                )),
            }
        }

        fn run_digest_provider<F>(
            &self,
            label: &str,
            timeout: Duration,
            work: F,
        ) -> Result<Digest>
        where
            F: FnOnce() -> Result<Digest>,
        {
            let mut child = self.spawn_registered(label, move |output| match work() {
                Ok(digest) => {
                    let mut message = Vec::with_capacity(34);
                    message.extend_from_slice(b"OK");
                    message.extend_from_slice(&digest);
                    if write_all_fd(output, &message).is_ok() {
                        0
                    } else {
                        124
                    }
                }
                Err(error) => {
                    let mut message = Vec::new();
                    message.extend_from_slice(b"ER");
                    message.extend_from_slice(error.to_string().as_bytes());
                    if write_all_fd(output, &message[..message.len().min(4096)]).is_ok() {
                        123
                    } else {
                        124
                    }
                }
            })?;
            if let Err(error) = Self::release_child(&mut child) {
                self.cleanup_registered_child(&mut child, None, true, true)?;
                self.quarantine(&format!(
                    "{label} bounded provider release failed: {error}"
                ))?;
                return Err(error);
            }
            let lane_deadline = self.current_io_deadline()?;
            let local_deadline = Instant::now()
                .checked_add(timeout)
                .ok_or(ControllerError::Rejected(
                    "bounded provider deadline overflow",
                ))?;
            let deadline = lane_deadline.min(local_deadline);
            if deadline <= Instant::now() {
                self.cleanup_registered_child(&mut child, None, true, true)?;
                return Err(ControllerError::Rejected(
                    "bounded provider deadline expired before collection",
                ));
            }
            let outcome = self.collect_child(child, deadline, 4096, None)?;
            if outcome.timed_out || !outcome.cleanup_proved {
                return Err(ControllerError::Unready(vec![format!(
                    "{label} provider timed out or cleanup was unproved"
                )]));
            }
            if !wait_status_success(outcome.wait_status)
                || outcome.output.len() != 34
                || &outcome.output[0..2] != b"OK"
            {
                return Err(ControllerError::Rejected(
                    "bounded provider returned invalid evidence",
                ));
            }
            copy_digest_at(&outcome.output, 2)
        }
    }

    fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd)> {
        let mut descriptors = [-1; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        })
    }

    fn install_identity_user_namespace_maps(pid: libc::pid_t) -> Result<()> {
        if pid <= 1 {
            return Err(ControllerError::Rejected(
                "user namespace map target PID is invalid",
            ));
        }
        let proc = open_canonical_directory(Path::new("/proc"), false)?;
        let map = b"0 0 4294967295\n";
        for name in ["uid_map", "gid_map"] {
            let relative = CString::new(format!("{pid}/{name}"))
                .map_err(|_| ControllerError::Invalid("namespace map path contains NUL"))?;
            let how = OpenHow {
                flags: (libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH
                    | RESOLVE_NO_MAGICLINKS
                    | RESOLVE_NO_SYMLINKS,
            };
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    proc.as_raw_fd(),
                    relative.as_ptr(),
                    &how,
                    mem::size_of::<OpenHow>(),
                ) as RawFd
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            write_all_fd(descriptor.as_raw_fd(), map)?;
        }
        Ok(())
    }

    fn set_nonblocking(fd: RawFd) -> Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn wait_watchdog_armed(
        acknowledgement: RawFd,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(ControllerError::Rejected(
                    "watchdog durable-arm acknowledgement deadline expired",
                ));
            }
            let timeout = deadline
                .duration_since(now)
                .as_millis()
                .max(1)
                .min(250)
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: acknowledgement,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result < 0 {
                if std::io::Error::last_os_error().raw_os_error()
                    == Some(libc::EINTR)
                {
                    continue;
                }
                return Err(std::io::Error::last_os_error().into());
            }
            if descriptor.revents & libc::POLLIN != 0 {
                let mut status = [0u8; 1];
                if unsafe {
                    libc::read(
                        acknowledgement,
                        status.as_mut_ptr() as *mut libc::c_void,
                        1,
                    )
                } != 1
                {
                    return Err(ControllerError::Rejected(
                        "watchdog durable-arm acknowledgement was truncated",
                    ));
                }
                return if status[0] == b'A' {
                    Ok(())
                } else {
                    Err(ControllerError::Rejected(
                        "watchdog failed to persist its durable armed journal",
                    ))
                };
            }
            if descriptor.revents
                & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
            {
                return Err(ControllerError::Rejected(
                    "watchdog exited before durable-arm acknowledgement",
                ));
            }
        }
    }

    fn signal_watchdog_and_wait(
        control: RawFd,
        acknowledgement: RawFd,
        command: u8,
        deadline: Instant,
    ) -> Result<()> {
        let control_error = write_all_fd(control, &[command]).err();
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(control_error.unwrap_or(ControllerError::Rejected(
                    "watchdog acknowledgement deadline expired",
                )));
            }
            let timeout = deadline
                .duration_since(now)
                .as_millis()
                .max(1)
                .min(250)
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: acknowledgement,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(std::io::Error::last_os_error().into());
            }
            if descriptor.revents & libc::POLLIN != 0 {
                let mut status = [0u8; 1];
                if unsafe {
                    libc::read(
                        acknowledgement,
                        status.as_mut_ptr() as *mut libc::c_void,
                        1,
                    )
                } != 1
                {
                    return Err(ControllerError::Rejected(
                        "watchdog acknowledgement was truncated",
                    ));
                }
                return if status[0] == b'D' {
                    Ok(())
                } else {
                    Err(ControllerError::Rejected(
                        "watchdog reported failed cgroup kill or durable journal",
                    ))
                };
            }
            if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(control_error.unwrap_or(ControllerError::Rejected(
                    "watchdog exited without a durable acknowledgement",
                )));
            }
        }
    }

    fn write_all_fd(fd: RawFd, bytes: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let count = unsafe {
                libc::write(
                    fd,
                    bytes[offset..].as_ptr() as *const libc::c_void,
                    bytes.len() - offset,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if count == 0 {
                return Err(ControllerError::Rejected("short child pipe write"));
            }
            offset += count as usize;
        }
        Ok(())
    }

    fn wait_monitor_ready(
        readiness: RawFd,
        workload_pid: libc::pid_t,
        workload_pidfd: RawFd,
        expected_start_time_ticks: u64,
        deadline: Instant,
    ) -> Result<Digest> {
        while Instant::now() < deadline {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .max(1)
                .min(250) as i32;
            let mut descriptors = [
                libc::pollfd {
                    fd: readiness,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: workload_pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    remaining,
                )
            };
            if result < 0 {
                if std::io::Error::last_os_error().raw_os_error()
                    == Some(libc::EINTR)
                {
                    continue;
                }
                return Err(std::io::Error::last_os_error().into());
            }
            if descriptors[1].revents & libc::POLLIN != 0 {
                return Err(ControllerError::Rejected(
                    "workload exited before monitor readiness",
                ));
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                let mut acknowledgement = [0u8; 1];
                if unsafe {
                    libc::read(
                        readiness,
                        acknowledgement.as_mut_ptr() as *mut libc::c_void,
                        1,
                    )
                } != 1
                    || acknowledgement[0] != b'M'
                    || proc_start_time_ticks(workload_pid)?
                        != expected_start_time_ticks
                    || !pidfd_poll_live(workload_pidfd)?
                {
                    return Err(ControllerError::Rejected(
                        "monitor readiness acknowledgement lost workload identity",
                    ));
                }
                let mut evidence = Vec::new();
                evidence.extend_from_slice(
                    b"catchplate/kernel-monitor-ready/v11\0",
                );
                evidence.extend_from_slice(&workload_pid.to_be_bytes());
                evidence.extend_from_slice(
                    &expected_start_time_ticks.to_be_bytes(),
                );
                evidence.extend_from_slice(b"monitor-ready-before-release");
                return Ok(sha256(&evidence));
            }
        }
        Err(ControllerError::Rejected(
            "monitor readiness deadline expired",
        ))
    }

    fn write_durable_journal(
        directory: RawFd,
        name: &CString,
        bytes: &[u8],
    ) -> Result<()> {
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { OwnedFd::from_raw_fd(raw) };
        write_all_fd(file.as_raw_fd(), bytes)?;
        if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut flags,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        flags |= FS_IMMUTABLE_FL;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_SETFLAGS,
                &flags,
            )
        } != 0
            || unsafe { libc::fsync(file.as_raw_fd()) } != 0
            || unsafe { libc::fsync(directory) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn watchdog_arm_record(
        frontend_pid: libc::pid_t,
        broker_pid: libc::pid_t,
        workload_cgroup: RawFd,
        workload_cgroup_name: &CString,
        workload_pid: libc::pid_t,
        workload_start_time_ticks: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let mut cgroup_identity: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(workload_cgroup, &mut cgroup_identity) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let deadline_remaining_ns = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ControllerError::Rejected(
                "watchdog deadline expired before durable arm",
            ))?
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let mut record = Vec::new();
        record.extend_from_slice(b"catchplate/watchdog-armed/v11\0");
        record.extend_from_slice(&frontend_pid.to_be_bytes());
        record.extend_from_slice(&broker_pid.to_be_bytes());
        record.extend_from_slice(&workload_pid.to_be_bytes());
        record.extend_from_slice(&workload_start_time_ticks.to_be_bytes());
        record.extend_from_slice(&cgroup_identity.st_dev.to_be_bytes());
        record.extend_from_slice(&cgroup_identity.st_ino.to_be_bytes());
        record.extend_from_slice(workload_cgroup_name.as_bytes());
        record.push(0);
        record.extend_from_slice(&deadline_remaining_ns.to_be_bytes());
        Ok(record)
    }

    fn reconcile_startup_worker(
        cgroup_root: &Path,
        cgroup_directory: RawFd,
        journal_root: &Path,
        journal_directory: RawFd,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let own_cgroup = current_cgroup_leaf()?;
        let mut transcript = Vec::new();
        transcript.extend_from_slice(
            b"catchplate/startup-reconciliation/v11\0",
        );
        let mut armed = BTreeMap::<String, Vec<u8>>::new();
        let mut journal_count = 0usize;
        for entry in std::fs::read_dir(journal_root)? {
            if Instant::now() >= deadline || journal_count >= 4096 {
                return Err(ControllerError::Rejected(
                    "startup journal reconciliation exceeded its bound",
                ));
            }
            journal_count += 1;
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| {
                    ControllerError::Rejected(
                        "startup journal name is not UTF-8",
                    )
                })?;
            if name.ends_with(".armed") {
                require_immutable_state_file(journal_directory, &name)?;
                let bytes =
                    read_required_state_file(journal_directory, &name)?;
                armed.insert(name, bytes);
            } else if name.ends_with(".journal")
                || name.ends_with(".reconciled")
            {
                require_immutable_state_file(journal_directory, &name)?;
            }
        }
        let mut referenced_cgroups = BTreeSet::new();
        for (armed_name, record) in &armed {
            let base = armed_name
                .strip_suffix(".armed")
                .ok_or(ControllerError::Invalid(
                    "armed journal suffix is absent",
                ))?;
            let closure_name = format!("{base}.journal");
            let reconciled_name = format!("{base}.reconciled");
            let cgroup_name = parse_watchdog_cgroup_name(record)?;
            referenced_cgroups.insert(cgroup_name.clone());
            let closure_exists = state_file_exists(
                journal_directory,
                &closure_name,
            )?;
            let reconciled_exists = state_file_exists(
                journal_directory,
                &reconciled_name,
            )?;
            if closure_exists {
                require_immutable_state_file(
                    journal_directory,
                    &closure_name,
                )?;
                transcript.extend_from_slice(armed_name.as_bytes());
                transcript.extend_from_slice(b":closed\0");
                continue;
            }
            if reconciled_exists {
                require_immutable_state_file(
                    journal_directory,
                    &reconciled_name,
                )?;
                transcript.extend_from_slice(armed_name.as_bytes());
                transcript.extend_from_slice(b":reconciled\0");
                continue;
            }
            kill_and_remove_stale_cgroup(
                cgroup_directory,
                &cgroup_name,
                deadline,
            )?;
            let mut reconciliation = Vec::new();
            reconciliation.extend_from_slice(
                b"catchplate/watchdog-startup-reconciled/v11\0",
            );
            reconciliation.extend_from_slice(&sha256(record));
            reconciliation.extend_from_slice(cgroup_name.as_bytes());
            reconciliation.push(0);
            reconciliation.extend_from_slice(&now_unix_ms()?.to_be_bytes());
            let reconciled = CString::new(reconciled_name).map_err(|_| {
                ControllerError::Invalid(
                    "reconciliation journal name contains NUL",
                )
            })?;
            write_durable_journal(
                journal_directory,
                &reconciled,
                &reconciliation,
            )?;
            require_immutable_state_file(
                journal_directory,
                reconciled
                    .to_str()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "reconciliation name is not UTF-8",
                        )
                    })?,
            )?;
            transcript.extend_from_slice(armed_name.as_bytes());
            transcript.extend_from_slice(b":killed-and-reconciled\0");
        }
        let mut cgroup_count = 0usize;
        for entry in std::fs::read_dir(cgroup_root)? {
            if Instant::now() >= deadline || cgroup_count >= 4096 {
                return Err(ControllerError::Rejected(
                    "startup cgroup reconciliation exceeded its bound",
                ));
            }
            cgroup_count += 1;
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| {
                    ControllerError::Rejected(
                        "controller cgroup name is not UTF-8",
                    )
                })?;
            if !name.starts_with("v11-")
                || Some(name.as_str()) == own_cgroup.as_deref()
            {
                continue;
            }
            kill_and_remove_stale_cgroup(
                cgroup_directory,
                &name,
                deadline,
            )?;
            transcript.extend_from_slice(name.as_bytes());
            transcript.extend_from_slice(if referenced_cgroups.contains(&name) {
                b":stale-referenced\0"
            } else {
                b":stale-unjournaled\0"
            });
        }
        if unsafe { libc::fsync(journal_directory) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(transcript)
    }

    fn current_cgroup_leaf() -> Result<Option<String>> {
        let bytes = read_bounded_file(Path::new("/proc/self/cgroup"), 64 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ControllerError::Rejected("self cgroup is not UTF-8"))?;
        let path = text
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or(ControllerError::Rejected(
                "unified self cgroup entry is absent",
            ))?;
        Ok(Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned))
    }

    fn parse_watchdog_cgroup_name(record: &[u8]) -> Result<String> {
        let prefix = b"catchplate/watchdog-armed/v11\0";
        let fixed = prefix.len() + 4 + 4 + 4 + 8 + 8 + 8;
        if !record.starts_with(prefix) || record.len() < fixed + 2 + 8 {
            return Err(ControllerError::Rejected(
                "armed watchdog journal is malformed",
            ));
        }
        let tail = &record[fixed..];
        let end = tail.iter().position(|byte| *byte == 0).ok_or(
            ControllerError::Rejected(
                "armed watchdog journal lacks cgroup terminator",
            ),
        )?;
        if end == 0 || tail.len() != end + 1 + 8 {
            return Err(ControllerError::Rejected(
                "armed watchdog journal has a noncanonical cgroup field",
            ));
        }
        let name = std::str::from_utf8(&tail[..end]).map_err(|_| {
            ControllerError::Rejected(
                "armed watchdog cgroup name is not UTF-8",
            )
        })?;
        if !name.starts_with("v11-")
            || name.contains('/')
            || name.as_bytes().contains(&0)
        {
            return Err(ControllerError::Rejected(
                "armed watchdog cgroup name is unsafe",
            ));
        }
        Ok(name.to_owned())
    }

    fn state_file_exists(directory: RawFd, name: &str) -> Result<bool> {
        let name = CString::new(name)
            .map_err(|_| ControllerError::Invalid("state name contains NUL"))?;
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
            )
        };
        if raw >= 0 {
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        Err(error.into())
    }

    fn kill_and_remove_stale_cgroup(
        root: RawFd,
        name: &str,
        deadline: Instant,
    ) -> Result<()> {
        let name_c = CString::new(name)
            .map_err(|_| ControllerError::Invalid("cgroup name contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root,
                name_c.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Err(ControllerError::Rejected(
                    "journaled stale cgroup is absent before authoritative reconciliation",
                ));
            }
            return Err(error.into());
        }
        let directory = unsafe { OwnedFd::from_raw_fd(raw) };
        write_control_file(directory.as_raw_fd(), "cgroup.kill", b"1\n")?;
        loop {
            if Instant::now() >= deadline {
                return Err(ControllerError::Rejected(
                    "stale cgroup closure deadline expired",
                ));
            }
            let events = read_bounded_control_file(
                directory.as_raw_fd(),
                "cgroup.events",
                64 * 1024,
            )?;
            let procs = read_bounded_control_file(
                directory.as_raw_fd(),
                "cgroup.procs",
                4 * 1024 * 1024,
            )?;
            let empty = std::str::from_utf8(&events)
                .ok()
                .map(|events| events.lines().any(|line| line == "populated 0"))
                .unwrap_or(false)
                && procs.iter().all(u8::is_ascii_whitespace);
            if empty {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(directory);
        if unsafe {
            libc::unlinkat(root, name_c.as_ptr(), libc::AT_REMOVEDIR)
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn watchdog_main(
        frontend_pidfd: RawFd,
        broker_pidfd: RawFd,
        control: RawFd,
        workload_cgroup: RawFd,
        workload_pid: libc::pid_t,
        workload_start_time_ticks: u64,
        journal_directory: RawFd,
        armed_journal_name: &CString,
        closure_journal_name: &CString,
        armed_record: &[u8],
        deadline: Instant,
        acknowledgement: RawFd,
        output: RawFd,
    ) -> i32 {
        let arm_durable = write_durable_journal(
            journal_directory,
            armed_journal_name,
            armed_record,
        );
        let arm_acknowledged = if arm_durable.is_ok() {
            write_all_fd(acknowledgement, b"A")
        } else {
            write_all_fd(acknowledgement, b"F")
        };
        let initial_reason = if arm_durable.is_err() {
            Some(b"durable-arm-failed".as_slice())
        } else if arm_acknowledged.is_err() {
            Some(b"durable-arm-ack-lost".as_slice())
        } else {
            None
        };
        let reason = if let Some(reason) = initial_reason {
            reason
        } else {
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break b"deadline".as_slice();
                }
                let timeout = deadline
                    .duration_since(now)
                    .as_millis()
                    .max(1)
                    .min(250)
                    .min(i32::MAX as u128)
                    as i32;
                let mut pollfds = [
                    libc::pollfd {
                        fd: frontend_pidfd,
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: broker_pidfd,
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: control,
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    },
                ];
                let result = unsafe {
                    libc::poll(
                        pollfds.as_mut_ptr(),
                        pollfds.len() as _,
                        timeout,
                    )
                };
                if result < 0 {
                    if std::io::Error::last_os_error().raw_os_error()
                        == Some(libc::EINTR)
                    {
                        continue;
                    }
                    break b"poll-error".as_slice();
                }
                if pollfds[0].revents
                    & (libc::POLLIN | libc::POLLHUP)
                    != 0
                {
                    break b"frontend-exit".as_slice();
                }
                if pollfds[1].revents
                    & (libc::POLLIN | libc::POLLHUP)
                    != 0
                {
                    break b"broker-exit".as_slice();
                }
                if pollfds[2].revents & libc::POLLIN != 0 {
                    let mut command = [0u8; 1];
                    if unsafe {
                        libc::read(
                            control,
                            command.as_mut_ptr()
                                as *mut libc::c_void,
                            1,
                        )
                    } == 1
                    {
                        break if command[0] == b'C' {
                            b"controller-closure".as_slice()
                        } else {
                            b"controller-quarantine".as_slice()
                        };
                    }
                }
                if pollfds[2].revents & libc::POLLHUP != 0 {
                    break b"controller-pipe-lost".as_slice();
                }
            }
        };
        let kill = write_control_file(workload_cgroup, "cgroup.kill", b"1\n");
        let mut journal = Vec::new();
        journal.extend_from_slice(b"catchplate/watchdog-closure/v11\0");
        journal.extend_from_slice(&workload_pid.to_be_bytes());
        journal.extend_from_slice(&workload_start_time_ticks.to_be_bytes());
        let mut cgroup_identity: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(workload_cgroup, &mut cgroup_identity) } == 0 {
            journal.extend_from_slice(&cgroup_identity.st_dev.to_be_bytes());
            journal.extend_from_slice(&cgroup_identity.st_ino.to_be_bytes());
        } else {
            journal.extend_from_slice(&[0; 16]);
        }
        journal.extend_from_slice(reason);
        journal.push(0);
        journal.extend_from_slice(
            if kill.is_ok() {
                b"cgroup-kill-ok"
            } else {
                b"cgroup-kill-failed"
            },
        );
        journal.push(0);
        if let Err(error) = &kill {
            journal.extend_from_slice(error.to_string().as_bytes());
            journal.push(0);
        }
        let durable = write_durable_journal(
            journal_directory,
            closure_journal_name,
            &journal,
        );
        let acknowledged = write_all_fd(
            acknowledgement,
            &[if kill.is_ok() && durable.is_ok() { b'D' } else { b'F' }],
        );
        let reported = write_all_fd(output, &journal);
        if kill.is_ok() && durable.is_ok() && acknowledged.is_ok() && reported.is_ok() {
            0
        } else {
            124
        }
    }

    fn drain_nonblocking(fd: RawFd, output: &mut Vec<u8>, maximum: usize) -> Result<()> {
        let mut buffer = [0u8; 8192];
        loop {
            let count = unsafe {
                libc::read(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if count > 0 {
                let count = count as usize;
                if output.len().saturating_add(count) > maximum {
                    return Err(ControllerError::Rejected(
                        "bounded child output exceeds configured cap",
                    ));
                }
                output.extend_from_slice(&buffer[..count]);
                continue;
            }
            if count == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::EAGAIN)
                || error.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Ok(());
            }
            return Err(error.into());
        }
    }

    fn write_control_file(directory: RawFd, name: &str, bytes: &[u8]) -> Result<()> {
        let name =
            CString::new(name).map_err(|_| ControllerError::Invalid("control name has NUL"))?;
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        write_all_fd(fd.as_raw_fd(), bytes)
    }

    fn read_bounded_control_file(
        directory: RawFd,
        name: &str,
        maximum: u64,
    ) -> Result<Vec<u8>> {
        let name =
            CString::new(name).map_err(|_| ControllerError::Invalid("control name has NUL"))?;
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let mut bytes = Vec::new();
        file.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(ControllerError::Rejected("control file exceeds bound"));
        }
        Ok(bytes)
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

    fn reap_pid_bounded(pid: libc::pid_t, deadline: Instant) -> Result<Option<i32>> {
        while Instant::now() < deadline {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                return Ok(Some(status));
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(None);
                }
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(None)
    }

    fn wait_status_success(status: i32) -> bool {
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn wait_status_exit_code(status: i32) -> i32 {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        }
    }

    impl CanonicalTreeManifest {
        fn encode(&self) -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"SWTREE11");
            push_tree_bytes(&mut bytes, self.root.as_os_str().as_bytes())?;
            bytes.extend_from_slice(&self.manifest_sha256);
            let count: u32 = self.entries.len().try_into().map_err(|_| {
                ControllerError::Rejected("tree manifest has too many entries")
            })?;
            bytes.extend_from_slice(&count.to_be_bytes());
            for entry in &self.entries {
                push_tree_bytes(&mut bytes, &entry.relative_path)?;
                bytes.push(entry.kind);
                bytes.extend_from_slice(&[0; 3]);
                bytes.extend_from_slice(&entry.device.to_be_bytes());
                bytes.extend_from_slice(&entry.inode.to_be_bytes());
                bytes.extend_from_slice(&entry.generation.to_be_bytes());
                bytes.extend_from_slice(&entry.size.to_be_bytes());
                bytes.extend_from_slice(&entry.mode.to_be_bytes());
                bytes.extend_from_slice(&entry.owner_uid.to_be_bytes());
                bytes.extend_from_slice(&entry.owner_gid.to_be_bytes());
                bytes.extend_from_slice(&entry.mtime.to_be_bytes());
                bytes.extend_from_slice(&entry.mtime_nsec.to_be_bytes());
                bytes.extend_from_slice(&entry.ctime.to_be_bytes());
                bytes.extend_from_slice(&entry.ctime_nsec.to_be_bytes());
                bytes.extend_from_slice(&entry.content_sha256);
            }
            if bytes.len() > PROVIDER_MAX_BYTES {
                return Err(ControllerError::Rejected(
                    "canonical tree manifest exceeds provider bound",
                ));
            }
            Ok(bytes)
        }

        fn decode(bytes: &[u8]) -> Result<Self> {
            if bytes.len() < 8 + 4 + 32 + 4
                || &bytes[0..8] != b"SWTREE11"
            {
                return Err(ControllerError::Rejected(
                    "canonical tree manifest header is invalid",
                ));
            }
            let mut cursor = 8usize;
            let root = PathBuf::from(std::ffi::OsString::from_vec(
                read_tree_bytes(bytes, &mut cursor)?,
            ));
            let digest_end = cursor.checked_add(32).ok_or(
                ControllerError::Invalid("tree digest offset overflow"),
            )?;
            let mut manifest_sha256 = [0u8; 32];
            manifest_sha256.copy_from_slice(bytes.get(cursor..digest_end).ok_or(
                ControllerError::Invalid("truncated tree manifest digest"),
            )?);
            cursor = digest_end;
            let count = read_tree_u32(bytes, &mut cursor)? as usize;
            if count > 100_000 {
                return Err(ControllerError::Rejected(
                    "tree manifest entry count exceeds bound",
                ));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let relative_path = read_tree_bytes(bytes, &mut cursor)?;
                let kind = *bytes.get(cursor).ok_or(
                    ControllerError::Invalid("truncated tree entry kind"),
                )?;
                if !matches!(kind, b'D' | b'F' | b'L')
                    || bytes
                        .get(cursor + 1..cursor + 4)
                        .ok_or(ControllerError::Invalid(
                            "truncated tree entry padding",
                        ))?
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(ControllerError::Rejected(
                        "tree manifest entry kind/padding is invalid",
                    ));
                }
                cursor += 4;
                let entry = TreeManifestEntry {
                    relative_path,
                    kind,
                    device: read_tree_u64(bytes, &mut cursor)?,
                    inode: read_tree_u64(bytes, &mut cursor)?,
                    generation: read_tree_u64(bytes, &mut cursor)?,
                    size: read_tree_u64(bytes, &mut cursor)?,
                    mode: read_tree_u32(bytes, &mut cursor)?,
                    owner_uid: read_tree_u32(bytes, &mut cursor)?,
                    owner_gid: read_tree_u32(bytes, &mut cursor)?,
                    mtime: read_tree_i64(bytes, &mut cursor)?,
                    mtime_nsec: read_tree_i64(bytes, &mut cursor)?,
                    ctime: read_tree_i64(bytes, &mut cursor)?,
                    ctime_nsec: read_tree_i64(bytes, &mut cursor)?,
                    content_sha256: {
                        let end = cursor.checked_add(32).ok_or(
                            ControllerError::Invalid(
                                "tree content digest offset overflow",
                            ),
                        )?;
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(bytes.get(cursor..end).ok_or(
                            ControllerError::Invalid(
                                "truncated tree content digest",
                            ),
                        )?);
                        cursor = end;
                        digest
                    },
                };
                entries.push(entry);
            }
            if cursor != bytes.len() {
                return Err(ControllerError::Rejected(
                    "tree manifest has trailing bytes",
                ));
            }
            let manifest = Self {
                root,
                entries,
                manifest_sha256,
            };
            if tree_manifest_digest(&manifest.entries)
                != manifest.manifest_sha256
            {
                return Err(ControllerError::Rejected(
                    "tree manifest digest is invalid",
                ));
            }
            Ok(manifest)
        }
    }

    fn refresh_tree_manifest(
        root: &Path,
        previous: Option<&CanonicalTreeManifest>,
        excludes: &[PathBuf],
    ) -> Result<CanonicalTreeManifest> {
        validate_absolute_normalized_path(root)?;
        for excluded in excludes {
            validate_absolute_normalized_path(excluded)?;
        }
        let previous_entries: BTreeMap<Vec<u8>, TreeManifestEntry> = previous
            .filter(|manifest| manifest.root == root)
            .map(|manifest| {
                manifest
                    .entries
                    .iter()
                    .cloned()
                    .map(|entry| (entry.relative_path.clone(), entry))
                    .collect()
            })
            .unwrap_or_default();
        let mut entries = Vec::new();
        collect_tree_manifest_entries(
            root,
            root,
            &previous_entries,
            excludes,
            &mut entries,
        )?;
        entries.sort_by(|left, right| {
            left.relative_path.cmp(&right.relative_path)
        });
        let manifest_sha256 = tree_manifest_digest(&entries);
        Ok(CanonicalTreeManifest {
            root: root.to_path_buf(),
            entries,
            manifest_sha256,
        })
    }

    fn collect_tree_manifest_entries(
        root: &Path,
        path: &Path,
        previous: &BTreeMap<Vec<u8>, TreeManifestEntry>,
        excludes: &[PathBuf],
        output: &mut Vec<TreeManifestEntry>,
    ) -> Result<()> {
        if path != root
            && excludes
                .iter()
                .any(|excluded| path == excluded || path.starts_with(excluded))
        {
            return Ok(());
        }
        if output.len() >= 100_000 {
            return Err(ControllerError::Rejected(
                "tree manifest entry count exceeded bound",
            ));
        }
        let metadata = std::fs::symlink_metadata(path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| {
                ControllerError::Rejected(
                    "tree entry escaped canonical root",
                )
            })?
            .as_os_str()
            .as_bytes()
            .to_vec();
        let (kind, generation, content_sha256) =
            if metadata.file_type().is_dir() {
                (b'D', 0, sha256(b"directory"))
            } else if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(path)?;
                (
                    b'L',
                    0,
                    sha256(target.as_os_str().as_bytes()),
                )
            } else if metadata.file_type().is_file() {
                let path_c = CString::new(path.as_os_str().as_bytes())
                    .map_err(|_| {
                        ControllerError::Rejected("tree path contains NUL")
                    })?;
                let raw = unsafe {
                    libc::open(
                        path_c.as_ptr(),
                        libc::O_RDONLY
                            | libc::O_CLOEXEC
                            | libc::O_NOFOLLOW,
                    )
                };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut file = unsafe { File::from_raw_fd(raw) };
                let opened = file.metadata()?;
                if !tree_metadata_same(&metadata, &opened) {
                    return Err(ControllerError::Rejected(
                        "tree file identity changed while opening",
                    ));
                }
                let mut generation_value: libc::c_int = 0;
                if unsafe {
                    libc::ioctl(
                        file.as_raw_fd(),
                        FS_IOC_GETVERSION,
                        &mut generation_value,
                    )
                } != 0
                {
                    return Err(ControllerError::Rejected(
                        "tree file generation is unavailable",
                    ));
                }
                let generation = generation_value as u32 as u64;
                let candidate = TreeManifestEntry {
                    relative_path: relative.clone(),
                    kind: b'F',
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    generation,
                    size: metadata.len(),
                    mode: metadata.mode(),
                    owner_uid: metadata.uid(),
                    owner_gid: metadata.gid(),
                    mtime: metadata.mtime(),
                    mtime_nsec: metadata.mtime_nsec(),
                    ctime: metadata.ctime(),
                    ctime_nsec: metadata.ctime_nsec(),
                    content_sha256: [0; 32],
                };
                let digest = previous
                    .get(&relative)
                    .filter(|entry| {
                        tree_entry_metadata_eq(entry, &candidate)
                    })
                    .map(|entry| entry.content_sha256)
                    .unwrap_or(sha256_exact_reader(
                        &mut file,
                        metadata.len(),
                    )?);
                let after = file.metadata()?;
                if !tree_metadata_same(&opened, &after) {
                    return Err(ControllerError::Rejected(
                        "tree file changed during digest observation",
                    ));
                }
                (b'F', generation, digest)
            } else {
                return Err(ControllerError::Rejected(
                    "tree manifest contains a special file",
                ));
            };
        output.push(TreeManifestEntry {
            relative_path: relative,
            kind,
            device: metadata.dev(),
            inode: metadata.ino(),
            generation,
            size: metadata.len(),
            mode: metadata.mode(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            content_sha256,
        });
        if metadata.file_type().is_dir() {
            let mut children = Vec::new();
            for child in std::fs::read_dir(path)? {
                children.push(child?.path());
            }
            children.sort_by(|left, right| {
                left.as_os_str()
                    .as_bytes()
                    .cmp(right.as_os_str().as_bytes())
            });
            for child in children {
                collect_tree_manifest_entries(
                    root,
                    &child,
                    previous,
                    excludes,
                    output,
                )?;
            }
        }
        let path_after = std::fs::symlink_metadata(path)?;
        if !tree_metadata_same(&metadata, &path_after) {
            return Err(ControllerError::Rejected(
                "tree entry changed during canonical manifest observation",
            ));
        }
        Ok(())
    }

    fn tree_entry_metadata_eq(
        left: &TreeManifestEntry,
        right: &TreeManifestEntry,
    ) -> bool {
        left.relative_path == right.relative_path
            && left.kind == right.kind
            && left.device == right.device
            && left.inode == right.inode
            && left.generation == right.generation
            && left.size == right.size
            && left.mode == right.mode
            && left.owner_uid == right.owner_uid
            && left.owner_gid == right.owner_gid
            && left.mtime == right.mtime
            && left.mtime_nsec == right.mtime_nsec
            && left.ctime == right.ctime
            && left.ctime_nsec == right.ctime_nsec
    }

    fn tree_metadata_same(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }

    fn tree_manifest_digest(entries: &[TreeManifestEntry]) -> Digest {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(
            b"catchplate/canonical-tree-manifest/v11\0",
        );
        for entry in entries {
            canonical.extend_from_slice(
                &(entry.relative_path.len() as u64).to_be_bytes(),
            );
            canonical.extend_from_slice(&entry.relative_path);
            canonical.push(entry.kind);
            canonical.extend_from_slice(&entry.device.to_be_bytes());
            canonical.extend_from_slice(&entry.inode.to_be_bytes());
            canonical.extend_from_slice(&entry.generation.to_be_bytes());
            canonical.extend_from_slice(&entry.size.to_be_bytes());
            canonical.extend_from_slice(&entry.mode.to_be_bytes());
            canonical.extend_from_slice(&entry.owner_uid.to_be_bytes());
            canonical.extend_from_slice(&entry.owner_gid.to_be_bytes());
            canonical.extend_from_slice(&entry.mtime.to_be_bytes());
            canonical.extend_from_slice(&entry.mtime_nsec.to_be_bytes());
            canonical.extend_from_slice(&entry.ctime.to_be_bytes());
            canonical.extend_from_slice(&entry.ctime_nsec.to_be_bytes());
            canonical.extend_from_slice(&entry.content_sha256);
        }
        sha256(&canonical)
    }

    fn artifact_tree_content_digest(
        entries: &[TreeManifestEntry],
    ) -> Digest {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(
            b"catchplate/artifact-content-tree/v11\0",
        );
        for entry in entries {
            canonical.extend_from_slice(
                &(entry.relative_path.len() as u64).to_be_bytes(),
            );
            canonical.extend_from_slice(&entry.relative_path);
            canonical.push(entry.kind);
            canonical.extend_from_slice(&entry.size.to_be_bytes());
            let immutable_mode = if entry.kind == b'L' {
                0
            } else {
                immutable_artifact_mode(entry.mode)
            };
            canonical.extend_from_slice(&immutable_mode.to_be_bytes());
            canonical.extend_from_slice(&entry.content_sha256);
        }
        sha256(&canonical)
    }

    fn promote_artifact_manifests_to_cas(
        state_root: &Path,
        manifests: &[(PathBuf, CanonicalTreeManifest)],
        expected: Digest,
        reader_gid: u32,
    ) -> Result<()> {
        let cas_parent = state_root.join("cas/sha256");
        std::fs::create_dir_all(&cas_parent)?;
        std::fs::set_permissions(
            state_root.join("cas"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        std::fs::set_permissions(
            &cas_parent,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let final_path = cas_parent.join(digest_hex(&expected));
        if final_path.is_dir() {
            return Ok(());
        }
        if final_path.exists()
            || std::fs::symlink_metadata(&final_path).is_ok()
        {
            return Err(ControllerError::Rejected(
                "artifact CAS target exists with another type",
            ));
        }
        let pending = cas_parent.join(format!(
            ".{}.pending-{}",
            digest_hex(&expected),
            unsafe { libc::getpid() },
        ));
        if pending.exists()
            || std::fs::symlink_metadata(&pending).is_ok()
        {
            return Err(ControllerError::Rejected(
                "artifact CAS pending target already exists",
            ));
        }
        std::fs::create_dir(&pending)?;
        std::fs::set_permissions(
            &pending,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let result = (|| -> Result<()> {
            for (index, (source_root, manifest)) in
                manifests.iter().enumerate()
            {
                if &manifest.root != source_root {
                    return Err(ControllerError::Rejected(
                        "artifact CAS source manifest root differs",
                    ));
                }
                let partition =
                    pending.join(format!("partition-{index:04}"));
                std::fs::create_dir(&partition)?;
                std::fs::set_permissions(
                    &partition,
                    std::fs::Permissions::from_mode(0o700),
                )?;
                copy_artifact_manifest(
                    source_root,
                    &partition,
                    manifest,
                    reader_gid,
                )?;
            }
            let mut canonical = Vec::new();
            canonical.extend_from_slice(
                b"catchplate/canonical-artifact-partitions/v11\0",
            );
            for (index, (original, _)) in
                manifests.iter().enumerate()
            {
                let partition =
                    pending.join(format!("partition-{index:04}"));
                let copied = refresh_tree_manifest(
                    &partition,
                    None,
                    &[],
                )?;
                canonical.extend_from_slice(
                    original.as_os_str().as_bytes(),
                );
                canonical.push(0);
                canonical.extend_from_slice(
                    &artifact_tree_content_digest(&copied.entries),
                );
            }
            if sha256(&canonical) != expected {
                return Err(ControllerError::Rejected(
                    "artifact CAS copy differs from the observed closure",
                ));
            }
            std::fs::set_permissions(
                &pending,
                std::fs::Permissions::from_mode(0o500),
            )?;
            std::fs::rename(&pending, &final_path)?;
            File::open(&cas_parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&pending);
        }
        result
    }

    fn copy_artifact_manifest(
        source_root: &Path,
        destination_root: &Path,
        manifest: &CanonicalTreeManifest,
        reader_gid: u32,
    ) -> Result<()> {
        for entry in &manifest.entries {
            let relative = PathBuf::from(
                std::ffi::OsString::from_vec(
                    entry.relative_path.clone(),
                ),
            );
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir
                            | std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                return Err(ControllerError::Rejected(
                    "artifact CAS manifest contains an unsafe path",
                ));
            }
            let source = source_root.join(&relative);
            let destination = destination_root.join(&relative);
            match entry.kind {
                b'D' => {
                    if !relative.as_os_str().is_empty() {
                        std::fs::create_dir(&destination)?;
                    }
                }
                b'F' => {
                    let source_c = CString::new(
                        source.as_os_str().as_bytes(),
                    )
                    .map_err(|_| {
                        ControllerError::Rejected(
                            "artifact source path contains NUL",
                        )
                    })?;
                    let raw = unsafe {
                        libc::open(
                            source_c.as_ptr(),
                            libc::O_RDONLY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW,
                        )
                    };
                    if raw < 0 {
                        return Err(
                            std::io::Error::last_os_error().into(),
                        );
                    }
                    let mut input =
                        unsafe { File::from_raw_fd(raw) };
                    let metadata = input.metadata()?;
                    if !metadata.file_type().is_file()
                        || metadata.len() != entry.size
                        || metadata.mode() != entry.mode
                    {
                        return Err(ControllerError::Rejected(
                            "artifact source identity changed before CAS copy",
                        ));
                    }
                    let mut output = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination)?;
                    let copied = std::io::copy(
                        &mut std::io::Read::by_ref(&mut input)
                            .take(entry.size),
                        &mut output,
                    )?;
                    if copied != entry.size {
                        return Err(ControllerError::Rejected(
                            "artifact CAS copy was truncated",
                        ));
                    }
                    input.seek(SeekFrom::Start(0))?;
                    if sha256_exact_reader(&mut input, entry.size)?
                        != entry.content_sha256
                    {
                        return Err(ControllerError::Rejected(
                            "artifact source digest changed during CAS copy",
                        ));
                    }
                    output.sync_all()?;
                }
                b'L' => {
                    let target = std::fs::read_link(&source)?;
                    if sha256(target.as_os_str().as_bytes())
                        != entry.content_sha256
                    {
                        return Err(ControllerError::Rejected(
                            "artifact symlink changed during CAS copy",
                        ));
                    }
                    std::os::unix::fs::symlink(
                        target,
                        &destination,
                    )?;
                }
                _ => {
                    return Err(ControllerError::Rejected(
                        "artifact CAS manifest contains a special file",
                    ))
                }
            }
        }
        for entry in manifest.entries.iter().rev() {
            if entry.kind == b'L' {
                continue;
            }
            let relative = PathBuf::from(
                std::ffi::OsString::from_vec(
                    entry.relative_path.clone(),
                ),
            );
            let destination = destination_root.join(relative);
            std::fs::set_permissions(
                &destination,
                std::fs::Permissions::from_mode(
                    immutable_artifact_mode(entry.mode),
                ),
            )?;
            let metadata = std::fs::symlink_metadata(&destination)?;
            if metadata.uid() != 0 || metadata.gid() != reader_gid {
                let destination_c = CString::new(
                    destination.as_os_str().as_bytes(),
                )
                .map_err(|_| {
                    ControllerError::Rejected(
                        "artifact CAS path contains NUL",
                    )
                })?;
                if unsafe {
                    libc::chown(
                        destination_c.as_ptr(),
                        0,
                        reader_gid,
                    )
                } != 0
                {
                    return Err(
                        std::io::Error::last_os_error().into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn immutable_artifact_mode(mode: u32) -> u32 {
        let immutable = mode & 0o555;
        immutable | ((immutable & 0o500) >> 3)
    }

    fn push_tree_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
        let length: u32 = value.len().try_into().map_err(|_| {
            ControllerError::Rejected("tree field exceeds u32")
        })?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value);
        Ok(())
    }

    fn read_tree_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
        let length = read_tree_u32(bytes, cursor)? as usize;
        let end = cursor.checked_add(length).ok_or(
            ControllerError::Invalid("tree field length overflow"),
        )?;
        let value = bytes
            .get(*cursor..end)
            .ok_or(ControllerError::Invalid("truncated tree field"))?
            .to_vec();
        *cursor = end;
        Ok(value)
    }

    fn read_tree_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
        let end = cursor
            .checked_add(4)
            .ok_or(ControllerError::Invalid("tree u32 offset overflow"))?;
        let value = u32::from_be_bytes(
            bytes
                .get(*cursor..end)
                .ok_or(ControllerError::Invalid("truncated tree u32"))?
                .try_into()
                .map_err(|_| ControllerError::Invalid("invalid tree u32"))?,
        );
        *cursor = end;
        Ok(value)
    }

    fn read_tree_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
        let end = cursor
            .checked_add(8)
            .ok_or(ControllerError::Invalid("tree u64 offset overflow"))?;
        let value = u64::from_be_bytes(
            bytes
                .get(*cursor..end)
                .ok_or(ControllerError::Invalid("truncated tree u64"))?
                .try_into()
                .map_err(|_| ControllerError::Invalid("invalid tree u64"))?,
        );
        *cursor = end;
        Ok(value)
    }

    fn read_tree_i64(bytes: &[u8], cursor: &mut usize) -> Result<i64> {
        Ok(read_tree_u64(bytes, cursor)? as i64)
    }

    impl TrustedHostProduction {
        fn observe_tree_cached(
            &self,
            root: &Path,
            label: &str,
            excludes: &[PathBuf],
        ) -> Result<Digest> {
            Ok(self
                .observe_tree_manifest_cached(root, label, excludes)?
                .manifest_sha256)
        }

        fn observe_tree_manifest_cached(
            &self,
            root: &Path,
            label: &str,
            excludes: &[PathBuf],
        ) -> Result<CanonicalTreeManifest> {
            let fanotify_generation =
                self.tree_drift_tracker.current_generation(root)?;
            let cached = self
                .tree_manifest_cache
                .lock()
                .map_err(|_| {
                    ControllerError::Unready(vec![
                        "canonical tree manifest cache lock poisoned"
                            .to_owned(),
                    ])
                })?
                .get(root)
                .cloned();
            if let Some(cached) = &cached {
                if cached.fanotify_generation == fanotify_generation {
                    return Ok(cached.manifest.clone());
                }
            }
            let previous = cached.map(|cached| cached.manifest);
            let root_owned = root.to_path_buf();
            let excludes_owned = excludes.to_vec();
            let bytes = self.run_bytes_worker(
                label,
                PROVIDER_MAX_BYTES,
                move || {
                    refresh_tree_manifest(
                        &root_owned,
                        previous.as_ref(),
                        &excludes_owned,
                    )?
                    .encode()
                },
            )?;
            let manifest = CanonicalTreeManifest::decode(&bytes)?;
            if manifest.root != root {
                return Err(ControllerError::Rejected(
                    "tree observer returned another root",
                ));
            }
            let observed = manifest.clone();
            self.tree_manifest_cache
                .lock()
                .map_err(|_| {
                    ControllerError::Unready(vec![
                        "canonical tree manifest cache lock poisoned"
                            .to_owned(),
                    ])
                })?
                .insert(
                    root.to_path_buf(),
                    CachedTreeManifest {
                        fanotify_generation,
                        manifest,
                    },
                );
            Ok(observed)
        }

        fn observe_artifacts_cached(&self, label: &str) -> Result<Digest> {
            let mut canonical = Vec::new();
            canonical.extend_from_slice(
                b"catchplate/canonical-artifact-partitions/v11\0",
            );
            for path in &self.artifact_paths {
                canonical.extend_from_slice(path.as_os_str().as_bytes());
                canonical.push(0);
                let manifest = self.observe_tree_manifest_cached(
                    path,
                    label,
                    &[],
                )?;
                canonical.extend_from_slice(
                    &artifact_tree_content_digest(&manifest.entries),
                );
            }
            Ok(sha256(&canonical))
        }

        fn promote_artifacts_to_cas(
            &self,
            artifact_closure_sha256: Digest,
        ) -> Result<()> {
            let mut manifests = Vec::with_capacity(
                self.artifact_paths.len(),
            );
            for path in &self.artifact_paths {
                manifests.push((
                    path.clone(),
                    self.observe_tree_manifest_cached(
                        path,
                        "artifact-cas-source",
                        &[],
                    )?,
                ));
            }
            let state_root = self.state.root_path.clone();
            let reader_gid = self.readiness_gid;
            let promoted = self.run_bytes_worker(
                "artifact-cas-promoter",
                32,
                move || {
                    promote_artifact_manifests_to_cas(
                        &state_root,
                        &manifests,
                        artifact_closure_sha256,
                        reader_gid,
                    )?;
                    Ok(artifact_closure_sha256.to_vec())
                },
            )?;
            if promoted.as_slice() != artifact_closure_sha256.as_slice() {
                return Err(ControllerError::Rejected(
                    "artifact CAS promoter returned another digest",
                ));
            }
            self.verify_promoted_artifact_cas(
                artifact_closure_sha256,
            )
        }

        fn verify_promoted_artifact_cas(
            &self,
            expected: Digest,
        ) -> Result<()> {
            let cas_root = self
                .state
                .root_path
                .join("cas/sha256")
                .join(digest_hex(&expected));
            let mut canonical = Vec::new();
            canonical.extend_from_slice(
                b"catchplate/canonical-artifact-partitions/v11\0",
            );
            for (index, original) in
                self.artifact_paths.iter().enumerate()
            {
                let partition =
                    cas_root.join(format!("partition-{index:04}"));
                canonical.extend_from_slice(
                    original.as_os_str().as_bytes(),
                );
                canonical.push(0);
                let manifest = self.observe_tree_manifest_cached(
                    &partition,
                    "artifact-cas-verifier",
                    &[],
                )?;
                canonical.extend_from_slice(
                    &artifact_tree_content_digest(&manifest.entries),
                );
            }
            if sha256(&canonical) != expected {
                return Err(ControllerError::Rejected(
                    "promoted artifact CAS differs from its build closure",
                ));
            }
            Ok(())
        }

        fn execute(
            &self,
            submission: &ClientSubmission,
            frame: &PreallocationFrame,
            peer_binding_sha256: Digest,
            peer_start_time_ticks: u64,
            peer_uid: u32,
            peer_gid: u32,
        ) -> Result<Vec<u8>> {
            self.readiness.require_ready()?;
            let admission_wall_start = now_unix_ms()?;
            if frame.deadline_unix_ms <= admission_wall_start {
                return Err(ControllerError::Rejected(
                    "request expired before queued admission",
                ));
            }
            let admission_deadline = Instant::now()
                .checked_add(Duration::from_millis(
                    frame.deadline_unix_ms - admission_wall_start,
                ))
                .ok_or(ControllerError::Rejected(
                    "queued admission deadline overflow",
                ))?;
            let mut observed = self.queued_executions.load(Ordering::Acquire);
            loop {
                if observed >= self.maximum_queued_executions {
                    return Err(ControllerError::Unready(vec![
                        "bounded execution admission queue is full".to_owned(),
                    ]));
                }
                match self.queued_executions.compare_exchange_weak(
                    observed,
                    observed + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(current) => observed = current,
                }
            }
            let queue_permit = ExecutionQueuePermit {
                queued: &self.queued_executions,
            };
            let _supervisor_guard = loop {
                if Instant::now() >= admission_deadline
                    || now_unix_ms()? >= frame.deadline_unix_ms
                {
                    return Err(ControllerError::Rejected(
                        "request expired in bounded execution admission queue",
                    ));
                }
                match self.execution_lock.try_lock() {
                    Ok(guard) => break guard,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(ControllerError::Unready(vec![
                            "shared direct supervisor execution lane lock poisoned"
                                .to_owned(),
                        ]))
                    }
                }
            };
            drop(queue_permit);
            let plan = self
                .plans
                .get(&submission.lane.plan)
                .ok_or(ControllerError::Rejected("fixed launch plan is absent"))?;
            let build_plan = self
                .plans
                .get(&Plan::Build)
                .ok_or(ControllerError::Rejected("fixed build plan is absent"))?;
            let lane_deadline_ms = *self
                .deadlines_ms
                .get(&submission.lane.plan)
                .ok_or(ControllerError::Rejected("lane deadline is absent"))?;
            let now = now_unix_ms()?;
            if frame.deadline_unix_ms <= now {
                return Err(ControllerError::Rejected(
                    "request expired after queued admission",
                ));
            }
            let transport_remaining = frame.deadline_unix_ms - now;
            let effective_timeout_ms = lane_deadline_ms.min(transport_remaining);
            if effective_timeout_ms < 100 {
                return Err(ControllerError::Rejected(
                    "effective monotonic execution window is too short",
                ));
            }
            let request_monotonic_start = Instant::now();
            let deadline = request_monotonic_start
                .checked_add(Duration::from_millis(effective_timeout_ms))
                .ok_or(ControllerError::Rejected(
                    "monotonic lane deadline overflow",
                ))?;
            let _io_deadline = self.enter_lane_io_deadline(deadline)?;
            if let Err(error) = self.verify_trusted_plan_table_bounded() {
                let reason =
                    format!("trusted five-plan table revalidation failed: {error}");
                self.quarantine(&reason)?;
                return Err(error);
            }
            let mut preflight_errors = Vec::new();
            let current_plan_identity = self.run_digest_provider(
                "fixed-plan-verifier",
                bounded_provider_timeout(deadline)?,
                || verify_fixed_plan(plan),
            );
            if !matches!(
                current_plan_identity,
                Ok(identity) if identity == plan.command_identity_sha256
            ) {
                let reason =
                    "current fixed plan differs from retained measured launch token";
                self.quarantine(reason)?;
                return Err(ControllerError::Unready(vec![reason.to_owned()]));
            }
            if submission.lane.plan != Plan::Build {
                let build_plan_identity = self.run_digest_provider(
                    "fixed-build-plan-verifier",
                    bounded_provider_timeout(deadline)?,
                    || verify_fixed_plan(build_plan),
                );
                if !matches!(
                    build_plan_identity,
                    Ok(identity) if identity == build_plan.command_identity_sha256
                ) {
                    let reason =
                        "original build plan differs from retained measured launch token";
                    self.quarantine(reason)?;
                    return Err(ControllerError::Unready(vec![reason.to_owned()]));
                }
            }
            let source_measurement = self.observe_tree_cached(
                &self.source_root,
                "source-observer",
                &self.artifact_paths,
            );
            let (source_sha256, source_observation_error) = match source_measurement {
                Ok(digest) => (digest, None),
                Err(error) => (
                    self.source_root_identity_sha256,
                    Some(format!("source observation unavailable: {error}")),
                ),
            };
            if let Some(error) = &source_observation_error {
                preflight_errors.push(error.clone());
            }
            if source_sha256 != submission.source_tree_sha256 {
                return Err(ControllerError::Rejected(
                    "signed request source tree differs from the measured read-only snapshot",
                ));
            }
            if plan.configuration_sha256
                != submission.plan_configuration_sha256
            {
                return Err(ControllerError::Rejected(
                    "signed request plan configuration differs from the fixed launch plan",
                ));
            }
            let request = RequestContext {
                request_id: submission.request_id,
                exact_signed_request_sha256:
                    submission.exact_signed_request_sha256(),
                nonce_sha256: sha256(&submission.raw_nonce),
                peer_binding_sha256,
                transport_deadline_unix_ms: frame.deadline_unix_ms,
                lane_deadline_ms,
                source_sha256,
                current_command_sha256: plan.command_identity_sha256,
                original_build_command_sha256: build_plan.command_identity_sha256,
                config_sha256: self.config_sha256,
                provider_measurement_sha256: self.provider_measurement_sha256,
                source_root_identity_sha256: self.source_root_identity_sha256,
                trust_epoch: self.trust_epoch,
                revocation_epoch: self.revocation_epoch,
            };
            if submission.lane.plan != Plan::Build {
                let committed = self.require_build_success(
                    request.source_sha256,
                    request.original_build_command_sha256,
                )?;
                if committed.artifact_closure_sha256 == [0; 32] {
                    return Err(ControllerError::Rejected(
                        "runNoBuild rejected before acceptance because the build closure is not successful",
                    ));
                }
            }
            match self.acceptance_decision(submission.lane, &request)? {
                AcceptanceDecision::Replay(receipt) => Ok(receipt),
                AcceptanceDecision::InFlight(lease) => {
                    let evidence = sha256(b"acceptance-in-flight");
                    let build = self.current_build_binding_if_any(
                        request.source_sha256,
                        request.original_build_command_sha256,
                        evidence,
                    )?;
                    self.finalize_receipt(
                        submission.lane,
                        request,
                        &lease,
                        ReceiptTerminal::Unknown,
                        build.as_ref(),
                        build
                            .as_ref()
                            .map(|record| record.artifact_closure_sha256)
                            .unwrap_or([0; 32]),
                        evidence,
                        -1,
                        "accepted request was already in flight; execution was not repeated",
                        request_monotonic_start,
                        now,
                    )
                }
                AcceptanceDecision::New(lease) => {
                    let trusted_start_unix_ms = now;
                    if !preflight_errors.is_empty() {
                        let error = preflight_errors.join("; ");
                        let evidence = sha256(error.as_bytes());
                        let build = self.current_build_binding_if_any(
                            request.source_sha256,
                            request.original_build_command_sha256,
                            evidence,
                        )?;
                        return self.finalize_receipt(
                            submission.lane,
                            request,
                            &lease,
                            ReceiptTerminal::Unknown,
                            build.as_ref(),
                            build
                                .as_ref()
                                .map(|record| record.artifact_closure_sha256)
                                .unwrap_or([0; 32]),
                            evidence,
                            -1,
                            &error,
                            request_monotonic_start,
                            trusted_start_unix_ms,
                        );
                    }
                    let result = if submission.lane.plan == Plan::Build {
                        self.execute_build(
                            plan,
                            &request,
                            peer_uid,
                            peer_gid,
                            peer_start_time_ticks,
                            deadline,
                        )
                    } else {
                        self.execute_no_build(
                            plan,
                            build_plan,
                            &request,
                            peer_uid,
                            peer_gid,
                            peer_start_time_ticks,
                            deadline,
                        )
                    };
                    let result = match result {
                        Ok((mut outcome, build)) => {
                            let observation = remaining_duration(deadline)
                                .and_then(|_| {
                                    self.observe_tree_cached(
                                        &self.source_root,
                                        "post-run-source-observer",
                                        &self.artifact_paths,
                                    )
                                });
                            match observation {
                                Ok(after) if after == request.source_sha256 => {}
                                Ok(_) => {
                                    let reason =
                                        "source closure changed during trusted-host execution";
                                    self.quarantine(reason)?;
                                    outcome = ExecutionOutcome {
                                        terminal: ReceiptTerminal::Unknown,
                                        exit_status: outcome.exit_status,
                                        evidence_sha256: sha256(reason.as_bytes()),
                                        reason: reason.to_owned(),
                                    };
                                }
                                Err(error) => {
                                    let reason = format!(
                                        "post-run source closure was unproved: {error}"
                                    );
                                    self.quarantine(&reason)?;
                                    outcome = ExecutionOutcome {
                                        terminal: ReceiptTerminal::Unknown,
                                        exit_status: outcome.exit_status,
                                        evidence_sha256: sha256(reason.as_bytes()),
                                        reason,
                                    };
                                }
                            }
                            Ok((outcome, build))
                        }
                        Err(error) => Err(error),
                    };
                    match result {
                        Ok((outcome, build)) => self.finalize_receipt(
                            submission.lane,
                            request,
                            &lease,
                            outcome.terminal,
                            build.as_ref(),
                            build
                                .as_ref()
                                .map(|record| record.artifact_closure_sha256)
                                .unwrap_or([0; 32]),
                            outcome.evidence_sha256,
                            outcome.exit_status,
                            &outcome.reason,
                            request_monotonic_start,
                            trusted_start_unix_ms,
                        ),
                        Err(error) => {
                            let evidence =
                                sha256(error.to_string().as_bytes());
                            let build = self.current_build_binding_if_any(
                                request.source_sha256,
                                request.original_build_command_sha256,
                                evidence,
                            )?;
                            self.finalize_receipt(
                                submission.lane,
                                request,
                                &lease,
                                ReceiptTerminal::Unknown,
                                build.as_ref(),
                                build
                                    .as_ref()
                                    .map(|record| {
                                        record.artifact_closure_sha256
                                    })
                                    .unwrap_or([0; 32]),
                                evidence,
                                -1,
                                &format!(
                                    "trusted-host production error: {error}"
                                ),
                                request_monotonic_start,
                                trusted_start_unix_ms,
                            )
                        }
                    }
                }
            }
        }

        fn execute_build(
            &self,
            plan: &FixedLaunchPlan,
            request: &RequestContext,
            peer_uid: u32,
            peer_gid: u32,
            peer_start_time_ticks: u64,
            deadline: Instant,
        ) -> Result<(ExecutionOutcome, Option<CommittedBuildRecord>)> {
            match self.reserve_build(
                request.source_sha256,
                request.original_build_command_sha256,
            )? {
                BuildDecision::Existing(record) => {
                    remaining_duration(deadline)?;
                    let measured = self.observe_artifacts_cached(
                        "existing-build-artifact-observer",
                    )?;
                    if measured != record.artifact_closure_sha256 {
                        let reason =
                            "existing committed build artifact closure changed";
                        self.quarantine(reason)?;
                        return Ok((
                            ExecutionOutcome {
                                terminal: ReceiptTerminal::Unknown,
                                exit_status: -1,
                                evidence_sha256: sha256(
                                    b"existing-build-artifact-closure-mismatch",
                                ),
                                reason: reason.to_owned(),
                            },
                            Some(record),
                        ));
                    }
                    let mut evidence = Vec::new();
                    evidence.extend_from_slice(b"catchplate/build-cache-hit/v11\0");
                    evidence.extend_from_slice(&record.commit_sha256);
                    evidence.extend_from_slice(&measured);
                    Ok((
                        ExecutionOutcome {
                            terminal: ReceiptTerminal::Success,
                            exit_status: 0,
                            evidence_sha256: self.persist_evidence(&evidence)?,
                            reason: "exact committed build already exists; build was not repeated"
                                .to_owned(),
                        },
                        Some(record),
                    ))
                }
                BuildDecision::InFlight(reservation) => {
                    let evidence_sha256 = sha256(b"build-reservation-in-flight");
                    let committed_terminal = self.commit_build_terminal(
                        &reservation,
                        ReceiptTerminal::Unknown,
                        evidence_sha256,
                    )?;
                    let receipt_binding = CommittedBuildRecord {
                        reservation: committed_terminal.reservation,
                        artifact_closure_sha256: [0; 32],
                        commit_sha256:
                            committed_terminal.commit_sha256,
                    };
                    Ok((
                        ExecutionOutcome {
                            terminal: ReceiptTerminal::Unknown,
                            exit_status: -1,
                            evidence_sha256,
                            reason:
                                "build reservation already existed; exactly-once build was not repeated"
                                    .to_owned(),
                        },
                        Some(receipt_binding),
                    ))
                }
                BuildDecision::Terminal(committed_terminal) => {
                    Ok((
                        ExecutionOutcome {
                            terminal: committed_terminal.terminal,
                            exit_status: -1,
                            evidence_sha256:
                                committed_terminal.evidence_sha256,
                            reason: format!(
                                "source digest has an exact committed {:?} build terminal",
                                committed_terminal.terminal,
                            ),
                        },
                        Some(CommittedBuildRecord {
                            reservation:
                                committed_terminal.reservation,
                            artifact_closure_sha256: [0; 32],
                            commit_sha256:
                                committed_terminal.commit_sha256,
                        }),
                    ))
                }
                BuildDecision::Reserved(reservation) => {
                    let execution = match self.run_fixed_command(
                        plan,
                        request,
                        peer_uid,
                        peer_gid,
                        peer_start_time_ticks,
                        false,
                        sha256(
                            &[
                                b"catchplate/build-pre-seal/v11\0"
                                    .as_slice(),
                                request
                                    .exact_signed_request_sha256
                                    .as_slice(),
                            ]
                            .concat(),
                        ),
                        deadline,
                    ) {
                        Ok(execution) => execution,
                        Err(error) => {
                            let evidence_sha256 = sha256(error.to_string().as_bytes());
                            let committed_terminal =
                                self.commit_build_terminal(
                                &reservation,
                                ReceiptTerminal::Unknown,
                                evidence_sha256,
                            )?;
                            return Ok((
                                ExecutionOutcome {
                                    terminal: ReceiptTerminal::Unknown,
                                    exit_status: -1,
                                    evidence_sha256,
                                    reason: format!(
                                        "build runtime failed after reservation: {error}"
                                    ),
                                },
                                Some(CommittedBuildRecord {
                                    reservation:
                                        committed_terminal.reservation,
                                    artifact_closure_sha256: [0; 32],
                                    commit_sha256:
                                        committed_terminal.commit_sha256,
                                }),
                            ));
                        }
                    };
                    if execution.terminal != ReceiptTerminal::Success {
                        let committed_terminal = self.commit_build_terminal(
                            &reservation,
                            execution.terminal,
                            execution.evidence_sha256,
                        )?;
                        return Ok((
                            ExecutionOutcome {
                                terminal: execution.terminal,
                                exit_status: execution.exit_status,
                                evidence_sha256: execution.evidence_sha256,
                                reason: execution.reason,
                            },
                            Some(CommittedBuildRecord {
                                reservation:
                                    committed_terminal.reservation,
                                artifact_closure_sha256: [0; 32],
                                commit_sha256:
                                    committed_terminal.commit_sha256,
                            }),
                        ));
                    }
                    remaining_duration(deadline)?;
                    let artifact_closure_sha256 =
                        match self.observe_artifacts_cached(
                            "build-artifact-observer",
                        ) {
                        Ok(digest) => digest,
                        Err(error) => {
                            let evidence_sha256 = sha256(error.to_string().as_bytes());
                            let committed_terminal =
                                self.commit_build_terminal(
                                &reservation,
                                ReceiptTerminal::Unknown,
                                evidence_sha256,
                            )?;
                            return Ok((
                                ExecutionOutcome {
                                    terminal: ReceiptTerminal::Unknown,
                                    exit_status: execution.exit_status,
                                    evidence_sha256,
                                    reason: format!(
                                        "build completed but artifact closure was unproved: {error}"
                                    ),
                                },
                                Some(CommittedBuildRecord {
                                    reservation:
                                        committed_terminal.reservation,
                                    artifact_closure_sha256: [0; 32],
                                    commit_sha256:
                                        committed_terminal.commit_sha256,
                                }),
                            ));
                        }
                    };
                    self.promote_artifacts_to_cas(
                        artifact_closure_sha256,
                    )?;
                    if self.observe_artifacts_cached(
                        "post-cas-build-artifact-observer",
                    )? != artifact_closure_sha256
                    {
                        return Err(ControllerError::Rejected(
                            "build artifacts changed during CAS promotion",
                        ));
                    }
                    let committed =
                        self.commit_build_success(&reservation, artifact_closure_sha256)?;
                    Ok((execution, Some(committed)))
                }
            }
        }

        fn execute_no_build(
            &self,
            plan: &FixedLaunchPlan,
            build_plan: &FixedLaunchPlan,
            request: &RequestContext,
            peer_uid: u32,
            peer_gid: u32,
            peer_start_time_ticks: u64,
            deadline: Instant,
        ) -> Result<(ExecutionOutcome, Option<CommittedBuildRecord>)> {
            if plan.command_identity_sha256 == build_plan.command_identity_sha256 {
                return Err(ControllerError::Rejected(
                    "runNoBuild lane resolved to build command identity",
                ));
            }
            let committed = self.require_build_success(
                request.source_sha256,
                build_plan.command_identity_sha256,
            )?;
            remaining_duration(deadline)?;
            if let Err(error) = self.verify_promoted_artifact_cas(
                committed.artifact_closure_sha256,
            ) {
                let reason =
                    "runNoBuild rejected because promoted build CAS changed";
                self.quarantine(reason)?;
                return Ok((
                    ExecutionOutcome {
                        terminal: ReceiptTerminal::Unknown,
                        exit_status: -1,
                        evidence_sha256: sha256(
                            error.to_string().as_bytes(),
                        ),
                        reason: format!("{reason}: {error}"),
                    },
                    Some(committed),
                ));
            }
            let execution = match self.run_fixed_command(
                plan,
                request,
                peer_uid,
                peer_gid,
                peer_start_time_ticks,
                true,
                committed.artifact_closure_sha256,
                deadline,
            ) {
                Ok(execution) => execution,
                Err(error) => {
                    return Ok((
                        ExecutionOutcome {
                            terminal: ReceiptTerminal::Unknown,
                            exit_status: -1,
                            evidence_sha256: sha256(error.to_string().as_bytes()),
                            reason: format!("runNoBuild runtime was unproved: {error}"),
                        },
                        Some(committed),
                    ))
                }
            };
            remaining_duration(deadline)?;
            if let Err(error) = self.verify_promoted_artifact_cas(
                committed.artifact_closure_sha256,
            ) {
                let reason =
                    "runNoBuild promoted artifact CAS changed";
                self.quarantine(reason)?;
                return Ok((
                    ExecutionOutcome {
                        terminal: ReceiptTerminal::Unknown,
                        exit_status: execution.exit_status,
                        evidence_sha256: sha256(
                            error.to_string().as_bytes(),
                        ),
                        reason: format!("{reason}: {error}"),
                    },
                    Some(committed),
                ));
            }
            Ok((execution, Some(committed)))
        }

        fn arm_workload_watchdog(
            &self,
            workload: &RegisteredChild,
            deadline: Instant,
        ) -> Result<RegisteredWatchdog> {
            let workload_barrier = workload
                .barrier
                .as_ref()
                .ok_or(ControllerError::Rejected(
                    "workload barrier is absent before watchdog creation",
                ))?
                .as_raw_fd();
            let broker_pid = unsafe { libc::getpid() };
            let broker_pidfd = pidfd_open(broker_pid)?;
            let frontend_pidfd = self.frontend_pidfd.as_raw_fd();
            let (control_read, control_write) = pipe_cloexec()?;
            let control_write_fd = control_write.as_raw_fd();
            let (acknowledgement_read, acknowledgement_write) = pipe_cloexec()?;
            let acknowledgement_read_fd = acknowledgement_read.as_raw_fd();
            let workload_cgroup = workload.cgroup_directory.as_raw_fd();
            let workload_pid = workload.pid;
            let workload_start_time_ticks = workload.start_time_ticks;
            let journal_directory = self.state.orphan_journal.as_raw_fd();
            let base = self.next_action_name("watchdog-journal")?;
            let armed_journal_name =
                format!("{}.armed", base.to_string_lossy());
            let closure_journal_name =
                format!("{}.journal", base.to_string_lossy());
            let armed_journal_name_c =
                CString::new(armed_journal_name.clone()).map_err(|_| {
                    ControllerError::Invalid(
                        "watchdog armed journal name contains NUL",
                    )
                })?;
            let closure_journal_name_c =
                CString::new(closure_journal_name.clone()).map_err(|_| {
                    ControllerError::Invalid(
                        "watchdog closure journal name contains NUL",
                    )
                })?;
            let armed_record = watchdog_arm_record(
                self.frontend_pid,
                broker_pid,
                workload_cgroup,
                &workload.cgroup_name,
                workload_pid,
                workload_start_time_ticks,
                deadline,
            )?;
            let armed_record_sha256 = sha256(&armed_record);
            let child_armed_record = armed_record.clone();
            let mut child = self.spawn_registered_active(
                "independent-watchdog",
                move |output| {
                    unsafe {
                        libc::close(control_write_fd);
                        libc::close(acknowledgement_read_fd);
                    }
                    watchdog_main(
                        frontend_pidfd,
                        broker_pidfd.as_raw_fd(),
                        control_read.as_raw_fd(),
                        workload_cgroup,
                        workload_pid,
                        workload_start_time_ticks,
                        journal_directory,
                        &armed_journal_name_c,
                        &closure_journal_name_c,
                        &child_armed_record,
                        deadline,
                        acknowledgement_write.as_raw_fd(),
                        output,
                    )
                },
            )?;
            let arm_deadline = deadline.min(self.cleanup_deadline());
            if let Err(error) = wait_watchdog_armed(
                acknowledgement_read.as_raw_fd(),
                arm_deadline,
            ) {
                let cleanup = self.cleanup_registered_child(
                    &mut child,
                    None,
                    true,
                    true,
                );
                let reason = format!(
                    "independent watchdog durable arm failed: {error}"
                );
                let quarantine = self.quarantine(&reason);
                return Err(ControllerError::Unready(vec![format!(
                    "{reason}; watchdog cleanup={}; quarantine={}",
                    cleanup
                        .err()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "ok".to_owned()),
                    quarantine
                        .err()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "ok".to_owned()),
                )]));
            }
            let armed_read_name = armed_journal_name.clone();
            let armed_readback = self.run_bytes_worker_with_closed_fds(
                "watchdog-armed-journal-readback",
                1024,
                &[workload_barrier],
                move || {
                    require_immutable_state_file(
                        journal_directory,
                        &armed_read_name,
                    )?;
                    read_required_state_file(
                        journal_directory,
                        &armed_read_name,
                    )
                },
            );
            let readback_error = match armed_readback {
                Ok(readback) if readback == armed_record => None,
                Ok(_) => Some(
                    "durable armed journal readback mismatch".to_owned(),
                ),
                Err(error) => Some(error.to_string()),
            };
            if let Some(readback_error) = readback_error {
                let watchdog_kill = signal_watchdog_and_wait(
                    control_write.as_raw_fd(),
                    acknowledgement_read.as_raw_fd(),
                    b'K',
                    self.cleanup_deadline(),
                );
                let cleanup = self.cleanup_registered_child(
                    &mut child,
                    None,
                    true,
                    true,
                );
                let reason = format!(
                    "independent watchdog durable arm was not proved: {readback_error}"
                );
                let quarantine = self.quarantine(&reason);
                return Err(ControllerError::Unready(vec![format!(
                    "{reason}; watchdog closure={}; cleanup={}; quarantine={}",
                    watchdog_kill
                        .err()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "ok".to_owned()),
                    cleanup
                        .err()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "ok".to_owned()),
                    quarantine
                        .err()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "ok".to_owned()),
                )]));
            }
            Ok(RegisteredWatchdog {
                child,
                control: control_write,
                acknowledgement: acknowledgement_read,
                armed_journal_name,
                closure_journal_name,
                armed_record_sha256,
            })
        }

        fn quarantine(&self, reason: &str) -> Result<()> {
            self.readiness.hard_unready(reason.to_owned());
            if self.quarantine_active.swap(true, Ordering::AcqRel) {
                return Err(ControllerError::Unready(vec![format!(
                    "recursive quarantine suppressed after hard-unready: {reason}"
                )]));
            }
            let _quarantine_guard = QuarantineGuard {
                active: &self.quarantine_active,
            };
            self.persist_quarantine_journal(reason).map_err(|error| {
                ControllerError::Unready(vec![format!(
                    "quarantine journal was incomplete for {reason}: {error}"
                )])
            })
        }

        fn quarantine_failure<T>(
            &self,
            context: &str,
            error: ControllerError,
        ) -> Result<T> {
            let reason = format!("{context}: {error}");
            self.readiness.hard_unready(reason.clone());
            match self.quarantine(&reason) {
                Ok(()) => Err(error),
                Err(quarantine_error) => {
                    Err(ControllerError::Unready(vec![format!(
                        "{reason}; durable quarantine failed: {quarantine_error}"
                    )]))
                }
            }
        }

        fn persist_quarantine_journal(&self, reason: &str) -> Result<()> {
            let base = self.next_action_name("controller-quarantine")?;
            let name = CString::new(format!("{}.journal", base.to_string_lossy()))
                .map_err(|_| ControllerError::Invalid("quarantine journal name contains NUL"))?;
            let mut record = Vec::new();
            record.extend_from_slice(b"catchplate/controller-quarantine/v11\0");
            record.extend_from_slice(reason.as_bytes());
            record.push(0);
            let directory = self.state.orphan_journal.as_raw_fd();
            let journal = self.spawn_registered_active(
                "controller-quarantine-journal",
                move |output| {
                    if write_durable_journal(directory, &name, &record).is_ok()
                        && write_all_fd(output, b"durable-quarantine-journal").is_ok()
                    {
                        0
                    } else {
                        125
                    }
                },
            )?;
            let journal_outcome = self.collect_child(
                journal,
                self.cleanup_deadline(),
                4096,
                None,
            )?;
            if !wait_status_success(journal_outcome.wait_status)
                || journal_outcome.timed_out
                || !journal_outcome.cleanup_proved
                || journal_outcome.output != b"durable-quarantine-journal"
            {
                return Err(ControllerError::Unready(vec![format!(
                    "quarantine journal worker was not durably proved for: {reason}"
                )]));
            }
            Ok(())
        }

        fn cleanup_held_launch(
            &self,
            workload: &mut RegisteredChild,
            reason: &str,
        ) -> Result<()> {
            let mut failures = Vec::new();
            if let Err(error) =
                self.cleanup_registered_child(workload, None, true, true)
            {
                failures.push(format!("workload cleanup: {error}"));
            }
            if let Err(error) = self.quarantine(reason) {
                failures.push(format!("durable quarantine: {error}"));
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(ControllerError::Unready(vec![format!(
                    "{reason}; {}",
                    failures.join("; ")
                )]))
            }
        }

        fn cleanup_with_released_watchdog(
            &self,
            workload: Option<&mut RegisteredChild>,
            monitor: Option<&mut RegisteredChild>,
            watchdog: RegisteredWatchdog,
            reason: &str,
        ) -> Result<()> {
            let mut failures = Vec::new();
            let mut watchdog_closure_proved = match signal_watchdog_and_wait(
                watchdog.control.as_raw_fd(),
                watchdog.acknowledgement.as_raw_fd(),
                b'K',
                self.cleanup_deadline(),
            ) {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("watchdog quarantine signal: {error}"));
                    false
                }
            };
            drop(watchdog.control);
            drop(watchdog.acknowledgement);
            match self.collect_child(
                watchdog.child,
                self.cleanup_deadline(),
                PROVIDER_MAX_BYTES,
                None,
            ) {
                Ok(outcome)
                    if wait_status_success(outcome.wait_status)
                        && !outcome.timed_out
                        && outcome.cleanup_proved => {}
                Ok(_) => {
                    watchdog_closure_proved = false;
                    failures.push(
                        "watchdog did not prove cgroup.kill, durable journal, and cleanup"
                            .to_owned(),
                    );
                }
                Err(error) => {
                    watchdog_closure_proved = false;
                    failures.push(format!("watchdog collection: {error}"));
                }
            }
            if let Some(monitor) = monitor {
                if let Err(error) =
                    self.cleanup_registered_child(monitor, None, true, true)
                {
                    failures.push(format!("monitor cleanup: {error}"));
                }
            }
            if let Some(workload) = workload {
                if let Err(error) =
                    self.cleanup_registered_child(
                        workload,
                        None,
                        true,
                        !watchdog_closure_proved,
                    )
                {
                    failures.push(format!("workload cleanup: {error}"));
                }
            }
            if let Err(error) = self.quarantine(reason) {
                failures.push(format!("durable quarantine: {error}"));
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(ControllerError::Unready(vec![format!(
                    "{reason}; {}",
                    failures.join("; ")
                )]))
            }
        }

        fn cleanup_authorized_released_launch(
            &self,
            workload: Option<&mut RegisteredChild>,
            monitor: Option<&mut RegisteredChild>,
            watchdog: RegisteredWatchdog,
            reason: &str,
            capability: &VerifiedTrustedHostDirectContainmentCapability,
        ) -> Result<()> {
            if let Some(workload) = workload.as_deref() {
                Self::verify_workload_capability_binding(
                    workload,
                    capability.gate(),
                    None,
                )?;
            }
            self.cleanup_with_released_watchdog(
                workload,
                monitor,
                watchdog,
                reason,
            )
        }

        fn finalize_receipt(
            &self,
            lane: Lane,
            request: RequestContext,
            lease: &VerifiedAcceptanceLease,
            terminal: ReceiptTerminal,
            build: Option<&CommittedBuildRecord>,
            artifact_closure_sha256: Digest,
            execution_evidence_sha256: Digest,
            exit_status: i32,
            reason: &str,
            monotonic_start: Instant,
            trusted_start_unix_ms: u64,
        ) -> Result<Vec<u8>> {
            let trusted_end_unix_ms = now_unix_ms()?;
            if trusted_end_unix_ms < trusted_start_unix_ms
                || (terminal == ReceiptTerminal::Success
                    && trusted_end_unix_ms > request.transport_deadline_unix_ms)
            {
                return Err(ControllerError::Rejected(
                    "trusted-host clock order/deadline check failed before receipt signing",
                ));
            }
            let elapsed = monotonic_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            if lease.request_binding_sha256 != request.binding_sha256(lane.plan) {
                return Err(ControllerError::Rejected(
                    "receipt cannot bind an acceptance lease for another request",
                ));
            }
            if build.is_none() {
                return Err(ControllerError::Rejected(
                    "typed receipt requires an exact current build reservation binding; reject before receipt otherwise",
                ));
            }
            if let Some(record) = build {
                self.reverify_current_build_reservation(&record.reservation)?;
                if record.reservation.source_sha256 != request.source_sha256
                    || record.reservation.original_build_command_sha256
                        != request.original_build_command_sha256
                    || artifact_closure_sha256 != record.artifact_closure_sha256
                {
                    return Err(ControllerError::Rejected(
                        "receipt build record does not exact-bind source/command/artifact",
                    ));
                }
                if terminal == ReceiptTerminal::Success {
                    let committed = self.require_build_success(
                        request.source_sha256,
                        request.original_build_command_sha256,
                    )?;
                    if committed.reservation.fence != record.reservation.fence
                        || committed.reservation.identity_sha256
                            != record.reservation.identity_sha256
                        || committed.reservation.generation
                            != record.reservation.generation
                        || committed.commit_sha256 != record.commit_sha256
                        || committed.artifact_closure_sha256
                            != record.artifact_closure_sha256
                    {
                        return Err(ControllerError::Rejected(
                            "successful receipt differs from current committed build CAS",
                        ));
                    }
                }
            }
            let (
                build_fence,
                build_identity,
                build_generation,
                committed_build_command_sha256,
                build_commit_sha256,
            ) = build
                .map(|record| {
                    (
                        record.reservation.fence,
                        record.reservation.identity_sha256,
                        record.reservation.generation,
                        record.reservation.original_build_command_sha256,
                        record.commit_sha256,
                    )
                })
                .unwrap_or((0, [0; 32], 0, [0; 32], [0; 32]));

            let mut terminal_evidence = Vec::new();
            terminal_evidence.extend_from_slice(b"catchplate/receipt-terminal-evidence/v11\0");
            terminal_evidence.push(terminal as u8);
            terminal_evidence.extend_from_slice(lane.plan.as_label().as_bytes());
            terminal_evidence.push(0);
            terminal_evidence.extend_from_slice(&request.request_id);
            terminal_evidence.extend_from_slice(&request.nonce_sha256);
            terminal_evidence.extend_from_slice(&request.peer_binding_sha256);
            terminal_evidence
                .extend_from_slice(&request.transport_deadline_unix_ms.to_be_bytes());
            terminal_evidence.extend_from_slice(&request.lane_deadline_ms.to_be_bytes());
            terminal_evidence.extend_from_slice(&request.source_sha256);
            terminal_evidence.extend_from_slice(&request.current_command_sha256);
            terminal_evidence.extend_from_slice(&request.original_build_command_sha256);
            terminal_evidence.extend_from_slice(&request.config_sha256);
            terminal_evidence.extend_from_slice(&request.provider_measurement_sha256);
            terminal_evidence.extend_from_slice(&self.trusted_plan_table_sha256);
            terminal_evidence.extend_from_slice(&self.trusted_plan_manifest_sha256);
            terminal_evidence.extend_from_slice(&request.source_root_identity_sha256);
            terminal_evidence.extend_from_slice(&request.trust_epoch.to_be_bytes());
            terminal_evidence.extend_from_slice(&request.revocation_epoch.to_be_bytes());
            terminal_evidence.extend_from_slice(&lease.fence.to_be_bytes());
            terminal_evidence.extend_from_slice(&lease.identity_sha256);
            terminal_evidence.extend_from_slice(&lease.generation.to_be_bytes());
            terminal_evidence.extend_from_slice(&lease.claim_sha256);
            terminal_evidence.extend_from_slice(&build_fence.to_be_bytes());
            terminal_evidence.extend_from_slice(&build_identity);
            terminal_evidence.extend_from_slice(&build_generation.to_be_bytes());
            terminal_evidence.extend_from_slice(&committed_build_command_sha256);
            terminal_evidence.extend_from_slice(&build_commit_sha256);
            terminal_evidence.extend_from_slice(&artifact_closure_sha256);
            terminal_evidence.extend_from_slice(&execution_evidence_sha256);
            terminal_evidence.extend_from_slice(&trusted_start_unix_ms.to_be_bytes());
            terminal_evidence.extend_from_slice(&trusted_end_unix_ms.to_be_bytes());
            terminal_evidence.extend_from_slice(&elapsed.to_be_bytes());
            terminal_evidence.extend_from_slice(&exit_status.to_be_bytes());
            terminal_evidence.extend_from_slice(&sha256(reason.as_bytes()));
            terminal_evidence
                .extend_from_slice(&self.attestation_scope_measurement_sha256);
            let terminal_evidence_sha256 =
                match self.persist_evidence(&terminal_evidence) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        return self.quarantine_failure(
                            "terminal receipt evidence commit failed",
                            error,
                        )
                    }
                };

            let mut evidence_closure = Vec::new();
            evidence_closure.extend_from_slice(b"catchplate/receipt-evidence-closure/v11\0");
            evidence_closure.extend_from_slice(&request.binding_sha256(lane.plan));
            evidence_closure.extend_from_slice(&lease.claim_sha256);
            evidence_closure.extend_from_slice(&request.source_sha256);
            evidence_closure.extend_from_slice(&request.current_command_sha256);
            evidence_closure.extend_from_slice(&request.original_build_command_sha256);
            evidence_closure.extend_from_slice(&build_commit_sha256);
            evidence_closure.extend_from_slice(&artifact_closure_sha256);
            evidence_closure.extend_from_slice(&execution_evidence_sha256);
            evidence_closure.extend_from_slice(&terminal_evidence_sha256);
            evidence_closure.extend_from_slice(&self.config_sha256);
            evidence_closure.extend_from_slice(&self.provider_measurement_sha256);
            evidence_closure.extend_from_slice(&self.trusted_plan_table_sha256);
            evidence_closure.extend_from_slice(&self.trusted_plan_manifest_sha256);
            evidence_closure.extend_from_slice(&self.attestation_scope_measurement_sha256);
            evidence_closure.extend_from_slice(&self.key_id_sha256);
            let evidence_closure_sha256 =
                match self.persist_evidence(&evidence_closure) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        return self.quarantine_failure(
                            "receipt evidence closure commit failed",
                            error,
                        )
                    }
                };

            let body = ControllerReceiptBody {
                terminal,
                lane,
                attestation_scope: AttestationScope::TrustedHostNoTee,
                deadline_unix_ms: request.transport_deadline_unix_ms,
                acceptance_fence: lease.fence,
                acceptance_generation: lease.generation,
                build_fence,
                build_reservation_generation: build_generation,
                request_id: request.request_id,
                exact_signed_request_sha256:
                    request.exact_signed_request_sha256,
                nonce_sha256: request.nonce_sha256,
                observed_source_sha256: request.source_sha256,
                current_lane_command_sha256: request.current_command_sha256,
                committed_build_command_sha256,
                acceptance_identity_sha256: lease.identity_sha256,
                build_reservation_identity_sha256: build_identity,
                config_sha256: self.config_sha256,
                provider_manifest_sha256: self.provider_measurement_sha256,
                fixed_plan_manifest_sha256: self.trusted_plan_table_sha256,
                evidence_closure_sha256,
                terminal_evidence_sha256,
                attestation_scope_measurement_sha256:
                    self.attestation_scope_measurement_sha256,
            };
            let signed = match SignedControllerReceipt::sign(
                body.clone(),
                &self.signing_key,
            ) {
                Ok(signed) => signed,
                Err(error) => {
                    return self.quarantine_failure(
                        "terminal receipt signing failed",
                        error,
                    )
                }
            };
            let receipt = match signed.encode() {
                Ok(receipt) => receipt,
                Err(error) => {
                    return self.quarantine_failure(
                        "terminal receipt encoding failed",
                        error,
                    )
                }
            };
            if let Err(error) =
                self.verify_exact_receipt(&receipt, &request, lease, &body)
            {
                return self.quarantine_failure(
                    "terminal receipt native self-verification failed",
                    error,
                );
            }
            match self.commit_acceptance_receipt(
                &request,
                lease,
                &body,
                &receipt,
            ) {
                Ok(committed) => Ok(committed),
                Err(error) => self.quarantine_failure(
                    "terminal receipt one-use CAS commit was ambiguous",
                    error,
                ),
            }
        }

        fn persist_local_evidence_reference(
            &self,
            label: &str,
            canonical_bytes: &[u8],
        ) -> Result<EvidenceReference> {
            self.persist_local_evidence_reference_with_closed_fds(
                label,
                canonical_bytes,
                &[],
            )
        }

        fn persist_local_evidence_reference_with_closed_fds(
            &self,
            label: &str,
            canonical_bytes: &[u8],
            foreign_authority_fds: &[RawFd],
        ) -> Result<EvidenceReference> {
            let object_sha256 = self.persist_evidence_with_closed_fds(
                canonical_bytes,
                foreign_authority_fds,
            )?;
            let mut chunk = Vec::new();
            chunk.extend_from_slice(
                b"catchplate/trusted-host-local-evidence-chunk/v11\0",
            );
            chunk.extend_from_slice(&object_sha256);
            chunk.extend_from_slice(&(canonical_bytes.len() as u64).to_be_bytes());
            let chunk_root_sha256 = sha256(&chunk);
            let mut retention = Vec::new();
            retention.extend_from_slice(
                b"catchplate/trusted-host-local-retention/v11\0",
            );
            retention.extend_from_slice(&object_sha256);
            retention.extend_from_slice(&self.provider_measurement_sha256);
            let retention_commitment_sha256 = sha256(&retention);
            let mut availability = Vec::new();
            availability.extend_from_slice(
                b"catchplate/trusted-host-local-availability/v11\0",
            );
            availability.extend_from_slice(&object_sha256);
            availability.extend_from_slice(
                &self.attestation_scope_measurement_sha256,
            );
            let availability_commitment_sha256 = sha256(&availability);
            let mut reference = EvidenceReference {
                namespace: "catchplate-trusted-host-local-v11".to_owned(),
                object_id: format!(
                    "{}-{}",
                    label,
                    digest_hex(&object_sha256)
                ),
                length: canonical_bytes.len() as u64,
                object_sha256,
                chunk_root_sha256,
                retention_commitment_sha256,
                availability_commitment_sha256,
                reference_sha256: [0; 32],
            };
            reference.reference_sha256 = reference.canonical_digest();
            reference.validate()?;
            Ok(reference)
        }

        fn launch_contract(
            &self,
            plan: &FixedLaunchPlan,
            peer_uid: u32,
            peer_gid: u32,
            no_build: bool,
            deadline_unix_ms: u64,
            bootstrap: bool,
            request_binding_sha256: Digest,
            artifact_seal_sha256: Digest,
        ) -> Result<LaunchContractV11> {
            if no_build != (plan.plan != Plan::Build) {
                return Err(ControllerError::Rejected(
                    "launch lane and no-build sandbox profile disagree",
                ));
            }
            let closure = plan
                .executable_closure
                .iter()
                .map(|member| LaunchClosureMemberV11 {
                    path: member.path.clone(),
                    executable: member.executable,
                    identity: LaunchFileIdentityV11 {
                        device: member.identity.device,
                        inode: member.identity.inode,
                        generation: member.identity.generation,
                        mode: member.identity.mode,
                        owner_uid: member.identity.owner_uid,
                        size: member.identity.size,
                    },
                    content_sha256: member.content_sha256,
                })
                .collect();
            let mut argv: Vec<Vec<u8>> = plan
                .argv
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect();
            if bootstrap {
                argv[1] = b"bootstrap-v11".to_vec();
            }
            let mode = if bootstrap {
                PlanApiModeV11::Bootstrap
            } else {
                PlanApiModeV11::Execute
            };
            let lane = Lane::checked(
                if plan.plan == Plan::Build {
                    Operation::Build
                } else {
                    Operation::RunNoBuild
                },
                plan.plan,
            )?;
            let one_use_capability = self.issue_plan_capability(
                mode,
                lane,
                deadline_unix_ms,
                request_binding_sha256,
                artifact_seal_sha256,
                peer_uid,
                peer_gid,
            )?;
            let mut env: Vec<Vec<u8>> = plan
                .env
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect();
            env.push(
                format!(
                    "CATCHPLATE_CONTROLLER_PLAN_CAPABILITY={}",
                    digest_hex(&one_use_capability),
                )
                .into_bytes(),
            );
            env.push(
                format!(
                    "CATCHPLATE_CONTROLLER_DAEMON_IDENTITY_SHA256={}",
                    digest_hex(&self.controller_process_identity_sha256),
                )
                .into_bytes(),
            );
            env.push(
                format!(
                    "CATCHPLATE_CONTROLLER_DEADLINE_MS={deadline_unix_ms}",
                )
                .into_bytes(),
            );
            let contract = LaunchContractV11 {
                lane,
                peer_uid,
                peer_gid,
                deadline_unix_ms,
                command_identity_sha256: plan.command_identity_sha256,
                executable_closure_sha256:
                    plan.executable_closure_sha256,
                sandbox_profile_sha256: plan.sandbox_profile_sha256,
                primary_executable: plan.executable_path.clone(),
                cwd: plan.cwd_path.clone(),
                source_root: self.source_root.clone(),
                controller_plan_api_socket:
                    PathBuf::from(CONTROLLER_PLAN_API_SOCKET_PATH),
                artifact_roots: self.artifact_paths.clone(),
                argv,
                env,
                closure,
            };
            if sha256(&contract.encode()?) == [0; 32] {
                return Err(ControllerError::Rejected(
                    "launch contract measurement is empty",
                ));
            }
            Ok(contract)
        }

        fn issue_plan_capability(
            &self,
            mode: PlanApiModeV11,
            lane: Lane,
            deadline_unix_ms: u64,
            request_binding_sha256: Digest,
            artifact_seal_sha256: Digest,
            peer_uid: u32,
            peer_gid: u32,
        ) -> Result<Digest> {
            if deadline_unix_ms <= now_unix_ms()? {
                return Err(ControllerError::Rejected(
                    "plan capability deadline is already expired",
                ));
            }
            let raw_capability = random_digest_worker_only()?;
            let capability_sha256 = sha256(&raw_capability);
            let record = PlanCapabilityRecordV11::new(
                mode,
                lane,
                deadline_unix_ms,
                capability_sha256,
                request_binding_sha256,
                self.controller_process_identity_sha256,
                artifact_seal_sha256,
            )?;
            let now = now_unix_ms()?;
            let mut capabilities =
                self.plan_capabilities.lock().map_err(|_| {
                    ControllerError::Unready(vec![
                        "plan capability registry lock is poisoned"
                            .to_owned(),
                    ])
                })?;
            capabilities.retain(|_, lease| {
                lease.record.deadline_unix_ms > now
            });
            if capabilities.len() >= 32
                || capabilities.contains_key(&capability_sha256)
            {
                return Err(ControllerError::Unready(vec![
                    "bounded plan capability registry is full or collided"
                        .to_owned(),
                ]));
            }
            capabilities.insert(
                capability_sha256,
                PlanCapabilityLease {
                    record,
                    peer_uid,
                    peer_gid,
                },
            );
            Ok(raw_capability)
        }

        fn consume_plan_capability(
            &self,
            request: &PlanApiRequestV11,
            peer_uid: u32,
            peer_gid: u32,
        ) -> Result<PlanCapabilityLease> {
            let capability_sha256 =
                sha256(&request.one_use_capability);
            let lease = self
                .plan_capabilities
                .lock()
                .map_err(|_| {
                    ControllerError::Unready(vec![
                        "plan capability registry lock is poisoned"
                            .to_owned(),
                    ])
                })?
                .remove(&capability_sha256)
                .ok_or(ControllerError::Rejected(
                    "plan capability is absent, expired, or already consumed",
                ))?;
            if lease.record.mode != request.mode
                || lease.record.lane != request.lane
                || lease.record.deadline_unix_ms
                    != request.deadline_unix_ms
                || lease.record.capability_sha256
                    != capability_sha256
                || lease.record.daemon_identity_sha256
                    != request.expected_daemon_identity_sha256
                || request.expected_daemon_identity_sha256
                    != self.controller_process_identity_sha256
                || lease.peer_uid != peer_uid
                || lease.peer_gid != peer_gid
                || now_unix_ms()? >= lease.record.deadline_unix_ms
            {
                return Err(ControllerError::Rejected(
                    "plan capability binding differs from its launch lease",
                ));
            }
            Ok(lease)
        }

        fn direct_supervisor_measurements(
            &self,
            foreign_authority_fds: &[RawFd],
        ) -> Result<TrustedHostSupervisorStateMachineMeasurements> {
            let mut exact = Vec::new();
            exact.extend_from_slice(
                b"catchplate-controller-v11/shared-trusted-host-supervisor-state-machine\0",
            );
            exact.extend_from_slice(&self.daemon_executable_sha256);
            exact.extend_from_slice(&self.daemon_executable_sha256);
            exact.extend_from_slice(
                &self.controller_process_identity_sha256,
            );
            exact.extend_from_slice(&self.config_sha256);
            exact.extend_from_slice(&self.orphan_journal_identity_sha256);
            let exact_measurement =
                self.persist_local_evidence_reference_with_closed_fds(
                "direct-supervisor-state-machine",
                &exact,
                foreign_authority_fds,
            )?;
            let measurements = TrustedHostSupervisorStateMachineMeasurements {
                shared_module_sha256: self.daemon_executable_sha256,
                backend_executable_sha256: self.daemon_executable_sha256,
                controller_process_identity_sha256:
                    self.controller_process_identity_sha256,
                immutable_config_sha256: self.config_sha256,
                durable_orphan_journal_identity_sha256:
                    self.orphan_journal_identity_sha256,
                exact_measurement,
            };
            if trusted_host_supervisor_state_machine_sha256(&measurements)
                != measurements.exact_measurement.object_sha256
            {
                return Err(ControllerError::Rejected(
                    "local shared supervisor measurement preimage is inconsistent",
                ));
            }
            Ok(measurements)
        }

        fn prepare_direct_supervisor(
            &self,
            request: &RequestContext,
            plan: &FixedLaunchPlan,
            workload: &RegisteredChild,
            watchdog: &RegisteredWatchdog,
            monitor: &RegisteredChild,
        ) -> Result<(
            TrustedHostDirectSupervisorStateMachine,
            RawTrustedHostDirectSupervisorRegistration,
        )> {
            if workload.barrier.is_none()
                || watchdog.child.barrier.is_some()
                || monitor.barrier.is_none()
            {
                return Err(ControllerError::Rejected(
                    "direct supervisor registration requires a held workload/monitor and an active independent watchdog",
                ));
            }
            let foreign_authority_fds = [
                workload
                    .barrier
                    .as_ref()
                    .ok_or(ControllerError::Rejected(
                        "workload barrier disappeared before registration",
                    ))?
                    .as_raw_fd(),
                monitor
                    .barrier
                    .as_ref()
                    .ok_or(ControllerError::Rejected(
                        "monitor barrier disappeared before registration",
                    ))?
                    .as_raw_fd(),
            ];
            let workload_pidfd_identity =
                pidfd_identity(workload.pidfd.as_raw_fd())?;
            if workload_pidfd_identity != format!("pid:{}", workload.pid) {
                return Err(ControllerError::Rejected(
                    "held workload pidfd identity changed before registration",
                ));
            }
            let watchdog_pidfd_identity =
                pidfd_identity(watchdog.child.pidfd.as_raw_fd())?;
            if watchdog_pidfd_identity
                != format!("pid:{}", watchdog.child.pid)
            {
                return Err(ControllerError::Rejected(
                    "watchdog pidfd identity changed before registration",
                ));
            }
            if watchdog.child.pid == workload.pid
                || !pidfd_poll_live(watchdog.child.pidfd.as_raw_fd())?
            {
                return Err(ControllerError::Rejected(
                    "independent watchdog is not a distinct live process",
                ));
            }
            let workload_cgroup_identity =
                directory_identity(workload.cgroup_directory.as_raw_fd())?;
            let controller_pid = unsafe { libc::getpid() };
            let workload_pid = workload.pid;
            let watchdog_pid = watchdog.child.pid;
            let watchdog_start_time_ticks =
                watchdog.child.start_time_ticks;
            let parent_bytes = self.run_bytes_worker_with_closed_fds(
                "direct-supervisor-parent-observer",
                24,
                &foreign_authority_fds,
                move || {
                    let workload_parent =
                        proc_parent_pid(workload_pid)?;
                    let watchdog_parent =
                        proc_parent_pid(watchdog_pid)?;
                    let watchdog_start =
                        proc_start_time_ticks(watchdog_pid)?;
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(
                        &workload_parent.to_be_bytes(),
                    );
                    bytes.extend_from_slice(
                        &watchdog_parent.to_be_bytes(),
                    );
                    bytes.extend_from_slice(&controller_pid.to_be_bytes());
                    bytes.extend_from_slice(
                        &watchdog_start.to_be_bytes(),
                    );
                    Ok(bytes)
                },
            )?;
            if parent_bytes.len() != 20
                || i32::from_be_bytes(
                    parent_bytes[0..4].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "workload parent observer result is invalid",
                        )
                    })?,
                ) != controller_pid
                || i32::from_be_bytes(
                    parent_bytes[4..8].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "watchdog parent observer result is invalid",
                        )
                    })?,
                ) != controller_pid
                || i32::from_be_bytes(
                    parent_bytes[8..12].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "direct controller PID result is invalid",
                        )
                    })?,
                ) != controller_pid
                || u64::from_be_bytes(
                    parent_bytes[12..20].try_into().map_err(|_| {
                        ControllerError::Invalid(
                            "watchdog start-time observer result is invalid",
                        )
                    })?,
                ) != watchdog_start_time_ticks
            {
                return Err(ControllerError::Rejected(
                    "controller is not the sole current parent of the held workload and independent watchdog",
                ));
            }
            let mut subreaper = 0;
            if unsafe {
                libc::prctl(
                    libc::PR_GET_CHILD_SUBREAPER,
                    &mut subreaper as *mut libc::c_int,
                    0,
                    0,
                    0,
                )
            } != 0
                || subreaper != 1
            {
                return Err(ControllerError::Rejected(
                    "controller subreaper state changed before registration",
                ));
            }

            let mut child_identity = Vec::new();
            child_identity.extend_from_slice(
                b"catchplate/direct-registered-child/v11\0",
            );
            child_identity.extend_from_slice(&workload.pid.to_be_bytes());
            child_identity
                .extend_from_slice(&workload.start_time_ticks.to_be_bytes());
            child_identity
                .extend_from_slice(&workload.process_group.to_be_bytes());
            child_identity.extend_from_slice(workload_pidfd_identity.as_bytes());
            append_file_identity(
                &mut child_identity,
                &workload_cgroup_identity,
            );
            let registered_child_identity =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-registered-child",
                    &child_identity,
                    &foreign_authority_fds,
                )?;

            let mut held = Vec::new();
            held.extend_from_slice(b"catchplate/direct-held-child/v11\0");
            held.extend_from_slice(&workload.pid.to_be_bytes());
            held.extend_from_slice(&workload.start_time_ticks.to_be_bytes());
            held.extend_from_slice(b"barrier-retained-before-shared-gate");
            let child_held_before_execution =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-held-child",
                    &held,
                    &foreign_authority_fds,
                )?;

            let mut pidfd = Vec::new();
            pidfd.extend_from_slice(b"catchplate/direct-pidfd/v11\0");
            pidfd.extend_from_slice(&workload.pid.to_be_bytes());
            pidfd.extend_from_slice(workload_pidfd_identity.as_bytes());
            let pidfd_identity =
                self.persist_local_evidence_reference_with_closed_fds(
                "direct-pidfd",
                &pidfd,
                &foreign_authority_fds,
            )?;

            let mut cgroup = Vec::new();
            cgroup.extend_from_slice(b"catchplate/direct-cgroup/v11\0");
            cgroup.extend_from_slice(
                workload.cgroup_name.as_bytes(),
            );
            append_file_identity(&mut cgroup, &workload_cgroup_identity);
            let cgroup_identity =
                self.persist_local_evidence_reference_with_closed_fds(
                "direct-cgroup",
                &cgroup,
                &foreign_authority_fds,
            )?;

            let mut parent_reaper = Vec::new();
            parent_reaper.extend_from_slice(
                b"catchplate/direct-controller-parent-reaper/v11\0",
            );
            parent_reaper.extend_from_slice(&controller_pid.to_be_bytes());
            parent_reaper.extend_from_slice(&workload.pid.to_be_bytes());
            parent_reaper
                .extend_from_slice(&watchdog.child.pid.to_be_bytes());
            parent_reaper
                .extend_from_slice(&self.controller_process_identity_sha256);
            parent_reaper.extend_from_slice(b"subreaper=1");
            let controller_parent_reaper =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-controller-parent-reaper",
                    &parent_reaper,
                    &foreign_authority_fds,
                )?;

            let mut watchdog_authority = Vec::new();
            watchdog_authority.extend_from_slice(
                b"catchplate/direct-independent-watchdog/v11\0",
            );
            watchdog_authority
                .extend_from_slice(&watchdog.child.pid.to_be_bytes());
            watchdog_authority.extend_from_slice(
                &watchdog.child.start_time_ticks.to_be_bytes(),
            );
            watchdog_authority
                .extend_from_slice(watchdog_pidfd_identity.as_bytes());
            watchdog_authority.extend_from_slice(&workload.pid.to_be_bytes());
            watchdog_authority.extend_from_slice(
                watchdog.armed_journal_name.as_bytes(),
            );
            watchdog_authority.push(0);
            watchdog_authority.extend_from_slice(
                watchdog.closure_journal_name.as_bytes(),
            );
            watchdog_authority.push(0);
            watchdog_authority.extend_from_slice(
                &watchdog.armed_record_sha256,
            );
            watchdog_authority.extend_from_slice(
                b"active-before-registration;non-parent;non-reaper;cgroup-kill;durable-journal",
            );
            let independent_watchdog_authority =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-independent-watchdog",
                    &watchdog_authority,
                    &foreign_authority_fds,
                )?;

            let mut orphan_journal = Vec::new();
            orphan_journal.extend_from_slice(
                b"catchplate/direct-durable-orphan-journal/v11\0",
            );
            orphan_journal
                .extend_from_slice(&self.orphan_journal_identity_sha256);
            orphan_journal.extend_from_slice(
                self.state.root_path.as_os_str().as_bytes(),
            );
            orphan_journal.push(0);
            orphan_journal.extend_from_slice(
                watchdog.armed_journal_name.as_bytes(),
            );
            orphan_journal.push(0);
            orphan_journal.extend_from_slice(
                watchdog.closure_journal_name.as_bytes(),
            );
            orphan_journal.push(0);
            orphan_journal.extend_from_slice(
                &watchdog.armed_record_sha256,
            );
            let durable_orphan_journal =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-durable-orphan-journal",
                    &orphan_journal,
                    &foreign_authority_fds,
                )?;

            let placeholder = registered_child_identity.clone();
            let mut registration =
                RawTrustedHostDirectSupervisorRegistration {
                    registration_binding_sha256: [0; 32],
                    request_sha256:
                        request.binding_sha256(plan.plan),
                    config_sha256: self.config_sha256,
                    fixed_plan_manifest_sha256:
                        self.trusted_plan_table_sha256,
                    current_lane_command_identity_sha256:
                        plan.command_identity_sha256,
                    deadline_unix_ms:
                        request.transport_deadline_unix_ms,
                    exact_registration: placeholder,
                    registered_child_identity,
                    child_held_before_execution,
                    pidfd_identity,
                    cgroup_identity,
                    controller_parent_reaper,
                    independent_watchdog_authority,
                    durable_orphan_journal,
                };
            let registration_binding_sha256 =
                trusted_host_direct_supervisor_registration_sha256(
                    &registration,
                );
            let mut exact_registration = Vec::new();
            exact_registration.extend_from_slice(
                b"catchplate-controller-v11/direct-supervisor-registration\0",
            );
            exact_registration
                .extend_from_slice(&registration.request_sha256);
            exact_registration.extend_from_slice(&registration.config_sha256);
            exact_registration.extend_from_slice(
                &registration.fixed_plan_manifest_sha256,
            );
            exact_registration.extend_from_slice(
                &registration.current_lane_command_identity_sha256,
            );
            exact_registration
                .extend_from_slice(&registration.deadline_unix_ms.to_be_bytes());
            for object in [
                &registration.registered_child_identity,
                &registration.child_held_before_execution,
                &registration.pidfd_identity,
                &registration.cgroup_identity,
                &registration.controller_parent_reaper,
                &registration.independent_watchdog_authority,
                &registration.durable_orphan_journal,
            ] {
                exact_registration
                    .extend_from_slice(&object.reference_sha256);
            }
            let exact_registration =
                self.persist_local_evidence_reference_with_closed_fds(
                    "direct-supervisor-registration",
                    &exact_registration,
                    &foreign_authority_fds,
                )?;
            if exact_registration.object_sha256
                != registration_binding_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct registration evidence preimage is inconsistent",
                ));
            }
            registration.registration_binding_sha256 =
                registration_binding_sha256;
            registration.exact_registration = exact_registration;

            let measurements =
                self.direct_supervisor_measurements(
                    &foreign_authority_fds,
                )?;
            let shared_state_machine_identity_sha256 =
                trusted_host_supervisor_state_machine_sha256(&measurements);
            let verifier = Arc::new(PinnedDirectSupervisorVerifier {
                registration_binding_sha256,
                shared_state_machine_identity_sha256,
                shared_state_machine_measurement_reference_sha256:
                    measurements.exact_measurement.reference_sha256,
                request_sha256: registration.request_sha256,
                config_sha256: registration.config_sha256,
                fixed_plan_manifest_sha256:
                    registration.fixed_plan_manifest_sha256,
                current_lane_command_identity_sha256:
                    registration.current_lane_command_identity_sha256,
                deadline_unix_ms: registration.deadline_unix_ms,
                registered_child_identity_reference_sha256:
                    registration.registered_child_identity.reference_sha256,
                child_held_reference_sha256:
                    registration
                        .child_held_before_execution
                        .reference_sha256,
                pidfd_identity_reference_sha256:
                    registration.pidfd_identity.reference_sha256,
                cgroup_identity_reference_sha256:
                    registration.cgroup_identity.reference_sha256,
                controller_parent_reaper_reference_sha256:
                    registration.controller_parent_reaper.reference_sha256,
                independent_watchdog_reference_sha256:
                    registration
                        .independent_watchdog_authority
                        .reference_sha256,
                durable_orphan_journal_reference_sha256:
                    registration.durable_orphan_journal.reference_sha256,
            });
            let state_machine =
                TrustedHostDirectSupervisorStateMachine::
                    measured_trusted_host_capability_route(
                        verifier,
                        measurements,
                    )?;
            Ok((state_machine, registration))
        }

        fn direct_release_evidence(
            &self,
            capability: &VerifiedTrustedHostDirectReleaseCapability<'_>,
        ) -> Result<EvidenceReference> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(
                b"catchplate-controller-v11/direct-supervisor-release-evidence\0",
            );
            bytes.extend_from_slice(
                &capability.gate().registration_binding_sha256(),
            );
            bytes.extend_from_slice(
                &capability.gate().authorization_sha256(),
            );
            bytes.extend_from_slice(&capability.transition_sha256());
            bytes.extend_from_slice(&capability.completion_transition_sha256());
            let evidence = self.persist_local_evidence_reference(
                "direct-supervisor-release",
                &bytes,
            )?;
            if evidence.object_sha256
                != trusted_host_direct_release_evidence_sha256(
                    capability.gate().registration_binding_sha256(),
                    capability.gate().authorization_sha256(),
                    capability.transition_sha256(),
                    capability.completion_transition_sha256(),
                )
            {
                return Err(ControllerError::Rejected(
                    "direct release evidence preimage is inconsistent",
                ));
            }
            Ok(evidence)
        }

        fn direct_containment_evidence(
            &self,
            capability: &VerifiedTrustedHostDirectContainmentCapability,
        ) -> Result<EvidenceReference> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(
                b"catchplate-controller-v11/direct-supervisor-containment-evidence\0",
            );
            bytes.extend_from_slice(
                &capability.gate().registration_binding_sha256(),
            );
            bytes.extend_from_slice(
                &capability.gate().authorization_sha256(),
            );
            bytes.extend_from_slice(&capability.transition_sha256());
            bytes.extend_from_slice(&capability.completion_transition_sha256());
            let evidence = self.persist_local_evidence_reference(
                "direct-supervisor-containment",
                &bytes,
            )?;
            if evidence.object_sha256
                != trusted_host_direct_containment_evidence_sha256(
                    capability.gate().registration_binding_sha256(),
                    capability.gate().authorization_sha256(),
                    capability.transition_sha256(),
                    capability.completion_transition_sha256(),
                )
            {
                return Err(ControllerError::Rejected(
                    "direct containment evidence preimage is inconsistent",
                ));
            }
            Ok(evidence)
        }

        fn close_direct_gate<F>(
            &self,
            state_machine: &TrustedHostDirectSupervisorStateMachine,
            gate: VerifiedTrustedHostDirectSupervisorGate,
            cleanup: F,
        ) -> Result<()>
        where
            F: FnOnce(
                &VerifiedTrustedHostDirectContainmentCapability,
            ) -> Result<()>,
        {
            let capability =
                state_machine.begin_capability_containment(gate)?;
            cleanup(&capability)?;
            self.complete_direct_containment_capability(
                state_machine,
                capability,
            )
            .map(|_| ())
        }

        fn complete_direct_containment_capability(
            &self,
            state_machine: &TrustedHostDirectSupervisorStateMachine,
            capability: VerifiedTrustedHostDirectContainmentCapability,
        ) -> Result<EvidenceReference> {
            let evidence = self.direct_containment_evidence(&capability)?;
            state_machine
                .complete_capability_containment(capability, &evidence)?;
            Ok(evidence)
        }

        fn run_fixed_command(
            &self,
            plan: &FixedLaunchPlan,
            request: &RequestContext,
            peer_uid: u32,
            peer_gid: u32,
            peer_start_time_ticks: u64,
            no_build: bool,
            artifact_seal_sha256: Digest,
            deadline: Instant,
        ) -> Result<ExecutionOutcome> {
            let action_deadline = action_execution_deadline(deadline)?;
            let launch_contract = self.launch_contract(
                plan,
                peer_uid,
                peer_gid,
                no_build,
                request.transport_deadline_unix_ms,
                false,
                request.exact_signed_request_sha256,
                artifact_seal_sha256,
            )?;
            let launch_contract_bytes = launch_contract.encode()?;
            let launch_contract_memfd = create_sealed_memfd(
                "catchplate-controller-launch-contract-v11",
                &launch_contract_bytes,
            )?;
            verify_sealed_memfd(
                launch_contract_memfd.as_raw_fd(),
                launch_contract_bytes.len() as u64,
            )?;
            let launcher_fd = self.launcher_opath.as_raw_fd();
            let mut workload = self.spawn_registered_isolated(
                "workload",
                move |output| {
                if unsafe { libc::dup2(output, libc::STDOUT_FILENO) } < 0
                    || unsafe { libc::dup2(output, libc::STDERR_FILENO) } < 0
                {
                    return 125;
                }
                exec_controller_launcher_mode(
                    launcher_fd,
                    launch_contract_memfd.as_raw_fd(),
                    false,
                )
            },
            )?;
            let mut watchdog = match self.arm_workload_watchdog(&workload, action_deadline) {
                Ok(watchdog) => watchdog,
                Err(error) => {
                    let reason =
                        format!("watchdog registration failed before workload release: {error}");
                    self.cleanup_held_launch(&mut workload, &reason)?;
                    return Err(error);
                }
            };
            let workload_pid = workload.pid;
            let mut launch_root = HostLaunchRootGuard::new(
                workload_pid,
                plan.command_identity_sha256,
            );
            let workload_pidfd = workload.pidfd.as_raw_fd();
            let workload_start = workload.start_time_ticks;
            let workload_cgroup = workload.cgroup_directory.as_raw_fd();
            let executable_identity = plan.executable_identity.clone();
            let executable_sha256 = plan.executable_sha256;
            let executable_path = plan.executable_path.clone();
            let monitor_timeout = remaining_duration(deadline)?;
            let (monitor_ready_read, monitor_ready_write) = pipe_cloexec()?;
            let monitor_spawn = self.spawn_registered("kernel-monitor", move |output| {
                monitor_workload(
                    workload_pid,
                    workload_pidfd,
                    workload_start,
                    &executable_path,
                    &executable_identity,
                    executable_sha256,
                    workload_cgroup,
                    no_build,
                    plan.executable_closure_sha256,
                    monitor_timeout,
                    monitor_ready_write.as_raw_fd(),
                    output,
                )
            });
            let mut monitor = match monitor_spawn {
                Ok(monitor) => monitor,
                Err(error) => {
                    let reason =
                        format!("monitor registration failed before release: {error}");
                    self.cleanup_with_released_watchdog(
                        Some(&mut workload),
                        None,
                        watchdog,
                        &reason,
                    )?;
                    return Err(error);
                }
            };
            let (direct_supervisor, registration) =
                match self.prepare_direct_supervisor(
                    request,
                    plan,
                    &workload,
                    &watchdog,
                    &monitor,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let reason = format!(
                            "shared direct supervisor preparation failed: {error}"
                        );
                        self.cleanup_with_released_watchdog(
                            Some(&mut workload),
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                        )?;
                        return Err(error);
                    }
                };
            let gate = match direct_supervisor
                .verify_and_authorize_registered_child(registration)
            {
                Ok(gate) => gate,
                Err(error) => {
                    let reason = format!(
                        "shared direct supervisor native verification failed: {error}"
                    );
                    self.cleanup_with_released_watchdog(
                        Some(&mut workload),
                        Some(&mut monitor),
                        watchdog,
                        &reason,
                    )?;
                    return Err(error);
                }
            };
            let direct_supervisor_identity =
                direct_supervisor.identity_sha256();
            let direct_authorization_sha256 =
                gate.authorization_sha256();
            if let Err(error) = Self::release_child(&mut monitor) {
                let reason =
                    format!("monitor release failed before workload release: {error}");
                self.close_direct_gate(
                    &direct_supervisor,
                    gate,
                    |capability| {
                        self.cleanup_authorized_released_launch(
                            Some(&mut workload),
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                            capability,
                        )
                    },
                )?;
                return Err(error);
            }
            let monitor_ready_sha256 = match wait_monitor_ready(
                monitor_ready_read.as_raw_fd(),
                workload_pid,
                workload_pidfd,
                workload_start,
                deadline,
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    let reason = format!(
                        "kernel monitor did not acknowledge readiness before workload release: {error}"
                    );
                    self.close_direct_gate(
                        &direct_supervisor,
                        gate,
                        |capability| {
                            self.cleanup_authorized_released_launch(
                                Some(&mut workload),
                                Some(&mut monitor),
                                watchdog,
                                &reason,
                                capability,
                            )
                        },
                    )?;
                    return Err(error);
                }
            };
            let release_capability =
                match direct_supervisor.begin_capability_release(&gate) {
                    Ok(capability) => capability,
                    Err(error) => {
                        let reason = format!(
                            "shared direct supervisor release authorization failed: {error}"
                        );
                        self.close_direct_gate(
                            &direct_supervisor,
                            gate,
                            |capability| {
                                self.cleanup_authorized_released_launch(
                                    Some(&mut workload),
                                    Some(&mut monitor),
                                    watchdog,
                                    &reason,
                                    capability,
                                )
                            },
                        )?;
                        return Err(error);
                    }
                };
            if let Err(error) = Self::release_verified_workload(
                &mut workload,
                &release_capability,
            ) {
                drop(release_capability);
                let reason = format!("workload release failed: {error}");
                self.close_direct_gate(
                    &direct_supervisor,
                    gate,
                    |capability| {
                        self.cleanup_authorized_released_launch(
                            Some(&mut workload),
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                            capability,
                        )
                    },
                )?;
                return Err(error);
            }
            let release_evidence =
                match self.direct_release_evidence(&release_capability) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        drop(release_capability);
                        let reason = format!(
                            "shared direct supervisor release evidence failed: {error}"
                        );
                        self.close_direct_gate(
                            &direct_supervisor,
                            gate,
                            |capability| {
                                self.cleanup_authorized_released_launch(
                                    Some(&mut workload),
                                    Some(&mut monitor),
                                    watchdog,
                                    &reason,
                                    capability,
                                )
                            },
                        )?;
                        return Err(error);
                    }
                };
            if let Err(error) = direct_supervisor
                .complete_capability_release(
                    release_capability,
                    &release_evidence,
                )
            {
                let reason = format!(
                    "shared direct supervisor release completion failed: {error}"
                );
                self.close_direct_gate(
                    &direct_supervisor,
                    gate,
                    |capability| {
                        self.cleanup_authorized_released_launch(
                            Some(&mut workload),
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                            capability,
                        )
                    },
                )?;
                return Err(error);
            }
            let containment_capability =
                match direct_supervisor.begin_capability_containment(gate) {
                    Ok(capability) => capability,
                    Err(error) => {
                        let reason = format!(
                            "shared direct supervisor containment authorization failed: {error}"
                        );
                        self.cleanup_with_released_watchdog(
                            Some(&mut workload),
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                        )?;
                        return Err(error);
                    }
                };
            let workload_outcome = match self.collect_verified_workload(
                workload,
                action_deadline,
                ACTION_OUTPUT_MAX_BYTES,
                Some((
                    watchdog.control.as_raw_fd(),
                    watchdog.acknowledgement.as_raw_fd(),
                )),
                &containment_capability,
            ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let reason =
                            format!("workload collection or closure failed: {error}");
                        self.cleanup_authorized_released_launch(
                            None,
                            Some(&mut monitor),
                            watchdog,
                            &reason,
                            &containment_capability,
                        )?;
                        self.complete_direct_containment_capability(
                            &direct_supervisor,
                            containment_capability,
                        )?;
                        if let Err(cleanup_error) = launch_root.cleanup() {
                            let cleanup_reason = format!(
                                "host launch-root cleanup failed after workload failure: {cleanup_error}",
                            );
                            self.quarantine(&cleanup_reason)?;
                            return Err(ControllerError::Unready(vec![
                                cleanup_reason,
                            ]));
                        }
                        return Err(error);
                    }
                };
            if let Err(error) = launch_root.cleanup() {
                let reason =
                    format!("host launch-root cleanup failed: {error}");
                self.quarantine(&reason)?;
                return Err(ControllerError::Unready(vec![reason]));
            }
            drop(watchdog.control);
            drop(watchdog.acknowledgement);
            let watchdog_result = self.collect_child(
                watchdog.child,
                deadline,
                PROVIDER_MAX_BYTES,
                None,
            );
            let monitor_result = self.collect_child(
                monitor,
                deadline,
                PROVIDER_MAX_BYTES,
                None,
            );
            let (watchdog_outcome, monitor_outcome) =
                match (watchdog_result, monitor_result) {
                    (Ok(watchdog), Ok(monitor)) => (watchdog, monitor),
                    (watchdog, monitor) => {
                        let reason = format!(
                            "post-workload watchdog/monitor collection failed: watchdog={}; monitor={}",
                            watchdog
                                .as_ref()
                                .err()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "ok".to_owned()),
                            monitor
                                .as_ref()
                                .err()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "ok".to_owned()),
                        );
                        self.quarantine(&reason)?;
                        return Err(ControllerError::Unready(vec![reason]));
                    }
                };
            let cleanup_and_provider_proved =
                workload_outcome.cleanup_proved
                    && !monitor_outcome.timed_out
                    && monitor_outcome.cleanup_proved
                    && !watchdog_outcome.timed_out
                    && watchdog_outcome.cleanup_proved
                    && wait_status_success(monitor_outcome.wait_status)
                    && wait_status_success(watchdog_outcome.wait_status);
            if !cleanup_and_provider_proved {
                let reason =
                    "runtime monitor/watchdog or containment cleanup was unproved";
                self.quarantine(reason)?;
                return Err(ControllerError::Unready(vec![
                    reason.to_owned(),
                ]));
            }
            let containment_evidence = match
                self.complete_direct_containment_capability(
                    &direct_supervisor,
                    containment_capability,
                )
            {
                Ok(evidence) => evidence,
                Err(error) => {
                    let reason = format!(
                        "shared containment completion was not proved after runtime closure: {error}"
                    );
                    self.quarantine(&reason)?;
                    return Err(error);
                }
            };
            let mut evidence = Vec::new();
            evidence.extend_from_slice(b"catchplate/trusted-host-execution/v11\0");
            evidence.extend_from_slice(plan.plan.as_label().as_bytes());
            evidence.push(0);
            evidence.extend_from_slice(&plan.command_identity_sha256);
            evidence.extend_from_slice(&plan.executable_sha256);
            evidence.extend_from_slice(&direct_supervisor_identity);
            evidence.extend_from_slice(&direct_authorization_sha256);
            evidence.extend_from_slice(&release_evidence.reference_sha256);
            evidence.extend_from_slice(&monitor_ready_sha256);
            evidence.extend_from_slice(
                &containment_evidence.reference_sha256,
            );
            append_file_identity(&mut evidence, &plan.executable_identity);
            append_file_identity(&mut evidence, &plan.cwd_identity);
            evidence.extend_from_slice(plan.cwd_path.as_os_str().as_bytes());
            evidence.push(0);
            evidence.extend_from_slice(&peer_start_time_ticks.to_be_bytes());
            evidence.extend_from_slice(&workload_outcome.wait_status.to_be_bytes());
            evidence.extend_from_slice(&sha256(&workload_outcome.output));
            evidence.extend_from_slice(&sha256(&monitor_outcome.output));
            evidence.extend_from_slice(&sha256(&watchdog_outcome.output));
            evidence.push(u8::from(workload_outcome.timed_out));
            evidence.push(u8::from(workload_outcome.cleanup_proved));
            evidence.push(u8::from(monitor_outcome.timed_out));
            evidence.push(u8::from(monitor_outcome.cleanup_proved));
            evidence.push(u8::from(watchdog_outcome.timed_out));
            evidence.push(u8::from(watchdog_outcome.cleanup_proved));
            evidence.extend_from_slice(&workload_outcome.output);
            evidence.extend_from_slice(&monitor_outcome.output);
            evidence.extend_from_slice(&watchdog_outcome.output);
            let evidence_sha256 = match self.persist_evidence(&evidence) {
                Ok(evidence) => evidence,
                Err(error) => {
                    let reason = format!(
                        "immutable execution evidence commit failed after runtime closure: {error}"
                    );
                    self.quarantine(&reason)?;
                    return Err(error);
                }
            };
            let exit_status = wait_status_exit_code(workload_outcome.wait_status);
            let (terminal, reason) = if workload_outcome.timed_out {
                (
                    ReceiptTerminal::Unknown,
                    "fixed command exceeded its reserved action deadline".to_owned(),
                )
            } else if wait_status_success(workload_outcome.wait_status) {
                (
                    ReceiptTerminal::Success,
                    "fixed descriptor-token command completed with verified cleanup".to_owned(),
                )
            } else {
                (
                    ReceiptTerminal::Failure,
                    format!("fixed command exited with status {exit_status}"),
                )
            };
            Ok(ExecutionOutcome {
                terminal,
                exit_status,
                evidence_sha256,
                reason,
            })
        }

        fn persist_evidence(&self, evidence: &[u8]) -> Result<Digest> {
            self.persist_evidence_with_closed_fds(evidence, &[])
        }

        fn persist_evidence_with_closed_fds(
            &self,
            evidence: &[u8],
            foreign_authority_fds: &[RawFd],
        ) -> Result<Digest> {
            if evidence.len() > PROVIDER_MAX_BYTES {
                return Err(ControllerError::Rejected(
                    "execution evidence exceeds immutable store cap",
                ));
            }
            let digest = sha256(evidence);
            let name = format!("{}.evidence", digest_hex(&digest));
            let directory = self.state.evidence.as_raw_fd();
            let evidence = evidence.to_vec();
            let committed = self.run_bytes_worker_with_closed_fds(
                "immutable-evidence-commit",
                32,
                foreign_authority_fds,
                move || {
                    if create_state_file_exclusive(directory, &name, &evidence)? {
                        let name_c = state_name_c(&name)?;
                        let raw = unsafe {
                            libc::openat(
                                directory,
                                name_c.as_ptr(),
                                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                            )
                        };
                        if raw < 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                        let mut flags: libc::c_uint = 0;
                        if unsafe {
                            libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags)
                        } != 0
                        {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        flags |= FS_IMMUTABLE_FL;
                        if unsafe {
                            libc::ioctl(fd.as_raw_fd(), FS_IOC_SETFLAGS, &flags)
                        } != 0
                        {
                            return Err(ControllerError::Rejected(
                                "immutable evidence store cannot set FS_IMMUTABLE_FL",
                            ));
                        }
                    }
                    require_immutable_state_file(directory, &name)?;
                    let readback = read_required_state_file(directory, &name)?;
                    if sha256(&readback) != digest || readback != evidence {
                        return Err(ControllerError::Rejected(
                            "immutable evidence readback mismatch",
                        ));
                    }
                    Ok(digest.to_vec())
                },
            )?;
            if committed.as_slice() != digest.as_slice() {
                return Err(ControllerError::Rejected(
                    "immutable evidence worker returned the wrong digest",
                ));
            }
            Ok(digest)
        }
    }

    fn remaining_duration(deadline: Instant) -> Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(ControllerError::Rejected("monotonic lane deadline expired"))
    }

    fn bounded_provider_timeout(deadline: Instant) -> Result<Duration> {
        Ok(remaining_duration(deadline)?.min(Duration::from_secs(5 * 60)))
    }

    fn action_execution_deadline(lane_deadline: Instant) -> Result<Instant> {
        let remaining = remaining_duration(lane_deadline)?;
        let remaining_ms = remaining.as_millis().min(u64::MAX as u128) as u64;
        let reserve_ms = (remaining_ms / 5).clamp(25, 30_000);
        if reserve_ms >= remaining_ms {
            return Err(ControllerError::Rejected(
                "lane deadline cannot reserve bounded containment and receipt time",
            ));
        }
        lane_deadline
            .checked_sub(Duration::from_millis(reserve_ms))
            .ok_or(ControllerError::Rejected(
                "action monotonic deadline underflow",
            ))
    }

    fn verify_fixed_plan(plan: &FixedLaunchPlan) -> Result<Digest> {
        let read_identity = regular_file_identity(plan.executable_read.as_raw_fd(), true)?;
        require_immutable_closure_file(plan.executable_read.as_raw_fd())?;
        let opath_identity = regular_file_identity_with_generation(
            plan.executable_opath.as_raw_fd(),
            true,
            read_identity.generation,
        )?;
        let content = digest_regular_fd(plan.executable_read.as_raw_fd(), read_identity.size)?;
        let cwd_identity = directory_identity(plan.cwd_fd.as_raw_fd())?;
        if read_identity != plan.executable_identity
            || opath_identity != plan.executable_identity
            || content != plan.executable_sha256
            || cwd_identity != plan.cwd_identity
        {
            return Err(ControllerError::Rejected(
                "retained plan file/cwd identity or content changed",
            ));
        }
        let mut closure = Vec::new();
        closure.extend_from_slice(b"catchplate/executable-closure/v11\0");
        closure.extend_from_slice(plan.plan.as_label().as_bytes());
        closure.push(0);
        for member in &plan.executable_closure {
            let read_identity = regular_file_identity(
                member.read.as_raw_fd(),
                member.executable,
            )?;
            require_immutable_closure_file(member.read.as_raw_fd())?;
            let opath_identity = regular_file_identity_with_generation(
                member.opath.as_raw_fd(),
                member.executable,
                read_identity.generation,
            )?;
            let content = digest_regular_fd(
                member.read.as_raw_fd(),
                read_identity.size,
            )?;
            if read_identity != member.identity
                || opath_identity != member.identity
                || content != member.content_sha256
            {
                return Err(ControllerError::Rejected(
                    "retained executable closure identity or content changed",
                ));
            }
            closure.push(u8::from(member.executable));
            closure.extend_from_slice(member.path.as_os_str().as_bytes());
            closure.push(0);
            append_file_identity(&mut closure, &member.identity);
            closure.extend_from_slice(&member.content_sha256);
        }
        if sha256(&closure) != plan.executable_closure_sha256 {
            return Err(ControllerError::Rejected(
                "retained executable closure digest changed",
            ));
        }
        Ok(plan.command_identity_sha256)
    }

    #[cfg(any())]
    fn duplicate_no_build_exec_token(plan: &FixedLaunchPlan) -> Result<OwnedFd> {
        let token = duplicate_fd(plan.executable_opath.as_raw_fd())?;
        verify_parent_no_build_exec_token(&token, &plan.executable_identity)?;
        Ok(token)
    }

    fn descriptor_flags(fd: RawFd) -> Result<libc::c_int> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(flags)
    }

    fn verify_parent_no_build_exec_token(
        token: &OwnedFd,
        expected: &FileIdentity,
    ) -> Result<()> {
        let flags = descriptor_flags(token.as_raw_fd())?;
        let identity = regular_file_identity_with_generation(
            token.as_raw_fd(),
            true,
            expected.generation,
        )?;
        if flags & libc::FD_CLOEXEC == 0 || &identity != expected {
            return Err(ControllerError::Rejected(
                "controller retained-token duplicate lost CLOEXEC or file identity",
            ));
        }
        Ok(())
    }

    fn activate_no_build_exec_token(
        retained_plan_fd: RawFd,
        expected: &FileIdentity,
    ) -> Result<()> {
        let flags = descriptor_flags(retained_plan_fd)?;
        if flags & libc::FD_CLOEXEC == 0
            || unsafe {
                libc::fcntl(
                    retained_plan_fd,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let active_flags = descriptor_flags(retained_plan_fd)?;
        let identity = regular_file_identity_with_generation(
            retained_plan_fd,
            true,
            expected.generation,
        )?;
        if active_flags & libc::FD_CLOEXEC != 0 || &identity != expected {
            return Err(ControllerError::Rejected(
                "child retained exec token did not become a stable non-CLOEXEC descriptor",
            ));
        }
        Ok(())
    }

    #[cfg(any())]
    fn prepare_child_sandbox(
        source_root: &Path,
        artifact_roots: &[PathBuf],
        denied_socket_paths: &[PathBuf],
        no_build: bool,
        retained_plan_fd: RawFd,
        retained_plan_identity: &FileIdentity,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Result<()> {
        if unsafe {
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWCGROUP,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let root = CString::new("/").unwrap();
        if unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        install_isolated_procfs()?;
        install_isolated_tmpfs()?;
        assign_isolated_tmpfs_owner(peer_uid, peer_gid)?;
        mask_runtime_directory()?;
        for path in denied_socket_paths {
            if path.starts_with("/run") || path.starts_with("/var/run") {
                continue;
            }
            mask_denied_path(path)?;
        }
        bind_mount_tree(source_root, true)?;
        for artifact_root in artifact_roots {
            bind_mount_tree(artifact_root, no_build)?;
        }
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setresgid(peer_gid, peer_gid, peer_gid) } != 0
            || unsafe { libc::setresuid(peer_uid, peer_uid, peer_uid) } != 0
            || unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut capabilities = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            2
        ];
        if unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header,
                capabilities.as_mut_ptr(),
            )
        } != 0
            || unsafe {
                libc::prctl(
                    PR_CAP_AMBIENT_VALUE,
                    PR_CAP_AMBIENT_CLEAR_ALL_VALUE,
                    0,
                    0,
                    0,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut writable_roots = vec![PathBuf::from("/tmp")];
        if !no_build {
            writable_roots.extend_from_slice(artifact_roots);
        }
        install_write_landlock(&writable_roots)?;
        if no_build {
            activate_no_build_exec_token(
                retained_plan_fd,
                retained_plan_identity,
            )?;
            install_no_build_seccomp(retained_plan_fd)?;
            if !verify_no_build_kernel_state(
                retained_plan_fd,
                retained_plan_identity,
            ) {
                return Err(ControllerError::Rejected(
                    "retired sandbox self-probe failed",
                ));
            }
        }
        unsafe {
            libc::umask(0o077);
        }
        Ok(())
    }

    fn assign_isolated_tmpfs_owner(uid: u32, gid: u32) -> Result<()> {
        let target = CString::new("/tmp").unwrap();
        if unsafe { libc::chown(target.as_ptr(), uid, gid) } != 0
            || unsafe { libc::chmod(target.as_ptr(), 0o700) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn install_isolated_procfs() -> Result<()> {
        let source = CString::new("proc").unwrap();
        let target = CString::new("/proc").unwrap();
        let filesystem = CString::new("proc").unwrap();
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC
                    | libc::MS_RDONLY,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn install_isolated_tmpfs() -> Result<()> {
        let source = CString::new("tmpfs").unwrap();
        let target = CString::new("/tmp").unwrap();
        let filesystem = CString::new("tmpfs").unwrap();
        let data = CString::new("mode=0700,size=1073741824,nr_inodes=131072").unwrap();
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                data.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn bind_mount_tree(path: &Path, read_only: bool) -> Result<()> {
        validate_absolute_normalized_path(path)?;
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("mount root contains NUL"))?;
        if unsafe {
            libc::mount(
                path_c.as_ptr(),
                path_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if !read_only {
            return Ok(());
        }
        let retained = open_canonical_path(path, libc::O_PATH, true)?;
        let empty = CString::new("").unwrap();
        let attributes = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY_FLAG,
            ..MountAttr::default()
        };
        if unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                retained.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | AT_RECURSIVE_FLAG,
                &attributes,
                mem::size_of::<MountAttr>(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn landlock_write_access(abi: i32) -> u64 {
        let mut access = LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            access |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            access |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
        access
    }

    fn install_write_landlock(writable_roots: &[PathBuf]) -> Result<()> {
        if writable_roots.is_empty() {
            return Err(ControllerError::Rejected(
                "Landlock write policy has no isolated writable root",
            ));
        }
        let abi = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<LandlockRulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION_VALUE,
            ) as i32
        };
        if abi < 1 {
            return Err(ControllerError::Unready(vec![
                "Landlock ABI is unavailable".to_owned(),
            ]));
        }
        let access = landlock_write_access(abi);
        let ruleset = LandlockRulesetAttr {
            handled_access_fs: access,
        };
        let ruleset_fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &ruleset,
                mem::size_of::<LandlockRulesetAttr>(),
                0,
            ) as RawFd
        };
        if ruleset_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let ruleset_fd = unsafe { OwnedFd::from_raw_fd(ruleset_fd) };
        let mut writable_descriptors = Vec::with_capacity(writable_roots.len());
        for writable_root in writable_roots {
            let writable =
                open_canonical_path(writable_root, libc::O_PATH, true)?;
            let path_rule = LandlockPathBeneathAttr {
                allowed_access: access,
                parent_fd: writable.as_raw_fd(),
                reserved: 0,
            };
            if unsafe {
                libc::syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd.as_raw_fd(),
                    LANDLOCK_RULE_PATH_BENEATH_VALUE,
                    &path_rule,
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            writable_descriptors.push(writable);
        }
        if unsafe {
            libc::syscall(
                SYS_LANDLOCK_RESTRICT_SELF,
                ruleset_fd.as_raw_fd(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn seccomp_statement(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn push_seccomp_errno(filter: &mut Vec<libc::sock_filter>, syscall: libc::c_long) {
        filter.push(seccomp_statement(0x15, 0, 1, syscall as u32));
        filter.push(seccomp_statement(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
        ));
    }

    fn push_seccomp_protected_fd(
        filter: &mut Vec<libc::sock_filter>,
        syscall: libc::c_long,
        argument_offset: u32,
        protected_fd: RawFd,
    ) {
        filter.push(seccomp_statement(0x15, 0, 3, syscall as u32));
        filter.push(seccomp_statement(0x20, 0, 0, argument_offset));
        filter.push(seccomp_statement(0x15, 0, 1, protected_fd as u32));
        filter.push(seccomp_statement(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
        ));
        filter.push(seccomp_statement(0x20, 0, 0, 0));
    }

    fn push_seccomp_protected_fd_fcntl(
        filter: &mut Vec<libc::sock_filter>,
        protected_fd: RawFd,
    ) {
        filter.push(seccomp_statement(0x15, 0, 5, libc::SYS_fcntl as u32));
        filter.push(seccomp_statement(0x20, 0, 0, 16));
        filter.push(seccomp_statement(0x15, 0, 3, protected_fd as u32));
        filter.push(seccomp_statement(0x20, 0, 0, 24));
        filter.push(seccomp_statement(0x15, 1, 0, libc::F_GETFD as u32));
        filter.push(seccomp_statement(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
        ));
        filter.push(seccomp_statement(0x20, 0, 0, 0));
    }

    fn install_no_build_seccomp(retained_plan_fd: RawFd) -> Result<()> {
        if retained_plan_fd < 3 {
            return Err(ControllerError::Rejected(
                "retained plan FD is not isolated from standard descriptors",
            ));
        }
        let mut filter = Vec::<libc::sock_filter>::new();
        filter.push(seccomp_statement(0x20, 0, 0, 4));
        filter.push(seccomp_statement(0x15, 1, 0, AUDIT_ARCH_NATIVE));
        filter.push(seccomp_statement(
            0x06,
            0,
            0,
            SECCOMP_RET_KILL_PROCESS_VALUE,
        ));
        filter.push(seccomp_statement(0x20, 0, 0, 0));

        // This legacy probe filter never launches a workload. The production
        // launcher uses a closure-only pivot root and permits execution only
        // after namespace reachability is constrained.
        push_seccomp_errno(&mut filter, libc::SYS_execve);
        push_seccomp_errno(&mut filter, libc::SYS_execveat);
        push_seccomp_protected_fd(
            &mut filter,
            libc::SYS_close,
            16,
            retained_plan_fd,
        );
        push_seccomp_errno(&mut filter, libc::SYS_close_range);
        push_seccomp_protected_fd(
            &mut filter,
            libc::SYS_dup2,
            24,
            retained_plan_fd,
        );
        push_seccomp_protected_fd(
            &mut filter,
            libc::SYS_dup3,
            24,
            retained_plan_fd,
        );
        push_seccomp_protected_fd_fcntl(&mut filter, retained_plan_fd);

        filter.push(seccomp_statement(0x15, 0, 4, libc::SYS_clone as u32));
        filter.push(seccomp_statement(0x20, 0, 0, 16));
        filter.push(seccomp_statement(0x45, 0, 1, 0x7e02_0000));
        filter.push(seccomp_statement(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32,
        ));
        filter.push(seccomp_statement(0x20, 0, 0, 0));

        for syscall in [
            libc::SYS_clone3,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_userfaultfd,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_process_vm_writev,
            libc::SYS_perf_event_open,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
        ] {
            push_seccomp_errno(&mut filter, syscall);
        }
        filter.push(seccomp_statement(0x06, 0, 0, SECCOMP_RET_ALLOW_VALUE));
        let program = libc::sock_fprog {
            len: filter
                .len()
                .try_into()
                .map_err(|_| ControllerError::Rejected("seccomp program is too large"))?,
            filter: filter.as_mut_ptr(),
        };
        if unsafe {
            libc::prctl(
                PR_SET_SECCOMP_VALUE,
                SECCOMP_MODE_FILTER_VALUE,
                &program as *const libc::sock_fprog,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn verify_no_build_kernel_state(
        retained_plan_fd: RawFd,
        expected: &FileIdentity,
    ) -> bool {
        if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2 {
            return false;
        }
        let token_open_and_persistent = descriptor_flags(retained_plan_fd)
            .map(|flags| flags & libc::FD_CLOEXEC == 0)
            .unwrap_or(false)
            && regular_file_identity_with_generation(
                retained_plan_fd,
                true,
                expected.generation,
            )
            .map(|identity| identity == *expected)
            .unwrap_or(false);
        let missing = CString::new("/catchplate-no-build-exec-probe").unwrap();
        let denied_exec = unsafe {
            libc::syscall(
                libc::SYS_execve,
                missing.as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
            )
        } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        let absolute = CString::new(LAUNCHER_INSTALL_PATH).unwrap();
        let denied_absolute_execveat = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                retained_plan_fd,
                absolute.as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                libc::AT_EMPTY_PATH,
            )
        } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        let denied_close = unsafe { libc::close(retained_plan_fd) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        let allowed_tmp = CString::new(format!(
            "/tmp/catchplate-landlock-{}",
            unsafe { libc::getpid() }
        ))
        .ok()
        .and_then(|path| {
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return None;
            }
            unsafe {
                libc::close(fd);
                libc::unlink(path.as_ptr());
            }
            Some(())
        })
        .is_some();
        let denied_outside = CString::new(format!(
            "/dev/shm/catchplate-landlock-{}",
            unsafe { libc::getpid() }
        ))
        .ok()
        .map(|path| {
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                    libc::unlink(path.as_ptr());
                }
                return false;
            }
            matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS)
            )
        })
        .unwrap_or(false);
        denied_exec
            && denied_absolute_execveat
            && denied_close
            && token_open_and_persistent
            && allowed_tmp
            && denied_outside
    }

    fn mask_runtime_directory() -> Result<()> {
        let source = CString::new("tmpfs").unwrap();
        let target = CString::new("/run").unwrap();
        let filesystem = CString::new("tmpfs").unwrap();
        let data = CString::new("mode=0555,size=4096").unwrap();
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                data.as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn mask_denied_path(path: &Path) -> Result<()> {
        validate_absolute_normalized_path(path)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ControllerError::Rejected(
                        "denied socket path is a symlink and cannot be safely masked",
                    ));
                }
                let source = CString::new("/dev/null").unwrap();
                let target = CString::new(path.as_os_str().as_bytes())
                    .map_err(|_| ControllerError::Invalid("denied path contains NUL"))?;
                if unsafe {
                    libc::mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn exec_controller_launcher_mode(
        launcher_fd: RawFd,
        contract_fd: RawFd,
        readiness_probe: bool,
    ) -> i32 {
        let descriptor_flags = unsafe { libc::fcntl(contract_fd, libc::F_GETFD) };
        if descriptor_flags < 0
            || unsafe {
                libc::fcntl(
                    contract_fd,
                    libc::F_SETFD,
                    descriptor_flags & !libc::FD_CLOEXEC,
                )
            } != 0
        {
            return 125;
        }
        let program = match CString::new(LAUNCHER_INSTALL_PATH) {
            Ok(value) => value,
            Err(_) => return 125,
        };
        let mode = CString::new(if readiness_probe {
            "probe-v11"
        } else {
            "launch-v11"
        })
        .unwrap();
        let contract = match CString::new(format!(
            "CATCHPLATE_CONTROLLER_LAUNCH_CONTRACT_FD={contract_fd}"
        )) {
            Ok(value) => value,
            Err(_) => return 125,
        };
        let argv = [program.as_ptr(), mode.as_ptr(), std::ptr::null()];
        let envp = [contract.as_ptr(), std::ptr::null()];
        let empty = CString::new("").unwrap();
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                launcher_fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        126
    }

    fn monitor_workload(
        pid: libc::pid_t,
        pidfd: RawFd,
        expected_start_time_ticks: u64,
        executable_path: &Path,
        executable_identity: &FileIdentity,
        executable_sha256: Digest,
        workload_cgroup: RawFd,
        require_seccomp_inheritance: bool,
        executable_closure_sha256: Digest,
        timeout: Duration,
        readiness_output: RawFd,
        output: RawFd,
    ) -> i32 {
        let deadline = match Instant::now().checked_add(timeout) {
            Some(deadline) => deadline,
            None => return 124,
        };
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"catchplate/procfs-pidfd-monitor/v11\0");
        transcript.extend_from_slice(&expected_start_time_ticks.to_be_bytes());
        transcript.extend_from_slice(executable_path.as_os_str().as_bytes());
        transcript.push(0);
        append_file_identity(&mut transcript, executable_identity);
        transcript.extend_from_slice(&executable_sha256);
        transcript.extend_from_slice(&executable_closure_sha256);
        if proc_start_time_ticks(pid).ok() != Some(expected_start_time_ticks)
            || !pidfd_poll_live(pidfd).unwrap_or(false)
        {
            return 123;
        }
        let members = match read_bounded_control_file(
            workload_cgroup,
            "cgroup.procs",
            4 * 1024 * 1024,
        ) {
            Ok(members) => members,
            Err(_) => return 123,
        };
        if !std::str::from_utf8(&members)
            .ok()
            .map(|members| {
                members.lines().any(|member| member == pid.to_string())
            })
            .unwrap_or(false)
            || write_all_fd(readiness_output, b"M").is_err()
        {
            return 123;
        }
        let mut exec_observed = false;
        let mut executable_vma_observed = false;
        let mut exit_observed = false;
        let mut seccomp_descendants_proved = !require_seccomp_inheritance;
        let mut map_hasher = Sha256::new();
        let mut kernel_executable_mapping_hasher = Sha256::new();
        let mut containment_hasher = Sha256::new();
        let mut samples = 0u64;
        while Instant::now() < deadline {
            match proc_start_time_ticks(pid) {
                Ok(start) if start == expected_start_time_ticks => {}
                Err(_) if !pidfd_poll_live(pidfd).unwrap_or(true) => {
                    transcript.extend_from_slice(
                        b"pidfd-exit-observed-after-proc-removal\0",
                    );
                    exit_observed = true;
                    break;
                }
                _ => {
                    if write_all_fd(
                        output,
                        b"monitor-start-time-mismatch",
                    )
                    .is_err()
                    {
                        return 124;
                    }
                    return 123;
                }
            }
            if !exec_observed {
                if let Ok(target) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                    if target == executable_path {
                        if let Ok(metadata) = std::fs::metadata(format!("/proc/{pid}/exe")) {
                            if metadata.dev() == executable_identity.device
                                && metadata.ino() == executable_identity.inode
                            {
                                exec_observed = true;
                                transcript.extend_from_slice(b"exec-observed\0");
                            }
                        }
                    }
                }
            }
            if exec_observed {
                if let Ok(maps) =
                    read_bounded_file(Path::new(&format!("/proc/{pid}/maps")), 4 * 1024 * 1024)
                {
                    if let Ok(text) = std::str::from_utf8(&maps) {
                        for line in text.lines() {
                            let fields: Vec<&str> =
                                line.split_ascii_whitespace().collect();
                            let executable = fields
                                .get(1)
                                .map(|permissions| permissions.contains('x'))
                                .unwrap_or(false);
                            if !executable {
                                continue;
                            }
                            let inode = fields
                                .get(4)
                                .and_then(|value| value.parse::<u64>().ok())
                                .unwrap_or(0);
                            let mapped_path = fields.get(5).copied().unwrap_or("");
                            if inode == executable_identity.inode
                                && mapped_path
                                    == executable_path.to_string_lossy().as_ref()
                            {
                                executable_vma_observed = true;
                                continue;
                            }
                            if mapped_path == "[vdso]" {
                                let range = fields.first().copied().unwrap_or("");
                                let measured = match measure_process_mapping(
                                    pid,
                                    range,
                                    16 * 1024 * 1024,
                                ) {
                                    Ok(measured) => measured,
                                    Err(_) => {
                                        let _ = write_all_fd(
                                            output,
                                            b"monitor-vdso-measurement-failed",
                                        );
                                        return 123;
                                    }
                                };
                                kernel_executable_mapping_hasher
                                    .update(b"vdso\0");
                                kernel_executable_mapping_hasher
                                    .update((measured.len() as u64).to_be_bytes());
                                kernel_executable_mapping_hasher.update(&measured);
                                continue;
                            }
                            if mapped_path == "[vsyscall]"
                                && inode == 0
                                && fields.first().copied()
                                    == Some("ffffffffff600000-ffffffffff601000")
                            {
                                kernel_executable_mapping_hasher
                                    .update(b"vsyscall\0");
                                kernel_executable_mapping_hasher
                                    .update(line.as_bytes());
                                continue;
                            }
                            let _ = write_all_fd(
                                output,
                                b"monitor-unlisted-executable-mapping",
                            );
                            return 123;
                        }
                    }
                    map_hasher.update((maps.len() as u64).to_be_bytes());
                    map_hasher.update(&maps);
                    samples = samples.saturating_add(1);
                }
            }
            {
                let mut sample_proved = true;
                let mut member_count = 0u64;
                match read_bounded_control_file(
                    workload_cgroup,
                    "cgroup.procs",
                    4 * 1024 * 1024,
                ) {
                    Ok(members) => {
                        containment_hasher
                            .update((members.len() as u64).to_be_bytes());
                        containment_hasher.update(&members);
                        let members = match std::str::from_utf8(&members) {
                            Ok(members) => members,
                            Err(_) => return 123,
                        };
                        for member in members.lines() {
                            let member_pid = match member.parse::<libc::pid_t>() {
                                Ok(member_pid) if member_pid > 0 => member_pid,
                                _ => return 123,
                            };
                            member_count = member_count.saturating_add(1);
                            if member_pid != pid {
                                let _ = write_all_fd(
                                    output,
                                    b"monitor-unlisted-descendant",
                                );
                                return 123;
                            }
                            let status = match read_bounded_file(
                                Path::new(&format!("/proc/{member_pid}/status")),
                                1024 * 1024,
                            ) {
                                Ok(status) => status,
                                Err(_) => {
                                    sample_proved = false;
                                    continue;
                                }
                            };
                            containment_hasher
                                .update((status.len() as u64).to_be_bytes());
                            containment_hasher.update(&status);
                            sample_proved &= !require_seccomp_inheritance
                                || std::str::from_utf8(&status)
                                .ok()
                                .map(|status| {
                                    status.lines().any(|line| {
                                        line.strip_prefix("Seccomp:")
                                            .map(str::trim)
                                            == Some("2")
                                    })
                                })
                                .unwrap_or(false);
                        }
                    }
                    Err(_) => sample_proved = false,
                }
                if member_count != 1 {
                    let _ =
                        write_all_fd(output, b"monitor-process-count-drift");
                    return 123;
                }
                seccomp_descendants_proved |= sample_proved;
            }
            let mut descriptor = libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut descriptor, 1, 20) };
            if polled < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return 123;
            }
            if descriptor.revents & libc::POLLIN != 0 {
                transcript.extend_from_slice(b"pidfd-exit-observed\0");
                exit_observed = true;
                break;
            }
        }
        if !exec_observed
            || !executable_vma_observed
            || !exit_observed
            || samples == 0
        {
            if write_all_fd(output, b"monitor-exec-or-vma-unproved").is_err() {
                return 124;
            }
            return 123;
        }
        if require_seccomp_inheritance && !seccomp_descendants_proved {
            if write_all_fd(output, b"monitor-seccomp-inheritance-unproved").is_err() {
                return 124;
            }
            return 123;
        }
        let maps_digest = map_hasher.finalize();
        let kernel_mapping_digest =
            kernel_executable_mapping_hasher.finalize();
        let containment_digest = containment_hasher.finalize();
        transcript.extend_from_slice(&samples.to_be_bytes());
        transcript.extend_from_slice(&maps_digest);
        transcript.extend_from_slice(&kernel_mapping_digest);
        transcript.extend_from_slice(&containment_digest);
        transcript.push(u8::from(seccomp_descendants_proved));
        transcript.push(1);
        if let Ok(cmdline) =
            read_bounded_file(Path::new(&format!("/proc/{pid}/cmdline")), 1024 * 1024)
        {
            transcript.extend_from_slice(&sha256(&cmdline));
        } else {
            transcript.extend_from_slice(&[0; 32]);
        }
        if transcript.len() > PROVIDER_MAX_BYTES || write_all_fd(output, &transcript).is_err() {
            return 124;
        }
        0
    }

    fn proc_retained_exec_token_is_persistent(
        pid: libc::pid_t,
        retained_fd: RawFd,
        expected: &FileIdentity,
    ) -> bool {
        let descriptor_path = format!("/proc/{pid}/fd/{retained_fd}");
        let metadata = match std::fs::metadata(&descriptor_path) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        if metadata.dev() != expected.device || metadata.ino() != expected.inode {
            return false;
        }
        let fdinfo_path = format!("/proc/{pid}/fdinfo/{retained_fd}");
        read_bounded_file(Path::new(&fdinfo_path), 64 * 1024)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("flags:\t"))
                    .and_then(|flags| u64::from_str_radix(flags.trim(), 8).ok())
            })
            .map(|flags| flags & libc::O_CLOEXEC as u64 == 0)
            .unwrap_or(false)
    }

    fn measure_process_mapping(
        pid: libc::pid_t,
        range: &str,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let (start, end) = range
            .split_once('-')
            .ok_or(ControllerError::Invalid(
                "executable mapping range is invalid",
            ))?;
        let start = u64::from_str_radix(start, 16).map_err(|_| {
            ControllerError::Invalid("mapping start is not hexadecimal")
        })?;
        let end = u64::from_str_radix(end, 16).map_err(|_| {
            ControllerError::Invalid("mapping end is not hexadecimal")
        })?;
        let length = end.checked_sub(start).ok_or(
            ControllerError::Invalid("mapping range is reversed"),
        )?;
        if length == 0 || length > maximum as u64 {
            return Err(ControllerError::Rejected(
                "executable kernel mapping exceeds its measurement bound",
            ));
        }
        let memory = File::open(format!("/proc/{pid}/mem"))?;
        let mut bytes = vec![0u8; length as usize];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let address = start
                .checked_add(offset as u64)
                .ok_or(ControllerError::Invalid(
                    "mapping measurement address overflow",
                ))?;
            let address: libc::off_t = address.try_into().map_err(|_| {
                ControllerError::Invalid(
                    "mapping address exceeds signed off_t",
                )
            })?;
            let count = unsafe {
                libc::pread(
                    memory.as_raw_fd(),
                    bytes[offset..].as_mut_ptr() as *mut libc::c_void,
                    bytes.len() - offset,
                    address,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "executable kernel mapping measurement truncated",
                ));
            }
            offset += count as usize;
        }
        Ok(bytes)
    }

    fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(ControllerError::Rejected("evidence file exceeds byte bound"));
        }
        Ok(bytes)
    }

    fn decode_mountinfo_path(encoded: &str) -> Result<PathBuf> {
        let input = encoded.as_bytes();
        let mut output = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            if input[index] != b'\\' {
                output.push(input[index]);
                index += 1;
                continue;
            }
            if index + 3 >= input.len()
                || !input[index + 1..=index + 3]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte))
            {
                return Err(ControllerError::Rejected(
                    "mountinfo path has an invalid escape",
                ));
            }
            let value = (input[index + 1] - b'0') * 64
                + (input[index + 2] - b'0') * 8
                + (input[index + 3] - b'0');
            output.push(value);
            index += 4;
        }
        Ok(PathBuf::from(std::ffi::OsString::from_vec(output)))
    }

    fn current_namespace_identities() -> Result<Vec<PathBuf>> {
        let mut identities = Vec::new();
        for namespace in ["mnt", "pid", "user", "ipc", "uts", "net", "cgroup"] {
            identities.push(std::fs::read_link(format!(
                "/proc/self/ns/{namespace}"
            ))?);
        }
        Ok(identities)
    }

    fn probe_linux_requirements() -> Result<()> {
        let pid = unsafe { libc::getpid() };
        let pidfd = pidfd_open(pid)?;
        if pidfd_identity(pidfd.as_raw_fd())? != format!("pid:{pid}") {
            return Err(ControllerError::Rejected("pidfd probe failed"));
        }
        let memfd = create_sealed_memfd("catchplate-controller-probe-v11", b"v11")?;
        verify_sealed_memfd(memfd.as_raw_fd(), 3)?;
        Ok(())
    }

    pub struct FailClosedLinuxChildSupervisor<'a> {
        evidence: &'a dyn ContainmentEvidenceSink,
        cgroup_root: PathBuf,
    }

    impl<'a> FailClosedLinuxChildSupervisor<'a> {
        pub fn new(
            evidence: &'a dyn ContainmentEvidenceSink,
            cgroup_root: PathBuf,
        ) -> Result<Self> {
            if !cgroup_root.is_absolute() {
                return Err(ControllerError::Invalid(
                    "child supervisor cgroup root must be absolute",
                ));
            }
            Ok(Self {
                evidence,
                cgroup_root,
            })
        }
    }

    #[cfg(any())]
    impl<'a> FailClosedLinuxChildSupervisor<'a> {
        pub fn new(
            evidence: &'a dyn ContainmentEvidenceSink,
            cgroup_root: PathBuf,
        ) -> Result<Self> {
            if !cgroup_root.is_absolute() {
                return Err(ControllerError::Invalid(
                    "child supervisor cgroup root must be absolute",
                ));
            }
            Ok(Self {
                evidence,
                cgroup_root,
            })
        }

        fn record(&self, label: &'static str, bytes: &[u8]) -> Result<EvidenceReference> {
            self.evidence.record_observation(label, bytes)
        }

        fn open_cgroup_directory(&self, path: &Path) -> Result<OwnedFd> {
            if !path.is_absolute()
                || !path.starts_with(&self.cgroup_root)
                || path == self.cgroup_root
            {
                return Err(ControllerError::Rejected(
                    "verified cgroup path is outside the supervisor root",
                ));
            }
            let path_c = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| ControllerError::Invalid("cgroup path contains NUL"))?;
            let how = OpenHow {
                flags: (libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW) as u64,
                mode: 0,
                resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            };
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    path_c.as_ptr(),
                    &how,
                    mem::size_of::<OpenHow>(),
                ) as RawFd
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let directory = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut stat: libc::stat = unsafe { mem::zeroed() };
            if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if stat.st_uid != 0
                || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
                || stat.st_mode & 0o022 != 0
            {
                return Err(ControllerError::Rejected(
                    "cgroup directory is not root-owned and nonwritable",
                ));
            }
            Ok(directory)
        }

        fn read_cgroup_file(
            directory: RawFd,
            name: &'static str,
            maximum: u64,
        ) -> Result<Vec<u8>> {
            let name_c = CString::new(name)
                .map_err(|_| ControllerError::Invalid("cgroup filename contains NUL"))?;
            let raw = unsafe {
                libc::openat(
                    directory,
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let file = unsafe { File::from_raw_fd(raw) };
            let mut bytes = Vec::new();
            file.take(maximum + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > maximum {
                return Err(ControllerError::Rejected(
                    "cgroup control file exceeds byte bound",
                ));
            }
            Ok(bytes)
        }

        fn write_cgroup_kill(directory: RawFd) -> Result<()> {
            let name = CString::new("cgroup.kill")
                .map_err(|_| ControllerError::Invalid("cgroup filename contains NUL"))?;
            let raw = unsafe {
                libc::openat(
                    directory,
                    name.as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut file = unsafe { File::from_raw_fd(raw) };
            file.write_all(b"1\n")?;
            Ok(())
        }

        fn exact_cgroup_membership(pid: libc::pid_t, cgroup_path: &Path) -> Result<Vec<u8>> {
            let bytes = read_bounded_file(
                Path::new(&format!("/proc/{pid}/cgroup")),
                64 * 1024,
            )?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| ControllerError::Rejected("child cgroup data is not UTF-8"))?;
            let relative = cgroup_path
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| ControllerError::Rejected("child cgroup is not on cgroup v2"))?;
            let expected = format!("/{}", relative.display());
            if !text
                .lines()
                .any(|line| line.strip_prefix("0::") == Some(expected.as_str()))
            {
                return Err(ControllerError::Rejected(
                    "child is not in the exact supervisor-owned cgroup",
                ));
            }
            Ok(bytes)
        }

        fn collect_namespace_identities(
            pid: libc::pid_t,
        ) -> Result<(Vec<(String, String)>, Vec<u8>)> {
            let mut values = Vec::new();
            let mut canonical = Vec::new();
            for name in ["mnt", "pid", "user", "net", "ipc", "uts", "cgroup"] {
                let child = std::fs::read_link(format!("/proc/{pid}/ns/{name}"))?;
                let controller = std::fs::read_link(format!("/proc/self/ns/{name}"))?;
                if child == controller {
                    return Err(ControllerError::Rejected(
                        "child namespace is shared with controller",
                    ));
                }
                let value = child
                    .to_str()
                    .ok_or(ControllerError::Rejected(
                        "namespace identity is not UTF-8",
                    ))?
                    .to_owned();
                values.push((name.to_owned(), value.clone()));
                canonical.extend_from_slice(name.as_bytes());
                canonical.push(0);
                canonical.extend_from_slice(value.as_bytes());
                canonical.push(0);
            }
            Ok((values, canonical))
        }

        fn collect_privilege_evidence(
            pid: libc::pid_t,
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            let status = read_bounded_file(
                Path::new(&format!("/proc/{pid}/status")),
                1024 * 1024,
            )?;
            let text = std::str::from_utf8(&status)
                .map_err(|_| ControllerError::Rejected("child status is not UTF-8"))?;
            let no_new_privileges = text
                .lines()
                .find_map(|line| line.strip_prefix("NoNewPrivs:\t"))
                == Some("1");
            let capabilities_dropped = text
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:\t"))
                .map(|value| value.bytes().all(|byte| byte == b'0'))
                == Some(true);
            let seccomp_filter = text
                .lines()
                .find_map(|line| line.strip_prefix("Seccomp:\t"))
                == Some("2");
            if !no_new_privileges || !capabilities_dropped || !seccomp_filter {
                return Err(ControllerError::Rejected(
                    "child privilege-drop or seccomp precondition is absent",
                ));
            }
            let lsm = read_bounded_file(
                Path::new(&format!("/proc/{pid}/attr/current")),
                64 * 1024,
            )?;
            let lsm_text = std::str::from_utf8(&lsm)
                .map_err(|_| ControllerError::Rejected("child LSM label is not UTF-8"))?
                .trim();
            if lsm_text.is_empty() || lsm_text == "unconfined" {
                return Err(ControllerError::Rejected(
                    "child has no confined LSM label",
                ));
            }
            Ok((status, lsm))
        }

        fn collect_mount_and_socket_evidence(
            pre_execution: &VerifiedPreExecution,
            pid: libc::pid_t,
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            if !pre_execution.descendant_source_mounts_read_only()
                || pre_execution.mandatory_denied_socket_paths().is_empty()
            {
                return Err(ControllerError::Rejected(
                    "verified sandbox policy is incomplete",
                ));
            }
            let mountinfo = read_bounded_file(
                Path::new(&format!("/proc/{pid}/mountinfo")),
                4 * 1024 * 1024,
            )?;
            let text = std::str::from_utf8(&mountinfo)
                .map_err(|_| ControllerError::Rejected("child mountinfo is not UTF-8"))?;
            let mut source_root_seen = false;
            for line in text.lines() {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                if fields.len() <= 5 {
                    return Err(ControllerError::Rejected(
                        "child mountinfo record is malformed",
                    ));
                }
                let mountpoint = decode_mountinfo_path(fields[4])?;
                if mountpoint == pre_execution.source_root()
                    || mountpoint.starts_with(pre_execution.source_root())
                {
                    if !fields[5].split(',').any(|option| option == "ro") {
                        return Err(ControllerError::Rejected(
                            "source descendant mount is writable",
                        ));
                    }
                    source_root_seen |= mountpoint == pre_execution.source_root();
                }
            }
            if !source_root_seen {
                return Err(ControllerError::Rejected(
                    "source root is not an explicit read-only mount",
                ));
            }
            let mut socket_canonical = Vec::new();
            for socket in pre_execution.mandatory_denied_socket_paths() {
                let relative = socket
                    .strip_prefix("/")
                    .map_err(|_| ControllerError::Rejected("invalid denied socket path"))?;
                let visible = PathBuf::from(format!("/proc/{pid}/root")).join(relative);
                match std::fs::symlink_metadata(&visible) {
                    Ok(_) => {
                        return Err(ControllerError::Rejected(
                            "mandatory container socket path remains visible",
                        ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                socket_canonical.extend_from_slice(socket.as_os_str().as_bytes());
                socket_canonical.push(0);
            }
            Ok((mountinfo, socket_canonical))
        }

        fn open_member_pidfds(
            directory: RawFd,
            required_leader: libc::pid_t,
        ) -> Result<Vec<OwnedFd>> {
            let first = Self::read_cgroup_file(directory, "cgroup.procs", 4 * 1024 * 1024)?;
            let text = std::str::from_utf8(&first)
                .map_err(|_| ControllerError::Rejected("cgroup.procs is not UTF-8"))?;
            let mut pids = Vec::new();
            for line in text.lines() {
                let pid = line
                    .parse::<libc::pid_t>()
                    .map_err(|_| ControllerError::Rejected("invalid cgroup member PID"))?;
                if pid <= 1 || pids.len() >= 4096 {
                    return Err(ControllerError::Rejected(
                        "cgroup member set is invalid or too large",
                    ));
                }
                pids.push(pid);
            }
            if !pids.contains(&required_leader) {
                return Err(ControllerError::Rejected(
                    "leader is absent from its supervisor-owned cgroup",
                ));
            }
            let mut pidfds = Vec::with_capacity(pids.len());
            for pid in pids {
                pidfds.push(pidfd_open(pid)?);
            }
            let second = Self::read_cgroup_file(directory, "cgroup.procs", 4 * 1024 * 1024)?;
            if first != second {
                return Err(ControllerError::Rejected(
                    "cgroup membership changed during supervisor registration",
                ));
            }
            Ok(pidfds)
        }

        fn unknown(&self, reason: &str) -> Result<RawContainmentTerminal> {
            let evidence = self.record("containment-unknown", reason.as_bytes())?;
            Ok(RawContainmentTerminal {
                kind: ContainmentTerminalKind::Unknown,
                preconditions: evidence.clone(),
                pidfd_signal: evidence.clone(),
                cgroup_kill: evidence.clone(),
                process_group_kill: evidence.clone(),
                bounded_reap: evidence.clone(),
                watchdog_deadline_and_reap: evidence.clone(),
                cgroup_events_empty: evidence.clone(),
                cgroup_procs_empty: evidence,
            })
        }

        fn append_cleanup_result(
            transcript: &mut Vec<u8>,
            label: &'static str,
            result: &Result<()>,
        ) -> bool {
            transcript.extend_from_slice(label.as_bytes());
            transcript.push(0);
            match result {
                Ok(()) => {
                    transcript.extend_from_slice(b"ok");
                    transcript.push(0);
                    true
                }
                Err(error) => {
                    transcript.extend_from_slice(error.to_string().as_bytes());
                    transcript.push(0);
                    false
                }
            }
        }

        fn force_cleanup(
            &self,
            reason: &str,
            pid: libc::pid_t,
            pidfd: &OwnedFd,
            cgroup_directory: Option<&OwnedFd>,
            registered_member_pidfds: &[OwnedFd],
            process_group: Option<libc::pid_t>,
            watchdog_pid: libc::pid_t,
            watchdog_pidfd: &OwnedFd,
            watchdog_deadline_unix_ms: u64,
        ) -> Result<RawContainmentTerminal> {
            let mut pidfd_transcript = Vec::new();
            let mut cgroup_transcript = Vec::new();
            let mut process_group_transcript = Vec::new();
            let mut reap_transcript = Vec::new();
            let mut all_attempts_succeeded = true;

            let term = Self::checked_signal_pidfd(pidfd.as_raw_fd(), libc::SIGTERM);
            all_attempts_succeeded &=
                Self::append_cleanup_result(&mut pidfd_transcript, "leader-term", &term);

            if Self::live_group_identity(pid, pidfd.as_raw_fd(), process_group) {
                let group_term = Self::checked_signal_group(pid, libc::SIGTERM);
                all_attempts_succeeded &= Self::append_cleanup_result(
                    &mut process_group_transcript,
                    "group-term",
                    &group_term,
                );
            } else {
                process_group_transcript
                    .extend_from_slice(b"group-term-skipped-unproved-identity\0");
                all_attempts_succeeded = false;
            }

            // Do not reap before the last numeric process-group signal. Keeping
            // the direct child unreaped prevents PID/PGID reuse during cleanup.
            std::thread::sleep(Duration::from_millis(250));
            if Self::live_group_identity(pid, pidfd.as_raw_fd(), process_group) {
                let group_kill = Self::checked_signal_group(pid, libc::SIGKILL);
                all_attempts_succeeded &= Self::append_cleanup_result(
                    &mut process_group_transcript,
                    "group-kill",
                    &group_kill,
                );
            } else {
                process_group_transcript
                    .extend_from_slice(b"group-kill-skipped-no-live-leader\0");
            }

            let cgroup_kill = match cgroup_directory {
                Some(directory) => Self::write_cgroup_kill(directory.as_raw_fd()),
                None => Err(ControllerError::Rejected(
                    "supervisor cgroup directory was unavailable during cleanup",
                )),
            };
            all_attempts_succeeded &= Self::append_cleanup_result(
                &mut cgroup_transcript,
                "cgroup-kill",
                &cgroup_kill,
            );

            let mut cleanup_member_pidfds = Vec::new();
            if registered_member_pidfds.is_empty() {
                if let Some(directory) = cgroup_directory {
                    match Self::open_member_pidfds(directory.as_raw_fd(), pid) {
                        Ok(pidfds) => cleanup_member_pidfds = pidfds,
                        Err(error) => {
                            cgroup_transcript
                                .extend_from_slice(b"member-pidfd-refresh-error\0");
                            cgroup_transcript
                                .extend_from_slice(error.to_string().as_bytes());
                            cgroup_transcript.push(0);
                            all_attempts_succeeded = false;
                        }
                    }
                }
            }
            let member_pidfds = if registered_member_pidfds.is_empty() {
                cleanup_member_pidfds.as_slice()
            } else {
                registered_member_pidfds
            };
            for member in member_pidfds {
                let member_kill =
                    Self::checked_signal_pidfd(member.as_raw_fd(), libc::SIGKILL);
                all_attempts_succeeded &= Self::append_cleanup_result(
                    &mut pidfd_transcript,
                    "member-kill",
                    &member_kill,
                );
            }

            let leader_kill =
                Self::checked_signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL);
            all_attempts_succeeded &= Self::append_cleanup_result(
                &mut pidfd_transcript,
                "leader-kill",
                &leader_kill,
            );

            let final_reap =
                Self::reap_bounded(pid, Instant::now() + Duration::from_secs(2));
            let leader_reaped = match final_reap {
                Ok(Some(status)) => {
                    reap_transcript.extend_from_slice(b"final-reap\0");
                    reap_transcript.extend_from_slice(&status.to_be_bytes());
                    reap_transcript.push(0);
                    true
                }
                Ok(None) => {
                    reap_transcript.extend_from_slice(b"final-reap-timeout\0");
                    all_attempts_succeeded = false;
                    false
                }
                Err(error) => {
                    reap_transcript.extend_from_slice(b"final-reap-error\0");
                    reap_transcript.extend_from_slice(error.to_string().as_bytes());
                    reap_transcript.push(0);
                    all_attempts_succeeded = false;
                    false
                }
            };

            let mut events_bytes = Vec::new();
            let mut procs_bytes = Vec::new();
            let mut cgroup_empty = false;
            if let Some(directory) = cgroup_directory {
                let proof_deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < proof_deadline {
                    let events = Self::read_cgroup_file(
                        directory.as_raw_fd(),
                        "cgroup.events",
                        64 * 1024,
                    );
                    let procs = Self::read_cgroup_file(
                        directory.as_raw_fd(),
                        "cgroup.procs",
                        4 * 1024 * 1024,
                    );
                    match (events, procs) {
                        (Ok(events), Ok(procs)) => {
                            let populated_zero = std::str::from_utf8(&events)
                                .ok()
                                .and_then(|text| {
                                    text.lines().find_map(|line| {
                                        line.strip_prefix("populated ")
                                    })
                                })
                                == Some("0");
                            let procs_empty =
                                procs.iter().all(u8::is_ascii_whitespace);
                            events_bytes = events;
                            procs_bytes = procs;
                            if populated_zero && procs_empty {
                                cgroup_empty = true;
                                break;
                            }
                        }
                        (Err(error), _) | (_, Err(error)) => {
                            cgroup_transcript
                                .extend_from_slice(b"cgroup-empty-proof-error\0");
                            cgroup_transcript
                                .extend_from_slice(error.to_string().as_bytes());
                            cgroup_transcript.push(0);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            if !cgroup_empty {
                all_attempts_succeeded = false;
                if events_bytes.is_empty() {
                    events_bytes.extend_from_slice(b"cgroup-events-unavailable");
                }
                if procs_bytes.is_empty() {
                    procs_bytes.extend_from_slice(b"cgroup-procs-unavailable");
                }
            }

            let mut preconditions_bytes = Vec::new();
            preconditions_bytes.extend_from_slice(reason.as_bytes());
            preconditions_bytes.push(0);
            preconditions_bytes.extend_from_slice(
                if all_attempts_succeeded && leader_reaped && cgroup_empty {
                    b"cleanup-complete"
                } else {
                    b"cleanup-unproved"
                },
            );
            let preconditions =
                self.record("containment-forced-preconditions", &preconditions_bytes)?;
            let pidfd_signal =
                self.record("containment-forced-pidfd-signals", &pidfd_transcript)?;
            let cgroup_kill =
                self.record("containment-forced-cgroup-kill", &cgroup_transcript)?;
            let process_group_kill = self.record(
                "containment-forced-process-group-signals",
                &process_group_transcript,
            )?;
            let bounded_reap =
                self.record("containment-forced-bounded-reap", &reap_transcript)?;
            let cgroup_events_empty =
                self.record("containment-forced-cgroup-events", &events_bytes)?;
            let cgroup_procs_empty =
                self.record("containment-forced-cgroup-procs", &procs_bytes)?;
            let (watchdog_deadline_and_reap, _) = self.stop_watchdog(
                watchdog_pid,
                watchdog_pidfd,
                watchdog_deadline_unix_ms,
            )?;
            Ok(RawContainmentTerminal {
                kind: ContainmentTerminalKind::Unknown,
                preconditions,
                pidfd_signal,
                cgroup_kill,
                process_group_kill,
                bounded_reap,
                watchdog_deadline_and_reap,
                cgroup_events_empty,
                cgroup_procs_empty,
            })
        }

        fn preconditions_present(
            &self,
            pre_execution: &VerifiedPreExecution,
            child: &SupervisorChildHandle,
        ) -> bool {
            let references = [
                &child.pidfd_identity,
                &child.cgroup_identity,
                &child.namespace_identities,
                &child.source_read_only,
                &child.docker_masked,
                &child.no_new_privileges,
                &child.capability_drop,
                &child.seccomp,
                &child.lsm,
            ];
            child.pid() > 1
                && child.process_group() == child.pid()
                && Self::live_pidfd_identity(
                    child.watchdog_pid(),
                    child.watchdog_pidfd().as_raw_fd(),
                )
                && child.cgroup_path().is_absolute()
                && child.cgroup_path().starts_with(&self.cgroup_root)
                && child.cgroup_path() != self.cgroup_root
                && child.validate_supervisor_binding(pre_execution).is_ok()
                && references
                    .iter()
                    .all(|reference| reference.object_sha256 != [0; 32])
        }

        fn verify_live_preconditions(
            &self,
            child: &SupervisorChildHandle,
        ) -> Result<EvidenceReference> {
            if unsafe { libc::getpgid(child.pid()) } != child.pid() {
                return Err(ControllerError::Rejected(
                    "child does not own a dedicated process group",
                ));
            }
            let namespace_names = ["mnt", "pid", "user", "net", "ipc", "uts", "cgroup"];
            let mut canonical = Vec::new();
            for namespace in namespace_names {
                let child_ns =
                    std::fs::read_link(format!("/proc/{}/ns/{namespace}", child.pid()))?;
                let controller_ns =
                    std::fs::read_link(format!("/proc/self/ns/{namespace}"))?;
                if child_ns == controller_ns {
                    return Err(ControllerError::Rejected(
                        "child namespace is shared with controller",
                    ));
                }
                canonical.extend_from_slice(namespace.as_bytes());
                canonical.push(0);
                canonical.extend_from_slice(child_ns.as_os_str().as_bytes());
                canonical.push(0);
            }
            let status_bytes =
                read_bounded_file(Path::new(&format!("/proc/{}/status", child.pid())), 1024 * 1024)?;
            let status = std::str::from_utf8(&status_bytes)
                .map_err(|_| ControllerError::Rejected("child status is not UTF-8"))?;
            let no_new_privileges = status
                .lines()
                .find_map(|line| line.strip_prefix("NoNewPrivs:\t"))
                == Some("1");
            let capabilities_dropped = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:\t"))
                .map(|value| value.bytes().all(|byte| byte == b'0'))
                == Some(true);
            let seccomp_filter = status
                .lines()
                .find_map(|line| line.strip_prefix("Seccomp:\t"))
                == Some("2");
            if !no_new_privileges || !capabilities_dropped || !seccomp_filter {
                return Err(ControllerError::Rejected(
                    "child privilege-drop or seccomp precondition is absent",
                ));
            }
            let lsm = read_bounded_file(
                Path::new(&format!("/proc/{}/attr/current", child.pid())),
                64 * 1024,
            )?;
            let lsm_text = std::str::from_utf8(&lsm)
                .map_err(|_| ControllerError::Rejected("child LSM label is not UTF-8"))?
                .trim();
            if lsm_text.is_empty() || lsm_text == "unconfined" {
                return Err(ControllerError::Rejected(
                    "child has no confined LSM label",
                ));
            }
            let mountinfo_bytes = read_bounded_file(
                Path::new(&format!("/proc/{}/mountinfo", child.pid())),
                4 * 1024 * 1024,
            )?;
            let mountinfo = std::str::from_utf8(&mountinfo_bytes)
                .map_err(|_| ControllerError::Rejected("child mountinfo is not UTF-8"))?;
            let source_root = child.source_root();
            let mut source_root_seen = false;
            for line in mountinfo.lines() {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                if fields.len() <= 5 {
                    return Err(ControllerError::Rejected(
                        "child mountinfo record is malformed",
                    ));
                }
                let mountpoint = decode_mountinfo_path(fields[4])?;
                if mountpoint == source_root || mountpoint.starts_with(source_root) {
                    if !fields[5].split(',').any(|option| option == "ro") {
                        return Err(ControllerError::Rejected(
                            "source descendant mount is writable",
                        ));
                    }
                    source_root_seen |= mountpoint == source_root;
                }
            }
            if !source_root_seen {
                return Err(ControllerError::Rejected(
                    "child source root is not an explicit read-only mount",
                ));
            }
            for socket in child.denied_socket_paths() {
                if !socket.is_absolute() {
                    return Err(ControllerError::Rejected(
                        "masked container socket path is not absolute",
                    ));
                }
                let relative = socket
                    .strip_prefix("/")
                    .map_err(|_| ControllerError::Rejected("invalid masked socket path"))?;
                let visible =
                    PathBuf::from(format!("/proc/{}/root", child.pid())).join(relative);
                match std::fs::symlink_metadata(visible) {
                    Ok(_) => {
                        return Err(ControllerError::Rejected(
                            "container socket path remains visible inside child root",
                        ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let cgroup_bytes = read_bounded_file(
                Path::new(&format!("/proc/{}/cgroup", child.pid())),
                64 * 1024,
            )?;
            let cgroup = std::str::from_utf8(&cgroup_bytes)
                .map_err(|_| ControllerError::Rejected("child cgroup data is not UTF-8"))?;
            let expected_cgroup = child
                .cgroup_path()
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| ControllerError::Rejected("child cgroup is not on cgroup v2"))?;
            let expected_cgroup = format!("/{}", expected_cgroup.display());
            if !cgroup
                .lines()
                .any(|line| line.strip_prefix("0::") == Some(expected_cgroup.as_str()))
            {
                return Err(ControllerError::Rejected(
                    "child is not in its dedicated cgroup",
                ));
            }
            canonical.extend_from_slice(&status_bytes);
            canonical.extend_from_slice(&lsm);
            canonical.extend_from_slice(&mountinfo_bytes);
            canonical.extend_from_slice(&cgroup_bytes);
            self.record("containment-live-preconditions", &canonical)
        }

        fn checked_signal_pidfd(pidfd: RawFd, signal: libc::c_int) -> Result<()> {
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

        fn checked_signal_group(group: libc::pid_t, signal: libc::c_int) -> Result<()> {
            if unsafe { libc::killpg(group, signal) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error.into());
                }
            }
            Ok(())
        }

        fn live_pidfd_identity(pid: libc::pid_t, pidfd: RawFd) -> bool {
            if pidfd_identity(pidfd)
                .map(|identity| identity != format!("pid:{pid}"))
                .unwrap_or(true)
            {
                return false;
            }
            (unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            }) == 0
        }

        fn live_group_identity(
            pid: libc::pid_t,
            pidfd: RawFd,
            process_group: Option<libc::pid_t>,
        ) -> bool {
            process_group == Some(pid)
                && unsafe { libc::getpgid(pid) } == pid
                && Self::live_pidfd_identity(pid, pidfd)
        }

        fn reprove_live_leader(&self, child: &SupervisorChildHandle) -> Result<bool> {
            let signal_result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    child.pidfd().as_raw_fd(),
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if signal_result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(false);
                }
                return Err(error.into());
            }
            if unsafe { libc::getpgid(child.pid()) } != child.process_group() {
                return Err(ControllerError::Rejected(
                    "live leader no longer owns its registered process group",
                ));
            }
            Self::exact_cgroup_membership(child.pid(), child.cgroup_path())?;
            let (namespaces, _) = Self::collect_namespace_identities(child.pid())?;
            if namespaces.as_slice() != child.namespace_identity_values() {
                return Err(ControllerError::Rejected(
                    "live leader namespace identity changed after registration",
                ));
            }
            Ok(true)
        }

        fn reap_bounded(pid: libc::pid_t, deadline: Instant) -> Result<Option<i32>> {
            while Instant::now() < deadline {
                let mut status = 0;
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    return Ok(Some(status));
                }
                if result < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None)
        }

        fn stop_watchdog(
            &self,
            watchdog_pid: libc::pid_t,
            watchdog_pidfd: &OwnedFd,
            watchdog_deadline_unix_ms: u64,
        ) -> Result<(EvidenceReference, bool)> {
            let mut transcript = Vec::new();
            transcript.extend_from_slice(&watchdog_deadline_unix_ms.to_be_bytes());
            let identity_ok = pidfd_identity(watchdog_pidfd.as_raw_fd())
                .map(|identity| identity == format!("pid:{watchdog_pid}"))
                .unwrap_or(false);
            transcript.extend_from_slice(if identity_ok {
                b"watchdog-identity-ok\0"
            } else {
                b"watchdog-identity-unproved\0"
            });
            let term = Self::checked_signal_pidfd(
                watchdog_pidfd.as_raw_fd(),
                libc::SIGTERM,
            );
            let term_ok = Self::append_cleanup_result(
                &mut transcript,
                "watchdog-term",
                &term,
            );
            std::thread::sleep(Duration::from_millis(50));
            let kill = Self::checked_signal_pidfd(
                watchdog_pidfd.as_raw_fd(),
                libc::SIGKILL,
            );
            let kill_ok = Self::append_cleanup_result(
                &mut transcript,
                "watchdog-kill",
                &kill,
            );
            let reaped = match Self::reap_bounded(
                watchdog_pid,
                Instant::now() + Duration::from_secs(2),
            ) {
                Ok(Some(status)) => {
                    transcript.extend_from_slice(b"watchdog-reaped\0");
                    transcript.extend_from_slice(&status.to_be_bytes());
                    transcript.push(0);
                    true
                }
                Ok(None) => {
                    transcript.extend_from_slice(b"watchdog-reap-timeout\0");
                    false
                }
                Err(error) => {
                    transcript.extend_from_slice(b"watchdog-reap-error\0");
                    transcript.extend_from_slice(error.to_string().as_bytes());
                    transcript.push(0);
                    false
                }
            };
            let evidence = self.record(
                "containment-watchdog-deadline-and-reap",
                &transcript,
            )?;
            Ok((evidence, identity_ok && term_ok && kill_ok && reaped))
        }

    }

    #[cfg(any())]
    impl LinuxChildSupervisorBoundary for FailClosedLinuxChildSupervisor<'_> {
        fn launch_registered_child(
            &self,
            _pre_execution: &VerifiedPreExecution,
            _no_build: Option<&VerifiedNoBuildKernelCapability>,
            _trusted_start: &SignedTrustedTime,
        ) -> Result<SupervisorChildHandle> {
            Err(ControllerError::Unready(vec![
                "measured root clone3/pidfd/cgroup launcher is not installed"
                    .to_owned(),
                "external runtime providers cannot launch or nominate a PID"
                    .to_owned(),
            ]))
        }

        fn supervise_and_terminate(
            &self,
            pre_execution: &VerifiedPreExecution,
            child: SupervisorChildHandle,
            deadline_unix_ms: u64,
        ) -> Result<RawContainmentTerminal> {
            let primary = (|| -> Result<RawContainmentTerminal> {
            if !self.preconditions_present(pre_execution, &child) {
                return self.unknown("containment preconditions are incomplete");
            }
            let child_pidfd_identity = match pidfd_identity(child.pidfd().as_raw_fd()) {
                Ok(identity) => identity,
                Err(error) => {
                    return self.unknown(&format!("pidfd identity read failed: {error}"))
                }
            };
            if child_pidfd_identity != format!("pid:{}", child.pid()) {
                return self.unknown("pidfd does not identify child PID");
            }
            let preconditions = match self.verify_live_preconditions(&child) {
                Ok(evidence) => evidence,
                Err(error) => {
                    return self.unknown(&format!(
                        "live containment preconditions failed: {error}"
                    ))
                }
            };
            let now = now_unix_ms()?;
            if deadline_unix_ms <= now {
                return self.unknown("containment deadline already expired");
            }
            if let Err(error) =
                Self::checked_signal_pidfd(child.pidfd().as_raw_fd(), libc::SIGTERM)
            {
                return self.unknown(&format!("pidfd SIGTERM failed: {error}"));
            }
            let mut process_group_term = false;
            match self.reprove_live_leader(&child) {
                Ok(true) => {
                    if let Err(error) =
                        Self::checked_signal_group(child.process_group(), libc::SIGTERM)
                    {
                        return self.unknown(&format!(
                            "process-group SIGTERM failed: {error}"
                        ));
                    }
                    process_group_term = true;
                }
                Ok(false) => {}
                Err(error) => {
                    return self.unknown(&format!(
                        "leader revalidation before group TERM failed: {error}"
                    ))
                }
            }
            let grace = Instant::now() + Duration::from_millis(250);
            let reaped_during_grace = match Self::reap_bounded(child.pid(), grace) {
                Ok(status) => status,
                Err(error) => return self.unknown(&format!("grace reap failed: {error}")),
            };

            // The cgroup directory and all pidfds were opened and retained by the
            // supervisor at registration, so path replacement and PID reuse cannot
            // redirect cleanup.
            if let Err(error) =
                Self::write_cgroup_kill(child.cgroup_directory().as_raw_fd())
            {
                return self.unknown(&format!("cgroup.kill failed: {error}"));
            }
            for member in child.member_pidfds() {
                if let Err(error) =
                    Self::checked_signal_pidfd(member.as_raw_fd(), libc::SIGKILL)
                {
                    return self.unknown(&format!(
                        "cgroup member pidfd SIGKILL failed: {error}"
                    ));
                }
            }
            let mut process_group_kill = false;
            if reaped_during_grace.is_none() {
                match self.reprove_live_leader(&child) {
                    Ok(true) => {
                        if let Err(error) =
                            Self::checked_signal_group(child.process_group(), libc::SIGKILL)
                        {
                            return self.unknown(&format!(
                                "process-group SIGKILL failed: {error}"
                            ));
                        }
                        process_group_kill = true;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        return self.unknown(&format!(
                            "leader revalidation before group KILL failed: {error}"
                        ))
                    }
                }
            }
            let remaining = deadline_unix_ms.saturating_sub(now_unix_ms()?);
            if remaining == 0 {
                return self.unknown("containment deadline expired before final reap");
            }
            let status = match reaped_during_grace {
                Some(status) => status,
                None => {
                    let bound = Duration::from_millis(remaining.min(2_000));
                    match Self::reap_bounded(child.pid(), Instant::now() + bound) {
                        Ok(Some(status)) => status,
                        Ok(None) => return self.unknown("bounded reap deadline expired"),
                        Err(error) => {
                            return self.unknown(&format!("bounded reap failed: {error}"))
                        }
                    }
                }
            };
            let pidfd_signal = self.record(
                "containment-pidfd-term-and-kill",
                if child.member_pidfds().is_empty() {
                    b"no-member-pidfds"
                } else {
                    b"supervisor-owned-member-pidfds"
                },
            )?;
            let process_group_kill = self.record(
                "containment-process-group-signals",
                &[
                    u8::from(process_group_term),
                    u8::from(process_group_kill),
                ],
            )?;
            let cgroup_kill = self.record("containment-cgroup-kill", b"success")?;
            let bounded_reap =
                self.record("containment-bounded-reap", &status.to_be_bytes())?;

            let events = match Self::read_cgroup_file(
                child.cgroup_directory().as_raw_fd(),
                "cgroup.events",
                64 * 1024,
            ) {
                Ok(events) => events,
                Err(error) => {
                    return self.unknown(&format!("cgroup.events read failed: {error}"))
                }
            };
            let populated_zero = std::str::from_utf8(&events)
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.strip_prefix("populated "))
                })
                == Some("0");
            if !populated_zero {
                return self.unknown("cgroup.events does not prove populated 0");
            }
            let cgroup_events_empty =
                self.record("containment-cgroup-events", &events)?;
            let procs = match Self::read_cgroup_file(
                child.cgroup_directory().as_raw_fd(),
                "cgroup.procs",
                4 * 1024 * 1024,
            ) {
                Ok(procs) => procs,
                Err(error) => {
                    return self.unknown(&format!("cgroup.procs read failed: {error}"))
                }
            };
            if !procs.iter().all(u8::is_ascii_whitespace) {
                return self.unknown("cgroup.procs is not empty after reap");
            }
            let cgroup_procs_empty =
                self.record("containment-cgroup-procs", &procs)?;
            Ok(RawContainmentTerminal {
                kind: ContainmentTerminalKind::Clean,
                preconditions,
                pidfd_signal,
                cgroup_kill,
                process_group_kill,
                watchdog_deadline_and_reap: bounded_reap.clone(),
                bounded_reap,
                cgroup_events_empty,
                cgroup_procs_empty,
            })
            })();
            match primary {
                Ok(mut terminal)
                    if terminal.kind == ContainmentTerminalKind::Clean =>
                {
                    match self.stop_watchdog(
                        child.watchdog_pid(),
                        child.watchdog_pidfd(),
                        child.watchdog_deadline_unix_ms(),
                    ) {
                        Ok((watchdog_evidence, watchdog_clean)) => {
                            terminal.watchdog_deadline_and_reap =
                                watchdog_evidence;
                            if !watchdog_clean {
                                terminal.kind = ContainmentTerminalKind::Unknown;
                            }
                            Ok(terminal)
                        }
                        Err(error) => self.force_cleanup(
                            &format!(
                                "watchdog shutdown evidence failed: {error}"
                            ),
                            child.pid(),
                            child.pidfd(),
                            Some(child.cgroup_directory()),
                            child.member_pidfds(),
                            Some(child.process_group()),
                            child.watchdog_pid(),
                            child.watchdog_pidfd(),
                            child.watchdog_deadline_unix_ms(),
                        ),
                    }
                }
                Ok(terminal) => self.force_cleanup(
                    &format!(
                        "primary containment returned non-clean terminal: {:?}",
                        terminal.kind
                    ),
                    child.pid(),
                    child.pidfd(),
                    Some(child.cgroup_directory()),
                    child.member_pidfds(),
                    Some(child.process_group()),
                    child.watchdog_pid(),
                    child.watchdog_pidfd(),
                    child.watchdog_deadline_unix_ms(),
                ),
                Err(error) => self.force_cleanup(
                    &format!("primary containment failed: {error}"),
                    child.pid(),
                    child.pidfd(),
                    Some(child.cgroup_directory()),
                    child.member_pidfds(),
                    Some(child.process_group()),
                    child.watchdog_pid(),
                    child.watchdog_pidfd(),
                    child.watchdog_deadline_unix_ms(),
                ),
            }
        }
    }

    impl LinuxChildSupervisorBoundary for FailClosedLinuxChildSupervisor<'_> {
        fn prepare_registered_child(
            &self,
            _pre_execution: &VerifiedPreExecution,
            _no_build: Option<&VerifiedNoBuildKernelCapability>,
            _trusted_start: &SignedTrustedTime,
        ) -> Result<RawSupervisorPreparedExecution> {
            Err(ControllerError::Unready(vec![
                "the full-controller external supervisor route is not configured; standalone trusted-host production uses the shared sealed direct-supervisor capability route"
                    .to_owned(),
                "external runtimes cannot nominate or launch a PID".to_owned(),
            ]))
        }

        fn abort_unverified_preparation(
            &self,
            _pre_execution: &VerifiedPreExecution,
            _prepared: RawSupervisorPreparedExecution,
            _deadline_unix_ms: u64,
        ) -> Result<RawContainmentTerminal> {
            Err(ControllerError::Unready(vec![
                "no external prepared child can exist in trusted-host mode".to_owned(),
            ]))
        }

        fn release_verified_child(
            &self,
            _pre_execution: &VerifiedPreExecution,
            _gate: &VerifiedSupervisorExecutionGate,
            _trusted_start: &SignedTrustedTime,
            _deadline_unix_ms: u64,
        ) -> Result<RawSupervisorReleaseEvidence> {
            Err(ControllerError::Unready(vec![
                "the external shared supervisor release route is disabled".to_owned(),
            ]))
        }

        fn supervise_and_terminate(
            &self,
            _pre_execution: &VerifiedPreExecution,
            _gate: VerifiedSupervisorExecutionGate,
            _deadline_unix_ms: u64,
        ) -> Result<RawContainmentTerminal> {
            Err(ControllerError::Unready(vec![
                "the external shared supervisor containment route is disabled".to_owned(),
            ]))
        }
    }
}
