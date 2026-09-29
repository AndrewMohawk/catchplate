#[cfg(target_os = "linux")]
use crate::{
    canonical_json_bytes, decode_canonical_json,
    load_root_owned_v2_config,
    AuthenticatedClientIdentity, V2ConsumeAndRetrieveExactParams,
    ResponseObservationV2Runtime,
    RootOwnedResponseObservationV2Config,
    V2OperationRequest,
    V2ResponseDataControlResponse, V2ResponseDataRequest,
    RESPONSE_OBSERVATION_V2_API_VERSION,
    RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES,
};
#[cfg(target_os = "linux")]
use super::AuthenticatedSessionIdentity;
use std::error::Error;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub(crate) fn run_router_transaction_listener(
    config: RootOwnedResponseObservationV2Config,
    ready: std::sync::mpsc::SyncSender<()>,
) -> Result<(), super::V2RuntimeError> {
    linux_runtime::run(config, ready).map_err(|error| {
        super::V2RuntimeError::new(
            "custody_router_transaction_listener_failed",
            error.to_string(),
        )
    })
}

#[cfg(target_os = "linux")]
pub fn run_custody_service(
    service_role: super::config::CustodyServiceRole,
    config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    let config = load_root_owned_v2_config(&config_path)?;
    super::guest_delivery::require_host(&config)?;
    run_loaded_custody_service(config, service_role)
}

#[cfg(target_os = "linux")]
fn run_loaded_custody_service(
    config: RootOwnedResponseObservationV2Config,
    service_role: super::config::CustodyServiceRole,
) -> Result<(), super::V2RuntimeError> {
    super::guest_delivery::check(&config)?;
    let service_config = config.clone();
    let service = std::thread::Builder::new()
        .name(format!(
            "response-v2-{}-runtime",
            service_role.as_str()
        ))
        .spawn(move || {
            super::services::run_service(
                service_config,
                service_role,
            )
        })
        .map_err(|_| {
            super::V2RuntimeError::new(
                "custody_service_thread_failed",
                "start custody service runtime",
            )
        })?;
    wait_for_custody_service_start(
        &config,
        service_role,
        &service,
    )?;
    super::generation::publish_service_generation_readiness(
        &config,
        service_role,
    )?;
    if let Some(owner) = &config.guest_delivery {
        // This means only this process completed real local readiness publication.
        // Generation activation still requires its existing independent quorum.
        owner.complete_local_startup()?;
    }
    service.join().map_err(|_| {
        super::V2RuntimeError::new(
            "custody_service_thread_failed",
            "custody service runtime panicked",
        )
    })?
}

#[cfg(target_os = "linux")]
fn wait_for_custody_service_start(
    config: &RootOwnedResponseObservationV2Config,
    service_role: super::config::CustodyServiceRole,
    service: &std::thread::JoinHandle<
        Result<(), super::V2RuntimeError>,
    >,
) -> Result<(), super::V2RuntimeError> {
    let timeout_ms =
        super::generation::activation_timeout_ms(config)?;
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(timeout_ms))
        .ok_or_else(|| {
            super::V2RuntimeError::new(
                "custody_service_start_deadline_overflow",
                "custody service startup deadline overflowed",
            )
        })?;
    loop {
        super::guest_delivery::check(config)?;
        if service.is_finished() {
            return Err(super::V2RuntimeError::new(
                "custody_service_start_failed",
                format!(
                    "{} runtime exited before publishing readiness",
                    service_role.as_str()
                ),
            ));
        }
        if super::services::check_readiness(config, service_role)
            .is_ok()
        {
            super::guest_delivery::check(config)?;
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(super::V2RuntimeError::new(
                "custody_service_start_timeout",
                format!(
                    "{} did not publish live readiness before its signed request timeout",
                    service_role.as_str()
                ),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
pub fn check_custody_service_readiness(
    service_role: super::config::CustodyServiceRole,
    config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    let config = load_root_owned_v2_config(&config_path)?;
    super::guest_delivery::require_host(&config)?;
    super::services::check_readiness(&config, service_role)
}

#[cfg(target_os = "linux")]
pub fn run_generation_bootstrap(
    config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    let config = load_root_owned_v2_config(&config_path)?;
    super::guest_delivery::require_host(&config)?;
    super::generation::provision_generation_from_systemd_credentials(
        &config,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run_generation_activation(
    config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    let config = load_root_owned_v2_config(&config_path)?;
    super::guest_delivery::require_host(&config)?;
    super::generation::activate_generation_from_systemd_credentials(
        &config,
    )
}

#[cfg(target_os = "linux")]
pub fn run_provider_rpc_v1_compatibility(
) -> Result<(), super::V2RuntimeError> {
    Err(super::V2RuntimeError::new(
        "provider_rpc_v1_disabled",
        "the per-request provider-rpc-v1 launcher is disabled under the seven-process custody topology because it would expose role configuration to the router",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn run_custody_service(
    _service_role: super::config::CustodyServiceRole,
    _config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
pub fn check_custody_service_readiness(
    _service_role: super::config::CustodyServiceRole,
    _config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
pub fn run_generation_bootstrap(
    _config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
pub fn run_generation_activation(
    _config_path: PathBuf,
) -> Result<(), super::V2RuntimeError> {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
pub fn run_provider_rpc_v1_compatibility(
) -> Result<(), super::V2RuntimeError> {
    unsupported_platform()
}

#[cfg(not(target_os = "linux"))]
fn unsupported_platform() -> Result<(), super::V2RuntimeError> {
    Err(super::V2RuntimeError::new(
        "custody_platform_unsupported",
        "response-observation v2 requires Linux Unix sockets, CLOCK_BOOTTIME, peer credentials, sealed descriptors, pidfds, and cgroup v2",
    ))
}

pub fn dispatch_from_process_args(
) -> Result<(), super::V2RuntimeError> {
    let mut service_role = None;
    let mut config_path = None;
    let mut check_readiness = false;
    let mut bootstrap_generation = false;
    let mut activate_generation = false;
    let mut provider_compatibility = false;
    let mut guest_path = None;
    let mut guest_sha256 = None;
    let mut guest_listener_fd = None;
    let mut guest_listener_handoff_fd = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--guest-listener-fd" if guest_listener_fd.is_none() => {
                guest_listener_fd = Some(guest_descriptor_argument(arguments.next())?);
            }
            "--guest-listener-handoff-fd" if guest_listener_handoff_fd.is_none() => {
                guest_listener_handoff_fd = Some(guest_descriptor_argument(arguments.next())?);
            }
            "--guest-delivery" if guest_path.is_none() => {
                guest_path = Some(PathBuf::from(arguments.next().ok_or_else(|| {
                    super::V2RuntimeError::new("custody_cli_invalid", "--guest-delivery requires a protected absolute path")
                })?));
            }
            "--guest-delivery-sha256" if guest_sha256.is_none() => {
                guest_sha256 = Some(arguments.next().ok_or_else(|| {
                    super::V2RuntimeError::new("custody_cli_invalid", "--guest-delivery-sha256 requires the exact original digest")
                })?);
            }
            "--service" if service_role.is_none() => {
                let value = arguments.next().ok_or_else(|| {
                    super::V2RuntimeError::new(
                        "custody_cli_invalid",
                        "--service requires one of the seven closed service roles",
                    )
                })?;
                service_role = Some(value.parse().map_err(
                    |message: String| {
                        super::V2RuntimeError::new(
                            "custody_cli_invalid",
                            message,
                        )
                    },
                )?);
            }
            "--config" if config_path.is_none() => {
                config_path =
                    Some(PathBuf::from(arguments.next().ok_or_else(
                        || {
                            super::V2RuntimeError::new(
                                "custody_cli_invalid",
                                "--config requires an absolute path",
                            )
                        },
                    )?));
            }
            "--check-readiness" if !check_readiness => {
                check_readiness = true;
            }
            "--bootstrap-generation" if !bootstrap_generation => {
                bootstrap_generation = true;
            }
            "--activate-generation" if !activate_generation => {
                activate_generation = true;
            }
            "--serverware-provider-rpc-v1"
                if !provider_compatibility =>
            {
                provider_compatibility = true;
            }
            _ => {
                return Err(super::V2RuntimeError::new(
                    "custody_cli_invalid",
                    format!("unknown or duplicate argument: {argument}"),
                ))
            }
        }
    }
    let listener_supplied = guest_listener_fd.is_some() || guest_listener_handoff_fd.is_some();
    if listener_supplied && (guest_path.is_none() || guest_sha256.is_none()
        || guest_listener_fd.is_none() || guest_listener_handoff_fd.is_none()
        || guest_listener_fd == guest_listener_handoff_fd
        || service_role != Some(super::config::CustodyServiceRole::CustodyRouter)
        || check_readiness || bootstrap_generation || activate_generation || provider_compatibility) {
        return Err(super::V2RuntimeError::new("custody_cli_invalid",
            "paired distinct guest listener descriptors require only the signed guest router startup mode"));
    }
    #[cfg(target_os = "linux")]
    if listener_supplied {
        // Close-on-exec precedes generation/TEE verifier children in load().
        for fd in [guest_listener_fd, guest_listener_handoff_fd].into_iter().flatten() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
                return Err(super::V2RuntimeError::new("custody_cli_invalid", "guest inherited descriptor is unavailable"));
            }
        }
    }
    if guest_path.is_some() || guest_sha256.is_some() {
        if provider_compatibility || guest_path.is_none() || guest_sha256.is_none()
            || (bootstrap_generation && activate_generation)
            || ((bootstrap_generation || activate_generation) && (service_role.is_some() || check_readiness))
        {
            return Err(super::V2RuntimeError::new("custody_cli_invalid", "guest delivery flags must be paired with one exact custody startup mode"));
        }
        #[cfg(target_os = "linux")]
        {
            let role = if bootstrap_generation || activate_generation {
                super::config::CustodyServiceRole::StateAuthority
            } else {
                service_role.ok_or_else(|| super::V2RuntimeError::new("custody_cli_invalid", "guest service role required"))?
            };
            let config_path = config_path.ok_or_else(|| super::V2RuntimeError::new("custody_cli_invalid", "guest --config required"))?;
            let mut config = super::guest_delivery::load(&config_path, role,
                guest_path.as_ref().unwrap(), guest_sha256.as_ref().unwrap())?;
            if listener_supplied {
                use std::os::fd::{FromRawFd, OwnedFd};
                let socket = guest_listener_fd.ok_or_else(|| super::V2RuntimeError::new("custody_cli_invalid", "guest listener fd absent"))?;
                let handoff = guest_listener_handoff_fd.ok_or_else(|| super::V2RuntimeError::new("custody_cli_invalid", "guest handoff fd absent"))?;
                if unsafe { libc::fcntl(socket, libc::F_GETFD) } < 0 || unsafe { libc::fcntl(handoff, libc::F_GETFD) } < 0 {
                    return Err(super::V2RuntimeError::new("custody_cli_invalid", "guest descriptor is not an actual open inherited original"));
                }
                // Explicit inherited originals, never environment lookup. The
                // closed guest owner still verifies every FD and signed binding.
                let socket = unsafe { OwnedFd::from_raw_fd(socket) };
                let handoff = unsafe { OwnedFd::from_raw_fd(handoff) };
                super::guest_listener::attach(&mut config, socket, handoff)?;
            }
            if bootstrap_generation {
                super::generation::provision_generation_from_systemd_credentials(&config)?;
            } else if activate_generation {
                super::generation::activate_generation_from_systemd_credentials(&config)?;
            } else if check_readiness {
                super::services::check_readiness(&config, role)?;
            } else {
                return run_loaded_custody_service(config, role);
            }
            return super::guest_delivery::check(&config);
        }
        #[cfg(not(target_os = "linux"))]
        { return unsupported_platform(); }
    }
    if provider_compatibility {
        if service_role.is_some()
            || config_path.is_some()
            || check_readiness
            || bootstrap_generation
            || activate_generation
        {
            return Err(super::V2RuntimeError::new(
                "custody_cli_invalid",
                "provider-rpc-v1 compatibility cannot be combined with service mode",
            ));
        }
        return run_provider_rpc_v1_compatibility();
    }
    if bootstrap_generation {
        if service_role.is_some()
            || check_readiness
            || activate_generation
        {
            return Err(super::V2RuntimeError::new(
                "custody_cli_invalid",
                "generation bootstrap cannot be combined with service or readiness mode",
            ));
        }
        let config_path = config_path.ok_or_else(|| {
            super::V2RuntimeError::new(
                "custody_cli_invalid",
                "--bootstrap-generation requires --config",
            )
        })?;
        if !config_path.is_absolute() {
            return Err(super::V2RuntimeError::new(
                "custody_cli_invalid",
                "--config must be an absolute path",
            ));
        }
        return run_generation_bootstrap(config_path);
    }
    if activate_generation {
        if service_role.is_some() || check_readiness {
            return Err(super::V2RuntimeError::new(
                "custody_cli_invalid",
                "generation activation cannot be combined with service or readiness mode",
            ));
        }
        let config_path = config_path.ok_or_else(|| {
            super::V2RuntimeError::new(
                "custody_cli_invalid",
                "--activate-generation requires --config",
            )
        })?;
        if !config_path.is_absolute() {
            return Err(super::V2RuntimeError::new(
                "custody_cli_invalid",
                "--config must be an absolute path",
            ));
        }
        return run_generation_activation(config_path);
    }
    let service_role = service_role.ok_or_else(|| {
        super::V2RuntimeError::new(
            "custody_cli_invalid",
            "--service is required",
        )
    })?;
    let config_path = config_path.ok_or_else(|| {
        super::V2RuntimeError::new(
            "custody_cli_invalid",
            "--config is required",
        )
    })?;
    if !config_path.is_absolute() {
        return Err(super::V2RuntimeError::new(
            "custody_cli_invalid",
            "--config must be an absolute path",
        ));
    }
    if check_readiness {
        check_custody_service_readiness(
            service_role,
            config_path,
        )
    } else {
        run_custody_service(service_role, config_path)
    }
}

fn guest_descriptor_argument(value: Option<String>) -> Result<i32, super::V2RuntimeError> {
    let value = value.ok_or_else(|| super::V2RuntimeError::new("custody_cli_invalid", "guest descriptor argument missing"))?;
    let fd = value.parse::<i32>().map_err(|_| super::V2RuntimeError::new("custody_cli_invalid", "guest descriptor is not an integer"))?;
    if fd < 3 || fd.to_string() != value {
        return Err(super::V2RuntimeError::new("custody_cli_invalid", "guest descriptor must be canonical and outside stdio"));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
mod linux_runtime {
    use super::*;
    use super::super::peer_measurement::{
        ExecutableMeasurementCache, PeerMeasurement, capture_connection, capture_packet,
        received_fd_is_cloexec, open_peer_pidfd, ensure_pidfd_alive,
        prove_pidfds_same_process, peer_security_label,
        socket_peer_credentials, EXECUTABLE_CACHE_ENTRIES_PER_WORKER,
        MAX_EXECUTABLE_CACHE_ENTRIES,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::mem::{align_of, size_of, zeroed};
    use std::os::fd::{
        AsRawFd, FromRawFd, OwnedFd, RawFd,
    };
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{
        FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::path::Component;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{
        sync_channel, Receiver, SyncSender, TrySendError,
    };
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant};

    const SOCKET_DIRECTORY_MODE_MASK: u32 = 0o022;
    const SOCKET_MODE: u32 = 0o660;
    const LISTEN_BACKLOG: libc::c_int = 64;
    const MAX_RECEIVED_FDS: usize = 16;
    const MAX_PACKETS_PER_SESSION: usize = 256;
    const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(300);
    const SO_PASSPIDFD_OPTION: libc::c_int = 76;
    const SCM_PIDFD_TYPE: libc::c_int = 0x04;
    const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;

    #[repr(C)]
    struct Clone3ProbeArgs {
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

    pub(super) fn run(
        config: RootOwnedResponseObservationV2Config,
        ready: SyncSender<()>,
    ) -> Result<(), Box<dyn Error>> {
        probe_required_uapi()?;
        let guest = config.guest_listener.is_some();
        let mut socket_ownership = if guest { None } else {
            validate_socket_directory(config.socket_path(), config.expected_socket_gid())?;
            Some(SocketOwnershipLease::acquire(
                config.socket_path(),
                config.expected_socket_gid(),
            )?)
        };
        let worker_count = config.max_concurrent_operations();
        if worker_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured accept worker count must be nonzero",
            )
            .into());
        }
        let runtime = Arc::new(ResponseObservationV2Runtime::new(
            config.clone(),
        )?);
        let listener = if guest { SeqPacketListener::activate_guest(&config)? } else {
            SeqPacketListener::bind(config.socket_path(), config.expected_socket_gid())?
        };
        if let Some(owner) = &mut socket_ownership { owner.bind_socket_identity(listener.identity)?; }
        ready.send(()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "router readiness coordinator stopped before transaction listener publication",
            )
        })?;
        let (sender, receiver) = sync_channel(worker_count);
        let receiver = Arc::new(Mutex::new(receiver));
        let config = Arc::new(config);
        let cache_capacity = worker_count
            .saturating_mul(EXECUTABLE_CACHE_ENTRIES_PER_WORKER)
            .clamp(1, MAX_EXECUTABLE_CACHE_ENTRIES);
        let executable_cache = Arc::new(
            ExecutableMeasurementCache::new(cache_capacity),
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let runtime = Arc::clone(&runtime);
            let config = Arc::clone(&config);
            let executable_cache = Arc::clone(&executable_cache);
            let shutdown = Arc::clone(&shutdown);
            let deadline = config.whole_operation_timeout();
            workers.push(
                thread::Builder::new()
                    .name(format!("serverware-response-v2-{index}"))
                    .spawn(move || {
                        worker_loop(
                            receiver,
                            runtime,
                            config,
                            executable_cache,
                            shutdown,
                            deadline,
                        )
                    })?,
            );
        }

        eprintln!(
            "serverware response-observation v2 custody listening socket={} transport=SOCK_SEQPACKET bulk=sealed-memfd+SCM_RIGHTS providersReady={} attestationMode={:?} bootId={} expectedClientUid={}",
            config.socket_path().display(),
            runtime.providers_ready(),
            config.attestation_mode(),
            runtime.boot_id(),
            config.expected_client_uid(),
        );

        let accept_result = accept_loop(
            &listener,
            &sender,
        );
        shutdown.store(true, Ordering::Release);
        drop(sender);
        for worker in workers {
            let _ = worker.join();
        }
        accept_result?;
        Ok(())
    }

    fn accept_loop(
        listener: &SeqPacketListener,
        sender: &SyncSender<AcceptedConnection>,
    ) -> io::Result<()> {
        loop {
            let connection = listener.accept()?;
            let accepted_at = Instant::now();
            if let Err(error) =
                enable_per_packet_sender_identity(connection.as_raw_fd())
            {
                eprintln!(
                    "response-observation v2 rejected peer: {error}"
                );
                continue;
            }
            match sender.try_send(AcceptedConnection {
                socket: connection,
                accepted_at,
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(_connection)) => {
                    eprintln!(
                        "response-observation v2 rejected peer: bounded worker queue is full"
                    );
                }
                Err(TrySendError::Disconnected(_connection)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "response-observation v2 worker pool stopped",
                    ));
                }
            }
        }
    }

    fn worker_loop(
        receiver: Arc<Mutex<Receiver<AcceptedConnection>>>,
        runtime: Arc<ResponseObservationV2Runtime>,
        config: Arc<RootOwnedResponseObservationV2Config>,
        executable_cache: Arc<ExecutableMeasurementCache>,
        shutdown: Arc<AtomicBool>,
        deadline: Duration,
    ) {
        while !shutdown.load(Ordering::Acquire) {
            let received = match receiver.lock() {
                Ok(receiver) => receiver.recv(),
                Err(_) => return,
            };
            let connection = match received {
                Ok(connection) => connection,
                Err(_) => return,
            };
            if let Err(error) = serve_session(
                connection,
                &runtime,
                &config,
                &executable_cache,
                deadline,
            ) {
                eprintln!(
                    "response-observation v2 session failed: {error}"
                );
            }
        }
    }

    fn serve_session(
        connection: AcceptedConnection,
        runtime: &ResponseObservationV2Runtime,
        config: &RootOwnedResponseObservationV2Config,
        executable_cache: &ExecutableMeasurementCache,
        deadline: Duration,
    ) -> io::Result<()> {
        let socket = connection.socket.as_raw_fd();
        let peer = authenticate_peer(
            socket,
            config,
            executable_cache,
        )?;
        let session_identity = runtime
            .begin_authenticated_session(&peer.identity)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error,
                )
            })?;
        let mut hello_established = false;
        let mut response_data_request_ids = HashSet::new();
        for packet_index in 0..MAX_PACKETS_PER_SESSION {
            let operation_started_at = if packet_index == 0 {
                connection.accepted_at
            } else {
                Instant::now()
            };
            let packet_timeout = session_packet_remaining(
                deadline,
                operation_started_at,
                connection.accepted_at,
            )?;
            set_socket_deadline(socket, packet_timeout)?;
            let packet = receive_packet(socket)?;
            validate_packet_sender(
                socket,
                &peer,
                &packet.credentials,
                &packet.sender_pidfd,
                executable_cache,
            )?;
            if let Ok(request) =
                decode_canonical_json::<V2OperationRequest>(
                    &packet.control,
                )
            {
                let establishes_hello = validate_session_operation(
                    hello_established,
                    &request,
                    packet.files.is_empty(),
                )?;
                let response = runtime
                    .handle_control_packet(
                        &packet.control,
                        packet.files,
                        operation_started_at,
                        &peer.identity,
                        &session_identity,
                    )
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            error,
                        )
                    })?;
                response.with_parts(|control, files| {
                    validate_packet_sender(
                        socket,
                        &peer,
                        &packet.credentials,
                        &packet.sender_pidfd,
                        executable_cache,
                    )?;
                    set_socket_deadline(
                        socket,
                        session_packet_remaining(
                            deadline,
                            operation_started_at,
                            connection.accepted_at,
                        )?,
                    )?;
                    let raw_files: Vec<RawFd> =
                        files.iter().map(AsRawFd::as_raw_fd).collect();
                    send_packet(socket, control, &raw_files)
                })?;
                if establishes_hello {
                    hello_established = true;
                }
                continue;
            }
            let request: V2ResponseDataRequest =
                decode_canonical_json(&packet.control).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "control packet is neither an early lifecycle request nor a canonical response-data request",
                    )
                })?;
            if !hello_established {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "response-data operation rejected before authenticated Hello",
                ));
            }
            let operation_started_at = Instant::now();
            validate_response_data_request(
                runtime,
                &peer.identity,
                &request,
                &mut response_data_request_ids,
                operation_started_at,
                config.whole_operation_timeout(),
            )?;
            let descriptors = request.exact_object_descriptors();
            let validated = super::super::validate_exact_object_files(
                &descriptors,
                packet.files,
                None,
            )
            .map_err(runtime_io_error)?;
            let routed =
                super::super::services::router::
                    handle_response_data_request(
                        config,
                        request.clone(),
                        validated.into_files(),
                    )
                    .map_err(runtime_io_error)?;
            let output_descriptors =
                crate::response_observation_v2_api::
                    response_data_result_exact_object_descriptors(
                        &routed.result,
                    );
            if output_descriptors.len()
                != routed.exact_objects.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "response-data result descriptors do not match the exact descriptor transfer",
                ));
            }
            let response =
                attach_response_data_attestation(
                    runtime,
                    &request,
                    routed.result,
                    &output_descriptors,
                    &peer.identity,
                    &session_identity,
                    operation_started_at,
                    config.whole_operation_timeout(),
                )?;
            let control = canonical_json_bytes(&response).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response-data response cannot be canonicalized",
                )
            })?;
            let raw_files = routed
                .exact_objects
                .iter()
                .map(AsRawFd::as_raw_fd)
                .collect::<Vec<_>>();
            send_packet(socket, &control, &raw_files)?;
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated session packet bound exhausted",
        ))
    }

    struct AcceptedConnection {
        socket: OwnedFd,
        accepted_at: Instant,
    }

    struct AuthenticatedPeer {
        identity: AuthenticatedClientIdentity,
        pidfd: OwnedFd,
        measurement: PeerMeasurement,
    }

    fn validate_response_data_request(
        runtime: &ResponseObservationV2Runtime,
        client_identity: &AuthenticatedClientIdentity,
        request: &V2ResponseDataRequest,
        seen_request_ids: &mut HashSet<String>,
        accepted_at: Instant,
        maximum_duration: Duration,
    ) -> io::Result<()> {
        use crate::response_observation_v2_api::
            V2ResponseDataRequest as Request;
        let (api_version, binding) = match request {
            Request::AppendReleaseTransparency {
                api_version,
                params,
                ..
            } => (
                api_version,
                Some((
                    params.binding.request_id.as_str(),
                    params.binding.custody_boot_id.as_str(),
                    params.binding.client_identity_sha256.as_str(),
                )),
            ),
            Request::InspectImmutableResponse {
                api_version,
                params,
                ..
            } => (
                api_version,
                Some((
                    params.binding.request_id.as_str(),
                    params.binding.custody_boot_id.as_str(),
                    params.binding.client_identity_sha256.as_str(),
                )),
            ),
            Request::ValidateFinalEnvelope {
                api_version,
                params,
                ..
            } => (
                api_version,
                Some((
                    params.binding.request_id.as_str(),
                    params.binding.custody_boot_id.as_str(),
                    params.binding.client_identity_sha256.as_str(),
                )),
            ),
            Request::AuthorizeExactRelease {
                api_version,
                params,
                ..
            } => (
                api_version,
                Some((
                    params.binding.request_id.as_str(),
                    params.binding.custody_boot_id.as_str(),
                    params.binding.client_identity_sha256.as_str(),
                )),
            ),
            Request::ConsumeAndRetrieveExact {
                api_version,
                params,
                ..
            } => {
                let binding = match params {
                    V2ConsumeAndRetrieveExactParams::Prepare {
                        binding,
                        ..
                    } => (
                        binding.request_id.as_str(),
                        binding.custody_boot_id.as_str(),
                        binding.client_identity_sha256.as_str(),
                    ),
                    V2ConsumeAndRetrieveExactParams::Retrieve {
                        binding,
                        ..
                    } => (
                        binding.request_id.as_str(),
                        binding.custody_boot_id.as_str(),
                        binding.client_identity_sha256.as_str(),
                    ),
                };
                (api_version, Some(binding))
            }
            Request::ResolveExactReplay { api_version, .. }
            | Request::SettleAttempt { api_version, .. } => {
                (api_version, None)
            }
        };
        let (deadline, deadline_at_epoch_ms) = request.deadline();
        super::super::deadline_from_monotonic_binding(
            deadline,
            deadline_at_epoch_ms,
            runtime.boot_id(),
            accepted_at,
            maximum_duration,
        )
        .map_err(runtime_io_error)?;
        if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
            || request.boot_id() != runtime.boot_id()
            || request.request_id().is_empty()
            || request.request_id().len() > 256
            || request.attempt_id().is_empty()
            || request.stable_resume_id().is_empty()
            || request.fencing_token() == 0
            || !seen_request_ids.insert(request.request_id().to_owned())
            || binding.is_some_and(
                |(binding_request_id, custody_boot_id, client_sha256)| {
                binding_request_id != request.request_id()
                    || custody_boot_id != runtime.boot_id()
                    || client_sha256
                        != client_identity.identity_sha256()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "response-data request is not bound to the authenticated client, boot, unique request ID, attempt, fence, and live deadline",
            ));
        }
        Ok(())
    }

    fn attach_response_data_attestation(
        runtime: &ResponseObservationV2Runtime,
        request: &V2ResponseDataRequest,
        result:
            crate::response_observation_v2_api::V2ResponseDataResult,
        descriptors: &[crate::response_observation_v2_api::
            ExactByteObjectDescriptor],
        client_identity: &AuthenticatedClientIdentity,
        session_identity: &AuthenticatedSessionIdentity,
        accepted_at: Instant,
        maximum_duration: Duration,
    ) -> io::Result<V2ResponseDataControlResponse> {
        let unsigned = V2ResponseDataControlResponse::Success {
            api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: request.request_id().to_owned(),
            boot_id: runtime.boot_id().to_owned(),
            result: result.clone(),
            attestation: None,
        };
        let request_bytes =
            canonical_json_bytes(request).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response-data request cannot be canonicalized",
                )
            })?;
        let unsigned_bytes =
            canonical_json_bytes(&unsigned).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsigned response-data result cannot be canonicalized",
                )
            })?;
        let (monotonic_deadline, deadline_at_epoch_ms) =
            request.deadline();
        let deadline =
            super::super::deadline_from_monotonic_binding(
                monotonic_deadline,
                deadline_at_epoch_ms,
                runtime.boot_id(),
                accepted_at,
                maximum_duration,
            )
            .map_err(runtime_io_error)?;
        let providers = runtime
            .providers
            .configured()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "response-data release requires the configured trusted-host attestation authority",
                )
            })?;
        let attestation = providers
            .verify_fresh_attestation(
                &format!(
                    "sha256:{:x}",
                    Sha256::digest(&request_bytes)
                ),
                &format!(
                    "sha256:{:x}",
                    Sha256::digest(&unsigned_bytes)
                ),
                &super::super::descriptor_manifest_sha256(
                    descriptors,
                ),
                runtime.boot_id(),
                session_identity.session_sha256(),
                client_identity.identity_sha256(),
                &deadline,
            )
            .map_err(runtime_io_error)?;
        Ok(V2ResponseDataControlResponse::Success {
            api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: request.request_id().to_owned(),
            boot_id: runtime.boot_id().to_owned(),
            result,
            attestation: Some(attestation),
        })
    }

    fn runtime_io_error(error: super::super::V2RuntimeError) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, error)
    }

    fn remaining(
        deadline: Duration,
        accepted_at: Instant,
    ) -> io::Result<Duration> {
        deadline
            .checked_sub(accepted_at.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "whole-operation deadline exceeded",
                )
            })
    }

    fn session_packet_remaining(
        operation_deadline: Duration,
        operation_started_at: Instant,
        session_started_at: Instant,
    ) -> io::Result<Duration> {
        let operation_remaining =
            remaining(operation_deadline, operation_started_at)?;
        let session_remaining =
            remaining(MAX_SESSION_LIFETIME, session_started_at)?;
        Ok(operation_remaining.min(session_remaining))
    }

    fn validate_session_operation(
        hello_established: bool,
        request: &V2OperationRequest,
        has_no_exact_objects: bool,
    ) -> io::Result<bool> {
        match (hello_established, request) {
            (
                false,
                V2OperationRequest::Hello {
                    api_version,
                    boot_id,
                    ..
                },
            ) if api_version == RESPONSE_OBSERVATION_V2_API_VERSION
                && boot_id.is_none()
                && has_no_exact_objects =>
            {
                Ok(true)
            }
            (false, V2OperationRequest::Hello { .. }) => {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "initial hello does not satisfy the closed session establishment contract",
                ))
            }
            (false, _) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-hello operation rejected before authenticated session establishment",
            )),
            (true, V2OperationRequest::Hello { .. }) => {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "hello may establish an authenticated session only once",
                ))
            }
            (
                true,
                V2OperationRequest::Reserve { .. }
                | V2OperationRequest::Authority { .. }
                | V2OperationRequest::Stage { .. }
                | V2OperationRequest::Dispatch { .. }
                | V2OperationRequest::Terminal { .. },
            ) => Ok(false),
            (true, _) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legacy Finalize, Attest, Publish, Retrieve, Recover, and VerifyArchive are disabled on the response-data session",
            )),
        }
    }

    struct ReceivedPacket {
        control: Vec<u8>,
        files: Vec<File>,
        credentials: libc::ucred,
        sender_pidfd: OwnedFd,
    }

    fn receive_packet(socket: RawFd) -> io::Result<ReceivedPacket> {
        let mut control =
            vec![0u8; RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES];
        let rights_capacity = cmsg_space(
            MAX_RECEIVED_FDS
                .checked_mul(size_of::<RawFd>())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ancillary descriptor bound overflow",
                    )
                })?,
        )?;
        let credentials_capacity =
            cmsg_space(size_of::<libc::ucred>())?;
        let pidfd_capacity = cmsg_space(size_of::<RawFd>())?;
        let ancillary_capacity = rights_capacity
            .checked_add(credentials_capacity)
            .and_then(|value| value.checked_add(pidfd_capacity))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ancillary identity capacity overflow",
                )
            })?;
        let mut ancillary = aligned_ancillary_buffer(ancillary_capacity);
        let ancillary_base = ancillary.as_mut_ptr().cast::<u8>();
        let mut iovec = libc::iovec {
            iov_base: control.as_mut_ptr().cast(),
            iov_len: control.len(),
        };
        // SAFETY: zeroed msghdr is initialized below before recvmsg.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = ancillary_base.cast();
        set_msg_controllen(&mut message, ancillary_capacity)?;
        // SAFETY: all msghdr buffers are valid for the duration of recvmsg.
        let received =
            unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let returned_ancillary = msg_controllen(&message)?;
        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            if message.msg_control == ancillary_base.cast() {
                let cleanup_length =
                    returned_ancillary.min(ancillary_capacity);
                let _cleanup = scan_proven_rights(
                    &mut message,
                    ancillary_base,
                    cleanup_length,
                );
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated ancillary packet",
            ));
        }
        if message.msg_control != ancillary_base.cast()
            || returned_ancillary > ancillary_capacity
        {
            if message.msg_control == ancillary_base.cast() {
                let cleanup_length =
                    returned_ancillary.min(ancillary_capacity);
                let _cleanup = scan_proven_rights(
                    &mut message,
                    ancillary_base,
                    cleanup_length,
                );
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned an out-of-region ancillary buffer",
            ));
        }
        if message.msg_flags & libc::MSG_TRUNC != 0 {
            let _cleanup = scan_proven_rights(
                &mut message,
                ancillary_base,
                returned_ancillary,
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated control packet",
            ));
        }
        if received == 0 {
            let _cleanup = scan_proven_rights(
                &mut message,
                ancillary_base,
                returned_ancillary,
            );
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty SOCK_SEQPACKET request",
            ));
        }
        if received as usize > control.len() {
            let _cleanup = scan_proven_rights(
                &mut message,
                ancillary_base,
                returned_ancillary,
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned an out-of-region control length",
            ));
        }
        let scan = scan_proven_rights(
            &mut message,
            ancillary_base,
            returned_ancillary,
        );
        if let Some(violation) = scan.violation {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                violation,
            ));
        }
        let credentials = scan.credentials.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet lacks mandatory SCM_CREDENTIALS",
            )
        })?;
        let (sender_pidfd, files) =
            scan.rights.into_packet_parts().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "packet lacks mandatory SCM_PIDFD",
                )
            })?;
        control.truncate(received as usize);
        Ok(ReceivedPacket {
            control,
            files,
            credentials,
            sender_pidfd,
        })
    }

    struct AncillaryScan {
        rights: ProvenRights,
        credentials: Option<libc::ucred>,
        violation: Option<&'static str>,
    }

    struct ProvenRights {
        exact_fds: Vec<RawFd>,
        sender_pidfds: Vec<RawFd>,
        unique: HashSet<RawFd>,
        armed: bool,
    }

    impl ProvenRights {
        fn new() -> Self {
            Self {
                exact_fds: Vec::new(),
                sender_pidfds: Vec::new(),
                unique: HashSet::new(),
                armed: true,
            }
        }

        fn record_exact(&mut self, fd: RawFd) -> bool {
            if fd < 0 || !self.unique.insert(fd) {
                return false;
            }
            self.exact_fds.push(fd);
            true
        }

        fn record_sender_pidfd(&mut self, fd: RawFd) -> bool {
            if fd < 0 || !self.unique.insert(fd) {
                return false;
            }
            self.sender_pidfds.push(fd);
            self.sender_pidfds.len() == 1
        }

        fn into_packet_parts(
            mut self,
        ) -> Option<(OwnedFd, Vec<File>)> {
            if self.sender_pidfds.len() != 1 {
                return None;
            }
            let sender = self.sender_pidfds.pop()?;
            self.armed = false;
            let files = self
                .exact_fds
                .drain(..)
                .map(|fd| {
                    // SAFETY: fd was read from a fully bounded SCM_RIGHTS
                    // payload and is transferred exactly once.
                    File::from(unsafe { OwnedFd::from_raw_fd(fd) })
                })
                .collect();
            // SAFETY: sender was delivered by one fully bounded SCM_PIDFD and
            // is transferred exactly once.
            let sender_pidfd =
                unsafe { OwnedFd::from_raw_fd(sender) };
            Some((sender_pidfd, files))
        }
    }

    impl Drop for ProvenRights {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            for fd in self.sender_pidfds.drain(..) {
                // SAFETY: each unique fd was proven to be delivered by a
                // complete SCM_PIDFD payload and has not been owned elsewhere.
                unsafe {
                    libc::close(fd);
                }
            }
            for fd in self.exact_fds.drain(..) {
                // SAFETY: each unique fd was proven to be delivered by a
                // complete SCM_RIGHTS payload and has not been owned elsewhere.
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }

    fn scan_proven_rights(
        message: &mut libc::msghdr,
        base: *mut u8,
        returned_length: usize,
    ) -> AncillaryScan {
        let mut scan = AncillaryScan {
            rights: ProvenRights::new(),
            credentials: None,
            violation: None,
        };
        if returned_length == 0 {
            return scan;
        }
        let region_start = base as usize;
        let Some(region_end) = region_start.checked_add(returned_length) else {
            scan.violation = Some("ancillary region address overflow");
            return scan;
        };
        if region_start % align_of::<libc::cmsghdr>() != 0 {
            scan.violation = Some("ancillary region is not cmsghdr aligned");
            return scan;
        }
        let minimum_length = match cmsg_len(0) {
            Ok(length) => length,
            Err(_) => {
                scan.violation =
                    Some("ancillary header length is unsupported");
                return scan;
            }
        };
        let header_size = size_of::<libc::cmsghdr>();
        let cmsg_alignment = align_of::<libc::size_t>();
        let mut offset = 0usize;
        while offset < returned_length {
            let remaining = returned_length - offset;
            if remaining < header_size {
                // SAFETY: this slice is inside the returned ancillary region.
                let trailing = unsafe {
                    std::slice::from_raw_parts(base.add(offset), remaining)
                };
                if trailing.iter().any(|byte| *byte != 0) {
                    scan.violation =
                        Some("nonzero bytes follow the last ancillary header");
                }
                break;
            }
            let Some(header_address) = region_start.checked_add(offset) else {
                scan.violation = Some("ancillary header address overflow");
                break;
            };
            if header_address % align_of::<libc::cmsghdr>() != 0
                || header_address >= region_end
            {
                scan.violation =
                    Some("ancillary header is unaligned or out of region");
                break;
            }
            let header = header_address as *mut libc::cmsghdr;
            // SAFETY: address alignment and a complete in-region header were
            // proven before this dereference.
            let current = unsafe { &*header };
            let Ok(current_length) = usize::try_from(current.cmsg_len) else {
                scan.violation =
                    Some("ancillary header length exceeds usize");
                break;
            };
            if current_length < minimum_length {
                scan.violation =
                    Some("ancillary header is shorter than CMSG_LEN(0)");
                break;
            }
            let Some(current_end_offset) =
                offset.checked_add(current_length)
            else {
                scan.violation = Some("ancillary header length overflow");
                break;
            };
            if current_end_offset > returned_length {
                scan.violation =
                    Some("ancillary header exceeds returned msg_controllen");
                break;
            }
            // SAFETY: current header was fully bounded before using CMSG_DATA.
            let data = unsafe { libc::CMSG_DATA(header).cast::<u8>() };
            let data_address = data as usize;
            let Some(expected_data_address) =
                header_address.checked_add(minimum_length)
            else {
                scan.violation = Some("ancillary data address overflow");
                break;
            };
            let Some(current_end_address) =
                region_start.checked_add(current_end_offset)
            else {
                scan.violation = Some("ancillary payload address overflow");
                break;
            };
            if data_address != expected_data_address
                || data_address > current_end_address
                || current_end_address > region_end
            {
                scan.violation =
                    Some("ancillary payload lies outside its header");
                break;
            }
            let payload_length = current_length - minimum_length;
            if current.cmsg_level != libc::SOL_SOCKET {
                scan.violation.get_or_insert(
                    "only exact SOL_SOCKET ancillary messages are accepted",
                );
            } else if current.cmsg_type == libc::SCM_RIGHTS {
                if payload_length == 0
                    || payload_length % size_of::<RawFd>() != 0
                    || data_address % align_of::<RawFd>() != 0
                {
                    scan.violation.get_or_insert(
                        "SCM_RIGHTS payload is empty, misaligned, or partial",
                    );
                } else {
                    let count = payload_length / size_of::<RawFd>();
                    let Some(total) = scan
                        .rights
                        .exact_fds
                        .len()
                        .checked_add(count)
                    else {
                        scan.violation.get_or_insert(
                            "SCM_RIGHTS descriptor count overflow",
                        );
                        break;
                    };
                    if total > MAX_RECEIVED_FDS {
                        scan.violation.get_or_insert(
                            "SCM_RIGHTS descriptor count exceeds fixed bound",
                        );
                    }
                    let fd_data = data.cast::<RawFd>();
                    for index in 0..count {
                        // SAFETY: data is RawFd-aligned and the complete
                        // payload is inside the validated current header.
                        let fd =
                            unsafe { std::ptr::read(fd_data.add(index)) };
                        if !scan.rights.record_exact(fd) {
                            scan.violation.get_or_insert(
                                "SCM_RIGHTS delivered a negative or duplicate descriptor",
                            );
                            continue;
                        }
                        if !received_fd_is_cloexec(fd) {
                            scan.violation.get_or_insert(
                                "SCM_RIGHTS descriptor is invalid or lacks CLOEXEC",
                            );
                        }
                    }
                }
            } else if current.cmsg_type == libc::SCM_CREDENTIALS {
                if payload_length != size_of::<libc::ucred>()
                    || data_address % align_of::<libc::ucred>() != 0
                    || scan.credentials.is_some()
                {
                    scan.violation.get_or_insert(
                        "SCM_CREDENTIALS is duplicate, misaligned, or has the wrong size",
                    );
                } else {
                    // SAFETY: data is ucred-aligned and exact-sized within the
                    // validated current header.
                    scan.credentials = Some(unsafe {
                        std::ptr::read(data.cast::<libc::ucred>())
                    });
                }
            } else if current.cmsg_type == SCM_PIDFD_TYPE {
                if payload_length == 0
                    || payload_length % size_of::<RawFd>() != 0
                    || data_address % align_of::<RawFd>() != 0
                {
                    scan.violation.get_or_insert(
                        "SCM_PIDFD is empty, misaligned, or partial",
                    );
                } else {
                    let count = payload_length / size_of::<RawFd>();
                    if count != 1 {
                        scan.violation.get_or_insert(
                            "SCM_PIDFD must contain exactly one descriptor",
                        );
                    }
                    let fd_data = data.cast::<RawFd>();
                    for index in 0..count {
                        // SAFETY: data is RawFd-aligned and the complete
                        // descriptor lies within the validated payload.
                        let fd = unsafe {
                            std::ptr::read(fd_data.add(index))
                        };
                        let first_sender =
                            scan.rights.record_sender_pidfd(fd);
                        if !first_sender {
                            scan.violation.get_or_insert(
                                "SCM_PIDFD delivered a negative, duplicate, or aliased descriptor",
                            );
                        }
                        if fd >= 0
                            && scan.rights.unique.contains(&fd)
                            && !received_fd_is_cloexec(fd)
                        {
                            scan.violation.get_or_insert(
                                "SCM_PIDFD descriptor is invalid or lacks CLOEXEC",
                            );
                        }
                    }
                }
            } else {
                scan.violation.get_or_insert(
                    "ancillary type is not SCM_RIGHTS, SCM_CREDENTIALS, or SCM_PIDFD",
                );
            }

            let Some(aligned_next) =
                align_up_checked(current_end_offset, cmsg_alignment)
            else {
                scan.violation =
                    Some("ancillary next-header alignment overflow");
                break;
            };
            // SAFETY: CMSG_NXTHDR is called only after the current cmsg_len and
            // region bounds have been completely validated.
            let helper_next =
                unsafe { libc::CMSG_NXTHDR(message, header) };
            let has_complete_next = aligned_next
                .checked_add(header_size)
                .map(|end| end <= returned_length)
                .unwrap_or(false);
            if has_complete_next {
                let expected = match region_start.checked_add(aligned_next) {
                    Some(address) => address,
                    None => {
                        scan.violation =
                            Some("ancillary next-header address overflow");
                        break;
                    }
                };
                if helper_next.is_null()
                    || helper_next as usize != expected
                    || expected % align_of::<libc::cmsghdr>() != 0
                {
                    scan.violation =
                        Some("CMSG_NXTHDR disagrees with bounded traversal");
                    break;
                }
                offset = aligned_next;
                continue;
            }
            if !helper_next.is_null() {
                scan.violation =
                    Some("CMSG_NXTHDR returned an out-of-region header");
            }
            if current_end_offset < returned_length {
                // SAFETY: current_end_offset and returned_length were bounded.
                let trailing = unsafe {
                    std::slice::from_raw_parts(
                        base.add(current_end_offset),
                        returned_length - current_end_offset,
                    )
                };
                if trailing.iter().any(|byte| *byte != 0) {
                    scan.violation.get_or_insert(
                        "nonzero bytes follow the final ancillary payload",
                    );
                }
            }
            break;
        }
        scan
    }

    fn align_up_checked(value: usize, alignment: usize) -> Option<usize> {
        let mask = alignment.checked_sub(1)?;
        value.checked_add(mask).map(|aligned| aligned & !mask)
    }

    fn send_packet(
        socket: RawFd,
        control: &[u8],
        files: &[RawFd],
    ) -> io::Result<()> {
        if control.is_empty()
            || control.len() > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
            || files.len() > MAX_RECEIVED_FDS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response packet exceeds the fixed transport bounds",
            ));
        }
        let mut iovec = libc::iovec {
            iov_base: control.as_ptr() as *mut libc::c_void,
            iov_len: control.len(),
        };
        // SAFETY: zeroed msghdr is initialized before sendmsg.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        let mut ancillary: Vec<libc::size_t> = Vec::new();
        if !files.is_empty() {
            let payload_length = files
                .len()
                .checked_mul(size_of::<RawFd>())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "response descriptor bound overflow",
                    )
                })?;
            ancillary =
                aligned_ancillary_buffer(cmsg_space(payload_length)?);
            message.msg_control = ancillary.as_mut_ptr().cast();
            set_msg_controllen(
                &mut message,
                cmsg_space(payload_length)?,
            )?;
            // SAFETY: ancillary contains enough CMSG_SPACE for this payload.
            let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            if header.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to construct SCM_RIGHTS header",
                ));
            }
            // SAFETY: header and payload lie within ancillary.
            let header_length = cmsg_len(payload_length)?;
            set_cmsg_len(header, header_length)?;
            unsafe {
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                std::ptr::copy_nonoverlapping(
                    files.as_ptr(),
                    libc::CMSG_DATA(header).cast::<RawFd>(),
                    files.len(),
                );
            }
            set_msg_controllen(
                &mut message,
                cmsg_space(payload_length)?,
            )?;
        }
        // SAFETY: msghdr and all referenced buffers remain valid for sendmsg.
        let sent =
            unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != control.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "SOCK_SEQPACKET response was not sent atomically",
            ));
        }
        Ok(())
    }

    fn cmsg_space(payload_length: usize) -> io::Result<usize> {
        let payload = u32::try_from(payload_length).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ancillary payload exceeds libc bound",
            )
        })?;
        // SAFETY: CMSG_SPACE is a pure size calculation.
        Ok(unsafe { libc::CMSG_SPACE(payload) as usize })
    }

    fn set_msg_controllen(
        message: &mut libc::msghdr,
        length: usize,
    ) -> io::Result<()> {
        message.msg_controllen = length.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ancillary region exceeds native msg_controllen",
            )
        })?;
        Ok(())
    }

    fn msg_controllen(message: &libc::msghdr) -> io::Result<usize> {
        usize::try_from(message.msg_controllen).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel msg_controllen exceeds usize",
            )
        })
    }

    fn set_cmsg_len(
        header: *mut libc::cmsghdr,
        length: usize,
    ) -> io::Result<()> {
        // SAFETY: callers pass a non-null header inside a CMSG_SPACE-bounded
        // ancillary buffer.
        unsafe {
            (*header).cmsg_len = length.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ancillary record exceeds native cmsg_len",
                )
            })?;
        }
        Ok(())
    }

    fn aligned_ancillary_buffer(byte_length: usize) -> Vec<libc::size_t> {
        let word = size_of::<libc::size_t>();
        let words = byte_length.saturating_add(word - 1) / word;
        vec![0; words]
    }

    fn cmsg_len(payload_length: usize) -> io::Result<usize> {
        let payload = u32::try_from(payload_length).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ancillary payload exceeds libc bound",
            )
        })?;
        // SAFETY: CMSG_LEN is a pure size calculation.
        Ok(unsafe { libc::CMSG_LEN(payload) as usize })
    }

    fn set_socket_deadline(
        socket: RawFd,
        timeout: Duration,
    ) -> io::Result<()> {
        let seconds = libc::time_t::try_from(timeout.as_secs())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket deadline seconds exceed platform range",
                )
            })?;
        let micros_value = if timeout.as_secs() == 0 {
            timeout.subsec_micros().max(1)
        } else {
            timeout.subsec_micros()
        };
        let micros = libc::suseconds_t::try_from(micros_value)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket deadline microseconds exceed platform range",
                )
            })?;
        let value = libc::timeval {
            tv_sec: seconds,
            tv_usec: micros,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: value is a valid timeval with the exact supplied length.
            let result = unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    option,
                    (&value as *const libc::timeval).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn probe_required_uapi() -> io::Result<()> {
        let mut clone_pidfd: RawFd = -1;
        let mut clone_args = Clone3ProbeArgs {
            flags: CLONE_PIDFD_FLAG,
            pidfd:
                (&mut clone_pidfd as *mut RawFd) as u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        // SAFETY: clone3 receives initialized arguments and atomically
        // returns the direct probe child pidfd.
        let clone_result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut clone_args as *mut Clone3ProbeArgs,
                size_of::<Clone3ProbeArgs>(),
            ) as libc::pid_t
        };
        if clone_result == 0 {
            unsafe { libc::_exit(0) };
        }
        if clone_result < 0 || clone_pidfd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "clone3(CLONE_PIDFD) is required",
            ));
        }
        // SAFETY: clone_pidfd was returned uniquely for clone_result.
        let clone_pidfd =
            unsafe { OwnedFd::from_raw_fd(clone_pidfd) };
        let mut status = 0;
        // SAFETY: clone_result is the exact direct child returned above.
        if unsafe { libc::waitpid(clone_result, &mut status, 0) }
            != clone_result
        {
            return Err(io::Error::last_os_error());
        }
        drop(clone_pidfd);
        let mut raw_pair = [-1; 2];
        // SAFETY: raw_pair provides space for exactly two returned fds.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                raw_pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful socketpair returned two unique descriptors.
        let receiver =
            unsafe { OwnedFd::from_raw_fd(raw_pair[0]) };
        // SAFETY: successful socketpair returned two unique descriptors.
        let sender =
            unsafe { OwnedFd::from_raw_fd(raw_pair[1]) };
        enable_per_packet_sender_identity(receiver.as_raw_fd())?;
        let peer_pidfd = open_peer_pidfd(receiver.as_raw_fd())?;
        ensure_pidfd_alive(&peer_pidfd)?;
        let _security_label =
            peer_security_label(receiver.as_raw_fd())?;
        let probe_byte = [0x56u8];
        // SAFETY: sender and probe_byte remain valid for this call.
        let sent = unsafe {
            libc::send(
                sender.as_raw_fd(),
                probe_byte.as_ptr().cast(),
                probe_byte.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != probe_byte.len() as isize {
            return Err(if sent < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "SOCK_SEQPACKET UAPI probe was not sent atomically",
                )
            });
        }
        let packet = receive_packet(receiver.as_raw_fd())?;
        let process_identity = prove_pidfds_same_process(
            &peer_pidfd,
            &packet.sender_pidfd,
            packet.credentials.pid,
        )?;
        // SAFETY: getpid/getuid/getgid have no preconditions.
        let current_pid = unsafe { libc::getpid() };
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        if packet.control != probe_byte
            || !packet.files.is_empty()
            || packet.credentials.pid != current_pid
            || packet.credentials.uid != current_uid
            || packet.credentials.gid != current_gid
            || process_identity.pid() != current_pid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "required SCM_CREDENTIALS, SCM_PIDFD, or SO_PEERPIDFD UAPI probe returned inconsistent identity",
            ));
        }
        probe_sealed_memfd_and_rights(
            receiver.as_raw_fd(),
            sender.as_raw_fd(),
            &peer_pidfd,
            current_pid,
        )?;
        let executable = File::open("/proc/self/exe")?;
        let metadata = executable.metadata()?;
        let _integrity_signal =
            executable_integrity_signal(&executable, &metadata)?;
        Ok(())
    }

    fn probe_sealed_memfd_and_rights(
        receiver: RawFd,
        sender: RawFd,
        peer_pidfd: &OwnedFd,
        expected_pid: libc::pid_t,
    ) -> io::Result<()> {
        let name = b"serverware-response-v2-uapi-probe\0";
        // SAFETY: name is NUL-terminated and memfd_create returns a new fd.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        } as RawFd;
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: memfd_create returned a new uniquely owned descriptor.
        let memfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let probe_byte = [0xa5u8];
        // SAFETY: memfd and probe_byte remain valid for this exact write.
        let written = unsafe {
            libc::pwrite(
                memfd.as_raw_fd(),
                probe_byte.as_ptr().cast(),
                probe_byte.len(),
                0,
            )
        };
        if written != probe_byte.len() as isize {
            return Err(if written < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sealed memfd UAPI probe write was not exact",
                )
            });
        }
        let required_seals = libc::F_SEAL_SEAL
            | libc::F_SEAL_SHRINK
            | libc::F_SEAL_GROW
            | libc::F_SEAL_WRITE;
        // SAFETY: memfd is live and was created with MFD_ALLOW_SEALING.
        if unsafe {
            libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, required_seals)
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let control = [0x52u8];
        send_packet(sender, &control, &[memfd.as_raw_fd()])?;
        let mut packet = receive_packet(receiver)?;
        let process_identity = prove_pidfds_same_process(
            peer_pidfd,
            &packet.sender_pidfd,
            expected_pid,
        )?;
        if packet.control != control
            || packet.credentials.pid != expected_pid
            || process_identity.pid() != expected_pid
            || packet.files.len() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sealed memfd plus SCM_RIGHTS UAPI probe returned inconsistent data",
            ));
        }
        let delivered = packet.files.pop().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SCM_RIGHTS UAPI probe did not deliver its memfd",
            )
        })?;
        // SAFETY: delivered is a live descriptor received through bounded
        // SCM_RIGHTS ancillary data.
        let observed_seals =
            unsafe { libc::fcntl(delivered.as_raw_fd(), libc::F_GET_SEALS) };
        let mut observed_byte = [0u8; 1];
        // SAFETY: delivered and observed_byte remain valid for this exact read.
        let read = unsafe {
            libc::pread(
                delivered.as_raw_fd(),
                observed_byte.as_mut_ptr().cast(),
                observed_byte.len(),
                0,
            )
        };
        if observed_seals < 0
            || observed_seals & required_seals != required_seals
            || read != observed_byte.len() as isize
            || observed_byte != probe_byte
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "delivered SCM_RIGHTS object is not the exact sealed memfd",
            ));
        }
        Ok(())
    }

    fn authenticate_peer(
        socket: RawFd,
        config: &RootOwnedResponseObservationV2Config,
        executable_cache: &ExecutableMeasurementCache,
    ) -> io::Result<AuthenticatedPeer> {
        let (pidfd, measurement) = capture_connection(socket, config.expected_client_uid(), executable_cache)?;
        if measurement.uid() == 0 || measurement.uid() != config.expected_client_uid() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "peer credentials are incomplete or privileged"));
        }
        let identity = config.authenticate_peer_identity(
            measurement.uid(), measurement.cgroup_sha256(),
            measurement.security_label_sha256(), measurement.executable_sha256(),
        ).map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied,
            "peer UID, cgroup, security label, or executable measurement does not match root-owned pins"))?;
        let peer = AuthenticatedPeer { identity, pidfd, measurement };
        ensure_peer_alive(&peer)?;
        Ok(peer)
    }

    fn enable_per_packet_sender_identity(socket: RawFd) -> io::Result<()> {
        set_socket_boolean(socket, libc::SO_PASSCRED)?;
        set_socket_boolean(socket, SO_PASSPIDFD_OPTION)
    }

    fn set_socket_boolean(
        socket: RawFd,
        option: libc::c_int,
    ) -> io::Result<()> {
        let enabled: libc::c_int = 1;
        // SAFETY: enabled is one c_int with its exact byte length.
        let result = unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                option,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn validate_packet_sender(
        socket: RawFd,
        peer: &AuthenticatedPeer,
        credentials: &libc::ucred,
        sender_pidfd: &OwnedFd,
        executable_cache: &ExecutableMeasurementCache,
    ) -> io::Result<()> {
        ensure_peer_alive(peer)?;
        ensure_pidfd_alive(sender_pidfd)?;
        if !peer.measurement.matches_credentials(credentials) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "per-packet credentials do not match the authenticated connection owner"));
        }
        let observed = capture_packet(socket, &peer.pidfd, sender_pidfd, &peer.measurement, executable_cache)?;
        ensure_peer_alive(peer)?;
        if observed != peer.measurement {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "packet sender changed kernel identity, cgroup, security label, or executable after authentication"));
        }
        Ok(())
    }

    fn ensure_peer_alive(peer: &AuthenticatedPeer) -> io::Result<()> {
        ensure_pidfd_alive(&peer.pidfd)
    }

    fn validate_socket_directory(
        socket_path: &Path,
        expected_gid: u32,
    ) -> io::Result<()> {
        let parent = socket_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path has no parent directory",
            )
        })?;
        let mut walked = PathBuf::from("/");
        for component in parent.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(name) => walked.push(name),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "socket directory path is not canonical",
                    ));
                }
            }
            let ancestor = fs::symlink_metadata(&walked)?;
            if !ancestor.file_type().is_dir()
                || ancestor.file_type().is_symlink()
                || ancestor.uid() != 0
                || ancestor.mode() & SOCKET_DIRECTORY_MODE_MASK != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "every socket path directory must be root-owned, non-symlink, and non-writable by group or world",
                ));
            }
        }
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != expected_gid
            || metadata.mode() & SOCKET_DIRECTORY_MODE_MASK != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket directory must be a root-owned, non-symlink directory with the configured group and no group/world write bits",
            ));
        }
        Ok(())
    }

    const SOCKET_OWNER_API_VERSION: &str =
        "serverware.responseObservationV2SocketOwner/v1";

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SocketOwnerRecord {
        api_version: String,
        pid: i32,
        process_start_time: u64,
        boot_id: String,
        socket_device: u64,
        socket_inode: u64,
    }

    struct SocketOwnershipLease {
        _lock: File,
        owner_path: PathBuf,
        parent: PathBuf,
        record: SocketOwnerRecord,
        canonical_record: Vec<u8>,
    }

    impl SocketOwnershipLease {
        fn acquire(
            socket_path: &Path,
            expected_gid: u32,
        ) -> io::Result<Self> {
            let parent = socket_path
                .parent()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "custody socket has no parent",
                    )
                })?
                .to_owned();
            let file_name = socket_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "custody socket filename is not canonical UTF-8",
                    )
                })?;
            let lock_path =
                parent.join(format!(".{file_name}.recovery.lock"));
            let owner_path =
                parent.join(format!(".{file_name}.owner.json"));
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&lock_path)?;
            let lock_metadata = lock.metadata()?;
            if !lock_metadata.is_file()
                || lock_metadata.uid() != 0
                || lock_metadata.mode() & 0o777 != 0o600
                || lock_metadata.nlink() != 1
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socket recovery lock is not a root-owned mode-0600 single-link regular file",
                ));
            }
            if unsafe {
                libc::flock(
                    lock.as_raw_fd(),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another custody process owns socket recovery",
                ));
            }
            let prior = read_socket_owner_record(&owner_path)?;
            if let Ok(metadata) = fs::symlink_metadata(socket_path) {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != 0
                    || metadata.gid() != expected_gid
                    || metadata.mode() & 0o777 != SOCKET_MODE
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing custody socket is not the expected root-owned socket inode",
                    ));
                }
                prove_socket_peer_absent(socket_path)?;
                let prior = prior.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "existing custody socket lacks an authenticated owner record",
                    )
                })?;
                let pending_bind =
                    prior.socket_device == 0
                        && prior.socket_inode == 0;
                if !pending_bind
                    && (prior.socket_device != metadata.dev()
                        || prior.socket_inode != metadata.ino())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "stale custody socket inode does not match its owner record",
                    ));
                }
                prove_socket_owner_dead(prior)?;
                fs::remove_file(socket_path)?;
                File::open(&parent)?.sync_all()?;
            } else if let Some(prior) = prior.as_ref() {
                prove_socket_owner_dead(prior)?;
            }
            // SAFETY: getpid returns the exact current custody process.
            let pid = unsafe { libc::getpid() };
            let proc_directory =
                open_proc_task_directory(pid)?;
            let process_start_time =
                read_proc_start_time(&proc_directory, pid)?;
            let boot_id = fs::read_to_string(
                "/proc/sys/kernel/random/boot_id",
            )?
            .trim()
            .to_owned();
            if boot_id.is_empty()
                || !boot_id.bytes().all(|byte| {
                    byte.is_ascii_hexdigit() || byte == b'-'
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kernel boot ID is invalid",
                ));
            }
            let record = SocketOwnerRecord {
                api_version:
                    SOCKET_OWNER_API_VERSION.to_owned(),
                pid,
                process_start_time,
                boot_id,
                socket_device: 0,
                socket_inode: 0,
            };
            let canonical_record =
                write_socket_owner_record(
                    &owner_path,
                    &parent,
                    &record,
                )?;
            Ok(Self {
                _lock: lock,
                owner_path,
                parent,
                record,
                canonical_record,
            })
        }

        fn bind_socket_identity(
            &mut self,
            identity: SocketPathIdentity,
        ) -> io::Result<()> {
            self.record.socket_device = identity.device;
            self.record.socket_inode = identity.inode;
            self.canonical_record = write_socket_owner_record(
                &self.owner_path,
                &self.parent,
                &self.record,
            )?;
            Ok(())
        }
    }

    impl Drop for SocketOwnershipLease {
        fn drop(&mut self) {
            if fs::read(&self.owner_path)
                .map(|bytes| bytes == self.canonical_record)
                .unwrap_or(false)
            {
                let _ = fs::remove_file(&self.owner_path);
                let _ = File::open(&self.parent)
                    .and_then(|directory| directory.sync_all());
            }
        }
    }

    fn read_socket_owner_record(
        owner_path: &Path,
    ) -> io::Result<Option<SocketOwnerRecord>> {
        let metadata = match fs::symlink_metadata(owner_path) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len()
                > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket owner record is not a bounded root-owned mode-0600 single-link file",
            ));
        }
        let bytes = fs::read(owner_path)?;
        let record: SocketOwnerRecord =
            decode_canonical_json(&bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "socket owner record is not canonical closed JSON",
                )
            })?;
        if record.api_version != SOCKET_OWNER_API_VERSION
            || record.pid <= 1
            || record.process_start_time == 0
            || record.boot_id.is_empty()
            || !record.boot_id.bytes().all(|byte| {
                byte.is_ascii_hexdigit() || byte == b'-'
            })
            || (record.socket_device == 0)
                != (record.socket_inode == 0)
            || canonical_json_bytes(&record)
                .map(|canonical| canonical != bytes)
                .unwrap_or(true)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socket owner record has invalid identity fields",
            ));
        }
        Ok(Some(record))
    }

    fn write_socket_owner_record(
        owner_path: &Path,
        parent: &Path,
        record: &SocketOwnerRecord,
    ) -> io::Result<Vec<u8>> {
        let bytes = canonical_json_bytes(record).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "socket owner record cannot be canonicalized",
            )
        })?;
        let temporary = owner_path.with_extension("pending");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, owner_path)?;
        File::open(parent)?.sync_all()?;
        Ok(bytes)
    }

    fn prove_socket_peer_absent(
        socket_path: &Path,
    ) -> io::Result<()> {
        let path_bytes = socket_path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un =
            unsafe { zeroed() };
        address.sun_family =
            libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address
            .sun_path
            .iter_mut()
            .zip(path_bytes.iter().copied())
        {
            *destination = source as libc::c_char;
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let address_length = libc::socklen_t::try_from(
            size_of::<libc::sa_family_t>()
                + path_bytes.len()
                + 1,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "existing socket address length overflowed",
            )
        })?;
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_length,
            )
        };
        if result == 0 {
            let credentials =
                socket_peer_credentials(socket.as_raw_fd())?;
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "custody socket is live under pid={} uid={}",
                    credentials.pid, credentials.uid
                ),
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ECONNREFUSED) {
            return Err(error);
        }
        Ok(())
    }

    fn prove_socket_owner_dead(
        owner: &SocketOwnerRecord,
    ) -> io::Result<()> {
        let current_boot_id = fs::read_to_string(
            "/proc/sys/kernel/random/boot_id",
        )?
        .trim()
        .to_owned();
        if current_boot_id.is_empty()
            || !current_boot_id.bytes().all(|byte| {
                byte.is_ascii_hexdigit() || byte == b'-'
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel boot ID is invalid",
            ));
        }
        if current_boot_id != owner.boot_id {
            return Ok(());
        }
        let raw = unsafe {
            libc::syscall(
                libc::SYS_pidfd_open,
                owner.pid,
                0,
            ) as libc::c_int
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error);
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let proc_directory =
            match open_proc_task_directory(owner.pid) {
                Ok(directory) => directory,
                Err(error)
                    if error.raw_os_error()
                        == Some(libc::ENOENT) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
        if read_proc_start_time(&proc_directory, owner.pid)?
            != owner.process_start_time
        {
            return Ok(());
        }
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pollfd, 1, 0) } == 1
            && pollfd.revents
                & (libc::POLLIN
                    | libc::POLLHUP
                    | libc::POLLERR)
                != 0
        {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "prior custody socket owner is still alive",
        ))
    }

    struct SeqPacketListener {
        fd: OwnedFd,
        path: PathBuf,
        identity: SocketPathIdentity,
        guest: Option<super::super::guest_listener::Retention>,
    }

    impl SeqPacketListener {
        fn activate_guest(config: &RootOwnedResponseObservationV2Config) -> io::Result<Self> {
            let (fd, retention) = super::super::guest_listener::activate(config)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
            let identity = SocketPathIdentity::capture(config.socket_path())?;
            Ok(Self { fd, path:config.socket_path().to_owned(), identity, guest:Some(retention) })
        }
        fn bind(path: &Path, expected_gid: u32) -> io::Result<Self> {
            let path_bytes = path.as_os_str().as_bytes();
            // SAFETY: zeroed sockaddr_un is initialized before bind.
            let mut address: libc::sockaddr_un = unsafe { zeroed() };
            address.sun_family = libc::AF_UNIX as libc::sa_family_t;
            if path_bytes.is_empty()
                || path_bytes.len() >= address.sun_path.len()
                || path_bytes.contains(&0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket path exceeds sockaddr_un or contains NUL",
                ));
            }
            for (destination, source) in address
                .sun_path
                .iter_mut()
                .zip(path_bytes.iter().copied())
            {
                *destination = source as libc::c_char;
            }
            // SAFETY: socket arguments request one close-on-exec seqpacket FD.
            let raw = unsafe {
                libc::socket(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: raw is newly returned and uniquely owned.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let address_length = (size_of::<libc::sa_family_t>()
                + path_bytes.len()
                + 1) as libc::socklen_t;
            // SAFETY: address is initialized for address_length bytes.
            let mut path_guard = SocketPathGuard::new(path);
            let bind_result = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address_length,
                )
            };
            if bind_result != 0 {
                return Err(io::Error::last_os_error());
            }
            path_guard.arm();
            let identity = SocketPathIdentity::capture(path)?;
            path_guard.set_identity(identity);
            let c_path = CString::new(path_bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket path contains NUL",
                )
            })?;
            // SAFETY: path identifies the socket just created by this process.
            if unsafe {
                libc::chown(
                    c_path.as_ptr(),
                    0,
                    expected_gid as libc::gid_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(SOCKET_MODE),
            )?;
            let socket_metadata = fs::symlink_metadata(path)?;
            if !socket_metadata.file_type().is_socket()
                || socket_metadata.uid() != 0
                || socket_metadata.gid() != expected_gid
                || socket_metadata.mode() & 0o777 != SOCKET_MODE
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bound socket ownership, group, type, or mode does not match root-owned configuration",
                ));
            }
            // SAFETY: fd is a bound SOCK_SEQPACKET socket.
            if unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) } != 0 {
                return Err(io::Error::last_os_error());
            }
            path_guard.disarm();
            Ok(Self {
                fd,
                path: path.to_owned(),
                identity,
                guest: None,
            })
        }

        fn accept(&self) -> io::Result<OwnedFd> {
            if let Some(owner) = &self.guest { owner.check()
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?; }
            // SAFETY: listener fd is valid; peer address is not required.
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: accept4 returned a new uniquely owned descriptor.
            let accepted = unsafe { OwnedFd::from_raw_fd(raw) };
            if let Some(owner) = &self.guest { owner.check()
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?; }
            Ok(accepted)
        }
    }

    impl Drop for SeqPacketListener {
        fn drop(&mut self) {
            if self.guest.is_none() { remove_socket_if_same(&self.path, self.identity); }
        }
    }

    #[derive(Clone, Copy)]
    struct SocketPathIdentity {
        device: u64,
        inode: u64,
    }

    impl SocketPathIdentity {
        fn capture(path: &Path) -> io::Result<Self> {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bound custody path is not a socket",
                ));
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        fn matches(self, metadata: &fs::Metadata) -> bool {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }
    }

    fn remove_socket_if_same(path: &Path, identity: SocketPathIdentity) {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if identity.matches(&metadata) {
                let _ = fs::remove_file(path);
            }
        }
    }

    struct SocketPathGuard {
        path: PathBuf,
        identity: Option<SocketPathIdentity>,
        armed: bool,
    }

    impl SocketPathGuard {
        fn new(path: &Path) -> Self {
            Self {
                path: path.to_owned(),
                identity: None,
                armed: false,
            }
        }

        fn arm(&mut self) {
            self.armed = true;
        }

        fn set_identity(&mut self, identity: SocketPathIdentity) {
            self.identity = Some(identity);
        }

        fn disarm(&mut self) {
            self.armed = false;
        }
    }

    impl Drop for SocketPathGuard {
        fn drop(&mut self) {
            if self.armed {
                if let Some(identity) = self.identity {
                    remove_socket_if_same(&self.path, identity);
                } else if let Ok(metadata) =
                    fs::symlink_metadata(&self.path)
                {
                    if metadata.file_type().is_socket() {
                        let _ = fs::remove_file(&self.path);
                    }
                }
            }
        }
    }
}
