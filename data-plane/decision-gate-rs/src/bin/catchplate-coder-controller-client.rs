#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "{}: Linux pidfd/memfd/SOCK_SEQPACKET support is required",
        "catchplate-coder-controller-v11"
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    match linux::run() {
        Ok(linux::ClientExit::Success) => {}
        Ok(linux::ClientExit::Failure(detail)) => {
            eprintln!(
                "{}: signed controller Failure: {detail}",
                coder_controller_v11::PROTOCOL_NAME
            );
            std::process::exit(2);
        }
        Ok(linux::ClientExit::Unknown(detail)) => {
            eprintln!(
                "{}: signed controller Unknown: {detail}",
                coder_controller_v11::PROTOCOL_NAME
            );
            std::process::exit(3);
        }
        Err(error) => {
            eprintln!("{}: {error}", coder_controller_v11::PROTOCOL_NAME);
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::coder_controller_v11::{
        build_signed_request_from_template_v11, ed25519_spki_der_sha256_v11,
        format_rfc3339_seconds_v11, now_unix_ms, peer_binding, sha256,
        sha256_exact_reader, AcceptanceTicketRequestV11, AcceptanceTicketV11,
        CanonicalControllerReceiptV11, CanonicalFrameKindV11,
        CanonicalPreallocationFrameV11, ControllerError, Digest, FrameKind,
        HelloEnvelope, HelloResponse, Lane, Plan, PreallocationFrame, Result,
        TrustedPlanManifestV11, ACCEPTANCE_TICKET_BYTES,
        ACCEPTANCE_TICKET_REQUEST_BYTES, DEFAULT_SOCKET_PATH,
        FINAL_VERDICT_PUBLIC_KEY_PATH, FIXED_FRAME_BYTES,
        MAX_DEADLINE_FUTURE_MS, RECEIPT_MAX_BYTES,
        RECEIPT_PUBLIC_KEY_PATH, REQUESTER_PUBLIC_KEY_PATH,
        REQUESTER_SIGNING_KEY_PATH, REQUEST_MAX_BYTES,
        REQUEST_TEMPLATE_DIRECTORY, TRUSTED_PLAN_MANIFEST_BYTES,
        TRUSTED_PLAN_MANIFEST_PATH,
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const SCM_PIDFD_VALUE: libc::c_int = 0x04;
    const SO_PASSPIDFD_VALUE: libc::c_int = 76;
    const CONTROL_BYTES: usize = 256;
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
    const FS_IMMUTABLE_FL: libc::c_uint = 0x00000010;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const DEADLINE_ENV: &str = "CATCHPLATE_CONTROLLER_DEADLINE_MS";
    const BUILD_DEADLINE_ENV: &str = "CATCHPLATE_CONTROLLER_BUILD_DEADLINE_MS";
    const UNIT_DEADLINE_ENV: &str = "CATCHPLATE_CONTROLLER_UNIT_DEADLINE_MS";
    const INTEGRATION_DEADLINE_ENV: &str =
        "CATCHPLATE_CONTROLLER_INTEGRATION_DEADLINE_MS";
    const E2E_DEADLINE_ENV: &str = "CATCHPLATE_CONTROLLER_E2E_DEADLINE_MS";
    const ATTESTATION_DEADLINE_ENV: &str =
        "CATCHPLATE_CONTROLLER_ATTESTATION_DEADLINE_MS";

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C, align(16))]
    struct AlignedControl([u8; CONTROL_BYTES]);

    pub(super) enum ClientExit {
        Success,
        Failure(String),
        Unknown(String),
    }

    #[derive(Clone, Copy)]
    struct TransportDeadline {
        monotonic: Instant,
        unix_ms: u64,
    }

    impl TransportDeadline {
        fn new(duration: Duration) -> Result<Self> {
            let duration_ms: u64 = duration
                .as_millis()
                .try_into()
                .map_err(|_| ControllerError::Invalid("deadline duration exceeds u64"))?;
            if duration_ms == 0 || duration_ms > MAX_DEADLINE_FUTURE_MS {
                return Err(ControllerError::Invalid(
                    "client deadline is outside the v11 server bound",
                ));
            }
            let monotonic = Instant::now()
                .checked_add(duration)
                .ok_or(ControllerError::Invalid("monotonic deadline overflow"))?;
            let unix_ms = now_unix_ms()?
                .checked_add(duration_ms)
                .ok_or(ControllerError::Invalid("wall deadline overflow"))?;
            Ok(Self {
                monotonic,
                unix_ms,
            })
        }

        fn ensure_live(&self) -> Result<()> {
            if Instant::now() >= self.monotonic {
                return Err(ControllerError::Rejected("transport deadline expired"));
            }
            Ok(())
        }
    }

    struct ReceivedPacket {
        frame: [u8; FIXED_FRAME_BYTES],
        memfd: OwnedFd,
        pidfd: OwnedFd,
        peer: libc::ucred,
        pidfd_identity: String,
    }

    pub(super) fn run() -> Result<ClientExit> {
        let arguments: Vec<String> = std::env::args().collect();
        if arguments.len() == 2 && arguments[1] == "hello" {
            return run_hello();
        }
        if arguments.len() != 4 || arguments[1] != "submit-fixed-v11" {
            return Err(ControllerError::Invalid(
                "usage: catchplate-coder-controller-client hello | submit-fixed-v11 --operation=<build|runNoBuild> --plan=<fixed-v11-plan>",
            ));
        }
        let lane = Lane::parse_frozen_flags(&arguments[2], &arguments[3])?;
        let timeout = lane_timeout(lane)?;
        let timeout_ms: u64 = timeout
            .as_millis()
            .try_into()
            .map_err(|_| ControllerError::Invalid("lane timeout exceeds u64"))?;
        let deadline = TransportDeadline::new(timeout)?;
        let receipt_key = load_immutable_receipt_public_key()?;
        let final_verdict_key = load_immutable_final_verdict_public_key()?;
        let trusted_plan_manifest = load_immutable_trusted_plan_manifest()?;
        let requester_signing_key = load_protected_requester_signing_key()?;
        let requester_public_key = load_immutable_requester_public_key()?;
        if requester_signing_key.verifying_key().as_bytes()
            != requester_public_key.as_bytes()
        {
            return Err(ControllerError::Rejected(
                "protected requester key does not match its immutable public trust anchor",
            ));
        }
        let local_pidfd = pidfd_open(unsafe { libc::getpid() })?;
        let local_identity = pidfd_identity(local_pidfd.as_raw_fd())?;
        let local_binding = peer_binding(
            unsafe { libc::getpid() } as u32,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &local_identity,
        );
        let raw_nonce = random_digest()?;
        let ticket_request = AcceptanceTicketRequestV11::new(
            lane,
            timeout_ms,
            raw_nonce,
            local_binding,
        )?;
        let ticket = request_acceptance_ticket(
            &ticket_request,
            &receipt_key,
        )?;
        if ticket.config_sha256 != trusted_plan_manifest.config_sha256 {
            return Err(ControllerError::Rejected(
                "acceptance ticket does not bind the pinned controller config",
            ));
        }
        let template = load_immutable_request_template(lane)?;
        let built = build_signed_request_from_template_v11(
            &template,
            lane,
            raw_nonce,
            &format_rfc3339_seconds_v11(ticket.accepted_at_unix_ms)?,
            &format_rfc3339_seconds_v11(ticket.frame_deadline_unix_ms)?,
            &format_rfc3339_seconds_v11(ticket.request_deadline_unix_ms)?,
            &requester_signing_key,
            ed25519_spki_der_sha256_v11(&requester_public_key),
        )?;
        if built.request.plan_configuration_sha256
                != trusted_plan_manifest.config_sha256
            || built.request.lane != lane
            || built.request.raw_nonce != raw_nonce
        {
            return Err(ControllerError::Rejected(
                "canonical request template differs from the pinned lane or config",
            ));
        }
        let request_bytes = built.request.exact_bytes();
        let request_frame_bytes = built.frame.encode()?;
        let socket = connect_seqpacket(Path::new(DEFAULT_SOCKET_PATH), &deadline)?;
        let payload = create_sealed_memfd(
            "catchplate-controller-request-v11",
            request_bytes,
        )?;
        send_frame_with_memfd(
            socket.as_raw_fd(),
            &request_frame_bytes,
            payload.as_raw_fd(),
            &deadline,
        )?;
        let packet = receive_frame(socket.as_raw_fd(), &deadline)?;
        verify_pidfd_peer(&packet)?;
        if packet.peer.uid != 0 {
            return Err(ControllerError::Rejected("controller daemon is not root"));
        }
        let remote_binding = peer_binding(
            packet.peer.pid as u32,
            packet.peer.uid,
            packet.peer.gid,
            &packet.pidfd_identity,
        );
        if remote_binding == [0; 32] {
            return Err(ControllerError::Rejected(
                "controller peer binding is empty",
            ));
        }
        let response = CanonicalPreallocationFrameV11::decode(&packet.frame)?;
        if response.kind != CanonicalFrameKindV11::Receipt {
            return Err(ControllerError::Rejected(
                "production response is not a canonical v11 receipt frame",
            ));
        }
        response.verify_receive_deadline(now_unix_ms()?)?;
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            response.declared_canonical_bytes,
        )?;
        let bytes = read_memfd_bounded(
            packet.memfd,
            response.declared_canonical_bytes,
            RECEIPT_MAX_BYTES,
        )?;
        deadline.ensure_live()?;
        let receipt = CanonicalControllerReceiptV11::parse_and_verify(
            bytes,
            &response,
            &receipt_key,
            ed25519_spki_der_sha256_v11(&receipt_key),
            &final_verdict_key,
            ed25519_spki_der_sha256_v11(&final_verdict_key),
            built.request.request_envelope_sha256,
            sha256(&raw_nonce),
        )?;
        deadline.ensure_live()?;
        let detail = format!(
            "variant={}; receiptEnvelopeSha256={}",
            receipt.receipt_variant,
            super::coder_controller_v11::digest_hex(
                &receipt.receipt_envelope_sha256,
            ),
        );
        match receipt.verdict.as_str() {
            "PASS" => {
                println!("controller canonical receipt verified: PASS; {detail}");
                Ok(ClientExit::Success)
            }
            "FAIL" | "REJECTED" => Ok(ClientExit::Failure(detail)),
            "UNKNOWN" => Ok(ClientExit::Unknown(detail)),
            _ => Err(ControllerError::Rejected(
                "canonical receipt carries an unknown verdict",
            )),
        }
    }

    fn run_hello() -> Result<ClientExit> {
        let deadline = TransportDeadline::new(Duration::from_secs(5))?;
        let raw_nonce = random_digest()?;
        let hello = HelloEnvelope::new(raw_nonce);
        let bytes = hello.encode();
        let local_pidfd = pidfd_open(unsafe { libc::getpid() })?;
        let local_identity = pidfd_identity(local_pidfd.as_raw_fd())?;
        let binding = peer_binding(
            unsafe { libc::getpid() } as u32,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            &local_identity,
        );
        let frame = PreallocationFrame::new(
            FrameKind::Hello,
            None,
            bytes.len() as u64,
            &bytes,
            &raw_nonce,
            binding,
            hello.request_id,
            deadline.unix_ms,
        )?;
        let socket = connect_seqpacket(Path::new(DEFAULT_SOCKET_PATH), &deadline)?;
        let memfd = create_sealed_memfd("catchplate-controller-hello-v11", &bytes)?;
        send_frame_with_memfd(
            socket.as_raw_fd(),
            &frame.encode(),
            memfd.as_raw_fd(),
            &deadline,
        )?;
        let packet = receive_frame(socket.as_raw_fd(), &deadline)?;
        require_root_controller_packet(&packet)?;
        let remote_binding = peer_binding(
            packet.peer.pid as u32,
            packet.peer.uid,
            packet.peer.gid,
            &packet.pidfd_identity,
        );
        let response = PreallocationFrame::decode(&packet.frame)?;
        response.verify_before_body(&remote_binding, now_unix_ms()?)?;
        if response.kind != FrameKind::Hello
            || response.request_id != frame.request_id
            || response.nonce_sha256 != frame.nonce_sha256
        {
            return Err(ControllerError::Rejected(
                "hello response lost its request binding",
            ));
        }
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            response.declared_envelope_bytes,
        )?;
        let response_bytes = read_memfd_bounded(
            packet.memfd,
            response.declared_envelope_bytes,
            RECEIPT_MAX_BYTES,
        )?;
        let response_envelope = HelloResponse::decode(&response_bytes)?;
        response.verify_raw_nonce(&response_envelope.raw_nonce)?;
        println!("{}", response_envelope.message);
        Ok(ClientExit::Success)
    }

    fn request_acceptance_ticket(
        request: &AcceptanceTicketRequestV11,
        receipt_key: &VerifyingKey,
    ) -> Result<AcceptanceTicketV11> {
        let deadline = TransportDeadline::new(Duration::from_secs(5))?;
        let bytes = request.encode();
        let frame = PreallocationFrame::new(
            FrameKind::Hello,
            None,
            ACCEPTANCE_TICKET_REQUEST_BYTES as u64,
            &bytes,
            &request.raw_nonce,
            request.peer_binding_sha256,
            request.request_sha256,
            deadline.unix_ms,
        )?;
        let socket = connect_seqpacket(Path::new(DEFAULT_SOCKET_PATH), &deadline)?;
        let memfd = create_sealed_memfd(
            "catchplate-controller-acceptance-v11",
            &bytes,
        )?;
        send_frame_with_memfd(
            socket.as_raw_fd(),
            &frame.encode(),
            memfd.as_raw_fd(),
            &deadline,
        )?;
        let packet = receive_frame(socket.as_raw_fd(), &deadline)?;
        require_root_controller_packet(&packet)?;
        let remote_binding = peer_binding(
            packet.peer.pid as u32,
            packet.peer.uid,
            packet.peer.gid,
            &packet.pidfd_identity,
        );
        let response = PreallocationFrame::decode(&packet.frame)?;
        response.verify_before_body(&remote_binding, now_unix_ms()?)?;
        if response.kind != FrameKind::Hello
            || response.request_id != request.request_sha256
            || response.nonce_sha256 != sha256(&request.raw_nonce)
            || response.declared_envelope_bytes
                != ACCEPTANCE_TICKET_BYTES as u64
        {
            return Err(ControllerError::Rejected(
                "acceptance ticket response lost its request binding",
            ));
        }
        verify_sealed_memfd(
            packet.memfd.as_raw_fd(),
            response.declared_envelope_bytes,
        )?;
        let ticket_bytes = read_memfd_bounded(
            packet.memfd,
            response.declared_envelope_bytes,
            ACCEPTANCE_TICKET_BYTES as u64,
        )?;
        AcceptanceTicketV11::decode_and_verify(
            &ticket_bytes,
            receipt_key,
            request,
        )
    }

    fn require_root_controller_packet(packet: &ReceivedPacket) -> Result<()> {
        verify_pidfd_peer(packet)?;
        if packet.peer.uid != 0 {
            return Err(ControllerError::Rejected(
                "controller daemon is not root",
            ));
        }
        Ok(())
    }

    fn lane_timeout(lane: Lane) -> Result<Duration> {
        let (variable, default_ms) = match lane.plan {
            Plan::Build => (BUILD_DEADLINE_ENV, 14 * 60 * 1000),
            Plan::UnitNoBuild => (UNIT_DEADLINE_ENV, 2 * 60 * 1000),
            Plan::IntegrationNoBuild => {
                (INTEGRATION_DEADLINE_ENV, 5 * 60 * 1000)
            }
            Plan::E2eNoBuild => (E2E_DEADLINE_ENV, 8 * 60 * 1000),
            Plan::AttestationNoBuild => {
                (ATTESTATION_DEADLINE_ENV, 5 * 60 * 1000)
            }
        };
        let configured =
            std::env::var_os(DEADLINE_ENV).or_else(|| std::env::var_os(variable));
        let milliseconds = match configured {
            None => default_ms,
            Some(value) => value
                .to_str()
                .ok_or(ControllerError::Invalid(
                    "lane deadline environment value is not UTF-8",
                ))?
                .parse::<u64>()
                .map_err(|_| {
                    ControllerError::Invalid(
                        "lane deadline environment value is not decimal milliseconds",
                    )
                })?,
        };
        if milliseconds == 0 || milliseconds > MAX_DEADLINE_FUTURE_MS {
            return Err(ControllerError::Invalid(
                "lane deadline exceeds the authoritative v11 server bound",
            ));
        }
        Ok(Duration::from_millis(milliseconds))
    }

    fn load_immutable_request_template(lane: Lane) -> Result<Vec<u8>> {
        let path = PathBuf::from(REQUEST_TEMPLATE_DIRECTORY)
            .join(format!("{}.request.json", lane.plan.as_label()));
        read_root_immutable_file(
            &path,
            1,
            REQUEST_MAX_BYTES,
            "canonical request template",
        )
    }

    fn load_immutable_final_verdict_public_key() -> Result<VerifyingKey> {
        let bytes = read_root_immutable_file(
            Path::new(FINAL_VERDICT_PUBLIC_KEY_PATH),
            32,
            32,
            "final-verdict public key",
        )?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            ControllerError::Invalid(
                "final-verdict public key has the wrong length",
            )
        })?;
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            ControllerError::Rejected(
                "final-verdict public key is not canonical Ed25519",
            )
        })
    }

    fn read_root_immutable_file(
        path: &Path,
        minimum: u64,
        maximum: u64,
        label: &'static str,
    ) -> Result<Vec<u8>> {
        if !path.is_absolute()
            || minimum == 0
            || maximum < minimum
            || maximum > usize::MAX as u64
        {
            return Err(ControllerError::Invalid(
                "immutable file bound or path is invalid",
            ));
        }
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ControllerError::Invalid("immutable path contains NUL"))?;
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
        let before = fstat_exact(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_nlink != 1
            || before.st_size < minimum as i64
            || before.st_size > maximum as i64
        {
            return Err(ControllerError::InvalidOwned(format!(
                "{label} is not one bounded root-owned nonwritable regular file",
            )));
        }
        let mut filesystem_flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut filesystem_flags,
            )
        } != 0
            || filesystem_flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::InvalidOwned(format!(
                "{label} lacks the filesystem immutable flag",
            )));
        }
        let mut bytes = Vec::with_capacity(before.st_size as usize);
        (&mut file).take(maximum).read_to_end(&mut bytes)?;
        if bytes.len() as i64 != before.st_size {
            return Err(ControllerError::InvalidOwned(format!(
                "{label} is truncated",
            )));
        }
        let after = fstat_exact(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ControllerError::InvalidOwned(format!(
                "{label} identity changed while its FD was read",
            )));
        }
        Ok(bytes)
    }

    fn load_immutable_trusted_plan_manifest() -> Result<TrustedPlanManifestV11> {
        let path = CString::new(TRUSTED_PLAN_MANIFEST_PATH)
            .map_err(|_| ControllerError::Invalid("trusted plan manifest path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = fstat_exact(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_nlink != 1
            || before.st_size != TRUSTED_PLAN_MANIFEST_BYTES as i64
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest is not one root-owned immutable fixed-size regular file",
            ));
        }
        let mut filesystem_flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut filesystem_flags,
            )
        } != 0
            || filesystem_flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest lacks the filesystem immutable flag",
            ));
        }
        let mut bytes = [0u8; TRUSTED_PLAN_MANIFEST_BYTES];
        file.read_exact(&mut bytes)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(ControllerError::Rejected(
                "trusted plan manifest exceeds its fixed length",
            ));
        }
        let after = fstat_exact(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest identity changed while reading its opened FD",
            ));
        }
        TrustedPlanManifestV11::decode(&bytes)
    }

    fn load_immutable_receipt_public_key() -> Result<VerifyingKey> {
        let path = CString::new(RECEIPT_PUBLIC_KEY_PATH)
            .map_err(|_| ControllerError::Invalid("receipt key path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = fstat_exact(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_nlink != 1
            || before.st_size != 32
        {
            return Err(ControllerError::Rejected(
                "receipt key is not one root-owned nonwritable 32-byte regular file",
            ));
        }
        let mut filesystem_flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut filesystem_flags,
            )
        } != 0
            || filesystem_flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "receipt key lacks the filesystem immutable flag",
            ));
        }
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(ControllerError::Rejected(
                "receipt key exceeds its canonical raw length",
            ));
        }
        let after = fstat_exact(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ControllerError::Rejected(
                "receipt key identity changed while reading its opened FD",
            ));
        }
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            ControllerError::Rejected(
                "receipt key is not a canonical Ed25519 public key",
            )
        })
    }

    fn load_protected_requester_signing_key() -> Result<SigningKey> {
        let path = CString::new(REQUESTER_SIGNING_KEY_PATH)
            .map_err(|_| ControllerError::Invalid("requester key path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = fstat_exact(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o027 != 0
            || before.st_nlink != 1
            || before.st_size != 32
        {
            return Err(ControllerError::Rejected(
                "requester key is not one protected root-owned 32-byte regular file",
            ));
        }
        let mut filesystem_flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut filesystem_flags,
            )
        } != 0
            || filesystem_flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "requester key lacks the filesystem immutable flag",
            ));
        }
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            key_bytes.fill(0);
            return Err(ControllerError::Rejected(
                "requester key exceeds its canonical raw length",
            ));
        }
        let after = fstat_exact(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            key_bytes.fill(0);
            return Err(ControllerError::Rejected(
                "requester key identity changed while reading its opened FD",
            ));
        }
        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.fill(0);
        Ok(signing_key)
    }

    fn load_immutable_requester_public_key() -> Result<VerifyingKey> {
        let path = CString::new(REQUESTER_PUBLIC_KEY_PATH)
            .map_err(|_| ControllerError::Invalid("requester public key path contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = fstat_exact(file.as_raw_fd())?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_nlink != 1
            || before.st_size != 32
        {
            return Err(ControllerError::Rejected(
                "requester public key is not one root-owned nonwritable 32-byte regular file",
            ));
        }
        let mut filesystem_flags: libc::c_uint = 0;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_GETFLAGS,
                &mut filesystem_flags,
            )
        } != 0
            || filesystem_flags & FS_IMMUTABLE_FL == 0
        {
            return Err(ControllerError::Rejected(
                "requester public key lacks the filesystem immutable flag",
            ));
        }
        let mut key_bytes = [0u8; 32];
        file.read_exact(&mut key_bytes)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(ControllerError::Rejected(
                "requester public key exceeds its canonical raw length",
            ));
        }
        let after = fstat_exact(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(ControllerError::Rejected(
                "requester public key identity changed while reading its opened FD",
            ));
        }
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            ControllerError::Rejected(
                "requester public key is not canonical Ed25519",
            )
        })
    }

    fn fstat_exact(fd: RawFd) -> Result<libc::stat> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(stat)
    }

    fn connect_seqpacket(path: &Path, deadline: &TransportDeadline) -> Result<OwnedFd> {
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        enable_pass_pidfd(socket.as_raw_fd())?;
        let path_bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if path_bytes.len() >= address.sun_path.len() {
            return Err(ControllerError::Invalid("controller socket path is too long"));
        }
        for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
            *destination = *source as libc::c_char;
        }
        let length =
            (mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
        let connected = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        };
        if connected != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS)
                    | Some(libc::EALREADY)
                    | Some(libc::EAGAIN)
            ) {
                return Err(error.into());
            }
            poll_until(socket.as_raw_fd(), libc::POLLOUT, deadline)?;
            let mut socket_error: libc::c_int = 0;
            let mut option_len =
                mem::size_of::<libc::c_int>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut socket_error as *mut _ as *mut libc::c_void,
                    &mut option_len,
                )
            } != 0
                || option_len as usize != mem::size_of::<libc::c_int>()
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if socket_error != 0 {
                return Err(std::io::Error::from_raw_os_error(socket_error).into());
            }
        }
        deadline.ensure_live()?;
        Ok(socket)
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

    fn random_digest() -> Result<Digest> {
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
        let duplicate = duplicate_fd(memfd.as_raw_fd())?;
        let mut file = File::from(duplicate);
        file.write_all(bytes)?;
        file.flush()?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(memfd)
    }

    fn duplicate_fd(fd: RawFd) -> Result<OwnedFd> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn pidfd_identity(pidfd: RawFd) -> Result<String> {
        let contents = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}"))?;
        let pid = contents
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t"))
            .ok_or(ControllerError::Invalid("pidfd has no kernel PID identity"))?;
        Ok(format!("pid:{pid}"))
    }

    fn verify_pidfd_peer(packet: &ReceivedPacket) -> Result<()> {
        if packet.peer.pid <= 0 {
            return Err(ControllerError::Rejected(
                "SO_PEERCRED returned an invalid peer process",
            ));
        }
        if packet.pidfd_identity != format!("pid:{}", packet.peer.pid) {
            return Err(ControllerError::Rejected(
                "SCM_PIDFD and SO_PEERCRED identify different processes",
            ));
        }
        let start_time_before = process_start_time_ticks(packet.peer.pid)?;
        ensure_pidfd_not_exited(packet.pidfd.as_raw_fd())?;
        let signal_result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                packet.pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if signal_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM) {
                return Err(ControllerError::Rejected("peer pidfd is not live"));
            }
            // EPERM is expected for an unprivileged client probing a root
            // daemon. It is accepted only inside this already-joined path.
        }
        ensure_pidfd_not_exited(packet.pidfd.as_raw_fd())?;
        let start_time_after = process_start_time_ticks(packet.peer.pid)?;
        let final_identity = pidfd_identity(packet.pidfd.as_raw_fd())?;
        if start_time_before != start_time_after
            || final_identity != packet.pidfd_identity
        {
            return Err(ControllerError::Rejected(
                "peer process identity changed during pidfd liveness proof",
            ));
        }
        Ok(())
    }

    fn process_start_time_ticks(pid: libc::pid_t) -> Result<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let close = stat.rfind(')').ok_or(ControllerError::Rejected(
            "peer proc stat has no command terminator",
        ))?;
        let fields = stat
            .get(close + 1..)
            .ok_or(ControllerError::Rejected("peer proc stat is truncated"))?
            .split_whitespace();
        fields
            .skip(19)
            .next()
            .ok_or(ControllerError::Rejected(
                "peer proc stat lacks process start time",
            ))?
            .parse::<u64>()
            .map_err(|_| {
                ControllerError::Rejected("peer proc start time is not canonical")
            })
    }

    fn ensure_pidfd_not_exited(pidfd: RawFd) -> Result<()> {
        let mut pollfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if result < 0
                && std::io::Error::last_os_error().raw_os_error()
                    == Some(libc::EINTR)
            {
                continue;
            }
            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if result != 0
                || pollfd.revents
                    & (libc::POLLIN
                        | libc::POLLERR
                        | libc::POLLHUP
                        | libc::POLLNVAL)
                    != 0
            {
                return Err(ControllerError::Rejected(
                    "peer pidfd reports process exit or invalidation",
                ));
            }
            return Ok(());
        }
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

    fn digest_memfd(fd: RawFd, length: u64) -> Result<Digest> {
        let mut file = File::from(duplicate_fd(fd)?);
        file.seek(SeekFrom::Start(0))?;
        sha256_exact_reader(&mut file, length)
    }

    fn read_memfd_bounded(fd: OwnedFd, length: u64, limit: u64) -> Result<Vec<u8>> {
        if length > limit {
            return Err(ControllerError::Rejected("response exceeds local byte bound"));
        }
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(length).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length {
            return Err(ControllerError::Invalid("response memfd truncated"));
        }
        Ok(bytes)
    }

    fn poll_until(
        fd: RawFd,
        events: libc::c_short,
        deadline: &TransportDeadline,
    ) -> Result<libc::c_short> {
        loop {
            let now = Instant::now();
            if now >= deadline.monotonic {
                return Err(ControllerError::Rejected("transport deadline expired"));
            }
            let remaining = deadline.monotonic.duration_since(now);
            let timeout = remaining
                .as_millis()
                .max(1)
                .min(i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
            if result < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            }
            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if result == 0 {
                continue;
            }
            if result != 1 || pollfd.revents & libc::POLLNVAL != 0 {
                return Err(ControllerError::Rejected(
                    "transport poll returned an invalid descriptor",
                ));
            }
            if pollfd.revents
                & (events | libc::POLLERR | libc::POLLHUP)
                == 0
            {
                return Err(ControllerError::Rejected(
                    "transport poll returned unrelated readiness",
                ));
            }
            deadline.ensure_live()?;
            return Ok(pollfd.revents);
        }
    }

    fn send_frame_with_memfd(
        socket: RawFd,
        frame: &[u8; FIXED_FRAME_BYTES],
        memfd: RawFd,
        deadline: &TransportDeadline,
    ) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        let mut control = AlignedControl([0u8; CONTROL_BYTES]);
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
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
        }
        loop {
            let revents = poll_until(socket, libc::POLLOUT, deadline)?;
            if revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                return Err(ControllerError::Rejected(
                    "controller socket failed before request send",
                ));
            }
            let count =
                unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
            if count == FIXED_FRAME_BYTES as isize {
                return Ok(());
            }
            if count >= 0 {
                return Err(ControllerError::Rejected(
                    "SOCK_SEQPACKET request send was not atomic",
                ));
            }
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EINTR) | Some(libc::EAGAIN)
            ) {
                continue;
            }
            return Err(error.into());
        }
    }

    fn receive_frame(
        socket: RawFd,
        deadline: &TransportDeadline,
    ) -> Result<ReceivedPacket> {
        loop {
            let revents = poll_until(socket, libc::POLLIN, deadline)?;
            if revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                return Err(ControllerError::Rejected(
                    "controller socket failed before response receive",
                ));
            }
            let mut frame = [0u8; FIXED_FRAME_BYTES];
            let mut iov = libc::iovec {
                iov_base: frame.as_mut_ptr() as *mut libc::c_void,
                iov_len: frame.len(),
            };
            let mut control = AlignedControl([0u8; CONTROL_BYTES]);
            let mut message: libc::msghdr = unsafe { mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control =
                control.0.as_mut_ptr() as *mut libc::c_void;
            message.msg_controllen = control.0.len();
            let count =
                unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINTR) | Some(libc::EAGAIN)
                ) {
                    continue;
                }
                return Err(error.into());
            }
            // A successful recvmsg may already have installed descriptors. Own
            // every visible descriptor before any packet or cmsg rejection.
            let ancillary = own_received_descriptors(&message);
            if count != FIXED_FRAME_BYTES as isize
                || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            {
                return Err(ControllerError::Invalid("invalid response frame size"));
            }
            if ancillary.invalid {
                return Err(ControllerError::Rejected(
                    "response contains malformed or unexpected ancillary data",
                ));
            }
            let mut rights = ancillary.rights;
            let mut pidfds = ancillary.pidfds;
            if rights.len() != 1 || pidfds.len() != 1 {
                return Err(ControllerError::Rejected(
                    "response must contain one memfd and one kernel pidfd",
                ));
            }
            let memfd = rights.pop().unwrap();
            let pidfd = pidfds.pop().unwrap();
            let peer = socket_peer(socket)?;
            let pidfd_identity = pidfd_identity(pidfd.as_raw_fd())?;
            return Ok(ReceivedPacket {
                frame,
                memfd,
                pidfd,
                peer,
                pidfd_identity,
            });
        }
    }

    struct AncillaryOwnership {
        rights: Vec<OwnedFd>,
        pidfds: Vec<OwnedFd>,
        invalid: bool,
    }

    fn own_received_descriptors(message: &libc::msghdr) -> AncillaryOwnership {
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
}
