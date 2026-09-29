//! Actual Linux peer/process/executable measurements shared by the custody
//! receiver and its guest inspection owner. These are kernel observations,
//! not caller-provided process summaries or attestation verdicts.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Constructed only by actual socket/PIDFD observation below. No public wire
/// decoder, process-id constructor or caller-supplied measurement is admitted.
#[derive(Eq, PartialEq)]
pub(super) struct PeerMeasurement {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    process: StableProcessIdentity,
    cgroup: String,
    security_label: String,
    executable: String,
}

impl PeerMeasurement {
    pub(super) fn uid(&self) -> libc::uid_t { self.uid }
    pub(super) fn matches_credentials(&self, value: &libc::ucred) -> bool {
        self.pid == value.pid && self.uid == value.uid && self.gid == value.gid
    }
    pub(super) fn cgroup_sha256(&self) -> &str { &self.cgroup }
    pub(super) fn security_label_sha256(&self) -> &str { &self.security_label }
    pub(super) fn executable_sha256(&self) -> &str { &self.executable }
    pub(super) fn process_binding_sha256(&self) -> String { self.process.binding_sha256() }
}

pub(super) fn capture_connection(socket: RawFd, expected_uid: libc::uid_t, cache: &ExecutableMeasurementCache)
    -> io::Result<(OwnedFd, PeerMeasurement)> {
    let credentials = socket_peer_credentials(socket)?;
    if credentials.uid == 0 || credentials.uid != expected_uid {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "peer credentials are incomplete or privileged"));
    }
    let pidfd = open_peer_pidfd(socket)?;
    let measured = capture(socket, &pidfd, None, None, cache)?;
    Ok((pidfd, measured))
}

pub(super) fn capture_packet(socket: RawFd, connection: &OwnedFd, sender: &OwnedFd,
    expected: &PeerMeasurement, cache: &ExecutableMeasurementCache) -> io::Result<PeerMeasurement> {
    capture(socket, connection, Some(sender), Some(expected), cache)
}

fn capture(socket: RawFd, connection: &OwnedFd, sender: Option<&OwnedFd>,
    expected: Option<&PeerMeasurement>, cache: &ExecutableMeasurementCache) -> io::Result<PeerMeasurement> {
    let credentials = socket_peer_credentials(socket)?;
    if credentials.uid == 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "privileged peer cannot be an authenticated workload"));
    }
    let identity = || match sender {
        Some(sender) => prove_pidfds_same_process(connection, sender, credentials.pid),
        None => capture_pidfd_process_identity(connection, credentials.pid),
    };
    let before = identity()?;
    if expected.is_some_and(|v| v.process != before || !v.matches_credentials(&credentials)) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "per-packet identity differs from the authenticated connection owner"));
    }
    let cgroup = read_bounded_proc_file(&format!("/proc/{}/cgroup", credentials.pid), MAX_PEER_CGROUP_BYTES)?;
    let security_label = peer_security_identity_sha256(socket, credentials.pid)?;
    let executable = measure_peer_executable(credentials.pid, &before, cache)?;
    let after = identity()?;
    if before != after {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "peer kernel process identity changed during measurement"));
    }
    ensure_pidfd_alive(connection)?;
    if let Some(sender) = sender { ensure_pidfd_alive(sender)?; }
    Ok(PeerMeasurement { pid:credentials.pid, uid:credentials.uid, gid:credentials.gid,
        process:after, cgroup:sha256_bytes(&cgroup), security_label, executable })
}

const MAX_PEER_CGROUP_BYTES: u64 = 64 * 1024;

const MAX_PEER_SECURITY_LABEL_BYTES: usize = 64 * 1024;

const MAX_PEER_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

const MAX_PIDFD_FDINFO_BYTES: u64 = 16 * 1024;

const MAX_PROC_STAT_BYTES: u64 = 16 * 1024;

const MAX_PID_NAMESPACE_DEPTH: usize = 32;

const MAX_IMA_XATTR_BYTES: usize = 16 * 1024;

const EXECUTABLE_CACHE_TTL: Duration = Duration::from_secs(2);

pub(super) const EXECUTABLE_CACHE_ENTRIES_PER_WORKER: usize = 4;

pub(super) const MAX_EXECUTABLE_CACHE_ENTRIES: usize = 1024;

const SO_PEERPIDFD_OPTION: libc::c_int = 77;

const AT_EMPTY_PATH_FLAG: libc::c_int = 0x1000;

const STATX_BASIC_STATS_MASK: libc::c_uint = 0x0000_07ff;

const STATX_ATTR_VERITY_FLAG: u64 = 0x0010_0000;

const STATX_BUFFER_BYTES: usize = 256;

const STATX_ATTRIBUTES_OFFSET: usize = 8;

const STATX_ATTRIBUTES_MASK_OFFSET: usize = 56;

const IMA_XATTR_NAME: &[u8] = b"security.ima\0";

#[repr(C, align(8))]
struct StatxBuffer {
    bytes: [u8; STATX_BUFFER_BYTES],
}

impl StatxBuffer {
    fn native_u64_at(&self, offset: usize) -> u64 {
        let mut bytes = [0u8; size_of::<u64>()];
        let end = offset + size_of::<u64>();
        bytes.copy_from_slice(&self.bytes[offset..end]);
        u64::from_ne_bytes(bytes)
    }
}


#[derive(Clone, Eq, Hash, PartialEq)]
struct PidfdFdinfoIdentity {
    pid: libc::pid_t,
    namespace_pids: Vec<libc::pid_t>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct StableProcessIdentity {
    pidfd: PidfdFdinfoIdentity,
    proc_device: u64,
    proc_inode: u64,
    start_time_ticks: u64,
}

impl StableProcessIdentity {
    pub(super) fn pid(&self) -> libc::pid_t { self.pidfd.pid }
    fn binding_sha256(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"serverware.responseV2.guestInspectorProcess/v1\0");
        hash.update(self.pidfd.pid.to_be_bytes());
        hash.update((self.pidfd.namespace_pids.len() as u32).to_be_bytes());
        for pid in &self.pidfd.namespace_pids { hash.update(pid.to_be_bytes()); }
        hash.update(self.proc_device.to_be_bytes());
        hash.update(self.proc_inode.to_be_bytes());
        hash.update(self.start_time_ticks.to_be_bytes());
        format!("sha256:{:x}", hash.finalize())
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct ExecutableFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct ExecutableCacheKey {
    process: StableProcessIdentity,
    executable: ExecutableFileIdentity,
    integrity_signal_sha256: String,
}

struct CachedExecutableMeasurement {
    measurement_sha256: String,
    cached_at: Instant,
}

pub(super) struct ExecutableMeasurementCache {
    entries: Mutex<
        HashMap<ExecutableCacheKey, CachedExecutableMeasurement>,
    >,
    capacity: usize,
}


impl ExecutableMeasurementCache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn get(
        &self,
        key: &ExecutableCacheKey,
    ) -> io::Result<Option<String>> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "executable measurement cache lock poisoned",
            )
        })?;
        entries.retain(|_, entry| {
            now.saturating_duration_since(entry.cached_at)
                <= EXECUTABLE_CACHE_TTL
        });
        Ok(entries
            .get(key)
            .map(|entry| entry.measurement_sha256.clone()))
    }

    fn insert(
        &self,
        key: ExecutableCacheKey,
        measurement_sha256: String,
    ) -> io::Result<()> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "executable measurement cache lock poisoned",
            )
        })?;
        entries.retain(|_, entry| {
            now.saturating_duration_since(entry.cached_at)
                <= EXECUTABLE_CACHE_TTL
        });
        if entries.len() >= self.capacity
            && !entries.contains_key(&key)
        {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(oldest, _)| oldest.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            CachedExecutableMeasurement {
                measurement_sha256,
                cached_at: now,
            },
        );
        Ok(())
    }
}


pub(super) fn received_fd_is_cloexec(fd: RawFd) -> bool {
    // SAFETY: caller records fd only after a complete descriptor-carrying
    // control message has been bounded.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC != 0
}


pub(super) fn open_peer_pidfd(socket: RawFd) -> io::Result<OwnedFd> {
    let mut raw: RawFd = -1;
    let mut length = size_of::<RawFd>() as libc::socklen_t;
    // SAFETY: SO_PEERPIDFD writes one new pidfd into raw. Unsupported
    // kernels fail closed rather than falling back to a racy pidfd_open.
    let result = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            SO_PEERPIDFD_OPTION,
            (&mut raw as *mut RawFd).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if raw < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERPIDFD returned an invalid descriptor",
        ));
    }
    // SAFETY: SO_PEERPIDFD returned a new uniquely owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    if length as usize != size_of::<RawFd>()
        || !received_fd_is_cloexec(pidfd.as_raw_fd())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERPIDFD returned a malformed or non-CLOEXEC descriptor",
        ));
    }
    Ok(pidfd)
}

pub(super) fn prove_pidfds_same_process(
    peer_pidfd: &OwnedFd,
    sender_pidfd: &OwnedFd,
    expected_pid: libc::pid_t,
) -> io::Result<StableProcessIdentity> {
    ensure_pidfd_alive(peer_pidfd)?;
    ensure_pidfd_alive(sender_pidfd)?;
    let peer_before = read_pidfd_fdinfo(peer_pidfd)?;
    let sender_before = read_pidfd_fdinfo(sender_pidfd)?;
    if peer_before != sender_before
        || peer_before.pid != expected_pid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCM_PIDFD and SO_PEERPIDFD kernel identities differ",
        ));
    }
    let process =
        capture_pidfd_process_identity(peer_pidfd, expected_pid)?;
    let peer_after = read_pidfd_fdinfo(peer_pidfd)?;
    let sender_after = read_pidfd_fdinfo(sender_pidfd)?;
    ensure_pidfd_alive(peer_pidfd)?;
    ensure_pidfd_alive(sender_pidfd)?;
    if peer_after != peer_before
        || sender_after != sender_before
        || process.pidfd != peer_before
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pidfd kernel identity changed during stable process proof",
        ));
    }
    Ok(process)
}

pub(super) fn capture_pidfd_process_identity(
    pidfd: &OwnedFd,
    expected_pid: libc::pid_t,
) -> io::Result<StableProcessIdentity> {
    ensure_pidfd_alive(pidfd)?;
    let fdinfo_before = read_pidfd_fdinfo(pidfd)?;
    if fdinfo_before.pid != expected_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pidfd kernel identity does not match expected process",
        ));
    }
    let proc_directory = open_proc_task_directory(expected_pid)?;
    let metadata_before = proc_directory.metadata()?;
    if !metadata_before.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "live proc task identity is not a directory",
        ));
    }
    let start_time_before =
        read_proc_start_time(&proc_directory, expected_pid)?;
    let fdinfo_after = read_pidfd_fdinfo(pidfd)?;
    let start_time_after =
        read_proc_start_time(&proc_directory, expected_pid)?;
    let metadata_after = proc_directory.metadata()?;
    ensure_pidfd_alive(pidfd)?;
    if fdinfo_after != fdinfo_before
        || start_time_after != start_time_before
        || metadata_after.dev() != metadata_before.dev()
        || metadata_after.ino() != metadata_before.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live proc task identity changed during pidfd proof",
        ));
    }
    Ok(StableProcessIdentity {
        pidfd: fdinfo_after,
        proc_device: metadata_after.dev(),
        proc_inode: metadata_after.ino(),
        start_time_ticks: start_time_after,
    })
}

fn read_pidfd_fdinfo(
    pidfd: &OwnedFd,
) -> io::Result<PidfdFdinfoIdentity> {
    let path =
        format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let bytes =
        read_bounded_proc_file(&path, MAX_PIDFD_FDINFO_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pidfd fdinfo is not UTF-8",
        )
    })?;
    let mut pid = None;
    let mut namespace_pids = None;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pidfd fdinfo contains a field without a delimiter",
            ));
        };
        match name {
            "Pid" => {
                if pid.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pidfd fdinfo contains duplicate Pid fields",
                    ));
                }
                let parsed =
                    value.trim().parse::<libc::pid_t>().map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "pidfd fdinfo Pid is malformed",
                            )
                        },
                    )?;
                if parsed <= 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pidfd fdinfo does not identify a live process",
                    ));
                }
                pid = Some(parsed);
            }
            "NSpid" => {
                if namespace_pids.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pidfd fdinfo contains duplicate NSpid fields",
                    ));
                }
                let parsed = value
                    .split_ascii_whitespace()
                    .map(|entry| {
                        entry.parse::<libc::pid_t>().map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "pidfd fdinfo NSpid is malformed",
                            )
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                if parsed.is_empty()
                    || parsed.len() > MAX_PID_NAMESPACE_DEPTH
                    || parsed.iter().any(|entry| *entry <= 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pidfd fdinfo NSpid is empty or overbound",
                    ));
                }
                namespace_pids = Some(parsed);
            }
            _ => {}
        }
    }
    let pid = pid.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel pidfd fdinfo lacks mandatory Pid",
        )
    })?;
    let namespace_pids = namespace_pids.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel pidfd fdinfo lacks mandatory NSpid",
        )
    })?;
    if namespace_pids.first() != Some(&pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pidfd fdinfo Pid and NSpid disagree",
        ));
    }
    Ok(PidfdFdinfoIdentity {
        pid,
        namespace_pids,
    })
}

fn open_proc_task_directory(pid: libc::pid_t) -> io::Result<File> {
    let path = CString::new(format!("/proc/{pid}")).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "proc task path contains NUL",
        )
    })?;
    // SAFETY: path is NUL-terminated and flags request one owned fd.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned one new uniquely owned descriptor.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw) }))
}

fn read_proc_start_time(
    proc_directory: &File,
    expected_pid: libc::pid_t,
) -> io::Result<u64> {
    let name = b"stat\0";
    // SAFETY: name is NUL-terminated and proc_directory is live.
    let raw = unsafe {
        libc::openat(
            proc_directory.as_raw_fd(),
            name.as_ptr().cast(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned one new uniquely owned descriptor.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let bytes = read_bounded_file(file, MAX_PROC_STAT_BYTES)?;
    parse_proc_start_time(&bytes, expected_pid)
}

fn parse_proc_start_time(
    bytes: &[u8],
    expected_pid: libc::pid_t,
) -> io::Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat is not UTF-8",
        )
    })?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat is not exactly one bounded record",
        ));
    }
    let open = line.find('(').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat lacks command opening delimiter",
        )
    })?;
    let close = line.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat lacks command closing delimiter",
        )
    })?;
    if close <= open
        || line[..open].trim().parse::<libc::pid_t>().ok()
            != Some(expected_pid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proc stat does not identify the expected process",
        ));
    }
    let fields = line
        .get(close + 1..)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proc stat command delimiter is out of range",
            )
        })?
        .split_ascii_whitespace();
    let start_time = fields
        .enumerate()
        .find_map(|(index, field)| (index == 19).then_some(field))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proc stat lacks field 22 starttime",
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proc stat field 22 starttime is malformed",
            )
        })?;
    if start_time == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat field 22 starttime is zero",
        ));
    }
    Ok(start_time)
}


pub(super) fn ensure_pidfd_alive(pidfd: &OwnedFd) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor points to one initialized pollfd.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result != 0
        || descriptor.revents
            & (libc::POLLIN
                | libc::POLLERR
                | libc::POLLHUP
                | libc::POLLNVAL)
            != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated peer process is no longer alive",
        ));
    }
    Ok(())
}

pub(super) fn peer_security_label(socket: RawFd) -> io::Result<Vec<u8>> {
    let mut label = vec![0u8; MAX_PEER_SECURITY_LABEL_BYTES];
    let mut length =
        libc::socklen_t::try_from(label.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "security label buffer exceeds socklen_t",
            )
        })?;
    // SAFETY: label is writable for exactly length bytes.
    let result = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            label.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let returned = length as usize;
    if returned == 0 || returned > label.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer security label is empty or overbound",
        ));
    }
    label.truncate(returned);
    if label.last() == Some(&0) {
        label.pop();
    }
    if label.is_empty() || label.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer security label is not a single exact label",
        ));
    }
    Ok(label)
}

fn peer_security_identity_sha256(
    socket: RawFd,
    pid: libc::pid_t,
) -> io::Result<String> {
    let socket_label = peer_security_label(socket)?;
    let current_label = read_bounded_proc_file(
        &format!("/proc/{pid}/attr/current"),
        MAX_PEER_SECURITY_LABEL_BYTES as u64,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(
        b"serverware.response-v2/client-security-identity/v1",
    );
    for value in [&socket_label[..], &current_label[..]] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn read_bounded_proc_file(
    path: &str,
    maximum_bytes: u64,
) -> io::Result<Vec<u8>> {
    read_bounded_file(File::open(path)?, maximum_bytes)
}

fn read_bounded_file(
    file: File,
    maximum_bytes: u64,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer proc identity data is empty or overbound",
        ));
    }
    Ok(bytes)
}

fn measure_peer_executable(
    pid: libc::pid_t,
    process_identity: &StableProcessIdentity,
    cache: &ExecutableMeasurementCache,
) -> io::Result<String> {
    let path = format!("/proc/{pid}/exe");
    let mut executable = File::open(&path)?;
    let before = executable.metadata()?;
    if !before.file_type().is_file()
        || before.len() == 0
        || before.len() > MAX_PEER_EXECUTABLE_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer executable is not a bounded regular file",
        ));
    }
    let executable_identity =
        ExecutableFileIdentity::from_metadata(&before);
    let integrity_before =
        executable_integrity_signal(&executable, &before)?;
    let cache_key = integrity_before.as_ref().map(|signal| {
        ExecutableCacheKey {
            process: process_identity.clone(),
            executable: executable_identity.clone(),
            integrity_signal_sha256: signal.clone(),
        }
    });
    if let Some(key) = cache_key.as_ref() {
        if let Some(measurement) = cache.get(key)? {
            let current = fs::metadata(&path)?;
            if ExecutableFileIdentity::from_metadata(&current)
                != executable_identity
                || executable_integrity_signal(
                    &executable,
                    &before,
                )? != integrity_before
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer executable cache identity changed during revalidation",
                ));
            }
            return Ok(measurement);
        }
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = executable.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "peer executable length overflow",
            )
        })?;
        if total > MAX_PEER_EXECUTABLE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer executable exceeds measurement bound",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let after = executable.metadata()?;
    let current = fs::metadata(&path)?;
    let integrity_after =
        executable_integrity_signal(&executable, &after)?;
    if total != before.len()
        || ExecutableFileIdentity::from_metadata(&after)
            != executable_identity
        || ExecutableFileIdentity::from_metadata(&current)
            != executable_identity
        || integrity_after != integrity_before
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer executable changed during measurement",
        ));
    }
    let measurement = format!("sha256:{:x}", hasher.finalize());
    if let Some(key) = cache_key {
        cache.insert(key, measurement.clone())?;
    }
    Ok(measurement)
}

impl ExecutableFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn executable_integrity_signal(
    executable: &File,
    metadata: &fs::Metadata,
) -> io::Result<Option<String>> {
    let verity = executable_has_fs_verity(executable)?;
    let ima = read_ima_xattr(executable)?;
    if !verity && ima.is_none() {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    hasher.update(
        b"serverware.response-v2/executable-integrity-signal/v1",
    );
    hasher.update(metadata.dev().to_be_bytes());
    hasher.update(metadata.ino().to_be_bytes());
    hasher.update([u8::from(verity)]);
    if let Some(ima) = ima {
        hasher.update((ima.len() as u64).to_be_bytes());
        hasher.update(ima);
    } else {
        hasher.update(0u64.to_be_bytes());
    }
    Ok(Some(format!("sha256:{:x}", hasher.finalize())))
}

fn executable_has_fs_verity(executable: &File) -> io::Result<bool> {
    let mut status = StatxBuffer {
        bytes: [0u8; STATX_BUFFER_BYTES],
    };
    let empty_path = b"\0";
    // SAFETY: executable is live, empty_path is NUL-terminated, and
    // AT_EMPTY_PATH asks statx to inspect that descriptor. StatxBuffer is
    // the Linux ABI's fixed 256-byte, eight-byte-aligned output region.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            executable.as_raw_fd(),
            empty_path.as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH_FLAG | libc::AT_SYMLINK_NOFOLLOW,
            STATX_BASIC_STATS_MASK,
            &mut status as *mut StatxBuffer,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS)
                | Some(libc::EINVAL)
                | Some(libc::EOPNOTSUPP)
        ) {
            return Ok(false);
        }
        return Err(error);
    }
    let attributes =
        status.native_u64_at(STATX_ATTRIBUTES_OFFSET);
    let attributes_mask =
        status.native_u64_at(STATX_ATTRIBUTES_MASK_OFFSET);
    Ok(attributes_mask & STATX_ATTR_VERITY_FLAG != 0
        && attributes & STATX_ATTR_VERITY_FLAG != 0)
}

fn read_ima_xattr(executable: &File) -> io::Result<Option<Vec<u8>>> {
    // SAFETY: the name is NUL-terminated; a null value with size zero
    // requests the exact xattr length.
    let length = unsafe {
        libc::fgetxattr(
            executable.as_raw_fd(),
            IMA_XATTR_NAME.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if xattr_signal_unavailable(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    let length = usize::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "security.ima length exceeds usize",
        )
    })?;
    if length == 0 || length > MAX_IMA_XATTR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security.ima signal is empty or overbound",
        ));
    }
    let mut value = vec![0u8; length];
    // SAFETY: value is writable for exactly length bytes.
    let returned = unsafe {
        libc::fgetxattr(
            executable.as_raw_fd(),
            IMA_XATTR_NAME.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if returned < 0 {
        return Err(io::Error::last_os_error());
    }
    if returned as usize != value.len() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "security.ima signal changed during revalidation",
        ));
    }
    Ok(Some(value))
}

fn xattr_signal_unavailable(error: &io::Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    [
        libc::ENODATA,
        libc::ENOTSUP,
        libc::EOPNOTSUPP,
        libc::EACCES,
        libc::EPERM,
    ]
    .contains(&code)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}


pub(super) fn socket_peer_credentials(
    socket: RawFd,
) -> io::Result<libc::ucred> {
    let mut credentials: libc::ucred =
        unsafe { zeroed() };
    let mut length =
        size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing socket peer credentials are unavailable",
        ));
    }
    Ok(credentials)
}
