//! Fixed two-phase client for a separately provisioned runtime observer.
//!
//! The root peer's ready echo is channel readiness only, not a signature or a
//! mapping observation. The real observer service/acquisition is not supplied
//! here. The caller retains target custody and independently admits the final
//! original result, its observer signature, and every execution/output join.

use super::{boottime_now_ns_v11, ControllerError, Digest, Result};
use super::runner_output_storage_v12::fd_mount_id;
use crate::plan_protocol::{ArtifactCasReference, SourceCasReference};
use crate::plan_protocol::body_launch_contract_v12::BodyLaunchContextV12;
use crate::plan_protocol::body_observer_contract_v12::{BodyObserverLaunchV12,
    BodyObserverReadyV12, BodyObserverTerminalV12, SOCKET_PATH, LAUNCH_VERSION,
    TERMINAL_VERSION, MAX_CONTROL_BYTES, FD_ROLES};
pub(super) use crate::plan_protocol::body_observer_contract_v12::BodyObserverTerminalRequestV12;
use crate::runtime_evidence::{verify_static_executable_fd_bounded, ExecutableRole};
use crate::runtime_evidence::body_result_v12::MAX_BODY_RESULT_BYTES_V12;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x10;
// Kernel-generated ancillary pidfds are forbidden, but still need closing.
const SCM_PIDFD: libc::c_int = 0x04;

fn rejected(message: &'static str) -> ControllerError { ControllerError::Rejected(message) }
fn live(deadline: u64) -> Result<()> {
    if boottime_now_ns_v11()? >= deadline { return Err(rejected("observer exchange original deadline expired")); }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
fn node(stat: &libc::stat) -> Node {
    Node { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
        uid: stat.st_uid, gid: stat.st_gid }
}
fn stat_fd(fd: RawFd) -> Result<libc::stat> {
    let mut value = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(value)
}
fn open_at(parent: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn protected_directory(fd: RawFd) -> Result<Node> {
    let stat = stat_fd(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != 0
        || stat.st_gid != 0 || stat.st_mode & 0o022 != 0 {
        return Err(rejected("observer endpoint ancestor lacks protected root ownership"));
    }
    Ok(node(&stat))
}
fn endpoint_parent(deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    let mut directory = open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    protected_directory(directory.as_raw_fd())?;
    let (parent, _) = SOCKET_PATH.rsplit_once('/')
        .ok_or_else(|| rejected("source-fixed observer socket has no parent"))?;
    for component in parent[1..].split('/') {
        live(deadline)?;
        let component = CString::new(component)
            .map_err(|_| rejected("source-fixed observer ancestor contains NUL"))?;
        directory = open_at(directory.as_raw_fd(), &component,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        protected_directory(directory.as_raw_fd())?;
    }
    live(deadline)?;
    Ok(directory)
}
fn endpoint_node(parent: RawFd) -> Result<Node> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, c"control.sock".as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.st_mode & libc::S_IFMT != libc::S_IFSOCK || value.st_uid != 0
        || value.st_gid != 0 || value.st_nlink != 1 || value.st_mode & 0o022 != 0 {
        return Err(rejected("observer endpoint is not the protected root-owned socket"));
    }
    Ok(node(&value))
}

fn peer_credentials(socket: RawFd) -> Result<libc::ucred> {
    let mut value: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe { libc::getsockopt(socket, libc::SOL_SOCKET, libc::SO_PEERCRED,
        (&mut value as *mut libc::ucred).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() || value.pid <= 0 || value.uid != 0 || value.gid != 0 {
        return Err(rejected("observer socket peer is not one actual root process"));
    }
    Ok(value)
}

// Linux >=6.5: pin sk_peer_pid itself, not a reopened numeric SO_PEERCRED PID.
fn socket_peer_pidfd(socket: RawFd, deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    let mut raw: RawFd = -1;
    let mut length = std::mem::size_of::<RawFd>() as libc::socklen_t;
    if unsafe { libc::getsockopt(socket, libc::SOL_SOCKET, libc::SO_PEERPIDFD,
        (&mut raw as *mut RawFd).cast(), &mut length) } != 0 {
        // No numeric-PID reopen fallback on kernels without this facility.
        return Err(std::io::Error::last_os_error().into());
    }
    if raw < 0 { return Err(rejected("observer socket did not return its actual peer pidfd")); }
    // Adopt immediately: all subsequent length/time/flag failures close it.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    if length as usize != std::mem::size_of::<RawFd>() {
        return Err(rejected("observer socket peer pidfd has an invalid returned length"));
    }
    live(deadline)?;
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 { return Err(std::io::Error::last_os_error().into()); }
    if flags & libc::FD_CLOEXEC == 0 && unsafe {
        libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC)
    } < 0 { return Err(std::io::Error::last_os_error().into()); }
    let actual = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
    if actual < 0 { return Err(std::io::Error::last_os_error().into()); }
    if actual & libc::FD_CLOEXEC == 0 { return Err(rejected("observer peer pidfd lacks close-on-exec")); }
    pidfd_live(owned.as_raw_fd())?;
    live(deadline)?;
    Ok(owned)
}

fn pidfd_live(pidfd: RawFd) -> Result<()> {
    let mut descriptor = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
    let count = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if count < 0 { return Err(std::io::Error::last_os_error().into()); }
    if count != 0 || descriptor.revents != 0 { return Err(rejected("observer peer process is no longer live")); }
    Ok(())
}

fn start_ticks(process: RawFd, pid: libc::pid_t, deadline: u64) -> Result<u64> {
    let stat = open_at(process, c"stat", libc::O_RDONLY | libc::O_NOFOLLOW)?;
    let mut bytes = [0u8; 16 * 1024 + 1];
    let mut length = 0;
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(stat.as_raw_fd(), bytes[length..].as_mut_ptr().cast(),
            bytes.len() - length, length as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { break; }
        length += count as usize;
        if length == bytes.len() { return Err(rejected("observer process stat exceeds its fixed bound")); }
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| rejected("observer process stat is not UTF8"))?;
    let open = text.find('(').ok_or_else(|| rejected("observer process stat lacks a command"))?;
    let close = text.rfind(')').ok_or_else(|| rejected("observer process stat lacks a command end"))?;
    if close <= open || text[..open].trim().parse::<i32>().ok() != Some(pid) {
        return Err(rejected("observer process stat belongs to another PID"));
    }
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let state = fields.next().ok_or_else(|| rejected("observer process state is missing"))?;
    if state.len() != 1 || matches!(state, "Z" | "X" | "x") {
        return Err(rejected("observer process is already terminal"));
    }
    fields.nth(18).and_then(|value| value.parse::<u64>().ok()).filter(|value| *value != 0)
        .ok_or_else(|| rejected("observer process start ticks are invalid"))
}

#[derive(Eq, PartialEq)]
struct ExecutableIdentity { node: Node, links: u64, size: i64,
    modified: i64, modified_ns: i64, changed: i64, changed_ns: i64 }
fn executable_identity(fd: RawFd) -> Result<ExecutableIdentity> {
    let value = stat_fd(fd)?;
    let mut flags: libc::c_uint = 0;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_uid != 0
        || value.st_gid != 0 || value.st_nlink != 1 || value.st_mode & 0o022 != 0
        || value.st_size <= 0 || value.st_size as u64 > MAX_EXECUTABLE_BYTES
        || unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0 || flags & FS_IMMUTABLE_FL == 0 {
        return Err(rejected("observer executable lost its immutable root-owned identity"));
    }
    Ok(ExecutableIdentity { node: node(&value), links: value.st_nlink, size: value.st_size,
        modified: value.st_mtime, modified_ns: value.st_mtime_nsec,
        changed: value.st_ctime, changed_ns: value.st_ctime_nsec })
}

// Both socket and retained peer are polled. A scheduler/native syscall can
// finish late; actual before/after checks deny it, not claim hard interruption.
fn wait(socket: RawFd, peer_pidfd: RawFd, events: i16, deadline: u64) -> Result<()> {
    loop {
        let now = boottime_now_ns_v11()?;
        if now >= deadline { return Err(rejected("observer exchange original deadline expired")); }
        let mut descriptors = [libc::pollfd { fd: socket, events, revents: 0 },
            libc::pollfd { fd: peer_pidfd, events: libc::POLLIN, revents: 0 }];
        let milliseconds = ((deadline - now) / 1_000_000).clamp(1, 100) as i32;
        let count = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, milliseconds) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if descriptors[1].revents != 0 { return Err(rejected("observer peer exited during the exchange")); }
        if descriptors[0].revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(rejected("observer socket failed during the exchange"));
        }
        if descriptors[0].revents & (events | libc::POLLHUP) != 0 { return Ok(()); }
    }
}

fn send_all(socket: RawFd, peer: RawFd, mut bytes: &[u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        wait(socket, peer, libc::POLLOUT, deadline)?;
        let count = unsafe { libc::send(socket, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) { continue; }
            return Err(error.into());
        }
        if count == 0 { return Err(rejected("observer socket closed during a request")); }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}

// Kernel-delivered descriptors must be closed before ANY deadline, truncation
// or shape error is returned. Linux closes rights omitted by MSG_CTRUNC; every
// delivered right is enumerated here even though all ancillary data is denied.
fn close_ancillary(message: &libc::msghdr) -> bool {
    let unexpected = message.msg_controllen != 0 || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET
                && matches!((*header).cmsg_type, libc::SCM_RIGHTS | SCM_PIDFD) {
                let length = (*header).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                for index in 0..length / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index));
                    if fd >= 0 { libc::close(fd); }
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    unexpected
}

fn receive_once(socket: RawFd, bytes: &mut [u8], deadline: u64) -> Result<Option<usize>> {
    loop {
        live(deadline)?;
        let mut ancillary = [0usize; 64];
        let mut io = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut io;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            live(deadline)?;
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            if error.kind() == std::io::ErrorKind::WouldBlock { return Ok(None); }
            return Err(error.into());
        }
        // Receive has installed any delivered rights even if it completed
        // after the deadline. Close them before checking time or returning.
        if close_ancillary(&message) { return Err(rejected("observer response carried forbidden ancillary data")); }
        live(deadline)?;
        return Ok(Some(count as usize));
    }
}

fn receive_exact(socket: RawFd, peer: RawFd, mut bytes: &mut [u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        wait(socket, peer, libc::POLLIN, deadline)?;
        let received = receive_once(socket, bytes, deadline)?;
        live(deadline)?;
        match received {
            Some(0) => return Err(rejected("observer response ended before its declared length")),
            Some(count) => bytes = &mut bytes[count..],
            None => {}
        }
    }
    Ok(())
}
fn require_quiet(socket: RawFd, deadline: u64) -> Result<()> {
    live(deadline)?;
    let observed = receive_once(socket, &mut [0u8; 1], deadline)?;
    live(deadline)?;
    if observed.is_some() { return Err(rejected("observer channel has unsolicited bytes or early EOF")); }
    Ok(())
}
fn frame(socket: RawFd, peer: RawFd, bytes: &[u8], deadline: u64) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| rejected("observer request frame length is invalid"))?;
    send_all(socket, peer, &length.to_be_bytes(), deadline)?;
    send_all(socket, peer, bytes, deadline)
}
fn receive_frame(socket: RawFd, peer: RawFd, maximum: usize, deadline: u64) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    receive_exact(socket, peer, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(2..=maximum).contains(&length) { return Err(rejected("observer response length exceeds its fixed bound")); }
    let mut bytes = vec![0u8; length];
    receive_exact(socket, peer, &mut bytes, deadline)?;
    Ok(bytes)
}

fn transfer_target(socket: RawFd, peer: RawFd, fds: &[RawFd; 9], deadline: u64) -> Result<()> {
    for (index, fd) in fds.iter().enumerate() {
        if *fd < 0 || fds[..index].contains(fd) || unsafe { libc::fcntl(*fd, libc::F_GETFD) } < 0 {
            return Err(rejected("observer handoff lacks nine distinct retained descriptors"));
        }
    }
    let mut ancillary = [0usize; 16];
    let byte = [b'L'];
    let mut io = libc::iovec { iov_base: byte.as_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast::<RawFd>(), fds.len());
    }
    loop {
        wait(socket, peer, libc::POLLOUT, deadline)?;
        let count = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if count == 1 { return Ok(()); }
        if let Some(error) = error {
            if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) { continue; }
            return Err(error.into());
        }
        return Err(rejected("observer descriptor handoff was incomplete"));
    }
}

pub(super) struct BodyObserverExchangeV12 {
    owner_pid: libc::pid_t,
    socket: OwnedFd,
    parent: OwnedFd,
    parent_identity: Node,
    parent_mount: u64,
    socket_identity: Node,
    peer_pid: libc::pid_t,
    peer_pidfd: OwnedFd,
    peer_proc: OwnedFd,
    peer_proc_identity: Node,
    peer_start: u64,
    peer_executable: OwnedFd,
    peer_executable_identity: ExecutableIdentity,
    launch: BodyObserverLaunchV12,
    deadline: u64,
}

impl BodyObserverExchangeV12 {
    pub(super) fn begin(context: &BodyLaunchContextV12, target_pid: u32, target_start: u64,
        target_pidfd_inode: u64, target_custody: Digest, target_fds: &[RawFd; 9],
        expected_observer_executable: Digest, source: &SourceCasReference,
        artifacts: Option<&ArtifactCasReference>, expected_proxy: &Digest, deadline: u64) -> Result<Self> {
        live(deadline)?;
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0
            || !(2..=i32::MAX as u32).contains(&target_pid) || target_start == 0
            || target_pidfd_inode == 0 || target_custody == [0; 32]
            || expected_observer_executable == [0; 32] || *expected_proxy == [0; 32]
            || deadline > context.deadline_boottime_ns {
            return Err(rejected("observer launch lacks original root/target/deadline scope"));
        }
        // Bound the admitted original graph before making the owned launch.
        drop(context.original_bytes().map_err(|_| rejected("observer launch context is invalid"))?);
        source.validate().map_err(|_| rejected("observer launch source reference is invalid"))?;
        if let Some(artifacts) = artifacts {
            artifacts.validate().map_err(|_| rejected("observer launch artifact reference is invalid"))?;
            if artifacts.source_manifest_sha256 != source.manifest_sha256 {
                return Err(rejected("observer launch artifact/source scope differs"));
            }
        }
        // Typed serialization keeps the original context's own exact field
        // order; the whole wrapper, including independent scope, is capped.
        let launch = BodyObserverLaunchV12 { version: LAUNCH_VERSION.to_owned(), context: context.clone(),
            source: source.clone(), artifacts: artifacts.cloned(), expected_proxy: *expected_proxy,
            target_pid, target_start, target_pidfd_inode, target_custody,
            deadline_boottime_ns: deadline, fd_roles: FD_ROLES.map(str::to_owned) };
        let launch_original = launch.original_bytes()
            .map_err(|_| rejected("observer launch cannot encode its closed original scope"))?;
        let parent = endpoint_parent(deadline)?;
        let parent_identity = protected_directory(parent.as_raw_fd())?;
        let parent_mount = fd_mount_id(parent.as_raw_fd())?;
        let socket_identity = endpoint_node(parent.as_raw_fd())?;
        // Resolve only the source-fixed basename through our retained directory,
        // not through a second caller-selected path lookup.
        let path = format!("/proc/self/fd/{}/control.sock", parent.as_raw_fd());
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if path.len() >= address.sun_path.len() { return Err(rejected("observer anchored socket path is too long")); }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, byte) in address.sun_path.iter_mut().zip(path.bytes()) { *destination = byte as libc::c_char; }
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        live(deadline)?;
        let connected = unsafe { libc::connect(socket.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(),
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t) };
        if connected != 0 {
            // AF_UNIX queue pressure/EINTR is denied; no reconnect or uncertain
            // connect retry is permitted. A real EINPROGRESS completion is one
            // pending connect on this same socket, under the original deadline.
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) { return Err(error.into()); }
            wait(socket.as_raw_fd(), -1, libc::POLLOUT, deadline)?;
            let mut status: libc::c_int = 0;
            let mut length = std::mem::size_of_val(&status) as libc::socklen_t;
            if unsafe { libc::getsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR,
                (&mut status as *mut libc::c_int).cast(), &mut length) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if status != 0 || length as usize != std::mem::size_of_val(&status) {
                return Err(rejected("observer nonblocking connection did not complete"));
            }
        }
        live(deadline)?;
        let credentials = peer_credentials(socket.as_raw_fd())?;
        let peer_pidfd = socket_peer_pidfd(socket.as_raw_fd(), deadline)?;
        let proc_root = open_at(libc::AT_FDCWD, c"/proc", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(proc_root.as_raw_fd(), &mut filesystem) } != 0 || filesystem.f_type != PROC_MAGIC {
            return Err(rejected("observer process custody requires actual procfs"));
        }
        let pid_name = CString::new(credentials.pid.to_string()).map_err(|_| rejected("observer PID encoding failed"))?;
        let peer_proc = open_at(proc_root.as_raw_fd(), &pid_name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let peer_proc_identity = node(&stat_fd(peer_proc.as_raw_fd())?);
        let peer_start = start_ticks(peer_proc.as_raw_fd(), credentials.pid, deadline)?;
        // This single fixed procfs magic link selects the real peer executable.
        let peer_executable = open_at(peer_proc.as_raw_fd(), c"exe", libc::O_RDONLY)?;
        let peer_executable_identity = executable_identity(peer_executable.as_raw_fd())?;
        let measured = verify_static_executable_fd_bounded(peer_executable.as_raw_fd(),
            ExecutableRole::ControllerOwnedRunner, MAX_EXECUTABLE_BYTES, deadline)
            .map_err(|_| rejected("observer peer executable lacks admitted immutable static measurement"))?;
        if measured.content_sha256 != expected_observer_executable {
            return Err(rejected("observer peer executable differs from the independent pin"));
        }
        let held = Self { owner_pid: unsafe { libc::getpid() }, socket, parent, parent_identity, parent_mount,
            socket_identity, peer_pid: credentials.pid, peer_pidfd, peer_proc, peer_proc_identity, peer_start,
            peer_executable, peer_executable_identity, launch, deadline };
        held.verify(deadline)?;
        require_quiet(held.socket.as_raw_fd(), deadline)?;
        transfer_target(held.socket.as_raw_fd(), held.peer_pidfd.as_raw_fd(), target_fds, deadline)?;
        frame(held.socket.as_raw_fd(), held.peer_pidfd.as_raw_fd(), &launch_original, deadline)?;
        let original = receive_frame(held.socket.as_raw_fd(), held.peer_pidfd.as_raw_fd(), MAX_CONTROL_BYTES, deadline)?;
        let ready = BodyObserverReadyV12::parse_original(&original)
            .map_err(|_| rejected("observer ready original is not the closed canonical schema"))?;
        ready.validate_for(&held.launch)
            .map_err(|_| rejected("observer ready original does not join the exact held launch"))?;
        require_quiet(held.socket.as_raw_fd(), deadline)?;
        held.verify(deadline)?;
        Ok(held)
    }

    fn verify(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getegid() } != 0 || deadline > self.deadline {
            return Err(rejected("observer exchange crossed owner identity or original deadline"));
        }
        let parent = endpoint_parent(deadline)?;
        if protected_directory(parent.as_raw_fd())? != self.parent_identity
            || protected_directory(self.parent.as_raw_fd())? != self.parent_identity
            || fd_mount_id(parent.as_raw_fd())? != self.parent_mount
            || fd_mount_id(self.parent.as_raw_fd())? != self.parent_mount
            || endpoint_node(parent.as_raw_fd())? != self.socket_identity
            || endpoint_node(self.parent.as_raw_fd())? != self.socket_identity {
            return Err(rejected("observer endpoint custody changed"));
        }
        let credentials = peer_credentials(self.socket.as_raw_fd())?;
        if credentials.pid != self.peer_pid { return Err(rejected("observer socket peer changed")); }
        pidfd_live(self.peer_pidfd.as_raw_fd())?;
        if node(&stat_fd(self.peer_proc.as_raw_fd())?) != self.peer_proc_identity
            || start_ticks(self.peer_proc.as_raw_fd(), self.peer_pid, deadline)? != self.peer_start {
            return Err(rejected("observer retained process identity changed"));
        }
        let current = open_at(self.peer_proc.as_raw_fd(), c"exe", libc::O_RDONLY)?;
        if executable_identity(current.as_raw_fd())? != self.peer_executable_identity
            || executable_identity(self.peer_executable.as_raw_fd())? != self.peer_executable_identity {
            return Err(rejected("observer no longer executes its held immutable executable"));
        }
        live(deadline)
    }

    pub(super) fn finish(self, claims: &BodyObserverTerminalRequestV12, deadline: u64) -> Result<Vec<u8>> {
        let deadline = deadline.min(self.deadline);
        self.verify(deadline)?;
        let terminal = BodyObserverTerminalV12 { version: TERMINAL_VERSION.to_owned(),
            context_sha256: self.launch.context.context_sha256, target_custody: self.launch.target_custody,
            deadline_boottime_ns: self.deadline, claims: claims.clone() };
        terminal.validate_for(&self.launch)
            .map_err(|_| rejected("observer terminal request differs from held body/output scope"))?;
        let original = terminal.original_bytes()
            .map_err(|_| rejected("observer terminal request cannot encode its closed original"))?;
        require_quiet(self.socket.as_raw_fd(), deadline)?;
        frame(self.socket.as_raw_fd(), self.peer_pidfd.as_raw_fd(), &original, deadline)?;
        live(deadline)?;
        if unsafe { libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_WR) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = receive_frame(self.socket.as_raw_fd(), self.peer_pidfd.as_raw_fd(), MAX_BODY_RESULT_BYTES_V12, deadline)?;
        loop {
            wait(self.socket.as_raw_fd(), self.peer_pidfd.as_raw_fd(), libc::POLLIN, deadline)?;
            let received = receive_once(self.socket.as_raw_fd(), &mut [0u8; 1], deadline)?;
            live(deadline)?;
            match received {
                Some(0) => break,
                Some(_) => return Err(rejected("observer terminal response has trailing bytes")),
                None => {}
            }
        }
        self.verify(deadline)?;
        // Dropping self closes this owned socket and all peer/path duplicates;
        // borrowed target descriptors were never closed or modified here.
        Ok(result)
    }
}
