//! One-use observer-side launch receipt. Every delivered right is adopted
//! before errors can return; only the first `L` byte may carry exactly nine.

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use crate::plan_protocol::body_observer_contract_v12::{
    BodyObserverLaunchV12, MAX_LAUNCH_BYTES, SOCKET_PATH,
};
use crate::runtime_evidence::{verify_static_executable_fd_bounded, ExecutableRole};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const SCM_PIDFD: libc::c_int = 0x04;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x10;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }
fn now() -> PlanResult<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(invalid("observer receiver boot clock is invalid"));
    }
    (time.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| invalid("observer receiver boot clock overflowed"))
}
fn live(deadline: u64) -> PlanResult<()> {
    if now()? >= deadline { return Err(invalid("observer receipt original deadline expired")); }
    Ok(())
}
fn root() -> PlanResult<()> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(invalid("observer receipt requires its actual root service owner"));
    }
    Ok(())
}
fn stat(fd: RawFd) -> PlanResult<libc::stat> {
    let mut value = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(value)
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Node { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
fn node(value: &libc::stat) -> Node {
    Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid }
}
fn open_at(parent: RawFd, name: &CStr, flags: i32) -> PlanResult<OwnedFd> {
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn protected_directory(fd: RawFd) -> PlanResult<Node> {
    let value = stat(fd)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_uid != 0
        || value.st_gid != 0 || value.st_mode & 0o022 != 0 {
        return Err(invalid("observer endpoint ancestor is not protected root storage"));
    }
    Ok(node(&value))
}
fn endpoint_parent(deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let mut directory = open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    protected_directory(directory.as_raw_fd())?;
    let (parent, _) = SOCKET_PATH.rsplit_once('/').ok_or_else(|| invalid("fixed observer endpoint lacks parent"))?;
    for component in parent[1..].split('/') {
        live(deadline)?;
        let name = CString::new(component).map_err(|_| invalid("fixed observer endpoint contains NUL"))?;
        directory = open_at(directory.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        protected_directory(directory.as_raw_fd())?;
    }
    Ok(directory)
}
fn endpoint_node(parent: RawFd) -> PlanResult<Node> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, c"control.sock".as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.st_mode & libc::S_IFMT != libc::S_IFSOCK || value.st_uid != 0 || value.st_gid != 0
        || value.st_nlink != 1 || value.st_mode & 0o022 != 0 {
        return Err(invalid("observer local endpoint lost protected socket ownership"));
    }
    Ok(node(&value))
}
fn integer_option(socket: RawFd, option: i32) -> PlanResult<i32> {
    let mut value: i32 = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(socket, libc::SOL_SOCKET, option,
        (&mut value as *mut i32).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of_val(&value) { return Err(invalid("observer socket option has wrong size")); }
    Ok(value)
}
fn local_endpoint(socket: RawFd) -> PlanResult<()> {
    if integer_option(socket, libc::SO_DOMAIN)? != libc::AF_UNIX
        || integer_option(socket, libc::SO_TYPE)? != libc::SOCK_STREAM
        || integer_option(socket, libc::SO_ACCEPTCONN)? != 0
        || integer_option(socket, libc::SO_PASSPIDFD)? != 0 {
        return Err(invalid("observer receipt requires one accepted Unix stream"));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe { libc::getsockname(socket, (&mut address as *mut libc::sockaddr_un).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    if address.sun_family as i32 != libc::AF_UNIX
        || length as usize != offset + SOCKET_PATH.len() + 1
        || address.sun_path[SOCKET_PATH.len()] != 0
        || !address.sun_path[..SOCKET_PATH.len()].iter().zip(SOCKET_PATH.bytes())
            .all(|(actual, expected)| *actual as u8 == expected) {
        return Err(invalid("observer accepted socket is not at the source-fixed endpoint"));
    }
    let flags = unsafe { libc::fcntl(socket, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(invalid("observer accepted socket lacks close-on-exec custody"));
    }
    Ok(())
}
fn peer_credentials(socket: RawFd) -> PlanResult<libc::ucred> {
    let mut value: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(socket, libc::SOL_SOCKET, libc::SO_PEERCRED,
        (&mut value as *mut libc::ucred).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of_val(&value) || value.pid <= 1 || value.uid != 0 || value.gid != 0 {
        return Err(invalid("observer launch peer is not an actual root controller process"));
    }
    Ok(value)
}
fn peer_pidfd(socket: RawFd, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let mut raw: RawFd = -1;
    let mut length = std::mem::size_of_val(&raw) as libc::socklen_t;
    if unsafe { libc::getsockopt(socket, libc::SOL_SOCKET, libc::SO_PEERPIDFD,
        (&mut raw as *mut RawFd).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if raw < 0 { return Err(invalid("observer peer-pidfd option returned no descriptor")); }
    // Adopt before any shape/deadline/flag failure. No numeric PID reopen.
    let held = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    if length as usize != std::mem::size_of_val(&raw) { return Err(invalid("observer peer-pidfd size differs")); }
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let actual = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if actual < 0 || actual & libc::FD_CLOEXEC == 0 {
        return Err(invalid("observer peer pidfd lacks close-on-exec custody"));
    }
    pidfd_live(raw)?;
    live(deadline)?;
    Ok(held)
}
fn pidfd_live(fd: RawFd) -> PlanResult<()> {
    let mut descriptor = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let count = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if count < 0 { return Err(std::io::Error::last_os_error().into()); }
    if count != 0 || descriptor.revents != 0 { return Err(invalid("observer controller peer is no longer live")); }
    Ok(())
}
fn read_small(parent: RawFd, name: &CStr, deadline: u64) -> PlanResult<Vec<u8>> {
    let fd = open_at(parent, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
    let mut bytes = vec![0u8; 16 * 1024 + 1];
    let mut length = 0;
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(fd.as_raw_fd(), bytes[length..].as_mut_ptr().cast(),
            bytes.len() - length, length as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { bytes.truncate(length); return Ok(bytes); }
        length += count as usize;
        if length == bytes.len() { return Err(invalid("observer peer kernel record exceeds bound")); }
    }
}
fn start_ticks(process: RawFd, pid: libc::pid_t, deadline: u64) -> PlanResult<u64> {
    let bytes = read_small(process, c"stat", deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("observer peer stat is not UTF8"))?;
    let open = text.find('(').ok_or_else(|| invalid("observer peer stat lacks command"))?;
    let close = text.rfind(')').ok_or_else(|| invalid("observer peer stat lacks command end"))?;
    if close <= open || text[..open].trim().parse::<i32>().ok() != Some(pid) {
        return Err(invalid("observer peer stat belongs to another PID"));
    }
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let state = fields.next().ok_or_else(|| invalid("observer peer state missing"))?;
    if state.len() != 1 || matches!(state, "Z" | "X" | "x") { return Err(invalid("observer peer already exited")); }
    fields.nth(18).and_then(|value| value.parse::<u64>().ok()).filter(|value| *value != 0)
        .ok_or_else(|| invalid("observer peer start ticks invalid"))
}
#[derive(Eq, PartialEq)]
struct ExecutableIdentity { node: Node, links: u64, size: i64,
    modified: i64, modified_ns: i64, changed: i64, changed_ns: i64 }
fn executable_identity(fd: RawFd) -> PlanResult<ExecutableIdentity> {
    let value = stat(fd)?;
    let mut flags: libc::c_uint = 0;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_uid != 0 || value.st_gid != 0
        || value.st_nlink != 1 || value.st_mode & 0o022 != 0 || value.st_size <= 0
        || value.st_size as u64 > MAX_EXECUTABLE_BYTES
        || unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0 || flags & FS_IMMUTABLE_FL == 0 {
        return Err(invalid("observer controller executable lacks immutable root custody"));
    }
    Ok(ExecutableIdentity { node: node(&value), links: value.st_nlink, size: value.st_size,
        modified: value.st_mtime, modified_ns: value.st_mtime_nsec,
        changed: value.st_ctime, changed_ns: value.st_ctime_nsec })
}

struct Received { length: usize, rights: Vec<OwnedFd>, ancillary: bool }
fn receive_once(socket: RawFd, bytes: &mut [u8], deadline: u64) -> PlanResult<Option<Received>> {
    loop {
        live(deadline)?;
        let mut control = [0usize; 64];
        let mut io = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut io;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            live(deadline)?;
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            if error.kind() == std::io::ErrorKind::WouldBlock { return Ok(None); }
            return Err(error.into());
        }
        // The kernel bounds/constructs these headers. Adopt every delivered
        // right before any error, even if the message was truncated or late.
        let mut rights = Vec::new();
        let mut invalid_control = message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
        let mut rights_headers = 0;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && matches!((*header).cmsg_type, libc::SCM_RIGHTS | SCM_PIDFD) {
                    if (*header).cmsg_type == libc::SCM_RIGHTS { rights_headers += 1; }
                    else {
                        // This option is denied before reads, but still adopt
                        // any kernel-installed pidfd before rejecting it.
                        invalid_control = true;
                    }
                    let length = (*header).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    if length == 0 || length % std::mem::size_of::<RawFd>() != 0 { invalid_control = true; }
                    for index in 0..length / std::mem::size_of::<RawFd>() {
                        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index));
                        if fd < 0 { invalid_control = true; } else { rights.push(OwnedFd::from_raw_fd(fd)); }
                    }
                } else { invalid_control = true; }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        live(deadline)?;
        if invalid_control || rights_headers > 1 {
            return Err(invalid("observer request has truncated or forbidden ancillary data"));
        }
        return Ok(Some(Received { length: count as usize, rights, ancillary: message.msg_controllen != 0 }));
    }
}

pub(super) struct ObserverLaunchChannelV12 {
    owner: libc::pid_t,
    socket: OwnedFd,
    parent: OwnedFd,
    parent_identity: Node,
    socket_identity: Node,
    peer_pid: libc::pid_t,
    peer_pidfd: OwnedFd,
    peer_proc: OwnedFd,
    peer_proc_identity: Node,
    peer_start: u64,
    peer_executable: OwnedFd,
    peer_executable_identity: ExecutableIdentity,
    deadline: u64,
}
pub(super) struct ReceivedObserverLaunchV12 {
    pub(super) channel: ObserverLaunchChannelV12,
    pub(super) launch: BodyObserverLaunchV12,
    pub(super) target_fds: [OwnedFd; 9],
    pub(super) deadline: u64,
}
impl ObserverLaunchChannelV12 {
    pub(super) fn receive(socket: OwnedFd, expected_controller: Digest, deadline: u64) -> PlanResult<ReceivedObserverLaunchV12> {
        root()?;
        live(deadline)?;
        if expected_controller == [0; 32] { return Err(invalid("observer receipt lacks independent controller pin")); }
        local_endpoint(socket.as_raw_fd())?;
        let parent = endpoint_parent(deadline)?;
        let parent_identity = protected_directory(parent.as_raw_fd())?;
        let socket_identity = endpoint_node(parent.as_raw_fd())?;
        let credentials = peer_credentials(socket.as_raw_fd())?;
        let peer_pidfd = peer_pidfd(socket.as_raw_fd(), deadline)?;
        let proc_root = open_at(libc::AT_FDCWD, c"/proc", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(proc_root.as_raw_fd(), &mut filesystem) } != 0 || filesystem.f_type != PROC_MAGIC {
            return Err(invalid("observer controller custody requires actual procfs"));
        }
        let pid_name = CString::new(credentials.pid.to_string()).map_err(|_| invalid("observer peer PID encoding failed"))?;
        let peer_proc = open_at(proc_root.as_raw_fd(), &pid_name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let peer_proc_identity = node(&stat(peer_proc.as_raw_fd())?);
        let peer_start = start_ticks(peer_proc.as_raw_fd(), credentials.pid, deadline)?;
        let peer_executable = open_at(peer_proc.as_raw_fd(), c"exe", libc::O_RDONLY)?;
        let peer_executable_identity = executable_identity(peer_executable.as_raw_fd())?;
        let actual = verify_static_executable_fd_bounded(peer_executable.as_raw_fd(),
            ExecutableRole::ControllerOwnedRunner, MAX_EXECUTABLE_BYTES, deadline)?;
        if actual.content_sha256 != expected_controller { return Err(invalid("observer controller peer differs from admitted executable")); }
        let mut channel = Self { owner: unsafe { libc::getpid() }, socket, parent, parent_identity, socket_identity,
            peer_pid: credentials.pid, peer_pidfd, peer_proc, peer_proc_identity, peer_start,
            peer_executable, peer_executable_identity, deadline };
        channel.verify(deadline)?;
        let mut byte = [0u8; 1];
        let received = loop {
            channel.wait(deadline)?;
            if let Some(received) = receive_once(channel.socket.as_raw_fd(), &mut byte, deadline)? { break received; }
        };
        if received.length != 1 || byte != [b'L'] || !received.ancillary || received.rights.len() != 9 {
            return Err(invalid("observer launch must begin with L and exactly nine descriptors"));
        }
        let target_fds: [OwnedFd; 9] = received.rights.try_into()
            .map_err(|_| invalid("observer target descriptor count differs"))?;
        for fd in &target_fds {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            if flags < 0 || flags & libc::FD_CLOEXEC == 0 { return Err(invalid("received target descriptor lacks close-on-exec")); }
        }
        let mut header = [0u8; 4];
        channel.receive_exact(&mut header, deadline)?;
        let length = u32::from_be_bytes(header) as usize;
        if !(2..=MAX_LAUNCH_BYTES).contains(&length) { return Err(invalid("observer launch frame exceeds fixed bound")); }
        let mut bytes = vec![0u8; length];
        channel.receive_exact(&mut bytes, deadline)?;
        let launch = BodyObserverLaunchV12::parse_original(&bytes)?;
        channel.deadline = deadline.min(launch.deadline_boottime_ns);
        channel.verify_pending(channel.deadline)?;
        let deadline = channel.deadline;
        Ok(ReceivedObserverLaunchV12 { channel, launch, target_fds, deadline })
    }

    fn wait(&self, deadline: u64) -> PlanResult<()> {
        loop {
            let current = now()?;
            if current >= deadline { return Err(invalid("observer launch receive deadline expired")); }
            let mut descriptors = [libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.peer_pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
            let milliseconds = ((deadline - current) / 1_000_000).clamp(1, 100) as i32;
            let count = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, milliseconds) };
            let error = (count < 0).then(std::io::Error::last_os_error);
            live(deadline)?;
            if let Some(error) = error {
                if error.kind() == std::io::ErrorKind::Interrupted { continue; }
                return Err(error.into());
            }
            if descriptors[1].revents != 0 { return Err(invalid("controller peer exited during observer receipt")); }
            if descriptors[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 { return Err(invalid("observer request socket failed")); }
            if descriptors[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 { return Ok(()); }
        }
    }

    fn receive_exact(&self, mut bytes: &mut [u8], deadline: u64) -> PlanResult<()> {
        while !bytes.is_empty() {
            self.wait(deadline)?;
            if let Some(received) = receive_once(self.socket.as_raw_fd(), bytes, deadline)? {
                if received.ancillary || !received.rights.is_empty() {
                    return Err(invalid("observer launch frame carried additional descriptors"));
                }
                if received.length == 0 { return Err(invalid("observer launch ended before declared length")); }
                bytes = &mut bytes[received.length..];
            }
        }
        Ok(())
    }

    fn verify(&self, deadline: u64) -> PlanResult<()> {
        root()?;
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner || deadline > self.deadline {
            return Err(invalid("observer receipt crossed owner or original deadline"));
        }
        local_endpoint(self.socket.as_raw_fd())?;
        let current_parent = endpoint_parent(deadline)?;
        if protected_directory(current_parent.as_raw_fd())? != self.parent_identity
            || protected_directory(self.parent.as_raw_fd())? != self.parent_identity
            || endpoint_node(current_parent.as_raw_fd())? != self.socket_identity
            || endpoint_node(self.parent.as_raw_fd())? != self.socket_identity {
            return Err(invalid("observer accepted endpoint custody changed"));
        }
        let credentials = peer_credentials(self.socket.as_raw_fd())?;
        pidfd_live(self.peer_pidfd.as_raw_fd())?;
        if credentials.pid != self.peer_pid || node(&stat(self.peer_proc.as_raw_fd())?) != self.peer_proc_identity
            || start_ticks(self.peer_proc.as_raw_fd(), self.peer_pid, deadline)? != self.peer_start {
            return Err(invalid("observer controller process identity changed"));
        }
        let current_executable = open_at(self.peer_proc.as_raw_fd(), c"exe", libc::O_RDONLY)?;
        if executable_identity(current_executable.as_raw_fd())? != self.peer_executable_identity
            || executable_identity(self.peer_executable.as_raw_fd())? != self.peer_executable_identity {
            return Err(invalid("observer controller executable custody changed"));
        }
        pidfd_live(self.peer_pidfd.as_raw_fd())?;
        live(deadline)
    }

    pub(super) fn verify_pending(&self, deadline: u64) -> PlanResult<()> {
        self.verify(deadline)?;
        if receive_once(self.socket.as_raw_fd(), &mut [0u8; 1], deadline)?.is_some() {
            return Err(invalid("observer launch has premature bytes or closed before readiness"));
        }
        self.verify(deadline)
    }
}
