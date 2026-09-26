//! Unsigned namespace-worker stop data and private one-shot control transport.
//!
//! The inherited channel is AF_UNIX/SOCK_SEQPACKET. The receiving parent must
//! enable SO_PASSCRED before fork: SCM_CREDENTIALS identifies the actual child
//! sender, while socketpair SO_PEERCRED would identify the creating process.
//! No ready, resume, generic command, signature or execution proof is produced.

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use super::super::boottime_ns;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::fd::RawFd;

pub(super) const WORKER_STOP_VERSION: &str = "serverware.controllerBodyObserverNamespaceStop/v12";
pub(super) const MAX_WORKER_CONTROL_BYTES: usize = 4096;
const SCM_PIDFD: libc::c_int = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NamespaceWorkerStopV12 {
    pub(super) version: String,
    pub(super) context_sha256: Digest,
    pub(super) host_target_pid: u32,
    pub(super) target_start_ticks: u64,
    pub(super) target_pidfd_inode: u64,
    pub(super) target_pid_namespace_inode: u64,
    pub(super) host_worker_pid: u32,
    pub(super) namespace_worker_pid: u32,
    pub(super) worker_start_ticks: u64,
    pub(super) observed_at_boottime_ns: u64,
    pub(super) deadline_boottime_ns: u64,
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

struct BoundedBytes(Vec<u8>);
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().checked_add(bytes.len())
            .filter(|length| *length <= MAX_WORKER_CONTROL_BYTES).is_none() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                "namespace worker control exceeds its fixed bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl NamespaceWorkerStopV12 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        if self.version != WORKER_STOP_VERSION || self.context_sha256 == [0; 32]
            || !(2..=i32::MAX as u32).contains(&self.host_target_pid)
            || !(2..=i32::MAX as u32).contains(&self.host_worker_pid)
            || !(2..=i32::MAX as u32).contains(&self.namespace_worker_pid)
            || self.host_worker_pid == self.host_target_pid || self.target_start_ticks == 0
            || self.target_pidfd_inode == 0 || self.target_pid_namespace_inode == 0
            || self.worker_start_ticks == 0 || self.observed_at_boottime_ns == 0
            || self.observed_at_boottime_ns >= self.deadline_boottime_ns {
            return Err(invalid("namespace worker stop lacks its fixed nonzero scope and interval"));
        }
        Ok(())
    }

    pub(super) fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        // The only dynamic member must equal the source-fixed version before
        // encoding. All other fields are fixed-width scalars or one digest.
        self.validate()?;
        let mut output = BoundedBytes(Vec::with_capacity(1024));
        serde_json::to_writer(&mut output, self)?;
        Ok(output.0)
    }

    pub(super) fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        if !(2..=MAX_WORKER_CONTROL_BYTES).contains(&bytes.len()) {
            return Err(invalid("namespace worker stop original exceeds its fixed bound"));
        }
        // Closed typed serde denies unknown/duplicate fields and wrong scalar
        // shapes. Its recursion limit remains active on the bounded original.
        let record: Self = serde_json::from_slice(bytes)?;
        if record.original_bytes()? != bytes {
            return Err(invalid("namespace worker stop is not exact typed canonical JSON"));
        }
        Ok(record)
    }
}

fn live(deadline: u64) -> PlanResult<u64> {
    let now = boottime_ns()?;
    if now >= deadline { return Err(invalid("namespace worker original deadline expired")); }
    Ok(now)
}

fn socket_option(fd: RawFd, name: libc::c_int) -> PlanResult<libc::c_int> {
    let mut value: libc::c_int = -1;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name,
        (&mut value as *mut libc::c_int).cast(), &mut length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of_val(&value) {
        return Err(invalid("namespace worker socket option has an invalid length"));
    }
    Ok(value)
}

fn require_socket(fd: RawFd, peer_pidfd: RawFd, passcred: bool, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    if fd < 0 || peer_pidfd < 0 || fd == peer_pidfd
        || socket_option(fd, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
        || socket_option(fd, libc::SO_PASSCRED)? != (if passcred { 1 } else { 0 }) {
        return Err(invalid("namespace worker control is not the exact inherited seqpacket endpoint"));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || descriptor_flags < 0 { return Err(std::io::Error::last_os_error().into()); }
    if flags & libc::O_NONBLOCK == 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(invalid("namespace worker control lost nonblocking or close-on-exec custody"));
    }
    peer_live(peer_pidfd)?;
    live(deadline)?;
    Ok(())
}

fn peer_live(pidfd: RawFd) -> PlanResult<()> {
    let mut poll = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 { return Err(std::io::Error::last_os_error().into()); }
    if poll.revents != 0 { return Err(invalid("namespace worker control peer has exited or lost its pidfd")); }
    Ok(())
}

fn wait(fd: RawFd, peer_pidfd: RawFd, events: i16, deadline: u64) -> PlanResult<()> {
    loop {
        let now = live(deadline)?;
        let mut polls = [libc::pollfd { fd, events, revents: 0 },
            libc::pollfd { fd: peer_pidfd, events: libc::POLLIN, revents: 0 }];
        let milliseconds = ((deadline - now) / 1_000_000).clamp(1, 100) as i32;
        let count = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, milliseconds) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if polls[1].revents != 0 { return Err(invalid("namespace worker control peer exited during the original interval")); }
        if polls[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(invalid("namespace worker control socket failed"));
        }
        if polls[0].revents & (events | libc::POLLHUP) != 0 { return Ok(()); }
    }
}

struct Ancillary { credentials: Option<libc::ucred>, invalid: bool }

fn inspect_ancillary(message: &libc::msghdr) -> Ancillary {
    let mut result = Ancillary { credentials: None,
        invalid: message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 };
    // Kernel-returned cmsg lengths are bounded again before reading their data.
    // Rights (including automatically supplied SCM_PIDFD) are always closed,
    // even when another cmsg, truncation, or a later deadline causes denial.
    unsafe {
        let start = message.msg_control as usize;
        let end = start + message.msg_controllen;
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let address = header as usize;
            if address < start || address > end || end - address < std::mem::size_of::<libc::cmsghdr>() {
                result.invalid = true;
                break;
            }
            let minimum = libc::CMSG_LEN(0) as usize;
            let length = (*header).cmsg_len;
            if length < minimum || length > end - address {
                result.invalid = true;
            }
            let available = (end - address).saturating_sub(minimum);
            let payload = length.saturating_sub(minimum).min(available);
            if (*header).cmsg_level == libc::SOL_SOCKET
                && matches!((*header).cmsg_type, libc::SCM_RIGHTS | SCM_PIDFD) {
                for index in 0..payload / std::mem::size_of::<RawFd>() {
                    let received = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index));
                    libc::close(received);
                }
                result.invalid = true;
            } else if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_CREDENTIALS
                && payload == std::mem::size_of::<libc::ucred>() && length == minimum + payload {
                let credentials = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
                if result.credentials.replace(credentials).is_some() { result.invalid = true; }
            } else { result.invalid = true; }
            if length < minimum || length > end - address { break; }
            header = libc::CMSG_NXTHDR(message, header);
        }
        if message.msg_controllen != 0 && libc::CMSG_FIRSTHDR(message).is_null() { result.invalid = true; }
    }
    result
}

struct Packet { count: usize, credentials: Option<libc::ucred> }

fn receive_once(fd: RawFd, bytes: &mut [u8], deadline: u64) -> PlanResult<Option<Packet>> {
    loop {
        live(deadline)?;
        let mut control = [0usize; 64];
        let mut io = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut io;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            live(deadline)?;
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            if error.kind() == std::io::ErrorKind::WouldBlock { return Ok(None); }
            return Err(error.into());
        }
        let ancillary = inspect_ancillary(&message);
        // Descriptor cleanup above precedes every late-success error.
        live(deadline)?;
        if ancillary.invalid || count as usize > bytes.len() {
            return Err(invalid("namespace worker packet has forbidden or truncated ancillary data"));
        }
        return Ok(Some(Packet { count: count as usize, credentials: ancillary.credentials }));
    }
}

pub(super) fn send_stop(fd: RawFd, parent_pidfd: RawFd, record: &NamespaceWorkerStopV12, deadline: u64) -> PlanResult<()> {
    require_socket(fd, parent_pidfd, false, deadline)?;
    let now = live(deadline)?;
    if record.deadline_boottime_ns != deadline || record.observed_at_boottime_ns > now
        || record.namespace_worker_pid != unsafe { libc::getpid() } as u32 {
        return Err(invalid("namespace worker stop differs from its actual sender or original time"));
    }
    let bytes = record.original_bytes()?;
    loop {
        wait(fd, parent_pidfd, libc::POLLOUT, deadline)?;
        // No sender-supplied credentials or FDs: the parent's pre-enabled
        // SO_PASSCRED makes the kernel attach this child's actual credentials.
        let count = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) { continue; }
            return Err(error.into());
        }
        if count as usize != bytes.len() { return Err(invalid("namespace worker stop packet was not sent atomically")); }
        peer_live(parent_pidfd)?;
        return Ok(());
    }
}

pub(super) fn receive_stop(fd: RawFd, worker_pidfd: RawFd, expected_worker_host_pid: u32, deadline: u64)
    -> PlanResult<NamespaceWorkerStopV12> {
    require_socket(fd, worker_pidfd, true, deadline)?;
    if !(2..=i32::MAX as u32).contains(&expected_worker_host_pid) {
        return Err(invalid("namespace worker receiver lacks an exact child host PID"));
    }
    let mut bytes = [0u8; MAX_WORKER_CONTROL_BYTES];
    let packet = loop {
        wait(fd, worker_pidfd, libc::POLLIN, deadline)?;
        if let Some(packet) = receive_once(fd, &mut bytes, deadline)? { break packet; }
    };
    let credentials = packet.credentials.ok_or_else(|| invalid("namespace worker stop lacks kernel sender credentials"))?;
    if credentials.pid <= 1 || credentials.pid as u32 != expected_worker_host_pid
        || credentials.uid != 0 || credentials.gid != 0 {
        return Err(invalid("namespace worker stop credentials do not identify the exact root child"));
    }
    let record = NamespaceWorkerStopV12::parse_original(&bytes[..packet.count])?;
    if record.host_worker_pid != expected_worker_host_pid || record.deadline_boottime_ns != deadline
        || record.observed_at_boottime_ns > live(deadline)? {
        return Err(invalid("namespace worker stop differs from child custody or original time"));
    }
    // This is one record, not a stream or a reusable RPC. Do not accept an
    // already queued second packet (including empty packets or premature EOF).
    if receive_once(fd, &mut [0u8; 1], deadline)?.is_some() {
        return Err(invalid("namespace worker sent additional stop-control packets or early EOF"));
    }
    peer_live(worker_pidfd)?;
    live(deadline)?;
    Ok(record)
}

pub(super) fn wait_for_abort(fd: RawFd, parent_pidfd: RawFd, deadline: u64) -> PlanResult<()> {
    require_socket(fd, parent_pidfd, false, deadline)?;
    let mut bytes = [0u8; 2];
    loop {
        wait(fd, parent_pidfd, libc::POLLIN, deadline)?;
        let Some(packet) = receive_once(fd, &mut bytes, deadline)? else { continue; };
        if packet.credentials.is_some() { return Err(invalid("namespace worker abort must not carry ancillary credentials")); }
        if packet.count == 0 { return require_eof(fd, deadline); }
        if packet.count != 1 || bytes[0] != b'A' { return Err(invalid("namespace worker control permits only abort")); }
        if let Some(extra) = receive_once(fd, &mut [0u8; 1], deadline)? {
            if extra.count != 0 || extra.credentials.is_some() {
                return Err(invalid("namespace worker abort contains additional packets"));
            }
            require_eof(fd, deadline)?;
        }
        // Returning only tells the worker to exit. There is no resume branch.
        peer_live(parent_pidfd)?;
        live(deadline)?;
        return Ok(());
    }
}

fn require_eof(fd: RawFd, deadline: u64) -> PlanResult<()> {
    // A zero-length seqpacket is not itself EOF. Require the kernel's actual
    // read-side shutdown/hangup observation before accepting a zero result.
    live(deadline)?;
    let mut poll = libc::pollfd { fd, events: libc::POLLRDHUP, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        || poll.revents & (libc::POLLRDHUP | libc::POLLHUP) == 0 {
        return Err(invalid("namespace worker zero-length packet is not actual EOF"));
    }
    Ok(())
}
