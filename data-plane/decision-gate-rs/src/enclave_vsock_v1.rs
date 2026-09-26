//! Fixed inbound AF_VSOCK transport, not peer authentication or enclave proof.
//!
//! Linux assigns CID 2 to VMADDR_CID_HOST; AWS Nitro uses CID 3 for the parent
//! instance. The independently supplied expected CID is compared exactly; no
//! default, TLS identity, secret authority or attestation is inferred from it.
//! See https://man7.org/linux/man-pages/man7/vsock.7.html and
//! https://docs.aws.amazon.com/enclaves/latest/user/enclave-networking.html.
//!
//! All data sockets are nonblocking. ppoll waits use remaining CLOCK_BOOTTIME
//! time in bounded slices; interruption, spurious readiness and partial IO do
//! not renew an operation deadline. Scheduling/kernel delays are not hard
//! realtime cancellation. There is no outbound connector, raw-FD export,
//! stream clone or generic forwarding operation.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const CID_ANY: u32 = u32::MAX;
const MAX_IO_BYTES: usize = 64 * 1024;
const POLL_SLICE_NS: u64 = 100_000_000;
const LISTEN_BACKLOG: libc::c_int = 128;

// Linux vm_sockets.h: host-endian fields, 16 bytes. No routing flags are used.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct Address {
    family: libc::sa_family_t,
    reserved: u16,
    port: u32,
    cid: u32,
    flags: u8,
    zero: [u8; 3],
}
const _: [(); 16] = [(); std::mem::size_of::<Address>()];

fn error(kind: io::ErrorKind, message: &'static str) -> io::Error { io::Error::new(kind, message) }

fn now() -> io::Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(error(io::ErrorKind::InvalidData, "vsock boottime sample is invalid"));
    }
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| error(io::ErrorKind::InvalidData, "vsock boottime sample overflows"))
}

fn remaining(deadline: u64) -> io::Result<u64> {
    deadline.checked_sub(now()?).filter(|value| *value != 0)
        .ok_or_else(|| error(io::ErrorKind::TimedOut, "vsock original deadline expired"))
}

fn valid_port(port: u32) -> bool { port > 1023 && port != u32::MAX }
fn valid_peer_cid(cid: u32) -> bool { cid >= 2 && cid != CID_ANY }

fn socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option,
        (&mut value as *mut libc::c_int).cast(), &mut length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&value) {
        return Err(error(io::ErrorKind::InvalidData, "vsock socket option has an invalid length"));
    }
    Ok(value)
}

fn address(fd: RawFd, peer: bool) -> io::Result<Address> {
    let mut value: Address = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<Address>() as libc::socklen_t;
    let pointer = (&mut value as *mut Address).cast::<libc::sockaddr>();
    let status = unsafe {
        if peer { libc::getpeername(fd, pointer, &mut length) }
        else { libc::getsockname(fd, pointer, &mut length) }
    };
    if status != 0 { return Err(io::Error::last_os_error()); }
    if length as usize != std::mem::size_of::<Address>()
        || value.family != libc::AF_VSOCK as libc::sa_family_t
        || value.reserved != 0 || value.flags != 0 || value.zero != [0; 3]
        || !valid_port(value.port) {
        return Err(error(io::ErrorKind::InvalidData, "vsock address has an invalid type, length or value"));
    }
    Ok(value)
}

struct SocketOwner {
    fd: OwnedFd,
    pid: libc::pid_t,
    device: u64,
    inode: u64,
    flags: libc::c_int,
}

impl SocketOwner {
    fn acquire(fd: OwnedFd, pid: libc::pid_t) -> io::Result<Self> {
        if unsafe { libc::getpid() } != pid {
            return Err(error(io::ErrorKind::PermissionDenied, "vsock owner process changed"));
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_ino == 0 || flags < 0
            || flags & libc::O_NONBLOCK == 0 || flags & libc::O_ACCMODE != libc::O_RDWR
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } != libc::FD_CLOEXEC
            || socket_option(fd.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
            || socket_option(fd.as_raw_fd(), libc::SO_DOMAIN)? != libc::AF_VSOCK {
            return Err(error(io::ErrorKind::InvalidData, "vsock descriptor type or flags are invalid"));
        }
        Ok(Self { fd, pid, device: stat.st_dev as u64, inode: stat.st_ino as u64, flags })
    }

    fn check(&self) -> io::Result<()> {
        if unsafe { libc::getpid() } != self.pid {
            return Err(error(io::ErrorKind::PermissionDenied, "vsock owner process changed"));
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(self.fd.as_raw_fd(), &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_dev as u64 != self.device
            || stat.st_ino as u64 != self.inode
            || unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) } != self.flags
            || unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) } != libc::FD_CLOEXEC {
            return Err(error(io::ErrorKind::InvalidData, "vsock retained descriptor changed"));
        }
        Ok(())
    }

    fn poll(&self, events: libc::c_short, deadline: u64,
        closed: Option<&AtomicBool>) -> io::Result<libc::c_short> {
        loop {
            self.check()?;
            if closed.is_some_and(|value| value.load(Ordering::Acquire)) {
                return Err(error(io::ErrorKind::NotConnected, "vsock session was shut down"));
            }
            let wait = remaining(deadline)?.min(POLL_SLICE_NS);
            let timeout = libc::timespec { tv_sec: 0, tv_nsec: wait as libc::c_long };
            let mut item = libc::pollfd { fd: self.fd.as_raw_fd(), events, revents: 0 };
            let status = unsafe { libc::ppoll(&mut item, 1, &timeout, std::ptr::null()) };
            if status < 0 {
                let failure = io::Error::last_os_error();
                if failure.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(failure);
            }
            self.check()?;
            remaining(deadline)?;
            if closed.is_some_and(|value| value.load(Ordering::Acquire)) {
                return Err(error(io::ErrorKind::NotConnected, "vsock session was shut down"));
            }
            if status == 0 { continue; }
            if status != 1 || item.revents & libc::POLLNVAL != 0
                || item.revents & !(events | libc::POLLERR | libc::POLLHUP) != 0 {
                return Err(error(io::ErrorKind::InvalidData, "vsock poll returned invalid events"));
            }
            if item.revents != 0 { return Ok(item.revents); }
        }
    }
}

pub struct VsockListenerV1 {
    socket: SocketOwner,
    local: Address,
    expected_peer_cid: u32,
    deadline: u64,
}

impl VsockListenerV1 {
    pub fn bind(port: u32, expected_peer_cid: u32, deadline: u64) -> io::Result<Self> {
        if !valid_port(port) || !valid_peer_cid(expected_peer_cid) {
            return Err(error(io::ErrorKind::InvalidInput, "vsock fixed port or expected peer CID is invalid"));
        }
        remaining(deadline)?;
        let pid = unsafe { libc::getpid() };
        let fd = unsafe { libc::socket(libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let socket = SocketOwner::acquire(unsafe { OwnedFd::from_raw_fd(fd) }, pid)?;
        remaining(deadline)?;
        let local = Address { family: libc::AF_VSOCK as _, reserved: 0,
            port, cid: CID_ANY, flags: 0, zero: [0; 3] };
        if unsafe { libc::bind(socket.fd.as_raw_fd(), (&local as *const Address).cast(),
            std::mem::size_of::<Address>() as libc::socklen_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        remaining(deadline)?;
        if unsafe { libc::listen(socket.fd.as_raw_fd(), LISTEN_BACKLOG) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = Self { socket, local, expected_peer_cid, deadline };
        listener.check(deadline)?;
        Ok(listener)
    }

    fn check(&self, deadline: u64) -> io::Result<()> {
        self.socket.check()?;
        remaining(deadline)?;
        if address(self.socket.fd.as_raw_fd(), false)? != self.local
            || socket_option(self.socket.fd.as_raw_fd(), libc::SO_ACCEPTCONN)? != 1 {
            return Err(error(io::ErrorKind::InvalidData, "vsock listener identity changed"));
        }
        remaining(deadline).map(|_| ())
    }

    /// The returned session retains the clipped accept/session deadline.
    /// A denied peer is closed immediately and is never returned as a stream.
    pub fn accept(&self, deadline: u64) -> io::Result<VsockStreamV1> {
        let deadline = self.deadline.min(deadline);
        loop {
            self.check(deadline)?;
            let fd = unsafe { libc::accept4(self.socket.fd.as_raw_fd(), std::ptr::null_mut(),
                std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) };
            if fd < 0 {
                let failure = io::Error::last_os_error();
                if failure.kind() == io::ErrorKind::Interrupted { continue; }
                if failure.kind() != io::ErrorKind::WouldBlock { return Err(failure); }
                let events = self.socket.poll(libc::POLLIN, deadline, None)?;
                if events & (libc::POLLERR | libc::POLLHUP) != 0 {
                    return Err(error(io::ErrorKind::ConnectionAborted, "vsock listener failed"));
                }
                continue;
            }
            let socket = SocketOwner::acquire(unsafe { OwnedFd::from_raw_fd(fd) }, self.socket.pid)?;
            let admitted = (|| {
                self.check(deadline)?;
                let peer = address(socket.fd.as_raw_fd(), true)?;
                let local = address(socket.fd.as_raw_fd(), false)?;
                if peer.cid != self.expected_peer_cid || !valid_peer_cid(local.cid)
                    || local.port != self.local.port
                    || socket_option(socket.fd.as_raw_fd(), libc::SO_ACCEPTCONN)? != 0 {
                    return Err(error(io::ErrorKind::PermissionDenied, "vsock accepted peer or local scope was denied"));
                }
                socket.check()?;
                remaining(deadline)?;
                Ok(peer)
            })();
            let peer = match admitted {
                Ok(peer) => peer,
                Err(failure) => {
                    // No caller sees this FD; close after shutting down both directions.
                    unsafe { libc::shutdown(socket.fd.as_raw_fd(), libc::SHUT_RDWR); }
                    return Err(failure);
                }
            };
            return Ok(VsockStreamV1 { socket, peer, deadline, read_timeout_ns: AtomicU64::new(0),
                write_timeout_ns: AtomicU64::new(0), closed: Arc::new(AtomicBool::new(false)) });
        }
    }
}

pub struct VsockStreamV1 {
    socket: SocketOwner,
    peer: Address,
    deadline: u64,
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
    closed: Arc<AtomicBool>,
}

impl VsockStreamV1 {
    /// Cached routing metadata, not an authenticated principal.
    pub fn peer_cid(&self) -> u32 { self.peer.cid }
    pub fn peer_port(&self) -> u32 { self.peer.port }

    fn check(&self, deadline: u64) -> io::Result<()> {
        self.socket.check()?;
        remaining(deadline)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(error(io::ErrorKind::NotConnected, "vsock session was shut down"));
        }
        Ok(())
    }

    fn operation_deadline(&self, timeout: &AtomicU64) -> io::Result<u64> {
        self.check(self.deadline)?;
        let duration = timeout.load(Ordering::Acquire);
        Ok(if duration == 0 { self.deadline }
            else { self.deadline.min(now()?.saturating_add(duration)) })
    }

    fn set_timeout(&self, destination: &AtomicU64, timeout: Option<Duration>) -> io::Result<()> {
        self.check(self.deadline)?;
        let nanoseconds = match timeout {
            None => 0,
            Some(value) if !value.is_zero() && value.as_nanos() <= u64::MAX as u128 => value.as_nanos() as u64,
            Some(_) => return Err(error(io::ErrorKind::InvalidInput, "vsock timeout must be positive and bounded")),
        };
        destination.store(nanoseconds, Ordering::Release);
        Ok(())
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_timeout(&self.read_timeout_ns, timeout)
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_timeout(&self.write_timeout_ns, timeout)
    }

    /// Cancellation remains available after expiry; it never permits more IO.
    pub fn shutdown(&self) -> io::Result<()> { shutdown(&self.socket, &self.closed) }

    /// A separate owner may cancel an active session without acquiring IO or
    /// raw-descriptor authority. Its private duplicate cannot be exported.
    pub fn shutdown_handle(&self) -> io::Result<VsockShutdownV1> {
        self.check(self.deadline)?;
        let fd = unsafe { libc::fcntl(self.socket.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let socket = SocketOwner::acquire(unsafe { OwnedFd::from_raw_fd(fd) }, self.socket.pid)?;
        if socket.device != self.socket.device || socket.inode != self.socket.inode {
            return Err(error(io::ErrorKind::InvalidData, "vsock cancellation duplicate changed identity"));
        }
        self.check(self.deadline)?;
        Ok(VsockShutdownV1 { socket, closed: Arc::clone(&self.closed) })
    }
}

/// Cross-thread cancellation only. Not Clone; no IO or FD access is exposed.
pub struct VsockShutdownV1 { socket: SocketOwner, closed: Arc<AtomicBool> }

impl VsockShutdownV1 {
    pub fn shutdown(&self) -> io::Result<()> { shutdown(&self.socket, &self.closed) }
}

fn shutdown(socket: &SocketOwner, closed: &AtomicBool) -> io::Result<()> {
    socket.check()?;
    closed.store(true, Ordering::Release);
    if unsafe { libc::shutdown(socket.fd.as_raw_fd(), libc::SHUT_RDWR) } != 0 {
        let failure = io::Error::last_os_error();
        if failure.raw_os_error() != Some(libc::ENOTCONN) { return Err(failure); }
    }
    Ok(())
}

impl Read for VsockStreamV1 {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let deadline = self.operation_deadline(&self.read_timeout_ns)?;
        if buffer.is_empty() { return Ok(0); }
        let mut terminal_ready = false;
        loop {
            self.check(deadline)?;
            let count = unsafe { libc::recv(self.socket.fd.as_raw_fd(), buffer.as_mut_ptr().cast(),
                buffer.len().min(MAX_IO_BYTES), libc::MSG_DONTWAIT) };
            if count >= 0 { self.check(deadline)?; return Ok(count as usize); }
            let failure = io::Error::last_os_error();
            if failure.kind() == io::ErrorKind::Interrupted { continue; }
            if failure.kind() != io::ErrorKind::WouldBlock { return Err(failure); }
            if terminal_ready { return Err(error(io::ErrorKind::ConnectionAborted, "vsock terminal read was unavailable")); }
            let events = self.socket.poll(libc::POLLIN, deadline, Some(&self.closed))?;
            terminal_ready = events & (libc::POLLERR | libc::POLLHUP) != 0;
        }
    }
}

impl Write for VsockStreamV1 {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let deadline = self.operation_deadline(&self.write_timeout_ns)?;
        if buffer.is_empty() { return Ok(0); }
        let mut terminal_ready = false;
        loop {
            self.check(deadline)?;
            let count = unsafe { libc::send(self.socket.fd.as_raw_fd(), buffer.as_ptr().cast(),
                buffer.len().min(MAX_IO_BYTES), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
            if count > 0 { self.check(deadline)?; return Ok(count as usize); }
            if count == 0 { return Err(error(io::ErrorKind::WriteZero, "vsock write made no progress")); }
            let failure = io::Error::last_os_error();
            if failure.kind() == io::ErrorKind::Interrupted { continue; }
            if failure.kind() != io::ErrorKind::WouldBlock { return Err(failure); }
            if terminal_ready { return Err(error(io::ErrorKind::ConnectionAborted, "vsock terminal write was unavailable")); }
            let events = self.socket.poll(libc::POLLOUT, deadline, Some(&self.closed))?;
            terminal_ready = events & (libc::POLLERR | libc::POLLHUP) != 0;
        }
    }

    fn flush(&mut self) -> io::Result<()> { self.check(self.deadline) }
}
