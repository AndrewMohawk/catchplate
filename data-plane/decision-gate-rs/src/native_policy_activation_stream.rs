//! One inherited AF_VSOCK byte stream, never authority from a CID or a frame.
//! Each direction is one big-endian u32 length, literal bytes, then EOF. No
//! descriptor transfer, remote BOOTTIME, reconnect, or second request exists.
use super::{require, identity};
use std::os::fd::{AsRawFd, BorrowedFd};

const IO_SLICE: usize = 64 * 1024;
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Address {
    family: libc::sa_family_t, reserved: u16, port: u32, cid: u32,
    flags: u8, zero: [u8; 3],
}
const _: [(); 16] = [(); std::mem::size_of::<Address>()];
fn address(fd: BorrowedFd<'_>, peer: bool) -> Result<Address, String> {
    let mut value: Address = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    let pointer = (&mut value as *mut Address).cast::<libc::sockaddr>();
    let status = unsafe { if peer { libc::getpeername(fd.as_raw_fd(), pointer, &mut size) }
        else { libc::getsockname(fd.as_raw_fd(), pointer, &mut size) } };
    require(status == 0 && size as usize == std::mem::size_of::<Address>()
        && value.family == libc::AF_VSOCK as libc::sa_family_t
        && value.reserved == 0 && value.flags == 0 && value.zero == [0; 3]
        && value.cid >= 2 && value.cid != u32::MAX
        && value.port >= 1024 && value.port != u32::MAX)?;
    Ok(value)
}
fn socket(fd: BorrowedFd<'_>) -> Result<(), String> {
    for (option, expected) in [(libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_DOMAIN, libc::AF_VSOCK), (libc::SO_ACCEPTCONN, 0)] {
        let mut actual = 0i32;
        let mut size = std::mem::size_of_val(&actual) as libc::socklen_t;
        require(unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, option,
            (&mut actual as *mut i32).cast(), &mut size) } == 0
            && size as usize == std::mem::size_of::<i32>() && actual == expected)?;
    }
    require(identity(fd)?.mode & libc::S_IFMT == libc::S_IFSOCK)
}
pub(super) struct Connection { local: Address, peer: Address, pid: u32, flags: i32 }
impl Connection {
    pub(super) fn capture(fd: BorrowedFd<'_>) -> Result<Self, String> {
        socket(fd)?;
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        require(flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0)?;
        let value = Self { local: address(fd, false)?, peer: address(fd, true)?,
            pid: std::process::id(), flags: flags | libc::O_NONBLOCK };
        value.check(fd)?;
        Ok(value)
    }
    pub(super) fn check(&self, fd: BorrowedFd<'_>) -> Result<(), String> {
        socket(fd)?;
        require(self.pid == std::process::id() && address(fd, false)? == self.local
            && address(fd, true)? == self.peer
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC)
    }
}
fn progress(n: isize) -> Result<Option<usize>, String> {
    if n >= 0 { return Ok(Some(n as usize)); }
    if matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
        return Ok(None);
    }
    Err("native activation stream IO failed; outcome is not retryable".into())
}
pub(super) struct Reader {
    header: [u8; 4], header_used: usize, body: Vec<u8>, used: usize,
    maximum: usize, done: bool, failed: bool,
}
impl Reader {
    pub(super) fn new(maximum: usize) -> Self {
        Self { header: [0; 4], header_used: 0, body: Vec::new(), used: 0,
            maximum, done: false, failed: false }
    }
    /// At most one nonblocking IO slice. The retained caller checks its local
    /// original deadline and genuine authority before and after every poll.
    pub(super) fn poll(&mut self, fd: BorrowedFd<'_>) -> Result<Option<Vec<u8>>, String> {
        require(!self.done && !self.failed)?;
        let result = self.read(fd);
        if result.is_err() { self.failed = true; }
        result
    }
    fn read(&mut self, fd: BorrowedFd<'_>) -> Result<Option<Vec<u8>>, String> {
        let mut eof = [0u8; 1];
        let buffer = if self.header_used < 4 { &mut self.header[self.header_used..] }
            else if self.used < self.body.len() {
                let end = self.body.len().min(self.used + IO_SLICE);
                &mut self.body[self.used..end]
            } else { &mut eof[..] };
        let Some(n) = progress(unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(),
            buffer.len(), libc::MSG_DONTWAIT) })? else { return Ok(None); };
        if self.header_used < 4 {
            require(n > 0)?;
            self.header_used += n;
            if self.header_used == 4 {
                let size = u32::from_be_bytes(self.header) as usize;
                require(size > 0 && size <= self.maximum)?;
                self.body = vec![0; size];
            }
        } else if self.used < self.body.len() {
            require(n > 0)?;
            self.used += n;
        } else {
            require(n == 0)?; // A second frame or trailing byte is a refusal.
            self.done = true;
            return Ok(Some(std::mem::take(&mut self.body)));
        }
        Ok(None)
    }
}
pub(super) struct Writer { frame: Vec<u8>, used: usize, done: bool, failed: bool }
impl Writer {
    pub(super) fn new(raw: &[u8], maximum: usize) -> Result<Self, String> {
        require(!raw.is_empty() && raw.len() <= maximum && raw.len() <= u32::MAX as usize)?;
        let mut frame = Vec::with_capacity(4 + raw.len());
        frame.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        frame.extend_from_slice(raw);
        Ok(Self { frame, used: 0, done: false, failed: false })
    }
    pub(super) fn original(&self) -> &[u8] { &self.frame[4..] }
    pub(super) fn poll(&mut self, fd: BorrowedFd<'_>) -> Result<bool, String> {
        require(!self.done && !self.failed)?;
        let result = self.write(fd);
        if result.is_err() { self.failed = true; }
        result
    }
    fn write(&mut self, fd: BorrowedFd<'_>) -> Result<bool, String> {
        if self.used < self.frame.len() {
            let bytes = &self.frame[self.used..self.frame.len().min(self.used + IO_SLICE)];
            let Some(n) = progress(unsafe { libc::send(fd.as_raw_fd(), bytes.as_ptr().cast(),
                bytes.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) })? else { return Ok(false); };
            require(n > 0)?;
            self.used += n;
            return Ok(false);
        }
        // EOF is part of the single bounded attempt, not a new transaction.
        require(unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR) } == 0)?;
        self.done = true;
        Ok(true)
    }
}
