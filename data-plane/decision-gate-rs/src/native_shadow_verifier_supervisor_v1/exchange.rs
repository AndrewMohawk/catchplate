//! One public request/result exchange. No policy, key or deadline comes from
//! the network. Result framing is not a signature or a verification verdict.
use super::{ensure, json, watchdog::{self, Watchdog}};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use crate::native_shadow_verifier_runtime_v1::{RuntimeAdmission, originals::{Origin, Original}};
use serde::Deserialize;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const REQUEST_MAGIC: &[u8;8] = b"SWNSVQ1\0";
const RESULT_MAGIC: &[u8;8] = b"SWNSVR1\0";
const MAX_EVIDENCE: usize = 128 * 1024;
const MAX_RESULT: usize = 32 * 1024;
const SO_COOKIE: i32 = 57;

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Configuration {
    api_version: String, verifier_launch_sha256: String, verifier_configuration_sha256: String,
    local_address: String, peer_ip: String,
}
#[derive(Clone,Copy,PartialEq,Eq)]
struct SocketIdentity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32, cookie: u64 }
fn option<T: Copy + Default>(fd: RawFd, name: i32) -> Result<T,String> {
    let mut value = T::default();
    let mut length = std::mem::size_of::<T>() as libc::socklen_t;
    ensure(unsafe { libc::getsockopt(fd,libc::SOL_SOCKET,name,
        (&mut value as *mut T).cast(),&mut length) } == 0
        && length as usize == std::mem::size_of::<T>(), "verifier transport socket option unavailable")?;
    Ok(value)
}
fn identity(fd: RawFd) -> Result<SocketIdentity,String> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(fd,&mut stat) } == 0
        && stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
        && stat.st_uid == 0 && stat.st_gid == 0,
        "verifier transport requires its root-owned original TCP socket")?;
    let cookie = option::<u64>(fd,SO_COOKIE)?;
    ensure(cookie != 0 && option::<i32>(fd,libc::SO_TYPE)? == libc::SOCK_STREAM
        && option::<i32>(fd,libc::SO_PROTOCOL)? == libc::IPPROTO_TCP
        && option::<i32>(fd,libc::SO_ACCEPTCONN)? == 0
        && [libc::AF_INET,libc::AF_INET6].contains(&option::<i32>(fd,libc::SO_DOMAIN)?),
        "verifier transport is not a connected non-listening TCP original")?;
    Ok(SocketIdentity { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
        uid: stat.st_uid, gid: stat.st_gid, cookie })
}
fn interrupted() -> bool { std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) }
fn would_block() -> bool { std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) }

struct Socket {
    stream: TcpStream, identity: SocketIdentity, flags: i32, local: SocketAddr, peer: SocketAddr,
}
impl Socket {
    fn take(fd: OwnedFd) -> Result<Self,String> {
        let observed = identity(fd.as_raw_fd())?;
        // Keep the reserved inherited endpoint away from all fixed child slots.
        let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(),libc::F_DUPFD_CLOEXEC,128) };
        ensure(duplicate >= 128, "verifier transport original retention failed")?;
        let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
        drop(fd);
        ensure(identity(duplicate.as_raw_fd())? == observed, "verifier transport duplicate differs")?;
        let stream = unsafe { TcpStream::from_raw_fd(duplicate.into_raw_fd()) };
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(),libc::F_GETFL) };
        ensure(flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
            && flags & (libc::O_ASYNC|libc::O_APPEND|libc::O_PATH) == 0,
            "verifier transport flags differ")?;
        ensure(unsafe { libc::fcntl(stream.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK) } == 0,
            "verifier transport could not be nonblocking")?;
        let local = stream.local_addr().map_err(|_| "verifier transport local tuple absent")?;
        let peer = stream.peer_addr().map_err(|_| "verifier transport peer tuple absent")?;
        ensure(local.port() != 0 && peer.port() != 0 && local.is_ipv4() == peer.is_ipv4(),
            "verifier transport endpoint tuple invalid")?;
        let owner = Self { stream, identity: observed, flags: flags|libc::O_NONBLOCK, local, peer };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> Result<(),String> {
        let fd = self.stream.as_raw_fd();
        ensure(identity(fd)? == self.identity
            && unsafe { libc::fcntl(fd,libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(fd,libc::F_GETFD) } == libc::FD_CLOEXEC
            && self.stream.local_addr().map_err(|_| "verifier transport local tuple changed")? == self.local
            && self.stream.peer_addr().map_err(|_| "verifier transport peer tuple changed")? == self.peer,
            "verifier transport original changed")
    }
    fn quiet(&self) -> Result<(),String> {
        // A bounded queued-data check only, not proof of future silence/EOF.
        // The guest deliberately keeps its write direction open until result.
        let mut byte = [0u8;1];
        let count = unsafe { libc::recv(self.stream.as_raw_fd(),byte.as_mut_ptr().cast(),1,
            libc::MSG_PEEK|libc::MSG_DONTWAIT) };
        if count < 0 && would_block() { return Ok(()); }
        Err("verifier transport has trailing request data or premature EOF".into())
    }
}
impl Drop for Socket { fn drop(&mut self) { let _ = self.stream.shutdown(Shutdown::Both); } }

/// No public FD constructor: the separate fixed transport entrypoint reserves
/// FD4 and this actual FD6 before opening any owned object. FD5 must be absent.
pub(super) struct PendingExchange { socket: Socket }
impl PendingExchange {
    pub(super) fn take() -> Result<Self,String> {
        let missing = unsafe { libc::fcntl(5,libc::F_GETFD) };
        ensure(missing < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "verifier transport requires absent inherited FD5")?;
        ensure(unsafe { libc::fcntl(6,libc::F_GETFD) } >= 0,
            "verifier transport requires inherited connection FD6")?;
        let socket = Socket::take(unsafe { OwnedFd::from_raw_fd(6) })?;
        Ok(Self { socket })
    }
    /// Must be called after the actual original kernel watchdog is armed and
    /// before RuntimeAdmission is consumed for image/root preparation.
    pub(super) fn receive(self, admission: &RuntimeAdmission, watch: &Watchdog)
        -> Result<(Exchange,OwnedFd),String> {
        watch.check()?; admission.check()?;
        let origin = Origin::capture()?;
        let original = Original::open("native-shadow-verifier-transport.json",16384)?;
        let value = json::parse(&original.bytes,16384)?;
        ensure(canonical_ascii_bytes(&value)? == original.bytes,
            "verifier transport configuration is not original canonical ASCII")?;
        let config: Configuration = serde_json::from_value(value)
            .map_err(|_| "verifier transport configuration is not closed")?;
        let pins = admission.public_transport_pins()?;
        ensure(config.api_version == "catchplate.nativeShadowVerifierPublicExchange/v1"
            && config.verifier_launch_sha256 == pins.0 && config.verifier_configuration_sha256 == pins.1,
            "verifier transport does not pin the same independent launch/policy")?;
        let local: SocketAddr = config.local_address.parse().map_err(|_| "verifier transport local address invalid")?;
        let peer: IpAddr = config.peer_ip.parse().map_err(|_| "verifier transport peer IP invalid")?;
        ensure(local.to_string() == config.local_address && peer.to_string() == config.peer_ip
            && local.port() > 1023 && !local.ip().is_unspecified() && !local.ip().is_multicast()
            && !peer.is_unspecified() && !peer.is_multicast()
            && self.socket.local == local && self.socket.peer.ip() == peer,
            "verifier transport original socket differs from protected fixed scope")?;
        let mut exchange = Exchange { socket: self.socket, original, origin,
            issued: admission.issued_boottime_ns(), deadline: admission.deadline_boottime_ns(), ready: false };
        exchange.check(watch)?;
        let mut header = [0u8;12];
        exchange.read_exact(&mut header,watch)?;
        ensure(&header[..8] == REQUEST_MAGIC, "verifier transport request magic differs")?;
        let count = u32::from_be_bytes(header[8..].try_into().map_err(|_| "verifier request length absent")?) as usize;
        ensure(count > 0 && count <= MAX_EVIDENCE, "verifier transport evidence exceeds bound")?;
        let mut bytes = vec![0u8;count];
        exchange.read_exact(&mut bytes,watch)?;
        let value = json::parse(&bytes,MAX_EVIDENCE)?;
        let fields = value.as_object().ok_or("verifier transport evidence is not an object")?;
        let names = ["apiVersion","statement","possession","attestationDocumentBase64url",
            "userDataBase64url","publicKeyBase64url","nonceBase64url"];
        ensure(fields.len() == names.len() && names.iter().all(|name| fields.contains_key(*name))
            && value["apiVersion"] == admission.evidence_api()?
            && canonical_ascii_bytes(&value)? == bytes, "verifier transport evidence framing differs")?;
        exchange.ready = true;
        exchange.check(watch)?; admission.check()?;
        let evidence = exchange.seal(&bytes,admission,watch)?;
        exchange.check(watch)?; admission.check()?;
        Ok((exchange,evidence))
    }
}

pub(super) struct Exchange {
    socket: Socket, original: Original, origin: Origin, issued: u64, deadline: u64, ready: bool,
}
impl Exchange {
    pub(super) fn check(&self, watch: &Watchdog) -> Result<(),String> {
        watch.check()?;
        self.origin.check()?; self.original.check()?; self.socket.check()?;
        let now = watchdog::now()?;
        ensure(self.issued <= now && now < self.deadline, "verifier transport original window expired")?;
        if self.ready { self.socket.quiet()?; }
        watch.check()
    }
    fn wait(&self, events: i16, watch: &Watchdog) -> Result<(),String> {
        self.check(watch)?;
        let mut poll = libc::pollfd { fd: self.socket.stream.as_raw_fd(), events, revents: 0 };
        let result = unsafe { libc::poll(&mut poll,1,25) };
        if result < 0 && !interrupted() { return Err("verifier transport poll failed".into()); }
        ensure(poll.revents & (libc::POLLERR|libc::POLLNVAL) == 0, "verifier transport connection failed")?;
        self.check(watch)
    }
    fn read_exact(&self, bytes: &mut [u8], watch: &Watchdog) -> Result<(),String> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check(watch)?;
            let count = unsafe { libc::recv(self.socket.stream.as_raw_fd(),bytes[offset..].as_mut_ptr().cast(),
                bytes.len()-offset,libc::MSG_DONTWAIT) };
            if count > 0 { offset += count as usize; continue; }
            if count < 0 && interrupted() { continue; }
            if count < 0 && would_block() { self.wait(libc::POLLIN,watch)?; continue; }
            return Err("verifier transport request truncated".into());
        }
        self.check(watch)
    }
    fn seal(&self, bytes: &[u8], admission: &RuntimeAdmission, watch: &Watchdog) -> Result<OwnedFd,String> {
        self.check(watch)?; admission.check()?;
        let raw = unsafe { libc::syscall(libc::SYS_memfd_create,b"shadow-verifier-public-evidence\0".as_ptr(),
            libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING) as RawFd };
        ensure(raw >= 0, "verifier public evidence memfd unavailable")?;
        let original = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut offset = 0;
        while offset < bytes.len() {
            self.check(watch)?; admission.check()?;
            let count = unsafe { libc::pwrite(raw,bytes[offset..].as_ptr().cast(),bytes.len()-offset,offset as i64) };
            if count < 0 && interrupted() { continue; }
            ensure(count > 0, "verifier public evidence write failed")?;
            offset += count as usize;
        }
        ensure(unsafe { libc::fchown(raw,admission.uid(),admission.gid()) } == 0
            && unsafe { libc::fchmod(raw,0o600) } == 0
            && unsafe { libc::fcntl(raw,libc::F_ADD_SEALS,15) } == 0,
            "verifier public evidence could not be assigned and sealed")?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let seals = unsafe { libc::fcntl(raw,libc::F_GET_SEALS) };
        ensure(unsafe { libc::fstat(raw,&mut stat) } == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_mode & 0o7777 == 0o600 && stat.st_nlink == 0
            && stat.st_size == bytes.len() as i64 && stat.st_uid == admission.uid() && stat.st_gid == admission.gid()
            && seals >= 0 && seals & 15 == 15 && unsafe { libc::fcntl(raw,libc::F_GETFD) } == libc::FD_CLOEXEC,
            "verifier public evidence original differs")?;
        self.check(watch)?; admission.check()?;
        Ok(original)
    }
    fn write_all(&self, bytes: &[u8], watch: &Watchdog) -> Result<(),String> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check(watch)?;
            let count = unsafe { libc::send(self.socket.stream.as_raw_fd(),bytes[offset..].as_ptr().cast(),
                bytes.len()-offset,libc::MSG_NOSIGNAL|libc::MSG_DONTWAIT) };
            if count > 0 { offset += count as usize; continue; }
            if count < 0 && interrupted() { continue; }
            if count < 0 && would_block() { self.wait(libc::POLLOUT,watch)?; continue; }
            return Err("verifier transport result write failed".into());
        }
        self.check(watch)
    }
    /// Source-private framing only. The fixed parent must call ONLY after its
    /// own genuine terminal checks, same-PIDFD reap/root retirement and exit0.
    /// The claimant still must verify the independent result signature.
    pub(super) fn publish(self, raw: &[u8], watch: &Watchdog) -> Result<(),String> {
        self.check(watch)?;
        ensure(self.ready && !raw.is_empty() && raw.len() <= MAX_RESULT,
            "verifier transport result bound or phase differs")?;
        let value = json::parse(raw,MAX_RESULT)?;
        ensure(canonical_ascii_bytes(&value)? == raw, "verifier result transport changed original bytes")?;
        self.write_all(RESULT_MAGIC,watch)?;
        self.write_all(&(raw.len() as u32).to_be_bytes(),watch)?;
        self.write_all(raw,watch)?;
        self.check(watch)?;
        // Result is complete before the first EOF. No retry/reuse or success
        // frame follows; the actual relay drains its pending bytes then closes.
        self.socket.stream.shutdown(Shutdown::Both).map_err(|_| "verifier result close failed".to_owned())
    }
}
