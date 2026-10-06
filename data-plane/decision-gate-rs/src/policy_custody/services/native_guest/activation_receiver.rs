//! Service-enclave connection acquisition before independently signed C9 input.
//! The parent relay/CID and this public observation confer no service authority.
use super::*;
use super::super::super::super::guest_original::Process;
use crate::policy_shadow::policy_custody::services::guest;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const PORT: u32 = 9102;
const PARENT_CID: u32 = 3;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration { api_version: String, delivery_configuration: Pin }
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
fn identity(fd: BorrowedFd<'_>) -> Result<Identity, ShadowError> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstat(fd.as_raw_fd(), &mut s) } == 0)?;
    Ok(Identity { device: s.st_dev, inode: s.st_ino, mode: s.st_mode, uid: s.st_uid, gid: s.st_gid })
}
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Address { family: libc::sa_family_t, reserved: u16, port: u32, cid: u32, flags: u8, zero: [u8; 3] }
const _: [(); 16] = [(); std::mem::size_of::<Address>()];
fn address(fd: BorrowedFd<'_>, peer: bool) -> Result<Address, ShadowError> {
    let mut a: Address = unsafe { std::mem::zeroed() };
    let mut n = std::mem::size_of_val(&a) as libc::socklen_t;
    let p = (&mut a as *mut Address).cast();
    require(unsafe { if peer { libc::getpeername(fd.as_raw_fd(), p, &mut n) }
        else { libc::getsockname(fd.as_raw_fd(), p, &mut n) } } == 0
        && n as usize == std::mem::size_of::<Address>()
        && a.family == libc::AF_VSOCK as libc::sa_family_t
        && a.reserved == 0 && a.flags == 0 && a.zero == [0; 3])?;
    Ok(a)
}
fn socket(fd: BorrowedFd<'_>, listener: bool) -> Result<(), ShadowError> {
    for (option, expected) in [(libc::SO_TYPE, libc::SOCK_STREAM), (libc::SO_DOMAIN, libc::AF_VSOCK),
        (libc::SO_ACCEPTCONN, i32::from(listener))] {
        let mut value = 0i32;
        let mut n = std::mem::size_of_val(&value) as libc::socklen_t;
        require(unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, option,
            (&mut value as *mut i32).cast(), &mut n) } == 0
            && n as usize == std::mem::size_of::<i32>() && value == expected)?;
    }
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    require(flags >= 0 && flags & (libc::O_ACCMODE | libc::O_NONBLOCK) == libc::O_RDWR | libc::O_NONBLOCK
        && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC
        && identity(fd)?.mode & libc::S_IFMT == libc::S_IFSOCK)
}
fn pause(fd: BorrowedFd<'_>, events: i16) -> Result<(), ShadowError> {
    let mut p = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
    let status = unsafe { libc::poll(&mut p, 1, 100) };
    require(status >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR))?;
    require(p.revents & (libc::POLLERR | libc::POLLNVAL) == 0)
}
struct Connection { fd: OwnedFd, identity: Identity, local: Address, peer: Address, flags: i32 }
impl Connection {
    fn check(&self) -> Result<(), ShadowError> {
        socket(self.fd.as_fd(), false)?;
        require(identity(self.fd.as_fd())? == self.identity
            && address(self.fd.as_fd(), false)? == self.local && address(self.fd.as_fd(), true)? == self.peer
            && unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) } == self.flags)
    }
}
impl Drop for Connection { fn drop(&mut self) { unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR); } } }

/// Non-deserializable same-process owner. It never reads or initializes journal
/// contents and never acquires a key. Signed C9/service admission remains later.
pub(super) struct Cold {
    process: Process, original: Original, original_bytes: Vec<u8>, configuration: Configuration,
    delivery_original: Original, journal: OwnedFd, journal_identity: Identity, journal_flags: i32,
    connection: Option<Connection>, observed_at: Option<u64>,
}
impl Cold {
    fn open() -> Result<Self, ShadowError> {
        let journal = unsafe { OwnedFd::from_raw_fd(6) };
        require(unsafe { libc::fcntl(6, libc::F_SETFD, libc::FD_CLOEXEC) } == 0)?;
        let process = Process::capture().map_err(fail)?;
        let original = Original::activation_receiver_configuration().map_err(fail)?;
        let original_bytes = original.read(32768).map_err(fail)?.to_vec();
        let configuration: Configuration = exact(&original_bytes)?;
        require(configuration.api_version == "serverware.nativeShadowActivationReceiverConfiguration/v1")?;
        let delivery_original = configuration.delivery_configuration.open(65536)?;
        let delivery: guest::Configuration = exact(&delivery_original.read(65536).map_err(fail)?)?;
        require(delivery.api_version == "serverware.policyCustodyGuestConfiguration/v1"
            && delivery.service_role == guest::Role::ProductionBridge
            && delivery.uid > 0 && delivery.gid > 0)?;
        let journal_identity = identity(journal.as_fd())?;
        let flags = unsafe { libc::fcntl(journal.as_raw_fd(), libc::F_GETFL) };
        require(journal_identity.mode & libc::S_IFMT == libc::S_IFDIR
            && journal_identity.mode & 0o7777 == 0o700
            && journal_identity.uid == delivery.uid && journal_identity.gid == delivery.gid
            && flags >= 0 && flags & (libc::O_PATH | libc::O_ACCMODE) == libc::O_RDONLY)?;
        let value = Self { process, original, original_bytes, configuration, delivery_original,
            journal, journal_identity, journal_flags: flags, connection: None, observed_at: None };
        value.check()?; Ok(value)
    }
    pub(super) fn check(&self) -> Result<(), ShadowError> {
        self.process.check().map_err(fail)?;
        require(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
            && self.original.read(32768).map_err(fail)?.as_slice() == self.original_bytes.as_slice()
            && identity(self.journal.as_fd())? == self.journal_identity
            && unsafe { libc::fcntl(self.journal.as_raw_fd(), libc::F_GETFL) } == self.journal_flags
            && unsafe { libc::fcntl(self.journal.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC)?;
        self.delivery_original.check().map_err(fail)?;
        if let Some(connection) = &self.connection { connection.check()?; }
        Ok(())
    }
    pub(super) fn delivery_configuration(&self) -> &Pin { &self.configuration.delivery_configuration }
    pub(super) fn require_delivery(&self, p: &guest::Payload) -> Result<(), ShadowError> {
        self.check()?;
        let domain = self.process.domain();
        require(p.configuration_sha256 == self.configuration.delivery_configuration.sha256
            && p.boot_id_base64url == URL_SAFE_NO_PAD.encode(domain.authority_boot_id())
            && p.time_namespace_device == domain.time_namespace().device()
            && p.time_namespace_inode == domain.time_namespace().inode()
            && decimal(&p.issued_at_boottime_ns)? >= self.observed_at.ok_or(ShadowError::BindingDrift)?
            && now()? < decimal(&p.startup_deadline_boottime_ns)?)
    }
    fn accept(&mut self) -> Result<(), ShadowError> {
        self.check()?; require(self.connection.is_none())?;
        let raw = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
        require(raw >= 0)?;
        let listener = unsafe { OwnedFd::from_raw_fd(raw) };
        let a = Address { family: libc::AF_VSOCK as _, reserved: 0, port: PORT, cid: u32::MAX, flags: 0, zero: [0; 3] };
        require(unsafe { libc::bind(raw, (&a as *const Address).cast(), std::mem::size_of::<Address>() as _) } == 0
            && unsafe { libc::listen(raw, 1) } == 0)?;
        let listener_identity = identity(listener.as_fd())?;
        let local = address(listener.as_fd(), false)?;
        require(local.port == PORT)?;
        loop {
            self.check()?; socket(listener.as_fd(), true)?;
            require(identity(listener.as_fd())? == listener_identity && address(listener.as_fd(), false)? == local)?;
            let accepted = unsafe { libc::accept4(raw, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) };
            if accepted < 0 {
                require(matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)))?;
                pause(listener.as_fd(), libc::POLLIN)?; continue;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(accepted) };
            let value = Connection { identity: identity(fd.as_fd())?, local: address(fd.as_fd(), false)?,
                peer: address(fd.as_fd(), true)?, flags: unsafe { libc::fcntl(accepted, libc::F_GETFL) }, fd };
            value.check()?;
            require(value.local.cid > PARENT_CID && value.local.cid != u32::MAX && value.local.port == PORT
                && value.peer.cid == PARENT_CID && value.peer.port > 1023 && value.peer.port != u32::MAX)?;
            self.connection = Some(value); self.observed_at = Some(now()?);
            self.check()?; return Ok(()); // listener drops; no second connection.
        }
    }
    fn observation(&self) -> Result<Vec<u8>, ShadowError> {
        self.check()?;
        let connection = self.connection.as_ref().ok_or(ShadowError::BindingDrift)?;
        let domain = self.process.domain();
        let (pid, start, pidfd_inode) = self.process.native_binding().map_err(fail)?;
        canonical_json_bytes(&serde_json::json!({
            "apiVersion":"serverware.nativeShadowActivationReceiverObservation/v1", "okForAction":false,
            "configurationSha256":Sha256Digest::compute(&self.original_bytes),
            "deliveryConfigurationSha256":self.configuration.delivery_configuration.sha256,
            "processId":pid,"processStartTicks":start,"processPidfdInode":pidfd_inode,
            "bootIdBase64url":URL_SAFE_NO_PAD.encode(domain.authority_boot_id()),
            "timeNamespaceDevice":domain.time_namespace().device(),"timeNamespaceInode":domain.time_namespace().inode(),
            "observedAtBoottimeNs":self.observed_at.ok_or(ShadowError::BindingDrift)?.to_string(),
            "localCid":connection.local.cid,"localPort":PORT,"peerCid":PARENT_CID,"peerPort":connection.peer.port,
            "activation":[
                {"name":"activation-channel","fd":6,"device":connection.identity.device,"inode":connection.identity.inode,
                 "mode":connection.identity.mode,"uid":connection.identity.uid,"gid":connection.identity.gid},
                {"name":"activation-journal","fd":7,"device":self.journal_identity.device,"inode":self.journal_identity.inode,
                 "mode":self.journal_identity.mode,"uid":self.journal_identity.uid,"gid":self.journal_identity.gid}]
        }))
    }
    fn emit(&self, raw: &[u8]) -> Result<(), ShadowError> {
        require(!raw.is_empty() && raw.len() <= 8192)?;
        let fd = unsafe { BorrowedFd::borrow_raw(1) };
        let original = identity(fd)?;
        let flags = unsafe { libc::fcntl(1, libc::F_GETFL) };
        require(original.mode & libc::S_IFMT == libc::S_IFIFO && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_WRONLY
            && unsafe { libc::fcntl(1, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0)?;
        let mut frame = (raw.len() as u32).to_be_bytes().to_vec(); frame.extend_from_slice(raw);
        let mut used = 0;
        while used < frame.len() {
            self.check()?; require(identity(fd)? == original
                && unsafe { libc::fcntl(1, libc::F_GETFL) } == flags | libc::O_NONBLOCK)?;
            let n = unsafe { libc::write(1, frame[used..].as_ptr().cast(), frame.len() - used) };
            if n < 0 {
                require(matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)))?;
                pause(fd, libc::POLLOUT)?;
            } else { require(n > 0)?; used += n as usize; }
            self.check()?;
        }
        Ok(())
    }
}
pub(super) fn receive() -> Result<(Cold, super::activation_receiver_inputs::Completed), ShadowError> {
    let mut cold = Cold::open()?; cold.accept()?;
    let observation = cold.observation()?; cold.emit(&observation)?;
    let channel = retrieval_peer::duplicate(cold.connection.as_ref().ok_or(ShadowError::BindingDrift)?.fd.as_fd())?;
    let journal = retrieval_peer::duplicate(cold.journal.as_fd())?;
    let completed = super::activation_receiver_inputs::Completed::receive(&cold,
        &Sha256Digest::compute(&observation), channel, journal)?;
    cold.check()?; Ok((cold, completed))
}
