//! Fixed guest listener ownership. A sealed handoff is consistency data, never
//! authority: only the retained signed guest delivery admits final activation.
//! The actual privileged launcher and peer inspector are separate prerequisites.
use super::{guest_delivery, RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use super::config::CustodyServiceRole;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

pub const GUEST_RESPONSE_V2_SOCKET: &str = "/run/serverware-response-v2-guest/transaction.sock";
const DIRECTORY: &str = "/run/serverware-response-v2-guest";
const PROFILE: &str = "serverware.responseV2.guestListener/v1";
const HANDOFF: &str = "serverware.responseV2.guestListenerHandoff/v1";
const GATE_ID: u32 = 65534;
const MAX_HANDOFF: u64 = 16 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

fn fail(message: &str) -> V2RuntimeError { V2RuntimeError::new("guest_listener_refused", message) }
fn require(value: bool, message: &str) -> Result<(), V2RuntimeError> {
    if value { Ok(()) } else { Err(fail(message)) }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestResponseV2ListenerProfile { api_version: String }
pub(crate) fn configuration_profile<'de, D: serde::Deserializer<'de>>(d: D)
    -> Result<Option<GuestResponseV2ListenerProfile>, D::Error> {
    GuestResponseV2ListenerProfile::deserialize(d).map(Some)
}
impl GuestResponseV2ListenerProfile {
    pub fn router_gid(&self) -> u32 { super::config::TRUSTED_HOST_SHARED_UDS_GID }
    pub fn validate_client(&self, path: &Path, router_uid: u32) -> Result<(), String> {
        if self.api_version != PROFILE || path != Path::new(GUEST_RESPONSE_V2_SOCKET)
            || router_uid == 0 || router_uid == GATE_ID {
            return Err("guest response-v2 requires its fixed path and distinct nonzero router UID".to_owned());
        }
        Ok(())
    }
    pub(crate) fn validate(&self, config: &Config) -> Result<(), V2RuntimeError> {
        let scoped = config.scoped_service_config(CustodyServiceRole::CustodyRouter)?;
        self.validate_client(config.socket_path(), scoped.process.uid).map_err(|e| fail(&e))?;
        require(config.guest_delivery_authority.is_some()
            && config.expected_client_uid() == GATE_ID && config.expected_socket_gid() == GATE_ID
            && scoped.process.socket_path == config.socket_path(),
            "guest listener requires signed guest delivery and fixed gate UID/GID")
    }
    pub fn open_client_path(&self, path: &Path, router_uid: u32) -> Result<GuestResponseV2ClientPath, String> {
        self.validate_client(path, router_uid)?;
        require(unsafe { libc::getuid() } == GATE_ID && unsafe { libc::geteuid() } == GATE_ID
            && unsafe { libc::getgid() } == GATE_ID && unsafe { libc::getegid() } == GATE_ID
            && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0,
            "guest response-v2 client requires final gate identity without supplementary groups")
            .map_err(|e| e.to_string())?;
        Ok(GuestResponseV2ClientPath { paths: Paths::open(router_uid).map_err(|e| e.to_string())? })
    }
}

pub struct GuestResponseV2ClientPath { paths: Paths }
impl GuestResponseV2ClientPath {
    pub fn check(&self) -> Result<(), String> { self.paths.check().map_err(|e| e.to_string()) }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityBinding {
    pub(crate) configuration_sha256: String, pub(crate) delivery_sha256: String,
    pub(crate) generation_id: String, pub(crate) generation: u64, pub(crate) boot_id: String,
    pub(crate) issued_at_boottime_ns: String, pub(crate) deadline_boottime_ns: String,
    pub(crate) router_uid: u32, pub(crate) router_gid: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
impl Identity {
    fn of(m: &Metadata) -> Self { Self { device:m.dev(), inode:m.ino(), mode:m.mode(), uid:m.uid(), gid:m.gid() } }
    fn fd(fd: RawFd) -> Result<Self, V2RuntimeError> {
        let copy = duplicate(fd)?;
        let file = File::from(copy);
        Ok(Self::of(&file.metadata().map_err(|_| fail("inspect retained descriptor"))?))
    }
}
fn duplicate(fd: RawFd) -> Result<OwnedFd, V2RuntimeError> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 { return Err(fail("duplicate retained descriptor")); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

struct HeldPath { path: &'static str, file: File, identity: Identity }
impl HeldPath {
    fn open(path: &'static str) -> Result<Self, V2RuntimeError> {
        let c = CString::new(path).map_err(|_| fail("fixed path contains NUL"))?;
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if raw < 0 { return Err(fail("open fixed guest path original")); }
        let file = unsafe { File::from_raw_fd(raw) };
        let identity = Identity::of(&file.metadata().map_err(|_| fail("inspect fixed path original"))?);
        Ok(Self { path, file, identity })
    }
    fn check(&self) -> Result<(), V2RuntimeError> {
        let current = Self::open(self.path)?;
        require(current.identity == self.identity
            && Identity::of(&self.file.metadata().map_err(|_| fail("inspect held path"))?) == self.identity,
            "guest path original changed")
    }
}
struct Paths { root: HeldPath, run: HeldPath, directory: HeldPath, socket: HeldPath }
impl Paths {
    fn parents() -> Result<(HeldPath, HeldPath), V2RuntimeError> {
        let root = HeldPath::open("/")?;
        let run = HeldPath::open("/run")?;
        for parent in [&root, &run] {
            require(parent.identity.mode & libc::S_IFMT == libc::S_IFDIR
                && parent.identity.uid == 0 && parent.identity.mode & 0o022 == 0
                && parent.identity.mode & 0o001 != 0, "guest listener parent must be root owned, non-writable and traversable")?;
        }
        Ok((root, run))
    }
    fn open(router_uid: u32) -> Result<Self, V2RuntimeError> {
        let (root, run) = Self::parents()?;
        let directory = HeldPath::open(DIRECTORY)?;
        let socket = HeldPath::open(GUEST_RESPONSE_V2_SOCKET)?;
        require(directory.identity.mode == (libc::S_IFDIR | 0o711) && directory.identity.uid == 0
            && directory.identity.gid == GATE_ID, "guest socket-only directory requires root:65534 mode0711")?;
        require(socket.identity.mode == (libc::S_IFSOCK | 0o660) && socket.identity.uid == router_uid
            && socket.identity.gid == GATE_ID, "guest socket requires routerUID:65534 mode0660")?;
        let result = Self { root, run, directory, socket };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<(), V2RuntimeError> {
        for path in [&self.root, &self.run, &self.directory, &self.socket] { path.check()?; }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Handoff { api_version: String, binding: AuthorityBinding,
    directory: Identity, socket_path: Identity, socket_fd: Identity }

fn option(fd: RawFd, name: i32) -> Result<i32, V2RuntimeError> {
    let mut value = 0i32;
    let mut length = size_of::<i32>() as libc::socklen_t;
    require(unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name,
        (&mut value as *mut i32).cast(), &mut length) } == 0 && length as usize == size_of::<i32>(),
        "guest socket option unavailable")?;
    Ok(value)
}
fn socket_check(fd: RawFd, listening: bool) -> Result<(), V2RuntimeError> {
    require(option(fd, libc::SO_TYPE)? == libc::SOCK_SEQPACKET
        && option(fd, libc::SO_DOMAIN)? == libc::AF_UNIX && option(fd, libc::SO_PROTOCOL)? == 0
        && option(fd, libc::SO_ACCEPTCONN)? == (if listening { 1 } else { 0 }), "guest socket type/domain/listening state differs")?;
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(unsafe { libc::getsockname(fd, (&mut address as *mut libc::sockaddr_un).cast(), &mut length) } == 0,
        "read guest bound socket name")?;
    let name = GUEST_RESPONSE_V2_SOCKET.as_bytes();
    require(address.sun_family == libc::AF_UNIX as libc::sa_family_t
        && length as usize == size_of::<libc::sa_family_t>() + name.len() + 1
        && address.sun_path[..name.len()].iter().map(|v| *v as u8).eq(name.iter().copied())
        && address.sun_path[name.len()] == 0, "guest socket is not bound to the fixed original path")
}
fn seal(value: &Handoff) -> Result<File, V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(value).map_err(|_| fail("encode guest listener handoff"))?;
    require(!bytes.is_empty() && bytes.len() as u64 <= MAX_HANDOFF, "handoff exceeds bound")?;
    let raw = unsafe { libc::syscall(libc::SYS_memfd_create, b"serverware-guest-listener\0".as_ptr(),
        libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as i32 };
    if raw < 0 { return Err(fail("create handoff memfd")); }
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(&bytes).map_err(|_| fail("write handoff memfd"))?;
    require(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } == 0
        && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS, "seal handoff memfd")?;
    Ok(file)
}
fn read_handoff(file: &File) -> Result<Handoff, V2RuntimeError> {
    let m = file.metadata().map_err(|_| fail("inspect handoff memfd"))?;
    require(m.is_file() && m.len() > 0 && m.len() <= MAX_HANDOFF
        && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
        "handoff must be a bounded immutable sealed memfd")?;
    let mut bytes = vec![0; m.len() as usize];
    file.read_exact_at(&mut bytes, 0).map_err(|_| fail("read sealed handoff"))?;
    crate::decode_canonical_json(&bytes).map_err(|_| fail("handoff is not exact canonical closed JSON"))
}

/// A genuine root launcher retains this non-Clone owner until handoff and
/// process lifetime settlement. No existing directory/socket is reused or
/// removed. Successful preparation leaves cleanup to that still-missing owner.
pub struct PreparedGuestResponseV2Listener {
    authority: guest_delivery::ListenerPreparation, socket: OwnedFd, handoff: File, paths: Paths,
    poisoned: AtomicBool, exported: AtomicBool,
}
impl PreparedGuestResponseV2Listener {
    pub fn prepare(config_path: &Path, delivery_path: &Path, delivery_sha256: &str) -> Result<Self, V2RuntimeError> {
        let authority = guest_delivery::ListenerPreparation::open(config_path, delivery_path, delivery_sha256)?;
        let (root, run) = Paths::parents()?;
        authority.check()?;
        fs::DirBuilder::new().mode(0o700).create(DIRECTORY).map_err(|_| fail("guest directory must be fresh; no replacement or retry"))?;
        // From this point a partial failure deliberately leaves the fresh path
        // blocked. Never prune a possibly handed-off object or infer dead peers.
        let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(DIRECTORY).map_err(|_| fail("retain fresh guest directory"))?;
        authority.check()?;
        require(unsafe { libc::fchown(dir.as_raw_fd(), 0, GATE_ID) } == 0
            && unsafe { libc::fchmod(dir.as_raw_fd(), 0o711) } == 0, "set fresh guest directory identity")?;
        root.check()?; run.check()?; authority.check()?;
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 { return Err(fail("create guest seqpacket socket")); }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(GUEST_RESPONSE_V2_SOCKET.as_bytes()) { *destination = *source as libc::c_char; }
        authority.check()?;
        require(unsafe { libc::bind(socket.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(),
            (size_of::<libc::sa_family_t>() + GUEST_RESPONSE_V2_SOCKET.len() + 1) as libc::socklen_t) } == 0,
            "bind fresh guest socket")?;
        let path = CString::new(GUEST_RESPONSE_V2_SOCKET).map_err(|_| fail("fixed guest socket NUL"))?;
        authority.check()?;
        require(unsafe { libc::chown(path.as_ptr(), authority.binding().router_uid, GATE_ID) } == 0
            && unsafe { libc::chmod(path.as_ptr(), 0o660) } == 0, "assign only fresh guest socket ownership")?;
        let paths = Paths::open(authority.binding().router_uid)?;
        let handoff = seal(&Handoff { api_version:HANDOFF.to_owned(), binding:authority.binding().clone(),
            directory:paths.directory.identity.clone(), socket_path:paths.socket.identity.clone(),
            socket_fd:Identity::fd(socket.as_raw_fd())? })?;
        let result = Self { authority, socket, handoff, paths,
            poisoned:AtomicBool::new(false), exported:AtomicBool::new(false) };
        result.check()?;
        Ok(result)
    }
    pub fn check(&self) -> Result<(), V2RuntimeError> {
        let result = (|| {
            require(!self.poisoned.load(Ordering::Acquire), "guest preparation owner poisoned")?;
            self.authority.check()?; self.paths.check()?;
            socket_check(self.socket.as_raw_fd(), false)?;
            let original = read_handoff(&self.handoff)?;
            require(original.binding == *self.authority.binding() && original.socket_fd == Identity::fd(self.socket.as_raw_fd())?,
                "prepared guest listener originals changed")?;
            self.authority.check()
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
    pub fn descriptors(&self) -> Result<(BorrowedFd<'_>, BorrowedFd<'_>), V2RuntimeError> {
        self.check()?;
        require(self.exported.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok(),
            "guest listener descriptors already handed off")?;
        Ok((self.socket.as_fd(), self.handoff.as_fd()))
    }
}

pub(crate) struct Bound { socket: OwnedFd, handoff: File, paths: Paths, owner: Arc<guest_delivery::Delivery> }
impl std::fmt::Debug for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("BoundGuestListener { originals: <private> }") }
}
pub(crate) type SharedBound = Arc<Mutex<Option<Bound>>>;

pub(crate) fn attach(config: &mut Config, socket: OwnedFd, handoff: OwnedFd) -> Result<(), V2RuntimeError> {
    for fd in [socket.as_raw_fd(), handoff.as_raw_fd()] {
        require(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0, "retain inherited guest descriptors privately")?;
    }
    config.guest_listener.as_ref().ok_or_else(|| fail("inherited listener lacks cold guest profile"))?.validate(config)?;
    let owner = Arc::clone(config.guest_delivery.as_ref().ok_or_else(|| fail("actual retained guest delivery required"))?);
    let binding = owner.listener_binding()?;
    let handoff = File::from(handoff);
    let original = read_handoff(&handoff)?;
    require(original.api_version == HANDOFF && original.binding == binding && config.guest_listener_owner.is_none(),
        "listener handoff differs from actual signed delivery or repeats activation")?;
    let paths = Paths::open(binding.router_uid)?;
    require(original.directory == paths.directory.identity && original.socket_path == paths.socket.identity
        && original.socket_fd == Identity::fd(socket.as_raw_fd())?, "guest listener descriptor/path originals differ")?;
    socket_check(socket.as_raw_fd(), false)?;
    owner.listener_binding()?;
    config.guest_listener_owner = Some(Arc::new(Mutex::new(Some(Bound { socket, handoff, paths, owner }))));
    Ok(())
}

#[repr(C)]
struct CapHeader { version: u32, pid: i32 }
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData { effective: u32, permitted: u32, inheritable: u32 }
fn final_router(uid: u32, gid: u32) -> Result<(), V2RuntimeError> {
    let mut uids = [0u32; 3]; let mut gids = [0u32; 3];
    let mut header = CapHeader { version:0x2008_0522, pid:0 };
    let mut caps = [CapData { effective:0, permitted:0, inheritable:0 }; 2];
    require(unsafe { libc::getresuid(uids.as_mut_ptr(), uids.as_mut_ptr().add(1), uids.as_mut_ptr().add(2)) } == 0
        && unsafe { libc::getresgid(gids.as_mut_ptr(), gids.as_mut_ptr().add(1), gids.as_mut_ptr().add(2)) } == 0
        && uids == [uid; 3] && gids == [gid; 3] && uid != 0 && uid != GATE_ID
        && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0
        && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1
        && unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) } == 0
        && caps.iter().all(|v| v.effective == 0 && v.permitted == 0 && v.inheritable == 0),
        "guest router requires exact final IDs, no groups/capabilities and no-new-privileges")
}

pub(crate) struct Retention { paths: Paths, handoff: File, owner: Arc<guest_delivery::Delivery>,
    uid:u32, gid:u32, poisoned:AtomicBool }
impl Retention {
    pub(crate) fn check(&self) -> Result<(), V2RuntimeError> {
        let result = (|| {
            require(!self.poisoned.load(Ordering::Acquire), "activated guest listener poisoned")?;
            final_router(self.uid, self.gid)?;
            self.owner.check()?;
            self.paths.check()?;
            let original = read_handoff(&self.handoff)?;
            require(original.api_version == HANDOFF && original.directory == self.paths.directory.identity
                && original.socket_path == self.paths.socket.identity, "activated listener original changed")?;
            self.owner.check()
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
}
pub(crate) fn activate(config: &Config) -> Result<(OwnedFd, Retention), V2RuntimeError> {
    config.guest_listener.as_ref().ok_or_else(|| fail("guest listener profile absent"))?.validate(config)?;
    let slot = config.guest_listener_owner.as_ref().ok_or_else(|| fail("genuine bound listener handoff absent"))?;
    let bound = slot.lock().map_err(|_| fail("listener ownership poisoned"))?.take()
        .ok_or_else(|| fail("guest listener already consumed"))?;
    let actual = config.guest_delivery.as_ref().ok_or_else(|| fail("guest delivery absent"))?;
    require(Arc::ptr_eq(actual, &bound.owner), "listener did not retain the same admitted delivery owner")?;
    let binding = bound.owner.listener_binding()?;
    let original = read_handoff(&bound.handoff)?;
    require(original.binding == binding && original.socket_fd == Identity::fd(bound.socket.as_raw_fd())?,
        "activation changed exact descriptor or authority originals")?;
    bound.paths.check()?;
    socket_check(bound.socket.as_raw_fd(), false)?;
    final_router(binding.router_uid, binding.router_gid)?;
    bound.owner.listener_binding()?;
    // unix_listen snapshots this actual caller's peer credentials, not root's.
    require(unsafe { libc::listen(bound.socket.as_raw_fd(), 64) } == 0, "activate guest listener")?;
    socket_check(bound.socket.as_raw_fd(), true)?;
    bound.owner.listener_binding()?;
    let retention = Retention { paths:bound.paths, handoff:bound.handoff, owner:bound.owner,
        uid:binding.router_uid, gid:binding.router_gid, poisoned:AtomicBool::new(false) };
    retention.check()?;
    Ok((bound.socket, retention))
}
