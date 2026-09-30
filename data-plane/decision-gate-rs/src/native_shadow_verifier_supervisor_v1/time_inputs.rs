//! Retained original seed/socket, reserved before any policy/image open.
use super::{ensure, inputs::Sealed};
use crate::native_shadow_verifier_runtime_v1::{Profile, RuntimeAdmission};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64 }
fn identity(fd: RawFd) -> Result<Identity, String> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(fd, &mut value) } == 0, "issuer socket stat failed")?;
    Ok(Identity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink })
}
fn option<T: Copy + Default>(fd: RawFd, name: i32) -> Result<T, String> {
    let mut value = T::default(); let mut length = std::mem::size_of::<T>() as libc::socklen_t;
    ensure(unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&mut value as *mut T).cast(), &mut length) } == 0
        && length as usize == std::mem::size_of::<T>(), "issuer kernel socket option failed")?;
    Ok(value)
}
fn endpoint(fd: RawFd, peer: bool) -> Result<(IpAddr, u16), String> {
    let mut value: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe { if peer { libc::getpeername(fd, (&mut value as *mut libc::sockaddr_storage).cast(), &mut length) }
        else { libc::getsockname(fd, (&mut value as *mut libc::sockaddr_storage).cast(), &mut length) } };
    ensure(result == 0, "issuer socket is not actually connected")?;
    match value.ss_family as i32 {
        libc::AF_INET => {
            ensure(length as usize == std::mem::size_of::<libc::sockaddr_in>(), "issuer IPv4 tuple shape")?;
            let address = unsafe { &*((&value as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()) };
            Ok((IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())), u16::from_be(address.sin_port)))
        }
        libc::AF_INET6 => {
            ensure(length as usize == std::mem::size_of::<libc::sockaddr_in6>(), "issuer IPv6 tuple shape")?;
            let address = unsafe { &*((&value as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()) };
            ensure(address.sin6_flowinfo == 0 && address.sin6_scope_id == 0, "issuer IPv6 scope is not admitted")?;
            Ok((IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)), u16::from_be(address.sin6_port)))
        }
        _ => Err("issuer transport must be IP TCP".to_owned()),
    }
}

pub(super) struct Inputs {
    seed: Sealed, socket: OwnedFd, identity: Identity, cookie: u64, flags: i32,
    local: (IpAddr, u16), peer: (IpAddr, u16), assigned: bool,
}
impl Inputs {
    pub(super) fn take() -> Result<Self, String> {
        ensure(unsafe { libc::fcntl(4, libc::F_GETFD) } >= 0 && unsafe { libc::fcntl(5, libc::F_GETFD) } >= 0,
            "issuer requires actual inherited seed4/socket5 before admission")?;
        let seed = unsafe { OwnedFd::from_raw_fd(4) };
        let socket = unsafe { OwnedFd::from_raw_fd(5) };
        let seed = Sealed::exact_seed(seed)?;
        ensure(unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
            "issuer socket inheritance could not close")?;
        let fd = socket.as_raw_fd(); let observed = identity(fd)?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure(observed.mode & libc::S_IFMT == libc::S_IFSOCK && observed.uid == 0 && observed.gid == 0
            && flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
            && flags & (libc::O_ASYNC | libc::O_APPEND | libc::O_PATH) == 0
            && option::<i32>(fd, libc::SO_TYPE)? == libc::SOCK_STREAM
            && option::<i32>(fd, libc::SO_ACCEPTCONN)? == 0
            && option::<i32>(fd, libc::SO_PROTOCOL)? == libc::IPPROTO_TCP,
            "issuer inherited transport is not root-owned connected TCP")?;
        ensure(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0, "issuer nonblocking transport unavailable")?;
        let cookie = option::<u64>(fd, 57)?;
        ensure(cookie != 0, "issuer original socket cookie absent")?;
        let owner = Self { seed, local: endpoint(fd, false)?, peer: endpoint(fd, true)?, socket,
            identity: observed, cookie, flags: flags | libc::O_NONBLOCK, assigned: false };
        owner.originals()?; Ok(owner)
    }
    pub(super) fn bind(&mut self, admission: &RuntimeAdmission) -> Result<(), String> {
        admission.check()?;
        ensure(!self.assigned && admission.profile() == Profile::TimeIssuer, "issuer input binding not one-use")?;
        self.seed.assigned(admission.uid(), admission.gid())?;
        let (local, port, peer) = admission.time_transport()?;
        ensure(self.local.0.to_string() == local && self.local.1 == port && self.peer.0.to_string() == peer
            && self.peer.1 > 0, "issuer actual transport tuple differs from cold policy")?;
        self.assigned = true; self.check_connected()
    }
    pub(super) fn bind_origin(&mut self, admission: &RuntimeAdmission) -> Result<(), String> {
        admission.check()?;
        ensure(!self.assigned && admission.profile() == Profile::OriginIssuer, "origin issuer input binding not one-use")?;
        self.seed.assigned(admission.uid(), admission.gid())?;
        let (local, port, peer) = admission.origin_transport()?;
        ensure(self.local.0.to_string() == local && self.local.1 == port && self.peer.0.to_string() == peer
            && self.peer.1 > 0, "origin issuer actual transport tuple differs from cold policy")?;
        self.assigned = true; self.check_connected()
    }
    fn originals(&self) -> Result<(), String> {
        self.seed.check()?; let fd = self.socket.as_raw_fd();
        ensure(identity(fd)? == self.identity && option::<u64>(fd, 57)? == self.cookie
            && unsafe { libc::fcntl(fd, libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(fd, libc::F_GETFD) } == libc::FD_CLOEXEC,
            "issuer seed/socket original changed")
    }
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(self.assigned, "issuer input assignment absent")?; self.originals()
    }
    pub(super) fn check_connected(&self) -> Result<(), String> {
        self.check()?;
        ensure(endpoint(self.socket.as_raw_fd(), false)? == self.local && endpoint(self.socket.as_raw_fd(), true)? == self.peer,
            "issuer original connected tuple changed")
    }
    pub(super) fn seed(&self) -> BorrowedFd<'_> { self.seed.fd() }
    pub(super) fn socket(&self) -> BorrowedFd<'_> { self.socket.as_fd() }
}
