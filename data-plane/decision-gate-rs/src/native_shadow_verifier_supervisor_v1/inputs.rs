//! Fixed inherited originals. The supervisor never reads the private seed.
use super::ensure;
use crate::native_shadow_verifier_runtime_v1::RuntimeAdmission;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64,
    size: i64, modified: (i64, i64), changed: (i64, i64),
}
fn stat(fd: RawFd) -> Result<libc::stat, String> {
    let mut value = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(fd, &mut value) } == 0, "verifier input stat unavailable")?;
    Ok(value)
}
fn identity(value: libc::stat) -> Identity {
    Identity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink, size: value.st_size,
        modified: (value.st_mtime, value.st_mtime_nsec), changed: (value.st_ctime, value.st_ctime_nsec) }
}
struct Sealed { fd: OwnedFd, identity: Identity, flags: i32 }
impl Sealed {
    fn admit(fd: OwnedFd, maximum: i64) -> Result<Self, String> {
        let info = stat(fd.as_raw_fd())?;
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        ensure(info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_mode & 0o7777 == 0o600
            && info.st_nlink == 0 && info.st_size > 0 && info.st_size <= maximum
            && flags >= 0 && [libc::O_RDONLY,libc::O_RDWR].contains(&(flags & libc::O_ACCMODE))
            && flags & (libc::O_APPEND | libc::O_ASYNC | libc::O_PATH) == 0,
            "verifier sealed input metadata differs")?;
        ensure(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
            "verifier sealed input inheritance could not be closed")?;
        let owner = Self { fd, identity: identity(info), flags };
        owner.check()?; Ok(owner)
    }
    fn check(&self) -> Result<(), String> {
        let fd = self.fd.as_raw_fd();
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        ensure(identity(stat(fd)?) == self.identity
            && unsafe { libc::fcntl(fd, libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(fd, libc::F_GETFD) } == libc::FD_CLOEXEC
            && seals >= 0 && seals & 15 == 15, "verifier sealed input original changed")
    }
}
pub(super) struct Inputs { seed: Sealed, evidence: Sealed, binding: Option<(u32,u32)> }
impl Inputs {
    pub(super) fn take() -> Result<Self, String> {
        // Reserve BOTH real slots before opening any owned object. Missing
        // input can never be replaced by an incidental later open.
        ensure(unsafe { libc::fcntl(4, libc::F_GETFD) } >= 0
            && unsafe { libc::fcntl(5, libc::F_GETFD) } >= 0,
            "verifier requires inherited FD4/FD5 originals")?;
        let seed = unsafe { OwnedFd::from_raw_fd(4) };
        let evidence = unsafe { OwnedFd::from_raw_fd(5) };
        let seed = Sealed::admit(seed, 32)?;
        let evidence = Sealed::admit(evidence, 128 * 1024)?;
        ensure(seed.identity.size == 32
            && (seed.identity.device,seed.identity.inode) != (evidence.identity.device,evidence.identity.inode),
            "verifier seed/evidence are not exact distinct originals")?;
        Ok(Self { seed, evidence, binding: None })
    }
    pub(super) fn bind(&mut self, admission: &RuntimeAdmission) -> Result<(), String> {
        admission.check()?;
        ensure(self.binding.is_none(), "verifier input assignment is once-only")?;
        let expected = (admission.uid(),admission.gid());
        ensure([&self.seed,&self.evidence].iter().all(|original|
            (original.identity.uid,original.identity.gid) == expected),
            "verifier seed/evidence do not belong to the assigned final identity")?;
        self.binding = Some(expected); self.check()
    }
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(self.binding.is_some(), "verifier input assignment absent")?;
        self.seed.check()?; self.evidence.check()
    }
    pub(super) fn seed(&self) -> BorrowedFd<'_> { self.seed.fd.as_fd() }
    pub(super) fn evidence(&self) -> BorrowedFd<'_> { self.evidence.fd.as_fd() }
}

/// The fixed service interface is an inherited stdout pipe, not an arbitrary
/// path/socket/open/write facility. The public transport caller owns its reader.
pub(super) struct Output { fd: OwnedFd, identity: (u64,u64,u32,u32,u32), flags: i32 }
impl Output {
    pub(super) fn take() -> Result<Self, String> {
        let copy = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 128) };
        ensure(copy >= 128, "verifier result pipe unavailable")?;
        let fd = unsafe { OwnedFd::from_raw_fd(copy) };
        let info = stat(copy)?;
        let flags = unsafe { libc::fcntl(copy, libc::F_GETFL) };
        ensure(info.st_mode & libc::S_IFMT == libc::S_IFIFO && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_WRONLY
            && flags & (libc::O_ASYNC | libc::O_APPEND | libc::O_PATH) == 0,
            "verifier output must be the fixed write-only pipe")?;
        ensure(unsafe { libc::fcntl(copy, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "verifier output could not be bounded")?;
        let owner = Self { fd, identity: (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid),
            flags: flags | libc::O_NONBLOCK };
        owner.check()?; Ok(owner)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        let info = stat(self.fd.as_raw_fd())?;
        ensure((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid) == self.identity
            && unsafe { libc::fcntl(self.fd.as_raw_fd(),libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(self.fd.as_raw_fd(),libc::F_GETFD) } == libc::FD_CLOEXEC,
            "verifier result pipe original changed")
    }
    pub(super) fn fd(&self) -> BorrowedFd<'_> { self.fd.as_fd() }
}
