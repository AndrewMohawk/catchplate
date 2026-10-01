//! Held-file and process originals for guest service delivery, never path reopens.
use super::ServiceRunnerError as Error;
use super::super::boottime::BoottimeDomain;
use super::super::super::Sha256Digest;
use std::fs::{File, Metadata};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path};
use zeroize::Zeroizing;

pub(super) fn fail(message: &str) -> Error { Error::invalid(message) }

#[derive(PartialEq, Eq)]
struct Identity {
    dev: u64, ino: u64, mode: u32, uid: u32, gid: u32, links: u64,
    len: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self { dev:m.dev(), ino:m.ino(), mode:m.mode(), uid:m.uid(), gid:m.gid(),
            links:m.nlink(), len:m.len(), mtime:m.mtime(), mtime_ns:m.mtime_nsec(),
            ctime:m.ctime(), ctime_ns:m.ctime_nsec() }
    }
}

pub(super) struct Original { file: File, identity: Identity, sha256: Sha256Digest }
impl Original {
    /// Only the fixed driver continuation calls this after authenticating the
    /// same root parent and its signed, exact descriptor inventory. The parent
    /// has independently opened the protected path; bytes do not prove a path.
    pub(super) fn from_parent_file(file:File,uid:u32,gid:u32,maximum:usize,
        sha256:Sha256Digest)->Result<Self,Error> {
        let m=file.metadata()?;
        let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
        if !m.is_file() || m.uid()!=uid || m.gid()!=gid || m.mode()&0o7777!=0o400
            || m.nlink()!=1 || m.len()==0 || m.len()>maximum as u64 || flags<0
            || flags&(libc::O_ACCMODE|libc::O_PATH|libc::O_APPEND)!=libc::O_RDONLY {
            return Err(fail("late original is not the retained protected read-only file"));
        }
        let owner=Self{file,identity:Identity::of(&m),sha256};owner.check()?;Ok(owner)
    }
    /// The one fixed native entry's independently installed cold original.
    /// A hash derived here is consistency only; protected provisioning is the
    /// trust boundary. There is no unpinned caller-selected path constructor.
    pub(super) fn native_launch() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-guest-launch.json",32768)
    }
    pub(super) fn publication_genesis_parent() -> Result<Self,Error> {
        Self::fixed_native("native-publication-genesis-parent.json",32768)
    }
    pub(super) fn publication_genesis_precreation() -> Result<Self,Error> {
        Self::fixed_native("native-publication-genesis-precreation.json",32768)
    }
    pub(super) fn publication_genesis_endpoints() -> Result<Self,Error> {
        Self::fixed_native("native-publication-genesis-endpoints.json",32768)
    }
    pub(super) fn driver_bootstrap_configuration() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-driver-bootstrap.json",65536)
    }
    pub(super) fn driver_bootstrap_window() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-driver-bootstrap-window.json",32768)
    }
    pub(super) fn ordinary_service_launch(role:&str)->Result<Self,Error> {
        let leaf=match role {
            "durable-recovery-store"=>"custody-durable-recovery-store-guest.json",
            "cleanup-authorization-consumer"=>"custody-cleanup-authorization-consumer-guest.json",
            "recovery-target-provider"=>"custody-recovery-target-provider-guest.json",
            "current-signature-authority"=>"custody-current-signature-authority-guest.json",
            "bounded-cleanup-helper"=>"custody-bounded-cleanup-helper-guest.json",
            _=>return Err(fail("unknown ordinary custody service")),
        };
        let named=Self::fixed_native(leaf,32768)?;
        // This explicit ordinary profile reserves FD4 for the same protected
        // launch original retained by the real parent, not a new path selector.
        let file=unsafe{File::from_raw_fd(4)};
        let flags=unsafe{libc::fcntl(4,libc::F_GETFL)};
        if Identity::of(&file.metadata()?)!=named.identity || flags<0
            || flags&(libc::O_ACCMODE|libc::O_PATH|libc::O_APPEND)!=libc::O_RDONLY {
            return Err(fail("ordinary launch descriptor differs from protected original"));
        }
        super::set_cloexec(4)?;
        Ok(Self{file,identity:named.identity,sha256:named.sha256})
    }
    pub(super) fn retrieval_pair_configuration() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-retrieval-pair.json",32768)
    }
    pub(super) fn retrieval_pair_precreation() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-retrieval-pair-precreation.json",32768)
    }
    pub(super) fn proof_cohort_configuration() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-proof-cohort.json",32768)
    }
    pub(super) fn proof_cohort_precreation() -> Result<Self, Error> {
        Self::fixed_native("native-shadow-proof-cohort-precreation.json",32768)
    }
    fn fixed_native(leaf:&str, maximum:u64) -> Result<Self, Error> {
        let mut file = File::open("/")?;
        for name in ["etc", "serverware", leaf] {
            let parent = file.metadata()?;
            if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
                return Err(fail("native guest launch ancestor is not protected"));
            }
            let name = std::ffi::CString::new(name).map_err(|_| fail("invalid fixed launch name"))?;
            let raw = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
            file = unsafe { File::from_raw_fd(raw) };
        }
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o400
            || m.nlink() != 1 || m.len() == 0 || m.len() > maximum {
            return Err(fail("fixed native original metadata differs"));
        }
        let identity = Identity::of(&m);
        let mut bytes = vec![0; m.len() as usize];
        file.read_exact_at(&mut bytes, 0)?;
        if Identity::of(&file.metadata()?) != identity { return Err(fail("native launch changed")); }
        Ok(Self { file, identity, sha256: Sha256Digest::compute(&bytes) })
    }
    // Admission opens seeds but does not read their contents before final-UID checks.
    pub(super) fn open(path: &Path, uid: u32, gid: u32, maximum: usize,
        sha256: Sha256Digest) -> Result<Self, Error> {
        let text = path.to_str().ok_or_else(|| fail("guest original path is not UTF-8"))?;
        if !path.is_absolute() || text.len() > 4096 || text.split('/').skip(1)
            .any(|v| v.is_empty() || v == "." || v == "..") {
            return Err(fail("guest original requires an exact absolute path"));
        }
        let mut file = File::open("/")?;
        let components: Vec<_> = path.components().collect();
        for (index, part) in components.iter().enumerate().skip(1) {
            let Component::Normal(name) = part else { return Err(fail("invalid original component")); };
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| fail("NUL original path"))?;
            let last = index + 1 == components.len();
            let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
                | if last { 0 } else { libc::O_DIRECTORY };
            let raw = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
            if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
            file = unsafe { File::from_raw_fd(raw) };
            let m = file.metadata()?;
            if !last && (!m.is_dir() || (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0) {
                return Err(fail("guest original has an unprotected ancestor"));
            }
        }
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != 0o400
            || m.nlink() != 1 || m.len() == 0 || m.len() > maximum as u64 {
            return Err(fail("guest original owner, mode, links or size mismatch"));
        }
        Ok(Self { file, identity:Identity::of(&m), sha256 })
    }
    pub(super) fn read(&self, maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.check()?;
        if self.identity.len > maximum as u64 { return Err(fail("guest original exceeds consumer bound")); }
        let mut bytes = Zeroizing::new(vec![0; self.identity.len as usize]);
        let mut offset = 0;
        while offset < bytes.len() {
            let count = self.file.read_at(&mut bytes[offset..], offset as u64)?;
            if count == 0 { return Err(fail("guest original truncated")); }
            offset += count;
        }
        self.check()?;
        if Sha256Digest::compute(&bytes) != self.sha256 { return Err(fail("guest original digest changed")); }
        Ok(bytes)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if Identity::of(&self.file.metadata()?) != self.identity { return Err(fail("held original metadata changed")); }
        Ok(())
    }
    pub(super) fn identity(&self) -> (u64,u64) { (self.identity.dev,self.identity.ino) }
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> {self.file.as_fd()}
}

pub(super) fn live(pidfd: BorrowedFd<'_>) -> Result<(), Error> {
    let mut poll = libc::pollfd { fd:pidfd.as_raw_fd(), events:libc::POLLIN, revents:0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 { return Err(fail("retained process is not live")); }
    Ok(())
}
fn start(pid: i32) -> Result<u64, Error> {
    let bytes = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = bytes.rsplit_once(") ").ok_or_else(|| fail("malformed process stat"))?;
    tail.split_whitespace().nth(19).ok_or_else(|| fail("missing process start time"))?
        .parse().map_err(|_| fail("invalid process start time"))
}
fn pidfd_pid(fd: BorrowedFd<'_>) -> Result<i32, Error> {
    let bytes = std::fs::read_to_string(format!("/proc/self/fdinfo/{}",fd.as_raw_fd()))?;
    let values: Vec<_> = bytes.lines().filter_map(|v| v.strip_prefix("Pid:\t")).collect();
    if values.len() != 1 { return Err(fail("PIDFD lacks one kernel PID")); }
    values[0].parse().map_err(|_| fail("invalid kernel PIDFD identity"))
}
pub(super) struct Process {
    pid: i32, start: u64, pidfd: OwnedFd, domain: BoottimeDomain,
}
impl Process {
    pub(super) fn capture() -> Result<Self, Error> {
        let pid = unsafe { libc::getpid() };
        let first = start(pid)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open,pid,0) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let value = Self { pid, start:first, pidfd:unsafe { OwnedFd::from_raw_fd(raw as i32) },
            domain:BoottimeDomain::current().map_err(|e| Error::invalid(e.to_string()))? };
        value.check()?;
        Ok(value)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        live(self.pidfd.as_fd())?;
        if unsafe { libc::getpid() } != self.pid || start(self.pid)? != self.start
            || pidfd_pid(self.pidfd.as_fd())? != self.pid
            || BoottimeDomain::current().map_err(|e| Error::invalid(e.to_string()))? != self.domain {
            return Err(fail("guest delivery preparation process or boot changed"));
        }
        Ok(())
    }
    pub(super) fn domain(&self) -> BoottimeDomain { self.domain }
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> { self.pidfd.as_fd() }
    pub(super) fn native_binding(&self) -> Result<(i32,u64,u64), Error> {
        self.check()?;
        let stat = super::descriptor_stat(self.pidfd.as_fd())?;
        Ok((self.pid,self.start,stat.st_ino))
    }
}
pub(super) struct Parent { socket: OwnedFd, pidfd: OwnedFd, pid: i32, start: u64, stat: (u64,u64) }
impl Parent {
    pub(super) fn inherited() -> Result<Self, Error> {
        let socket = unsafe { OwnedFd::from_raw_fd(3) };
        super::set_cloexec(3)?;
        Self::from_retained(socket)
    }
    pub(super) fn from_retained(socket:OwnedFd)->Result<Self,Error> {
        let fd=socket.as_raw_fd();super::set_cloexec(fd)?;
        let stat = super::descriptor_stat(socket.as_fd())?;
        let mut kind: i32 = 0;
        let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_TYPE,(&mut kind as *mut i32).cast(),&mut size) } != 0
            || size as usize != std::mem::size_of_val(&kind)
            || kind != libc::SOCK_SEQPACKET || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(fail("guest parent channel is not seqpacket"));
        }
        let mut domain:i32 = 0;
        size = std::mem::size_of_val(&domain) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_DOMAIN,(&mut domain as *mut i32).cast(),&mut size) } != 0
            || size as usize != std::mem::size_of_val(&domain)
            || domain != libc::AF_UNIX { return Err(fail("guest parent channel is not local")); }
        let mut cred:libc::ucred = unsafe { std::mem::zeroed() };
        size = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_PEERCRED,(&mut cred as *mut libc::ucred).cast(),&mut size) } != 0
            || size as usize != std::mem::size_of_val(&cred)
            || cred.pid != unsafe { libc::getppid() } || cred.pid <= 1 || cred.uid != 0 || cred.gid != 0 {
            return Err(fail("guest parent channel does not identify the actual root preparation parent"));
        }
        let mut raw:i32 = -1;
        size = std::mem::size_of_val(&raw) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd,libc::SOL_SOCKET,77,(&mut raw as *mut i32).cast(),&mut size) } != 0 || raw < 0 {
            return Err(fail("guest parent SO_PEERPIDFD unavailable"));
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        if size as usize != std::mem::size_of_val(&raw) { return Err(fail("malformed parent PIDFD result")); }
        let value = Self { socket, pidfd, pid:cred.pid,
            start:start(cred.pid)?, stat:(stat.st_dev,stat.st_ino) };
        value.check()?;
        Ok(value)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.check_identity()?;
        let mut poll = libc::pollfd { fd:self.socket.as_raw_fd(),events:libc::POLLIN,revents:0 };
        if unsafe { libc::poll(&mut poll,1,0) } != 0 { return Err(fail("guest parent channel closed or sent unexpected data")); }
        Ok(())
    }
    fn check_identity(&self) -> Result<(), Error> {
        live(self.pidfd.as_fd())?;
        let stat = super::descriptor_stat(self.socket.as_fd())?;
        if self.pid != unsafe { libc::getppid() } || pidfd_pid(self.pidfd.as_fd())? != self.pid
            || start(self.pid)? != self.start || (stat.st_dev,stat.st_ino) != self.stat {
            return Err(fail("guest parent original changed"));
        }
        Ok(())
    }
    /// Only the explicit cold ordinary entry selects this parent-control
    /// receive path. All existing check()/send() callers still reject input.
    pub(super) fn configure_genesis_stop(&self) -> Result<(), Error> {
        self.check()?;
        for (option,value) in [(libc::SO_PASSCRED,1i32),(76,0i32)] {
            if unsafe{libc::setsockopt(self.socket.as_raw_fd(),libc::SOL_SOCKET,option,
                (&value as *const i32).cast(),std::mem::size_of_val(&value) as _)}!=0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        self.check()
    }
    pub(super) fn genesis_stop_pending(&self) -> Result<bool, Error> {
        self.check_identity()?;
        let mut poll=libc::pollfd{fd:self.socket.as_raw_fd(),events:libc::POLLIN,revents:0};
        let count=unsafe{libc::poll(&mut poll,1,0)};
        if count<0 {return Err(std::io::Error::last_os_error().into());}
        if count==0 {return Ok(false);}
        if poll.revents!=libc::POLLIN {return Err(fail("cold ordinary parent channel failed"));}
        Ok(true)
    }
    pub(super) fn receive_genesis_stop(&self) -> Result<Option<Vec<u8>>, Error> {
        if !self.genesis_stop_pending()? {return Ok(None);}
        let Some(packet)=super::try_receive_packet(self.socket.as_raw_fd(),(self.pid,0,0))? else {return Ok(None)};
        if !packet.rights.is_empty() || packet.frame.len()>4096 {
            return Err(fail("cold ordinary stop violates its descriptor-free bound"));
        }
        // A second queued request is not a retry or a new cleanup authority.
        self.check()?;
        Ok(Some(packet.frame))
    }
    pub(super) fn check_genesis_parent(&self) -> Result<(), Error> {self.check_identity()}
    pub(super) fn genesis_stop_descriptor(&self)->BorrowedFd<'_> {self.socket.as_fd()}
    pub(super) fn identity(&self) -> (u64,u64) { self.stat }
    pub(super) fn native_binding(&self) -> Result<(i32,u64,u64), Error> {
        self.check()?;
        let stat = super::descriptor_stat(self.pidfd.as_fd())?;
        Ok((self.pid,self.start,stat.st_ino))
    }
    pub(super) fn send(&self, bytes:&[u8], deadline:u64) -> Result<(), Error> {
        self.check()?;
        super::send_packet_until(self.socket.as_raw_fd(),bytes,&[],Some(deadline))?;
        self.check()
    }
}
