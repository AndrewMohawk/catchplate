//! Same-process root switch, irreversible role drop, and absolute timers.
//! These are native key-admission observations, never settlement-driver proof.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd,FromRawFd};
use std::os::unix::fs::MetadataExt;

pub(super) fn initial_confinement()->Result<BTreeSet<i32>,ShadowError> {
    let core=libc::rlimit{rlim_cur:0,rlim_max:0};
    require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&core)}==0
        && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0)?;
    // Before any admission open can fill an absent slot, refuse unexpected
    // inherited descriptors. C9 later owns and verifies every selected 6..69
    // original; FD3 is its genuine parent channel. No seed/config import slot.
    let entries=std::fs::read_dir("/proc/self/fd").map_err(fail)?;
    let mut present=BTreeSet::new();
    for entry in entries {
        let name=entry.map_err(fail)?.file_name();
        let fd=name.to_str().ok_or(ShadowError::CustodyUnavailable)?.parse::<i32>().map_err(fail)?;
        present.insert(fd);
    }
    // The read_dir FD has closed. Kernel checks distinguish it from genuine
    // inherited descriptors without reopening or closing caller-selected FDs.
    let mut inherited=BTreeSet::new();
    for fd in present {
        let result=unsafe{libc::fcntl(fd,libc::F_GETFD)};
        if result<0 {
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF))?;continue;
        }
        inherited.insert(fd);
        // FD4 is reserved only for the separately decoded retrieval launch.
        // The entry takes it before opening files and rejects it for old v1.
        if fd<=4 || (6..=69).contains(&fd) {continue;}
        return Err(ShadowError::BindingDrift);
    }
    require(inherited.contains(&3))?;
    Ok(inherited)
}

// The kernel timer ID is an opaque handle, not a Rust memory pointer. Retain
// its actual creating process so owned admission may be checked by threads
// without manufacturing a timer from a caller-supplied scalar.
pub(super) struct Timer {handle:usize,pid:i32,deadline:u64}
impl Timer {
    pub(super) fn arm(deadline:u64)->Result<Self,ShadowError> {
        let mut event:libc::sigevent=unsafe{std::mem::zeroed()};
        event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
        let mut timer=std::ptr::null_mut();
        require(unsafe{libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0)?;
        let owner=Self{handle:timer as usize,pid:unsafe{libc::getpid()},deadline};
        let value=libc::itimerspec {it_interval:libc::timespec{tv_sec:0,tv_nsec:0},
            it_value:libc::timespec{tv_sec:(deadline/1_000_000_000) as _,tv_nsec:(deadline%1_000_000_000) as _}};
        require(unsafe{libc::timer_settime(timer,libc::TIMER_ABSTIME,&value,std::ptr::null_mut())}==0)?;
        Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        require(unsafe{libc::getpid()}==self.pid)?;
        let before=now()?;let mut value:libc::itimerspec=unsafe{std::mem::zeroed()};
        require(unsafe{libc::timer_gettime(self.handle as libc::timer_t,&mut value)}==0)?;
        let after=now()?;
        require(before<=after && after<self.deadline && value.it_interval.tv_sec==0
            && value.it_interval.tv_nsec==0 && value.it_value.tv_sec>=0
            && (0..1_000_000_000).contains(&value.it_value.tv_nsec))?;
        let remaining=(value.it_value.tv_sec as u128)*1_000_000_000+value.it_value.tv_nsec as u128;
        require(remaining>0 && remaining>=(self.deadline-after) as u128
            && remaining<=(self.deadline-before) as u128)
    }
}
impl Drop for Timer {fn drop(&mut self){if unsafe{libc::getpid()}==self.pid {
    unsafe{libc::timer_delete(self.handle as libc::timer_t);}
}}}
pub(super) struct Lifetime {
    association:GuestClosureAssociation,startup:std::sync::Mutex<Option<Timer>>,_lifetime:Timer,parent:i32,
}
impl Lifetime {
    pub(super) fn arm(delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError> {
        let association=delivery.closure_association().map_err(fail)?;
        association.check_preparation().map_err(fail)?;
        let parent=association.owner.parent.native_binding().map_err(fail)?.0;
        require(unsafe{libc::getppid()}==parent
            && unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0
            && unsafe{libc::getppid()}==parent)?;
        let startup=Some(Timer::arm(association.startup())?);
        let lifetime=Timer::arm(association.lifetime())?;
        association.check_preparation().map_err(fail)?;
        Ok(Self{association,startup:std::sync::Mutex::new(startup),_lifetime:lifetime,parent})
    }
    pub(super) fn admitted(&self)->Result<(),ShadowError> {
        self.association.check_startup().map_err(fail)?;
        // Disarm only the completed startup bound. The original absolute
        // lifetime timer was armed before setup and is never replaced.
        self.startup.lock().map_err(fail)?.take().ok_or(ShadowError::CustodyUnavailable)?;
        self.check()
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        self.association.check().map_err(fail)?;
        let mut signal=0;
        require(unsafe{libc::getppid()}==self.parent
            && unsafe{libc::prctl(libc::PR_GET_PDEATHSIG,&mut signal)}==0 && signal==libc::SIGKILL)
    }
    pub(super) fn check_threaded_bridge(&self)->Result<(),ShadowError> {
        self.association.check().map_err(fail)?;
        require(unsafe{libc::getppid()}==self.parent)?;
        self._lifetime.check()?;
        if let Some(timer)=self.startup.lock().map_err(fail)?.as_ref(){timer.check()?;}
        // PDEATHSIG is thread-local. It remains required on the actual
        // initial thread; workers retain the same process-wide SIGKILL timer
        // and genuine C9 parent channel/PIDFD, not an inherited-bit assertion.
        if unsafe{libc::syscall(libc::SYS_gettid)}==unsafe{libc::getpid()} as libc::c_long {
            self.check()?;
        }
        Ok(())
    }
}

pub(super) fn isolate_mounts()->Result<(),ShadowError> {
    require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
        && unsafe{libc::unshare(libc::CLONE_NEWNS)}==0
        && unsafe{libc::mount(std::ptr::null(),b"/\0".as_ptr().cast(),std::ptr::null(),
            libc::MS_PRIVATE|libc::MS_REC,std::ptr::null())}==0)
}

pub(super) fn enter(closure:&PreparedNativeCustodyClosure,delivery:&PreparedGuestServiceDelivery,
    lifetime:&Lifetime)->Result<(),ShadowError> {
    let association=delivery.closure_association().map_err(fail)?;
    association.check_preparation().map_err(fail)?;
    let root=closure.root()?;
    enter_root(root,delivery.role_uid(),delivery.role_gid(),lifetime.parent,
        || association.check_preparation().map_err(fail))?;
    association.check_startup().map_err(fail)?;lifetime.check()
}

/// Only the independently admitted bootstrap owner can select this entry.
/// It shares the irreversible root/drop mechanics, never the old C9 authority.
pub(super) fn enter_bootstrap(owner:&super::driver_bootstrap::Prepared)->Result<(),ShadowError> {
    owner.check_root()?;
    enter_root(owner.root(),owner.uid(),owner.gid(),owner.parent_pid(),||owner.check_root())?;
    owner.check_final()
}
fn enter_root(root:std::os::fd::BorrowedFd<'_>,uid:u32,gid:u32,parent:i32,
    check:impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError> {
    // Clone only the genuine local procfs. The target must be an independently
    // pinned immutable-image directory, not a source/caller path or host relay.
    let raw=unsafe{libc::openat(root.as_raw_fd(),b"proc\0".as_ptr().cast(),
        libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    require(raw>=0)?;let target=unsafe{File::from_raw_fd(raw)};
    let m=target.metadata().map_err(fail)?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    require(m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o555
        && unsafe{libc::fstatfs(target.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x7371_7368)?;
    let proc=File::open("/proc").map_err(fail)?;
    require(unsafe{libc::fstatfs(proc.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x9fa0)?;
    let raw=unsafe{libc::syscall(libc::SYS_open_tree,proc.as_raw_fd(),b"\0".as_ptr().cast::<libc::c_char>(),
        1u32|libc::O_CLOEXEC as u32|libc::AT_EMPTY_PATH as u32)};
    require(raw>=0)?;let tree=unsafe{File::from_raw_fd(raw as i32)};
    #[repr(C)]struct Attributes {set:u64,clear:u64,propagation:u64,userns:u64}
    let attr=Attributes{set:1|2|4|8,clear:0,propagation:0,userns:0};
    require(unsafe{libc::syscall(libc::SYS_mount_setattr,tree.as_raw_fd(),b"\0".as_ptr().cast::<libc::c_char>(),
        libc::AT_EMPTY_PATH,&attr,std::mem::size_of::<Attributes>())}==0
        && unsafe{libc::syscall(libc::SYS_move_mount,tree.as_raw_fd(),b"\0".as_ptr().cast::<libc::c_char>(),
            root.as_raw_fd(),b"proc\0".as_ptr().cast::<libc::c_char>(),4u32)}==0)?;
    check()?;
    require(unsafe{libc::fchdir(root.as_raw_fd())}==0 && unsafe{libc::chroot(b".\0".as_ptr().cast())}==0
        && unsafe{libc::chdir(b"/\0".as_ptr().cast())}==0)?;
    let limits=libc::rlimit{rlim_cur:0,rlim_max:0};
    require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&limits)}==0
        && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0
        && unsafe{libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)}==0
        && unsafe{libc::prctl(47,4,0,0,0)}==0)?; // clear all ambient caps
    for capability in 0..64 {
        let present=unsafe{libc::prctl(libc::PR_CAPBSET_READ,capability,0,0,0)};
        if present<0 {
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EINVAL))?;
            continue;
        }
        if present==1 {require(unsafe{libc::prctl(libc::PR_CAPBSET_DROP,capability,0,0,0)}==0)?;}
    }
    require(unsafe{libc::setgroups(0,std::ptr::null())}==0
        && unsafe{libc::setresgid(gid,gid,gid)}==0
        && unsafe{libc::setresuid(uid,uid,uid)}==0)?;
    #[repr(C)]struct Header{version:u32,pid:i32}
    #[repr(C)]struct Data{effective:u32,permitted:u32,inheritable:u32}
    let header=Header{version:0x2008_0522,pid:0};
    let data=[Data{effective:0,permitted:0,inheritable:0},Data{effective:0,permitted:0,inheritable:0}];
    require(unsafe{libc::syscall(libc::SYS_capset,&header,data.as_ptr())}==0
        && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0
        && unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0
        && unsafe{libc::getppid()}==parent)
}

#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Context {
    api_version:String,profile:String,guest_sha256:Sha256Digest,execution_closure_manifest_sha256:Sha256Digest,
    process_id:i32,process_start_ticks:u64,pidfd_inode:u64,parent_process_id:i32,parent_start_ticks:u64,parent_pidfd_inode:u64,
    cgroup_sha256:Sha256Digest,root_device:u64,root_inode:u64,observed_at_boottime_ns:String,
}
pub(crate) struct ContextOwner {
    association:GuestClosureAssociation,closure:NativeCustodyClosureOwner,context:Context,
}
impl ContextOwner {
    pub(super) fn bind(delivery:&PreparedGuestServiceDelivery,closure:NativeCustodyClosureOwner)->Result<Self,ShadowError> {
        // The root-created association must be retained across drop; this
        // private getter performs no new root-only construction or path open.
        let association=GuestClosureAssociation{owner:Arc::clone(&delivery.owner)};
        association.check_startup().map_err(fail)?;closure.require_origin(&association)?;
        let own=association.owner.process.native_binding().map_err(fail)?;
        let parent=association.owner.parent.native_binding().map_err(fail)?;
        let root=std::fs::metadata("/").map_err(fail)?;
        let cgroup=std::fs::read("/proc/self/cgroup").map_err(fail)?;
        require(!cgroup.is_empty() && cgroup.len()<=16384)?;
        let context=Context{api_version:"serverware.nativeShadowKeyAdmissionContext/v1".into(),
            profile:"same-process-native-originals-v1".into(),guest_sha256:Sha256Digest::compute(&canonical_json_bytes(&association.binding())?),
            execution_closure_manifest_sha256:closure.manifest_sha256().clone(),process_id:own.0,process_start_ticks:own.1,pidfd_inode:own.2,
            parent_process_id:parent.0,parent_start_ticks:parent.1,parent_pidfd_inode:parent.2,cgroup_sha256:Sha256Digest::compute(&cgroup),
            root_device:root.dev(),root_inode:root.ino(),observed_at_boottime_ns:now()?.to_string()};
        let owner=Self{association,closure,context};owner.check()?;Ok(owner)
    }
    pub(crate) fn check(&self)->Result<(),ShadowError> {
        self.association.check().map_err(fail)?;self.closure.require_origin(&self.association)?;
        let own=self.association.owner.process.native_binding().map_err(fail)?;
        let parent=self.association.owner.parent.native_binding().map_err(fail)?;
        let root=std::fs::metadata("/").map_err(fail)?;
        let cgroup=std::fs::read("/proc/self/cgroup").map_err(fail)?;
        require(cgroup.len()<=16384 && (own.0,own.1,own.2)==(self.context.process_id,self.context.process_start_ticks,self.context.pidfd_inode)
            && parent==(self.context.parent_process_id,self.context.parent_start_ticks,self.context.parent_pidfd_inode)
            && (root.dev(),root.ino())==(self.context.root_device,self.context.root_inode)
            && Sha256Digest::compute(&cgroup)==self.context.cgroup_sha256)
    }
    pub(crate) fn value(&self)->Result<Context,ShadowError> {self.check()?;Ok(self.context.clone())}
}
