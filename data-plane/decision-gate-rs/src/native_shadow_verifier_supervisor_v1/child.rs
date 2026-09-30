//! Fixed clone-child trampoline. No authority acquisition or secret read here.
use crate::native_shadow_verifier_runtime_v1::{Profile, RuntimeBorrow, INTERPRETER_PATH};
use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

const ROOT: usize = 0;
const EXECUTABLE: usize = 1;
const CONFIGURATION: usize = 2;
const SEED: usize = 3;
const EVIDENCE: usize = 4;
const OUTPUT: usize = 5;
const GATE: usize = 6;
const PARENT: usize = 7;
const NULL: usize = 8;
const MAX_FILTER: usize = 768;
const SECUREBITS: libc::c_ulong = 0xef;
const GATE_BYTE: u8 = 0xa5;
fn require(value: bool, reason: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(reason.to_owned()) }
}
fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
    require(result >= 128, "verifier child original duplication failed")?;
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Descriptor {
    device: u64, inode: u64, rdev: u64, mode: u32, uid: u32, gid: u32, links: u64,
    size: i64, mtime: (i64,i64), ctime: (i64,i64), flags: i32,
}
fn descriptor(fd: RawFd) -> Option<Descriptor> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    let flags = unsafe { libc::syscall(libc::SYS_fcntl,fd,libc::F_GETFL) as i32 };
    if flags < 0 || unsafe { libc::syscall(libc::SYS_fstat,fd,&mut value) } != 0 { return None; }
    Some(Descriptor { device:value.st_dev, inode:value.st_ino, rdev:value.st_rdev,
        mode:value.st_mode, uid:value.st_uid, gid:value.st_gid, links:value.st_nlink, size:value.st_size,
        mtime:(value.st_mtime,value.st_mtime_nsec), ctime:(value.st_ctime,value.st_ctime_nsec), flags })
}
fn live(issued: u64, deadline: u64) -> bool {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) { return false; }
    (value.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v| v.checked_add(value.tv_nsec as u64))
        .is_some_and(|now| issued <= now && now < deadline)
}
fn last_capability() -> Result<u32, String> {
    for number in 0..=64u32 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_READ, number as libc::c_ulong, 0, 0, 0) };
        if result < 0 {
            require(number > 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL),
                "verifier capability ABI unavailable")?;
            return Ok(number - 1);
        }
        require(result <= 1, "verifier capability ABI differs")?;
    }
    Err("verifier capability ceiling exceeds closed ABI".to_owned())
}

pub(super) struct PreparedChild {
    fds: [OwnedFd;9], originals: [Descriptor;9], parent: libc::pid_t,
    uid: u32, gid: u32, issued: u64, deadline: u64, last_cap: u32,
    // CString buffers remain owned at stable addresses through the one clone.
    _arguments: [CString;4], argv: [*const libc::c_char;5],
    filter: Vec<libc::sock_filter>, self_pid_instruction: usize,
}
impl PreparedChild {
    pub(super) fn prepare_origin(runtime: &RuntimeBorrow<'_>, seed: BorrowedFd<'_>, transport: BorrowedFd<'_>,
        output: BorrowedFd<'_>, gate: BorrowedFd<'_>) -> Result<Self, String> {
        require(runtime.profile() == Profile::OriginIssuer, "origin issuer child requires its actual fixed runtime")?;
        Self::prepare_for(runtime, seed, transport, output, gate)
    }
    pub(super) fn prepare_time(runtime: &RuntimeBorrow<'_>, seed: BorrowedFd<'_>, transport: BorrowedFd<'_>,
        output: BorrowedFd<'_>, gate: BorrowedFd<'_>) -> Result<Self, String> {
        require(runtime.profile() == Profile::TimeIssuer, "issuer child requires its actual fixed runtime")?;
        Self::prepare_for(runtime, seed, transport, output, gate)
    }
    pub(super) fn prepare(runtime: &RuntimeBorrow<'_>, seed: BorrowedFd<'_>, evidence: BorrowedFd<'_>,
        output: BorrowedFd<'_>, gate: BorrowedFd<'_>) -> Result<Self, String> {
        require(runtime.profile() == Profile::Verifier, "verifier child cannot select an issuer")?;
        Self::prepare_for(runtime, seed, evidence, output, gate)
    }
    #[cfg(target_arch = "x86_64")]
    fn prepare_for(runtime: &RuntimeBorrow<'_>, seed: BorrowedFd<'_>, evidence: BorrowedFd<'_>,
        output: BorrowedFd<'_>, gate: BorrowedFd<'_>) -> Result<Self, String> {
        use std::os::fd::AsFd;
        let parent = unsafe { libc::getpid() };
        require(parent > 1 && unsafe { libc::syscall(libc::SYS_gettid) } == parent as libc::c_long
            && unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0
            && live(runtime.issued_boottime_ns(), runtime.deadline_boottime_ns()),
            "verifier child preparation lost its root/original interval")?;
        let parent_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, parent, 0) as RawFd };
        require(parent_fd >= 0, "verifier actual parent PIDFD unavailable")?;
        let parent_fd = unsafe { OwnedFd::from_raw_fd(parent_fd) };
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
        require(null_fd >= 0, "verifier null original unavailable")?;
        let null_fd = unsafe { OwnedFd::from_raw_fd(null_fd) };
        let fds = [duplicate(runtime.root())?, duplicate(runtime.interpreter())?, duplicate(runtime.configuration())?,
            duplicate(seed)?, duplicate(evidence)?, duplicate(output)?, duplicate(gate)?,
            duplicate(parent_fd.as_fd())?, duplicate(null_fd.as_fd())?];
        let mut captured = Vec::with_capacity(9);
        for fd in &fds {
            require(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC,
                "verifier child original is inheritable")?;
            captured.push(descriptor(fd.as_raw_fd()).ok_or("verifier child original stat failed")?);
        }
        let originals: [Descriptor;9] = captured.try_into().map_err(|_| "verifier child original inventory differs")?;
        require(originals[NULL].mode & libc::S_IFMT == libc::S_IFCHR
            && originals[NULL].uid == 0 && originals[NULL].gid == 0
            && libc::major(originals[NULL].rdev) == 1 && libc::minor(originals[NULL].rdev) == 3,
            "verifier null original is not the actual device")?;
        for (index, access) in [(OUTPUT,libc::O_WRONLY),(GATE,libc::O_RDONLY)] {
            let original = originals[index];
            require(original.mode & libc::S_IFMT == libc::S_IFIFO && original.links == 1
                && original.flags & libc::O_ACCMODE == access
                && original.flags & (libc::O_NONBLOCK | libc::O_ASYNC) == 0,
                "verifier child private pipe direction/flags differ")?;
        }
        require(originals[OUTPUT].device != originals[GATE].device || originals[OUTPUT].inode != originals[GATE].inode,
            "verifier output aliases its release gate")?;
        let uid = runtime.uid(); let gid = runtime.gid();
        require(uid > 0 && gid > 0 && uid < u32::MAX && gid < u32::MAX,
            "verifier child final identity is not admitted nonroot")?;
        // Parent inputs own the full independent key/evidence admission. These
        // metadata checks only keep exactly those separately sealed originals.
        let sealed: &[(usize, i64)] = match runtime.profile() {
            Profile::Verifier => &[(SEED,32),(EVIDENCE,128 * 1024)],
            Profile::TimeIssuer | Profile::OriginIssuer => &[(SEED,32)],
        };
        for &(index, maximum) in sealed {
            let original = originals[index];
            let seals = unsafe { libc::fcntl(fds[index].as_raw_fd(), libc::F_GET_SEALS) };
            require(original.mode & libc::S_IFMT == libc::S_IFREG && original.mode & 0o7777 == 0o600
                && original.uid == uid && original.gid == gid && original.links == 0
                && original.size > 0 && original.size <= maximum
                && original.flags & (libc::O_APPEND | libc::O_ASYNC | libc::O_PATH) == 0
                && matches!(original.flags & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR)
                && seals >= 0 && seals & 15 == 15,
                "verifier child sealed input original differs")?;
        }
        require(originals[SEED].size == 32 && (originals[SEED].device, originals[SEED].inode)
            != (originals[EVIDENCE].device, originals[EVIDENCE].inode), "verifier child seed/evidence alias or bound")?;
        if matches!(runtime.profile(), Profile::TimeIssuer | Profile::OriginIssuer) {
            let original = originals[EVIDENCE];
            require(original.mode & libc::S_IFMT == libc::S_IFSOCK && original.uid == 0 && original.gid == 0
                && original.flags & libc::O_ACCMODE == libc::O_RDWR && original.flags & libc::O_NONBLOCK != 0
                && original.flags & (libc::O_ASYNC | libc::O_APPEND | libc::O_PATH) == 0,
                "issuer child did not inherit the admitted nonblocking socket")?;
        }
        let arguments = [CString::new(INTERPRETER_PATH).unwrap(), CString::new("-I").unwrap(),
            CString::new("-B").unwrap(), CString::new(runtime.profile().entrypoint()).unwrap()];
        let argv = [arguments[0].as_ptr(),arguments[1].as_ptr(),arguments[2].as_ptr(),arguments[3].as_ptr(),std::ptr::null()];
        let (filter, self_pid_instruction) = filter(fds[EXECUTABLE].as_raw_fd(), runtime.profile())?;
        let owner = Self { fds, originals, parent, uid, gid, issued:runtime.issued_boottime_ns(),
            deadline:runtime.deadline_boottime_ns(), last_cap:last_capability()?, _arguments:arguments,
            argv, filter, self_pid_instruction };
        require(owner.parent_live() && live(owner.issued, owner.deadline), "verifier child preparation lost parent/time")?;
        Ok(owner)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn prepare_for(_: &RuntimeBorrow<'_>, _: BorrowedFd<'_>, _: BorrowedFd<'_>,
        _: BorrowedFd<'_>, _: BorrowedFd<'_>) -> Result<Self, String> {
        Err("external native-shadow verifier requires x86_64".to_owned())
    }
    fn parent_live(&self) -> bool {
        let mut event = libc::pollfd { fd:self.fds[PARENT].as_raw_fd(), events:libc::POLLIN, revents:0 };
        (unsafe { libc::syscall(libc::SYS_poll,&mut event,1usize,0) }) == 0 && event.revents == 0
    }
    /// The caller must be the immediate actual clone3 child of this preparation,
    /// with no CLONE_VM/CLONE_FILES/CLONE_SIGHAND and no intervening Rust work.
    #[cfg(target_arch = "x86_64")]
    pub(super) unsafe fn enter(&self) -> ! {
        unsafe { self.enter_fixed(); }
        unsafe { libc::syscall(libc::SYS_exit_group, 127); }
        loop { std::hint::spin_loop(); }
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) unsafe fn enter(&self) -> ! {
        unsafe { libc::syscall(libc::SYS_exit_group, 127); }
        loop { std::hint::spin_loop(); }
    }
    #[cfg(target_arch = "x86_64")]
    unsafe fn enter_fixed(&self) {
        let child = unsafe { libc::getpid() };
        if child <= 1 || child == self.parent || unsafe { libc::getppid() } != self.parent
            || !self.parent_live() || !live(self.issued,self.deadline)
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0) } != 0 { return; }
        // Only stack values, fixed buffers and raw/libc syscalls after clone.
        for index in 0..9 {
            if descriptor(self.fds[index].as_raw_fd()) != Some(self.originals[index]) { return; }
        }
        let action = Action { handler:0, flags:0, restorer:0, mask:0 };
        for signal in 1..=64 {
            if signal != libc::SIGKILL && signal != libc::SIGSTOP
                && unsafe { libc::syscall(libc::SYS_rt_sigaction,signal,&action,std::ptr::null::<u8>(),8usize) } != 0 { return; }
        }
        let mask = 0u64;
        if unsafe { libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,&mask,std::ptr::null::<u8>(),8usize) } != 0
            || unsafe { libc::fchdir(self.fds[ROOT].as_raw_fd()) } != 0
            || unsafe { libc::chroot(c".".as_ptr()) } != 0 || unsafe { libc::chdir(c"/".as_ptr()) } != 0 { return; }
        for (index,target) in [(NULL,0),(OUTPUT,1),(NULL,2),(CONFIGURATION,3),(SEED,4),(EVIDENCE,5)] {
            if unsafe { libc::dup3(self.fds[index].as_raw_fd(),target,0) } != target { return; }
        }
        unsafe { libc::umask(0o077); }
        if unsafe { libc::syscall(libc::SYS_setgroups,0usize,std::ptr::null::<libc::gid_t>()) } != 0
            || unsafe { libc::prctl(47,4,0,0,0) } != 0 { return; }
        for capability in 0..=self.last_cap {
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP,capability as libc::c_ulong,0,0,0) } != 0 { return; }
        }
        for (resource,maximum) in [(libc::RLIMIT_CORE,0),(libc::RLIMIT_FSIZE,0),(libc::RLIMIT_NPROC,1),
            (libc::RLIMIT_NOFILE,96),(libc::RLIMIT_AS,512*1024*1024),(libc::RLIMIT_STACK,16*1024*1024),
            (libc::RLIMIT_MEMLOCK,0)] {
            let limit = libc::rlimit { rlim_cur:maximum, rlim_max:maximum };
            if unsafe { libc::syscall(libc::SYS_setrlimit,resource,&limit) } != 0 { return; }
        }
        if unsafe { libc::prctl(libc::PR_SET_SECUREBITS,SECUREBITS,0,0,0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0) } != 0
            || unsafe { libc::syscall(libc::SYS_setresgid,self.gid,self.gid,self.gid) } != 0
            || unsafe { libc::syscall(libc::SYS_setresuid,self.uid,self.uid,self.uid) } != 0 { return; }
        let mut header = Header { version:0x2008_0522,pid:0 };
        let mut data = [Capabilities { effective:0,permitted:0,inheritable:0 };2];
        if unsafe { libc::syscall(libc::SYS_capset,&header,data.as_ptr()) } != 0
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0) } != 0
            // Credential transitions clear the original PDEATHSIG setting.
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0) } != 0
            || unsafe { libc::getppid() } != self.parent || !self.parent_live()
            || unsafe { libc::syscall(libc::SYS_capget,&mut header,data.as_mut_ptr()) } != 0
            || data != [Capabilities { effective:0,permitted:0,inheritable:0 };2] { return; }
        let mut uid = [0u32;3]; let mut gid = [0u32;3]; let mut death = 0;
        if unsafe { libc::syscall(libc::SYS_getresuid,uid.as_mut_ptr(),uid.as_mut_ptr().add(1),uid.as_mut_ptr().add(2)) } != 0
            || unsafe { libc::syscall(libc::SYS_getresgid,gid.as_mut_ptr(),gid.as_mut_ptr().add(1),gid.as_mut_ptr().add(2)) } != 0
            || uid != [self.uid;3] || gid != [self.gid;3]
            || unsafe { libc::syscall(libc::SYS_getgroups,0usize,std::ptr::null_mut::<libc::gid_t>()) } != 0
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE,0,0,0,0) } != 0
            || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0) } != 1
            || unsafe { libc::prctl(libc::PR_GET_SECUREBITS,0,0,0,0) } != SECUREBITS as i32
            || unsafe { libc::prctl(libc::PR_GET_PDEATHSIG,&mut death,0,0,0) } != 0 || death != libc::SIGKILL { return; }
        for capability in 0..=self.last_cap {
            if unsafe { libc::prctl(libc::PR_CAPBSET_READ,capability as libc::c_ulong,0,0,0) } != 0
                || unsafe { libc::prctl(47,1,capability as libc::c_ulong,0,0) } != 0 { return; }
        }
        // Do not close the high pinned executable before execveat. All high
        // originals, parent PIDFD and gate are instead guaranteed CLOEXEC.
        if unsafe { libc::syscall(libc::SYS_close_range,6u32,u32::MAX,4u32) } != 0 { return; }
        let empty = libc::sock_filter { code:0,jt:0,jf:0,k:0 };
        let mut filter = [empty;MAX_FILTER];
        unsafe { std::ptr::copy_nonoverlapping(self.filter.as_ptr(),filter.as_mut_ptr(),self.filter.len()); }
        filter[self.self_pid_instruction].k = child as u32;
        let program = libc::sock_fprog { len:self.filter.len() as u16,filter:filter.as_mut_ptr() };
        if unsafe { libc::prctl(libc::PR_SET_SECCOMP,2,&program,0,0) } != 0 { return; }
        if unsafe { libc::getppid() } != self.parent || !self.parent_live() || !live(self.issued,self.deadline) { return; }
        let mut gate = 0u8;
        if unsafe { libc::read(self.fds[GATE].as_raw_fd(),(&mut gate as *mut u8).cast(),1) } != 1 || gate != GATE_BYTE
            || unsafe { libc::getppid() } != self.parent || !self.parent_live() || !live(self.issued,self.deadline) { return; }
        unsafe { libc::close(self.fds[GATE].as_raw_fd()); }
        let environment: [*const libc::c_char;1] = [std::ptr::null()];
        unsafe { libc::syscall(libc::SYS_execveat,self.fds[EXECUTABLE].as_raw_fd(),c"".as_ptr(),
            self.argv.as_ptr(),environment.as_ptr(),libc::AT_EMPTY_PATH); }
    }
}
#[repr(C)]
struct Header { version:u32,pid:i32 }
#[repr(C)]
#[derive(Clone,Copy,PartialEq,Eq)]
struct Capabilities { effective:u32,permitted:u32,inheritable:u32 }
#[repr(C)]
struct Action { handler:usize,flags:usize,restorer:usize,mask:u64 }

#[cfg(target_arch = "x86_64")]
fn filter(executable: RawFd, profile: Profile) -> Result<(Vec<libc::sock_filter>,usize),String> {
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    const KILL: u32 = 0x8000_0000;
    fn s(code:u16,jt:u8,jf:u8,k:u32)->libc::sock_filter {libc::sock_filter {code,jt,jf,k}}
    fn equals(offset:u32,value:u32)->Vec<libc::sock_filter> {
        vec![s(0x20,0,0,offset),s(0x15,1,0,value),s(0x06,0,0,DENY)]
    }
    fn one_of(offset:u32,values:&[u32])->Vec<libc::sock_filter> {
        let mut body=vec![s(0x20,0,0,offset)];
        for value in values {body.push(s(0x15,0,1,*value));body.push(s(0x06,0,0,ALLOW));}
        body.push(s(0x06,0,0,DENY));body
    }
    fn branch(out:&mut Vec<libc::sock_filter>,call:libc::c_long,body:Vec<libc::sock_filter>)->Result<usize,String> {
        require(body.len()<=u8::MAX as usize,"verifier filter branch bound")?;
        out.push(s(0x15,0,body.len() as u8,call as u32));
        let start=out.len();out.extend(body);Ok(start)
    }
    fn readonly(offset:u32)->Vec<libc::sock_filter> {
        vec![s(0x20,0,0,offset),s(0x45,0,1,(libc::O_ACCMODE|libc::O_CREAT|libc::O_TRUNC|libc::O_APPEND
            |libc::O_ASYNC|(libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32),s(0x06,0,0,DENY),s(0x06,0,0,ALLOW)]
    }
    let mut out=vec![s(0x20,0,0,4),s(0x15,1,0,0xc000_003e),s(0x06,0,0,KILL),
        s(0x20,0,0,0),s(0x45,0,1,0x4000_0000),s(0x06,0,0,KILL)];
    // Each body returns; skipped bodies leave the syscall number in A.
    branch(&mut out,libc::SYS_open,readonly(24))?;
    branch(&mut out,libc::SYS_openat,readonly(32))?;
    for syscall in [libc::SYS_write,libc::SYS_writev] {branch(&mut out,syscall,one_of(16,&[1,2]))?;}
    let mut exec=equals(16,executable as u32);exec.extend(equals(20,0));
    exec.extend(equals(48,libc::AT_EMPTY_PATH as u32));exec.extend(equals(52,0));exec.push(s(0x06,0,0,ALLOW));
    branch(&mut out,libc::SYS_execveat,exec)?;
    let mut own=equals(16,0);own.extend(equals(20,0));own.extend(equals(24,0));own.extend(equals(28,0));own.push(s(0x06,0,0,ALLOW));
    let self_pid_instruction=branch(&mut out,libc::SYS_pidfd_open,own)?+1;
    // No dup variants or F_DUPFD; Python can only inspect descriptors or make
    // its inherited originals non-inheritable, never clear CLOEXEC.
    let mut fcntl=vec![s(0x20,0,0,24),s(0x15,0,4,libc::F_SETFD as u32)];
    fcntl.extend(equals(32,libc::FD_CLOEXEC as u32));fcntl.push(s(0x06,0,0,ALLOW));
    if matches!(profile, Profile::TimeIssuer | Profile::OriginIssuer) {
        // CPython may use F_SETFL for setblocking(False). Only the inherited
        // channel and exactly its already-admitted flags may be selected.
        let mut set = equals(16,5); set.extend(equals(20,0));
        set.extend(equals(32,(libc::O_RDWR | libc::O_NONBLOCK) as u32));set.extend(equals(36,0));
        set.push(s(0x06,0,0,ALLOW));
        fcntl.extend([s(0x20,0,0,24),s(0x15,0,set.len() as u8,libc::F_SETFL as u32)]);fcntl.extend(set);
    }
    fcntl.extend(one_of(24,&[libc::F_GETFD as u32,libc::F_GETFL as u32,libc::F_GET_SEALS as u32,libc::F_GETPIPE_SZ as u32]));
    branch(&mut out,libc::SYS_fcntl,fcntl)?;
    let mut ioctl = Vec::new();
    if matches!(profile, Profile::TimeIssuer | Profile::OriginIssuer) {
        let mut io = equals(16,5);io.extend(equals(20,0));io.push(s(0x06,0,0,ALLOW));
        ioctl.extend([s(0x20,0,0,24),s(0x15,0,io.len() as u8,libc::FIONBIO as u32)]);ioctl.extend(io);
    }
    ioctl.extend(one_of(24,&[libc::TCGETS as u32,libc::FIONREAD as u32,libc::FIOCLEX as u32]));
    branch(&mut out,libc::SYS_ioctl,ioctl)?;
    if matches!(profile, Profile::TimeIssuer | Profile::OriginIssuer) {
        for syscall in [libc::SYS_getsockname,libc::SYS_getpeername] {
            let mut body=equals(16,5);body.extend(equals(20,0));body.push(s(0x06,0,0,ALLOW));
            branch(&mut out,syscall,body)?;
        }
        let mut options=equals(16,5);options.extend(equals(20,0));options.extend(equals(24,libc::SOL_SOCKET as u32));
        options.extend(equals(28,0));options.extend(one_of(32,&[libc::SO_TYPE as u32,libc::SO_DOMAIN as u32,
            libc::SO_PROTOCOL as u32,libc::SO_ACCEPTCONN as u32,57]));
        branch(&mut out,libc::SYS_getsockopt,options)?;
        let mut send=equals(16,5);send.extend(equals(20,0));send.extend(equals(40,libc::MSG_NOSIGNAL as u32));
        send.extend(equals(44,0));send.extend(equals(48,0));send.extend(equals(52,0));
        send.extend(equals(56,0));send.extend(equals(60,0));send.push(s(0x06,0,0,ALLOW));
        branch(&mut out,libc::SYS_sendto,send)?;
        let mut receive=equals(16,5);receive.extend(equals(20,0));
        receive.extend(one_of(40,&[0,(libc::MSG_PEEK | libc::MSG_DONTWAIT) as u32]));
        branch(&mut out,libc::SYS_recvfrom,receive)?;
        let mut shutdown=equals(16,5);shutdown.extend(equals(20,0));shutdown.extend(equals(24,libc::SHUT_RDWR as u32));
        shutdown.extend(equals(28,0));shutdown.push(s(0x06,0,0,ALLOW));
        branch(&mut out,libc::SYS_shutdown,shutdown)?;
        // No socket/connect/bind/listen/accept, sendmsg/SCM_RIGHTS, exec variants
        // or writable files. The existing closed default remains EPERM.
    }
    let mut prctl=vec![s(0x20,0,0,16),s(0x15,0,4,libc::PR_SET_DUMPABLE as u32)];
    prctl.extend(equals(24,0));prctl.push(s(0x06,0,0,ALLOW));
    prctl.extend([s(0x20,0,0,16),s(0x15,0,4,libc::PR_SET_NO_NEW_PRIVS as u32)]);
    prctl.extend(equals(24,1));prctl.push(s(0x06,0,0,ALLOW));
    prctl.extend(one_of(16,&[libc::PR_GET_DUMPABLE as u32,libc::PR_GET_NO_NEW_PRIVS as u32]));
    branch(&mut out,libc::SYS_prctl,prctl)?;
    // Existing hard CORE=0 cannot be raised by the unprivileged interpreter.
    branch(&mut out,libc::SYS_setrlimit,one_of(16,&[libc::RLIMIT_CORE]))?;
    let mut limit=equals(16,0);limit.extend(equals(20,0));
    limit.extend([s(0x20,0,0,24),s(0x15,0,1,libc::RLIMIT_CORE),s(0x06,0,0,ALLOW)]);
    limit.extend(equals(32,0));limit.extend(equals(36,0));limit.push(s(0x06,0,0,ALLOW));
    branch(&mut out,libc::SYS_prlimit64,limit)?;
    branch(&mut out,libc::SYS_arch_prctl,one_of(16,&[0x1002,0x1003]))?;
    let mmap=vec![s(0x20,0,0,32),s(0x45,0,3,libc::PROT_WRITE as u32),
        s(0x20,0,0,40),s(0x45,0,1,libc::MAP_SHARED as u32),s(0x06,0,0,DENY),s(0x06,0,0,ALLOW)];
    branch(&mut out,libc::SYS_mmap,mmap)?;
    for syscall in [libc::SYS_read,libc::SYS_pread64,libc::SYS_close,libc::SYS_fstat,libc::SYS_stat,libc::SYS_lstat,
        libc::SYS_newfstatat,libc::SYS_statx,libc::SYS_lseek,libc::SYS_readlink,libc::SYS_readlinkat,libc::SYS_getdents64,
        libc::SYS_access,libc::SYS_faccessat,libc::SYS_faccessat2,libc::SYS_getcwd,libc::SYS_fstatfs,libc::SYS_statfs,
        libc::SYS_poll,libc::SYS_ppoll,libc::SYS_clock_gettime,libc::SYS_clock_getres,libc::SYS_gettimeofday,libc::SYS_time,
        libc::SYS_getpid,libc::SYS_getppid,libc::SYS_gettid,libc::SYS_getuid,libc::SYS_geteuid,libc::SYS_getgid,libc::SYS_getegid,
        libc::SYS_getresuid,libc::SYS_getresgid,libc::SYS_getgroups,libc::SYS_uname,libc::SYS_sysinfo,libc::SYS_getrusage,
        libc::SYS_getrandom,libc::SYS_getrlimit,libc::SYS_brk,libc::SYS_munmap,libc::SYS_mprotect,libc::SYS_mremap,
        libc::SYS_madvise,libc::SYS_futex,libc::SYS_set_tid_address,libc::SYS_set_robust_list,libc::SYS_rseq,
        libc::SYS_rt_sigaction,libc::SYS_rt_sigprocmask,libc::SYS_rt_sigreturn,libc::SYS_sigaltstack,
        libc::SYS_exit,libc::SYS_exit_group] {
        branch(&mut out,syscall,vec![s(0x06,0,0,ALLOW)])?;
    }
    out.push(s(0x06,0,0,DENY));
    require(out.len()<=MAX_FILTER && self_pid_instruction<out.len(),"verifier fixed filter exceeds preallocated bound")?;
    Ok((out,self_pid_instruction))
}
