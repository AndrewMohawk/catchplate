//! Fixed single-thread inspector identity and syscall ceiling.
use super::{wire::require, INSPECTOR_ID};
use std::{fs, io, mem::zeroed};

const CAP_VERSION: u32 = 0x2008_0522;
const PTRACECAP: u32 = 19;
const SECUREBITS: libc::c_ulong = 0xef;
#[repr(C)]
struct Header { version: u32, pid: i32 }
#[repr(C)]
#[derive(Clone, Copy)]
struct Data { effective: u32, permitted: u32, inheritable: u32 }

pub(super) struct Owner { pid: libc::pid_t, parent: libc::pid_t, last_cap: u32 }
fn ids() -> io::Result<([u32; 3], [u32; 3])> {
    let mut uid = [0; 3]; let mut gid = [0; 3];
    require(unsafe { libc::getresuid(uid.as_mut_ptr(), uid.as_mut_ptr().add(1), uid.as_mut_ptr().add(2)) } == 0
        && unsafe { libc::getresgid(gid.as_mut_ptr(), gid.as_mut_ptr().add(1), gid.as_mut_ptr().add(2)) } == 0, "read inspector identities")?;
    Ok((uid, gid))
}
pub(super) fn single_thread() -> io::Result<()> {
    let pid = unsafe { libc::getpid() };
    require(unsafe { libc::syscall(libc::SYS_gettid) } == pid as libc::c_long, "inspector must be initial thread")?;
    let mut tasks = fs::read_dir("/proc/self/task")?;
    let one = tasks.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing inspector task"))??;
    require(one.file_name() == pid.to_string().as_str() && tasks.next().is_none(), "inspector must be single-threaded")
}
fn last_cap() -> io::Result<u32> {
    for n in 0..=64u32 {
        let value = unsafe { libc::prctl(libc::PR_CAPBSET_READ, n as libc::c_ulong, 0, 0, 0) };
        if value < 0 {
            require(n > PTRACECAP && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL), "capability ABI unavailable")?;
            return Ok(n - 1);
        }
        require(value == 0 || value == 1, "invalid capability bound")?;
    }
    Err(io::Error::new(io::ErrorKind::Unsupported, "capability ABI exceeds fixed bound"))
}
pub(super) fn enter(parent: libc::pid_t) -> io::Result<Owner> {
    single_thread()?;
    require(ids()? == ([0; 3], [0; 3]) && parent > 0 && unsafe { libc::getppid() } == parent,
        "inspector requires its actual root launch parent")?;
    let last_cap = last_cap()?;
    // No core dumps, unbounded FD acquisition, or unbounded address-space use.
    for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_NOFILE, 256),
        (libc::RLIMIT_AS, 512 * 1024 * 1024)] {
        let limit = libc::rlimit { rlim_cur:value, rlim_max:value };
        require(unsafe { libc::setrlimit(resource, &limit) } == 0, "inspector resource limit")?;
    }
    require(unsafe { libc::setgroups(0, std::ptr::null()) } == 0
        && unsafe { libc::prctl(47, 4, 0, 0, 0) } == 0, "drop inspector supplementary/ambient authority")?;
    for n in 0..=last_cap {
        if n != PTRACECAP {
            require(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, n as libc::c_ulong, 0, 0, 0) } == 0,
                "drop inspector capability bound")?;
        }
    }
    // NO_SETUID_FIXUP retains the effective set only until the immediately
    // following explicit capset; NOROOT and every securebit are then locked.
    require(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0) } == 0
        && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
        && unsafe { libc::setresgid(INSPECTOR_ID, INSPECTOR_ID, INSPECTOR_ID) } == 0
        && unsafe { libc::setresuid(INSPECTOR_ID, INSPECTOR_ID, INSPECTOR_ID) } == 0,
        "permanent inspector identity drop")?;
    let header = Header { version:CAP_VERSION, pid:0 };
    let data = [Data { effective:1 << PTRACECAP, permitted:1 << PTRACECAP, inheritable:0 },
        Data { effective:0, permitted:0, inheritable:0 }];
    require(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } == 0
        && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0
        // Changing effective credentials clears PDEATHSIG. Set it afterwards,
        // then close the parent-death race by checking the same actual parent.
        && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0
        && unsafe { libc::getppid() } == parent, "inspector capability or parent binding")?;
    let owner = Owner { pid:unsafe { libc::getpid() }, parent, last_cap };
    owner.check_identity()?;
    single_thread()?;
    install()?;
    owner.check()?;
    Ok(owner)
}
impl Owner {
    fn check_identity(&self) -> io::Result<()> {
        let mut header = Header { version:CAP_VERSION, pid:0 };
        let mut data: [Data; 2] = unsafe { zeroed() };
        let mut death = 0;
        require(unsafe { libc::getpid() } == self.pid && unsafe { libc::getppid() } == self.parent
            && ids()? == ([INSPECTOR_ID; 3], [INSPECTOR_ID; 3])
            && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0
            && unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0
            && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1
            && unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } == SECUREBITS as i32
            && unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death, 0, 0, 0) } == 0
            && death == libc::SIGKILL
            && unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } == 0
            && data[0].effective == 1 << PTRACECAP && data[0].permitted == 1 << PTRACECAP
            && data[0].inheritable == 0 && data[1].effective == 0
            && data[1].permitted == 0 && data[1].inheritable == 0, "inspector confinement changed")?;
        for n in 0..=self.last_cap {
            require(unsafe { libc::prctl(libc::PR_CAPBSET_READ, n as libc::c_ulong, 0, 0, 0) } == i32::from(n == PTRACECAP)
                && unsafe { libc::prctl(47, 1, n as libc::c_ulong, 0, 0) } == 0, "inspector capability bound changed")?;
        }
        Ok(())
    }
    pub(super) fn check(&self) -> io::Result<()> {
        self.check_identity()?;
        require(unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } == 2, "inspector filter absent")
    }
}

#[cfg(target_arch = "x86_64")]
fn install() -> io::Result<()> {
    const ALLOW: u32 = 0x7fff_0000;
    const KILL: u32 = 0x8000_0000;
    fn s(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter { libc::sock_filter { code, jt, jf, k } }
    fn branch(out: &mut Vec<libc::sock_filter>, syscall: libc::c_long, body: Vec<libc::sock_filter>) {
        out.push(s(0x15, 0, body.len() as u8, syscall as u32));
        out.extend(body);
    }
    fn equals(offset: u32, allowed: &[u32]) -> Vec<libc::sock_filter> {
        let mut result = vec![s(0x20, 0, 0, offset)];
        for value in allowed { result.push(s(0x15, 0, 1, *value)); result.push(s(0x06, 0, 0, ALLOW)); }
        result.push(s(0x06, 0, 0, KILL)); result
    }
    fn readonly(offset: u32) -> Vec<libc::sock_filter> {
        vec![s(0x20, 0, 0, offset), s(0x45, 0, 1,
            (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND
                | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32),
            s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)]
    }
    let mut filter = vec![s(0x20, 0, 0, 4), s(0x15, 1, 0, 0xc000_003e),
        s(0x06, 0, 0, KILL), s(0x20, 0, 0, 0)];
    // No x32 ABI, unknown syscall, writes, ptrace/process_vm, process/namespace
    // creation, exec, mount, signal-to-target, network connect or new sockets.
    branch(&mut filter, libc::SYS_open, readonly(24));
    branch(&mut filter, libc::SYS_openat, readonly(32));
    branch(&mut filter, libc::SYS_recvmsg, equals(16, &[4]));
    // The only emitted bytes go to the two already-owned private endpoints.
    // sendmsg is denied entirely, so no descriptor can be returned.
    branch(&mut filter, libc::SYS_sendto, vec![
        s(0x20, 0, 0, 48), s(0x15, 1, 0, 0), s(0x06, 0, 0, KILL),
        s(0x20, 0, 0, 52), s(0x15, 1, 0, 0), s(0x06, 0, 0, KILL),
        s(0x20, 0, 0, 16), s(0x15, 2, 0, 3), s(0x15, 1, 0, 4),
        s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)]);
    branch(&mut filter, libc::SYS_fcntl, equals(24, &[libc::F_GETFD as u32, libc::F_GETFL as u32,
        libc::F_GET_SEALS as u32, libc::F_DUPFD_CLOEXEC as u32]));
    branch(&mut filter, libc::SYS_getsockopt, vec![
        s(0x20, 0, 0, 24), s(0x15, 1, 0, libc::SOL_SOCKET as u32), s(0x06, 0, 0, KILL),
        s(0x20, 0, 0, 32),
        s(0x15, 7, 0, libc::SO_PEERCRED as u32), s(0x15, 6, 0, libc::SO_PEERSEC as u32),
        s(0x15, 5, 0, 77), s(0x15, 4, 0, libc::SO_TYPE as u32),
        s(0x15, 3, 0, libc::SO_DOMAIN as u32), s(0x15, 2, 0, libc::SO_PROTOCOL as u32),
        s(0x15, 1, 0, libc::SO_ACCEPTCONN as u32), s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)]);
    let mut prctl = vec![s(0x20, 0, 0, 16), s(0x15, 0, 4, 47),
        s(0x20, 0, 0, 24), s(0x15, 1, 0, 1), s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)];
    prctl.extend(equals(16, &[libc::PR_GET_DUMPABLE as u32, libc::PR_GET_NO_NEW_PRIVS as u32,
        libc::PR_GET_SECUREBITS as u32, libc::PR_GET_PDEATHSIG as u32,
        libc::PR_CAPBSET_READ as u32, libc::PR_GET_SECCOMP as u32]));
    branch(&mut filter, libc::SYS_prctl, prctl);
    branch(&mut filter, libc::SYS_mmap, vec![
        s(0x20, 0, 0, 32), s(0x45, 0, 1, libc::PROT_EXEC as u32), s(0x06, 0, 0, KILL),
        s(0x20, 0, 0, 40), s(0x45, 1, 0, libc::MAP_ANONYMOUS as u32),
        s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)]);
    branch(&mut filter, libc::SYS_mprotect, vec![
        s(0x20, 0, 0, 32), s(0x45, 0, 1, libc::PROT_EXEC as u32),
        s(0x06, 0, 0, KILL), s(0x06, 0, 0, ALLOW)]);
    for syscall in [libc::SYS_read, libc::SYS_pread64, libc::SYS_close, libc::SYS_fstat,
        libc::SYS_newfstatat, libc::SYS_statx, libc::SYS_fgetxattr, libc::SYS_lseek,
        libc::SYS_readlink, libc::SYS_readlinkat, libc::SYS_getdents64, libc::SYS_getpeername,
        libc::SYS_poll, libc::SYS_ppoll, libc::SYS_clock_gettime,
        libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid, libc::SYS_getresuid,
        libc::SYS_getresgid, libc::SYS_getgroups, libc::SYS_capget,
        libc::SYS_brk, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_madvise,
        libc::SYS_futex, libc::SYS_rt_sigreturn, libc::SYS_exit, libc::SYS_exit_group] {
        branch(&mut filter, syscall, vec![s(0x06, 0, 0, ALLOW)]);
    }
    filter.push(s(0x06, 0, 0, KILL));
    let program = libc::sock_fprog { len:filter.len().try_into().map_err(|_| io::Error::other("inspector filter length"))?,
        filter:filter.as_mut_ptr() };
    require(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) } == 0, "install inspector syscall ceiling")
}
#[cfg(not(target_arch = "x86_64"))]
fn install() -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "inspector requires measured x86_64 closure")) }
