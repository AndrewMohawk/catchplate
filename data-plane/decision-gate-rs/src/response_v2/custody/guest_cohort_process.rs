//! Private fixed-role process ownership. Numeric IDs only compare identities
//! already supplied atomically by clone3 and kernel PIDFD ancillary messages.
use super::{config::{CustodyServiceRole as Role, ScopedCustodyServiceConfig},
    guest_inspector_parent_image::Sealed, guest_inspector_parent_process as kernel,
    peer_measurement as peer};
use crate::native_serving_privileges::Prepared;
use serde::{Deserialize, Serialize};
use std::{mem::{size_of, zeroed}, os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicBool, AtomicU8, Ordering}};

fn duplicate(fd: RawFd) -> Result<OwnedFd, String> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 11) };
    if copy < 0 { return Err("guest role inheritance duplication failed".into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}
#[repr(C)]
struct KernelSigaction { handler: usize, flags: usize, restorer: usize, mask: u64 }

// No allocator, destructor, callback or inherited environment before this
// fixed exec. Every source FD was moved above every fixed target before clone.
unsafe fn child(parent: libc::pid_t, inherited: &[RawFd; 7], router: bool, executable: RawFd) -> ! {
    let mut good = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0
        && unsafe { libc::getppid() } == parent;
    good &= unsafe { libc::dup3(inherited[0], 3, 0) } == 3;
    good &= unsafe { libc::dup3(inherited[1], 5, 0) } == 5;
    unsafe { libc::close(4); }
    for index in 0..5 {
        let target = 6 + index as i32;
        if router { good &= unsafe { libc::dup3(inherited[index + 2], target, 0) } == target; }
        else { unsafe { libc::close(target); } }
    }
    let action = KernelSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    for signal in 1..=64 {
        if signal != libc::SIGKILL && signal != libc::SIGSTOP {
            good &= unsafe { libc::syscall(libc::SYS_rt_sigaction, signal, &action,
                std::ptr::null::<u8>(), 8usize) } == 0;
        }
    }
    let mask = 0u64;
    good &= unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, &mask,
        std::ptr::null::<u8>(), 8usize) } == 0;
    good &= unsafe { libc::chdir(b"/\0".as_ptr().cast()) } == 0;
    unsafe { libc::umask(0o077); }
    for fd in 0..3 { unsafe { libc::close(fd); } }
    good &= unsafe { libc::syscall(libc::SYS_close_range, 11u32, u32::MAX, 4u32) } == 0;
    if good {
        let argv = [b"serverware-response-v2-guest-role\0".as_ptr().cast::<libc::c_char>(), std::ptr::null()];
        let env: [*const libc::c_char; 1] = [std::ptr::null()];
        unsafe { libc::syscall(libc::SYS_execveat, executable, b"\0".as_ptr(), argv.as_ptr(),
            env.as_ptr(), libc::AT_EMPTY_PATH); }
    }
    unsafe { libc::syscall(libc::SYS_exit_group, 127); }
    loop { std::hint::spin_loop(); }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Phase { Listening, Started }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Progress {
    api_version: String, channel_nonce: String, bootstrap_sha256: String,
    service_role: Role, phase: Phase,
}

pub(super) struct RoleProcess {
    role: Role,
    pidfd: OwnedFd,
    channel: OwnedFd,
    pid: libc::pid_t,
    parent: libc::pid_t,
    uid: u32,
    gid: u32,
    nonce: String,
    bootstrap_sha256: String,
    deadline: u64,
    phase: AtomicU8,
    stopped: AtomicBool,
    reaped: AtomicBool,
}
impl RoleProcess {
    pub(super) fn spawn(executable: &Sealed, bootstrap: &Sealed, nonce: &str,
        scoped: &ScopedCustodyServiceConfig, prepared: &Prepared, router: &[BorrowedFd<'_>]) -> Result<Self, String> {
        prepared.check()?;
        executable.check()?;
        bootstrap.check()?;
        let is_router = scoped.role == Role::CustodyRouter;
        if (is_router && router.len() != 5) || (!is_router && !router.is_empty()) {
            return Err("guest role descriptor recipe differs from its signed role".into());
        }
        let mut disposition: libc::sigaction = unsafe { zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0
            || disposition.sa_sigaction != libc::SIG_DFL || disposition.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err("guest role requires exactly waitable children".into());
        }
        let (parent_channel, child_channel) = kernel::pair()?;
        let mut sources = vec![duplicate(child_channel.as_raw_fd())?, duplicate(bootstrap.file().as_raw_fd())?];
        for fd in router { sources.push(duplicate(fd.as_raw_fd())?); }
        let executable = duplicate(executable.file().as_raw_fd())?;
        let mut inherited = [-1; 7];
        for (slot, source) in inherited.iter_mut().zip(&sources) { *slot = source.as_raw_fd(); }
        let parent = unsafe { libc::getpid() };
        let mut pidfd: i32 = -1;
        let args = CloneArgs { flags: libc::CLONE_PIDFD as u64, pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64, ..CloneArgs::default() };
        prepared.check()?;
        let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>()) };
        if pid == 0 { unsafe { child(parent, &inherited, is_router, executable.as_raw_fd()); } }
        if pid < 0 { return Err("guest fixed role clone3 failed".into()); }
        if pidfd < 0 { return Err("guest role clone3 returned no child PIDFD".into()); }
        let process = Self {
            role: scoped.role, pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) }, channel: parent_channel,
            pid: pid as libc::pid_t, parent, uid: scoped.process.uid, gid: scoped.process.gid,
            nonce: nonce.to_owned(), bootstrap_sha256: bootstrap.sha256().to_owned(), deadline: prepared.deadline(),
            phase: AtomicU8::new(0), stopped: AtomicBool::new(false), reaped: AtomicBool::new(false),
        };
        drop(sources); drop(child_channel); drop(executable);
        prepared.check()?;
        process.check()?;
        Ok(process)
    }
    pub(super) fn role(&self) -> Role { self.role }
    pub(super) fn reached(&self, started: bool) -> bool {
        self.phase.load(Ordering::Acquire) >= if started { 2 } else { 1 }
    }
    fn check(&self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.parent || self.stopped.load(Ordering::Acquire)
            || self.reaped.load(Ordering::Acquire) || kernel::now()? >= self.deadline {
            return Err("guest role original process lifetime is unavailable".into());
        }
        peer::ensure_pidfd_alive(&self.pidfd).map_err(|_| "owned guest role exited".into())
    }
    pub(super) fn observe_progress(&self, startup_deadline: u64) -> Result<(), String> {
        self.check()?;
        let until = startup_deadline.min(self.deadline);
        if kernel::now()? >= until { return Err("guest role progress exceeded original startup admission".into()); }
        let mut descriptor = libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { return Ok(()); }
        if ready == 0 && descriptor.revents == 0 { return Ok(()); }
        if ready != 1 || descriptor.revents != libc::POLLIN {
            return Err("guest role startup channel closed or failed".into());
        }
        let (raw, sender, credentials) = kernel::receive(self.channel.as_raw_fd())?;
        if raw.len() > 1024 || credentials.pid != self.pid || credentials.uid != self.uid || credentials.gid != self.gid {
            return Err("guest role progress sender is not its actual final signed identity".into());
        }
        peer::prove_pidfds_same_process(&self.pidfd, &sender, self.pid)
            .map_err(|_| "guest role progress PIDFD differs from owned child")?;
        let progress: Progress = crate::decode_canonical_json(&raw).map_err(|_| "guest role progress contract differs")?;
        let (before, after) = match progress.phase { Phase::Listening => (0, 1), Phase::Started => (1, 2) };
        if progress.api_version != "serverware.responseV2.guestRoleStartup/v1"
            || progress.channel_nonce != self.nonce || progress.bootstrap_sha256 != self.bootstrap_sha256
            || progress.service_role != self.role || self.phase.load(Ordering::Acquire) != before {
            return Err("guest role progress is not the next phase of its original bootstrap".into());
        }
        self.check()?;
        if kernel::now()? >= until { return Err("guest role progress arrived after original admission".into()); }
        self.phase.store(after, Ordering::Release);
        Ok(())
    }
    pub(super) fn idle(&self) -> Result<(), String> {
        self.check()?;
        if self.phase.load(Ordering::Acquire) != 2 { return Err("guest role local startup has not completed".into()); }
        let mut descriptor = libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut descriptor, 1, 0) } != 0 || descriptor.revents != 0 {
            return Err("guest role lifetime channel closed or sent extra progress".into());
        }
        Ok(())
    }
    pub(super) fn poll_descriptors(&self, result: &mut Vec<libc::pollfd>) {
        result.push(libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        result.push(libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
    }
    pub(super) fn stop(&self) {
        if unsafe { libc::getpid() } != self.parent || self.stopped.swap(true, Ordering::AcqRel) { return; }
        unsafe {
            libc::shutdown(self.channel.as_raw_fd(), libc::SHUT_RDWR);
            // Root can kill before its one-way drop. After it, the retained
            // private channel/child monitor and absolute timer enforce stop;
            // success is never inferred from this cross-UID signal attempt.
            libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(), 0);
        }
    }
    fn try_reap(&self) -> Result<bool, String> {
        if unsafe { libc::getpid() } != self.parent { return Err("guest role reap crossed creator".into()); }
        if self.reaped.load(Ordering::Acquire) { return Ok(true); }
        let mut info: libc::siginfo_t = unsafe { zeroed() };
        if unsafe { libc::waitid(libc::P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t, &mut info,
            libc::WEXITED | libc::WNOHANG) } != 0 { return Err("guest role exact reap failed".into()); }
        if unsafe { info.si_pid() } == 0 { return Ok(false); }
        if unsafe { info.si_pid() } != self.pid || info.si_signo != libc::SIGCHLD
            || !matches!(info.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED) {
            return Err("guest role reap identity differs".into());
        }
        self.reaped.store(true, Ordering::Release);
        Ok(true)
    }
    pub(super) fn stop_and_reap(&self) -> Result<(), String> {
        self.stop();
        loop {
            let before = kernel::now()?;
            let reaped = self.try_reap()?;
            let after = kernel::now()?;
            if before >= self.deadline || after >= self.deadline {
                return Err("guest role original cleanup bound passed; no timely reap claim".into());
            }
            if reaped { return Ok(()); }
            let mut descriptor = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let timeout = ((self.deadline - after) / 1_000_000).clamp(1, 25) as i32;
            if unsafe { libc::poll(&mut descriptor, 1, timeout) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err("guest role bounded reap wait failed".into());
            }
        }
    }
}
impl Drop for RoleProcess { fn drop(&mut self) { let _ = self.stop_and_reap(); } }
