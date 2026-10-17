//! Fixed clone/exec and kernel-authenticated initialization, not a cohort factory.
use super::{guest_inspector_parent_image::Sealed, peer_measurement as peer};
use crate::native_serving_privileges::Prepared;
use std::{mem::{size_of, zeroed}, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicBool, Ordering}};
use serde::{Deserialize, Serialize};

const SO_PASSPIDFD: i32 = 76;
const SCM_PIDFD: i32 = 4;
pub(super) fn now() -> Result<u64, String> {
    super::recovery::boottime_ns().map_err(|_| "inspector boottime unavailable".into())
}
fn duplicate(fd: RawFd) -> Result<OwnedFd, String> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 6) };
    if copy < 0 { return Err("inspector inheritance duplication failed".into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
pub(super) fn pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        0, fds.as_mut_ptr()) } != 0 { return Err("inspector private channel creation failed".into()); }
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    for fd in [&a, &b] {
        for option in [libc::SO_PASSCRED, SO_PASSPIDFD] {
            let yes: i32 = 1;
            if unsafe { libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, option,
                (&yes as *const i32).cast(), size_of::<i32>() as libc::socklen_t) } != 0 {
                return Err("inspector kernel sender credentials unavailable".into());
            }
        }
    }
    Ok((a, b))
}
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}
#[repr(C)]
struct KernelSigaction { handler: usize, flags: usize, restorer: usize, mask: u64 }

// This branch has no allocator, Rust destruction, environment, callback or
// application-controlled instruction before fixed execveat. Parent is still
// single-threaded and has not generated the native serving keys.
unsafe fn child(parent: libc::pid_t, lifetime: RawFd, router: RawFd, bootstrap: RawFd, executable: RawFd) -> ! {
    let mut good = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0
        && unsafe { libc::getppid() } == parent;
    for (source, target) in [(lifetime, 3), (router, 4), (bootstrap, 5)] {
        good &= unsafe { libc::dup3(source, target, 0) } == target;
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
    for fd in 0..3 { unsafe { libc::close(fd); } }
    good &= unsafe { libc::syscall(libc::SYS_close_range, 6u32, u32::MAX, 4u32) } == 0;
    if good {
        let argv = [b"catchplate-response-v2-guest-inspector\0".as_ptr().cast::<libc::c_char>(), std::ptr::null()];
        let env: [*const libc::c_char; 1] = [std::ptr::null()];
        unsafe { libc::syscall(libc::SYS_execveat, executable, b"\0".as_ptr(), argv.as_ptr(),
            env.as_ptr(), libc::AT_EMPTY_PATH); }
    }
    unsafe { libc::syscall(libc::SYS_exit_group, 127); }
    loop { std::hint::spin_loop(); }
}

pub(super) struct Process {
    pub(super) pidfd: OwnedFd,
    channel: OwnedFd,
    pid: libc::pid_t,
    parent: libc::pid_t,
    deadline: u64,
    stopped: AtomicBool,
    reaped: AtomicBool,
}
impl Process {
    pub(super) fn spawn(executable: &Sealed, bootstrap: &Sealed, prepared: &Prepared)
        -> Result<(Self, OwnedFd), String> {
        prepared.check()?;
        executable.check()?; bootstrap.check()?;
        let mut disposition: libc::sigaction = unsafe { zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0
            || disposition.sa_sigaction != libc::SIG_DFL || disposition.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err("inspector requires an exactly waitable child disposition".into());
        }
        let (parent_channel, child_channel) = pair()?;
        let (router_channel, inspector_channel) = pair()?;
        let inherited = [duplicate(child_channel.as_raw_fd())?, duplicate(inspector_channel.as_raw_fd())?,
            duplicate(bootstrap.file().as_raw_fd())?, duplicate(executable.file().as_raw_fd())?];
        let parent = unsafe { libc::getpid() };
        let mut pidfd: i32 = -1;
        let args = CloneArgs { flags: libc::CLONE_PIDFD as u64, pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64, ..CloneArgs::default() };
        prepared.check()?;
        let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>()) };
        if pid == 0 { unsafe { child(parent, inherited[0].as_raw_fd(), inherited[1].as_raw_fd(),
            inherited[2].as_raw_fd(), inherited[3].as_raw_fd()); } }
        if pid < 0 { return Err("inspector fixed clone3 failed".into()); }
        // Successful CLONE_PIDFD atomically supplies this descriptor. No
        // numeric-PID open/kill fallback is admitted.
        if pidfd < 0 { return Err("inspector clone3 returned no child identity".into()); }
        let result = Self { pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) }, channel: parent_channel,
            pid: pid as libc::pid_t, parent, deadline: prepared.deadline(),
            stopped: AtomicBool::new(false), reaped: AtomicBool::new(false) };
        drop(inherited); drop(child_channel); drop(inspector_channel);
        prepared.check()?;
        result.check()?;
        Ok((result, router_channel))
    }
    pub(super) fn check(&self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.parent || self.stopped.load(Ordering::Acquire)
            || self.reaped.load(Ordering::Acquire) || now()? >= self.deadline {
            return Err("inspector original process lifetime is unavailable".into());
        }
        peer::ensure_pidfd_alive(&self.pidfd).map_err(|_| "owned inspector child exited".to_owned())
    }
    pub(super) fn idle(&self) -> Result<(), String> {
        self.check()?;
        let mut poll = libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
            return Err("inspector lifetime channel closed or sent an unexpected packet".into());
        }
        Ok(())
    }
    pub(super) fn initialized(&self, nonce: &str, sha256: &str, startup_deadline: u64) -> Result<(), String> {
        loop {
            self.check()?;
            let sample = now()?;
            let until = startup_deadline.min(self.deadline);
            if sample >= until { return Err("inspector initialization exceeded original admission".into()); }
            let mut poll = libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let timeout = ((until - sample) / 1_000_000).min(25).max(1) as i32;
            let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
            if ready < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
                return Err("inspector initialization poll failed".into());
            }
            if ready == 0 { continue; }
            if poll.revents != libc::POLLIN { return Err("inspector initialization channel failed".into()); }
            let (raw, sender, credentials) = receive(self.channel.as_raw_fd())?;
            if credentials.pid != self.pid || credentials.uid != 64990 || credentials.gid != 64990 {
                return Err("inspector initialized sender is not the final fixed identity".into());
            }
            peer::prove_pidfds_same_process(&self.pidfd, &sender, self.pid)
                .map_err(|_| "inspector initialized packet differs from owned child")?;
            let value: Initialized = crate::decode_canonical_json(&raw)
                .map_err(|_| "inspector initialized contract differs")?;
            if value.api_version != "catchplate.responseV2.guestInspectorInitialized/v1"
                || value.channel_nonce != nonce || value.bootstrap_sha256 != sha256 {
                return Err("inspector initialization is not bound to original bootstrap".into());
            }
            if now()? >= until { return Err("inspector initialized outside original admission".into()); }
            return self.idle();
        }
    }
    // Emergency stop is based only on actual retained ownership, never on
    // still-live admission. The channel works after the gate's permanent UID
    // drop; the child separately enforces parent death and its absolute timer.
    pub(super) fn stop(&self) {
        if unsafe { libc::getpid() } != self.parent || self.stopped.swap(true, Ordering::AcqRel) { return; }
        unsafe {
            libc::shutdown(self.channel.as_raw_fd(), libc::SHUT_RDWR);
            libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(), 0);
        }
    }
    fn try_reap(&self) -> Result<bool, String> {
        if unsafe { libc::getpid() } != self.parent { return Err("inspector reap crossed its creator".into()); }
        if self.reaped.load(Ordering::Acquire) { return Ok(true); }
        let mut info: libc::siginfo_t = unsafe { zeroed() };
        if unsafe { libc::waitid(libc::P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t, &mut info,
            libc::WEXITED | libc::WNOHANG) } != 0 { return Err("inspector exact reap unavailable".into()); }
        if unsafe { info.si_pid() } == 0 { return Ok(false); }
        if unsafe { info.si_pid() } != self.pid || info.si_signo != libc::SIGCHLD
            || !matches!(info.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED) {
            return Err("inspector exact reap identity differs".into());
        }
        self.reaped.store(true, Ordering::Release);
        Ok(true)
    }
    pub(super) fn stop_and_reap(&self) -> Result<(), String> {
        self.stop();
        loop {
            let sample = now()?;
            let reaped = self.try_reap()?;
            if sample >= self.deadline || now()? >= self.deadline {
                return Err("inspector original cleanup bound passed; no timely reap claim".into());
            }
            if reaped { return Ok(()); }
            let mut poll = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let timeout = ((self.deadline - sample) / 1_000_000).min(25).max(1) as i32;
            if unsafe { libc::poll(&mut poll, 1, timeout) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err("inspector bounded reap poll failed".into());
            }
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) { self.stop(); let _ = self.try_reap(); }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Initialized { api_version: String, channel_nonce: String, bootstrap_sha256: String }

pub(super) fn receive(socket: RawFd) -> Result<(Vec<u8>, OwnedFd, libc::ucred), String> {
    let mut bytes = [0u8; 4096];
    let mut control = [0usize; 64];
    let mut vector = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector; message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 64]>().try_into()
        .map_err(|_| "inspector initialized control capacity exceeds ABI".to_owned())?;
    let length = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
    if length < 0 { return Err("inspector initialized receive failed".into()); }
    let mut owned = Vec::new();
    let mut credentials = None;
    let mut invalid = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || length == 0 || length as usize > bytes.len();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let item = unsafe { &*header };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        let header_length = item.cmsg_len as usize;
        let offset = (header as usize).checked_sub(message.msg_control as usize);
        if header_length < base || offset.and_then(|v| v.checked_add(header_length))
            .is_none_or(|end| end > message.msg_controllen as usize) {
            invalid = true; break;
        }
        let count = header_length - base;
        let data = unsafe { libc::CMSG_DATA(header) };
        if item.cmsg_level == libc::SOL_SOCKET && matches!(item.cmsg_type, SCM_PIDFD | libc::SCM_RIGHTS) {
            if count % size_of::<i32>() != 0 || item.cmsg_type != SCM_PIDFD || count != size_of::<i32>() { invalid = true; }
            for i in 0..count / size_of::<i32>() {
                let fd = unsafe { std::ptr::read_unaligned(data.add(i * size_of::<i32>()).cast::<i32>()) };
                if fd < 0 { invalid = true; } else { owned.push(unsafe { OwnedFd::from_raw_fd(fd) }); }
            }
        } else if item.cmsg_level == libc::SOL_SOCKET && item.cmsg_type == libc::SCM_CREDENTIALS
            && count == size_of::<libc::ucred>() && credentials.is_none() {
            credentials = Some(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
        } else { invalid = true; }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if invalid || owned.len() != 1 || credentials.is_none()
        || owned.iter().any(|fd| !peer::received_fd_is_cloexec(fd.as_raw_fd())) {
        return Err("inspector initialized ancillary originals differ".into());
    }
    Ok((bytes[..length as usize].to_vec(), owned.pop().ok_or("inspector sender identity absent")?,
        credentials.ok_or("inspector sender credentials absent")?))
}
