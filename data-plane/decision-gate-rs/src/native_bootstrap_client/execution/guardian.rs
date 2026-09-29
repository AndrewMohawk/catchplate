//! Independent, fixed-purpose guardian of an actual still-blocked new child.
//! Only a genuine child/containment borrow can arm it. READY is a local process
//! handshake, not exec, network admission, workload health or production proof.

use super::{child::{BlockedChild, GuardianBorrow}, guardian_process as process};
use std::cell::Cell;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}

fn now() -> Result<u64, String> {
    process::now().ok_or_else(|| "native guardian BOOTTIME unavailable".to_owned())
}

fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    require(raw >= 3, "native guardian original cannot be duplicated")?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[derive(PartialEq, Eq)]
struct PidfdIdentity { device: u64, inode: u64, mode: u32 }

fn pidfd_identity(fd: BorrowedFd<'_>) -> Result<PidfdIdentity, String> {
    let mut value: libc::stat = unsafe { zeroed() };
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    require(flags >= 0 && flags & libc::FD_CLOEXEC != 0
        && unsafe { libc::fstat(fd.as_raw_fd(), &mut value) } == 0 && value.st_ino != 0,
        "native guardian pidfd original identity is unavailable")?;
    // The type is established by clone3 / the genuine child owner, not this
    // observation. These immutable fields associate retained duplicate FDs.
    Ok(PidfdIdentity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode })
}

fn timer(deadline: u64) -> Result<OwnedFd, String> {
    let raw = unsafe { libc::timerfd_create(libc::CLOCK_BOOTTIME,
        libc::TFD_CLOEXEC | libc::TFD_NONBLOCK) };
    require(raw >= 0, "native guardian absolute timer cannot be created")?;
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut value: libc::itimerspec = unsafe { zeroed() };
    value.it_value.tv_sec = (deadline / 1_000_000_000).try_into()
        .map_err(|_| "native guardian timer seconds overflow")?;
    value.it_value.tv_nsec = (deadline % 1_000_000_000) as libc::c_long;
    require(deadline != 0 && unsafe { libc::timerfd_settime(fd.as_raw_fd(),
        libc::TFD_TIMER_ABSTIME, &value, std::ptr::null_mut()) } == 0,
        "native guardian fixed absolute timer cannot be armed")?;
    Ok(fd)
}

fn single_thread() -> Result<libc::pid_t, String> {
    let mut tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|_| "native guardian launcher task inventory unavailable")?;
    let task = tasks.next().ok_or("native guardian launcher task absent")?
        .map_err(|_| "native guardian launcher task unreadable")?;
    require(tasks.next().is_none(), "native guardian launcher must remain single-threaded")?;
    let thread = unsafe { libc::syscall(libc::SYS_gettid) };
    let thread = libc::pid_t::try_from(thread).map_err(|_| "native guardian thread invalid")?;
    require(thread > 0 && task.file_name().to_str() == Some(thread.to_string().as_str()),
        "native guardian observed task differs from its calling thread")?;
    Ok(thread)
}

struct SignalMask { old: libc::sigset_t, restored: bool }
impl SignalMask {
    fn block() -> Result<Self, String> {
        let mut mask: libc::sigset_t = unsafe { zeroed() };
        let mut old: libc::sigset_t = unsafe { zeroed() };
        require(unsafe { libc::sigfillset(&mut mask) } == 0
            && unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut old) } == 0,
            "native guardian signal mask cannot be installed")?;
        Ok(Self { old, restored: false })
    }
    fn restore(&mut self) -> Result<(), String> {
        require(!self.restored && unsafe { libc::sigprocmask(libc::SIG_SETMASK,
            &self.old, std::ptr::null_mut()) } == 0, "native guardian launcher signal restore failed")?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        if !self.restored { unsafe { libc::sigprocmask(libc::SIG_SETMASK,
            &self.old, std::ptr::null_mut()); } }
    }
}

#[repr(C)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}

/// Non-Clone actual process owner. Neither a serialized READY frame nor a PID
/// number can construct it. Drop requests cleanup but cannot assert success.
pub(super) struct Guardian {
    channel: OwnedFd,
    guardian_pidfd: OwnedFd,
    guardian_identity: PidfdIdentity,
    guardian_pid: libc::pid_t,
    leader_pidfd: OwnedFd,
    leader_identity: PidfdIdentity,
    operation: [u8; 32],
    cleanup: u64,
    stop: u64,
    pid: u32,
    thread: libc::pid_t,
    cancelled: Cell<bool>,
    reaped: bool,
}

/// Data-only local observation. Workload leader reaping remains owned by the
/// launcher; no combined cleanup/release receipt follows from this value.
pub(super) struct GuardianObservation {
    observed: u64,
    kill_acknowledged: bool,
}
impl GuardianObservation {
    pub(super) fn observed_boottime_ns(&self) -> u64 { self.observed }
    pub(super) fn kill_acknowledged(&self) -> bool { self.kill_acknowledged }
}

impl Guardian {
    pub(super) fn arm(child: &GuardianBorrow<'_>) -> Result<Self, String> {
        child.check()?;
        child.begin_guardian()?;
        let thread = single_thread()?;
        let mut disposition: libc::sigaction = unsafe { zeroed() };
        require(unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } == 0
            && disposition.sa_sigaction == libc::SIG_DFL
            && disposition.sa_flags & libc::SA_NOCLDWAIT == 0,
            "native guardian requires exact reapable child disposition")?;
        let admission = child.admission_deadline_boottime_ns()?;
        let stop = child.stop_boottime_ns();
        let cleanup = child.cleanup_boottime_ns();
        require(now()? < admission && admission <= stop && stop < cleanup,
            "native guardian original admission/stop/cleanup bounds differ")?;
        let scope = child.cleanup();
        scope.check()?;
        let leaf = duplicate(scope.directory())?;
        let kill = duplicate(scope.kill())?;
        let events = duplicate(scope.events())?;
        let parent = duplicate(child.launcher_pidfd())?;
        let leader = duplicate(child.leader_pidfd())?;
        let leader_identity = pidfd_identity(leader.as_fd())?;
        require(leader_identity == pidfd_identity(child.leader_pidfd())?
            && process::live(parent.as_raw_fd()) && process::live(leader.as_raw_fd()),
            "native guardian genuine parent/leader is no longer live")?;
        let mut pair = [-1; 2];
        require(unsafe { libc::socketpair(libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0, pair.as_mut_ptr()) } == 0, "native guardian private channel unavailable")?;
        let channel = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let stop_timer = timer(stop)?;
        let cleanup_timer = timer(cleanup)?;
        let operation = child.operation_sha256();
        let snapshot = process::Snapshot {
            fds: [leaf.as_raw_fd(), kill.as_raw_fd(), events.as_raw_fd(), parent.as_raw_fd(),
                leader.as_raw_fd(), peer.as_raw_fd(), stop_timer.as_raw_fd(), cleanup_timer.as_raw_fd()],
            identities: [process::identity(leaf.as_raw_fd(), None)
                    .ok_or("native guardian leaf identity unavailable")?,
                process::identity(kill.as_raw_fd(), None)
                    .ok_or("native guardian kill identity unavailable")?,
                process::identity(events.as_raw_fd(), None)
                    .ok_or("native guardian events identity unavailable")?],
            operation, stop, cleanup,
        };
        require(process::controls(&snapshot), "native guardian fixed control association differs")?;
        child.check()?;
        scope.check()?;
        require(now()? < admission && single_thread()? == thread,
            "native guardian admission ended before process creation")?;
        let mut mask = SignalMask::block()?;
        let mut pidfd = -1;
        let args = CloneArgs { flags: libc::CLONE_PIDFD as u64 | 0x1_0000_0000,
            pidfd: (&mut pidfd as *mut libc::c_int) as u64, child_tid: 0, parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64, stack: 0, stack_size: 0, tls: 0,
            set_tid: 0, set_tid_size: 0, cgroup: 0 };
        // No INTO_CGROUP: the guardian stays with the launcher, outside the
        // newly created workload leaf. No VM/files/signal-table sharing.
        let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>()) };
        if pid == 0 { process::run(&snapshot); }
        if pid < 0 {
            mask.restore()?;
            return Err("native guardian clone3 failed; workload remains blocked".to_owned());
        }
        // The guardian can already clean up. Close our copy of its channel so
        // launcher death or owner loss produces EOF even on later errors.
        drop(peer);
        require(pidfd >= 0, "native guardian clone returned no pidfd; cleanup outcome uncertain")?;
        let guardian_pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let guardian_identity = pidfd_identity(guardian_pidfd.as_fd())?;
        let guardian_pid = libc::pid_t::try_from(pid).map_err(|_| "native guardian PID overflow")?;
        let result = Self { channel, guardian_pidfd, guardian_identity, guardian_pid,
            leader_pidfd: leader, leader_identity, operation, cleanup, stop,
            pid: std::process::id(), thread, cancelled: Cell::new(false), reaped: false };
        mask.restore()?;
        let (flags, observed) = result.receive(1, admission)?;
        require(flags == 0 && observed < admission && observed <= now()?,
            "native guardian READY is outside the original admission")?;
        child.check()?;
        result.check_process()?;
        require(process::live(result.guardian_pidfd.as_raw_fd()) && now()? < admission,
            "native guardian ended before actual owner handoff")?;
        Ok(result)
    }

    fn check_process(&self) -> Result<(), String> {
        require(self.pid == std::process::id()
            && unsafe { libc::syscall(libc::SYS_gettid) } == self.thread as libc::c_long
            && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
            "native guardian owner crossed process/thread/privilege boundary")?;
        require(pidfd_identity(self.guardian_pidfd.as_fd())? == self.guardian_identity
            && pidfd_identity(self.leader_pidfd.as_fd())? == self.leader_identity,
            "native guardian retained process association changed")
    }

    pub(super) fn require_child(&self, child: &BlockedChild) -> Result<(), String> {
        let result = (|| {
            self.check_process()?;
            require(!self.cancelled.get() && !self.reaped && now()? < self.stop,
                "native guardian is stopped or expired")?;
            let original = child.guardian_borrow()?;
            original.check()?;
            require(original.operation_sha256() == self.operation
                && pidfd_identity(original.leader_pidfd())? == self.leader_identity
                && process::live(self.guardian_pidfd.as_raw_fd()),
                "native guardian belongs to another or terminated child")?;
            let mut byte = 0u8;
            let count = unsafe { libc::recv(self.channel.as_raw_fd(), (&mut byte as *mut u8).cast(),
                1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
            require(count == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
                "native guardian unexpectedly reported or closed before release")?;
            original.check()
        })();
        if result.is_err() { self.cancel(); }
        result
    }

    pub(super) fn request_stop(&self) { self.cancel(); }

    fn cancel(&self) {
        if self.pid != std::process::id() || self.cancelled.replace(true) { return; }
        // Exactly one bounded send. Even a failed send cannot suppress EOF when
        // this last owner closes; the independent absolute timer remains armed.
        unsafe { libc::send(self.channel.as_raw_fd(), b"K".as_ptr().cast(), 1,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL); }
        unsafe { libc::shutdown(self.channel.as_raw_fd(), libc::SHUT_WR); }
    }

    fn receive(&self, kind: u8, deadline: u64) -> Result<(u8, u64), String> {
        let mut previous = now()?;
        loop {
            require(previous < deadline, "native guardian response missed its absolute deadline")?;
            let mut raw = [0u8; process::FRAME_BYTES];
            let count = unsafe { libc::recv(self.channel.as_raw_fd(), raw.as_mut_ptr().cast(), raw.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
            if count >= 0 {
                require(count == raw.len() as isize, "native guardian frame truncated or channel closed")?;
                let value = process::decode(&raw, &self.operation, kind)
                    .ok_or("native guardian frame differs from its fixed purpose")?;
                let observed = now()?;
                require(observed >= previous && observed < deadline && value.1 <= observed,
                    "native guardian response clock changed or deadline ended")?;
                return Ok(value);
            }
            require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
                "native guardian channel receive failed")?;
            let timeout = (((deadline - previous).min(100_000_000) + 999_999) / 1_000_000) as libc::c_int;
            let mut polls = [libc::pollfd { fd: self.channel.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.guardian_pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
            require(unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, timeout) } >= 0
                && polls[0].revents & libc::POLLNVAL == 0 && polls[1].revents & libc::POLLNVAL == 0,
                "native guardian response poll failed")?;
            let instant = now()?;
            require(instant >= previous, "native guardian response BOOTTIME moved backwards")?;
            previous = instant;
        }
    }

    fn reap(&mut self) -> Result<bool, String> {
        self.check_process()?;
        require(!self.reaped, "native guardian process was already reaped")?;
        let mut info: libc::siginfo_t = unsafe { zeroed() };
        require(unsafe { libc::waitid(libc::P_PIDFD, self.guardian_pidfd.as_raw_fd() as libc::id_t,
            &mut info, libc::WEXITED | libc::WNOHANG) } == 0,
            "native guardian exact pidfd reap failed")?;
        if unsafe { info.si_pid() } == 0 { return Ok(false); }
        self.reaped = true;
        require(unsafe { info.si_pid() } == self.guardian_pid && info.si_code == libc::CLD_EXITED
            && unsafe { info.si_status() } == 0, "native guardian terminated without successful observation")?;
        Ok(true)
    }

    pub(super) fn finish(mut self) -> Result<GuardianObservation, String> {
        // Stop request precedes optional integrity/clock diagnostics. Expired
        // authority never causes us to leave the independent guardian idle.
        self.cancel();
        self.check_process()?;
        let (flags, observed) = self.receive(2, self.cleanup)?;
        require(flags & 2 != 0 && observed < self.cleanup,
            "native guardian did not observe its leaf empty within the original bound")?;
        while !self.reap()? {
            let instant = now()?;
            require(instant < self.cleanup, "native guardian exact reap missed cleanup bound")?;
            let mut poll = libc::pollfd { fd: self.guardian_pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let timeout = (((self.cleanup - instant).min(100_000_000) + 999_999) / 1_000_000) as libc::c_int;
            require(unsafe { libc::poll(&mut poll, 1, timeout) } >= 0
                && poll.revents & (libc::POLLNVAL | libc::POLLERR) == 0,
                "native guardian exact reap poll failed")?;
        }
        require(now()? < self.cleanup, "native guardian closing observation missed cleanup bound")?;
        Ok(GuardianObservation { observed, kill_acknowledged: flags & 1 != 0 })
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        self.cancel();
        // No blocking destructor, no kill of the guardian, and no success
        // claim. Explicit finish must retain the owner until exact reap.
        if self.pid == std::process::id() && !self.reaped { let _ = self.reap(); }
    }
}
