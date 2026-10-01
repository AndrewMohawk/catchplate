//! Same-parent, one-shot retirement of the actual inspection child.
//! No authority, signer, serialization, or caller-selected PID is accepted here.
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

fn refused() -> io::Error { io::Error::other("ordinary inspection child reap refused") }
fn require(value: bool) -> io::Result<()> { if value { Ok(()) } else { Err(refused()) } }
fn now() -> io::Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    require(value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec))?;
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64)).ok_or_else(refused)
}

/// Only a successful consuming wait below constructs this local capability.
/// The private fields deliberately have no Clone, Deserialize, or Serialize.
pub struct ReapedWorker {
    pid: i32,
    start: u64,
    code: i32,
    status: i32,
    reaped_at: u64,
}
impl ReapedWorker {
    pub fn pid(&self) -> i32 { self.pid }
    pub fn start_time_ticks(&self) -> u64 { self.start }
    /// Actual waitid si_code, not an inferred successful disposition.
    pub fn exit_code(&self) -> i32 { self.code }
    /// Actual waitid si_status (exit status or terminating signal).
    pub fn exit_status(&self) -> i32 { self.status }
    pub fn reaped_at_boottime_ns(&self) -> u64 { self.reaped_at }
}

/// Constructed only by the enclosing pre-drop clone3 owner. These fields are
/// private outside that owner module; no public adoption/reconstruction API.
pub(super) struct Child {
    pub(super) pid: i32,
    pub(super) start: u64,
    pub(super) pidfd: OwnedFd,
    pub(super) stop: Option<OwnedFd>,
    pub(super) parent: i32,
    pub(super) lifetime: u64,
    attempted: bool,
    consumed: bool,
}
impl Child {
    pub(super) fn new(pid: i32, pidfd: OwnedFd, stop: OwnedFd, parent: i32, lifetime: u64) -> Self {
        // Ownership must be installed before any fallible start-time read.
        Self { pid, start: 0, pidfd, stop: Some(stop), parent, lifetime, attempted: false, consumed: false }
    }

    pub(super) fn available(&self) -> bool { !self.attempted && !self.consumed }

    pub(super) fn stop_and_reap(&mut self) -> io::Result<ReapedWorker> {
        require(self.available())?;
        self.attempted = true; // Consume the admission attempt before reads.
        require(unsafe { libc::getpid() } == self.parent && self.pid > 1 && self.start > 0)?;
        self.stop.take(); // The dropped service cannot signal its root helper.
        let (code, status, reaped_at) = self.wait_for_exit()?;
        Ok(ReapedWorker { pid: self.pid, start: self.start, code, status, reaped_at })
    }

    fn wait_for_exit(&mut self) -> io::Result<(i32, i32, u64)> {
        require(!self.consumed && unsafe { libc::getpid() } == self.parent && self.pid > 1)?;
        let mut previous = now()?;
        loop {
            let before = now()?;
            require(previous <= before && before < self.lifetime)?;
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(libc::P_PIDFD, self.pidfd.as_raw_fd() as _, &mut status,
                    libc::WEXITED | libc::WNOHANG)
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) { previous = before; continue; }
                // In particular, ECHILD is never a successful reap.
                return Err(error);
            }
            let pid = unsafe { status.si_pid() };
            if pid != 0 {
                // waitid consumed a status. Even a failed subsequent identity,
                // disposition, or clock check must never cause a second reap.
                self.consumed = true;
                let after = now()?;
                require(pid == self.pid && status.si_signo == libc::SIGCHLD
                    && [libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED].contains(&status.si_code)
                    && before <= after && after < self.lifetime)?;
                return Ok((status.si_code, unsafe { status.si_status() }, after));
            }
            let mut poll = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let count = unsafe { libc::poll(&mut poll, 1, 1) };
            if count < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(io::Error::last_os_error());
            }
            require(poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0)?;
            previous = before;
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } != self.parent || self.consumed { return; }
        self.stop.take();
        // Partial startup and failed explicit attempts retain the original
        // stop/reap fallback. No renewed window and no terminal capability.
        if self.wait_for_exit().is_err() { unsafe { libc::_exit(1) } }
    }
}

#[cfg(test)]
#[path = "guest_ordinary_inspection_reap_tests.rs"]
mod tests;
