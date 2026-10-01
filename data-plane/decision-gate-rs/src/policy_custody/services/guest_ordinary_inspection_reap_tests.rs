//! Real, unprivileged child/PIDFD controls for the production reap owner.
//! A process-wide lock allows only one test child at a time, even under libtest.
use super::*;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::sync::Mutex;

static CHILD_LOCK: Mutex<()> = Mutex::new(());

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}

// Only raw libc calls occur in the post-clone child of the threaded test runner.
// The child carries no service keys, privileged inspection, or synthetic owner.
fn child_body(read: i32, write: i32, parent: i32, deadline: u64, early_status: Option<i32>) -> ! {
    unsafe {
        libc::close(write);
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
            libc::_exit(90);
        }
        let mut event: libc::sigevent = std::mem::zeroed();
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGKILL;
        let mut timer = std::ptr::null_mut();
        let value = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: (deadline / 1_000_000_000) as _, tv_nsec: (deadline % 1_000_000_000) as _ },
        };
        if libc::timer_create(libc::CLOCK_BOOTTIME, &mut event, &mut timer) != 0
            || libc::timer_settime(timer, libc::TIMER_ABSTIME, &value, std::ptr::null_mut()) != 0 {
            libc::_exit(91);
        }
        if let Some(status) = early_status { libc::_exit(status); }
        loop {
            let mut polled = libc::pollfd { fd: read, events: libc::POLLIN, revents: 0 };
            let result = libc::poll(&mut polled, 1, 1);
            if result > 0 && polled.revents & libc::POLLHUP != 0 { libc::_exit(0); }
            if result > 0 && polled.revents & (libc::POLLERR | libc::POLLNVAL) != 0 { libc::_exit(92); }
        }
    }
}

fn child(early_status: Option<i32>) -> Child {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) }, 0);
    assert_eq!(action.sa_sigaction, libc::SIG_DFL);
    assert_eq!(action.sa_flags & libc::SA_NOCLDWAIT, 0);
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
    let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let deadline = now().unwrap().checked_add(2_000_000_000).unwrap();
    let parent = unsafe { libc::getpid() };
    let mut raw_pidfd = -1;
    let args = CloneArgs { flags: libc::CLONE_PIDFD as u64,
        pidfd: (&mut raw_pidfd as *mut i32) as u64, exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default() };
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
    if pid == 0 { child_body(read.as_raw_fd(), write.as_raw_fd(), parent, deadline, early_status); }
    assert!(pid > 1, "clone3 failed: {}", io::Error::last_os_error());
    assert!(raw_pidfd >= 0);
    let mut owner = Child::new(pid as i32, unsafe { OwnedFd::from_raw_fd(raw_pidfd) }, write, parent, deadline);
    drop(read);
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    owner.start = raw.rsplit_once(") ").unwrap().1.split_whitespace().nth(19).unwrap().parse().unwrap();
    assert!(owner.start > 0);
    owner
}

fn duplicate(fd: &OwnedFd) -> OwnedFd {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(raw >= 0);
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn wait_actual(owner: &Child, consume: bool) -> libc::siginfo_t {
    loop {
        assert!(now().unwrap() < owner.lifetime);
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let flags = libc::WEXITED | libc::WNOHANG | if consume { 0 } else { libc::WNOWAIT };
        let result = unsafe { libc::waitid(libc::P_PIDFD, owner.pidfd.as_raw_fd() as _, &mut status, flags) };
        assert_eq!(result, 0, "waitid failed: {}", io::Error::last_os_error());
        if unsafe { status.si_pid() } != 0 {
            assert_eq!(unsafe { status.si_pid() }, owner.pid);
            return status;
        }
        let mut polled = libc::pollfd { fd: owner.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut polled, 1, 1); }
    }
}

#[test]
fn actual_stop_pipe_reap_is_consuming_and_drop_does_not_reap_again() {
    let _serial = CHILD_LOCK.lock().unwrap();
    let mut owner = child(None);
    let pidfd = duplicate(&owner.pidfd);
    let terminal = owner.stop_and_reap().unwrap();
    assert_eq!(terminal.pid(), owner.pid);
    assert_eq!(terminal.start_time_ticks(), owner.start);
    assert_eq!(terminal.exit_code(), libc::CLD_EXITED);
    assert_eq!(terminal.exit_status(), 0);
    assert!(terminal.reaped_at_boottime_ns() < owner.lifetime);
    drop(owner); // A second wait here would terminate the test process.
    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::waitid(libc::P_PIDFD, pidfd.as_raw_fd() as _, &mut status, libc::WEXITED | libc::WNOHANG) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

#[test]
fn a_second_explicit_attempt_cannot_mint_another_terminal() {
    let _serial = CHILD_LOCK.lock().unwrap();
    let mut owner = child(None);
    let terminal = owner.stop_and_reap().unwrap();
    assert_eq!(terminal.exit_status(), 0);
    assert!(owner.stop_and_reap().is_err());
    assert!(!owner.available());
}

#[test]
fn an_already_dead_child_retains_its_actual_nonzero_disposition() {
    let _serial = CHILD_LOCK.lock().unwrap();
    let mut owner = child(Some(23));
    let observed = wait_actual(&owner, false);
    assert_eq!(unsafe { observed.si_status() }, 23);
    let terminal = owner.stop_and_reap().unwrap();
    assert_eq!(terminal.exit_code(), libc::CLD_EXITED);
    assert_eq!(terminal.exit_status(), 23); // This is not successful shutdown.
}

#[test]
fn echild_is_unknown_and_does_not_mint_a_terminal() {
    let _serial = CHILD_LOCK.lock().unwrap();
    let mut owner = child(None);
    owner.stop.take();
    let consumed_elsewhere = wait_actual(&owner, true);
    assert_eq!(consumed_elsewhere.si_code, libc::CLD_EXITED);
    // The genuine child is already consumed above. Suppress only the fatal
    // production Drop fallback so this control can inspect ECHILD; no state is
    // rewritten as success, and all retained descriptors are explicitly freed.
    let mut owner = ManuallyDrop::new(owner);
    assert_eq!(owner.stop_and_reap().err().unwrap().raw_os_error(), Some(libc::ECHILD));
    assert!(!owner.consumed && !owner.available());
    assert!(owner.stop_and_reap().is_err());
    unsafe { std::ptr::drop_in_place(&mut owner.pidfd); }
}

#[test]
fn partial_startup_drop_reaps_without_a_terminal_capability() {
    let _serial = CHILD_LOCK.lock().unwrap();
    let mut owner = child(None);
    let pidfd = duplicate(&owner.pidfd);
    owner.start = 0; // The actual pre-drop owner failed before recording start.
    assert!(owner.stop_and_reap().is_err());
    drop(owner);
    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::waitid(libc::P_PIDFD, pidfd.as_raw_fd() as _, &mut status, libc::WEXITED | libc::WNOHANG) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}
