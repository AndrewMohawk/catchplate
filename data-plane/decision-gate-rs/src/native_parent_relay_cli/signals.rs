//! Process-local cooperative cancellation, not a hard watchdog or authority.
//!
//! Install on the single startup thread before creating relay workers. Workers
//! inherit the blocked TERM/INT mask. One owned signalfd reader translates a
//! signal into the shared cancellation flag; no asynchronous Rust handler runs.
//! Drop follows the joined relay call, joins this reader, and restores the
//! creator thread's original mask/dispositions. Pending signals can then take
//! their original action. This owner cannot move to another thread.

use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

const SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];
const POLL_MILLISECONDS: libc::c_int = 100;

struct Registration {
    pid: libc::pid_t,
    original_mask: libc::sigset_t,
    original_actions: Vec<(libc::c_int, libc::sigaction)>,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Never operate on inherited process/thread state after an unexpected
        // fork. The CLI performs no fork; the serving owners also reject it.
        if unsafe { libc::getpid() } != self.pid { return; }
        for (signal, action) in self.original_actions.iter().rev() {
            // Best-effort restoration at terminal process exit. No successful
            // cleanup receipt is derived from Drop or these syscall results.
            unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()); }
        }
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.original_mask, std::ptr::null_mut()); }
    }
}

fn register() -> Result<(Registration, OwnedFd), String> {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigemptyset(&mut mask) } != 0 {
        return Err("initialize parent relay signal mask".to_owned());
    }
    for signal in SIGNALS {
        if unsafe { libc::sigaddset(&mut mask, signal) } != 0 {
            return Err("configure parent relay signal mask".to_owned());
        }
    }
    let mut original_mask = unsafe { std::mem::zeroed() };
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut original_mask) } != 0 {
        return Err("block parent relay cancellation signals".to_owned());
    }
    let mut registration = Registration { pid: unsafe { libc::getpid() },
        original_mask, original_actions: Vec::with_capacity(2), _same_thread: PhantomData };
    for signal in SIGNALS {
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(signal, &action, &mut previous) } != 0
        {
            return Err("install parent relay blocked signal disposition".to_owned());
        }
        // Establish default dispositions even if SIGINT was inherited ignored;
        // delivery remains blocked and is consumed exclusively through the fd.
        registration.original_actions.push((signal, previous));
    }
    let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if fd < 0 { return Err("open parent relay cancellation signal descriptor".to_owned()); }
    Ok((registration, unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn receive(fd: OwnedFd, stop: &AtomicBool, cancel: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        let mut event = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let result = unsafe { libc::poll(&mut event, 1, POLL_MILLISECONDS) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
            break;
        }
        if result == 0 { continue; }
        if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            || event.revents & libc::POLLIN == 0 { break; }
        let mut record: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let read = unsafe { libc::read(fd.as_raw_fd(),
            (&mut record as *mut libc::signalfd_siginfo).cast(), std::mem::size_of_val(&record)) };
        if read < 0 {
            let kind = io::Error::last_os_error().kind();
            if kind == io::ErrorKind::Interrupted || kind == io::ErrorKind::WouldBlock { continue; }
            break;
        }
        // An unexpected/truncated record is also a terminal monitoring failure,
        // never an excuse to keep an unmonitored listener alive.
        if read as usize != std::mem::size_of_val(&record)
            || !SIGNALS.contains(&(record.ssi_signo as libc::c_int)) { break; }
        cancel.store(true, Ordering::Release);
        return;
    }
    if !stop.load(Ordering::Acquire) { cancel.store(true, Ordering::Release); }
}

pub(super) struct CancellationSignals {
    registration: Registration,
    stop: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl CancellationSignals {
    pub(super) fn install(cancel: Arc<AtomicBool>) -> Result<Self, String> {
        if cancel.load(Ordering::Acquire) {
            return Err("parent relay cancellation was already requested".to_owned());
        }
        let (registration, fd) = register()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new().name("parent-relay-signals".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    receive(fd, &worker_stop, &worker_cancel)));
                if result.is_err() { worker_cancel.store(true, Ordering::Release); }
            }).map_err(|_| "start parent relay cancellation reader".to_owned())?;
        Ok(Self { registration, stop, cancel, worker: Some(worker) })
    }
}

impl Drop for CancellationSignals {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } != self.registration.pid { return; }
        self.cancel.store(true, Ordering::Release);
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        // Registration drops next, only after every owned thread has joined.
    }
}
