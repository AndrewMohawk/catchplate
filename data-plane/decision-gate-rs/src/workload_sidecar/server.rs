//! Fixed loopback CONNECT service, not namespace or egress-policy provisioning.
//!
//! Authenticate the complete local header before contacting the native gate.
//! Each worker owns one fresh upstream connection; nothing is retried. TERM/INT
//! stop accepts and close retained local sockets before joining all workers.
//! An in-flight upstream connect/attestation is not immediately interruptible:
//! joining waits for that call's ORIGINAL connection bound (at most 120s),
//! checks cancellation on return, and drops its actual upstream owner. No
//! signal, EOF, thread join or byte count proves provider-operation completion.

use super::{config::Service, lifetime::ConnectionBounds, local_connect};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CHUNK: usize = 16 * 1024;
const POLL_MS: i32 = 10;
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

fn single_thread() -> Result<(), String> {
    // Bound enumeration to two entries. No pre-existing worker may inherit an
    // unblocked mask while this sole-purpose executable creates its workers.
    let mut tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|_| "sidecar startup thread observation unavailable")?;
    let first = tasks.next().ok_or("sidecar startup thread absent")?
        .map_err(|_| "sidecar startup thread observation failed")?;
    if first.file_name().to_str() != Some(std::process::id().to_string().as_str())
        || tasks.next().is_some()
    { return Err("sidecar signals require the single original startup thread".into()); }
    Ok(())
}

struct Signals {
    fd: OwnedFd,
    old: libc::sigset_t,
    pid: libc::pid_t,
    restored: bool,
    _same_thread: PhantomData<Rc<()>>,
}
impl Signals {
    fn open() -> Result<Self, String> {
        single_thread()?;
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut mask) } != 0 {
            return Err("sidecar signal mask unavailable".into());
        }
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // Do not replace a process-global callback or silently depend on
            // an inherited ignored signal. This explicit binary owns neither.
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) } != 0
                || action.sa_sigaction != libc::SIG_DFL
                || unsafe { libc::sigaddset(&mut mask, signal) } != 0
            { return Err("sidecar requires default cancellation signal dispositions".into()); }
        }
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut old) } != 0 {
            return Err("sidecar cannot block cancellation signals".into());
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()); }
            return Err("sidecar cancellation descriptor unavailable".into());
        }
        let owner = Self { fd: unsafe { OwnedFd::from_raw_fd(fd) }, old,
            pid: unsafe { libc::getpid() }, restored: false, _same_thread: PhantomData };
        single_thread()?;
        Ok(owner)
    }
    fn received(&self) -> Result<bool, String> {
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let count = unsafe { libc::read(self.fd.as_raw_fd(),
            (&mut info as *mut libc::signalfd_siginfo).cast(), std::mem::size_of_val(&info)) };
        if count < 0 {
            return match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(false),
                _ => Err("sidecar signal observation failed".into()),
            };
        }
        if count as usize != std::mem::size_of_val(&info)
            || ![libc::SIGINT as u32, libc::SIGTERM as u32].contains(&info.ssi_signo)
        { return Err("sidecar signal observation differs".into()); }
        Ok(true)
    }
    fn restore(&mut self) -> Result<(), String> {
        // Standard signals coalesce: consume the two owned pending kinds
        // after workers join. A later new signal resumes the caller's original
        // disposition; no handler or fresh shutdown allowance is installed.
        for _ in 0..2 { if !self.received()? { break; } }
        if unsafe { libc::getpid() } != self.pid
            || unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) } != 0
        { return Err("sidecar original signal mask could not be restored".into()); }
        self.restored = true;
        Ok(())
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        if !self.restored && unsafe { libc::getpid() } == self.pid {
            // Error fallback only, after run's scoped workers have joined.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()); }
        }
    }
}

struct Slot {
    busy: AtomicBool,
    local: Mutex<Option<TcpStream>>,
}
impl Slot {
    fn shutdown(&self) {
        let held = self.local.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(socket) = held.as_ref() { let _ = socket.shutdown(Shutdown::Both); }
    }
    fn clear(&self) {
        let mut held = self.local.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(socket) = held.take() { let _ = socket.shutdown(Shutdown::Both); }
        self.busy.store(false, Ordering::Release);
    }
}
struct Occupied<'a>(&'a Slot);
impl Drop for Occupied<'_> { fn drop(&mut self) { self.0.clear(); } }

struct Shared {
    stop: AtomicBool,
    failure: Mutex<Option<String>>,
}
impl Shared {
    fn fail(&self, error: String) {
        let mut failure = self.failure.lock().unwrap_or_else(|poison| poison.into_inner());
        if failure.is_none() { *failure = Some(error); }
        self.stop.store(true, Ordering::Release);
    }
    fn check(&self, service: &Service, bounds: ConnectionBounds) -> Result<(), String> {
        if self.stop.load(Ordering::Acquire) { return Err("sidecar is stopping".into()); }
        if let Err(error) = service.check() { self.fail(error.clone()); return Err(error); }
        bounds.check()
    }
}

struct Job { socket: TcpStream, bounds: ConnectionBounds, header_deadline: Instant }

fn nonblocking(socket: &TcpStream) -> Result<(), String> {
    socket.set_nonblocking(true).map_err(|_| "sidecar local nonblocking setup failed")?;
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err("sidecar accepted socket lacks close-on-exec".into());
    }
    Ok(())
}

fn wait_local(socket: &TcpStream, events: i16, deadline: Instant,
    service: &Service, shared: &Shared, bounds: ConnectionBounds) -> Result<(), String> {
    shared.check(service, bounds)?;
    let remaining = deadline.min(bounds.deadline).checked_duration_since(Instant::now())
        .ok_or("sidecar original IO deadline expired")?;
    let timeout = remaining.as_millis().min(POLL_MS as u128).max(1) as i32;
    let mut descriptor = libc::pollfd { fd: socket.as_raw_fd(), events, revents: 0 };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    let failure = (result < 0).then(io::Error::last_os_error);
    shared.check(service, bounds)?;
    if Instant::now() >= deadline { return Err("sidecar original IO deadline expired".into()); }
    if failure.is_some_and(|error| error.kind() != io::ErrorKind::Interrupted)
        || descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    { return Err("sidecar local socket poll failed".into()); }
    // HUP is handled by the next actual read/write, never promoted to success.
    Ok(())
}

fn authenticate(job: &mut Job, service: &Service, shared: &Shared) -> Result<String, String> {
    // The parser wipes a complete head; this wrapper also wipes partial heads
    // on timeout, disconnect, cancellation, parser failure and unwinding.
    let mut head = Zeroizing::new([0u8; local_connect::MAX_HEAD_BYTES]);
    let mut used = 0usize;
    let bounds = job.bounds;
    let deadline = job.header_deadline;
    let current = || -> Result<(), String> {
        if shared.stop.load(Ordering::Acquire) { return Err("sidecar is stopping".into()); }
        bounds.check()?;
        if Instant::now() >= deadline { return Err("sidecar local header expired".into()); }
        Ok(())
    };
    shared.check(service, bounds)?;
    loop {
        current()?;
        if used == head.len() {
            return Err("sidecar local CONNECT head exceeds its original bound".into());
        }
        // Read exactly one byte. No TLS byte after CRLFCRLF is consumed here.
        let result = job.socket.read(&mut head[used..used + 1]);
        current()?;
        match result {
            Ok(1) => {
                used += 1;
                // Retained file hashing is bounded per block, not repeated for
                // every unauthenticated byte. Poll waits also check full scope.
                if used % 64 == 0 { shared.check(service, bounds)?; }
                if head[..used].ends_with(b"\r\n\r\n") { break; }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                wait_local(&job.socket, libc::POLLIN, job.header_deadline, service, shared, job.bounds)?,
            _ => return Err("sidecar local header ended before authentication".into()),
        }
    }
    shared.check(service, bounds)?;
    current()?;
    let result = local_connect::authenticate_connect(&mut head[..used], &service.settings.workload_id,
        &service.token_digest, &service.settings.allowed_destinations);
    shared.check(service, bounds)?;
    current()?;
    result
}

fn connection(mut job: Job, service: &Service, shared: &Shared) -> Result<(), String> {
    let destination = authenticate(&mut job, service, shared)?;
    shared.check(service, job.bounds)?;
    // No upstream construction or network call precedes local authentication.
    // This call returns only after genuine upstream attestation and exact 200.
    let result = service.upstream.connect(&destination, job.bounds);
    shared.check(service, job.bounds)?;
    let mut tunnel = result?;
    tunnel.check()?;
    let mut response = 0usize;
    while response < ESTABLISHED.len() {
        shared.check(service, job.bounds)?;
        tunnel.check()?;
        let result = job.socket.write(&ESTABLISHED[response..]);
        shared.check(service, job.bounds)?;
        tunnel.check()?;
        match result {
            Ok(0) => return Err("sidecar local CONNECT response stopped".into()),
            Ok(count) => response += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                wait_local(&job.socket, libc::POLLOUT, job.bounds.deadline, service, shared, job.bounds)?,
            Err(_) => return Err("sidecar local CONNECT response failed".into()),
        }
    }
    let mut outgoing = Zeroizing::new([0u8; CHUNK]);
    let mut incoming = Zeroizing::new([0u8; CHUNK]);
    let (mut out_start, mut out_end, mut in_start, mut in_end) = (0, 0, 0, 0);
    let (mut sent_budget, mut received_budget) = (0u64, 0u64);
    let maximum = service.settings.maximum_tunnel_bytes;
    let mut upstream_eof = false;
    loop {
        shared.check(service, job.bounds)?;
        tunnel.check()?;
        let mut progress = false;
        if in_start < in_end {
            let result = job.socket.write(&incoming[in_start..in_end]);
            shared.check(service, job.bounds)?;
            tunnel.check()?;
            match result {
                Ok(0) => return Err("sidecar local tunnel write stopped".into()),
                Ok(count) => { in_start += count; progress = true; }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                Err(_) => return Err("sidecar local tunnel write failed".into()),
            }
        }
        if in_start == in_end { in_start = 0; in_end = 0; }
        if upstream_eof {
            if out_start != out_end { return Err("sidecar upstream closed with pending local bytes".into()); }
            if in_end == 0 { return Ok(()); }
        } else {
            // Exhaustion closes the connection, never reads an extra probe byte
            // or invents a successful provider result. Counters are per direction.
            if (sent_budget == maximum && out_start == out_end)
                || (received_budget == maximum && in_end == 0)
            { return Err("sidecar directional tunnel byte budget exhausted".into()); }
            if out_start == out_end {
                out_start = 0; out_end = 0;
                let size = (maximum - sent_budget).min(CHUNK as u64) as usize;
                let result = job.socket.read(&mut outgoing[..size]);
                shared.check(service, job.bounds)?;
                tunnel.check()?;
                match result {
                    // No half-close API: local EOF aborts this upstream owner,
                    // including any buffered bytes. It is not replayed or success.
                    Ok(0) => return Err("sidecar local tunnel EOF aborts upstream".into()),
                    Ok(count) => { out_end = count; sent_budget += count as u64; progress = true; }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                    Err(_) => return Err("sidecar local tunnel read failed".into()),
                }
            }
            let capacity = if in_end == 0 { (maximum - received_budget).min(CHUNK as u64) as usize } else { 0 };
            shared.check(service, job.bounds)?;
            let (sent, received, eof) = tunnel.step(&outgoing[out_start..out_end], &mut incoming[..capacity])?;
            shared.check(service, job.bounds)?;
            if sent > out_end - out_start || received > capacity {
                shared.fail("sidecar upstream step exceeded its source bounds".into());
                return Err("sidecar upstream step exceeded its source bounds".into());
            }
            out_start += sent;
            if received > 0 { in_end = received; received_budget += received as u64; }
            upstream_eof = eof;
            progress |= sent > 0 || received > 0 || eof;
        }
        if !progress {
            let events = (if !upstream_eof && out_start == out_end { libc::POLLIN } else { 0 })
                | (if in_start < in_end { libc::POLLOUT } else { 0 });
            // Also wakes at a fixed short interval for upstream progress, whose
            // descriptor stays private to the genuine tunnel owner.
            wait_local(&job.socket, events, job.bounds.deadline, service, shared, job.bounds)?;
        }
    }
}

fn worker(receiver: mpsc::Receiver<Job>, slot: &Slot, service: &Service, shared: &Shared) {
    while !shared.stop.load(Ordering::Acquire) {
        let job = match receiver.recv_timeout(Duration::from_millis(POLL_MS as u64)) {
            Ok(job) => job,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let _occupied = Occupied(slot);
        let _ = connection(job, service, shared);
        // Denied, malformed, expired and failed network sessions close only
        // themselves. Retained authority failure poisons the complete service.
        if !shared.stop.load(Ordering::Acquire) {
            if let Err(error) = service.check() { shared.fail(error); }
        }
    }
}

fn accept_loop(listener: &TcpListener, signals: &Signals, service: &Service,
    shared: &Shared, slots: &[Arc<Slot>], senders: &[mpsc::SyncSender<Job>]) -> Result<(), String> {
    while !shared.stop.load(Ordering::Acquire) {
        if signals.received()? { shared.stop.store(true, Ordering::Release); return Ok(()); }
        service.check()?;
        let available = slots.iter().position(|slot| !slot.busy.load(Ordering::Acquire));
        let mut events = [libc::pollfd { fd: signals.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if available.is_some() { listener.as_raw_fd() } else { -1 },
                events: libc::POLLIN, revents: 0 }];
        let result = unsafe { libc::poll(events.as_mut_ptr(), events.len() as libc::nfds_t, POLL_MS) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
            return Err("sidecar listener poll failed".into());
        }
        if events.iter().any(|event| event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0) {
            return Err("sidecar listener or signal descriptor failed".into());
        }
        if signals.received()? { shared.stop.store(true, Ordering::Release); return Ok(()); }
        service.check()?;
        if shared.stop.load(Ordering::Acquire) || events[1].revents & libc::POLLIN == 0 { continue; }
        let index = available.ok_or("sidecar available worker disappeared")?;
        let (socket, peer) = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("sidecar loopback accept failed".into()),
        };
        let accepted = Instant::now();
        service.check()?;
        // Both observations must name the genuine accepted IPv4 loopback peer,
        // not a forwarded/header identity or any other 127/8 address.
        if !matches!(peer, SocketAddr::V4(address) if *address.ip() == Ipv4Addr::LOCALHOST && address.port() != 0)
            || socket.peer_addr().ok() != Some(peer)
            || socket.local_addr().ok() != Some(SocketAddr::from((Ipv4Addr::LOCALHOST, service.settings.listen_port)))
        { let _ = socket.shutdown(Shutdown::Both); continue; }
        nonblocking(&socket)?;
        let bounds = service.connection_bounds()?;
        let header_deadline = accepted.checked_add(Duration::from_millis(service.settings.header_timeout_milliseconds))
            .ok_or("sidecar local header deadline overflow")?.min(bounds.deadline);
        let duplicate = socket.try_clone().map_err(|_| "sidecar local cancellation duplicate failed")?;
        let slot = &slots[index];
        if slot.busy.swap(true, Ordering::AcqRel) { return Err("sidecar worker slot was already occupied".into()); }
        *slot.local.lock().map_err(|_| "sidecar local cancellation owner poisoned")? = Some(duplicate);
        if senders[index].try_send(Job { socket, bounds, header_deadline }).is_err() {
            slot.clear();
            return Err("sidecar fixed worker handoff failed".into());
        }
    }
    Ok(())
}

pub(super) fn run(service: Arc<Service>) -> Result<(), String> {
    service.check()?;
    let count = usize::from(service.settings.maximum_connections);
    if !(1..=16).contains(&count) || !(1..=120).contains(&service.settings.maximum_connection_seconds)
        || !(1..=5000).contains(&service.settings.header_timeout_milliseconds)
        || !(4096..=1_073_741_824).contains(&service.settings.maximum_tunnel_bytes)
        || service.settings.listen_port == 0
    { return Err("sidecar fixed server limits differ".into()); }
    let mut signals = Signals::open()?;
    service.check()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, service.settings.listen_port))
        .map_err(|_| "sidecar fixed loopback listener unavailable")?;
    listener.set_nonblocking(true).map_err(|_| "sidecar listener nonblocking setup failed")?;
    let flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0
        || unsafe { libc::listen(listener.as_raw_fd(), count as libc::c_int) } != 0
        || listener.local_addr().ok() != Some(SocketAddr::from((Ipv4Addr::LOCALHOST, service.settings.listen_port)))
    { return Err("sidecar actual listener differs from its fixed scope".into()); }
    service.check()?;
    let shared = Shared { stop: AtomicBool::new(false), failure: Mutex::new(None) };
    let slots: Vec<_> = (0..count).map(|_| Arc::new(Slot { busy: AtomicBool::new(false), local: Mutex::new(None) })).collect();
    thread::scope(|scope| {
        let mut workers = Vec::with_capacity(count);
        let mut senders = Vec::with_capacity(count);
        for slot in &slots {
            let (sender, receiver) = mpsc::sync_channel(1);
            let (service, shared) = (&service, &shared);
            match thread::Builder::new().name("workload-sidecar".into()).stack_size(WORKER_STACK_BYTES)
                .spawn_scoped(scope, move || {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(receiver, slot, service, shared))).is_err() {
                        slot.clear();
                        shared.fail("sidecar fixed worker panicked".into());
                    }
                }) {
                Ok(handle) => { workers.push(handle); senders.push(sender); }
                Err(_) => { shared.fail("sidecar fixed worker creation failed".into()); break; }
            }
        }
        if workers.len() == count {
            if let Err(error) = accept_loop(&listener, &signals, &service, &shared, &slots, &senders) {
                shared.fail(error);
            }
        }
        shared.stop.store(true, Ordering::Release);
        drop(listener);
        for slot in &slots { slot.shutdown(); }
        drop(senders);
        // Never detach an in-flight owner, invent a new timeout, or restart it.
        for worker in workers {
            if worker.join().is_err() { shared.fail("sidecar worker join failed".into()); }
        }
        for slot in &slots { slot.clear(); }
    });
    let restored = signals.restore();
    let failure = shared.failure.lock().unwrap_or_else(|error| error.into_inner()).take();
    if let Some(error) = failure { return Err(error); }
    restored
}
