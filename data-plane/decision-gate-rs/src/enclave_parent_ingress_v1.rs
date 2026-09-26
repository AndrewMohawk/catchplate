//! Joined parent TCP ingress to one separately configured enclave VSOCK port.
//!
//! This moves opaque TLS bytes only. There is no TLS termination, HTTP parsing,
//! PROXY header, credential interpretation or wire-selected destination. The
//! original TCP client IP is not carried into the enclave and is not identity;
//! the enclave must authenticate the actual TLS client itself. CID/address
//! equality checks transport scope, not hardware or configuration admission.
//!
//! Queued TCP connections and running TCP/VSOCK pairs retain shutdown custody.
//! Cancellation or expiry stops sessions before every scoped worker is joined,
//! including partial startup failure and unwind. The connect operation keeps
//! its clipped three-second bound and original session deadline. Polling and
//! joins do not provide a hard kernel/syscall watchdog guarantee.

use crate::enclave_tls_relay_io_v1::{relay_tls_bytes, validate_target};
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

const MAX_WORKERS: usize = 16;
const MAX_QUEUED: usize = 64;
const IDLE_NS: u64 = 5_000_000;

fn error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

fn shutdown_tcp(stream: &TcpStream) -> io::Result<()> {
    match stream.shutdown(Shutdown::Both) {
        Err(problem) if problem.kind() == io::ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

struct TcpConnection {
    stream: TcpStream,
    pid: libc::pid_t,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.pid {
            let _ = shutdown_tcp(&self.stream);
        }
    }
}

struct ConnectedVsock(VsockStreamV1);
impl Drop for ConnectedVsock {
    fn drop(&mut self) { let _ = self.0.shutdown(); }
}

struct SessionShutdown {
    pid: libc::pid_t,
    tcp: TcpStream,
    stopped: AtomicBool,
    vsock: Mutex<Option<VsockShutdownV1>>,
}

impl SessionShutdown {
    fn owner(&self) -> io::Result<()> {
        if unsafe { libc::getpid() } != self.pid {
            return Err(error(io::ErrorKind::PermissionDenied, "parent ingress session process changed"));
        }
        Ok(())
    }

    fn attach(&self, stream: &VsockStreamV1) -> io::Result<()> {
        self.owner()?;
        let shutdown = stream.shutdown_handle()?;
        let mut held = self.vsock.lock()
            .map_err(|_| error(io::ErrorKind::Other, "parent ingress session is poisoned"))?;
        if self.stopped.load(Ordering::Acquire) || held.is_some() {
            let _ = shutdown.shutdown();
            return Err(error(io::ErrorKind::ConnectionAborted, "parent ingress session cannot attach"));
        }
        // shutdown sets stopped before taking this same lock. Thus a concurrent
        // stop either rejects this attachment or closes the newly held socket.
        *held = Some(shutdown);
        Ok(())
    }

    fn shutdown(&self) -> io::Result<()> {
        self.owner()?;
        self.stopped.store(true, Ordering::Release);
        let mut failure = shutdown_tcp(&self.tcp).err();
        let held = match self.vsock.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                if failure.is_none() {
                    failure = Some(error(io::ErrorKind::Other, "parent ingress session is poisoned"));
                }
                poisoned.into_inner()
            }
        };
        if let Some(handle) = held.as_ref() {
            if let Err(problem) = handle.shutdown() {
                if failure.is_none() { failure = Some(problem); }
            }
        }
        match failure { Some(failure) => Err(failure), None => Ok(()) }
    }
}

impl Drop for SessionShutdown {
    fn drop(&mut self) { let _ = self.shutdown(); }
}

struct Lifetime {
    pid: libc::pid_t,
    deadline: u64,
    expected_listen: SocketAddr,
    enclave_cid: u32,
    enclave_port: u32,
    stopped: AtomicBool,
    external_cancel: Arc<AtomicBool>,
    sessions: Mutex<Vec<Weak<SessionShutdown>>>,
    capacity: usize,
}

impl Lifetime {
    fn owner(&self) -> io::Result<()> {
        if unsafe { libc::getpid() } != self.pid {
            return Err(error(io::ErrorKind::PermissionDenied, "parent ingress creator process changed"));
        }
        Ok(())
    }

    fn remaining(&self) -> io::Result<u64> {
        self.owner()?;
        if self.stopped.load(Ordering::Acquire)
            || self.external_cancel.load(Ordering::Acquire)
        {
            return Err(error(io::ErrorKind::ConnectionAborted, "parent ingress serving stopped"));
        }
        let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
            return Err(error(io::ErrorKind::InvalidData, "parent ingress boottime sample is invalid"));
        }
        let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(sample.tv_nsec as u64))
            .ok_or_else(|| error(io::ErrorKind::InvalidData, "parent ingress boottime sample overflows"))?;
        self.deadline.checked_sub(now).filter(|value| *value != 0)
            .ok_or_else(|| error(io::ErrorKind::TimedOut, "parent ingress original deadline expired"))
    }

    fn idle(&self) -> io::Result<()> {
        let remaining = self.remaining()?;
        thread::park_timeout(Duration::from_nanos(remaining.min(IDLE_NS)));
        self.remaining().map(|_| ())
    }

    fn register(&self, stream: &TcpStream) -> io::Result<Arc<SessionShutdown>> {
        self.remaining()?;
        if stream.local_addr()? != self.expected_listen {
            return Err(error(io::ErrorKind::PermissionDenied, "parent ingress accepted local address differs"));
        }
        let tcp = stream.try_clone()?;
        if tcp.local_addr()? != self.expected_listen || tcp.peer_addr()? != stream.peer_addr()? {
            return Err(error(io::ErrorKind::InvalidData, "parent ingress TCP shutdown duplicate differs"));
        }
        let shutdown = Arc::new(SessionShutdown { pid: self.pid, tcp,
            stopped: AtomicBool::new(false), vsock: Mutex::new(None) });
        let mut sessions = self.sessions.lock()
            .map_err(|_| error(io::ErrorKind::Other, "parent ingress session registry is poisoned"))?;
        sessions.retain(|entry| entry.strong_count() != 0);
        // This only observes cancellation. Never call stop with this lock held.
        self.remaining()?;
        if sessions.len() >= self.capacity {
            return Err(error(io::ErrorKind::Other, "parent ingress session capacity was exceeded"));
        }
        sessions.push(Arc::downgrade(&shutdown));
        Ok(shutdown)
    }

    fn stop(&self) -> io::Result<()> {
        self.owner()?;
        self.stopped.store(true, Ordering::Release);
        let mut failure = None;
        let sessions = match self.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => {
                failure = Some(error(io::ErrorKind::Other, "parent ingress session registry is poisoned"));
                poisoned.into_inner()
            }
        };
        for handle in sessions.iter().filter_map(Weak::upgrade) {
            if let Err(problem) = handle.shutdown() {
                if failure.is_none() { failure = Some(problem); }
            }
        }
        match failure { Some(failure) => Err(failure), None => Ok(()) }
    }
}

struct StopGuard(Arc<Lifetime>);
impl Drop for StopGuard {
    fn drop(&mut self) { let _ = self.0.stop(); }
}

struct Work {
    tcp: TcpConnection,
    // Strong cancellation custody follows queued/running work, not history.
    shutdown: Arc<SessionShutdown>,
}
impl Drop for Work {
    fn drop(&mut self) { let _ = self.shutdown.shutdown(); }
}

fn run_worker(receiver: &Mutex<mpsc::Receiver<Work>>, lifetime: &Lifetime) -> io::Result<()> {
    loop {
        lifetime.owner()?;
        if lifetime.stopped.load(Ordering::Acquire) { return Ok(()); }
        lifetime.remaining()?;
        let received = receiver.lock()
            .map_err(|_| error(io::ErrorKind::Other, "parent ingress worker queue is poisoned"))?
            .try_recv();
        let mut work = match received {
            Ok(work) => work,
            Err(mpsc::TryRecvError::Empty) => { lifetime.idle()?; continue; }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        };
        lifetime.remaining()?;
        // A session failure closes this pair only: never retry or select another
        // destination. Work's shutdown owner covers connect failure and unwind.
        let _ = (|| -> io::Result<()> {
            if work.tcp.stream.local_addr()? != lifetime.expected_listen {
                return Err(error(io::ErrorKind::PermissionDenied, "parent ingress work local address differs"));
            }
            let mut vsock = ConnectedVsock(VsockStreamV1::connect_enclave(
                lifetime.enclave_cid, lifetime.enclave_port, lifetime.deadline,
                &lifetime.stopped,
            )?);
            lifetime.remaining()?;
            if vsock.0.peer_cid() != lifetime.enclave_cid
                || vsock.0.peer_port() != lifetime.enclave_port
                || vsock.0.deadline() != lifetime.deadline
            {
                return Err(error(io::ErrorKind::PermissionDenied, "parent ingress connected VSOCK scope differs"));
            }
            work.shutdown.attach(&vsock.0)?;
            lifetime.remaining()?;
            relay_tls_bytes(&mut work.tcp.stream, &mut vsock.0,
                lifetime.deadline, &lifetime.stopped)
        })();
        drop(work);
    }
}

fn verify_listener(listener: &TcpListener, expected: SocketAddr) -> io::Result<()> {
    if listener.local_addr()? != expected {
        return Err(error(io::ErrorKind::PermissionDenied, "parent ingress listener address differs"));
    }
    for (option, expected_value) in [(libc::SO_TYPE, libc::SOCK_STREAM), (libc::SO_ACCEPTCONN, 1)] {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe { libc::getsockopt(listener.as_raw_fd(), libc::SOL_SOCKET, option,
            (&mut value as *mut libc::c_int).cast(), &mut length) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of_val(&value) || value != expected_value {
            return Err(error(io::ErrorKind::InvalidData, "parent ingress requires an actual listening TCP stream socket"));
        }
    }
    Ok(())
}

/// Structural preflight only, suitable before binding the configured listener.
pub fn validate_parent_ingress_v1(listen: SocketAddr, cid: u32, port: u32,
    workers: usize, queue: usize) -> io::Result<()> {
    if listen.port() <= 1023 || cid <= 3 || cid == u32::MAX
        || port <= 1023 || port == u32::MAX
        || !(1..=MAX_WORKERS).contains(&workers) || !(1..=MAX_QUEUED).contains(&queue)
    {
        return Err(error(io::ErrorKind::InvalidInput, "parent ingress endpoint or resource bounds are invalid"));
    }
    validate_target(listen)
}

/// Consume one actual listener for a single fixed enclave destination.
/// Cancellation and expiry are errors, not completion receipts. Queue
/// saturation closes only the newly accepted TCP connection.
pub fn serve_parent_ingress_v1(listener: TcpListener, expected_listen: SocketAddr,
    enclave_cid: u32, enclave_port: u32, workers: usize, queue_capacity: usize,
    deadline: u64, cancel: Arc<AtomicBool>) -> io::Result<()> {
    validate_parent_ingress_v1(expected_listen, enclave_cid, enclave_port, workers, queue_capacity)?;
    let capacity = workers + queue_capacity + 1;
    let lifetime = Arc::new(Lifetime { pid: unsafe { libc::getpid() }, deadline,
        expected_listen, enclave_cid, enclave_port, stopped: AtomicBool::new(false),
        external_cancel: cancel, sessions: Mutex::new(Vec::with_capacity(capacity)), capacity });
    lifetime.remaining()?;
    verify_listener(&listener, expected_listen)?;
    listener.set_nonblocking(true)?;
    lifetime.remaining()?;
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel::<Work>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        // Drops before the queue during unwind; scope still joins all workers.
        let _stop_guard = StopGuard(Arc::clone(&lifetime));
        let mut held_workers = Vec::with_capacity(workers);
        let serving = (|| -> io::Result<()> {
            lifetime.remaining()?;
            for index in 0..workers {
                let receiver = Arc::clone(&receiver);
                let lifetime = Arc::clone(&lifetime);
                held_workers.push(thread::Builder::new().name(format!("parent-ingress-{index}"))
                    .spawn_scoped(scope, move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            run_worker(&receiver, &lifetime)
                        }));
                        let result = match result {
                            Ok(result) => result,
                            Err(_) => Err(error(io::ErrorKind::Other, "parent ingress worker panicked")),
                        };
                        if result.is_err() { let _ = lifetime.stop(); }
                        result
                    })?);
            }
            loop {
                lifetime.remaining()?;
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(problem) if problem.kind() == io::ErrorKind::WouldBlock => {
                        lifetime.idle()?;
                        continue;
                    }
                    Err(problem) if problem.kind() == io::ErrorKind::Interrupted => continue,
                    Err(problem) => return Err(problem),
                };
                let tcp = TcpConnection { stream, pid: lifetime.pid };
                tcp.stream.set_nonblocking(true)?;
                let shutdown = lifetime.register(&tcp.stream)?;
                let work = Work { tcp, shutdown };
                match sender.try_send(work) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(work)) => drop(work),
                    Err(mpsc::TrySendError::Disconnected(work)) => {
                        drop(work);
                        return Err(error(io::ErrorKind::BrokenPipe, "parent ingress worker queue disconnected"));
                    }
                }
            }
        })();
        let shutdown = lifetime.stop();
        drop(sender);
        let mut worker_failure = None;
        for worker in held_workers {
            let result = match worker.join() {
                Ok(result) => result,
                Err(_) => Err(error(io::ErrorKind::Other, "parent ingress worker join failed")),
            };
            if let Err(problem) = result {
                if worker_failure.is_none() { worker_failure = Some(problem); }
            }
        }
        // Joined workers no longer hold the receiver; destroy queued originals
        // and their shutdown owners before any return, even on an earlier error.
        drop(receiver);
        shutdown?;
        if let Some(problem) = worker_failure { return Err(problem); }
        serving
    })
}
