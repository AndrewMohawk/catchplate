//! Joined parent-side serving for one independently configured literal target.
//!
//! The consumed listener's fixed peer CID and original lifetime are checked
//! before contact. A CID is routing metadata, not attestation or permission.
//! No target, hostname, HTTP header or credential is read from the wire: only
//! opaque TLS bytes enter the existing fixed-target relay. Origin TLS remains
//! the enclave client's responsibility; this module does not terminate it.
//!
//! Queued and running streams retain shutdown custody. Every return or unwind
//! stops sessions and joins all workers; no detached worker is created. A TCP
//! connect already in progress can delay joining by its clipped three-second
//! operation bound, plus kernel/scheduling delay. Polls are not a hard syscall
//! watchdog. The separate fixed-configuration CLI now selects this composition;
//! this module is not provisioning, admitted configuration or production proof.

use crate::enclave_tls_relay_io_v1::{relay_fixed_upstream_with_cancel_v1, validate_target};
use crate::enclave_vsock_v1::{VsockListenerV1, VsockShutdownV1, VsockStreamV1};
use std::io;
use std::net::SocketAddr;
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

struct Lifetime {
    pid: libc::pid_t,
    deadline: u64,
    expected_peer_cid: u32,
    stopped: AtomicBool,
    external_cancel: Arc<AtomicBool>,
    sessions: Mutex<Vec<Weak<VsockShutdownV1>>>,
    capacity: usize,
}

impl Lifetime {
    fn owner(&self) -> io::Result<()> {
        if unsafe { libc::getpid() } != self.pid {
            return Err(error(io::ErrorKind::PermissionDenied, "parent relay creator process changed"));
        }
        Ok(())
    }

    fn remaining(&self) -> io::Result<u64> {
        self.owner()?;
        if self.stopped.load(Ordering::Acquire)
            || self.external_cancel.load(Ordering::Acquire)
        {
            return Err(error(io::ErrorKind::ConnectionAborted, "parent relay serving stopped"));
        }
        let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
            return Err(error(io::ErrorKind::InvalidData, "parent relay boottime sample is invalid"));
        }
        let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(sample.tv_nsec as u64))
            .ok_or_else(|| error(io::ErrorKind::InvalidData, "parent relay boottime sample overflows"))?;
        self.deadline.checked_sub(now).filter(|value| *value != 0)
            .ok_or_else(|| error(io::ErrorKind::TimedOut, "parent relay original deadline expired"))
    }

    fn idle(&self) -> io::Result<()> {
        let remaining = self.remaining()?;
        thread::park_timeout(Duration::from_nanos(remaining.min(IDLE_NS)));
        self.remaining().map(|_| ())
    }

    fn register(&self, stream: &VsockStreamV1) -> io::Result<Arc<VsockShutdownV1>> {
        self.remaining()?;
        if stream.peer_cid() != self.expected_peer_cid || stream.deadline() != self.deadline {
            return Err(error(io::ErrorKind::PermissionDenied, "parent relay accepted scope differs"));
        }
        let shutdown = Arc::new(stream.shutdown_handle()?);
        let mut sessions = self.sessions.lock()
            .map_err(|_| error(io::ErrorKind::Other, "parent relay session registry is poisoned"))?;
        sessions.retain(|entry| entry.strong_count() != 0);
        self.remaining()?;
        if sessions.len() >= self.capacity {
            return Err(error(io::ErrorKind::Other, "parent relay session capacity was exceeded"));
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
                failure = Some(error(io::ErrorKind::Other, "parent relay session registry is poisoned"));
                poisoned.into_inner()
            }
        };
        // Do not stop cleanup after the first error, including poisoned state.
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
    stream: Option<VsockStreamV1>,
    // The sole strong cancellation owner stays with queued or running work.
    shutdown: Arc<VsockShutdownV1>,
}

impl Drop for Work {
    fn drop(&mut self) { let _ = self.shutdown.shutdown(); }
}

fn run_worker(receiver: &Mutex<mpsc::Receiver<Work>>, lifetime: &Lifetime,
    target: SocketAddr) -> io::Result<()> {
    loop {
        lifetime.owner()?;
        if lifetime.stopped.load(Ordering::Acquire) { return Ok(()); }
        lifetime.remaining()?;
        let received = receiver.lock()
            .map_err(|_| error(io::ErrorKind::Other, "parent relay worker queue is poisoned"))?
            .try_recv();
        let mut work = match received {
            Ok(work) => work,
            Err(mpsc::TryRecvError::Empty) => { lifetime.idle()?; continue; }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        };
        lifetime.remaining()?;
        let stream = work.stream.take()
            .ok_or_else(|| error(io::ErrorKind::InvalidData, "parent relay work lost its stream"))?;
        // An upstream/session failure closes this work, not another destination
        // or a retry. The same immutable target is used for every connection.
        let _ = relay_fixed_upstream_with_cancel_v1(stream, target,
            lifetime.deadline, &lifetime.stopped);
        drop(work);
    }
}

/// Check the same literal-target rules used by serving, before listener bind.
/// This does not resolve a hostname, contact the target or admit its provenance.
pub fn validate_parent_relay_target_v1(target: SocketAddr) -> io::Result<()> {
    validate_target(target)
}

/// Serve one already-created listener and one separately configured target.
/// Expiry is an error, not a completion receipt. Workers are joined on every
/// exit; capacity rejection silently closes only the newly accepted stream.
pub fn serve_parent_relay_v1(listener: VsockListenerV1, target: SocketAddr,
    expected_peer_cid: u32, worker_count: usize, queue_capacity: usize,
    deadline: u64) -> io::Result<()> {
    serve_parent_relay_with_cancel_v1(listener, target, expected_peer_cid,
        worker_count, queue_capacity, deadline, Arc::new(AtomicBool::new(false)))
}

/// Serve the same fixed scope with externally owned cancellation. Cancellation
/// returns ConnectionAborted, not a completion receipt; the existing bounded
/// accept/idle ticks observe it and stop registered sessions before all joins.
/// An already-running TCP connect retains its clipped three-second bound.
pub fn serve_parent_relay_with_cancel_v1(listener: VsockListenerV1, target: SocketAddr,
    expected_peer_cid: u32, worker_count: usize, queue_capacity: usize,
    deadline: u64, cancel: Arc<AtomicBool>) -> io::Result<()> {
    if !(1..=MAX_WORKERS).contains(&worker_count) || !(1..=MAX_QUEUED).contains(&queue_capacity)
        || expected_peer_cid <= 3 || expected_peer_cid == u32::MAX {
        return Err(error(io::ErrorKind::InvalidInput, "parent relay worker, queue or enclave CID is invalid"));
    }
    validate_target(target)?;
    let deadline = deadline.min(listener.deadline());
    listener.verify_peer_scope(expected_peer_cid, deadline)?;
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel::<Work>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let capacity = worker_count + queue_capacity + 1;
        let lifetime = Arc::new(Lifetime { pid: unsafe { libc::getpid() }, deadline,
            expected_peer_cid, stopped: AtomicBool::new(false), capacity,
            external_cancel: cancel,
            sessions: Mutex::new(Vec::with_capacity(capacity)) });
        // This guard drops before the queue during unwind; thread::scope then
        // still joins every spawned worker after all streams are cancelled.
        let _stop_guard = StopGuard(Arc::clone(&lifetime));
        let mut workers = Vec::with_capacity(worker_count);
        let serving = (|| -> io::Result<()> {
            lifetime.remaining()?;
            for index in 0..worker_count {
                let receiver = Arc::clone(&receiver);
                let lifetime = Arc::clone(&lifetime);
                let worker = thread::Builder::new().name(format!("parent-relay-{index}"))
                    .spawn_scoped(scope, move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            run_worker(&receiver, &lifetime, target)
                        }));
                        let result = match result {
                            Ok(result) => result,
                            Err(_) => Err(error(io::ErrorKind::Other, "parent relay worker panicked")),
                        };
                        if result.is_err() { let _ = lifetime.stop(); }
                        result
                    })?;
                workers.push(worker);
            }
            loop {
                lifetime.remaining()?;
                // Never use an idle-tick deadline as the stream lifetime.
                let stream = match listener.try_accept(deadline) {
                    Ok(stream) => stream,
                    Err(failure) if failure.kind() == io::ErrorKind::WouldBlock => {
                        lifetime.idle()?;
                        continue;
                    }
                    Err(failure) => return Err(failure),
                };
                let shutdown = match lifetime.register(&stream) {
                    Ok(shutdown) => shutdown,
                    Err(failure) => {
                        let _ = stream.shutdown();
                        return Err(failure);
                    }
                };
                let work = Work { stream: Some(stream), shutdown };
                match sender.try_send(work) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(work)) => drop(work),
                    Err(mpsc::TrySendError::Disconnected(work)) => {
                        drop(work);
                        return Err(error(io::ErrorKind::BrokenPipe, "parent relay worker queue disconnected"));
                    }
                }
            }
        })();
        let shutdown = lifetime.stop();
        drop(sender);
        let mut worker_failure = None;
        for worker in workers {
            let result = match worker.join() {
                Ok(result) => result,
                Err(_) => Err(error(io::ErrorKind::Other, "parent relay worker join failed")),
            };
            if let Err(failure) = result {
                if worker_failure.is_none() { worker_failure = Some(failure); }
            }
        }
        // All receiver clones in joined workers are gone. Drop queued originals
        // and their strong shutdown owners before returning the serving result.
        drop(receiver);
        shutdown?;
        if let Some(failure) = worker_failure { return Err(failure); }
        serving
    })
}
