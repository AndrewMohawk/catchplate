//! Fixed-destination localhost CONNECT adapter for the real HTTPS client.
//!
//! CONNECT and its fresh local password terminate here; neither is sent to
//! the parent. Only opaque TLS bytes cross a preassigned parent-CID-3 port.
//! Reqwest retains origin-host TLS verification. A CID/port, this password,
//! or successful tunnelling is not attestation or destination admission.
//!
//! Four joined workers and a sixteen-item queue are owned until Drop. Idle
//! waits are at most 5ms and never renew the original boottime deadline.
//! Cancellation attempts shutdown of every established endpoint; streams are
//! discarded on failure. An in-progress vsock connect can delay joining up to
//! its clipped three-second bound, plus kernel/scheduling delay. This is not
//! a hard syscall watchdog. The shared relay's first EOF stops new reads in
//! both directions, drains only already buffered bytes, then closes both.

use crate::enclave_tls_relay_io_v1::relay_tls_bytes;
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use base64::{engine::general_purpose, Engine as _};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zeroize::Zeroizing;

const WORKERS: usize = 4;
const QUEUE: usize = 16;
const MAX_SESSIONS: usize = WORKERS + QUEUE + 1;
const MAX_AUTHORITY_BYTES: usize = 512;
const MAX_HEAD_BYTES: usize = 8192;
const IDLE_NS: u64 = 5_000_000;
const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

fn error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

fn remaining(deadline: u64) -> io::Result<u64> {
    let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
        return Err(error(io::ErrorKind::InvalidData, "loopback boottime sample is invalid"));
    }
    let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(sample.tv_nsec as u64))
        .ok_or_else(|| error(io::ErrorKind::InvalidData, "loopback boottime sample overflows"))?;
    deadline.checked_sub(now).filter(|value| *value != 0)
        .ok_or_else(|| error(io::ErrorKind::TimedOut, "loopback original deadline expired"))
}

fn validate_authority(authority: &str) -> io::Result<()> {
    let invalid = || error(io::ErrorKind::InvalidInput, "loopback requires a fixed host:port authority");
    if authority.is_empty() || authority.len() > MAX_AUTHORITY_BYTES || !authority.is_ascii() {
        return Err(invalid());
    }
    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:").ok_or_else(invalid)?;
        host.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        port
    } else {
        let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
        if host.is_empty() || host.len() > 253 || host.contains(':')
            || host.split('.').any(|label| label.is_empty() || label.len() > 63
                || label.starts_with('-') || label.ends_with('-')
                || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')) {
            return Err(invalid());
        }
        port
    };
    if port.is_empty() || port.len() > 5 || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().ok().filter(|value| *value != 0).is_none() {
        return Err(invalid());
    }
    Ok(())
}

struct Session {
    tcp_shutdown: TcpStream,
    vsock_shutdown: Mutex<Option<VsockShutdownV1>>,
}

impl Session {
    fn shutdown(&self) -> io::Result<()> {
        let mut failure = match self.tcp_shutdown.shutdown(Shutdown::Both) {
            Err(error) if error.kind() != io::ErrorKind::NotConnected => Some(error),
            _ => None,
        };
        let held = match self.vsock_shutdown.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                if failure.is_none() {
                    failure = Some(error(io::ErrorKind::Other, "loopback session lock poisoned"));
                }
                poisoned.into_inner()
            }
        };
        if let Some(handle) = held.as_ref() {
            if let Err(error) = handle.shutdown() {
                if failure.is_none() { failure = Some(error); }
            }
        }
        match failure { Some(error) => Err(error), None => Ok(()) }
    }

    fn install_vsock(&self, stream: &VsockStreamV1, control: &Control, deadline: u64)
        -> io::Result<()> {
        let handle = stream.shutdown_handle()?;
        let mut held = self.vsock_shutdown.lock()
            .map_err(|_| error(io::ErrorKind::Other, "loopback session lock poisoned"))?;
        if let Err(failure) = control.check(deadline) {
            let _ = handle.shutdown();
            return Err(failure);
        }
        if held.is_some() {
            let _ = handle.shutdown();
            return Err(error(io::ErrorKind::InvalidData, "loopback session already connected"));
        }
        *held = Some(handle);
        Ok(())
    }
}

struct Control {
    pid: libc::pid_t,
    stopped: AtomicBool,
    failed: AtomicBool,
    sessions: Mutex<Vec<Weak<Session>>>,
}

impl Control {
    fn check(&self, deadline: u64) -> io::Result<()> {
        if unsafe { libc::getpid() } != self.pid {
            return Err(error(io::ErrorKind::PermissionDenied, "loopback tunnel crossed its creating process"));
        }
        remaining(deadline)?;
        if self.stopped.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return Err(error(io::ErrorKind::ConnectionAborted, "loopback tunnel stopped"));
        }
        Ok(())
    }

    fn idle(&self, deadline: u64) -> io::Result<()> {
        self.check(deadline)?;
        thread::park_timeout(Duration::from_nanos(remaining(deadline)?.min(IDLE_NS)));
        self.check(deadline)
    }

    fn register(&self, stream: &TcpStream, deadline: u64) -> io::Result<Arc<Session>> {
        let session = Arc::new(Session { tcp_shutdown: stream.try_clone()?,
            vsock_shutdown: Mutex::new(None) });
        let mut sessions = self.sessions.lock()
            .map_err(|_| error(io::ErrorKind::Other, "loopback session inventory poisoned"))?;
        self.check(deadline)?;
        sessions.retain(|entry| entry.strong_count() != 0);
        if sessions.len() >= MAX_SESSIONS {
            return Err(error(io::ErrorKind::Other, "loopback session inventory exceeds bound"));
        }
        sessions.push(Arc::downgrade(&session));
        Ok(session)
    }

    fn stop(&self) {
        // Do not shutdown a parent process's inherited socket after fork.
        if unsafe { libc::getpid() } != self.pid { return; }
        self.stopped.store(true, Ordering::Release);
        let sessions = match self.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => {
                self.failed.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        for session in sessions.iter().filter_map(Weak::upgrade) {
            if session.shutdown().is_err() { self.failed.store(true, Ordering::Release); }
        }
    }
}

struct StopOnExit(Arc<Control>);
impl Drop for StopOnExit {
    fn drop(&mut self) { self.0.stop(); }
}

struct Work {
    stream: TcpStream,
    session: Arc<Session>,
}
impl Drop for Work {
    fn drop(&mut self) { let _ = self.session.shutdown(); }
}

fn equal_secret(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= (left.get(index).copied().unwrap_or(0)
            ^ right.get(index).copied().unwrap_or(0)) as usize;
    }
    difference == 0
}

fn admit_connect(stream: &mut TcpStream, authority: &str, authorization: &str,
    control: &Control, deadline: u64) -> io::Result<()> {
    let mut original = Zeroizing::new(Vec::with_capacity(MAX_HEAD_BYTES));
    while !original.ends_with(b"\r\n\r\n") {
        control.check(deadline)?;
        if original.len() == MAX_HEAD_BYTES {
            return Err(error(io::ErrorKind::InvalidData, "loopback CONNECT header exceeds bound"));
        }
        // Never consume the first TLS byte following the local request head.
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return Err(error(io::ErrorKind::UnexpectedEof, "loopback CONNECT header incomplete")),
            Ok(1) => original.push(byte[0]),
            Ok(_) => return Err(error(io::ErrorKind::InvalidData, "loopback read length invalid")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => control.idle(deadline)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    control.check(deadline)?;
    if !original.is_ascii() {
        return Err(error(io::ErrorKind::InvalidData, "loopback CONNECT header is not ASCII"));
    }
    let text = std::str::from_utf8(&original[..original.len() - 4])
        .map_err(|_| error(io::ErrorKind::InvalidData, "loopback CONNECT header is malformed"))?;
    let mut lines = text.split("\r\n");
    let request_line = format!("CONNECT {authority} HTTP/1.1");
    if lines.next() != Some(request_line.as_str()) {
        return Err(error(io::ErrorKind::PermissionDenied, "loopback CONNECT authority or method denied"));
    }
    let mut host_seen = false;
    let mut authorization_seen = false;
    let mut agent_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':')
            .ok_or_else(|| error(io::ErrorKind::InvalidData, "loopback CONNECT header field is malformed"))?;
        let value = value.trim_matches(|byte| byte == ' ' || byte == '\t');
        if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(error(io::ErrorKind::InvalidData, "loopback CONNECT header value is malformed"));
        }
        if name.eq_ignore_ascii_case("host") && !host_seen && value == authority {
            host_seen = true;
        } else if name.eq_ignore_ascii_case("proxy-authorization") && !authorization_seen
            && equal_secret(value.as_bytes(), authorization.as_bytes()) {
            authorization_seen = true;
        } else if name.eq_ignore_ascii_case("user-agent") && !agent_seen && !value.is_empty() {
            agent_seen = true;
        } else {
            // No body, transfer coding, duplicate field or arbitrary proxy
            // extension is accepted. Fail closed without echoing any secret.
            return Err(error(io::ErrorKind::PermissionDenied, "loopback CONNECT field denied"));
        }
    }
    if !host_seen || !authorization_seen {
        return Err(error(io::ErrorKind::PermissionDenied, "loopback CONNECT authentication missing"));
    }
    control.check(deadline)
}

fn handle(work: &mut Work, authority: &str, authorization: &str, relay_port: u32,
    control: &Control, deadline: u64) -> io::Result<()> {
    admit_connect(&mut work.stream, authority, authorization, control, deadline)?;
    let mut remote = VsockStreamV1::connect_parent(relay_port, deadline)?;
    work.session.install_vsock(&remote, control, deadline)?;
    let mut sent = 0;
    while sent < CONNECTED.len() {
        control.check(deadline)?;
        match work.stream.write(&CONNECTED[sent..]) {
            Ok(0) => return Err(error(io::ErrorKind::WriteZero, "loopback CONNECT response made no progress")),
            Ok(count) => sent += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => control.idle(deadline)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    control.check(deadline)?;
    relay_tls_bytes(&mut work.stream, &mut remote, deadline, &control.stopped)
}

fn serve(listener: TcpListener, address: SocketAddr, authority: String,
    authorization: Arc<Zeroizing<String>>, relay_port: u32, deadline: u64,
    control: Arc<Control>, ready: mpsc::SyncSender<()>) -> io::Result<()> {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel::<Work>(QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        // On unwinding, cancel sockets before sender disconnect and scope join.
        let _stop = StopOnExit(Arc::clone(&control));
        let mut workers = Vec::with_capacity(WORKERS);
        let serving = (|| -> io::Result<()> {
            for index in 0..WORKERS {
                let receiver = Arc::clone(&receiver);
                let control = Arc::clone(&control);
                let authority = &authority;
                let authorization = Arc::clone(&authorization);
                workers.push(thread::Builder::new().name(format!("native-loopback-relay-{index}"))
                    .spawn_scoped(scope, move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            loop {
                                let next = receiver.lock().map_err(|_| error(io::ErrorKind::Other,
                                    "loopback queue poisoned"))?.recv();
                                let Ok(mut work) = next else { return Ok::<(), io::Error>(()); };
                                if control.check(deadline).is_err() { continue; }
                                // Individual denied/incomplete sessions close; they
                                // neither authenticate later sessions nor stop peers.
                                let _ = handle(&mut work, authority, authorization.as_str(),
                                    relay_port, &control, deadline);
                            }
                        }));
                        match result {
                            Ok(Ok(())) => Ok(()),
                            _ => {
                                control.failed.store(true, Ordering::Release);
                                control.stop();
                                Err(error(io::ErrorKind::Other, "loopback relay worker failed"))
                            }
                        }
                    })?);
            }
            control.check(deadline)?;
            ready.send(()).map_err(|_| error(io::ErrorKind::BrokenPipe, "loopback startup owner disappeared"))?;
            loop {
                control.check(deadline)?;
                let (stream, peer) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        control.idle(deadline)?;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
                    || stream.peer_addr()? != peer || stream.local_addr()? != address {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                stream.set_nonblocking(true)?;
                let session = control.register(&stream, deadline)?;
                let work = Work { stream, session };
                match sender.try_send(work) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(rejected)) => drop(rejected),
                    Err(mpsc::TrySendError::Disconnected(rejected)) => {
                        drop(rejected);
                        return Err(error(io::ErrorKind::BrokenPipe, "loopback relay queue disconnected"));
                    }
                }
            }
        })();
        control.stop();
        drop(sender);
        let mut worker_failed = false;
        for worker in workers {
            if !matches!(worker.join(), Ok(Ok(()))) { worker_failed = true; }
        }
        if worker_failed {
            return Err(error(io::ErrorKind::Other, "loopback relay worker join failed"));
        }
        serving
    })
}

/// Local CONNECT permission only, not independent enclave or peer admission.
/// No Clone/Debug, raw socket export, alternate destination or detached worker.
pub struct LoopbackTlsTunnelV1 {
    address: SocketAddr,
    password: Zeroizing<String>,
    deadline: u64,
    control: Arc<Control>,
    server: Option<JoinHandle<io::Result<()>>>,
}

impl LoopbackTlsTunnelV1 {
    pub fn open(authority: &str, relay_port: u32, deadline: u64) -> io::Result<Self> {
        remaining(deadline)?;
        validate_authority(authority)?;
        if relay_port <= 1023 || relay_port == u32::MAX {
            return Err(error(io::ErrorKind::InvalidInput, "loopback parent relay port is invalid"));
        }
        let mut random = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(random.as_mut())
            .map_err(|_| error(io::ErrorKind::Other, "loopback proxy randomness unavailable"))?;
        let password = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(random.as_ref()));
        let mut credentials = Zeroizing::new(String::from("serverware-relay:"));
        credentials.push_str(&password);
        let encoded = Zeroizing::new(general_purpose::STANDARD.encode(credentials.as_bytes()));
        let mut authorization = Zeroizing::new(String::from("Basic "));
        authorization.push_str(&encoded);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
            return Err(error(io::ErrorKind::InvalidData, "loopback listener scope changed"));
        }
        let control = Arc::new(Control { pid: unsafe { libc::getpid() },
            stopped: AtomicBool::new(false), failed: AtomicBool::new(false),
            sessions: Mutex::new(Vec::with_capacity(MAX_SESSIONS)) });
        control.check(deadline)?;
        let worker_control = Arc::clone(&control);
        let authority = authority.to_owned();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let server = thread::Builder::new().name("native-loopback-listener".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    serve(listener, address, authority, Arc::new(authorization), relay_port,
                        deadline, Arc::clone(&worker_control), ready_sender)
                }));
                worker_control.failed.store(true, Ordering::Release);
                worker_control.stop();
                match result {
                    Ok(result) => result,
                    Err(_) => Err(error(io::ErrorKind::Other, "loopback listener failed")),
                }
            })?;
        let held = Self { address, password, deadline, control, server: Some(server) };
        loop {
            held.verify_live()?;
            match ready_receiver.try_recv() {
                Ok(()) => { held.verify_live()?; return Ok(held); }
                Err(mpsc::TryRecvError::Empty) => held.control.idle(deadline)?,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(error(io::ErrorKind::ConnectionAborted, "loopback workers failed to start"));
                }
            }
        }
    }

    /// Secret for the local client's Basic proxy authorization only.
    pub fn proxy_password(&self) -> &str { &self.password }
    pub fn proxy_addr(&self) -> SocketAddr { self.address }

    pub fn verify_live(&self) -> io::Result<()> {
        self.control.check(self.deadline)?;
        if self.server.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(error(io::ErrorKind::ConnectionAborted, "loopback serving owner is unavailable"));
        }
        Ok(())
    }
}

impl Drop for LoopbackTlsTunnelV1 {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } != self.control.pid { return; }
        self.control.stop();
        if let Some(server) = self.server.take() { let _ = server.join(); }
    }
}
