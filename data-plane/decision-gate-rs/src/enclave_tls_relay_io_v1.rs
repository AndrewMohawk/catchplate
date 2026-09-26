//! Bounded opaque TLS-byte relay, without a listener or a target-selection wire.
//!
//! The parent entry accepts a previously admitted enclave-CID stream and a
//! separately configured literal upstream socket address. Neither establishes
//! TLS identity or request permission. The enclave's TLS client must perform
//! genuine upstream certificate/hostname verification. No DNS, redirect, TLS
//! termination, credential parsing or production activation occurs here.
//!
//! First EOF stops both read directions; only bytes already in the two fixed
//! buffers are drained before full shutdown. Error, cancellation or expiry
//! discards pending bytes and attempts full shutdown immediately. Successful
//! draining is not an application-completion receipt. Requested polling/connect
//! bounds do not provide a hard scheduler/syscall watchdog guarantee.

use crate::enclave_vsock_v1::VsockStreamV1;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const BUFFER_BYTES: usize = 16 * 1024;
const IDLE_WAIT_NS: u64 = 5_000_000;
const CONNECT_LIMIT_NS: u64 = 3_000_000_000;

fn failure(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

fn live(deadline: u64, stopped: &AtomicBool) -> io::Result<u64> {
    if stopped.load(Ordering::Acquire) {
        return Err(failure(io::ErrorKind::ConnectionAborted, "TLS-byte relay was cancelled"));
    }
    let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
        return Err(failure(io::ErrorKind::InvalidData, "TLS-byte relay clock is invalid"));
    }
    let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(sample.tv_nsec as u64))
        .ok_or_else(|| failure(io::ErrorKind::InvalidData, "TLS-byte relay clock overflow"))?;
    deadline.checked_sub(now).filter(|remaining| *remaining != 0)
        .ok_or_else(|| failure(io::ErrorKind::TimedOut, "TLS-byte relay original deadline expired"))
}

struct PendingBytes {
    bytes: [u8; BUFFER_BYTES],
    start: usize,
    end: usize,
}

impl PendingBytes {
    fn new() -> Self { Self { bytes: [0; BUFFER_BYTES], start: 0, end: 0 } }
    fn is_empty(&self) -> bool { self.start == self.end }
    fn pending(&self) -> &[u8] { &self.bytes[self.start..self.end] }

    fn received(&mut self, count: usize) -> io::Result<()> {
        if !self.is_empty() || count > self.bytes.len() {
            return Err(failure(io::ErrorKind::InvalidData, "TLS-byte relay read length is invalid"));
        }
        self.start = 0;
        self.end = count;
        Ok(())
    }

    fn sent(&mut self, count: usize) -> io::Result<()> {
        if count == 0 {
            return Err(failure(io::ErrorKind::WriteZero, "TLS-byte relay write made no progress"));
        }
        if count > self.end - self.start {
            return Err(failure(io::ErrorKind::InvalidData, "TLS-byte relay write length is invalid"));
        }
        self.start += count;
        if self.is_empty() { self.start = 0; self.end = 0; }
        Ok(())
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}

fn shutdown_tcp(tcp: &TcpStream) -> io::Result<()> {
    match tcp.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

/// Private composition seam for the fixed loopback adapter and parent owner.
/// This attempts both full shutdowns on every returned result; callers must
/// discard both streams, including when shutdown itself reports an error.
pub(crate) fn relay_tls_bytes(tcp: &mut TcpStream, vsock: &mut VsockStreamV1,
    deadline: u64, stopped: &AtomicBool) -> io::Result<()> {
    let deadline = deadline.min(vsock.deadline());
    let result = (|| -> io::Result<()> {
        live(deadline, stopped)?;
        tcp.set_nonblocking(true)?;
        let mut to_vsock = PendingBytes::new();
        let mut to_tcp = PendingBytes::new();
        let mut draining = false;
        loop {
            live(deadline, stopped)?;
            let mut progressed = false;
            if !to_vsock.is_empty() {
                match vsock.try_write(to_vsock.pending()) {
                    Ok(count) => { to_vsock.sent(count)?; progressed = true; }
                    Err(error) if transient(&error) => {}
                    Err(error) => return Err(error),
                }
                live(deadline, stopped)?;
            }
            if !to_tcp.is_empty() {
                match tcp.write(to_tcp.pending()) {
                    Ok(count) => { to_tcp.sent(count)?; progressed = true; }
                    Err(error) if transient(&error) => {}
                    Err(error) => return Err(error),
                }
                live(deadline, stopped)?;
            }
            if !draining && to_vsock.is_empty() {
                match tcp.read(&mut to_vsock.bytes) {
                    Ok(0) => { draining = true; progressed = true; }
                    Ok(count) => { to_vsock.received(count)?; progressed = true; }
                    Err(error) if transient(&error) => {}
                    Err(error) => return Err(error),
                }
                live(deadline, stopped)?;
            }
            if !draining && to_tcp.is_empty() {
                match vsock.try_read(&mut to_tcp.bytes) {
                    Ok(0) => { draining = true; progressed = true; }
                    Ok(count) => { to_tcp.received(count)?; progressed = true; }
                    Err(error) if transient(&error) => {}
                    Err(error) => return Err(error),
                }
                live(deadline, stopped)?;
            }
            let remaining = live(deadline, stopped)?;
            if draining && to_vsock.is_empty() && to_tcp.is_empty() { return Ok(()); }
            if !progressed {
                // Spurious wakeups merely recheck the same original deadline.
                thread::park_timeout(Duration::from_nanos(remaining.min(IDLE_WAIT_NS)));
            }
        }
    })();
    // Always attempt both even when the first shutdown fails. Preserve the
    // original relay failure rather than presenting cleanup as successful IO.
    let tcp_closed = shutdown_tcp(tcp);
    let vsock_closed = vsock.shutdown();
    match result {
        Err(error) => Err(error),
        Ok(()) => tcp_closed.and(vsock_closed),
    }
}

pub(crate) fn validate_target(target: SocketAddr) -> io::Result<()> {
    let valid = target.port() != 0 && match target {
        SocketAddr::V4(address) => {
            let octets = address.ip().octets();
            // Keep independently assigned private/loopback unicast usable;
            // reject this-network, multicast and reserved/broadcast ranges.
            octets[0] != 0 && octets[0] < 224
        }
        SocketAddr::V6(address) => {
            let octets = address.ip().octets();
            !address.ip().is_unspecified() && !address.ip().is_multicast()
                && !(octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
                && address.ip().to_ipv4_mapped().is_none()
                && address.flowinfo() == 0 && address.scope_id() == 0
        }
    };
    if valid { Ok(()) } else {
        Err(failure(io::ErrorKind::InvalidInput, "TLS-byte relay requires a concrete unicast target"))
    }
}

struct AcceptedStream(VsockStreamV1);

impl Drop for AcceptedStream {
    fn drop(&mut self) { let _ = self.0.shutdown(); }
}

/// One parent connection, not a daemon, proxy protocol or target authorizer.
/// `stream` must already be admitted for the independently expected enclave CID;
/// `target` must be the separately admitted fixed assignment for that listener.
/// Validation below checks transport shape only. No target is read from bytes.
pub fn relay_fixed_upstream_v1(stream: VsockStreamV1, target: SocketAddr,
    deadline: u64) -> io::Result<()> {
    let stopped = AtomicBool::new(false);
    relay_fixed_upstream_with_cancel_v1(stream, target, deadline, &stopped)
}

/// The serving owner supplies its actual retained cancellation flag. Checking
/// that flag also aborts when pending TCP output prevents another VSOCK read.
pub(crate) fn relay_fixed_upstream_with_cancel_v1(stream: VsockStreamV1, target: SocketAddr,
    deadline: u64, stopped: &AtomicBool) -> io::Result<()> {
    let mut accepted = AcceptedStream(stream);
    let deadline = deadline.min(accepted.0.deadline());
    validate_target(target)?;
    let remaining = live(deadline, stopped)?;
    let mut tcp = TcpStream::connect_timeout(&target,
        Duration::from_nanos(remaining.min(CONNECT_LIMIT_NS)))?;
    let result = (|| -> io::Result<()> {
        live(deadline, stopped)?;
        if tcp.peer_addr()? != target {
            return Err(failure(io::ErrorKind::InvalidData, "TLS-byte relay upstream endpoint changed"));
        }
        relay_tls_bytes(&mut tcp, &mut accepted.0, deadline, stopped)
    })();
    let closed = shutdown_tcp(&tcp);
    match result { Err(error) => Err(error), Ok(()) => closed }
}
