//! Source-fixed local readiness upgrade transcript, not a Docker API override.
//!
//! The independently signed fixture pins the exact request header and both
//! streams. This exercises the existing controller-owned socket-pair probe;
//! it does not claim a real daemon attach or replace body-output capture.

use super::{
    boottime_now_ns_v11, read_deadline_cancelled, sha256,
    write_all_deadline_counted, ControllerError, Digest, Result,
    RELAY_CHUNK_BYTES_V11,
};
use sha2::{Digest as ShaDigest, Sha256};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
const RESPONSE_HEAD: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: catchplate-readiness\r\n\r\n";

pub(crate) struct ReadinessUpgradeReceiptV12 {
    pub client_stream_sha256: Digest,
    pub server_stream_sha256: Digest,
}

/// The stream is post-upgrade data, never an HTTP request body. This fixed
/// recipe must itself match the independently signed fixture's header pin.
pub(crate) fn request_head(target: &str) -> Result<Vec<u8>> {
    if !target.starts_with("/v1.") || target.len() > 1024
        || target.contains("..")
        || target.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b'#')
    {
        return Err(ControllerError::Rejected(
            "Docker readiness upgrade target is not a bounded canonical target",
        ));
    }
    Ok(format!(
        "POST {target} HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: catchplate-readiness\r\nContent-Length: 0\r\n\r\n",
    ).into_bytes())
}

pub(crate) fn execute(
    target: &str,
    expected_request_headers_sha256: &Digest,
    client_stream: Vec<u8>,
    server_stream: Vec<u8>,
    deadline: u64,
) -> Result<ReadinessUpgradeReceiptV12> {
    let head = request_head(target)?;
    if sha256(&head) != *expected_request_headers_sha256
        || client_stream.is_empty() || client_stream.len() > MAX_STREAM_BYTES
        || server_stream.len() < 2 || server_stream.len() > MAX_STREAM_BYTES
    {
        return Err(ControllerError::Rejected(
            "Docker readiness upgrade header pin or stream bounds differ",
        ));
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    require_live(deadline, &cancelled)?;
    let client_original: Arc<[u8]> = Arc::from(client_stream.into_boxed_slice());
    let server_original: Arc<[u8]> = Arc::from(server_stream.into_boxed_slice());
    let (mut client, mut server) = UnixStream::pair()?;
    client.set_nonblocking(true)?;
    server.set_nonblocking(true)?;
    let server_control = server.try_clone()?;
    let expected_head = head.clone();
    let expected_client = Arc::clone(&client_original);
    let emitted_server = Arc::clone(&server_original);
    let worker_cancelled = Arc::clone(&cancelled);
    let worker = std::thread::Builder::new()
        .name("catchplate-readiness-upgrade-v12".to_owned())
        .spawn(move || -> Result<Digest> {
            let mut failure = FailureSignal {
                cancelled: Arc::clone(&worker_cancelled),
                armed: true,
            };
            let sent = AtomicU64::new(0);
            let mut header_hash = Sha256::new();
            read_exact_original(
                &mut server, &expected_head, &mut header_hash,
                deadline, &worker_cancelled,
            )?;
            write_all_deadline_counted(
                &mut server, RESPONSE_HEAD, deadline, &worker_cancelled, &sent,
            )?;
            // A genuine pinned server byte is observed while the client write
            // side is still open. The remaining bytes are deliberately withheld
            // until the complete client original and its write-half EOF arrive.
            write_all_deadline_counted(
                &mut server, &emitted_server[..1], deadline, &worker_cancelled, &sent,
            )?;
            let mut client_hash = Sha256::new();
            read_exact_original(
                &mut server, &expected_client, &mut client_hash,
                deadline, &worker_cancelled,
            )?;
            require_eof(&mut server, deadline, &worker_cancelled)?;
            write_all_deadline_counted(
                &mut server, &emitted_server[1..], deadline, &worker_cancelled, &sent,
            )?;
            server.shutdown(Shutdown::Write)?;
            require_live(deadline, &worker_cancelled)?;
            failure.armed = false;
            Ok(client_hash.finalize().into())
        })
        .map_err(ControllerError::Io)?;
    let mut joined = JoinedFixture {
        server_control,
        cancelled: Arc::clone(&cancelled),
        worker: Some(worker),
    };
    let client_result = (|| -> Result<Digest> {
        let sent = AtomicU64::new(0);
        write_all_deadline_counted(
            &mut client, &head, deadline, &cancelled, &sent,
        )?;
        let mut header_hash = Sha256::new();
        read_exact_original(
            &mut client, RESPONSE_HEAD, &mut header_hash, deadline, &cancelled,
        )?;
        let mut server_hash = Sha256::new();
        read_exact_original(
            &mut client, &server_original[..1], &mut server_hash, deadline, &cancelled,
        )?;
        write_all_deadline_counted(
            &mut client, &client_original, deadline, &cancelled, &sent,
        )?;
        client.shutdown(Shutdown::Write)?;
        read_exact_original(
            &mut client, &server_original[1..], &mut server_hash, deadline, &cancelled,
        )?;
        require_eof(&mut client, deadline, &cancelled)?;
        require_live(deadline, &cancelled)?;
        Ok(server_hash.finalize().into())
    })();
    if client_result.is_err() {
        joined.cancel();
        let _ = client.shutdown(Shutdown::Both);
    }
    // Always join, including partial request/response errors. The client error
    // remains primary; worker failure/panic cancels the same original window.
    let worker_result = joined.join();
    let server_stream_sha256 = client_result?;
    let client_stream_sha256 = worker_result?;
    require_live(deadline, &cancelled)?;
    if client_stream_sha256 != sha256(&client_original)
        || server_stream_sha256 != sha256(&server_original)
    {
        return Err(ControllerError::Rejected(
            "Docker readiness upgrade observed transcript digest differs",
        ));
    }
    Ok(ReadinessUpgradeReceiptV12 {
        client_stream_sha256,
        server_stream_sha256,
    })
}

struct FailureSignal {
    cancelled: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for FailureSignal {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

struct JoinedFixture {
    server_control: UnixStream,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Digest>>>,
}

impl JoinedFixture {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.server_control.shutdown(Shutdown::Both);
    }

    fn join(&mut self) -> Result<Digest> {
        let worker = self.worker.take().ok_or(ControllerError::Rejected(
            "Docker readiness upgrade worker was already joined",
        ))?;
        worker.join().map_err(|_| {
            ControllerError::Rejected("Docker readiness upgrade worker panicked")
        })?
    }
}

impl Drop for JoinedFixture {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.cancel();
            let _ = worker.join();
        }
    }
}

fn require_live(deadline: u64, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) || boottime_now_ns_v11()? >= deadline {
        return Err(ControllerError::Rejected(
            "Docker readiness upgrade original deadline expired or was cancelled",
        ));
    }
    Ok(())
}

fn read_exact_original(
    stream: &mut UnixStream,
    expected: &[u8],
    hasher: &mut Sha256,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut offset = 0usize;
    let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
    while offset < expected.len() {
        let wanted = (expected.len() - offset).min(buffer.len());
        let count = read_deadline_cancelled(
            stream, &mut buffer[..wanted], deadline, cancelled,
        )?;
        if count == 0 || buffer[..count] != expected[offset..offset + count] {
            return Err(ControllerError::Rejected(
                "Docker readiness upgrade transcript is truncated or differs",
            ));
        }
        hasher.update(&buffer[..count]);
        offset += count;
    }
    require_live(deadline, cancelled)
}

fn require_eof(
    stream: &mut UnixStream,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut extra = [0u8; 1];
    if read_deadline_cancelled(stream, &mut extra, deadline, cancelled)? != 0 {
        return Err(ControllerError::Rejected(
            "Docker readiness upgrade transcript contains surplus bytes",
        ));
    }
    require_live(deadline, cancelled)
}
