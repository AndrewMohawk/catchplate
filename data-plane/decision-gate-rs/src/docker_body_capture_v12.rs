//! Fixed pre-start Docker API 1.45 non-TTY stdout/stderr subscription.
//!
//! The caller owns the admitted daemon/container identity, original deadline,
//! and controller-only tmpfs files. This module neither creates paths nor
//! manufactures runtime-observer evidence. A normal frame-boundary EOF must
//! still be joined by the owner to its independently successful Docker wait.

use super::{
    boottime_now_ns_v11, parse_response_status, read_deadline_cancelled,
    write_all_deadline_counted, ControllerError, Digest, Result,
    HTTP_HEAD_MAX_BYTES_V11, RELAY_CHUNK_BYTES_V11,
};
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{Seek, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

const MAX_STREAM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FRAMES: u64 = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyCaptureReceiptV12 {
    pub stdout_sha256: Digest,
    pub stderr_sha256: Digest,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

pub struct BodyCaptureV12 {
    stream: UnixStream,
    cancelled: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<BodyCaptureReceiptV12>>>,
}

impl BodyCaptureV12 {
    /// Returns only after the daemon has installed the output subscription
    /// and sent its complete 101 multiplexed-stream response header.
    pub fn start(
        mut stream: UnixStream,
        container_id: &str,
        mut stdout: File,
        mut stderr: File,
        per_stream_limit: u64,
        deadline: u64,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let failed = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let started = (|| {
            require_live(deadline, &cancelled)?;
            if container_id.len() != 64
                || !container_id.bytes().all(|byte| {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                })
                || per_stream_limit == 0
                || per_stream_limit > MAX_STREAM_BYTES
            {
                return Err(ControllerError::Rejected(
                    "Docker body capture container or byte bound is invalid",
                ));
            }
            let stdout_identity = initial_file(&mut stdout)?;
            let stderr_identity = initial_file(&mut stderr)?;
            if stdout_identity.device == stderr_identity.device
                && stdout_identity.inode == stderr_identity.inode
            {
                return Err(ControllerError::Rejected(
                    "Docker body capture streams share an output inode",
                ));
            }
            stream.set_nonblocking(true)?;
            let request = format!(
                "POST /v1.45/containers/{container_id}/attach?logs=0&stderr=1&stdin=0&stdout=1&stream=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            );
            let sent = AtomicU64::new(0);
            write_all_deadline_counted(
                &mut stream, request.as_bytes(), deadline, &cancelled, &sent,
            )?;
            read_upgrade(&mut stream, deadline, &cancelled)?;
            require_live(deadline, &cancelled)?;
            let reader = stream.try_clone()?;
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_failed = Arc::clone(&failed);
            let worker_completed = Arc::clone(&completed);
            std::thread::Builder::new()
                .name("serverware-docker-body-capture-v12".to_owned())
                .spawn(move || {
                    // A panic must wake the concurrent start/wait transport
                    // just as a normal capture error does.
                    let mut failure = FailureSignal {
                        cancelled: Arc::clone(&worker_cancelled),
                        failed: worker_failed,
                        armed: true,
                    };
                    let receipt = capture(
                        reader, stdout, stderr, stdout_identity,
                        stderr_identity, per_stream_limit, deadline,
                        &worker_cancelled,
                    )?;
                    worker_completed.store(true, Ordering::Release);
                    failure.armed = false;
                    Ok(receipt)
                })
                .map_err(ControllerError::Io)
        })();
        match started {
            Ok(worker) => Ok(Self {
                stream, cancelled, failed, completed, worker: Some(worker),
            }),
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                let _ = stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }

    /// Normal EOF is not failure. The owning lifecycle must still obtain its
    /// actual terminal wait result before accepting the captured digests.
    pub fn health(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire)
            || self.failed.load(Ordering::Acquire)
            || self.worker.as_ref().is_some_and(|worker| {
                worker.is_finished() && !self.completed.load(Ordering::Acquire)
            })
        {
            return Err(ControllerError::Rejected(
                "Docker body capture failed or was cancelled",
            ));
        }
        Ok(())
    }

    /// A subscription already closed before start is not launch readiness.
    pub fn require_pending(&self) -> Result<()> {
        self.health()?;
        if self.completed.load(Ordering::Acquire)
            || self.worker.as_ref().is_none_or(|worker| worker.is_finished())
        {
            return Err(ControllerError::Rejected(
                "Docker body capture subscription closed before container start",
            ));
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<BodyCaptureReceiptV12> {
        let worker = self.worker.take().ok_or(ControllerError::Rejected(
            "Docker body capture worker was already consumed",
        ))?;
        let result = worker.join().map_err(|_| {
            ControllerError::Rejected("Docker body capture worker panicked")
        }).and_then(|result| result);
        match result {
            Ok(receipt) => {
                // Taking the joined worker disarms Drop without cancelling a
                // successfully completed capture or any subsequent owner work.
                self.health()?;
                Ok(receipt)
            }
            Err(error) => {
                self.cancelled.store(true, Ordering::Release);
                let _ = self.stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }
}

impl Drop for BodyCaptureV12 {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.cancelled.store(true, Ordering::Release);
            let _ = self.stream.shutdown(Shutdown::Both);
            let _ = worker.join();
        }
    }
}

struct FailureSignal {
    cancelled: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for FailureSignal {
    fn drop(&mut self) {
        if self.armed {
            self.failed.store(true, Ordering::Release);
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

#[derive(Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

fn file_identity(file: &File) -> Result<(FileIdentity, u64)> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != 0 || metadata.gid() != 0 || metadata.nlink() != 1
    {
        return Err(ControllerError::Rejected(
            "Docker body capture file is not private root-owned regular storage",
        ));
    }
    Ok((FileIdentity {
        device: metadata.dev(), inode: metadata.ino(), mode: metadata.mode(),
        uid: metadata.uid(), gid: metadata.gid(), links: metadata.nlink(),
    }, metadata.len()))
}

fn initial_file(file: &mut File) -> Result<FileIdentity> {
    let (identity, length) = file_identity(file)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length != 0 || file.stream_position()? != 0
        || !matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
        || flags & libc::O_APPEND != 0
    {
        return Err(ControllerError::Rejected(
            "Docker body capture file is not an empty exclusive-position writer",
        ));
    }
    Ok(identity)
}

fn require_live(deadline: u64, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) || boottime_now_ns_v11()? >= deadline {
        return Err(ControllerError::Rejected(
            "Docker body capture original deadline expired or was cancelled",
        ));
    }
    Ok(())
}

fn read_upgrade(
    stream: &mut UnixStream,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    // Read only the header, leaving every multiplex frame byte on the socket.
    // Moby API 1.45 emits precisely these three upgrade headers for non-TTY
    // attach, after installing the output streams (daemon/attach.go).
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HTTP_HEAD_MAX_BYTES_V11 {
            return Err(ControllerError::Rejected(
                "Docker body attach response header exceeds its bound",
            ));
        }
        if read_deadline_cancelled(stream, &mut byte, deadline, cancelled)? == 0 {
            return Err(ControllerError::Rejected(
                "Docker body attach closed before its upgrade header",
            ));
        }
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head[..head.len() - 4]).map_err(|_| {
        ControllerError::Rejected("Docker body attach header is not UTF-8")
    })?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 ") || parse_response_status(status.as_bytes())? != 101 {
        return Err(ControllerError::Rejected(
            "Docker body attach did not establish its required 101 upgrade",
        ));
    }
    let mut content_type = false;
    let mut connection = false;
    let mut upgrade = false;
    for line in lines {
        let (name, value) = line.split_once(": ").ok_or(
            ControllerError::Rejected("Docker body attach header is malformed"),
        )?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" if !content_type
                && value == "application/vnd.docker.multiplexed-stream" => {
                content_type = true;
            }
            "connection" if !connection && value.eq_ignore_ascii_case("upgrade") => {
                connection = true;
            }
            "upgrade" if !upgrade && value.eq_ignore_ascii_case("tcp") => {
                upgrade = true;
            }
            _ => return Err(ControllerError::Rejected(
                "Docker body attach headers differ from the fixed non-TTY upgrade",
            )),
        }
    }
    if !content_type || !connection || !upgrade {
        return Err(ControllerError::Rejected(
            "Docker body attach upgrade headers are incomplete",
        ));
    }
    Ok(())
}

fn capture(
    mut stream: UnixStream,
    mut stdout: File,
    mut stderr: File,
    stdout_identity: FileIdentity,
    stderr_identity: FileIdentity,
    per_stream_limit: u64,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<BodyCaptureReceiptV12> {
    let mut stdout_hash = Sha256::new();
    let mut stderr_hash = Sha256::new();
    let mut stdout_bytes = 0u64;
    let mut stderr_bytes = 0u64;
    let mut frames = 0u64;
    let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
    loop {
        let mut header = [0u8; 8];
        let first = read_deadline_cancelled(&mut stream, &mut header, deadline, cancelled)?;
        if first == 0 {
            break;
        }
        let mut filled = first;
        while filled < header.len() {
            let count = read_deadline_cancelled(
                &mut stream, &mut header[filled..], deadline, cancelled,
            )?;
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "Docker body capture ended inside a multiplex header",
                ));
            }
            filled += count;
        }
        frames += 1; // Capped at one million before another iteration.
        if frames > MAX_FRAMES || !matches!(header[0], 1 | 2)
            || header[1..4] != [0, 0, 0]
        {
            return Err(ControllerError::Rejected(
                "Docker body capture multiplex frame type, padding or count is invalid",
            ));
        }
        let length = u64::from(u32::from_be_bytes([
            header[4], header[5], header[6], header[7],
        ]));
        let (file, hash, total) = if header[0] == 1 {
            (&mut stdout, &mut stdout_hash, &mut stdout_bytes)
        } else {
            (&mut stderr, &mut stderr_hash, &mut stderr_bytes)
        };
        let next_total = total.checked_add(length).ok_or(ControllerError::Rejected(
            "Docker body capture stream length overflowed",
        ))?;
        if next_total > per_stream_limit {
            return Err(ControllerError::Rejected(
                "Docker body capture exceeds its original per-stream byte bound",
            ));
        }
        let mut remaining = length;
        while remaining != 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            let count = read_deadline_cancelled(
                &mut stream, &mut buffer[..wanted], deadline, cancelled,
            )?;
            if count == 0 {
                return Err(ControllerError::Rejected(
                    "Docker body capture ended inside a multiplex payload",
                ));
            }
            write_file(file, &buffer[..count], deadline, cancelled)?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        *total = next_total;
    }
    finish_file(&mut stdout, &stdout_identity, stdout_bytes, deadline, cancelled)?;
    finish_file(&mut stderr, &stderr_identity, stderr_bytes, deadline, cancelled)?;
    require_live(deadline, cancelled)?;
    Ok(BodyCaptureReceiptV12 {
        stdout_sha256: stdout_hash.finalize().into(),
        stderr_sha256: stderr_hash.finalize().into(),
        stdout_bytes,
        stderr_bytes,
    })
}

fn write_file(
    file: &mut File,
    mut bytes: &[u8],
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    while !bytes.is_empty() {
        require_live(deadline, cancelled)?;
        match file.write(bytes) {
            Ok(0) => return Err(ControllerError::Rejected(
                "Docker body capture file made no write progress",
            )),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    require_live(deadline, cancelled)
}

fn finish_file(
    file: &mut File,
    expected: &FileIdentity,
    bytes: u64,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    require_live(deadline, cancelled)?;
    file.flush()?;
    let (identity, length) = file_identity(file)?;
    if &identity != expected || length != bytes || file.stream_position()? != bytes {
        return Err(ControllerError::Rejected(
            "Docker body capture file identity or final length changed",
        ));
    }
    require_live(deadline, cancelled)
}
