#![allow(dead_code)]

use crate::coder_controller_v11::{
    constant_time_eq, sha256, ControllerError, Digest, Result,
};
use crate::docker_contract::{
    boottime_now_ns_v11, DockerBoundsV11, DockerStreamModeV11,
};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const PROXY_ENVELOPE_MAGIC_V11: [u8; 8] = *b"SWDKRQ11";
const PROXY_ENVELOPE_HEADER_BYTES_V11: usize = 64;
const HTTP_HEAD_MAX_BYTES_V11: usize = 64 * 1024;
const CONTRACT_MAX_BYTES_V11: usize = 1024 * 1024;
const RELAY_CHUNK_BYTES_V11: usize = 64 * 1024;
const POLL_QUANTUM_MS_V11: u64 = 250;

static SPOOL_SEQUENCE_V11: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct DockerProxyEnvelopeHeaderV11 {
    pub stream_mode: DockerStreamModeV11,
    pub capability_bytes: u32,
    pub request_bytes: u32,
    pub http_head_bytes: u32,
    pub body_bytes: u64,
    pub body_sha256: Digest,
}

pub struct DockerProxyEnvelopeV11 {
    pub header: DockerProxyEnvelopeHeaderV11,
    pub capability: Vec<u8>,
    pub request: Vec<u8>,
    pub http: CanonicalDockerHttpHeadV11,
    pub body: DurableSpoolV11,
}

#[derive(Clone, Debug)]
pub struct CanonicalDockerHttpHeadV11 {
    pub method: String,
    pub raw_target: String,
    pub normalized_route: String,
    pub canonical_query: Vec<(String, String)>,
    pub daemon_head: Vec<u8>,
}

pub struct DurableSpoolV11 {
    path: PathBuf,
    file: File,
    length: u64,
    sha256: Digest,
}

impl Drop for DurableSpoolV11 {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl DurableSpoolV11 {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn sha256(&self) -> Digest {
        self.sha256
    }

    pub fn rewind(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    pub fn file(&self) -> Result<File> {
        Ok(self.file.try_clone()?)
    }

    pub fn remove(&mut self) -> Result<()> {
        self.file.sync_all()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        File::open(self.path.parent().ok_or(
            ControllerError::Invalid("spool path has no parent"),
        )?)?
        .sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DockerTransportReceiptV11 {
    pub status_code: u16,
    pub upgraded: bool,
    pub request_bytes: u64,
    pub upstream_bytes_sent: u64,
    pub upstream_disposition: DockerUpstreamDispositionV12,
    pub response_bytes: u64,
    pub response_sha256: Digest,
    pub response_path: PathBuf,
    pub completed_boottime_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerUpstreamDispositionV12 {
    NotSent,
    CompleteResponseValidated,
    PostSendUncertain,
}

#[derive(Clone, Debug)]
pub struct DockerPostSendUncertaintyV12 {
    pub upstream_bytes_sent: u64,
    pub response_bytes_received: u64,
    pub response_framing_validated: bool,
    pub deadline_boottime_ns: u64,
}

pub enum DockerTransportOutcomeV12 {
    Complete(DockerTransportReceiptV11),
    RejectedBeforeUpstream {
        error: ControllerError,
    },
    PostSendUncertain {
        uncertainty: DockerPostSendUncertaintyV12,
        error: ControllerError,
    },
    DownstreamReleaseFailed {
        receipt: DockerTransportReceiptV11,
        error: ControllerError,
    },
}

pub enum DockerRequestBodyV12 {
    Empty,
    Bytes(Vec<u8>),
    File {
        file: File,
        bytes: u64,
        sha256: Digest,
    },
}

impl DockerRequestBodyV12 {
    fn into_reader(self) -> Result<(Box<dyn Read + Send>, u64, Digest)> {
        match self {
            Self::Empty => Ok((
                Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                0,
                sha256(&[]),
            )),
            Self::Bytes(bytes) => {
                let length = bytes.len() as u64;
                let digest = sha256(&bytes);
                Ok((Box::new(std::io::Cursor::new(bytes)), length, digest))
            }
            Self::File {
                mut file,
                bytes,
                sha256: expected_sha256,
            } => {
                if bytes == 0 || expected_sha256 == [0; 32] {
                    return Err(ControllerError::Rejected(
                        "Docker direct request file has no exact identity",
                    ));
                }
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.len() != bytes
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(ControllerError::Rejected(
                        "Docker direct request file identity is unsafe",
                    ));
                }
                file.seek(SeekFrom::Start(0))?;
                let actual = crate::coder_controller_v11::sha256_exact_reader(
                    &mut file,
                    bytes,
                )?;
                if !constant_time_eq(&actual, &expected_sha256) {
                    return Err(ControllerError::Rejected(
                        "Docker direct request file digest differs",
                    ));
                }
                file.seek(SeekFrom::Start(0))?;
                Ok((Box::new(file), bytes, expected_sha256))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DockerHttpExchangeContractV12 {
    pub stream_mode: DockerStreamModeV11,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_stream_bytes: u64,
    pub deadline_boottime_ns: u64,
}

impl DockerHttpExchangeContractV12 {
    pub fn validate(&self) -> Result<()> {
        if self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_stream_bytes == 0
            || self.max_request_bytes > self.max_stream_bytes
            || self.max_response_bytes > self.max_stream_bytes
            || self.max_stream_bytes > 16 * 1024 * 1024 * 1024
            || self.deadline_boottime_ns <= boottime_now_ns_v11()?
        {
            return Err(ControllerError::Rejected(
                "Docker direct HTTP exchange contract is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DockerDirectHttpReceiptV12 {
    pub status_code: u16,
    pub upgraded: bool,
    pub request_bytes: u64,
    pub request_sha256: Digest,
    pub response_bytes: u64,
    pub response_sha256: Digest,
    pub response: Vec<u8>,
    pub completed_boottime_ns: u64,
}

#[derive(Clone, Debug)]
pub struct DockerJsonMessageSequenceReceiptV12 {
    pub status_code: u16,
    pub message_count: u64,
    pub body_bytes: u64,
    pub body_sha256: Digest,
}

#[derive(Debug)]
pub enum DockerDirectHttpOutcomeV12 {
    Complete(DockerDirectHttpReceiptV12),
    RejectedBeforeSend(ControllerError),
    PostSendUncertain {
        request_bytes_sent: u64,
        response_bytes_received: u64,
        error: ControllerError,
    },
}

pub fn canonical_docker_request_head_v12(
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body_bytes: u64,
) -> Result<Vec<u8>> {
    if !matches!(method, "GET" | "HEAD" | "POST" | "DELETE")
        || !target.starts_with("/v1.")
        || target.len() > 16 * 1024
        || target.bytes().any(|byte| {
            byte <= 0x20 || byte == 0x7f || byte == b'#'
        })
    {
        return Err(ControllerError::Rejected(
            "Docker direct HTTP request line is not canonical",
        ));
    }
    let mut prior: Option<&str> = None;
    let mut head = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    head.extend_from_slice(b"Host: docker\r\n");
    head.extend_from_slice(b"Connection: close\r\n");
    if body_bytes != 0 {
        head.extend_from_slice(
            format!("Content-Length: {body_bytes}\r\n").as_bytes(),
        );
    }
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if name != &lower
            || name.is_empty()
            || name.len() > 128
            || value.len() > 16 * 1024
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'
            })
            || value.bytes().any(|byte| {
                byte == 0
                    || byte == b'\r'
                    || byte == b'\n'
                    || byte == 0x7f
            })
            || matches!(
                lower.as_str(),
                "host" | "connection" | "content-length"
            )
            || prior.is_some_and(|prior| prior >= lower.as_str())
        {
            return Err(ControllerError::Rejected(
                "Docker direct HTTP header set is noncanonical",
            ));
        }
        prior = Some(name);
        let display = name
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_ascii_uppercase().to_string()
                            + chars.as_str()
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join("-");
        head.extend_from_slice(display.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    if head.len() > HTTP_HEAD_MAX_BYTES_V11 {
        return Err(ControllerError::Rejected(
            "Docker direct HTTP request header exceeds its bound",
        ));
    }
    Ok(head)
}

pub fn execute_bounded_docker_http_v12(
    daemon: &mut UnixStream,
    request_head: Vec<u8>,
    body: DockerRequestBodyV12,
    contract: &DockerHttpExchangeContractV12,
) -> DockerDirectHttpOutcomeV12 {
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let result = (|| -> Result<DockerDirectHttpReceiptV12> {
        contract.validate()?;
        if request_head.is_empty()
            || request_head.len() > HTTP_HEAD_MAX_BYTES_V11
            || !request_head.ends_with(b"\r\n\r\n")
        {
            return Err(ControllerError::Rejected(
                "Docker direct HTTP request header is incomplete",
            ));
        }
        let (mut body, body_bytes, body_sha256) =
            body.into_reader()?;
        let request_bytes = (request_head.len() as u64)
            .checked_add(body_bytes)
            .ok_or(ControllerError::Invalid(
                "Docker direct request length overflowed",
            ))?;
        if request_bytes > contract.max_request_bytes {
            return Err(ControllerError::Rejected(
                "Docker direct request exceeds its signed bound",
            ));
        }
        let mut request_hasher = Sha256::new();
        request_hasher.update(&request_head);
        request_hasher.update(body_sha256);
        request_hasher.update(body_bytes.to_be_bytes());
        let request_digest = request_hasher.finalize();
        let mut request_sha256 = [0u8; 32];
        request_sha256.copy_from_slice(&request_digest);
        daemon.set_nonblocking(true)?;
        let mut writer = daemon.try_clone()?;
        let mut reader = daemon.try_clone()?;
        let deadline = contract.deadline_boottime_ns;
        let sent_worker = Arc::clone(&sent);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_worker = Arc::clone(&cancelled);
        let upload = std::thread::Builder::new()
            .name("serverware-private-dind-http-upload-v12".to_owned())
            .spawn(move || -> Result<()> {
                let outcome = (|| -> Result<()> {
                    write_all_deadline_counted(
                        &mut writer,
                        &request_head,
                        deadline,
                        &cancelled_worker,
                        &sent_worker,
                    )?;
                    let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
                    loop {
                        let count = body.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        write_all_deadline_counted(
                            &mut writer,
                            &buffer[..count],
                            deadline,
                            &cancelled_worker,
                            &sent_worker,
                        )?;
                    }
                    writer.shutdown(std::net::Shutdown::Write)?;
                    Ok(())
                })();
                if outcome.is_err() {
                    cancelled_worker.store(true, Ordering::Release);
                }
                outcome
            })
            .map_err(ControllerError::Io)?;
        let response_result = (|| -> Result<(Vec<u8>, bool)> {
            let mut response = Vec::new();
            let mut complete = false;
            let mut peer_closed = false;
            while !complete {
                if response.len() as u64 >= contract.max_response_bytes
                    || response.len() as u64
                        >= contract.max_stream_bytes
                {
                    return Err(ControllerError::Rejected(
                        "Docker direct response exceeded its signed bound",
                    ));
                }
                let remaining = contract
                    .max_response_bytes
                    .min(contract.max_stream_bytes)
                    .saturating_sub(response.len() as u64)
                    .min(RELAY_CHUNK_BYTES_V11 as u64)
                    as usize;
                let mut buffer = vec![0u8; remaining.max(1)];
                let count = read_deadline_cancelled(
                    &mut reader,
                    &mut buffer,
                    deadline,
                    &cancelled,
                )?;
                if count == 0 {
                    peer_closed = true;
                    break;
                }
                response.extend_from_slice(&buffer[..count]);
                received.store(
                    response.len() as u64,
                    Ordering::Release,
                );
                complete = direct_http_response_complete_v12(
                    &response,
                    contract.stream_mode,
                )?
                .is_some();
            }
            Ok((response, peer_closed))
        })();
        if response_result.is_err() {
            cancelled.store(true, Ordering::Release);
            let _ = daemon.shutdown(std::net::Shutdown::Both);
        }
        let upload_result = upload.join().map_err(|_| {
            ControllerError::Rejected(
                "Docker direct upload worker panicked",
            )
        })?;
        let (response, peer_closed) = response_result?;
        upload_result?;
        let (status_code, message_bytes) =
            direct_http_response_complete_v12(
                &response,
                contract.stream_mode,
            )?
            .or_else(|| {
                peer_closed.then(|| {
                    header_end(&response)
                        .and_then(|end| {
                            parse_response_status(&response[..end]).ok()
                                .map(|status| (status, response.len()))
                        })
                })
                .flatten()
            })
            .ok_or(ControllerError::Rejected(
                "Docker direct response ended with incomplete framing",
            ))?;
        if message_bytes != response.len() {
            return Err(ControllerError::Rejected(
                "Docker direct response contains surplus bytes",
            ));
        }
        let upgraded = status_code == 101;
        if upgraded
            != matches!(
                contract.stream_mode,
                DockerStreamModeV11::Upgrade101
                    | DockerStreamModeV11::FullDuplex
            )
            && (upgraded
                || contract.stream_mode
                    == DockerStreamModeV11::Upgrade101)
        {
            return Err(ControllerError::Rejected(
                "Docker direct response upgrade differs from contract",
            ));
        }
        let completed_boottime_ns = boottime_now_ns_v11()?;
        if completed_boottime_ns >= deadline {
            return Err(ControllerError::Rejected(
                "Docker direct response completed after its deadline",
            ));
        }
        Ok(DockerDirectHttpReceiptV12 {
            status_code,
            upgraded,
            request_bytes,
            request_sha256,
            response_bytes: response.len() as u64,
            response_sha256: sha256(&response),
            response,
            completed_boottime_ns,
        })
    })();
    match result {
        Ok(receipt) => DockerDirectHttpOutcomeV12::Complete(receipt),
        Err(error) => {
            let sent = sent.load(Ordering::Acquire);
            let received = received.load(Ordering::Acquire);
            if sent == 0 {
                DockerDirectHttpOutcomeV12::RejectedBeforeSend(error)
            } else {
                DockerDirectHttpOutcomeV12::PostSendUncertain {
                    request_bytes_sent: sent,
                    response_bytes_received: received,
                    error,
                }
            }
        }
    }
}

fn direct_http_response_complete_v12(
    bytes: &[u8],
    stream_mode: DockerStreamModeV11,
) -> Result<Option<(u16, usize)>> {
    let Some(end) = header_end(bytes) else {
        if bytes.len() >= HTTP_HEAD_MAX_BYTES_V11 {
            return Err(ControllerError::Rejected(
                "Docker direct response header exceeds its bound",
            ));
        }
        return Ok(None);
    };
    let status = parse_response_status(&bytes[..end])?;
    if status == 101 {
        if !matches!(
            stream_mode,
            DockerStreamModeV11::Upgrade101
                | DockerStreamModeV11::FullDuplex
        ) {
            return Err(ControllerError::Rejected(
                "Docker direct response upgraded outside stream authority",
            ));
        }
        return Ok(None);
    }
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| {
        ControllerError::Rejected(
            "Docker direct response header is not UTF-8",
        )
    })?;
    let mut content_length = None;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").ok_or(
            ControllerError::Rejected(
                "Docker direct response header is noncanonical",
            ),
        )?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(ControllerError::Rejected(
                        "Docker direct response duplicates Content-Length",
                    ));
                }
                content_length = Some(value.parse::<usize>().map_err(|_| {
                    ControllerError::Rejected(
                        "Docker direct response Content-Length is invalid",
                    )
                })?);
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(ControllerError::Rejected(
                        "Docker direct response transfer encoding is unsupported",
                    ));
                }
                chunked = true;
            }
            _ => {}
        }
    }
    if content_length.is_some() && chunked {
        return Err(ControllerError::Rejected(
            "Docker direct response has conflicting framing",
        ));
    }
    let body_start = end;
    if let Some(length) = content_length {
        let total = body_start.checked_add(length).ok_or(
            ControllerError::Invalid(
                "Docker direct response length overflowed",
            ),
        )?;
        return Ok((bytes.len() >= total).then_some((status, total)));
    }
    if chunked {
        return Ok(
            complete_chunked_message_v12(&bytes[body_start..])?
                .map(|length| (status, body_start + length)),
        );
    }
    if matches!(status, 204 | 304) {
        return Ok(Some((status, body_start)));
    }
    Ok(None)
}

fn complete_chunked_message_v12(body: &[u8]) -> Result<Option<usize>> {
    let mut offset = 0usize;
    loop {
        let Some(line_end) = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|position| offset + position)
        else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&body[offset..line_end]).map_err(
            |_| {
                ControllerError::Rejected(
                    "Docker direct chunk size is not UTF-8",
                )
            },
        )?;
        if line.is_empty() || line.contains(';') || line.len() > 16 {
            return Err(ControllerError::Rejected(
                "Docker direct chunk size is noncanonical",
            ));
        }
        let size = usize::from_str_radix(line, 16).map_err(|_| {
            ControllerError::Rejected(
                "Docker direct chunk size is invalid",
            )
        })?;
        offset = line_end + 2;
        if size == 0 {
            if body.len() < offset + 2 {
                return Ok(None);
            }
            if &body[offset..offset + 2] != b"\r\n" {
                return Err(ControllerError::Rejected(
                    "Docker direct chunked response contains trailers",
                ));
            }
            return Ok(Some(offset + 2));
        }
        let terminal = offset
            .checked_add(size)
            .and_then(|value| value.checked_add(2))
            .ok_or(ControllerError::Invalid(
                "Docker direct chunk length overflowed",
            ))?;
        if body.len() < terminal {
            return Ok(None);
        }
        if &body[terminal - 2..terminal] != b"\r\n" {
            return Err(ControllerError::Rejected(
                "Docker direct chunk body lacks CRLF",
            ));
        }
        offset = terminal;
    }
}

pub fn docker_http_response_body_v12(
    exact_response: &[u8],
) -> Result<(u16, Vec<u8>)> {
    let end = header_end(exact_response).ok_or(
        ControllerError::Rejected(
            "Docker direct response lacks a complete header",
        ),
    )?;
    let status = parse_response_status(&exact_response[..end])?;
    let head = std::str::from_utf8(&exact_response[..end]).map_err(|_| {
        ControllerError::Rejected(
            "Docker direct response header is not UTF-8",
        )
    })?;
    let mut chunked = false;
    let mut content_length = None;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").ok_or(
            ControllerError::Rejected(
                "Docker direct response header is noncanonical",
            ),
        )?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = Some(value.parse::<usize>().map_err(
                    |_| {
                        ControllerError::Rejected(
                            "Docker direct Content-Length is invalid",
                        )
                    },
                )?);
            }
            "transfer-encoding"
                if value.eq_ignore_ascii_case("chunked") =>
            {
                chunked = true;
            }
            _ => {}
        }
    }
    let body = &exact_response[end..];
    if let Some(length) = content_length {
        if body.len() != length {
            return Err(ControllerError::Rejected(
                "Docker direct response body differs from Content-Length",
            ));
        }
        return Ok((status, body.to_vec()));
    }
    if chunked {
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        loop {
            let line_end = body[offset..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|position| offset + position)
                .ok_or(ControllerError::Rejected(
                    "Docker direct chunk size line is incomplete",
                ))?;
            let size = usize::from_str_radix(
                std::str::from_utf8(&body[offset..line_end]).map_err(
                    |_| {
                        ControllerError::Rejected(
                            "Docker direct chunk size is not UTF-8",
                        )
                    },
                )?,
                16,
            )
            .map_err(|_| {
                ControllerError::Rejected(
                    "Docker direct chunk size is invalid",
                )
            })?;
            offset = line_end + 2;
            if size == 0 {
                if body.get(offset..offset + 2) != Some(b"\r\n") {
                    return Err(ControllerError::Rejected(
                        "Docker direct chunked terminal is invalid",
                    ));
                }
                offset += 2;
                if offset != body.len() {
                    return Err(ControllerError::Rejected(
                        "Docker direct chunked response has surplus bytes",
                    ));
                }
                return Ok((status, decoded));
            }
            let end = offset.checked_add(size).ok_or(
                ControllerError::Invalid(
                    "Docker direct decoded chunk length overflowed",
                ),
            )?;
            if body.get(end..end + 2) != Some(b"\r\n") {
                return Err(ControllerError::Rejected(
                    "Docker direct chunk body is incomplete",
                ));
            }
            decoded.extend_from_slice(&body[offset..end]);
            offset = end + 2;
        }
    }
    Ok((status, body.to_vec()))
}

pub fn validate_docker_json_message_sequence_v12(
    exact_response: &[u8],
    allowed_statuses: &[u16],
    maximum_messages: u64,
    maximum_message_bytes: u64,
) -> Result<DockerJsonMessageSequenceReceiptV12> {
    if allowed_statuses.is_empty()
        || maximum_messages == 0
        || maximum_message_bytes == 0
    {
        return Err(ControllerError::Rejected(
            "Docker JSON message sequence has invalid bounds",
        ));
    }
    let (status_code, body) =
        docker_http_response_body_v12(exact_response)?;
    if !allowed_statuses.contains(&status_code) {
        return Err(ControllerError::InvalidOwned(format!(
            "Docker JSON message sequence returned unexpected status {status_code}: {}",
            String::from_utf8_lossy(&body),
        )));
    }
    if body.is_empty() {
        return Err(ControllerError::Rejected(
            "Docker JSON message sequence is empty",
        ));
    }
    let mut stream =
        serde_json::Deserializer::from_slice(&body).into_iter::<Value>();
    let mut prior_offset = 0usize;
    let mut message_count = 0u64;
    while let Some(message) = stream.next() {
        let message = message.map_err(|_| {
            ControllerError::Rejected(
                "Docker JSON message sequence contains invalid JSON",
            )
        })?;
        let next_offset = stream.byte_offset();
        let message_bytes =
            next_offset.saturating_sub(prior_offset) as u64;
        if message_bytes == 0 || message_bytes > maximum_message_bytes {
            return Err(ControllerError::Rejected(
                "Docker JSON message exceeds its exact bound",
            ));
        }
        message_count = message_count.checked_add(1).ok_or(
            ControllerError::Invalid(
                "Docker JSON message count overflowed",
            ),
        )?;
        if message_count > maximum_messages {
            return Err(ControllerError::Rejected(
                "Docker JSON message count exceeds its exact bound",
            ));
        }
        reject_docker_terminal_error_v12(&message)?;
        prior_offset = next_offset;
    }
    if message_count == 0 {
        return Err(ControllerError::Rejected(
            "Docker JSON message sequence has no messages",
        ));
    }
    Ok(DockerJsonMessageSequenceReceiptV12 {
        status_code,
        message_count,
        body_bytes: body.len() as u64,
        body_sha256: sha256(&body),
    })
}

fn reject_docker_terminal_error_v12(message: &Value) -> Result<()> {
    let object = message.as_object().ok_or(
        ControllerError::Rejected(
            "Docker JSON message is not an object",
        ),
    )?;
    let direct_error = object
        .get("error")
        .filter(|value| !value.is_null())
        .map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        });
    let detailed_error = object
        .get("errorDetail")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        });
    if let Some(error) = direct_error.or(detailed_error) {
        return Err(ControllerError::InvalidOwned(format!(
            "Docker JSON message sequence reported a terminal error: {error}",
        )));
    }
    Ok(())
}

struct ResponseSpoolCleanupV11 {
    path: PathBuf,
    armed: bool,
}

impl Drop for ResponseSpoolCleanupV11 {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub fn read_proxy_envelope_v11<T, F>(
    client: &mut UnixStream,
    spool_root: &Path,
    absolute_deadline_boottime_ns: u64,
    maximum_body_bytes: u64,
    verify_preamble: F,
) -> Result<(DockerProxyEnvelopeV11, T)>
where
    F: FnOnce(
        &DockerProxyEnvelopeHeaderV11,
        &[u8],
        &[u8],
        &CanonicalDockerHttpHeadV11,
    ) -> Result<(T, u64)>,
{
    require_private_spool_root(spool_root)?;
    client.set_nonblocking(true)?;
    let mut fixed = [0u8; PROXY_ENVELOPE_HEADER_BYTES_V11];
    read_exact_deadline(
        client,
        &mut fixed,
        absolute_deadline_boottime_ns,
    )?;
    let header = decode_header(&fixed)?;
    if header.capability_bytes as usize > CONTRACT_MAX_BYTES_V11
        || header.request_bytes as usize > CONTRACT_MAX_BYTES_V11
        || header.http_head_bytes as usize > HTTP_HEAD_MAX_BYTES_V11
        || header.body_bytes > maximum_body_bytes
        || header.body_bytes == 0 && header.body_sha256 != sha256(&[])
    {
        return Err(ControllerError::Rejected(
            "Docker proxy envelope exceeds its fixed bounds",
        ));
    }
    let mut capability = vec![0u8; header.capability_bytes as usize];
    let mut request = vec![0u8; header.request_bytes as usize];
    let mut http_head = vec![0u8; header.http_head_bytes as usize];
    read_exact_deadline(
        client,
        &mut capability,
        absolute_deadline_boottime_ns,
    )?;
    read_exact_deadline(
        client,
        &mut request,
        absolute_deadline_boottime_ns,
    )?;
    read_exact_deadline(
        client,
        &mut http_head,
        absolute_deadline_boottime_ns,
    )?;
    let http = parse_http_head_v11(
        &http_head,
        header.body_bytes,
        header.stream_mode,
    )?;
    let (verified, body_deadline) =
        verify_preamble(&header, &capability, &request, &http)?;
    if body_deadline > absolute_deadline_boottime_ns
        || body_deadline <= boottime_now_ns_v11()?
    {
        return Err(ControllerError::Rejected(
            "Docker signed body deadline exceeds the active lane",
        ));
    }
    let body = spool_exact(
        client,
        spool_root,
        "request",
        header.body_bytes,
        header.body_sha256,
        body_deadline,
    )?;
    Ok((
        DockerProxyEnvelopeV11 {
            header,
            capability,
            request,
            http,
            body,
        },
        verified,
    ))
}

pub fn relay_authorized_exchange_v11(
    client: &mut UnixStream,
    daemon: &mut UnixStream,
    envelope: &DockerProxyEnvelopeV11,
    response_spool_root: &Path,
    bounds: &DockerBoundsV11,
    absolute_deadline_boottime_ns: u64,
    release_response_during_relay: bool,
) -> Result<DockerTransportReceiptV11> {
    match relay_authorized_exchange_outcome_v12(
        client,
        daemon,
        envelope,
        response_spool_root,
        bounds,
        absolute_deadline_boottime_ns,
        release_response_during_relay,
    ) {
        DockerTransportOutcomeV12::Complete(receipt) => Ok(receipt),
        DockerTransportOutcomeV12::RejectedBeforeUpstream { error } => {
            Err(error)
        }
        DockerTransportOutcomeV12::PostSendUncertain {
            uncertainty,
            error,
        } => Err(ControllerError::InvalidOwned(format!(
            "POST_SEND_UNCERTAIN upstreamBytes={} responseBytes={} framingValidated={}: {error}",
            uncertainty.upstream_bytes_sent,
            uncertainty.response_bytes_received,
            uncertainty.response_framing_validated,
        ))),
        DockerTransportOutcomeV12::DownstreamReleaseFailed {
            receipt,
            error,
        } => {
            let _ = std::fs::remove_file(&receipt.response_path);
            Err(ControllerError::InvalidOwned(format!(
                "DOWNSTREAM_RELEASE_FAILED validatedResponseSha256={} responseBytes={}: {error}",
                hex_digest_v12(&receipt.response_sha256),
                receipt.response_bytes,
            )))
        }
    }
}

pub fn relay_authorized_exchange_outcome_v12(
    client: &mut UnixStream,
    daemon: &mut UnixStream,
    envelope: &DockerProxyEnvelopeV11,
    response_spool_root: &Path,
    bounds: &DockerBoundsV11,
    absolute_deadline_boottime_ns: u64,
    release_validated_response: bool,
) -> DockerTransportOutcomeV12 {
    let upstream_bytes_sent = Arc::new(AtomicU64::new(0));
    let response_bytes_received = Arc::new(AtomicU64::new(0));
    let response_framing_validated = Arc::new(AtomicBool::new(false));
    let downstream_release_started = Arc::new(AtomicBool::new(false));
    let validated_receipt = Arc::new(Mutex::new(None));
    let result = relay_authorized_exchange_inner_v12(
        client,
        daemon,
        envelope,
        response_spool_root,
        bounds,
        absolute_deadline_boottime_ns,
        release_validated_response,
        Arc::clone(&upstream_bytes_sent),
        Arc::clone(&response_bytes_received),
        Arc::clone(&response_framing_validated),
        Arc::clone(&downstream_release_started),
        Arc::clone(&validated_receipt),
    );
    match result {
        Ok(receipt) => DockerTransportOutcomeV12::Complete(receipt),
        Err(error) => {
            if downstream_release_started.load(Ordering::Acquire)
                && response_framing_validated.load(Ordering::Acquire)
            {
                if let Ok(guard) = validated_receipt.lock() {
                    if let Some(receipt) = guard.as_ref() {
                        return DockerTransportOutcomeV12::DownstreamReleaseFailed {
                            receipt: receipt.clone(),
                            error,
                        };
                    }
                }
            }
            if upstream_bytes_sent.load(Ordering::Acquire) != 0 {
                DockerTransportOutcomeV12::PostSendUncertain {
                    uncertainty: DockerPostSendUncertaintyV12 {
                        upstream_bytes_sent: upstream_bytes_sent
                            .load(Ordering::Acquire),
                        response_bytes_received: response_bytes_received
                            .load(Ordering::Acquire),
                        response_framing_validated:
                            response_framing_validated
                                .load(Ordering::Acquire),
                        deadline_boottime_ns:
                            absolute_deadline_boottime_ns,
                    },
                    error,
                }
            } else {
                DockerTransportOutcomeV12::RejectedBeforeUpstream {
                    error,
                }
            }
        }
    }
}

fn relay_authorized_exchange_inner_v12(
    client: &mut UnixStream,
    daemon: &mut UnixStream,
    envelope: &DockerProxyEnvelopeV11,
    response_spool_root: &Path,
    bounds: &DockerBoundsV11,
    absolute_deadline_boottime_ns: u64,
    release_validated_response: bool,
    upstream_bytes_sent: Arc<AtomicU64>,
    response_bytes_received: Arc<AtomicU64>,
    response_framing_validated: Arc<AtomicBool>,
    downstream_release_started: Arc<AtomicBool>,
    validated_receipt: Arc<Mutex<Option<DockerTransportReceiptV11>>>,
) -> Result<DockerTransportReceiptV11> {
    bounds.validate()?;
    if envelope.body.length() > bounds.max_request_bytes
        || envelope.header.stream_mode == DockerStreamModeV11::Upgrade101
            && envelope.body.length() != 0
        || matches!(
            envelope.header.stream_mode,
            DockerStreamModeV11::FullDuplex
                | DockerStreamModeV11::Upgrade101
        ) && envelope
            .http
            .canonical_query
            .iter()
            .any(|(name, value)| name == "stdin" && value != "0")
    {
        return Err(ControllerError::Rejected(
            "Docker transport exceeds its bounds or requests unvalidated interactive input",
        ));
    }
    require_private_spool_root(response_spool_root)?;
    client.set_nonblocking(true)?;
    daemon.set_nonblocking(true)?;
    let mut daemon_writer = daemon.try_clone()?;
    let mut daemon_reader = daemon.try_clone()?;
    let mut client_writer = client.try_clone()?;
    let mut body = envelope.body.file()?;
    let head = envelope.http.daemon_head.clone();
    let mode = envelope.header.stream_mode;
    let request_bound = bounds.max_request_bytes;
    let deadline = absolute_deadline_boottime_ns;
    let cancelled = Arc::new(AtomicBool::new(false));
    let upload_cancelled = Arc::clone(&cancelled);
    let upload_bytes_sent = Arc::clone(&upstream_bytes_sent);
    let upload_daemon_cancel = daemon.try_clone()?;
    let upload_client_cancel = client.try_clone()?;
    let upload = std::thread::Builder::new()
        .name("serverware-docker-upload-v12".to_owned())
        .spawn(move || -> Result<u64> {
            let result = (|| -> Result<u64> {
                write_all_deadline_counted(
                    &mut daemon_writer,
                    &head,
                    deadline,
                    &upload_cancelled,
                    &upload_bytes_sent,
                )?;
                let mut transferred = head.len() as u64;
                let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
                loop {
                    if upload_cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    let count = body.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    transferred = transferred
                        .checked_add(count as u64)
                        .ok_or(ControllerError::Invalid(
                            "Docker request byte count overflowed",
                        ))?;
                    if transferred > request_bound {
                        return Err(ControllerError::Rejected(
                            "Docker request exceeded its signed byte bound",
                        ));
                    }
                    write_all_deadline_counted(
                        &mut daemon_writer,
                        &buffer[..count],
                        deadline,
                        &upload_cancelled,
                        &upload_bytes_sent,
                    )?;
                }
                daemon_writer.shutdown(std::net::Shutdown::Write)?;
                Ok(transferred)
            })();
            if result.is_err() {
                upload_cancelled.store(true, Ordering::Release);
                let _ =
                    upload_daemon_cancel.shutdown(std::net::Shutdown::Both);
                let _ =
                    upload_client_cancel.shutdown(std::net::Shutdown::Read);
            }
            result
        })
        .map_err(ControllerError::Io)?;

    let response_path = unique_spool_path(response_spool_root, "response");
    let mut response_cleanup = ResponseSpoolCleanupV11 {
        path: response_path.clone(),
        armed: true,
    };
    let mut response_file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&response_path)?;
    let download = (|| -> Result<(u16, u64, Digest)> {
        let mut response_hasher = Sha256::new();
        let mut response_bytes = 0u64;
        let mut response_head = Vec::new();
        let mut parsed_status = None;
        let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
        loop {
            let count = read_deadline_cancelled(
                &mut daemon_reader,
                &mut buffer,
                deadline,
                &cancelled,
            )?;
            if count == 0 {
                break;
            }
            response_bytes = response_bytes
                .checked_add(count as u64)
                .ok_or(ControllerError::Invalid(
                    "Docker response byte count overflowed",
                ))?;
            if response_bytes > bounds.max_response_bytes
                || response_bytes > bounds.max_stream_bytes
            {
                return Err(ControllerError::Rejected(
                    "Docker response exceeded its signed byte bound",
                ));
            }
            if parsed_status.is_none() {
                let remaining =
                    HTTP_HEAD_MAX_BYTES_V11.saturating_sub(response_head.len());
                response_head
                    .extend_from_slice(&buffer[..count.min(remaining)]);
                if let Some(end) = header_end(&response_head) {
                    parsed_status =
                        Some(parse_response_status(&response_head[..end])?);
                } else if response_head.len() >= HTTP_HEAD_MAX_BYTES_V11 {
                    return Err(ControllerError::Rejected(
                        "Docker response header exceeded its bound",
                    ));
                }
            }
            response_file.write_all(&buffer[..count])?;
            response_hasher.update(&buffer[..count]);
            response_bytes_received
                .store(response_bytes, Ordering::Release);
        }
        let status = parsed_status.ok_or(ControllerError::Rejected(
            "Docker daemon closed without a complete response header",
        ))?;
        let digest = response_hasher.finalize();
        let mut response_sha256 = [0u8; 32];
        response_sha256.copy_from_slice(&digest);
        Ok((status, response_bytes, response_sha256))
    })();
    if download.is_err() {
        cancelled.store(true, Ordering::Release);
        let _ = daemon.shutdown(std::net::Shutdown::Both);
        let _ = client.shutdown(std::net::Shutdown::Read);
    } else if matches!(
        mode,
        DockerStreamModeV11::FullDuplex | DockerStreamModeV11::Upgrade101
    ) {
        cancelled.store(true, Ordering::Release);
        let _ = client.shutdown(std::net::Shutdown::Read);
        let _ = daemon.shutdown(std::net::Shutdown::Write);
    }
    let upload_result = upload
        .join()
        .map_err(|_| {
            ControllerError::Rejected("Docker upload worker panicked")
        })?;
    let (status_code, response_bytes, response_sha256) = download?;
    let upload_bytes = upload_result?;
    let upgraded = status_code == 101;
    if upgraded
        != matches!(
            envelope.header.stream_mode,
            DockerStreamModeV11::Upgrade101
                | DockerStreamModeV11::FullDuplex
        )
        && (upgraded
            || envelope.header.stream_mode
                == DockerStreamModeV11::Upgrade101)
    {
        return Err(ControllerError::Rejected(
            "Docker response upgrade status differs from signed stream mode",
        ));
    }
    response_file.sync_all()?;
    File::open(response_spool_root)?.sync_all()?;
    let validated_status = validate_response_spool_v11(
        &mut response_file,
        response_bytes,
        envelope.header.stream_mode,
    )?;
    if validated_status != status_code {
        return Err(ControllerError::Rejected(
            "Docker response status changed during framing validation",
        ));
    }
    response_file.seek(SeekFrom::Start(0))?;
    let validated_sha256 = crate::coder_controller_v11::sha256_exact_reader(
        &mut response_file,
        response_bytes,
    )?;
    if !constant_time_eq(&validated_sha256, &response_sha256) {
        return Err(ControllerError::Rejected(
            "Docker response digest changed before complete validation",
        ));
    }
    let completed_boottime_ns = boottime_now_ns_v11()?;
    if completed_boottime_ns >= deadline {
        return Err(ControllerError::Rejected(
            "Docker response validation exceeded its absolute deadline",
        ));
    }
    response_framing_validated.store(true, Ordering::Release);
    response_cleanup.armed = false;
    let receipt = DockerTransportReceiptV11 {
        status_code,
        upgraded,
        request_bytes: upload_bytes,
        upstream_bytes_sent: upstream_bytes_sent.load(Ordering::Acquire),
        upstream_disposition:
            DockerUpstreamDispositionV12::CompleteResponseValidated,
        response_bytes,
        response_sha256,
        response_path,
        completed_boottime_ns,
    };
    *validated_receipt.lock().map_err(|_| {
        ControllerError::Rejected(
            "Docker validated response receipt mutex is poisoned",
        )
    })? = Some(receipt.clone());
    if release_validated_response {
        downstream_release_started.store(true, Ordering::Release);
        release_spooled_response_v11(
            &mut client_writer,
            &receipt.response_path,
            receipt.response_bytes,
            receipt.response_sha256,
            deadline,
        )?;
        client_writer.shutdown(std::net::Shutdown::Write)?;
    }
    Ok(receipt)
}

pub fn release_spooled_response_v11(
    client: &mut UnixStream,
    path: &Path,
    expected_bytes: u64,
    expected_sha256: Digest,
    absolute_deadline_boottime_ns: u64,
) -> Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || metadata.len() != expected_bytes
    {
        return Err(ControllerError::Rejected(
            "Docker replay spool storage is unsafe",
        ));
    }
    let preflight_sha256 =
        crate::coder_controller_v11::sha256_exact_reader(
            &mut file,
            expected_bytes,
        )?;
    if !constant_time_eq(&preflight_sha256, &expected_sha256) {
        return Err(ControllerError::Rejected(
            "Docker replay spool differs before downstream release",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut remaining = expected_bytes;
    let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..wanted])?;
        if count == 0 {
            return Err(ControllerError::Rejected(
                "Docker replay spool is truncated",
            ));
        }
        hasher.update(&buffer[..count]);
        write_all_deadline(
            client,
            &buffer[..count],
            absolute_deadline_boottime_ns,
        )?;
        remaining -= count as u64;
    }
    let digest = hasher.finalize();
    let mut actual = [0u8; 32];
    actual.copy_from_slice(&digest);
    if !constant_time_eq(&actual, &expected_sha256) {
        return Err(ControllerError::Rejected(
            "Docker replay spool digest differs",
        ));
    }
    client.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

pub fn canonical_route_and_query_v11(
    raw_target: &str,
) -> Result<(String, Vec<(String, String)>)> {
    if raw_target.is_empty()
        || raw_target.len() > 16 * 1024
        || !raw_target.starts_with('/')
        || raw_target.contains('#')
    {
        return Err(ControllerError::Rejected(
            "Docker HTTP target is noncanonical",
        ));
    }
    let (path, query) =
        raw_target.split_once('?').unwrap_or((raw_target, ""));
    if path.contains('%') || path.contains("//") || path.contains("..") {
        return Err(ControllerError::Rejected(
            "Docker HTTP path contains encoded or ambiguous components",
        ));
    }
    let normalized = strip_version(path)?;
    let mut pairs = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(
                ControllerError::Rejected(
                    "Docker query pair lacks an equals sign",
                ),
            )?;
            let name = percent_decode_canonical(name)?;
            let value = percent_decode_canonical(value)?;
            if name.is_empty()
                || name.len() > 64
                || value.len() > 2048
            {
                return Err(ControllerError::Rejected(
                    "Docker query pair exceeds its canonical bound",
                ));
            }
            pairs.push((name, value));
        }
        if pairs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ControllerError::Rejected(
                "Docker query is not strictly sorted and unique",
            ));
        }
    }
    Ok((normalized.to_owned(), pairs))
}

fn decode_header(
    bytes: &[u8; PROXY_ENVELOPE_HEADER_BYTES_V11],
) -> Result<DockerProxyEnvelopeHeaderV11> {
    if bytes[0..8] != PROXY_ENVELOPE_MAGIC_V11
        || u16::from_be_bytes([bytes[8], bytes[9]]) != 11
        || bytes[11] != 0
    {
        return Err(ControllerError::Rejected(
            "Docker proxy envelope header is invalid",
        ));
    }
    let stream_mode = match bytes[10] {
        1 => DockerStreamModeV11::BoundedHttp,
        2 => DockerStreamModeV11::FullDuplex,
        3 => DockerStreamModeV11::Upgrade101,
        4 => DockerStreamModeV11::BuildKit,
        _ => {
            return Err(ControllerError::Rejected(
                "Docker proxy stream mode is invalid",
            ))
        }
    };
    Ok(DockerProxyEnvelopeHeaderV11 {
        stream_mode,
        capability_bytes: u32::from_be_bytes(
            bytes[12..16].try_into().map_err(|_| {
                ControllerError::Invalid(
                    "Docker capability length is invalid",
                )
            })?,
        ),
        request_bytes: u32::from_be_bytes(
            bytes[16..20].try_into().map_err(|_| {
                ControllerError::Invalid(
                    "Docker request length is invalid",
                )
            })?,
        ),
        http_head_bytes: u32::from_be_bytes(
            bytes[20..24].try_into().map_err(|_| {
                ControllerError::Invalid(
                    "Docker HTTP head length is invalid",
                )
            })?,
        ),
        body_bytes: u64::from_be_bytes(
            bytes[24..32].try_into().map_err(|_| {
                ControllerError::Invalid(
                    "Docker body length is invalid",
                )
            })?,
        ),
        body_sha256: bytes[32..64].try_into().map_err(|_| {
            ControllerError::Invalid(
                "Docker body digest is invalid",
            )
        })?,
    })
}

fn parse_http_head_v11(
    bytes: &[u8],
    body_bytes: u64,
    stream_mode: DockerStreamModeV11,
) -> Result<CanonicalDockerHttpHeadV11> {
    if bytes.len() < 16
        || bytes.len() > HTTP_HEAD_MAX_BYTES_V11
        || header_end(bytes) != Some(bytes.len() - 4)
    {
        return Err(ControllerError::Rejected(
            "Docker HTTP request head is incomplete or oversized",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        ControllerError::Invalid("Docker HTTP head is not UTF-8")
    })?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(ControllerError::Invalid(
        "Docker HTTP request line is absent",
    ))?;
    let mut fields = request_line.split(' ');
    let method = fields.next().unwrap_or("");
    let target = fields.next().unwrap_or("");
    let version = fields.next().unwrap_or("");
    if fields.next().is_some()
        || !matches!(method, "GET" | "HEAD" | "POST" | "DELETE")
        || version != "HTTP/1.1"
    {
        return Err(ControllerError::Rejected(
            "Docker HTTP request line is outside the v11 contract",
        ));
    }
    let mut host = false;
    let mut content_length = None;
    let mut connection = None;
    let mut upgrade = None;
    let mut forwarded = Vec::<(String, String)>::new();
    for line in lines {
        let (name, raw_value) = line.split_once(':').ok_or(
            ControllerError::Rejected(
                "Docker HTTP header lacks a colon",
            ),
        )?;
        let value = raw_value.strip_prefix(' ').ok_or(
            ControllerError::Rejected(
                "Docker HTTP header lacks one canonical space",
            ),
        )?;
        if name.trim() != name
            || name.is_empty()
            || value.trim() != value
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-'
            })
            || value.bytes().any(|byte| {
                byte == 0 || byte == b'\r' || byte == b'\n'
            })
        {
            return Err(ControllerError::Rejected(
                "Docker HTTP header is noncanonical",
            ));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "authorization"
                | "x-registry-auth"
                | "x-registry-config"
                | "proxy-authorization"
                | "transfer-encoding"
                | "trailer"
        ) {
            return Err(ControllerError::Rejected(
                "Docker HTTP header is not permitted at the authority boundary",
            ));
        }
        match lower.as_str() {
            "host" => {
                if host || value != "docker" {
                    return Err(ControllerError::Rejected(
                        "Docker Host header is duplicate or invalid",
                    ));
                }
                host = true;
            }
            "content-length" => {
                if content_length
                    .replace(value.parse::<u64>().map_err(|_| {
                        ControllerError::Invalid(
                            "Docker Content-Length is invalid",
                        )
                    })?)
                    .is_some()
                {
                    return Err(ControllerError::Rejected(
                        "Docker Content-Length is duplicated",
                    ));
                }
            }
            "connection" => {
                if connection.replace(value.to_owned()).is_some() {
                    return Err(ControllerError::Rejected(
                        "Docker Connection header is duplicated",
                    ));
                }
            }
            "upgrade" => {
                if upgrade.replace(value.to_owned()).is_some() {
                    return Err(ControllerError::Rejected(
                        "Docker Upgrade header is duplicated",
                    ));
                }
            }
            "content-type" | "user-agent" | "accept" => {
                forwarded.push((name.to_owned(), value.to_owned()));
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker HTTP header is not exactly allowlisted",
                ))
            }
        }
    }
    let upgrade_expected =
        stream_mode == DockerStreamModeV11::Upgrade101;
    if !host
        || content_length.unwrap_or(0) != body_bytes
        || upgrade_expected
            != (connection.as_deref() == Some("Upgrade")
                && upgrade.as_deref() == Some("tcp"))
        || (!upgrade_expected
            && (connection.as_deref().is_some_and(|value| {
                value != "close"
            }) || upgrade.is_some()))
    {
        return Err(ControllerError::Rejected(
            "Docker HTTP framing differs from the authority envelope",
        ));
    }
    let (normalized_route, canonical_query) =
        canonical_route_and_query_v11(target)?;
    let mut daemon_head = Vec::new();
    daemon_head.extend_from_slice(
        format!("{method} {target} HTTP/1.1\r\n").as_bytes(),
    );
    daemon_head.extend_from_slice(b"Host: docker\r\n");
    daemon_head.extend_from_slice(
        format!("Content-Length: {body_bytes}\r\n").as_bytes(),
    );
    for (name, value) in forwarded {
        daemon_head.extend_from_slice(
            format!("{name}: {value}\r\n").as_bytes(),
        );
    }
    if upgrade_expected {
        daemon_head.extend_from_slice(
            b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
        );
    } else {
        daemon_head.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    Ok(CanonicalDockerHttpHeadV11 {
        method: method.to_owned(),
        raw_target: target.to_owned(),
        normalized_route,
        canonical_query,
        daemon_head,
    })
}

fn spool_exact(
    source: &mut UnixStream,
    root: &Path,
    label: &str,
    length: u64,
    expected_sha256: Digest,
    deadline: u64,
) -> Result<DurableSpoolV11> {
    let path = unique_spool_path(root, label);
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; RELAY_CHUNK_BYTES_V11];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count =
            read_deadline(source, &mut buffer[..wanted], deadline)?;
        if count == 0 {
            return Err(ControllerError::Rejected(
                "Docker authority body ended before its declared length",
            ));
        }
        file.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let actual_sha256 = {
        let digest = hasher.finalize();
        let mut value = [0u8; 32];
        value.copy_from_slice(&digest);
        value
    };
    if !constant_time_eq(&actual_sha256, &expected_sha256) {
        return Err(ControllerError::Rejected(
            "Docker authority body differs from its declared digest",
        ));
    }
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(DurableSpoolV11 {
        path,
        file,
        length,
        sha256: actual_sha256,
    })
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    mut output: &mut [u8],
    deadline: u64,
) -> Result<()> {
    while !output.is_empty() {
        let count = read_deadline(stream, output, deadline)?;
        if count == 0 {
            return Err(ControllerError::Rejected(
                "Docker authority stream closed before an exact frame",
            ));
        }
        output = &mut output[count..];
    }
    Ok(())
}

fn read_deadline(
    stream: &mut UnixStream,
    output: &mut [u8],
    deadline: u64,
) -> Result<usize> {
    loop {
        poll_deadline(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        match stream.read(output) {
            Ok(count) => return Ok(count),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_deadline_cancelled(
    stream: &mut UnixStream,
    output: &mut [u8],
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<usize> {
    loop {
        poll_deadline_cancelled(
            stream.as_raw_fd(),
            libc::POLLIN,
            deadline,
            cancelled,
        )?;
        match stream.read(output) {
            Ok(count) => return Ok(count),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn write_all_deadline(
    stream: &mut UnixStream,
    mut input: &[u8],
    deadline: u64,
) -> Result<()> {
    while !input.is_empty() {
        poll_deadline(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(input) {
            Ok(0) => {
                return Err(ControllerError::Rejected(
                    "Docker authority stream closed during write",
                ))
            }
            Ok(count) => input = &input[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_deadline_counted(
    stream: &mut UnixStream,
    mut input: &[u8],
    deadline: u64,
    cancelled: &AtomicBool,
    bytes_sent: &AtomicU64,
) -> Result<()> {
    while !input.is_empty() {
        poll_deadline_cancelled(
            stream.as_raw_fd(),
            libc::POLLOUT,
            deadline,
            cancelled,
        )?;
        match stream.write(input) {
            Ok(0) => {
                return Err(ControllerError::Rejected(
                    "Docker upstream closed during write",
                ))
            }
            Ok(count) => {
                bytes_sent.fetch_add(count as u64, Ordering::AcqRel);
                input = &input[count..];
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn poll_deadline(fd: i32, events: i16, deadline: u64) -> Result<()> {
    loop {
        let now = boottime_now_ns_v11()?;
        if now >= deadline {
            return Err(ControllerError::Rejected(
                "Docker transport absolute deadline expired",
            ));
        }
        let remaining_ms = (deadline - now)
            .saturating_add(999_999)
            / 1_000_000;
        let timeout = remaining_ms
            .min(POLL_QUANTUM_MS_V11)
            .min(i32::MAX as u64) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents
                & (libc::POLLERR | libc::POLLNVAL)
                != 0
            {
                return Err(ControllerError::Rejected(
                    "Docker transport descriptor failed",
                ));
            }
            return Ok(());
        }
        if result < 0
            && std::io::Error::last_os_error().kind()
                != std::io::ErrorKind::Interrupted
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn poll_deadline_cancelled(
    fd: i32,
    events: i16,
    deadline: u64,
    cancelled: &AtomicBool,
) -> Result<()> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(ControllerError::Rejected(
                "Docker full-duplex relay was cancelled",
            ));
        }
        let now = boottime_now_ns_v11()?;
        if now >= deadline {
            return Err(ControllerError::Rejected(
                "Docker transport absolute deadline expired",
            ));
        }
        let remaining_ms = (deadline - now)
            .saturating_add(999_999)
            / 1_000_000;
        let timeout = remaining_ms
            .min(POLL_QUANTUM_MS_V11)
            .min(i32::MAX as u64) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents
                & (libc::POLLERR | libc::POLLNVAL)
                != 0
            {
                return Err(ControllerError::Rejected(
                    "Docker transport descriptor failed",
                ));
            }
            if cancelled.load(Ordering::Acquire) {
                return Err(ControllerError::Rejected(
                    "Docker full-duplex relay was cancelled",
                ));
            }
            return Ok(());
        }
        if result < 0
            && std::io::Error::last_os_error().kind()
                != std::io::ErrorKind::Interrupted
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn parse_response_status(head: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(head).map_err(|_| {
        ControllerError::Invalid(
            "Docker response header is not UTF-8",
        )
    })?;
    let line = text.split("\r\n").next().unwrap_or("");
    let mut fields = line.split(' ');
    let version = fields.next().unwrap_or("");
    let status = fields.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ControllerError::Rejected(
            "Docker response status line is invalid",
        ));
    }
    status.parse::<u16>().map_err(|_| {
        ControllerError::Invalid("Docker response status is invalid")
    })
}

fn validate_response_spool_v11(
    file: &mut File,
    total_bytes: u64,
    stream_mode: DockerStreamModeV11,
) -> Result<u16> {
    file.seek(SeekFrom::Start(0))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while header_end(&head).is_none() {
        if head.len() >= HTTP_HEAD_MAX_BYTES_V11 {
            return Err(ControllerError::Rejected(
                "Docker response header exceeded its bound",
            ));
        }
        if file.read(&mut byte)? != 1 {
            return Err(ControllerError::Rejected(
                "Docker response ended before a complete header",
            ));
        }
        head.push(byte[0]);
    }
    let head_end = header_end(&head).ok_or(
        ControllerError::Rejected(
            "Docker response header delimiter is absent",
        ),
    )? + 4;
    let text = std::str::from_utf8(&head[..head_end - 4]).map_err(
        |_| {
            ControllerError::Invalid(
                "Docker response header is not UTF-8",
            )
        },
    )?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = parse_response_status(status_line.as_bytes())?;
    let mut content_length = None;
    let mut chunked = false;
    let mut connection_upgrade = false;
    let mut upgrade = false;
    for line in lines {
        let (name, raw_value) = line.split_once(':').ok_or(
            ControllerError::Rejected(
                "Docker response header lacks a colon",
            ),
        )?;
        let value = raw_value.strip_prefix(' ').ok_or(
            ControllerError::Rejected(
                "Docker response header lacks canonical spacing",
            ),
        )?;
        if name.is_empty()
            || name.trim() != name
            || value.trim() != value
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-'
            })
            || value.bytes().any(|byte| {
                byte == 0 || byte == b'\r' || byte == b'\n'
            })
        {
            return Err(ControllerError::Rejected(
                "Docker response header is noncanonical",
            ));
        }
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if content_length
                    .replace(value.parse::<u64>().map_err(|_| {
                        ControllerError::Invalid(
                            "Docker response Content-Length is invalid",
                        )
                    })?)
                    .is_some()
                {
                    return Err(ControllerError::Rejected(
                        "Docker response Content-Length is duplicated",
                    ));
                }
            }
            "transfer-encoding" => {
                if chunked || value != "chunked" {
                    return Err(ControllerError::Rejected(
                        "Docker response transfer encoding is unsupported",
                    ));
                }
                chunked = true;
            }
            "connection" => {
                if value.eq_ignore_ascii_case("upgrade") {
                    if connection_upgrade {
                        return Err(ControllerError::Rejected(
                            "Docker response Connection upgrade is duplicated",
                        ));
                    }
                    connection_upgrade = true;
                } else if !value.eq_ignore_ascii_case("close") {
                    return Err(ControllerError::Rejected(
                        "Docker response Connection value is unsupported",
                    ));
                }
            }
            "upgrade" => {
                if upgrade || !value.eq_ignore_ascii_case("tcp") {
                    return Err(ControllerError::Rejected(
                        "Docker response Upgrade value is unsupported",
                    ));
                }
                upgrade = true;
            }
            "content-type"
            | "docker-experimental"
            | "api-version"
            | "ostype"
            | "server"
            | "date" => {}
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker response header is not exactly allowlisted",
                ))
            }
        }
    }
    if content_length.is_some() && chunked {
        return Err(ControllerError::Rejected(
            "Docker response has conflicting body framing",
        ));
    }
    let body_bytes = total_bytes
        .checked_sub(head_end as u64)
        .ok_or(ControllerError::Invalid(
            "Docker response length underflowed",
        ))?;
    if status_code == 101 {
        if stream_mode != DockerStreamModeV11::Upgrade101
            || !connection_upgrade
            || !upgrade
            || content_length.is_some()
            || chunked
        {
            return Err(ControllerError::Rejected(
                "Docker 101 response differs from the signed upgrade mode",
            ));
        }
    } else if connection_upgrade
        || upgrade
        || stream_mode == DockerStreamModeV11::Upgrade101
    {
        return Err(ControllerError::Rejected(
            "Docker non-101 response contains upgrade framing",
        ));
    } else if let Some(length) = content_length {
        if length != body_bytes {
            return Err(ControllerError::Rejected(
                "Docker response body length differs from Content-Length",
            ));
        }
    } else if chunked {
        validate_chunked_response(file, body_bytes)?;
    }
    Ok(status_code)
}

fn validate_chunked_response(
    file: &mut File,
    body_bytes: u64,
) -> Result<()> {
    let start = file.stream_position()?;
    let mut consumed = 0u64;
    loop {
        let line = read_file_crlf_line(file, 1024)?;
        consumed = consumed
            .checked_add(line.len() as u64)
            .ok_or(ControllerError::Invalid(
                "Docker chunked response length overflowed",
            ))?;
        let line_text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| {
                ControllerError::Invalid(
                    "Docker chunk size is not UTF-8",
                )
            })?;
        if line_text.contains(';') {
            return Err(ControllerError::Rejected(
                "Docker chunk extensions are not permitted",
            ));
        }
        let size = u64::from_str_radix(line_text, 16).map_err(|_| {
            ControllerError::Invalid("Docker chunk size is invalid")
        })?;
        if size == 0 {
            let terminal = read_file_crlf_line(file, 2)?;
            consumed = consumed
                .checked_add(terminal.len() as u64)
                .ok_or(ControllerError::Invalid(
                    "Docker chunk terminal length overflowed",
                ))?;
            if terminal != b"\r\n" {
                return Err(ControllerError::Rejected(
                    "Docker chunked response contains trailers",
                ));
            }
            break;
        }
        file.seek(SeekFrom::Current(
            i64::try_from(size).map_err(|_| {
                ControllerError::Invalid(
                    "Docker chunk size is too large",
                )
            })?,
        ))?;
        let mut delimiter = [0u8; 2];
        file.read_exact(&mut delimiter)?;
        if delimiter != *b"\r\n" {
            return Err(ControllerError::Rejected(
                "Docker chunk lacks its data delimiter",
            ));
        }
        consumed = consumed
            .checked_add(size)
            .and_then(|value| value.checked_add(2))
            .ok_or(ControllerError::Invalid(
                "Docker chunked response length overflowed",
            ))?;
        if consumed > body_bytes {
            return Err(ControllerError::Rejected(
                "Docker chunked response exceeds its body bound",
            ));
        }
    }
    if consumed != body_bytes
        || file.stream_position()? != start + body_bytes
    {
        return Err(ControllerError::Rejected(
            "Docker chunked response has surplus or missing bytes",
        ));
    }
    Ok(())
}

fn read_file_crlf_line(
    file: &mut File,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() < maximum {
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(ControllerError::Rejected(
        "Docker response line exceeded its bound",
    ))
}

fn strip_version(path: &str) -> Result<&str> {
    let mut components = path.split('/').filter(|part| !part.is_empty());
    if components.next().is_some_and(|part| {
        part.starts_with('v')
            && part.len() > 1
            && part[1..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
    }) {
        let first = path.find('/').unwrap_or(0);
        let rest = &path[first + 1..];
        let next = rest.find('/').ok_or(ControllerError::Rejected(
            "versioned Docker API path has no operation",
        ))?;
        return Ok(&rest[next..]);
    }
    Ok(path)
}

fn percent_decode_canonical(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                    || bytes[index + 1].is_ascii_lowercase()
                    || bytes[index + 2].is_ascii_lowercase()
                {
                    return Err(ControllerError::Rejected(
                        "Docker query percent encoding is noncanonical",
                    ));
                }
                let high = hex_nibble(bytes[index + 1])?;
                let low = hex_nibble(bytes[index + 2])?;
                let byte = high * 16 + low;
                if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~')
                {
                    return Err(ControllerError::Rejected(
                        "Docker query percent-encodes an unreserved byte",
                    ));
                }
                output.push(byte);
                index += 3;
            }
            b'+' => {
                return Err(ControllerError::Rejected(
                    "Docker query must not use ambiguous plus encoding",
                ))
            }
            byte
                if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~') =>
            {
                output.push(byte);
                index += 1;
            }
            byte if byte >= 0x20 && byte < 0x7f => {
                return Err(ControllerError::Rejected(
                    "Docker query leaves a reserved byte unescaped",
                ))
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker query contains non-ASCII or control bytes",
                ))
            }
        }
    }
    String::from_utf8(output).map_err(|_| {
        ControllerError::Invalid("Docker query is not UTF-8")
    })
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ControllerError::Invalid(
            "Docker percent-encoded nibble is invalid",
        )),
    }
}

fn unique_spool_path(root: &Path, label: &str) -> PathBuf {
    root.join(format!(
        "{}-{}-{}.spool",
        label,
        unsafe { libc::getpid() },
        SPOOL_SEQUENCE_V11.fetch_add(1, Ordering::AcqRel),
    ))
}

fn hex_digest_v12(value: &Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn require_private_spool_root(root: &Path) -> Result<()> {
    if !root.is_absolute()
        || root.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(ControllerError::Rejected(
            "Docker spool root is not absolute and normalized",
        ));
    }
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(ControllerError::Rejected(
            "Docker spool root is not private root-owned storage",
        ));
    }
    Ok(())
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
