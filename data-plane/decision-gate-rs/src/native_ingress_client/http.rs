//! One fixed public attestation exchange over the already-owned outer TLS.
//!
//! Framing success is not quote verification, TLS-policy admission, challenge
//! consumption or permission to dispatch a proxy request. The returned bytes
//! remain the exact response original, including its evidence framing LF.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serverware_decision_gate::native_ingress_challenge_v1::CHALLENGE_HEADER;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const MAX_HEAD_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 98_304;
const MAX_AUTHORITY_BYTES: usize = 259;

#[derive(Clone, Copy)]
enum Completion { AuthenticatedClose, ConnectContinuation }

pub(super) fn exchange<T: Read + Write>(connection: &mut T, authority: &str,
    challenge: [u8; 32]) -> Result<Vec<u8>, String> {
    exchange_fixed(connection, authority, challenge, Completion::AuthenticatedClose)
}

/// The caller must supply an actual original-deadline TLS owner and verify the
/// returned originals against that same connection before sending CONNECT.
/// This fixed opt-in never accepts an arbitrary HTTP method, path or header.
pub(super) fn exchange_for_connect<T: Read + Write>(connection: &mut T, authority: &str,
    challenge: [u8; 32]) -> Result<Vec<u8>, String> {
    exchange_fixed(connection, authority, challenge, Completion::ConnectContinuation)
}

fn exchange_fixed<T: Read + Write>(connection: &mut T, authority: &str,
    challenge: [u8; 32], completion: Completion) -> Result<Vec<u8>, String> {
    validate_authority(authority)?;
    if challenge == [0; 32] {
        return Err("native ingress HTTP challenge must be nonzero".to_owned());
    }
    // Authority is a separately chosen endpoint spelling, not a destination
    // received from a server. No method/path/header/credential extension exists.
    let ending = match completion {
        Completion::AuthenticatedClose => "Connection: close\r\n\r\n",
        Completion::ConnectContinuation =>
            "x-serverware-ingress-continuation: connect-v1\r\nConnection: keep-alive\r\n\r\n",
    };
    let request = format!(
        "GET /attestation HTTP/1.1\r\nHost: {authority}\r\n{CHALLENGE_HEADER}: {}\r\n{ending}",
        URL_SAFE_NO_PAD.encode(challenge));
    // Both actual TLS callers check their original lifetime before and after
    // every read/write/flush, including accesses to buffered plaintext. No
    // generic stream, parser result or HTTP status supplies that ownership.
    connection.write_all(request.as_bytes())
        .map_err(|_| "write fixed native ingress attestation request".to_owned())?;
    connection.flush().map_err(|_| "flush native ingress attestation request".to_owned())?;

    // Byte reads prevent the header reader from discarding any original body
    // or surplus plaintext. The source bound includes the terminating CRLFCRLF.
    let mut head = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        if head.len() == MAX_HEAD_BYTES {
            return Err("native ingress HTTP head exceeds its bound".to_owned());
        }
        if read_checked(connection, &mut one)? == 0 {
            return Err("native ingress TLS closed before the HTTP head completed".to_owned());
        }
        head.push(one[0]);
        if head.ends_with(b"\r\n\r\n") { break; }
    }
    let length = response_length(&head, completion)?;
    let mut body = vec![0u8; length];
    let mut offset = 0usize;
    while offset < body.len() {
        let read = read_checked(connection, &mut body[offset..])?;
        if read == 0 {
            return Err("native ingress TLS closed before its declared body completed".to_owned());
        }
        offset = offset.checked_add(read).ok_or("native ingress HTTP body offset overflow")?;
    }
    // Nonempty rustls reads return zero only after peer close_notify with all
    // plaintext drained. A bare TCP close propagates UnexpectedEof; it is not
    // completion. Any extra plaintext, including trailers, is rejected.
    if matches!(completion, Completion::AuthenticatedClose) {
        if read_checked(connection, &mut one)? != 0 {
            return Err("native ingress response contains surplus plaintext".to_owned());
        }
    }
    // Continuation deliberately stops at exact Content-Length. Do not probe
    // EOF or consume subsequent bytes on the persistent TLS connection.
    Ok(body)
}

fn validate_authority(authority: &str) -> Result<(), String> {
    if authority.is_empty() || authority.len() > MAX_AUTHORITY_BYTES
        || !authority.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return Err("native ingress HTTP authority has invalid bounded syntax".to_owned());
    }
    let (host, port) = authority.rsplit_once(':')
        .ok_or("native ingress HTTP authority requires an explicit port")?;
    let parsed = port.parse::<u16>().map_err(|_| "native ingress HTTP authority port is invalid")?;
    if host.is_empty() || parsed == 0 || parsed.to_string() != port {
        return Err("native ingress HTTP authority port is not canonical".to_owned());
    }
    Ok(())
}

fn read_checked<T: Read>(connection: &mut T, buffer: &mut [u8]) -> Result<usize, String> {
    loop {
        let result = connection.read(buffer);
        match result {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read native ingress HTTP through authenticated TLS framing".to_owned()),
        }
    }
}

fn response_length(head: &[u8], completion: Completion) -> Result<usize, String> {
    let bodyless = head.strip_suffix(b"\r\n\r\n")
        .ok_or("native ingress HTTP head is incomplete")?;
    if !bodyless.is_ascii() {
        return Err("native ingress HTTP head must be ASCII".to_owned());
    }
    let text = std::str::from_utf8(bodyless).map_err(|_| "native ingress HTTP head is invalid")?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("native ingress HTTP requires exactly one 200 OK response".to_owned());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, raw_value) = line.split_once(':')
            .ok_or("native ingress HTTP header lacks its separator")?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphabetic() || byte == b'-') {
            return Err("native ingress HTTP header name is invalid".to_owned());
        }
        let name = name.to_ascii_lowercase();
        if !matches!(name.as_str(), "content-type" | "content-length" | "connection" | "cache-control") {
            return Err("native ingress HTTP contains an unsupported response header".to_owned());
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty() || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
            || headers.insert(name, value).is_some()
        {
            return Err("native ingress HTTP has an invalid or repeated physical header".to_owned());
        }
    }
    let expected_connection = match completion {
        Completion::AuthenticatedClose => "close",
        Completion::ConnectContinuation => "keep-alive",
    };
    if headers.len() != 4 || headers.get("content-type") != Some(&"application/json")
        || headers.get("connection") != Some(&expected_connection)
        || headers.get("cache-control") != Some(&"no-store")
    {
        return Err("native ingress HTTP response headers differ from the fixed contract".to_owned());
    }
    let length = headers.get("content-length").ok_or("native ingress HTTP content length is absent")?;
    if length.len() > 5 || length.starts_with('0') || !length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("native ingress HTTP content length must be canonical and positive".to_owned());
    }
    let length = length.parse::<usize>().map_err(|_| "native ingress HTTP content length is invalid")?;
    if length == 0 || length > MAX_BODY_BYTES {
        return Err("native ingress HTTP body exceeds its source bound".to_owned());
    }
    Ok(length)
}
