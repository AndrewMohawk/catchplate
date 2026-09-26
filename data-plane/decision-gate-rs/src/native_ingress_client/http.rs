//! One fixed public attestation exchange over the already-owned outer TLS.
//!
//! Framing success is not quote verification, TLS-policy admission, challenge
//! consumption or permission to dispatch a proxy request. The returned bytes
//! remain the exact response original, including its evidence framing LF.

use super::transport::Connection;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serverware_decision_gate::native_ingress_challenge_v1::CHALLENGE_HEADER;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const MAX_HEAD_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 98_304;
const MAX_AUTHORITY_BYTES: usize = 259;

pub(super) fn exchange(connection: &mut Connection, authority: &str,
    challenge: [u8; 32]) -> Result<Vec<u8>, String> {
    connection.check()?;
    validate_authority(authority)?;
    if challenge == [0; 32] {
        return Err("native ingress HTTP challenge must be nonzero".to_owned());
    }
    // Authority is a separately chosen endpoint spelling, not a destination
    // received from a server. No method/path/header/credential extension exists.
    let request = format!(
        "GET /attestation HTTP/1.1\r\nHost: {authority}\r\n{CHALLENGE_HEADER}: {}\r\nConnection: close\r\n\r\n",
        URL_SAFE_NO_PAD.encode(challenge),
    );
    connection.check()?;
    connection.write_all(request.as_bytes())
        .map_err(|_| "write fixed native ingress attestation request".to_owned())?;
    connection.check()?;
    connection.flush().map_err(|_| "flush native ingress attestation request".to_owned())?;
    connection.check()?;

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
    let length = response_length(&head)?;
    connection.check()?;
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
    if read_checked(connection, &mut one)? != 0 {
        return Err("native ingress response contains surplus plaintext".to_owned());
    }
    connection.check()?;
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

fn read_checked(connection: &mut Connection, buffer: &mut [u8]) -> Result<usize, String> {
    loop {
        connection.check()?;
        let result = connection.read(buffer);
        connection.check()?;
        match result {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read native ingress HTTP through authenticated TLS framing".to_owned()),
        }
    }
}

fn response_length(head: &[u8]) -> Result<usize, String> {
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
    if headers.len() != 4 || headers.get("content-type") != Some(&"application/json")
        || headers.get("connection") != Some(&"close")
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
