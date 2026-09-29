//! Exactly one bootstrap POST; HTTP framing never supplies authority.

use super::{ensure, exchange};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serverware_decision_gate::native_ingress_challenge_v1::CHALLENGE_HEADER;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const MAX_HEAD_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(super) fn post<T: Read + Write>(connection: &mut T, authority: &str,
    challenge: [u8; 32], original: &[u8]) -> Result<Vec<u8>, String> {
    ensure(!authority.is_empty() && authority.len() <= 259
        && authority.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')),
        "bootstrap HTTP authority differs")?;
    let (host, port) = authority.rsplit_once(':').ok_or("bootstrap HTTP authority has no port")?;
    let parsed = port.parse::<u16>().map_err(|_| "bootstrap HTTP port is invalid")?;
    ensure(!host.is_empty() && parsed != 0 && parsed.to_string() == port && challenge != [0; 32]
        && !original.is_empty() && original.len() <= exchange::MAX_REQUEST_BYTES,
        "bootstrap HTTP request exceeds its fixed contract")?;
    let head = format!("POST {} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{CHALLENGE_HEADER}: {}\r\nConnection: close\r\n\r\n",
        exchange::PATH, original.len(), URL_SAFE_NO_PAD.encode(challenge));
    connection.write_all(head.as_bytes()).map_err(|_| "write bootstrap HTTP head")?;
    connection.write_all(original).map_err(|_| "write bootstrap HTTP original")?;
    connection.flush().map_err(|_| "flush bootstrap HTTP original")?;
    // Never overread the head or silently discard extra plaintext.
    let mut head = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        ensure(head.len() < MAX_HEAD_BYTES, "bootstrap HTTP head exceeds its bound")?;
        ensure(read(connection, &mut one)? != 0, "bootstrap TLS closed before HTTP head")?;
        head.push(one[0]);
        if head.ends_with(b"\r\n\r\n") { break; }
    }
    let length = response_length(&head)?;
    let mut body = vec![0u8; length];
    let mut offset = 0usize;
    while offset < length {
        let count = read(connection, &mut body[offset..])?;
        ensure(count != 0, "bootstrap TLS closed before declared HTTP body")?;
        offset = offset.checked_add(count).ok_or("bootstrap HTTP body overflow")?;
    }
    // Rustls must authenticate close_notify. Bare TCP EOF is an error in the
    // actual transport; no redirects, continuation, trailers or second reply.
    ensure(read(connection, &mut one)? == 0, "bootstrap HTTP surplus plaintext")?;
    Ok(body)
}

fn read<T: Read>(connection: &mut T, output: &mut [u8]) -> Result<usize, String> {
    loop {
        match connection.read(output) {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read authenticated bootstrap HTTP framing".to_owned()),
        }
    }
}

fn response_length(head: &[u8]) -> Result<usize, String> {
    let head = head.strip_suffix(b"\r\n\r\n").ok_or("bootstrap HTTP head is incomplete")?;
    ensure(head.is_ascii(), "bootstrap HTTP head is not ASCII")?;
    let text = std::str::from_utf8(head).map_err(|_| "bootstrap HTTP head is invalid")?;
    let mut lines = text.split("\r\n");
    ensure(lines.next() == Some("HTTP/1.1 200 OK"), "bootstrap HTTP status differs")?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("bootstrap HTTP header separator is absent")?;
        ensure(!name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphabetic() || byte == b'-'),
            "bootstrap HTTP header name is invalid")?;
        let name = name.to_ascii_lowercase();
        ensure(matches!(name.as_str(), "content-type" | "content-length" | "connection" | "cache-control"),
            "bootstrap HTTP unsupported header")?;
        let value = value.trim_matches([' ', '\t']);
        ensure(!value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            && headers.insert(name, value).is_none(), "bootstrap HTTP repeated or invalid header")?;
    }
    ensure(headers.len() == 4 && headers.get("content-type") == Some(&"application/json")
        && headers.get("connection") == Some(&"close") && headers.get("cache-control") == Some(&"no-store"),
        "bootstrap HTTP response profile differs")?;
    let length = headers.get("content-length").ok_or("bootstrap HTTP length is absent")?;
    ensure(!length.is_empty() && length.len() <= 7 && !length.starts_with('0')
        && length.bytes().all(|byte| byte.is_ascii_digit()), "bootstrap HTTP length is not canonical")?;
    let length = length.parse::<usize>().map_err(|_| "bootstrap HTTP length overflow")?;
    ensure((1..=MAX_BODY_BYTES).contains(&length), "bootstrap HTTP body exceeds its bound")?;
    Ok(length)
}
