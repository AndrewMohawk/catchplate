use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Map, Value};
use serverware_decision_gate::{validate_response_statement, ProxyResponseStatement};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Serverware-Proxy-Response-v1";
const STREAM_EXPORTER_LABEL: &[u8] = b"EXPORTER-Serverware-Proxy-Stream-v1";
const MAX_RESPONSE_HEAD_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONFIGURED_STREAM_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CHUNK_SIZE_LINE_BYTES: usize = 128;
const MAX_RUNTIME_PROOF_BYTES: usize = 96 * 1024;
const MAX_TRAILER_LINE_BYTES: usize = MAX_RUNTIME_PROOF_BYTES * 4 / 3 + 256;
const MAX_TRAILER_BLOCK_BYTES: usize = MAX_TRAILER_LINE_BYTES + 1024;
const STREAM_PROOF_B64_TRAILER: &str = "x-serverware-stream-proof-b64";
const STREAM_PROOF_SHA256_TRAILER: &str = "x-serverware-stream-proof-sha256";
const STREAM_PROOF_B64_TRAILER_WIRE: &str = "X-Serverware-Stream-Proof-B64";
const STREAM_PROOF_SHA256_TRAILER_WIRE: &str = "X-Serverware-Stream-Proof-SHA256";
const STREAM_TRAILER_NAMES: [&str; 2] = [STREAM_PROOF_B64_TRAILER, STREAM_PROOF_SHA256_TRAILER];
const STALE_PUBLICATION_ENTRY_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SCAVENGE_DIRECTORY_ENTRIES: usize = 256;
const MAX_SCAVENGE_REMOVALS: usize = 16;

struct Args {
    stream: bool,
    proxy: String,
    method: String,
    url: Url,
    ca: PathBuf,
    out: PathBuf,
    body_out: Option<PathBuf>,
    collector_key: PathBuf,
    verifier_key: Option<PathBuf>,
    expected_server_instance_id: Option<String>,
    client_nonce: Option<[u8; 32]>,
    expected_principal_id: String,
    proxy_headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    timeout_seconds: u64,
    max_age_seconds: u64,
    max_stream_bytes: u64,
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct RuntimeProofExpectations<'a> {
    nonce: &'a str,
    tls_exporter: &'a str,
    peer_spiffe_id: &'a str,
    peer_leaf_digest: &'a str,
    client_request_digest: &'a str,
    principal_id: &'a str,
    max_age_seconds: u64,
}

struct StreamResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    trailers: BTreeMap<String, String>,
    body_digest: String,
    body_bytes: u64,
}

struct PendingStreamCollection {
    staged_body: StagedBody,
    proof_target: ResolvedOutputTarget,
    client_request_digest: String,
    nonce: String,
    nonce_bytes: [u8; 32],
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization failed")
}

#[cfg(test)]
fn canonical_json_ensure_ascii(value: &Value) -> String {
    let encoded = canonical_json(value);
    let mut ascii = String::with_capacity(encoded.len());
    for character in encoded.chars() {
        let codepoint = character as u32;
        if codepoint <= 0x7f {
            ascii.push(character);
        } else if codepoint <= 0xffff {
            ascii.push_str(&format!("\\u{codepoint:04x}"));
        } else {
            let supplementary = codepoint - 0x1_0000;
            let high = 0xd800 + (supplementary >> 10);
            let low = 0xdc00 + (supplementary & 0x3ff);
            ascii.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
        }
    }
    ascii
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn parse_header(raw: &str, label: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("{label} must use Name: value syntax"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || value.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.contains(['\r', '\n'])
    {
        return Err(format!("{label} is invalid"));
    }
    Ok((name.to_string(), value.to_string()))
}

fn validate_proof_method(method: &str) -> Result<&'static str, String> {
    match method {
        "GET" => Ok("GET"),
        "HEAD" => Err("response proof collection is GET-only; HEAD is not supported".to_string()),
        _ => Err("response proof collection requires method GET".to_string()),
    }
}

fn parse_args() -> Result<Args, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from<I>(values: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut stream = false;
    let mut proxy = None;
    let mut method = "GET".to_string();
    let mut url = None;
    let mut ca = None;
    let mut out = None;
    let mut body_out = None;
    let mut collector_key = None;
    let mut verifier_key = None;
    let mut expected_server_instance_id = None;
    let mut expected_principal_id = None;
    let mut client_nonce = None;
    let mut proxy_headers = Vec::new();
    let mut request_headers = Vec::new();
    let mut timeout_seconds = 20u64;
    let mut max_age_seconds = 300u64;
    let mut max_stream_bytes = DEFAULT_MAX_STREAM_BYTES;
    let mut max_stream_bytes_supplied = false;
    let mut values = values.into_iter();
    while let Some(flag) = values.next() {
        if flag == "--stream" {
            if stream {
                return Err("--stream may be specified only once".to_string());
            }
            stream = true;
            continue;
        }
        let value = values
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--proxy" => proxy = Some(value),
            "--method" => method = validate_proof_method(&value)?.to_string(),
            "--url" => url = Some(Url::parse(&value).map_err(|err| format!("parse --url: {err}"))?),
            "--ca" => ca = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            "--body-out" => body_out = Some(PathBuf::from(value)),
            "--collector-key" => collector_key = Some(PathBuf::from(value)),
            "--verifier-key" => verifier_key = Some(PathBuf::from(value)),
            "--expected-server-instance-id" => expected_server_instance_id = Some(value),
            "--expected-principal-id" => expected_principal_id = Some(value),
            "--nonce" => {
                let decoded = general_purpose::URL_SAFE_NO_PAD
                    .decode(value.as_bytes())
                    .map_err(|_| "--nonce must be unpadded base64url".to_string())?;
                client_nonce = Some(
                    decoded
                        .try_into()
                        .map_err(|_| "--nonce must contain exactly 32 bytes".to_string())?,
                );
            }
            "--proxy-header" => proxy_headers.push(parse_header(&value, "--proxy-header")?),
            "--header" => request_headers.push(parse_header(&value, "--header")?),
            "--timeout-seconds" => {
                timeout_seconds = value
                    .parse::<u64>()
                    .map_err(|_| "--timeout-seconds must be an integer".to_string())?;
                if !(1..=120).contains(&timeout_seconds) {
                    return Err("--timeout-seconds must be between 1 and 120".to_string());
                }
            }
            "--max-age-seconds" => {
                max_age_seconds = value
                    .parse::<u64>()
                    .map_err(|_| "--max-age-seconds must be an integer".to_string())?;
                if !(1..=900).contains(&max_age_seconds) {
                    return Err("--max-age-seconds must be between 1 and 900".to_string());
                }
            }
            "--max-stream-bytes" => {
                max_stream_bytes_supplied = true;
                max_stream_bytes = value
                    .parse::<u64>()
                    .map_err(|_| "--max-stream-bytes must be an integer".to_string())?;
                if !(1..=MAX_CONFIGURED_STREAM_BYTES).contains(&max_stream_bytes) {
                    return Err(format!(
                        "--max-stream-bytes must be between 1 and {MAX_CONFIGURED_STREAM_BYTES}"
                    ));
                }
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if stream && body_out.is_none() {
        return Err("--stream requires --body-out".to_string());
    }
    if !stream && body_out.is_some() {
        return Err("--body-out is valid only with --stream".to_string());
    }
    if !stream && max_stream_bytes_supplied {
        return Err("--max-stream-bytes is valid only with --stream".to_string());
    }
    let url = url.ok_or("--url is required")?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("--url must be an HTTPS URL without userinfo or a fragment".to_string());
    }
    for (name, _) in &request_headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "content-length"
                | "transfer-encoding"
                | "upgrade"
                | "authorization"
                | "x-serverware-data-plane-token"
                | "x-serverware-proof-nonce"
                | "x-serverware-stream-proof-nonce"
        ) {
            return Err(format!("--header cannot override reserved field {name}"));
        }
    }
    let mut normalized_request_headers = BTreeMap::new();
    for (name, value) in &request_headers {
        let lowered = name.to_ascii_lowercase();
        if normalized_request_headers
            .insert(lowered.clone(), value.trim().to_string())
            .is_some()
        {
            return Err(format!(
                "--header repeats field {lowered} after case normalization"
            ));
        }
    }
    let mut has_agent_identity = false;
    let mut normalized_proxy_headers = BTreeMap::new();
    for (name, value) in &proxy_headers {
        let lowered = name.to_ascii_lowercase();
        if normalized_proxy_headers
            .insert(lowered.clone(), value.as_str())
            .is_some()
        {
            return Err(format!(
                "--proxy-header repeats field {lowered} after case normalization"
            ));
        }
        if lowered == "x-serverware-agent" {
            if value.is_empty()
                || value != value.trim()
                || value.len() > 256
                || value.chars().any(char::is_control)
            {
                return Err("X-Serverware-Agent proxy identity is invalid".to_string());
            }
            has_agent_identity = true;
        }
    }
    if !has_agent_identity {
        return Err(
            "response proof collection requires exactly one X-Serverware-Agent --proxy-header"
                .to_string(),
        );
    }
    let expected_principal_id = expected_principal_id
        .ok_or("response proof collection requires --expected-principal-id")?;
    if expected_principal_id.is_empty()
        || expected_principal_id != expected_principal_id.trim()
        || expected_principal_id.len() > 256
        || expected_principal_id.chars().any(char::is_control)
    {
        return Err("--expected-principal-id is invalid".to_string());
    }
    if let Some(instance_id) = expected_server_instance_id.as_deref() {
        if !instance_id.starts_with("spiffe://") || instance_id.len() <= "spiffe://".len() {
            return Err("--expected-server-instance-id must be a non-empty SPIFFE ID".to_string());
        }
    }
    Ok(Args {
        stream,
        proxy: proxy.ok_or("--proxy is required")?,
        method,
        url,
        ca: ca.ok_or("--ca is required")?,
        out: out.ok_or("--out is required")?,
        body_out,
        collector_key: collector_key.ok_or("--collector-key is required")?,
        verifier_key,
        expected_server_instance_id,
        client_nonce,
        expected_principal_id,
        proxy_headers,
        request_headers,
        timeout_seconds,
        max_age_seconds,
        max_stream_bytes,
    })
}

fn canonical_authority(url: &Url) -> String {
    url.host_str()
        .map(|host| {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host
            };
            match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
        })
        .unwrap_or_default()
}

fn is_excluded_client_proof_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "content-length"
            | "transfer-encoding"
            | "upgrade"
            | "authorization"
            | "x-serverware-agent"
            | "x-serverware-data-plane-token"
            | "x-serverware-proof-nonce"
            | "x-serverware-stream-proof-nonce"
    )
}

fn canonical_client_proof_request_for_mode(
    method: &str,
    url: &Url,
    request_headers: &[(String, String)],
    stream: bool,
) -> Result<Value, String> {
    let method = validate_proof_method(method)?;
    let mut headers = BTreeMap::new();
    for (name, value) in request_headers {
        let name = name.to_ascii_lowercase();
        if is_excluded_client_proof_header(&name) {
            continue;
        }
        if headers
            .insert(name.clone(), value.trim().to_string())
            .is_some()
        {
            return Err(format!(
                "proof request repeats header {name} after case normalization"
            ));
        }
    }
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<Vec<_>>();
    query.sort();
    Ok(json!({
        "apiVersion":if stream {
            "serverware.streamingClientProofRequest/v1"
        } else {
            "serverware.clientProofRequest/v1"
        },
        "method":method,
        "scheme":url.scheme().to_ascii_lowercase(),
        "authority":canonical_authority(url),
        "path":url.path(),
        "query":query,
        "headers":headers,
        "body_sha256":sha256_prefixed(b""),
    }))
}

#[cfg(test)]
fn canonical_client_proof_request(
    method: &str,
    url: &Url,
    request_headers: &[(String, String)],
) -> Result<Value, String> {
    canonical_client_proof_request_for_mode(method, url, request_headers, false)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_head<R: Read>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    while find_header_end(&buffer).is_none() {
        let read = reader
            .read(&mut chunk)
            .map_err(|err| format!("read HTTP response head: {err}"))?;
        if read == 0 {
            return Err("connection closed before the HTTP response head completed".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if find_header_end(&buffer)
            .map(|offset| offset + 4 > maximum)
            .unwrap_or(buffer.len() > maximum)
        {
            return Err("HTTP response head exceeds the configured limit".to_string());
        }
    }
    Ok(buffer)
}

fn parse_head(buffer: &[u8]) -> Result<(u16, BTreeMap<String, String>, usize), String> {
    let header_end = find_header_end(buffer).ok_or("HTTP response head is incomplete")?;
    let text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| "HTTP response headers are not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("HTTP response status line is missing")?;
    let mut status_parts = status_line.split_ascii_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .ok_or("HTTP response status is missing")?
        .parse::<u16>()
        .map_err(|_| "HTTP response status is invalid".to_string())?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("HTTP response version is unsupported".to_string());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("HTTP response header is malformed")?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if headers.insert(name.clone(), value).is_some() {
            return Err(format!("HTTP response repeats header {name}"));
        }
    }
    Ok((status, headers, header_end + 4))
}

fn read_response<R: Read>(reader: &mut R) -> Result<HttpResponse, String> {
    let mut buffer = read_head(reader, MAX_RESPONSE_HEAD_BYTES)?;
    let (status, headers, body_start) = parse_head(&buffer)?;
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("proof response must use a bounded Content-Length body".to_string());
    }
    let content_length = headers
        .get("content-length")
        .ok_or("proof response is missing Content-Length")?
        .parse::<usize>()
        .map_err(|_| "proof response Content-Length is invalid".to_string())?;
    if content_length > MAX_RESPONSE_BODY_BYTES {
        return Err("proof response body exceeds the collector limit".to_string());
    }
    let total = body_start
        .checked_add(content_length)
        .ok_or("proof response size overflow")?;
    if buffer.len() > total {
        return Err("proof response contains bytes after the declared body".to_string());
    }
    let prefetched_body_bytes = buffer.len().saturating_sub(body_start);
    buffer.resize(total, 0);
    reader
        .read_exact(&mut buffer[body_start + prefetched_body_bytes..])
        .map_err(|err| format!("read proof response body: {err}"))?;
    Ok(HttpResponse {
        status,
        headers,
        body: buffer[body_start..].to_vec(),
    })
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_stream_head(buffer: &[u8]) -> Result<(u16, BTreeMap<String, String>, usize), String> {
    let header_end = find_header_end(buffer).ok_or("stream response head is incomplete")?;
    if header_end + 4 > MAX_RESPONSE_HEAD_BYTES {
        return Err("stream response head exceeds the collector limit".to_string());
    }
    let text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| "stream response head is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or("stream response status line is missing")?;
    let status_suffix = status_line
        .strip_prefix("HTTP/1.1 ")
        .ok_or("stream response must use HTTP/1.1")?;
    let status_text = status_suffix
        .get(..3)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or("stream response status is invalid")?;
    if status_suffix.len() > 3 && status_suffix.as_bytes().get(3) != Some(&b' ') {
        return Err("stream response status line is malformed".to_string());
    }
    if status_suffix
        .as_bytes()
        .iter()
        .any(|byte| !byte.is_ascii() || (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err("stream response status line contains invalid bytes".to_string());
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| "stream response status is invalid".to_string())?;
    if !(200..=299).contains(&status) {
        return Err(format!(
            "stream proof response must have a 2xx status, received {status}"
        ));
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err("stream response head contains obs-fold".to_string());
        }
        let (name, raw_value) = line
            .split_once(':')
            .ok_or("stream response header is malformed")?;
        if !is_http_token(name) {
            return Err("stream response header name is invalid".to_string());
        }
        if raw_value
            .bytes()
            .any(|byte| !byte.is_ascii() || (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err("stream response header value contains invalid bytes".to_string());
        }
        let name = name.to_ascii_lowercase();
        let value = raw_value.trim_matches([' ', '\t']).to_string();
        if headers.insert(name.clone(), value).is_some() {
            return Err(format!("stream response repeats header {name}"));
        }
    }
    if headers.contains_key("content-length") {
        return Err("stream proof response must not contain Content-Length".to_string());
    }
    if !headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        return Err("stream proof response Transfer-Encoding must be exactly chunked".to_string());
    }
    let declared = headers
        .get("trailer")
        .ok_or("stream proof response is missing Trailer")?
        .split(',')
        .map(|name| name.trim_matches([' ', '\t']).to_ascii_lowercase())
        .collect::<Vec<_>>();
    if declared.len() != STREAM_TRAILER_NAMES.len()
        || STREAM_TRAILER_NAMES
            .iter()
            .any(|expected| declared.iter().filter(|name| *name == expected).count() != 1)
        || declared
            .iter()
            .any(|name| !STREAM_TRAILER_NAMES.contains(&name.as_str()))
    {
        return Err(format!(
            "stream proof Trailer must declare exactly {STREAM_PROOF_B64_TRAILER} and {STREAM_PROOF_SHA256_TRAILER} once each"
        ));
    }
    Ok((status, headers, header_end + 4))
}

fn read_crlf_line<R: Read>(reader: &mut R, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err(format!("premature EOF while reading {label}")),
            Ok(_) => {}
            Err(err) => return Err(format!("read {label}: {err}")),
        }
        if byte[0] == b'\n' {
            if line.last() != Some(&b'\r') {
                return Err(format!("{label} must end with CRLF"));
            }
            line.pop();
            return Ok(line);
        }
        line.push(byte[0]);
        if line.len() > maximum + 1 {
            return Err(format!("{label} exceeds the collector limit"));
        }
    }
}

fn parse_canonical_chunk_size(line: &[u8]) -> Result<u64, String> {
    if line.is_empty() {
        return Err("stream chunk size is empty".to_string());
    }
    if line.contains(&b';') {
        return Err("stream chunk extensions are forbidden".to_string());
    }
    if line.len() > 1 && line[0] == b'0' {
        return Err("stream chunk size has a noncanonical leading zero".to_string());
    }
    if !line
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("stream chunk size is not canonical lowercase hexadecimal".to_string());
    }
    line.iter().try_fold(0u64, |value, byte| {
        let digit = if byte.is_ascii_digit() {
            u64::from(*byte - b'0')
        } else {
            u64::from(*byte - b'a' + 10)
        };
        value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| "stream chunk size overflows u64".to_string())
    })
}

fn is_forbidden_trailer(name: &str) -> bool {
    matches!(
        name,
        "transfer-encoding"
            | "content-length"
            | "host"
            | "trailer"
            | "content-encoding"
            | "content-type"
            | "content-range"
            | "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "www-authenticate"
            | "set-cookie"
    )
}

fn parse_stream_trailers<R: Read>(reader: &mut R) -> Result<BTreeMap<String, String>, String> {
    let mut trailers = BTreeMap::new();
    let mut total = 0usize;
    loop {
        let line = read_crlf_line(reader, MAX_TRAILER_LINE_BYTES, "stream trailer line")?;
        total = total
            .checked_add(line.len() + 2)
            .ok_or("stream trailer block size overflow")?;
        if total > MAX_TRAILER_BLOCK_BYTES {
            return Err("stream trailer block exceeds the collector limit".to_string());
        }
        if line.is_empty() {
            break;
        }
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err("stream trailer block contains obs-fold".to_string());
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| "stream trailer line is not UTF-8".to_string())?;
        let (name, raw_value) = line
            .split_once(':')
            .ok_or("stream trailer line is malformed")?;
        if !is_http_token(name) {
            return Err("stream trailer name is invalid".to_string());
        }
        if raw_value
            .bytes()
            .any(|byte| !byte.is_ascii() || (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err("stream trailer value contains invalid bytes".to_string());
        }
        let name = name.to_ascii_lowercase();
        if is_forbidden_trailer(&name) {
            return Err(format!("stream response contains forbidden trailer {name}"));
        }
        if !STREAM_TRAILER_NAMES.contains(&name.as_str()) {
            return Err(format!(
                "stream response contains undeclared trailer {name}"
            ));
        }
        let value = raw_value.trim_matches([' ', '\t']).to_string();
        if value.is_empty() {
            return Err(format!("stream trailer {name} is empty"));
        }
        if trailers.insert(name.clone(), value).is_some() {
            return Err(format!("stream response repeats trailer {name}"));
        }
    }
    if trailers.len() != STREAM_TRAILER_NAMES.len()
        || STREAM_TRAILER_NAMES
            .iter()
            .any(|name| !trailers.contains_key(*name))
    {
        return Err("stream response is missing required final proof trailers".to_string());
    }
    Ok(trailers)
}

fn read_stream_response<R: Read>(
    reader: &mut R,
    body_file: &mut File,
    max_stream_bytes: u64,
) -> Result<StreamResponse, String> {
    let buffer = read_head(reader, MAX_RESPONSE_HEAD_BYTES)?;
    let (status, headers, body_start) = parse_stream_head(&buffer)?;
    let prefetched = buffer[body_start..].to_vec();
    let mut framed = Cursor::new(prefetched).chain(reader);
    let mut hasher = Sha256::new();
    let mut body_bytes = 0u64;
    let mut transfer = [0u8; 16 * 1024];
    loop {
        let size_line = read_crlf_line(
            &mut framed,
            MAX_CHUNK_SIZE_LINE_BYTES,
            "stream chunk-size line",
        )?;
        let chunk_size = parse_canonical_chunk_size(&size_line)?;
        if chunk_size == 0 {
            break;
        }
        let new_total = body_bytes
            .checked_add(chunk_size)
            .ok_or("stream decoded body byte count overflow")?;
        if new_total > max_stream_bytes {
            return Err(format!(
                "stream decoded body exceeds --max-stream-bytes {max_stream_bytes}"
            ));
        }
        let mut remaining = chunk_size;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(transfer.len() as u64))
                .map_err(|_| "stream chunk size does not fit this platform")?;
            let read = framed
                .read(&mut transfer[..wanted])
                .map_err(|err| format!("read stream chunk data: {err}"))?;
            if read == 0 {
                return Err("premature EOF while reading stream chunk data".to_string());
            }
            body_file
                .write_all(&transfer[..read])
                .map_err(|err| format!("write unverified stream body: {err}"))?;
            hasher.update(&transfer[..read]);
            remaining -= read as u64;
        }
        let terminator = read_crlf_line(&mut framed, 0, "stream chunk terminator")?;
        if !terminator.is_empty() {
            return Err("stream chunk data has an invalid terminator".to_string());
        }
        body_bytes = new_total;
    }
    let trailers = parse_stream_trailers(&mut framed)?;
    let mut extra = [0u8; 1];
    match framed.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err("stream response contains bytes after final trailers".to_string()),
        Err(err) => return Err(format!("check EOF after stream trailers: {err}")),
    }
    Ok(StreamResponse {
        status,
        headers,
        trailers,
        body_digest: format!("sha256:{}", hex::encode(hasher.finalize())),
        body_bytes,
    })
}

struct ResolvedOutputTarget {
    display_path: PathBuf,
    name: OsString,
    directory: Arc<PrivateOutputDirectory>,
}

impl ResolvedOutputTarget {
    fn resolve(
        path: &Path,
        label: &str,
        require_private_directory: bool,
        require_absent: bool,
    ) -> Result<Self, String> {
        Self::resolve_with_hook(
            path,
            label,
            require_private_directory,
            require_absent,
            |_, _| Ok(()),
        )
    }

    fn resolve_with_hook<F>(
        path: &Path,
        label: &str,
        require_private_directory: bool,
        require_absent: bool,
        mut after_component_open: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&OsStr, &File) -> Result<(), String>,
    {
        let absolute = path.is_absolute();
        let mut normal_components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => {}
                std::path::Component::Normal(value) => normal_components.push(value.to_os_string()),
                std::path::Component::ParentDir => {
                    return Err(format!("{label} must not contain '..' components"));
                }
                std::path::Component::Prefix(_) => {
                    return Err(format!("{label} uses an unsupported path prefix"));
                }
            }
        }
        let name = normal_components
            .pop()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{label} must name a file"))?;
        let anchor = if absolute {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(anchor)
            .map_err(|err| format!("open trusted {label} path anchor: {err}"))?;

        for component in normal_components {
            let component_c = c_entry_name(&component, label)?;
            let mut was_missing = false;
            let mut child = open_directory_at(&current, &component_c);
            if child
                .as_ref()
                .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
            {
                was_missing = true;
                let result =
                    unsafe { libc::mkdirat(current.as_raw_fd(), component_c.as_ptr(), 0o700) };
                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(format!(
                            "create private {label} directory component {}: {err}",
                            component.to_string_lossy()
                        ));
                    }
                }
                child = open_directory_at(&current, &component_c);
            }
            let child = child.map_err(|err| {
                format!(
                    "open {label} directory component {} without following symlinks: {err}",
                    component.to_string_lossy()
                )
            })?;
            let metadata = child.metadata().map_err(|err| {
                format!(
                    "inspect opened {label} directory component {}: {err}",
                    component.to_string_lossy()
                )
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "{label} directory component {} is not a directory",
                    component.to_string_lossy()
                ));
            }
            if was_missing {
                validate_private_output_directory_metadata(&metadata)?;
            }
            after_component_open(&component, &child)?;
            current = child;
        }

        let metadata = current
            .metadata()
            .map_err(|err| format!("inspect final {label} directory descriptor: {err}"))?;
        if require_private_directory {
            validate_private_output_directory_metadata(&metadata)?;
        } else if !metadata.is_dir() {
            return Err(format!("final {label} parent is not a directory"));
        }
        let directory = Arc::new(PrivateOutputDirectory::from_file(current)?);
        let target = Self {
            display_path: path.to_path_buf(),
            name,
            directory,
        };
        if require_absent {
            match target.directory.open_read(&target.name) {
                Ok(_) => return Err(format!("{label} already exists; overwrite is forbidden")),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "inspect {label} {} without following symlinks: {err}",
                        target.display_path.display()
                    ));
                }
            }
        }
        Ok(target)
    }
}

fn open_directory_at(parent: &File, name: &CStr) -> std::io::Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn output_target_aliases_path(target: &ResolvedOutputTarget, path: &Path) -> bool {
    let Ok(output) = target.directory.open_read(&target.name) else {
        return false;
    };
    let Ok(input) = File::open(path) else {
        return false;
    };
    output
        .metadata()
        .and_then(|output_metadata| {
            input.metadata().map(|input_metadata| {
                FileIdentity::from_metadata(&output_metadata)
                    == FileIdentity::from_metadata(&input_metadata)
            })
        })
        .unwrap_or(false)
}

fn validate_stream_output_paths(
    args: &Args,
) -> Result<(ResolvedOutputTarget, ResolvedOutputTarget), String> {
    let body_target = ResolvedOutputTarget::resolve(
        args.body_out
            .as_deref()
            .ok_or("--stream requires --body-out")?,
        "stream body output",
        true,
        false,
    )?;
    let proof_target = ResolvedOutputTarget::resolve(&args.out, "stream proof output", true, true)?;
    if body_target.directory.identity != proof_target.directory.identity {
        return Err(
            "--body-out and --out must resolve through directory fds to the same owner-owned 0700 directory; same-UID writers are trusted"
                .to_string(),
        );
    }
    if body_target.name == proof_target.name {
        return Err("--body-out and --out must identify distinct files".to_string());
    }
    for (path, label) in [(&args.ca, "--ca"), (&args.collector_key, "--collector-key")] {
        if output_target_aliases_path(&body_target, path)
            || output_target_aliases_path(&proof_target, path)
        {
            return Err(format!("stream output aliases {label}"));
        }
    }
    if let Some(path) = args.verifier_key.as_deref() {
        if output_target_aliases_path(&body_target, path)
            || output_target_aliases_path(&proof_target, path)
        {
            return Err("stream output aliases --verifier-key".to_string());
        }
    }
    Ok((body_target, proof_target))
}

fn c_entry_name(name: &OsStr, label: &str) -> Result<CString, String> {
    if Path::new(name).components().count() != 1 {
        return Err(format!("{label} must be a single directory entry"));
    }
    CString::new(name.as_bytes()).map_err(|_| format!("{label} contains NUL"))
}

#[cfg(target_os = "linux")]
fn atomic_rename_noreplace_at(
    directory_fd: libc::c_int,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), std::io::Error> {
    let source = c_entry_name(source, "stream source entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let destination = c_entry_name(destination, "stream destination entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let result = unsafe {
        libc::renameat2(
            directory_fd,
            source.as_ptr(),
            directory_fd,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn atomic_rename_noreplace_at(
    directory_fd: libc::c_int,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), std::io::Error> {
    let source = c_entry_name(source, "stream source entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let destination = c_entry_name(destination, "stream destination entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let result = unsafe {
        libc::renameatx_np(
            directory_fd,
            source.as_ptr(),
            directory_fd,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn atomic_rename_noreplace_at(
    directory_fd: libc::c_int,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), std::io::Error> {
    let source = c_entry_name(source, "stream source entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    let destination = c_entry_name(destination, "stream destination entry")
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    if unsafe {
        libc::linkat(
            directory_fd,
            source.as_ptr(),
            directory_fd,
            destination.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::unlinkat(directory_fd, source.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

struct StagedBody {
    target: PathBuf,
    target_name: OsString,
    directory: Arc<PrivateOutputDirectory>,
    file: Option<File>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct PrivateOutputDirectory {
    file: File,
    identity: FileIdentity,
}

impl PrivateOutputDirectory {
    fn from_file(file: File) -> Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|err| format!("read stream output directory metadata: {err}"))?;
        if !metadata.is_dir() {
            return Err("stream output directory descriptor is not a directory".to_string());
        }
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self { file, identity })
    }

    fn open_at(
        &self,
        name: &OsStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> std::io::Result<File> {
        let name = c_entry_name(name, "stream output entry")
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                libc::c_uint::from(mode),
            )
        };
        if descriptor < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    fn create_new(&self, name: &OsStr) -> std::io::Result<File> {
        self.open_at(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600)
    }

    fn open_read(&self, name: &OsStr) -> std::io::Result<File> {
        self.open_at(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
    }

    fn open_lock(&self, name: &OsStr) -> std::io::Result<File> {
        self.open_at(name, libc::O_RDWR | libc::O_CREAT, 0o600)
    }

    fn unlink(&self, name: &OsStr) -> std::io::Result<()> {
        let name = c_entry_name(name, "stream output entry")
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn rename_noreplace(&self, source: &OsStr, destination: &OsStr) -> std::io::Result<()> {
        atomic_rename_noreplace_at(self.file.as_raw_fd(), source, destination)
    }

    fn rename_replace(&self, source: &OsStr, destination: &OsStr) -> std::io::Result<()> {
        let source = c_entry_name(source, "stream source entry")
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        let destination = c_entry_name(destination, "stream destination entry")
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                destination.as_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn sync(&self) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|err| format!("sync private stream output directory: {err}"))
    }

    fn validate_body_entry(
        &self,
        name: &OsStr,
        identity: FileIdentity,
        expected_bytes: u64,
    ) -> Result<File, String> {
        let file = self.open_read(name).map_err(|err| {
            format!("open stream body output entry without following symlinks: {err}")
        })?;
        let metadata = file
            .metadata()
            .map_err(|err| format!("read stream body output descriptor metadata: {err}"))?;
        validate_private_body_metadata(&metadata, expected_bytes)?;
        if FileIdentity::from_metadata(&metadata) != identity {
            return Err("stream body output entry changed before proof commit".to_string());
        }
        Ok(file)
    }

    fn remove_owned_entry_with_hook<F>(
        &self,
        name: &OsStr,
        identity: FileIdentity,
        expected_bytes: u64,
        accepted_modes: &[u32],
        before_quarantine: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let candidate = self
            .open_read(name)
            .map_err(|err| format!("open owned stream cleanup entry: {err}"))?;
        let metadata = candidate
            .metadata()
            .map_err(|err| format!("read owned stream cleanup metadata: {err}"))?;
        validate_owned_regular_metadata(&metadata, Some(expected_bytes), accepted_modes)?;
        if FileIdentity::from_metadata(&metadata) != identity {
            return Err("stream cleanup entry identity changed before quarantine".to_string());
        }
        before_quarantine()?;
        self.quarantine_and_remove(name, identity, |metadata| {
            validate_owned_regular_metadata(metadata, Some(expected_bytes), accepted_modes)
        })
    }

    fn quarantine_and_remove<F>(
        &self,
        name: &OsStr,
        identity: FileIdentity,
        validate: F,
    ) -> Result<(), String>
    where
        F: Fn(&fs::Metadata) -> Result<(), String>,
    {
        let quarantined_name = self.allocate_renamed_entry(name, quarantine_name, "quarantine")?;
        let quarantined = self.open_read(&quarantined_name).map_err(|err| {
            format!(
                "open quarantined stream output for identity verification; entry retained: {err}"
            )
        })?;
        let metadata = quarantined.metadata().map_err(|err| {
            format!("read quarantined stream output metadata; entry retained: {err}")
        })?;
        if validate(&metadata).is_err() || FileIdentity::from_metadata(&metadata) != identity {
            let retained_name = self
                .allocate_renamed_entry(&quarantined_name, retained_name, "retained")
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|_| quarantined_name.to_string_lossy().into_owned());
            return Err(format!(
                "stream cleanup quarantined a substituted or unsafe inode; entry retained as {retained_name}"
            ));
        }
        self.unlink(&quarantined_name)
            .map_err(|err| format!("unlink verified owned stream quarantine entry: {err}"))?;
        self.sync()
    }

    fn allocate_renamed_entry<F>(
        &self,
        source: &OsStr,
        make_name: F,
        label: &str,
    ) -> Result<OsString, String>
    where
        F: Fn(u32, &[u8; 16]) -> OsString,
    {
        let rng = SystemRandom::new();
        for _ in 0..16 {
            let mut random = [0u8; 16];
            rng.fill(&mut random)
                .map_err(|_| format!("generate stream cleanup {label} name"))?;
            let candidate = make_name(std::process::id(), &random);
            match self.rename_noreplace(source, &candidate) {
                Ok(()) => return Ok(candidate),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "atomically {label} owned stream output before cleanup: {err}"
                    ));
                }
            }
        }
        Err(format!(
            "could not allocate a unique stream cleanup {label} entry"
        ))
    }

    fn scavenge_stale_entries(
        &self,
        body_name: &OsStr,
        proof_name: &OsStr,
    ) -> Result<usize, String> {
        self.scavenge_stale_entries_with_hook(body_name, proof_name, |_| Ok(()))
    }

    fn scavenge_stale_entries_with_hook<F>(
        &self,
        body_name: &OsStr,
        proof_name: &OsStr,
        mut before_quarantine: F,
    ) -> Result<usize, String>
    where
        F: FnMut(&OsStr) -> Result<(), String>,
    {
        let names = self.read_entry_names_bounded(MAX_SCAVENGE_DIRECTORY_ENTRIES)?;
        let mut removed = 0;
        for name in names {
            if removed == MAX_SCAVENGE_REMOVALS {
                break;
            }
            if name == body_name
                || name == proof_name
                || !is_scavenge_candidate(&name, body_name, proof_name)
            {
                continue;
            }
            let file = match self.open_read(&name) {
                Ok(file) => file,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::InvalidInput
                    ) =>
                {
                    continue;
                }
                Err(err) if err.raw_os_error() == Some(libc::ELOOP) => continue,
                Err(err) => {
                    return Err(format!("open stale stream cleanup candidate: {err}"));
                }
            };
            let metadata = file
                .metadata()
                .map_err(|err| format!("inspect stale stream cleanup candidate: {err}"))?;
            if validate_owned_regular_metadata(&metadata, None, &[0o600, 0o400]).is_err()
                || metadata
                    .modified()
                    .ok()
                    .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                    .is_none_or(|age| age < STALE_PUBLICATION_ENTRY_AGE)
            {
                continue;
            }
            let identity = FileIdentity::from_metadata(&metadata);
            before_quarantine(&name)?;
            self.quarantine_and_remove(&name, identity, |current| {
                validate_owned_regular_metadata(current, None, &[0o600, 0o400])
            })?;
            removed += 1;
        }
        Ok(removed)
    }

    fn read_entry_names_bounded(&self, maximum: usize) -> Result<Vec<OsString>, String> {
        let dot = c".";
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(format!(
                "open stream output directory for bounded scavenging: {}",
                std::io::Error::last_os_error()
            ));
        }
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(descriptor) };
            return Err(format!(
                "open descriptor-relative stream output enumeration: {err}"
            ));
        }
        let result = (|| {
            let mut names = Vec::new();
            while names.len() < maximum {
                clear_errno();
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error().is_some_and(|code| code != 0) {
                        return Err(format!("enumerate stream output directory: {err}"));
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    names.push(OsString::from_vec(name.to_vec()));
                }
            }
            Ok(names)
        })();
        let close_result = unsafe { libc::closedir(stream) };
        if close_result != 0 && result.is_ok() {
            return Err(format!(
                "close stream output directory enumeration: {}",
                std::io::Error::last_os_error()
            ));
        }
        result
    }
}

fn generated_target_name(
    base: &OsStr,
    process_id: u32,
    random: &[u8; 16],
    suffix: &str,
) -> OsString {
    let mut name = OsString::from(".");
    name.push(base);
    name.push(format!(".{process_id}.{}{suffix}", hex::encode(random)));
    name
}

fn verified_body_temporary_name(base: &OsStr, process_id: u32, random: &[u8; 16]) -> OsString {
    generated_target_name(base, process_id, random, ".verified.tmp")
}

fn stream_staging_temporary_name(base: &OsStr, process_id: u32, random: &[u8; 16]) -> OsString {
    generated_target_name(base, process_id, random, ".stream.tmp")
}

fn proof_temporary_name(base: &OsStr, process_id: u32, random: &[u8; 16]) -> OsString {
    generated_target_name(base, process_id, random, ".tmp")
}

fn quarantine_name(process_id: u32, random: &[u8; 16]) -> OsString {
    OsString::from(format!(
        ".serverware-quarantine.{process_id}.{}",
        hex::encode(random)
    ))
}

fn retained_name(process_id: u32, random: &[u8; 16]) -> OsString {
    OsString::from(format!(
        ".serverware-retained.{process_id}.{}",
        hex::encode(random)
    ))
}

fn has_pid_and_random(value: &[u8]) -> bool {
    let mut fields = value.split(|byte| *byte == b'.');
    let process_id = fields.next().unwrap_or_default();
    let random = fields.next().unwrap_or_default();
    fields.next().is_none()
        && !process_id.is_empty()
        && process_id.iter().all(u8::is_ascii_digit)
        && random.len() == 32
        && random
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn matches_target_generated_name(name: &OsStr, base: &OsStr, suffix: &[u8]) -> bool {
    let mut prefix = Vec::with_capacity(base.as_bytes().len() + 2);
    prefix.push(b'.');
    prefix.extend_from_slice(base.as_bytes());
    prefix.push(b'.');
    let bytes = name.as_bytes();
    bytes.starts_with(&prefix)
        && bytes.ends_with(suffix)
        && bytes.len() > prefix.len() + suffix.len()
        && has_pid_and_random(&bytes[prefix.len()..bytes.len() - suffix.len()])
}

fn is_scavenge_candidate(name: &OsStr, body_name: &OsStr, proof_name: &OsStr) -> bool {
    matches_target_generated_name(name, body_name, b".verified.tmp")
        || matches_target_generated_name(name, body_name, b".stream.tmp")
        || matches_target_generated_name(name, proof_name, b".tmp")
        || name
            .as_bytes()
            .strip_prefix(b".serverware-quarantine.")
            .is_some_and(has_pid_and_random)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

fn validate_private_output_directory_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    // Same-UID processes are explicitly inside this boundary; this does not defend against them.
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(
            "stream body and proof require one non-symlink, owner-owned exact-mode 0700 output directory; same-UID processes are trusted and must not be malicious writers"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyPublication {
    Published,
    Reused,
}

struct ReleasedBody {
    path: PathBuf,
    name: OsString,
    directory: Arc<PrivateOutputDirectory>,
    file: File,
    identity: FileIdentity,
    publication: BodyPublication,
    expected_bytes: u64,
}

impl ReleasedBody {
    fn new(
        path: PathBuf,
        name: OsString,
        directory: Arc<PrivateOutputDirectory>,
        file: File,
        publication: BodyPublication,
        expected_bytes: u64,
    ) -> Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|err| format!("read stream body descriptor metadata: {err}"))?;
        validate_private_body_metadata(&metadata, expected_bytes)?;
        let released = Self {
            path,
            name,
            directory,
            identity: FileIdentity::from_metadata(&metadata),
            file,
            publication,
            expected_bytes,
        };
        released.validate_path_identity()?;
        Ok(released)
    }

    fn validate_path_identity(&self) -> Result<(), String> {
        let descriptor_metadata = self
            .file
            .metadata()
            .map_err(|err| format!("read stream body descriptor metadata: {err}"))?;
        validate_private_body_metadata(&descriptor_metadata, self.expected_bytes)?;
        if FileIdentity::from_metadata(&descriptor_metadata) != self.identity {
            return Err("stream body descriptor identity changed before proof commit".to_string());
        }
        self.directory
            .validate_body_entry(&self.name, self.identity, self.expected_bytes)?;
        Ok(())
    }

    fn remove_owned_unpublished(self) -> Result<(), String> {
        self.remove_owned_unpublished_with_prequarantine(|| Ok(()))
    }

    fn remove_owned_unpublished_with_prequarantine<F>(
        self,
        before_quarantine: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        if self.publication == BodyPublication::Reused {
            return Ok(());
        }
        self.directory.remove_owned_entry_with_hook(
            &self.name,
            self.identity,
            self.expected_bytes,
            &[0o400],
            before_quarantine,
        )
    }
}

struct PublicationLock {
    _file: File,
}

impl PublicationLock {
    fn acquire(directory: &PrivateOutputDirectory, file_name: &OsStr) -> Result<Self, String> {
        let mut lock_name = OsString::from(".");
        lock_name.push(file_name);
        lock_name.push(".serverware-proof.lock");
        let file = directory
            .open_lock(&lock_name)
            .map_err(|err| format!("open stream publication lock: {err}"))?;
        validate_private_lock_metadata(
            &file
                .metadata()
                .map_err(|err| format!("read stream publication lock metadata: {err}"))?,
        )?;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("lock stream output publication: {err}"));
            }
        }
        let descriptor_metadata = file
            .metadata()
            .map_err(|err| format!("revalidate stream publication lock metadata: {err}"))?;
        validate_private_lock_metadata(&descriptor_metadata)?;
        let path_file = directory
            .open_read(&lock_name)
            .map_err(|err| format!("reopen stream publication lock entry: {err}"))?;
        let path_metadata = path_file
            .metadata()
            .map_err(|err| format!("revalidate stream publication lock entry: {err}"))?;
        validate_private_lock_metadata(&path_metadata)?;
        if FileIdentity::from_metadata(&descriptor_metadata)
            != FileIdentity::from_metadata(&path_metadata)
        {
            return Err("stream publication lock path changed while acquiring lock".to_string());
        }
        Ok(Self { _file: file })
    }
}

fn validate_private_lock_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("stream publication lock is not a private regular file".to_string());
    }
    Ok(())
}

fn validate_private_body_metadata(
    metadata: &fs::Metadata,
    expected_bytes: u64,
) -> Result<(), String> {
    validate_owned_regular_metadata(metadata, Some(expected_bytes), &[0o400]).map_err(|_| {
        "verified stream body is not an owner-owned, single-link, read-only regular file"
            .to_string()
    })
}

fn validate_recovery_body_metadata(
    metadata: &fs::Metadata,
    expected_bytes: u64,
) -> Result<(), String> {
    validate_owned_regular_metadata(metadata, Some(expected_bytes), &[0o600, 0o400])
        .map_err(|_| "existing stream body is not a private regular recovery candidate".to_string())
}

fn validate_owned_regular_metadata(
    metadata: &fs::Metadata,
    expected_bytes: Option<u64>,
    accepted_modes: &[u32],
) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || expected_bytes.is_some_and(|bytes| metadata.len() != bytes)
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || !accepted_modes.contains(&(metadata.mode() & 0o777))
    {
        return Err("stream output entry failed owner/type/link-count/mode validation".to_string());
    }
    Ok(())
}

impl StagedBody {
    #[cfg(test)]
    fn create(target: PathBuf) -> Result<Self, String> {
        let target = ResolvedOutputTarget::resolve(&target, "stream body output", true, false)?;
        Self::create_resolved(target)
    }

    fn create_resolved(target: ResolvedOutputTarget) -> Result<Self, String> {
        let rng = SystemRandom::new();
        for _ in 0..16 {
            let mut random = [0u8; 16];
            rng.fill(&mut random)
                .map_err(|_| "generate stream temporary file name".to_string())?;
            let temporary =
                stream_staging_temporary_name(&target.name, std::process::id(), &random);
            match target.directory.create_new(&temporary) {
                Ok(file) => {
                    target
                        .directory
                        .unlink(&temporary)
                        .map_err(|err| format!("unlink private stream staging entry: {err}"))?;
                    return Ok(Self {
                        target: target.display_path,
                        target_name: target.name,
                        directory: target.directory,
                        file: Some(file),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "create private stream temporary entry {}: {err}",
                        temporary.to_string_lossy()
                    ))
                }
            }
        }
        Err("could not create a unique stream temporary file".to_string())
    }

    fn file_mut(&mut self) -> Result<&mut File, String> {
        self.file
            .as_mut()
            .ok_or("stream body staging file is closed".to_string())
    }

    fn sync(&mut self) -> Result<(), String> {
        self.file_mut()?
            .sync_all()
            .map_err(|err| format!("sync unverified stream body: {err}"))
    }

    fn release(
        mut self,
        expected_digest: &str,
        expected_bytes: u64,
    ) -> Result<ReleasedBody, String> {
        self.sync()?;
        let target = self.target.clone();
        match self.directory.open_read(&self.target_name) {
            Ok(mut existing) => {
                let metadata = existing
                    .metadata()
                    .map_err(|err| format!("read existing stream body metadata: {err}"))?;
                validate_recovery_body_metadata(&metadata, expected_bytes)?;
                let identity = FileIdentity::from_metadata(&metadata);
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    let read = existing
                        .read(&mut buffer)
                        .map_err(|err| format!("hash existing stream body candidate: {err}"))?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
                if digest != expected_digest {
                    return Err(
                        "existing stream body does not match the newly verified response"
                            .to_string(),
                    );
                }
                existing
                    .set_permissions(fs::Permissions::from_mode(0o400))
                    .map_err(|err| format!("make recovered stream body read-only: {err}"))?;
                existing.sync_all().map_err(|err| {
                    format!("durably sync recovered read-only stream body: {err}")
                })?;
                self.directory
                    .validate_body_entry(&self.target_name, identity, expected_bytes)?;
                let released = ReleasedBody::new(
                    target,
                    self.target_name.clone(),
                    Arc::clone(&self.directory),
                    existing,
                    BodyPublication::Reused,
                    expected_bytes,
                )?;
                self.file.take();
                return Ok(released);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "open existing stream body candidate without following symlinks: {err}"
                ))
            }
        }
        self.file_mut()?
            .seek(SeekFrom::Start(0))
            .map_err(|err| format!("rewind verified stream body: {err}"))?;
        let rng = SystemRandom::new();
        let mut temporary_output = None;
        for _ in 0..16 {
            let mut random = [0u8; 16];
            rng.fill(&mut random)
                .map_err(|_| "generate verified stream body temporary name".to_string())?;
            let name = verified_body_temporary_name(&self.target_name, std::process::id(), &random);
            match self.directory.create_new(&name) {
                Ok(file) => {
                    temporary_output = Some((name, file));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "create verified stream body temporary entry: {err}"
                    ))
                }
            }
        }
        let (temporary, mut output) = temporary_output
            .ok_or("could not create a unique verified stream body temporary file")?;
        let temporary_identity = FileIdentity::from_metadata(
            &output
                .metadata()
                .map_err(|err| format!("read verified stream temporary metadata: {err}"))?,
        );
        if let Err(err) = std::io::copy(self.file_mut()?, &mut output)
            .map_err(|err| format!("copy verified stream body: {err}"))
            .and_then(|copied| {
                if copied != expected_bytes {
                    return Err(format!(
                        "verified stream body byte count changed before publication: expected {expected_bytes}, copied {copied}"
                    ));
                }
                output
                    .set_permissions(fs::Permissions::from_mode(0o400))
                    .map_err(|err| format!("make verified stream body read-only: {err}"))?;
                output
                    .sync_all()
                    .map_err(|err| format!("durably sync read-only verified stream body: {err}"))
            })
            .and_then(|_| {
                self.directory
                    .rename_noreplace(&temporary, &self.target_name)
                    .map_err(|err| format!("atomically publish verified stream body: {err}"))
            })
        {
            let temporary_bytes = output
                .metadata()
                .map(|metadata| metadata.len())
                .unwrap_or(expected_bytes);
            let _ = self.directory.remove_owned_entry_with_hook(
                &temporary,
                temporary_identity,
                temporary_bytes,
                &[0o600, 0o400],
                || Ok(()),
            );
            return Err(err);
        }
        drop(output);
        let output = self.directory.validate_body_entry(
            &self.target_name,
            temporary_identity,
            expected_bytes,
        )?;
        let released = ReleasedBody::new(
            target,
            self.target_name.clone(),
            Arc::clone(&self.directory),
            output,
            BodyPublication::Published,
            expected_bytes,
        )?;
        if let Err(err) = self.directory.sync() {
            return match released.remove_owned_unpublished() {
                Ok(()) => Err(err),
                Err(cleanup_err) => Err(format!(
                    "{err}; cleanup uncommitted verified body failed: {cleanup_err}"
                )),
            };
        }
        self.file.take();
        Ok(released)
    }
}

fn load_roots(path: &PathBuf) -> Result<RootCertStore, String> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|err| format!("open CA bundle {}: {err}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse CA bundle {}: {err}", path.display()))?;
    if certificates.is_empty() {
        return Err("CA bundle contains no certificates".to_string());
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|err| format!("add CA certificate: {err}"))?;
    }
    Ok(roots)
}

fn decode_public_key_pem(pem: &str) -> Result<(VerifyingKey, String), String> {
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "response proof signing key PEM is invalid")?;
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    if der.len() != PREFIX.len() + 32 || der[..PREFIX.len()] != PREFIX {
        return Err("response proof signing key is not Ed25519 SPKI".to_string());
    }
    let key_bytes: [u8; 32] = der[PREFIX.len()..]
        .try_into()
        .map_err(|_| "response proof Ed25519 key is invalid")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "response proof Ed25519 key is invalid")?;
    Ok((key, sha256_prefixed(&der)))
}

fn public_key_material(signing_key: &SigningKey) -> (String, String) {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&signing_key.verifying_key().to_bytes());
    let encoded = general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    (pem, sha256_prefixed(&der))
}

fn load_collector_key(path: &PathBuf) -> Result<SigningKey, String> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("read collector key metadata {}: {err}", path.display()))?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err("collector private key must be a regular non-symlink file".to_string());
    }
    if link_metadata.permissions().mode() & 0o077 != 0 {
        return Err("collector private key must not be accessible by group or other".to_string());
    }
    let pem = fs::read_to_string(path)
        .map_err(|err| format!("read collector key {}: {err}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem)
        .map_err(|err| format!("parse Ed25519 collector private key: {err}"))
}

fn load_verifier_key(path: &Path) -> Result<(VerifyingKey, String), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("read verifier key metadata {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("vendor verifier public key must be a regular non-symlink file".to_string());
    }
    let pem = fs::read_to_string(path)
        .map_err(|err| format!("read verifier key {}: {err}", path.display()))?;
    decode_public_key_pem(&pem)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn required_digest<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    required_string(value, field).and_then(|digest| {
        is_sha256_digest(digest)
            .then_some(digest)
            .ok_or_else(|| format!("runtime proof field {field} is not a canonical SHA-256 digest"))
    })
}

fn decode_base64url(value: &str, label: &str, minimum: usize) -> Result<Vec<u8>, String> {
    if value.contains('=') {
        return Err(format!("{label} must use unpadded base64url"));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| format!("{label} is not valid base64url"))?;
    if decoded.len() < minimum {
        return Err(format!("{label} must contain at least {minimum} bytes"));
    }
    Ok(decoded)
}

fn verify_ed25519_value(
    key: &VerifyingKey,
    signature_value: &str,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let encoded = signature_value
        .strip_prefix("ed25519:")
        .ok_or_else(|| format!("{label} must use ed25519"))?;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| format!("{label} is invalid base64url"))?;
    let signature: [u8; 64] = decoded
        .try_into()
        .map_err(|_| format!("{label} must contain 64 bytes"))?;
    key.verify(payload, &Signature::from_bytes(&signature))
        .map_err(|_| format!("{label} verification failed"))
}

fn production_identifier(value: &str, label: &str) -> Result<(), String> {
    let lowered = value.to_ascii_lowercase();
    if value.is_empty()
        || ["dev", "fixture", "mock", "test", "none"]
            .iter()
            .any(|marker| lowered.contains(marker))
    {
        return Err(format!("{label} is not a production identifier"));
    }
    Ok(())
}

fn atomic_write_private_with_mode(
    path: &Path,
    payload: &[u8],
    replace_existing: bool,
) -> Result<(), String> {
    let target = ResolvedOutputTarget::resolve(path, "proof output", false, false)?;
    let rng = SystemRandom::new();
    let mut temporary_file = None;
    for _ in 0..16 {
        let mut random = [0u8; 16];
        rng.fill(&mut random)
            .map_err(|_| "generate proof temporary file name".to_string())?;
        let temporary = proof_temporary_name(&target.name, std::process::id(), &random);
        match target.directory.create_new(&temporary) {
            Ok(file) => {
                temporary_file = Some((temporary, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("create proof temporary entry: {err}")),
        }
    }
    let (temporary, mut file) =
        temporary_file.ok_or("could not create a unique proof temporary file")?;
    let identity = FileIdentity::from_metadata(
        &file
            .metadata()
            .map_err(|err| format!("read proof temporary metadata: {err}"))?,
    );
    let result = (|| -> Result<(), String> {
        file.write_all(payload)
            .map_err(|err| format!("write proof temporary file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("sync proof temporary file: {err}"))?;
        if replace_existing {
            target
                .directory
                .rename_replace(&temporary, &target.name)
                .map_err(|err| format!("replace proof output {}: {err}", path.display()))?;
        } else {
            target
                .directory
                .rename_noreplace(&temporary, &target.name)
                .map_err(|err| format!("publish proof output without replacement: {err}"))?;
        }
        target.directory.sync()
    })();
    if result.is_err() {
        let temporary_bytes = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let _ = target.directory.remove_owned_entry_with_hook(
            &temporary,
            identity,
            temporary_bytes,
            &[0o600],
            || Ok(()),
        );
    }
    result
}

fn atomic_write_private(path: &Path, payload: &[u8]) -> Result<(), String> {
    atomic_write_private_with_mode(path, payload, true)
}

#[derive(Debug)]
struct NoReplacePublishError {
    message: String,
    destination_published: bool,
}

#[cfg(test)]
fn atomic_write_private_noreplace(
    path: &Path,
    payload: &[u8],
) -> Result<(), NoReplacePublishError> {
    atomic_write_private_noreplace_with_precommit(path, payload, || Ok(()))
}

#[cfg(test)]
fn atomic_write_private_noreplace_with_precommit<F>(
    path: &Path,
    payload: &[u8],
    precommit: F,
) -> Result<(), NoReplacePublishError>
where
    F: FnOnce() -> Result<(), String>,
{
    let target = ResolvedOutputTarget::resolve(path, "stream proof output", true, false).map_err(
        |message| NoReplacePublishError {
            message,
            destination_published: false,
        },
    )?;
    atomic_write_private_noreplace_in_directory_with_precommit(
        &target.directory,
        &target.name,
        payload,
        precommit,
    )
}

fn atomic_write_private_noreplace_in_directory_with_precommit<F>(
    directory: &PrivateOutputDirectory,
    destination: &OsStr,
    payload: &[u8],
    precommit: F,
) -> Result<(), NoReplacePublishError>
where
    F: FnOnce() -> Result<(), String>,
{
    let rng = SystemRandom::new();
    let mut temporary_file = None;
    for _ in 0..16 {
        let mut random = [0u8; 16];
        rng.fill(&mut random).map_err(|_| NoReplacePublishError {
            message: "generate proof temporary file name".to_string(),
            destination_published: false,
        })?;
        let temporary = proof_temporary_name(destination, std::process::id(), &random);
        match directory.create_new(&temporary) {
            Ok(file) => {
                temporary_file = Some((temporary, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(NoReplacePublishError {
                    message: format!("create proof temporary entry: {err}"),
                    destination_published: false,
                })
            }
        }
    }
    let (temporary, mut file) = temporary_file.ok_or_else(|| NoReplacePublishError {
        message: "could not create a unique proof temporary file".to_string(),
        destination_published: false,
    })?;
    let temporary_identity = file
        .metadata()
        .map(|metadata| FileIdentity::from_metadata(&metadata))
        .map_err(|err| NoReplacePublishError {
            message: format!("read proof temporary descriptor metadata: {err}"),
            destination_published: false,
        })?;
    let mut destination_published = false;
    let result = (|| -> Result<(), String> {
        file.write_all(payload)
            .map_err(|err| format!("write proof temporary file: {err}"))?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|err| format!("make verified stream proof read-only: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("durably sync read-only stream proof: {err}"))?;
        precommit()?;
        directory
            .rename_noreplace(&temporary, destination)
            .map_err(|err| format!("atomically publish verified stream proof: {err}"))?;
        destination_published = true;
        directory.sync()
    })();
    if let Err(message) = result {
        if !destination_published {
            let temporary_bytes = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            if let Err(cleanup_err) = directory.remove_owned_entry_with_hook(
                &temporary,
                temporary_identity,
                temporary_bytes,
                &[0o600, 0o400],
                || Ok(()),
            ) {
                return Err(NoReplacePublishError {
                    message: format!(
                        "{message}; cleanup proof temporary entry failed: {cleanup_err}"
                    ),
                    destination_published,
                });
            }
        }
        return Err(NoReplacePublishError {
            message,
            destination_published,
        });
    }
    Ok(())
}

#[cfg(test)]
fn publish_verified_stream_outputs(
    staged_body: StagedBody,
    proof_path: &Path,
    proof_payload: &[u8],
    expected_body_digest: &str,
    expected_body_bytes: u64,
) -> Result<PathBuf, String> {
    let proof_target =
        ResolvedOutputTarget::resolve(proof_path, "stream proof output", true, false)?;
    publish_verified_stream_outputs_resolved_with_precommit(
        staged_body,
        proof_target,
        proof_payload,
        expected_body_digest,
        expected_body_bytes,
        || Ok(()),
    )
}

#[cfg(test)]
fn publish_verified_stream_outputs_with_precommit<F>(
    staged_body: StagedBody,
    proof_path: &Path,
    proof_payload: &[u8],
    expected_body_digest: &str,
    expected_body_bytes: u64,
    before_body_revalidation: F,
) -> Result<PathBuf, String>
where
    F: FnOnce() -> Result<(), String>,
{
    let proof_target =
        ResolvedOutputTarget::resolve(proof_path, "stream proof output", true, false)?;
    publish_verified_stream_outputs_resolved_with_precommit(
        staged_body,
        proof_target,
        proof_payload,
        expected_body_digest,
        expected_body_bytes,
        before_body_revalidation,
    )
}

fn publish_verified_stream_outputs_resolved(
    staged_body: StagedBody,
    proof_target: ResolvedOutputTarget,
    proof_payload: &[u8],
    expected_body_digest: &str,
    expected_body_bytes: u64,
) -> Result<PathBuf, String> {
    publish_verified_stream_outputs_resolved_with_precommit(
        staged_body,
        proof_target,
        proof_payload,
        expected_body_digest,
        expected_body_bytes,
        || Ok(()),
    )
}

fn publish_verified_stream_outputs_resolved_with_precommit<F>(
    staged_body: StagedBody,
    proof_target: ResolvedOutputTarget,
    proof_payload: &[u8],
    expected_body_digest: &str,
    expected_body_bytes: u64,
    before_body_revalidation: F,
) -> Result<PathBuf, String>
where
    F: FnOnce() -> Result<(), String>,
{
    if proof_target.directory.identity != staged_body.directory.identity {
        return Err(
            "stream body and proof must resolve through directory fds to the same owner-owned exact-mode 0700 output directory; same-UID writers are trusted"
                .to_string(),
        );
    }
    let _publication_lock =
        PublicationLock::acquire(&staged_body.directory, &staged_body.target_name)?;
    staged_body
        .directory
        .scavenge_stale_entries(&staged_body.target_name, &proof_target.name)?;
    let released_body = staged_body.release(expected_body_digest, expected_body_bytes)?;
    let body_path = released_body.path.clone();
    if let Err(err) = atomic_write_private_noreplace_in_directory_with_precommit(
        &released_body.directory,
        &proof_target.name,
        proof_payload,
        || {
            released_body.validate_path_identity()?;
            before_body_revalidation()?;
            released_body.validate_path_identity()
        },
    ) {
        if err.destination_published {
            return Err(format!(
                "{}; proof and verified body retained because the proof destination was published",
                err.message
            ));
        }
        return match released_body.remove_owned_unpublished() {
            Ok(()) => Err(err.message),
            Err(cleanup_err) => Err(format!(
                "{}; remove owned verified body after proof publication failure: {cleanup_err}",
                err.message
            )),
        };
    }
    Ok(body_path)
}

fn peer_identity(
    tls: &StreamOwned<ClientConnection, TcpStream>,
) -> Result<(String, String), String> {
    let certificate = tls
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or("TLS peer did not present a leaf certificate")?;
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|err| format!("parse TLS peer leaf certificate: {err}"))?;
    let san = parsed
        .subject_alternative_name()
        .map_err(|err| format!("parse TLS peer subjectAltName: {err}"))?
        .ok_or("TLS peer certificate has no subjectAltName")?;
    let spiffe_ids = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(value) if value.starts_with("spiffe://") => Some((*value).to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if spiffe_ids.len() != 1 {
        return Err("TLS peer certificate must contain exactly one SPIFFE URI SAN".to_string());
    }
    Ok((spiffe_ids[0].clone(), sha256_prefixed(certificate.as_ref())))
}

fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("runtime proof is missing object {field}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("runtime proof is missing string {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("runtime proof is missing integer {field}"))
}

fn require_exact_fields(
    object: &Map<String, Value>,
    fields: &[&str],
    label: &str,
) -> Result<(), String> {
    if object.len() != fields.len()
        || object.keys().any(|field| !fields.contains(&field.as_str()))
        || fields.iter().any(|field| !object.contains_key(*field))
    {
        return Err(format!("{label} has missing or unexpected fields"));
    }
    Ok(())
}

fn validate_strict_response_statement(statement: &Value) -> Result<(), String> {
    let typed: ProxyResponseStatement = serde_json::from_value(statement.clone())
        .map_err(|err| format!("server response statement schema is invalid: {err}"))?;
    validate_response_statement(&typed)
        .map_err(|err| format!("server response statement contract is invalid: {err}"))
}

fn validated_control_plane_authorization_receipt(statement: &Value) -> Result<Value, String> {
    const FIELDS: [&str; 7] = [
        "apiVersion",
        "kind",
        "principal_id",
        "route_id",
        "release_authority",
        "request",
        "response",
    ];
    let receipt = required_object(statement, "control_plane_authorization_receipt")?;
    if receipt.len() != FIELDS.len()
        || receipt
            .keys()
            .any(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err("control-plane authorization receipt has unexpected fields".to_string());
    }
    Ok(Value::Object(receipt.clone()))
}

fn optional_authority_identifier(
    authority: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    match authority.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if !value.is_empty()
                && value == value.trim()
                && value.len() <= 256
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value.clone()))
        }
        _ => Err(format!(
            "server response release authority {field} is invalid"
        )),
    }
}

fn validated_release_authority(statement: &Value) -> Result<Value, String> {
    const FIELDS: [&str; 13] = [
        "authority_mode",
        "grant_id",
        "approval_id",
        "credential_ref",
        "credential_version",
        "request_digest",
        "operation_digest",
        "attempt_id",
        "consumption_identity_digest",
        "authorization_state_at_upstream_dispatch",
        "authorization_state_observed_at_epoch_ms",
        "reservation_expires_at_epoch_ms",
        "dispatch_expires_at_epoch_ms",
    ];
    let authority = required_object(statement, "release_authority")?;
    if authority.len() != FIELDS.len()
        || authority
            .keys()
            .any(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err("server response release authority has unexpected fields".to_string());
    }
    if authority.get("authority_mode").and_then(Value::as_str) != Some("atomic") {
        return Err("server response release authority is not atomic".to_string());
    }
    let grant_id = optional_authority_identifier(authority, "grant_id")?;
    let approval_id = optional_authority_identifier(authority, "approval_id")?;
    if grant_id.is_some() != approval_id.is_some() {
        return Err("server response release grant and approval IDs must be paired".to_string());
    }
    let credential_ref = optional_authority_identifier(authority, "credential_ref")?;
    let authority_value = Value::Object(authority.clone());
    let credential_version = required_u64(&authority_value, "credential_version")?;
    if credential_ref.is_some() != (credential_version > 0) {
        return Err("server response credential identity and version are inconsistent".to_string());
    }
    let request_digest = required_digest(&authority_value, "request_digest")?;
    let operation_digest = required_digest(&authority_value, "operation_digest")?;
    if statement.get("request_digest").and_then(Value::as_str) != Some(request_digest)
        || statement.get("operation_digest").and_then(Value::as_str) != Some(operation_digest)
    {
        return Err("server response release authority digest mismatch".to_string());
    }
    required_digest(&authority_value, "attempt_id")?;
    required_digest(&authority_value, "consumption_identity_digest")?;
    if authority
        .get("authorization_state_at_upstream_dispatch")
        .and_then(Value::as_str)
        != Some("dispatching")
    {
        return Err(
            "server response release authorization was not dispatching at upstream dispatch"
                .to_string(),
        );
    }
    let observed_at = required_u64(&authority_value, "authorization_state_observed_at_epoch_ms")?;
    let dispatch_expires_at = required_u64(&authority_value, "dispatch_expires_at_epoch_ms")?;
    let reservation_expires_at = match authority.get("reservation_expires_at_epoch_ms") {
        Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or(
            "server response release authority reservation expiry is invalid".to_string(),
        )?),
        None => {
            return Err(
                "server response release authority reservation expiry is missing".to_string(),
            )
        }
    };
    let issued_at = required_u64(statement, "issued_at_unix")?;
    let statement_end_epoch_ms = issued_at
        .saturating_add(1)
        .saturating_mul(1000)
        .saturating_sub(1);
    if observed_at == 0
        || dispatch_expires_at <= observed_at
        || observed_at > statement_end_epoch_ms
        || reservation_expires_at.is_some_and(|expires_at| observed_at >= expires_at)
    {
        return Err(
            "server response release authorization observation is temporally invalid".to_string(),
        );
    }
    Ok(authority_value)
}

fn validated_upstream_response(statement: &Value) -> Result<Value, String> {
    let upstream = required_object(statement, "upstream_response")?;
    if upstream.len() != 4
        || upstream.keys().any(|field| {
            !matches!(
                field.as_str(),
                "status" | "selected_raw_policy_headers_b64" | "body_digest" | "canonical_digest"
            )
        })
    {
        return Err("server response upstream binding has unexpected fields".to_string());
    }
    let upstream_value = Value::Object(upstream.clone());
    let status = required_u64(&upstream_value, "status")?;
    if !(100..=599).contains(&status)
        || required_object(statement, "response")?
            .get("status")
            .and_then(Value::as_u64)
            != Some(status)
    {
        return Err("server response upstream status binding mismatch".to_string());
    }
    let body_digest = required_digest(&upstream_value, "body_digest")?;
    required_digest(&upstream_value, "canonical_digest")?;
    let selected = required_object(&upstream_value, "selected_raw_policy_headers_b64")?;
    const REQUIRED_HEADERS: [&str; 3] = ["content-encoding", "content-length", "content-type"];
    const ALLOWED_HEADERS: [&str; 9] = [
        "cache-control",
        "content-encoding",
        "content-language",
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "retry-after",
        "www-authenticate",
    ];
    if REQUIRED_HEADERS
        .iter()
        .any(|name| !selected.contains_key(*name))
    {
        return Err("server response upstream raw header binding is incomplete".to_string());
    }
    for (name, values) in selected {
        if !ALLOWED_HEADERS.contains(&name.as_str()) {
            return Err(format!(
                "server response upstream raw header binding contains unsupported header {name}"
            ));
        }
        let values = values
            .as_array()
            .filter(|values| values.len() <= 128)
            .ok_or_else(|| {
                format!("server response upstream raw header {name} has invalid values")
            })?;
        for value in values {
            let encoded = value.as_str().ok_or_else(|| {
                format!("server response upstream raw header {name} is not base64url")
            })?;
            let decoded = decode_base64url(encoded, "server response upstream raw header", 0)?;
            if decoded.len() > 8 * 1024
                || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != encoded
            {
                return Err(format!(
                    "server response upstream raw header {name} is not canonical"
                ));
            }
        }
    }
    let canonical = json!({
        "status":status,
        "selected_raw_policy_headers_b64":selected,
        "body_digest":body_digest,
    });
    let canonical_digest = sha256_prefixed(canonical_json(&canonical).as_bytes());
    if upstream.get("canonical_digest").and_then(Value::as_str) != Some(canonical_digest.as_str()) {
        return Err("server response upstream canonical digest mismatch".to_string());
    }
    Ok(upstream_value)
}

fn validated_streaming_upstream_response(statement: &Value) -> Result<Value, String> {
    const FIELDS: [&str; 5] = [
        "status",
        "selected_raw_policy_headers_b64",
        "body_digest",
        "body_bytes",
        "canonical_digest",
    ];
    let upstream = required_object(statement, "upstream_response")?;
    require_exact_fields(upstream, &FIELDS, "streaming upstream response binding")?;
    let upstream_value = Value::Object(upstream.clone());
    let status = required_u64(&upstream_value, "status")?;
    if !(100..=599).contains(&status)
        || required_object(statement, "released_response")?
            .get("status")
            .and_then(Value::as_u64)
            != Some(status)
    {
        return Err("streaming upstream response status binding mismatch".to_string());
    }
    let body_digest = required_digest(&upstream_value, "body_digest")?;
    let body_bytes = required_u64(&upstream_value, "body_bytes")?;
    required_digest(&upstream_value, "canonical_digest")?;
    let selected = required_object(&upstream_value, "selected_raw_policy_headers_b64")?;
    const REQUIRED_HEADERS: [&str; 3] = ["content-encoding", "content-length", "content-type"];
    const ALLOWED_HEADERS: [&str; 9] = [
        "cache-control",
        "content-encoding",
        "content-language",
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "retry-after",
        "www-authenticate",
    ];
    if REQUIRED_HEADERS
        .iter()
        .any(|name| !selected.contains_key(*name))
    {
        return Err("streaming upstream raw header binding is incomplete".to_string());
    }
    for (name, values) in selected {
        if !ALLOWED_HEADERS.contains(&name.as_str()) {
            return Err(format!(
                "streaming upstream raw header binding contains unsupported header {name}"
            ));
        }
        let values = values
            .as_array()
            .filter(|values| values.len() <= 128)
            .ok_or_else(|| format!("streaming upstream raw header {name} has invalid values"))?;
        for value in values {
            let encoded = value
                .as_str()
                .ok_or_else(|| format!("streaming upstream raw header {name} is not base64url"))?;
            let decoded = decode_base64url(encoded, "streaming upstream raw header", 0)?;
            if decoded.len() > 8 * 1024
                || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != encoded
            {
                return Err(format!(
                    "streaming upstream raw header {name} is not canonical"
                ));
            }
        }
    }
    let canonical = json!({
        "status":status,
        "selected_raw_policy_headers_b64":selected,
        "body_digest":body_digest,
        "body_bytes":body_bytes,
    });
    let canonical_digest = sha256_prefixed(canonical_json(&canonical).as_bytes());
    if upstream.get("canonical_digest").and_then(Value::as_str) != Some(canonical_digest.as_str()) {
        return Err("streaming upstream canonical digest mismatch".to_string());
    }
    Ok(upstream_value)
}

fn valid_bounded_identity(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
}

fn validate_streaming_authorization_binding(statement: &Value) -> Result<Value, String> {
    const VALIDATION_FIELDS: [&str; 3] = ["status", "binding_commitment", "binding_digest"];
    const BINDING_FIELDS: [&str; 12] = [
        "attempt_id",
        "flow_id",
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "request_digest",
        "operation_digest",
        "operation_context_digest",
        "require_jit_grant",
        "shared_quotas",
    ];
    const FIXED_QUOTA_FIELDS: [&str; 6] = [
        "counter_key",
        "constraint_id",
        "operation",
        "window_kind",
        "window_seconds",
        "max_count",
    ];
    const CALENDAR_QUOTA_FIELDS: [&str; 5] = [
        "counter_key",
        "constraint_id",
        "operation",
        "window_kind",
        "max_count",
    ];
    let validation = required_object(statement, "authorization_binding_validation")?;
    require_exact_fields(
        validation,
        &VALIDATION_FIELDS,
        "streaming authorization binding validation",
    )?;
    if validation.get("status").and_then(Value::as_str) != Some("validated") {
        return Err("streaming authorization binding was not validated".to_string());
    }
    let binding = validation
        .get("binding_commitment")
        .and_then(Value::as_object)
        .ok_or("streaming authorization binding commitment is not an object")?;
    require_exact_fields(
        binding,
        &BINDING_FIELDS,
        "streaming authorization binding commitment",
    )?;
    let binding_value = Value::Object(binding.clone());
    let binding_digest = validation
        .get("binding_digest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or("streaming authorization binding digest is invalid")?;
    let authority = required_object(statement, "release_authority")?;
    if authority
        .get("consumption_identity_digest")
        .and_then(Value::as_str)
        != Some(binding_digest)
    {
        return Err("streaming authorization binding digest mismatch".to_string());
    }
    let expected_credential_id = authority
        .get("credential_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    for (field, expected) in [
        (
            "attempt_id",
            authority.get("attempt_id").and_then(Value::as_str),
        ),
        (
            "flow_id",
            authority.get("attempt_id").and_then(Value::as_str),
        ),
        (
            "principal_id",
            statement.get("principal_id").and_then(Value::as_str),
        ),
        (
            "route_id",
            statement.get("route_id").and_then(Value::as_str),
        ),
        ("credential_id", Some(expected_credential_id)),
        (
            "policy_hash",
            statement.get("policy_digest").and_then(Value::as_str),
        ),
        (
            "request_digest",
            statement.get("request_digest").and_then(Value::as_str),
        ),
        (
            "operation_digest",
            statement.get("operation_digest").and_then(Value::as_str),
        ),
    ] {
        let expected =
            expected.ok_or_else(|| format!("streaming binding source {field} missing"))?;
        if binding.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "streaming authorization binding {field} claim substitution"
            ));
        }
    }
    if binding.get("credential_version").and_then(Value::as_u64)
        != authority.get("credential_version").and_then(Value::as_u64)
        || binding
            .get("operation_context_digest")
            .and_then(Value::as_str)
            .is_none_or(|value| !is_sha256_digest(value))
        || binding
            .get("require_jit_grant")
            .and_then(Value::as_bool)
            .is_none()
    {
        return Err("streaming authorization binding context is invalid".to_string());
    }
    let quotas = binding
        .get("shared_quotas")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 256)
        .ok_or("streaming authorization binding shared_quotas is invalid")?;
    let mut previous_counter_key: Option<&str> = None;
    for quota in quotas {
        let quota = quota
            .as_object()
            .ok_or("streaming authorization binding quota is not an object")?;
        let window_kind = quota
            .get("window_kind")
            .and_then(Value::as_str)
            .ok_or("streaming authorization binding quota window_kind is invalid")?;
        let quota_fields = match window_kind {
            "fixed" => &FIXED_QUOTA_FIELDS[..],
            "utcDay" | "utcIsoWeek" | "utcMonth" => &CALENDAR_QUOTA_FIELDS[..],
            _ => {
                return Err(
                    "streaming authorization binding quota window_kind is invalid".to_string(),
                )
            }
        };
        require_exact_fields(quota, quota_fields, "streaming authorization binding quota")?;
        let counter_key = quota
            .get("counter_key")
            .and_then(Value::as_str)
            .filter(|value| is_sha256_digest(value))
            .ok_or("streaming authorization binding quota counter_key is invalid")?;
        let constraint_id = quota
            .get("constraint_id")
            .and_then(Value::as_str)
            .filter(|value| valid_bounded_identity(value))
            .ok_or("streaming authorization binding quota constraint_id is invalid")?;
        let _ = constraint_id;
        match quota.get("operation") {
            Some(Value::Null) => {}
            Some(Value::String(value)) if valid_bounded_identity(value) => {}
            _ => {
                return Err("streaming authorization binding quota operation is invalid".to_string())
            }
        }
        let window_is_valid = match window_kind {
            "fixed" => quota
                .get("window_seconds")
                .and_then(Value::as_u64)
                .is_some_and(|value| (1..=31_536_000).contains(&value)),
            "utcDay" | "utcIsoWeek" | "utcMonth" => !quota.contains_key("window_seconds"),
            _ => false,
        };
        if !window_is_valid
            || !(1..=1_000_000_000)
                .contains(&quota.get("max_count").and_then(Value::as_u64).unwrap_or(0))
            || previous_counter_key.is_some_and(|previous| previous >= counter_key)
        {
            return Err("streaming authorization binding quota is invalid".to_string());
        }
        previous_counter_key = Some(counter_key);
    }
    Ok(binding_value)
}

fn validate_streaming_statement_with_shared_contract(statement: &Value) -> Result<(), String> {
    const STATEMENT_FIELDS: [&str; 20] = [
        "apiVersion",
        "issued_at_unix",
        "client_nonce",
        "client_request_digest",
        "principal_id",
        "route_id",
        "request_digest",
        "operation_digest",
        "release_authority",
        "authorization_binding_validation",
        "control_plane_authorization_receipt",
        "control_plane_authorization_receipt_sha256",
        "upstream_response",
        "released_response",
        "policy_digest",
        "runtime_manifest_digest",
        "data_plane_binary_digest",
        "release_digest",
        "server_instance",
        "tls_channel_binding",
    ];
    let statement_object = statement
        .as_object()
        .ok_or("streaming server statement is not an object")?;
    require_exact_fields(
        statement_object,
        &STATEMENT_FIELDS,
        "streaming server response statement",
    )?;
    if statement.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.streamingResponseStatement/v1")
    {
        return Err("streaming server response statement has the wrong version".to_string());
    }

    validate_streaming_authorization_binding(statement)?;
    let receipt = validated_control_plane_authorization_receipt(statement)?;
    let receipt_digest = sha256_prefixed(canonical_json(&receipt).as_bytes());
    if statement
        .get("control_plane_authorization_receipt_sha256")
        .and_then(Value::as_str)
        != Some(receipt_digest.as_str())
    {
        return Err("streaming control-plane authorization receipt digest mismatch".to_string());
    }

    const RESPONSE_FIELDS: [&str; 9] = [
        "status",
        "content_type",
        "selected_wire_headers",
        "selected_wire_headers_digest",
        "body_digest",
        "body_bytes",
        "framing",
        "completion",
        "trailer_names",
    ];
    let response = required_object(statement, "released_response")?;
    require_exact_fields(response, &RESPONSE_FIELDS, "streaming projected response")?;
    let response_value = Value::Object(response.clone());
    let body_digest = required_digest(&response_value, "body_digest")?.to_string();
    let body_bytes = required_u64(&response_value, "body_bytes")?;
    let selected = response
        .get("selected_wire_headers")
        .and_then(Value::as_object)
        .ok_or("streaming response selected_wire_headers is not an object")?;
    const REQUIRED_SELECTED_HEADERS: [&str; 4] =
        ["connection", "content-type", "trailer", "transfer-encoding"];
    if selected.len() != REQUIRED_SELECTED_HEADERS.len()
        || REQUIRED_SELECTED_HEADERS
            .iter()
            .any(|name| !selected.contains_key(*name))
        || selected
            .keys()
            .any(|name| !REQUIRED_SELECTED_HEADERS.contains(&name.as_str()))
    {
        return Err(
            "streaming response selected-wire-header set is incomplete or unexpected".to_string(),
        );
    }
    let content_type = required_string(&response_value, "content_type")?;
    let expected_selected = json!({
        "connection":"close",
        "content-type":content_type,
        "trailer":format!(
            "{STREAM_PROOF_B64_TRAILER_WIRE}, {STREAM_PROOF_SHA256_TRAILER_WIRE}"
        ),
        "transfer-encoding":"chunked",
    });
    if response.get("selected_wire_headers") != Some(&expected_selected) {
        return Err("streaming response selected wire headers are noncanonical".to_string());
    }
    let selected_digest = sha256_prefixed(canonical_json(&expected_selected).as_bytes());
    if required_digest(&response_value, "selected_wire_headers_digest")? != selected_digest {
        return Err("streaming response selected-wire-header digest mismatch".to_string());
    }
    if content_type.len() > 8 * 1024 || content_type.chars().any(char::is_control) {
        return Err("streaming response content_type is invalid".to_string());
    }
    if response.get("framing").and_then(Value::as_str) != Some("http1.1-chunked-trailers")
        || response.get("completion").and_then(Value::as_str) != Some("normal-eof")
        || response.get("trailer_names")
            != Some(&json!([
                STREAM_PROOF_B64_TRAILER_WIRE,
                STREAM_PROOF_SHA256_TRAILER_WIRE
            ]))
    {
        return Err("streaming response framing or completion binding is invalid".to_string());
    }

    let upstream = validated_streaming_upstream_response(statement)?;
    let mut surrogate = statement.clone();
    surrogate["apiVersion"] = Value::String("serverware.proxyResponseStatement/v2".to_string());
    let surrogate_object = surrogate
        .as_object_mut()
        .ok_or("streaming statement is not an object")?;
    surrogate_object.remove("authorization_binding_validation");
    surrogate_object.remove("control_plane_authorization_receipt_sha256");
    surrogate_object.remove("released_response");
    let mut surrogate_upstream = upstream
        .as_object()
        .cloned()
        .ok_or("streaming upstream response is not an object")?;
    surrogate_upstream.remove("body_bytes");
    let surrogate_upstream_canonical = json!({
        "status":surrogate_upstream.get("status"),
        "selected_raw_policy_headers_b64":surrogate_upstream.get("selected_raw_policy_headers_b64"),
        "body_digest":surrogate_upstream.get("body_digest"),
    });
    surrogate_upstream.insert(
        "canonical_digest".to_string(),
        Value::String(sha256_prefixed(
            canonical_json(&surrogate_upstream_canonical).as_bytes(),
        )),
    );
    surrogate["upstream_response"] = Value::Object(surrogate_upstream);
    let mut surrogate_selected = Map::new();
    for (header, field) in [
        (
            "x-serverware-client-request-digest",
            "client_request_digest",
        ),
        ("x-serverware-request-digest", "request_digest"),
        ("x-serverware-operation-digest", "operation_digest"),
        ("x-serverware-policy-hash", "policy_digest"),
    ] {
        surrogate_selected.insert(
            header.to_string(),
            statement
                .get(field)
                .cloned()
                .ok_or_else(|| format!("streaming statement is missing {field}"))?,
        );
    }
    surrogate_selected.insert(
        "content-length".to_string(),
        Value::String(body_bytes.to_string()),
    );
    surrogate_selected.insert(
        "content-type".to_string(),
        Value::String(content_type.to_string()),
    );
    surrogate_selected.insert(
        "x-serverware-response-body-sha256".to_string(),
        Value::String(body_digest.clone()),
    );
    let surrogate_selected_digest =
        sha256_prefixed(canonical_json(&Value::Object(surrogate_selected.clone())).as_bytes());
    surrogate["response"] = json!({
        "status":response.get("status"),
        "selected_headers":surrogate_selected,
        "selected_headers_digest":surrogate_selected_digest,
        "body_digest":body_digest,
    });
    let surrogate_tls = surrogate
        .get_mut("tls_channel_binding")
        .and_then(Value::as_object_mut)
        .ok_or("streaming TLS channel binding is not an object")?;
    surrogate_tls.remove("exporter_label");
    validate_strict_response_statement(&surrogate)
        .map_err(|err| format!("streaming shared response contract is invalid: {err}"))
}

fn verify_vendor_tee_for_mode(
    proof: &Value,
    statement: &Value,
    nonce_bytes: &[u8],
    verifier_key_path: Option<&Path>,
    expected_server_instance_id: Option<&str>,
    max_age_seconds: u64,
    streaming: bool,
) -> Result<&'static str, String> {
    let vendor = required_object(proof, "vendor_tee")?;
    let vendor_value = Value::Object(vendor.clone());
    let platform = required_string(&vendor_value, "platform")?;
    let provider = required_string(&vendor_value, "provider")?;
    let quote = vendor
        .get("quote")
        .filter(|value| value.is_object())
        .ok_or("vendor TEE evidence is missing its quote")?;
    required_string(quote, "format")?;
    decode_base64url(required_string(quote, "body_b64")?, "vendor quote body", 64)?;
    let quote_digest = sha256_prefixed(canonical_json(quote).as_bytes());
    if vendor.get("quote_sha256").and_then(Value::as_str) != Some(quote_digest.as_str()) {
        return Err("vendor quote digest mismatch".to_string());
    }
    let trusted = vendor
        .get("trusted_verifier")
        .filter(|value| value.is_object())
        .ok_or("vendor TEE evidence is missing trusted_verifier")?;
    if trusted.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.vendorTeeVerification/v1")
        || trusted.get("kind").and_then(Value::as_str) != Some("ServerwareVendorTeeVerification")
    {
        return Err("vendor verifier result has the wrong type".to_string());
    }
    let verifier_statement = trusted
        .get("statement")
        .filter(|value| value.is_object())
        .ok_or("vendor verifier result is missing its statement")?;

    let Some(verifier_key_path) = verifier_key_path else {
        if platform != "none-dev"
            || provider != "development-fixture"
            || verifier_statement
                .get("environment")
                .and_then(Value::as_str)
                != Some("development")
            || verifier_statement.get("debug").and_then(Value::as_bool) != Some(true)
            || !trusted.get("signature").is_none_or(Value::is_null)
        {
            return Err("production response proof requires --verifier-key".to_string());
        }
        return Ok("development");
    };

    production_identifier(platform, "vendor TEE platform")?;
    production_identifier(provider, "vendor quote provider")?;
    let expected_server_instance_id = expected_server_instance_id
        .ok_or("production response proof requires --expected-server-instance-id")?;
    let (verifier_key, verifier_key_id) = load_verifier_key(verifier_key_path)?;
    if verifier_statement
        .get("verifier_key_id")
        .and_then(Value::as_str)
        != Some(verifier_key_id.as_str())
    {
        return Err("vendor verifier key does not match the configured trust root".to_string());
    }
    let verifier_signature = trusted
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("vendor verifier result is missing its signature")?;
    verify_ed25519_value(
        &verifier_key,
        verifier_signature,
        canonical_json(verifier_statement).as_bytes(),
        "vendor verifier signature",
    )?;
    for (field, expected) in [
        ("outcome", "verified"),
        ("environment", "production"),
        ("trust_basis", "vendor-root-certificate-chain"),
        ("tee_platform", platform),
        ("quote_provider", provider),
    ] {
        if verifier_statement.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(format!("vendor verifier statement {field} mismatch"));
        }
    }
    for field in [
        "vendor_quote_verified",
        "certificate_chain_verified",
        "revocation_checked",
    ] {
        if verifier_statement.get(field).and_then(Value::as_bool) != Some(true) {
            return Err(format!("vendor verifier did not prove {field}"));
        }
    }
    if verifier_statement.get("debug").and_then(Value::as_bool) != Some(false) {
        return Err("vendor verifier accepted debug mode".to_string());
    }
    if verifier_statement
        .get("vendor_quote_sha256")
        .and_then(Value::as_str)
        != Some(quote_digest.as_str())
    {
        return Err("vendor verifier quote digest mismatch".to_string());
    }
    let now = now_unix();
    let verified_at = required_u64(verifier_statement, "verified_at_unix")?;
    let expires_at = required_u64(verifier_statement, "expires_at_unix")?;
    if verified_at > now.saturating_add(30)
        || now.saturating_sub(verified_at) > max_age_seconds
        || expires_at < now
        || expires_at <= verified_at
        || expires_at - verified_at > 900
    {
        return Err(
            "vendor verifier receipt is stale or has an invalid validity window".to_string(),
        );
    }

    let statement_digest = sha256_prefixed(canonical_json(statement).as_bytes());
    let verifier_statement_digest_field = if streaming {
        "streaming_response_statement_sha256"
    } else {
        "server_statement_sha256"
    };
    if verifier_statement
        .get(verifier_statement_digest_field)
        .and_then(Value::as_str)
        != Some(statement_digest.as_str())
    {
        return Err("vendor verifier server statement digest mismatch".to_string());
    }
    let server_signature = required_object(proof, "server_signature")?;
    let response_signing_key_id = server_signature
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or("server response signing key id is invalid")?;
    if verifier_statement
        .get("response_signing_key_id")
        .and_then(Value::as_str)
        != Some(response_signing_key_id)
    {
        return Err("vendor verifier did not bind the response signing key".to_string());
    }

    let server_instance = required_object(statement, "server_instance")?;
    let server_instance_id = server_instance
        .get("id")
        .and_then(Value::as_str)
        .ok_or("server statement is missing its instance ID")?;
    if server_instance_id != expected_server_instance_id {
        return Err(
            "server instance does not match the configured production identity".to_string(),
        );
    }
    let server_instance_identity_digest = sha256_prefixed(server_instance_id.as_bytes());
    if server_instance
        .get("identity_digest")
        .and_then(Value::as_str)
        != Some(server_instance_identity_digest.as_str())
    {
        return Err("server instance identity digest mismatch".to_string());
    }
    let response = required_object(
        statement,
        if streaming {
            "released_response"
        } else {
            "response"
        },
    )?;
    let response_value = Value::Object(response.clone());
    let release_authority = validated_release_authority(statement)?;
    let control_plane_authorization_receipt =
        validated_control_plane_authorization_receipt(statement)?;
    let control_plane_authorization_receipt_sha256 =
        sha256_prefixed(canonical_json(&control_plane_authorization_receipt).as_bytes());
    let upstream_response = if streaming {
        validated_streaming_upstream_response(statement)?
    } else {
        validated_upstream_response(statement)?
    };
    let tls_channel_binding = required_object(statement, "tls_channel_binding")?;
    let nonce = required_string(statement, "client_nonce")?;
    if general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes) != nonce {
        return Err("server statement nonce bytes mismatch".to_string());
    }
    let issued_at = required_u64(statement, "issued_at_unix")?;
    if issued_at > now.saturating_add(30) || now.saturating_sub(issued_at) > max_age_seconds {
        return Err("server response statement is stale".to_string());
    }
    let expected_claims = if streaming {
        let authorization_validation =
            required_object(statement, "authorization_binding_validation")?;
        let upstream = upstream_response
            .as_object()
            .ok_or("streaming upstream response is not an object")?;
        let raw_headers = upstream
            .get("selected_raw_policy_headers_b64")
            .ok_or("streaming upstream response raw headers are missing")?;
        json!({
            "streaming_response_statement_api_version":"serverware.streamingResponseStatement/v1",
            "streaming_response_statement_sha256":statement_digest,
            "issued_at_unix":issued_at,
            "client_nonce_sha256":sha256_prefixed(nonce_bytes),
            "client_request_digest":required_digest(statement, "client_request_digest")?,
            "principal_id":required_string(statement, "principal_id")?,
            "route_id":required_string(statement, "route_id")?,
            "request_digest":required_digest(statement, "request_digest")?,
            "operation_digest":required_digest(statement, "operation_digest")?,
            "release_authority":release_authority,
            "authorization_binding_digest":required_digest(&Value::Object(authorization_validation.clone()), "binding_digest")?,
            "control_plane_authorization_receipt_sha256":control_plane_authorization_receipt_sha256,
            "upstream_status":required_u64(&Value::Object(upstream.clone()), "status")?,
            "upstream_selected_raw_policy_headers_digest":sha256_prefixed(canonical_json(raw_headers).as_bytes()),
            "upstream_body_digest":required_digest(&Value::Object(upstream.clone()), "body_digest")?,
            "upstream_body_bytes":required_u64(&Value::Object(upstream.clone()), "body_bytes")?,
            "upstream_canonical_digest":required_digest(&Value::Object(upstream.clone()), "canonical_digest")?,
            "released_response_status":response.get("status").and_then(Value::as_u64).ok_or("streaming response status is invalid")?,
            "released_response_content_type":required_string(&response_value, "content_type")?,
            "selected_response_wire_headers_digest":required_digest(&response_value, "selected_wire_headers_digest")?,
            "released_response_body_digest":required_digest(&response_value, "body_digest")?,
            "released_response_body_bytes":required_u64(&response_value, "body_bytes")?,
            "response_framing":required_string(&response_value, "framing")?,
            "response_completion":required_string(&response_value, "completion")?,
            "response_trailer_names":response.get("trailer_names").cloned().ok_or("streaming response trailer_names is missing")?,
            "policy_digest":required_digest(statement, "policy_digest")?,
            "runtime_manifest_digest":required_digest(statement, "runtime_manifest_digest")?,
            "data_plane_binary_digest":required_digest(statement, "data_plane_binary_digest")?,
            "release_digest":required_digest(statement, "release_digest")?,
            "server_instance_id":server_instance_id,
            "server_instance_identity_digest":server_instance_identity_digest,
            "tls_channel_binding_type":tls_channel_binding.get("type").and_then(Value::as_str).ok_or("TLS channel binding type is missing")?,
            "tls_exporter_label":tls_channel_binding.get("exporter_label").and_then(Value::as_str).ok_or("TLS exporter label is missing")?,
            "tls_channel_binding_sha256":sha256_prefixed(canonical_json(&Value::Object(tls_channel_binding.clone())).as_bytes()),
            "response_signing_key_id":response_signing_key_id,
        })
    } else {
        json!({
            "server_statement_sha256":statement_digest,
            "server_statement_api_version":"serverware.proxyResponseStatement/v2",
            "issued_at_unix":issued_at,
            "client_nonce_sha256":sha256_prefixed(nonce_bytes),
            "client_request_digest":required_digest(statement, "client_request_digest")?,
            "principal_id":required_string(statement, "principal_id")?,
            "route_id":required_string(statement, "route_id")?,
            "request_digest":required_digest(statement, "request_digest")?,
            "operation_digest":required_digest(statement, "operation_digest")?,
            "release_authority":release_authority,
            "control_plane_authorization_receipt_sha256":control_plane_authorization_receipt_sha256,
            "upstream_response":upstream_response,
            "response_status":response.get("status").and_then(Value::as_u64).ok_or("server response status is invalid")?,
            "selected_response_headers_digest":required_digest(&response_value, "selected_headers_digest")?,
            "response_body_digest":required_digest(&response_value, "body_digest")?,
            "policy_digest":required_digest(statement, "policy_digest")?,
            "runtime_manifest_digest":required_digest(statement, "runtime_manifest_digest")?,
            "data_plane_binary_digest":required_digest(statement, "data_plane_binary_digest")?,
            "release_digest":required_digest(statement, "release_digest")?,
            "server_instance_id":server_instance_id,
            "server_instance_identity_digest":server_instance_identity_digest,
            "tls_channel_binding_type":tls_channel_binding.get("type").and_then(Value::as_str).ok_or("TLS channel binding type is missing")?,
            "tls_channel_binding_sha256":sha256_prefixed(canonical_json(&Value::Object(tls_channel_binding.clone())).as_bytes()),
            "response_signing_key_id":response_signing_key_id,
        })
    };
    if verifier_statement.get("attested_claims") != Some(&expected_claims) {
        return Err(
            "vendor TEE attested claims do not exactly match the response statement".to_string(),
        );
    }
    Ok("production")
}

fn verify_vendor_tee(
    proof: &Value,
    statement: &Value,
    nonce_bytes: &[u8],
    verifier_key_path: Option<&Path>,
    expected_server_instance_id: Option<&str>,
    max_age_seconds: u64,
) -> Result<&'static str, String> {
    verify_vendor_tee_for_mode(
        proof,
        statement,
        nonce_bytes,
        verifier_key_path,
        expected_server_instance_id,
        max_age_seconds,
        false,
    )
}

fn verify_runtime_proof(
    proof: &Value,
    response: &HttpResponse,
    expectations: &RuntimeProofExpectations<'_>,
) -> Result<Value, String> {
    let nonce = expectations.nonce;
    let tls_exporter = expectations.tls_exporter;
    let peer_spiffe_id = expectations.peer_spiffe_id;
    let peer_leaf_digest = expectations.peer_leaf_digest;
    let expected_client_request_digest = expectations.client_request_digest;
    let expected_principal_id = expectations.principal_id;
    let max_age_seconds = expectations.max_age_seconds;
    if proof.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.proxyResponseRuntimeProof/v2")
        || proof.get("kind").and_then(Value::as_str) != Some("ServerwareProxyResponseRuntimeProof")
    {
        return Err("runtime response proof has the wrong type".to_string());
    }
    let statement = proof
        .get("server_statement")
        .filter(|value| value.is_object())
        .ok_or("runtime proof is missing server_statement")?;
    if statement.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.proxyResponseStatement/v2")
    {
        return Err("server response statement has the wrong version".to_string());
    }
    validate_strict_response_statement(statement)?;
    let canonical_statement = canonical_json(statement);
    let statement_digest = sha256_prefixed(canonical_statement.as_bytes());
    if required_string(proof, "server_statement_sha256")? != statement_digest {
        return Err("server response statement digest mismatch".to_string());
    }
    let signature = required_object(proof, "server_signature")?;
    if signature.get("algorithm").and_then(Value::as_str) != Some("Ed25519") {
        return Err("server response signature algorithm is not Ed25519".to_string());
    }
    let public_key_pem = signature
        .get("public_key_pem")
        .and_then(Value::as_str)
        .ok_or("server response signature is missing its public key")?;
    let (verifying_key, key_id) = decode_public_key_pem(public_key_pem)?;
    if signature.get("key_id").and_then(Value::as_str) != Some(key_id.as_str()) {
        return Err("server response signature key id mismatch".to_string());
    }
    let signature_text = signature
        .get("signature")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("ed25519:"))
        .ok_or("server response signature is invalid")?;
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_text.as_bytes())
        .map_err(|_| "server response signature is invalid base64url")?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "server response signature must contain 64 bytes")?;
    verifying_key
        .verify(
            canonical_statement.as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| "server response signature verification failed")?;

    if required_string(statement, "client_nonce")? != nonce {
        return Err("server response statement nonce mismatch".to_string());
    }
    let issued_at = required_u64(statement, "issued_at_unix")?;
    let now = now_unix();
    if issued_at > now.saturating_add(30) || now.saturating_sub(issued_at) > max_age_seconds {
        return Err("server response statement is stale".to_string());
    }
    if required_digest(statement, "client_request_digest")? != expected_client_request_digest {
        return Err("server response statement client request digest mismatch".to_string());
    }
    if required_string(statement, "principal_id")? != expected_principal_id {
        return Err(
            "server response statement principal does not match --expected-principal-id"
                .to_string(),
        );
    }
    let route_id = required_string(statement, "route_id")?;
    required_digest(statement, "request_digest")?;
    required_digest(statement, "operation_digest")?;
    let release_authority = validated_release_authority(statement)?;
    let control_plane_authorization_receipt =
        validated_control_plane_authorization_receipt(statement)?;
    let upstream_response = validated_upstream_response(statement)?;
    required_digest(statement, "policy_digest")?;
    required_digest(statement, "runtime_manifest_digest")?;
    required_digest(statement, "data_plane_binary_digest")?;
    required_digest(statement, "release_digest")?;
    let statement_tls = required_object(statement, "tls_channel_binding")?;
    if statement_tls.get("type").and_then(Value::as_str) != Some("tls-exporter")
        || statement_tls.get("value").and_then(Value::as_str) != Some(tls_exporter)
    {
        return Err("server response statement TLS exporter mismatch".to_string());
    }
    let server_instance = required_object(statement, "server_instance")?;
    if server_instance.get("id").and_then(Value::as_str) != Some(peer_spiffe_id) {
        return Err(
            "server response statement SPIFFE identity does not match the TLS peer".to_string(),
        );
    }
    let peer_identity_digest = sha256_prefixed(peer_spiffe_id.as_bytes());
    if server_instance
        .get("identity_digest")
        .and_then(Value::as_str)
        != Some(peer_identity_digest.as_str())
    {
        return Err("server response statement SPIFFE identity digest mismatch".to_string());
    }
    if !is_sha256_digest(peer_leaf_digest) {
        return Err("TLS peer leaf certificate digest is invalid".to_string());
    }
    let statement_response = required_object(statement, "response")?;
    if statement_response.get("status").and_then(Value::as_u64) != Some(u64::from(response.status))
    {
        return Err("server response statement status mismatch".to_string());
    }
    let body_digest = sha256_prefixed(&response.body);
    if statement_response
        .get("body_digest")
        .and_then(Value::as_str)
        != Some(body_digest.as_str())
    {
        return Err("server response statement body digest mismatch".to_string());
    }
    let selected = statement_response
        .get("selected_headers")
        .and_then(Value::as_object)
        .filter(|headers| !headers.is_empty())
        .ok_or("server response statement selected no headers")?;
    let required_headers = [
        "content-length",
        "x-serverware-client-request-digest",
        "x-serverware-policy-hash",
        "x-serverware-request-digest",
        "x-serverware-operation-digest",
        "x-serverware-response-body-sha256",
    ];
    if required_headers
        .iter()
        .any(|name| !selected.contains_key(*name))
        || selected
            .keys()
            .any(|name| !required_headers.contains(&name.as_str()) && name != "content-type")
    {
        return Err(
            "server response statement selected-header set is incomplete or unexpected".to_string(),
        );
    }
    if selected
        .get("content-length")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<usize>().ok())
        != Some(response.body.len())
    {
        return Err("server response statement Content-Length mismatch".to_string());
    }
    for (header, field) in [
        (
            "x-serverware-client-request-digest",
            "client_request_digest",
        ),
        ("x-serverware-request-digest", "request_digest"),
        ("x-serverware-operation-digest", "operation_digest"),
        ("x-serverware-policy-hash", "policy_digest"),
    ] {
        if selected.get(header).and_then(Value::as_str)
            != statement.get(field).and_then(Value::as_str)
        {
            return Err(format!(
                "server response statement header {header} binding mismatch"
            ));
        }
    }
    if selected
        .get("x-serverware-response-body-sha256")
        .and_then(Value::as_str)
        != Some(body_digest.as_str())
    {
        return Err("server response statement body digest header mismatch".to_string());
    }
    let mut captured_headers = Map::new();
    for (name, expected) in selected {
        let expected = expected
            .as_str()
            .ok_or("server response statement selected header is not a string")?;
        let actual = response
            .headers
            .get(name)
            .ok_or_else(|| format!("captured response is missing selected header {name}"))?;
        if actual != expected {
            return Err(format!(
                "captured response header {name} does not match the server statement"
            ));
        }
        captured_headers.insert(name.clone(), Value::String(actual.clone()));
    }
    let captured_headers_value = Value::Object(captured_headers.clone());
    let selected_digest = sha256_prefixed(canonical_json(&captured_headers_value).as_bytes());
    if statement_response
        .get("selected_headers_digest")
        .and_then(Value::as_str)
        != Some(selected_digest.as_str())
    {
        return Err("server response statement selected-header digest mismatch".to_string());
    }
    Ok(json!({
        "apiVersion":"serverware.proxyResponseCapture/v2",
        "environment":"production",
        "collection_mode":"external-client-capture",
        "captured_at_unix":now_unix(),
        "client_nonce":nonce,
        "client_request_digest":expected_client_request_digest,
        "principal_id":expected_principal_id,
        "route_id":route_id,
        "request_digest":required_string(statement, "request_digest")?,
        "operation_digest":required_string(statement, "operation_digest")?,
        "release_authority":release_authority,
        "control_plane_authorization_receipt":control_plane_authorization_receipt,
        "upstream_response":upstream_response,
        "response":{
            "status":response.status,
            "selected_headers":captured_headers,
            "selected_headers_digest":selected_digest,
            "body_digest":body_digest,
        },
        "tls_channel_binding":{
            "type":"tls-exporter",
            "value":tls_exporter,
        },
        "tls_peer":{
            "spiffe_id":peer_spiffe_id,
            "leaf_certificate_sha256":peer_leaf_digest,
        },
        "server_statement_sha256":statement_digest,
    }))
}

fn decode_stream_runtime_proof(response: &StreamResponse) -> Result<(Value, String), String> {
    let encoded = response
        .trailers
        .get(STREAM_PROOF_B64_TRAILER)
        .ok_or("stream response is missing its runtime proof trailer")?;
    if encoded.contains('=') {
        return Err("stream runtime proof must use unpadded base64url".to_string());
    }
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| "stream runtime proof is invalid base64url")?;
    if bytes.len() > MAX_RUNTIME_PROOF_BYTES
        || general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != *encoded
    {
        return Err("stream runtime proof is oversized or noncanonical base64url".to_string());
    }
    let digest = sha256_prefixed(&bytes);
    let declared_digest = response
        .trailers
        .get(STREAM_PROOF_SHA256_TRAILER)
        .filter(|value| is_sha256_digest(value))
        .ok_or("stream runtime proof digest trailer is not canonical SHA-256")?;
    if declared_digest != &digest {
        return Err("stream runtime proof digest trailer mismatch".to_string());
    }
    let proof = serde_json::from_slice(&bytes)
        .map_err(|err| format!("parse stream runtime proof: {err}"))?;
    Ok((proof, digest))
}

fn validate_stream_runtime_proof_shape(proof: &Value) -> Result<(), String> {
    const PROOF_FIELDS: [&str; 6] = [
        "apiVersion",
        "kind",
        "streaming_response_statement",
        "streaming_response_statement_sha256",
        "server_signature",
        "vendor_tee",
    ];
    const SIGNATURE_FIELDS: [&str; 4] = ["algorithm", "key_id", "public_key_pem", "signature"];
    const VENDOR_FIELDS: [&str; 5] = [
        "platform",
        "provider",
        "quote_sha256",
        "quote",
        "trusted_verifier",
    ];
    const QUOTE_FIELDS: [&str; 2] = ["format", "body_b64"];
    const TRUSTED_FIELDS: [&str; 4] = ["apiVersion", "kind", "statement", "signature"];
    let proof_object = proof
        .as_object()
        .ok_or("stream runtime proof is not an object")?;
    require_exact_fields(proof_object, &PROOF_FIELDS, "stream runtime proof")?;
    let signature = required_object(proof, "server_signature")?;
    require_exact_fields(signature, &SIGNATURE_FIELDS, "stream server signature")?;
    let vendor = required_object(proof, "vendor_tee")?;
    require_exact_fields(vendor, &VENDOR_FIELDS, "stream vendor TEE evidence")?;
    let quote = vendor
        .get("quote")
        .and_then(Value::as_object)
        .ok_or("stream vendor quote is not an object")?;
    require_exact_fields(quote, &QUOTE_FIELDS, "stream vendor quote")?;
    let trusted = vendor
        .get("trusted_verifier")
        .and_then(Value::as_object)
        .ok_or("stream trusted verifier result is not an object")?;
    require_exact_fields(trusted, &TRUSTED_FIELDS, "stream trusted verifier result")?;
    let verifier_statement = trusted
        .get("statement")
        .and_then(Value::as_object)
        .ok_or("stream trusted verifier statement is not an object")?;
    const DEVELOPMENT_VERIFIER_FIELDS: [&str; 6] = [
        "outcome",
        "environment",
        "debug",
        "streaming_response_statement_sha256",
        "response_signing_key_id",
        "attested_claims",
    ];
    const PRODUCTION_VERIFIER_FIELDS: [&str; 16] = [
        "verifier_key_id",
        "outcome",
        "environment",
        "trust_basis",
        "vendor_quote_verified",
        "certificate_chain_verified",
        "revocation_checked",
        "debug",
        "verified_at_unix",
        "expires_at_unix",
        "tee_platform",
        "quote_provider",
        "vendor_quote_sha256",
        "streaming_response_statement_sha256",
        "response_signing_key_id",
        "attested_claims",
    ];
    const STREAM_ATTESTED_CLAIM_FIELDS: [&str; 35] = [
        "streaming_response_statement_api_version",
        "streaming_response_statement_sha256",
        "issued_at_unix",
        "client_nonce_sha256",
        "client_request_digest",
        "principal_id",
        "route_id",
        "request_digest",
        "operation_digest",
        "release_authority",
        "authorization_binding_digest",
        "control_plane_authorization_receipt_sha256",
        "upstream_status",
        "upstream_selected_raw_policy_headers_digest",
        "upstream_body_digest",
        "upstream_body_bytes",
        "upstream_canonical_digest",
        "released_response_status",
        "released_response_content_type",
        "selected_response_wire_headers_digest",
        "released_response_body_digest",
        "released_response_body_bytes",
        "response_framing",
        "response_completion",
        "response_trailer_names",
        "policy_digest",
        "runtime_manifest_digest",
        "data_plane_binary_digest",
        "release_digest",
        "server_instance_id",
        "server_instance_identity_digest",
        "tls_channel_binding_type",
        "tls_exporter_label",
        "tls_channel_binding_sha256",
        "response_signing_key_id",
    ];
    match verifier_statement
        .get("environment")
        .and_then(Value::as_str)
    {
        Some("development") => require_exact_fields(
            verifier_statement,
            &DEVELOPMENT_VERIFIER_FIELDS,
            "development stream verifier statement",
        ),
        Some("production") => require_exact_fields(
            verifier_statement,
            &PRODUCTION_VERIFIER_FIELDS,
            "production stream verifier statement",
        ),
        _ => Err("stream verifier statement environment is invalid".to_string()),
    }?;
    let attested_claims = verifier_statement
        .get("attested_claims")
        .and_then(Value::as_object)
        .ok_or("stream verifier attested_claims is not an object")?;
    require_exact_fields(
        attested_claims,
        &STREAM_ATTESTED_CLAIM_FIELDS,
        "stream verifier attested claims",
    )
}

fn verify_stream_runtime_proof(
    proof: &Value,
    response: &StreamResponse,
    expectations: &RuntimeProofExpectations<'_>,
) -> Result<Value, String> {
    validate_stream_runtime_proof_shape(proof)?;
    if proof.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.streamingResponseRuntimeProof/v1")
        || proof.get("kind").and_then(Value::as_str)
            != Some("ServerwareStreamingResponseRuntimeProof")
    {
        return Err("stream runtime response proof has the wrong type".to_string());
    }
    let statement = proof
        .get("streaming_response_statement")
        .filter(|value| value.is_object())
        .ok_or("stream runtime proof is missing streaming_response_statement")?;
    validate_streaming_statement_with_shared_contract(statement)?;
    let canonical_statement = canonical_json(statement);
    let statement_digest = sha256_prefixed(canonical_statement.as_bytes());
    if required_digest(proof, "streaming_response_statement_sha256")? != statement_digest {
        return Err("streaming response statement digest mismatch".to_string());
    }
    let signature = required_object(proof, "server_signature")?;
    if signature.get("algorithm").and_then(Value::as_str) != Some("Ed25519") {
        return Err("stream server response signature algorithm is not Ed25519".to_string());
    }
    let public_key_pem = signature
        .get("public_key_pem")
        .and_then(Value::as_str)
        .ok_or("stream server signature is missing its public key")?;
    let (verifying_key, key_id) = decode_public_key_pem(public_key_pem)?;
    if signature.get("key_id").and_then(Value::as_str) != Some(key_id.as_str()) {
        return Err("stream server response signature key id mismatch".to_string());
    }
    let signature_text = signature
        .get("signature")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("ed25519:"))
        .ok_or("stream server response signature is invalid")?;
    if signature_text.contains('=') {
        return Err("stream server response signature is not unpadded base64url".to_string());
    }
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_text.as_bytes())
        .map_err(|_| "stream server response signature is invalid base64url")?;
    if general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_text {
        return Err("stream server response signature is noncanonical base64url".to_string());
    }
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "stream server response signature must contain 64 bytes")?;
    verifying_key
        .verify(
            canonical_statement.as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| "stream server response signature verification failed")?;

    if required_string(statement, "client_nonce")? != expectations.nonce {
        return Err("streaming response statement nonce mismatch".to_string());
    }
    let issued_at = required_u64(statement, "issued_at_unix")?;
    let now = now_unix();
    if issued_at > now.saturating_add(30)
        || now.saturating_sub(issued_at) > expectations.max_age_seconds
    {
        return Err("streaming response statement is stale".to_string());
    }
    if required_digest(statement, "client_request_digest")? != expectations.client_request_digest {
        return Err("streaming response statement client request digest mismatch".to_string());
    }
    if required_string(statement, "principal_id")? != expectations.principal_id {
        return Err(
            "streaming response principal does not match --expected-principal-id".to_string(),
        );
    }
    let route_id = required_string(statement, "route_id")?;
    required_digest(statement, "request_digest")?;
    required_digest(statement, "operation_digest")?;
    let release_authority = validated_release_authority(statement)?;
    let authorization_binding = validate_streaming_authorization_binding(statement)?;
    let control_plane_authorization_receipt =
        validated_control_plane_authorization_receipt(statement)?;
    let upstream_response = validated_streaming_upstream_response(statement)?;
    required_digest(statement, "policy_digest")?;
    required_digest(statement, "runtime_manifest_digest")?;
    required_digest(statement, "data_plane_binary_digest")?;
    required_digest(statement, "release_digest")?;

    let statement_tls = required_object(statement, "tls_channel_binding")?;
    const TLS_FIELDS: [&str; 3] = ["type", "exporter_label", "value"];
    require_exact_fields(statement_tls, &TLS_FIELDS, "streaming TLS channel binding")?;
    if statement_tls.get("type").and_then(Value::as_str) != Some("tls-exporter")
        || statement_tls.get("exporter_label").and_then(Value::as_str)
            != Some("EXPORTER-Serverware-Proxy-Stream-v1")
        || statement_tls.get("value").and_then(Value::as_str) != Some(expectations.tls_exporter)
    {
        return Err("streaming response statement TLS exporter mismatch".to_string());
    }
    let server_instance = required_object(statement, "server_instance")?;
    const SERVER_INSTANCE_FIELDS: [&str; 2] = ["id", "identity_digest"];
    require_exact_fields(
        server_instance,
        &SERVER_INSTANCE_FIELDS,
        "streaming server instance",
    )?;
    if server_instance.get("id").and_then(Value::as_str) != Some(expectations.peer_spiffe_id) {
        return Err("streaming response SPIFFE identity does not match the TLS peer".to_string());
    }
    let peer_identity_digest = sha256_prefixed(expectations.peer_spiffe_id.as_bytes());
    if server_instance
        .get("identity_digest")
        .and_then(Value::as_str)
        != Some(peer_identity_digest.as_str())
    {
        return Err("streaming response SPIFFE identity digest mismatch".to_string());
    }
    if !is_sha256_digest(expectations.peer_leaf_digest) {
        return Err("stream TLS peer leaf certificate digest is invalid".to_string());
    }

    let released = required_object(statement, "released_response")?;
    let released_value = Value::Object(released.clone());
    if released.get("status").and_then(Value::as_u64) != Some(u64::from(response.status)) {
        return Err("streaming response status mismatch".to_string());
    }
    if required_digest(&released_value, "body_digest")? != response.body_digest {
        return Err("streaming projected body digest mismatch".to_string());
    }
    if required_u64(&released_value, "body_bytes")? != response.body_bytes {
        return Err("streaming projected body byte count mismatch".to_string());
    }
    let content_type = response
        .headers
        .get("content-type")
        .ok_or("stream response is missing Content-Type")?;
    if released.get("content_type").and_then(Value::as_str) != Some(content_type.as_str()) {
        return Err("streaming response Content-Type mismatch".to_string());
    }
    let selected = released
        .get("selected_wire_headers")
        .and_then(Value::as_object)
        .ok_or("streaming response selected_wire_headers is missing")?;
    let mut captured_headers = Map::new();
    for (name, expected) in selected {
        let expected = expected
            .as_str()
            .ok_or("streaming selected wire header is not a string")?;
        let actual = response
            .headers
            .get(name)
            .ok_or_else(|| format!("captured stream is missing selected header {name}"))?;
        if actual != expected {
            return Err(format!(
                "captured stream header {name} does not match the signed statement"
            ));
        }
        captured_headers.insert(name.clone(), Value::String(actual.clone()));
    }
    let captured_headers_value = Value::Object(captured_headers.clone());
    let selected_digest = sha256_prefixed(canonical_json(&captured_headers_value).as_bytes());
    if required_digest(&released_value, "selected_wire_headers_digest")? != selected_digest {
        return Err("streaming selected wire header digest mismatch".to_string());
    }
    if released.get("framing").and_then(Value::as_str) != Some("http1.1-chunked-trailers")
        || released.get("completion").and_then(Value::as_str) != Some("normal-eof")
        || released.get("trailer_names")
            != Some(&json!([
                STREAM_PROOF_B64_TRAILER_WIRE,
                STREAM_PROOF_SHA256_TRAILER_WIRE
            ]))
    {
        return Err("streaming response completion binding mismatch".to_string());
    }

    Ok(json!({
        "apiVersion":"serverware.streamingProxyResponseCapture/v1",
        "environment":"production",
        "collection_mode":"strict-incremental-stream-capture",
        "classification":"verified-complete-stream",
        "captured_at_unix":now_unix(),
        "client_nonce":expectations.nonce,
        "client_request_digest":expectations.client_request_digest,
        "principal_id":expectations.principal_id,
        "route_id":route_id,
        "request_digest":required_string(statement, "request_digest")?,
        "operation_digest":required_string(statement, "operation_digest")?,
        "release_authority":release_authority,
        "authorization_binding_commitment":authorization_binding,
        "control_plane_authorization_receipt":control_plane_authorization_receipt,
        "control_plane_authorization_receipt_sha256":statement.get("control_plane_authorization_receipt_sha256"),
        "upstream_response":upstream_response,
        "released_response":{
            "status":response.status,
            "content_type":content_type,
            "selected_wire_headers":captured_headers,
            "selected_wire_headers_digest":selected_digest,
            "body_digest":response.body_digest,
            "body_bytes":response.body_bytes,
            "framing":"http1.1-chunked-trailers",
            "completion":"normal-eof",
            "trailer_names":[STREAM_PROOF_B64_TRAILER_WIRE, STREAM_PROOF_SHA256_TRAILER_WIRE],
        },
        "tls_channel_binding":{
            "type":"tls-exporter",
            "exporter_label":"EXPORTER-Serverware-Proxy-Stream-v1",
            "value":expectations.tls_exporter,
        },
        "tls_peer":{
            "spiffe_id":expectations.peer_spiffe_id,
            "leaf_certificate_sha256":expectations.peer_leaf_digest,
        },
        "streaming_response_statement_sha256":statement_digest,
    }))
}

fn finish_stream_collection(
    args: &Args,
    mut tls: StreamOwned<ClientConnection, TcpStream>,
    pending: PendingStreamCollection,
) -> Result<Value, String> {
    let PendingStreamCollection {
        mut staged_body,
        proof_target,
        client_request_digest: expected_client_request_digest,
        nonce,
        nonce_bytes,
    } = pending;
    let proof_path = proof_target.display_path.clone();
    let response = read_stream_response(&mut tls, staged_body.file_mut()?, args.max_stream_bytes)?;
    staged_body.sync()?;
    let exporter = tls
        .conn
        .export_keying_material([0u8; 32], STREAM_EXPORTER_LABEL, Some(&nonce_bytes))
        .map_err(|err| format!("derive streaming client TLS exporter: {err}"))?;
    let tls_exporter = general_purpose::URL_SAFE_NO_PAD.encode(exporter);
    let (peer_spiffe_id, peer_leaf_digest) = peer_identity(&tls)?;
    let (runtime_proof, runtime_proof_digest) = decode_stream_runtime_proof(&response)?;
    let mut external_capture = verify_stream_runtime_proof(
        &runtime_proof,
        &response,
        &RuntimeProofExpectations {
            nonce: &nonce,
            tls_exporter: &tls_exporter,
            peer_spiffe_id: &peer_spiffe_id,
            peer_leaf_digest: &peer_leaf_digest,
            client_request_digest: &expected_client_request_digest,
            principal_id: &args.expected_principal_id,
            max_age_seconds: args.max_age_seconds,
        },
    )?;
    let statement = runtime_proof
        .get("streaming_response_statement")
        .filter(|value| value.is_object())
        .ok_or("stream runtime proof is missing streaming_response_statement")?;
    let proof_environment = verify_vendor_tee_for_mode(
        &runtime_proof,
        statement,
        &nonce_bytes,
        args.verifier_key.as_deref(),
        args.expected_server_instance_id.as_deref(),
        args.max_age_seconds,
        true,
    )?;
    external_capture["environment"] = Value::String(proof_environment.to_string());
    external_capture["runtime_proof_sha256"] = Value::String(runtime_proof_digest);
    let collector_key = load_collector_key(&args.collector_key)?;
    let (collector_public_key_pem, collector_key_id) = public_key_material(&collector_key);
    let capture_bytes = canonical_json(&external_capture);
    let collector_signature = collector_key.sign(capture_bytes.as_bytes());
    collector_key
        .verifying_key()
        .verify(capture_bytes.as_bytes(), &collector_signature)
        .map_err(|_| "collector signature self-verification failed".to_string())?;
    let proof = json!({
        "apiVersion":"serverware.streamingProxyResponseProof/v1",
        "kind":"ServerwareStreamingProxyResponseProof",
        "external_capture":external_capture,
        "collector_signature":{
            "algorithm":"Ed25519",
            "key_id":collector_key_id,
            "public_key_pem":collector_public_key_pem,
            "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(collector_signature.to_bytes())),
        },
        "streaming_response_statement":runtime_proof.get("streaming_response_statement").cloned().unwrap_or(Value::Null),
        "server_signature":runtime_proof.get("server_signature").cloned().unwrap_or(Value::Null),
        "vendor_tee":runtime_proof.get("vendor_tee").cloned().unwrap_or(Value::Null),
    });
    if proof.get("vendor_tee").is_none_or(Value::is_null) {
        return Err("stream runtime response proof is missing vendor TEE evidence".to_string());
    }
    let output = serde_json::to_vec_pretty(&proof)
        .map_err(|err| format!("serialize streaming proxy response proof: {err}"))?;
    let proof_payload = [output.as_slice(), b"\n"].concat();
    let proof_digest = sha256_prefixed(&proof_payload);
    let body_path = publish_verified_stream_outputs_resolved(
        staged_body,
        proof_target,
        &proof_payload,
        &response.body_digest,
        response.body_bytes,
    )?;
    Ok(json!({
        "ok":true,
        "stream_verified":true,
        "proof_path":proof_path,
        "proof_sha256":proof_digest,
        "body_path":body_path,
        "body_sha256":response.body_digest,
        "body_bytes":response.body_bytes,
        "client_nonce":nonce,
        "client_request_digest":expected_client_request_digest,
        "principal_id":args.expected_principal_id,
        "route_id":statement.get("route_id"),
        "request_digest":statement.get("request_digest"),
        "operation_digest":statement.get("operation_digest"),
        "release_authority":statement.get("release_authority"),
        "tls_channel_binding":tls_exporter,
        "response_status":response.status,
        "response_content_type":response.headers.get("content-type"),
        "collector_key_id":collector_key_id,
        "server_instance_id":peer_spiffe_id,
        "tls_peer_leaf_certificate_sha256":peer_leaf_digest,
    }))
}

fn collect(args: Args) -> Result<Value, String> {
    let method = validate_proof_method(&args.method)?;
    let canonical_client_request = canonical_client_proof_request_for_mode(
        method,
        &args.url,
        &args.request_headers,
        args.stream,
    )?;
    let expected_client_request_digest =
        sha256_prefixed(canonical_json(&canonical_client_request).as_bytes());
    let stream_outputs = if args.stream {
        let (body_target, proof_target) = validate_stream_output_paths(&args)?;
        Some((StagedBody::create_resolved(body_target)?, proof_target))
    } else {
        None
    };
    let host = args.url.host_str().ok_or("--url has no host")?.to_string();
    let port = args
        .url
        .port_or_known_default()
        .ok_or("--url has no port")?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let timeout = Duration::from_secs(args.timeout_seconds);
    let mut tcp = TcpStream::connect(&args.proxy)
        .map_err(|err| format!("connect to proxy {}: {err}", args.proxy))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|err| format!("set proxy read timeout: {err}"))?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|err| format!("set proxy write timeout: {err}"))?;
    let mut connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    for (name, value) in &args.proxy_headers {
        connect.push_str(&format!("{name}: {value}\r\n"));
    }
    connect.push_str("Connection: keep-alive\r\n\r\n");
    tcp.write_all(connect.as_bytes())
        .map_err(|err| format!("write CONNECT request: {err}"))?;
    tcp.flush()
        .map_err(|err| format!("flush CONNECT request: {err}"))?;
    let connect_head = read_head(&mut tcp, 64 * 1024)?;
    let (connect_status, _, body_start) = parse_head(&connect_head)?;
    if connect_head.len() != body_start || connect_status != 200 {
        return Err(format!("proxy CONNECT failed with status {connect_status}"));
    }

    let roots = load_roots(&args.ca)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| format!("invalid TLS server name {host}"))?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("create TLS client: {err}"))?;
    let mut tls = StreamOwned::new(connection, tcp);
    let rng = SystemRandom::new();
    let mut nonce_bytes = args.client_nonce.unwrap_or([0u8; 32]);
    if args.client_nonce.is_none() {
        rng.fill(&mut nonce_bytes)
            .map_err(|_| "generate response proof nonce".to_string())?;
    }
    let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
    let mut target = args.url.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = args.url.query() {
        target.push('?');
        target.push_str(query);
    }
    let host_header = if port == 443 {
        host.clone()
    } else {
        authority.clone()
    };
    let proof_nonce_header = if args.stream {
        "X-Serverware-Stream-Proof-Nonce"
    } else {
        "X-Serverware-Proof-Nonce"
    };
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host_header}\r\n{proof_nonce_header}: {nonce}\r\n"
    );
    for (name, value) in &args.request_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .map_err(|err| format!("write proof request: {err}"))?;
    tls.flush()
        .map_err(|err| format!("flush proof request: {err}"))?;
    if let Some((staged_body, proof_target)) = stream_outputs {
        return finish_stream_collection(
            &args,
            tls,
            PendingStreamCollection {
                staged_body,
                proof_target,
                client_request_digest: expected_client_request_digest,
                nonce,
                nonce_bytes,
            },
        );
    }
    let response = read_response(&mut tls)?;
    let exporter = tls
        .conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&nonce_bytes))
        .map_err(|err| format!("derive client TLS exporter: {err}"))?;
    let tls_exporter = general_purpose::URL_SAFE_NO_PAD.encode(exporter);
    let (peer_spiffe_id, peer_leaf_digest) = peer_identity(&tls)?;
    let runtime_proof_b64 = response
        .headers
        .get("x-serverware-response-proof-b64")
        .ok_or("captured response is missing X-Serverware-Response-Proof-B64")?;
    let runtime_proof_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(runtime_proof_b64.as_bytes())
        .map_err(|_| "runtime response proof is invalid base64url")?;
    let declared_runtime_digest = response
        .headers
        .get("x-serverware-response-proof-sha256")
        .ok_or("captured response is missing X-Serverware-Response-Proof-SHA256")?;
    if sha256_prefixed(&runtime_proof_bytes) != *declared_runtime_digest {
        return Err("runtime response proof digest header mismatch".to_string());
    }
    let runtime_proof: Value = serde_json::from_slice(&runtime_proof_bytes)
        .map_err(|err| format!("parse runtime response proof: {err}"))?;
    let external_capture = verify_runtime_proof(
        &runtime_proof,
        &response,
        &RuntimeProofExpectations {
            nonce: &nonce,
            tls_exporter: &tls_exporter,
            peer_spiffe_id: &peer_spiffe_id,
            peer_leaf_digest: &peer_leaf_digest,
            client_request_digest: &expected_client_request_digest,
            principal_id: &args.expected_principal_id,
            max_age_seconds: args.max_age_seconds,
        },
    )?;
    let statement = runtime_proof
        .get("server_statement")
        .filter(|value| value.is_object())
        .ok_or("runtime proof is missing server_statement")?;
    let proof_environment = verify_vendor_tee(
        &runtime_proof,
        statement,
        &nonce_bytes,
        args.verifier_key.as_deref(),
        args.expected_server_instance_id.as_deref(),
        args.max_age_seconds,
    )?;
    let mut external_capture = external_capture;
    external_capture["environment"] = Value::String(proof_environment.to_string());
    let collector_key = load_collector_key(&args.collector_key)?;
    let (collector_public_key_pem, collector_key_id) = public_key_material(&collector_key);
    let collector_signature = collector_key.sign(canonical_json(&external_capture).as_bytes());
    let proof = json!({
        "apiVersion":"serverware.proxyResponseProof/v3",
        "kind":"ServerwareProxyResponseProof",
        "external_capture":external_capture,
        "collector_signature":{
            "algorithm":"Ed25519",
            "key_id":collector_key_id,
            "public_key_pem":collector_public_key_pem,
            "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(collector_signature.to_bytes())),
        },
        "server_statement":runtime_proof.get("server_statement").cloned().unwrap_or(Value::Null),
        "server_signature":runtime_proof.get("server_signature").cloned().unwrap_or(Value::Null),
        "vendor_tee":runtime_proof.get("vendor_tee").cloned().unwrap_or(Value::Null),
    });
    if proof.get("vendor_tee").is_none_or(Value::is_null) {
        return Err("runtime response proof is missing vendor TEE evidence".to_string());
    }
    let output = serde_json::to_vec_pretty(&proof)
        .map_err(|err| format!("serialize proxy response proof: {err}"))?;
    atomic_write_private(&args.out, &[output.as_slice(), b"\n"].concat())?;
    let capture = required_object(&proof, "external_capture")?;
    Ok(json!({
        "ok":true,
        "proof_path":args.out,
        "proof_sha256":sha256_prefixed(&fs::read(&args.out).map_err(|err| format!("read proof output: {err}"))?),
        "client_nonce":capture.get("client_nonce"),
        "client_request_digest":capture.get("client_request_digest"),
        "principal_id":capture.get("principal_id"),
        "route_id":capture.get("route_id"),
        "request_digest":capture.get("request_digest"),
        "operation_digest":capture.get("operation_digest"),
        "release_authority":capture.get("release_authority"),
        "tls_channel_binding":capture.get("tls_channel_binding").and_then(Value::as_object).and_then(|value| value.get("value")),
        "response_status":response.status,
        "response_body_digest":sha256_prefixed(&response.body),
        "collector_key_id":collector_key_id,
        "server_instance_id":peer_spiffe_id,
        "tls_peer_leaf_certificate_sha256":peer_leaf_digest,
    }))
}

fn main() {
    let result = parse_args().and_then(collect);
    match result {
        Ok(summary) => println!("{}", canonical_json(&summary)),
        Err(error) => {
            eprintln!("{}", canonical_json(&json!({"ok":false,"error":error})));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;
    use std::thread;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn digest(byte: u8) -> String {
        sha256_prefixed(&[byte; 32])
    }

    #[test]
    fn client_request_digest_is_computed_from_client_observable_material() {
        let url = Url::parse("https://EXAMPLE.com.:443/a%20b?z=2&a=one%20two&a=one").unwrap();
        let canonical = canonical_client_proof_request(
            "GET",
            &url,
            &[
                ("X-Custom".to_string(), "  value  ".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
                ("X-Serverware-Agent".to_string(), "demo-agent".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(
            canonical,
            json!({
                "apiVersion":"serverware.clientProofRequest/v1",
                "method":"GET",
                "scheme":"https",
                "authority":"example.com",
                "path":"/a%20b",
                "query":[["a","one"],["a","one two"],["z","2"]],
                "headers":{"accept":"application/json","x-custom":"value"},
                "body_sha256":sha256_prefixed(b""),
            })
        );
        assert!(sha256_prefixed(canonical_json(&canonical).as_bytes()).starts_with("sha256:"));
    }

    #[test]
    fn proof_collection_is_explicitly_get_only() {
        let url = Url::parse("https://example.test/resource").unwrap();
        assert_eq!(
            canonical_client_proof_request("GET", &url, &[]).unwrap()["method"],
            "GET"
        );
        assert!(canonical_client_proof_request("HEAD", &url, &[])
            .expect_err("HEAD must be rejected")
            .contains("GET-only"));
    }

    fn required_arguments() -> Vec<String> {
        [
            "--proxy",
            "127.0.0.1:8080",
            "--url",
            "https://example.test/resource",
            "--ca",
            "/tmp/serverware-ca.pem",
            "--out",
            "/tmp/serverware-proof.json",
            "--collector-key",
            "/tmp/serverware-collector.pem",
            "--expected-principal-id",
            "demo-agent",
            "--proxy-header",
            "X-Serverware-Agent: demo-agent",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn stream_cli_requires_body_output_and_bounds_stream_size() {
        let buffered = parse_args_from(required_arguments()).expect("buffered arguments");
        assert!(!buffered.stream);
        assert!(buffered.body_out.is_none());

        let mut missing_body = required_arguments();
        missing_body.push("--stream".to_string());
        assert!(parse_args_from(missing_body)
            .err()
            .expect("stream without body output")
            .contains("--body-out"));

        let mut body_without_stream = required_arguments();
        body_without_stream.extend(["--body-out".to_string(), "/tmp/body".to_string()]);
        assert!(parse_args_from(body_without_stream)
            .err()
            .expect("body output without stream")
            .contains("only with --stream"));

        let mut streaming = required_arguments();
        streaming.extend([
            "--stream".to_string(),
            "--body-out".to_string(),
            "/tmp/body".to_string(),
            "--max-stream-bytes".to_string(),
            MAX_CONFIGURED_STREAM_BYTES.to_string(),
        ]);
        let streaming = parse_args_from(streaming).expect("valid streaming arguments");
        assert!(streaming.stream);
        assert_eq!(streaming.max_stream_bytes, MAX_CONFIGURED_STREAM_BYTES);

        let mut oversized = required_arguments();
        oversized.extend([
            "--stream".to_string(),
            "--body-out".to_string(),
            "/tmp/body".to_string(),
            "--max-stream-bytes".to_string(),
            (MAX_CONFIGURED_STREAM_BYTES + 1).to_string(),
        ]);
        assert!(parse_args_from(oversized).is_err());

        let canonical = canonical_client_proof_request_for_mode(
            "GET",
            &Url::parse("https://example.test/resource").unwrap(),
            &[],
            true,
        )
        .expect("streaming canonical request");
        assert_eq!(
            canonical["apiVersion"],
            "serverware.streamingClientProofRequest/v1"
        );
    }

    struct FragmentedReader {
        bytes: Vec<u8>,
        offset: usize,
        maximum_read: usize,
    }

    impl Read for FragmentedReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let count = output
                .len()
                .min(self.maximum_read)
                .min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    fn test_directory(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_os = "macos")]
        let temporary_root = PathBuf::from("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let temporary_root = env::temp_dir();
        let path = temporary_root.join(format!(
            "serverware-proof-client-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make test output directory private");
        path
    }

    fn stage_body(target: PathBuf, payload: &[u8]) -> StagedBody {
        let mut staged = StagedBody::create(target).expect("stage body");
        staged
            .file_mut()
            .expect("staging file")
            .write_all(payload)
            .expect("write staged body");
        staged
    }

    fn file_mode(path: &Path) -> u32 {
        fs::metadata(path).expect("read file metadata").mode() & 0o777
    }

    fn make_stale(path: &Path) {
        let file = File::open(path).expect("open stale test entry");
        let stale_seconds = now_unix()
            .saturating_sub(STALE_PUBLICATION_ENTRY_AGE.as_secs())
            .saturating_sub(60);
        let times = [
            libc::timespec {
                tv_sec: stale_seconds as libc::time_t,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: stale_seconds as libc::time_t,
                tv_nsec: 0,
            },
        ];
        assert_eq!(
            unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) },
            0
        );
    }

    fn stream_head(extra: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n{extra}\r\n"
        )
    }

    fn valid_stream_wire() -> Vec<u8> {
        let proof = b"{}";
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(proof);
        format!(
            "{}2\r\nab\r\n3\r\ncde\r\n0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nX-Serverware-Stream-Proof-SHA256: {}\r\n\r\n",
            stream_head(""),
            sha256_prefixed(proof),
        )
        .into_bytes()
    }

    fn parse_stream_wire(
        wire: Vec<u8>,
        maximum_read: usize,
        maximum_body: u64,
    ) -> Result<(StreamResponse, Vec<u8>), String> {
        let directory = test_directory("parse");
        let body_path = directory.join("body.tmp");
        let mut body_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&body_path)
            .expect("create body sink");
        let mut reader = FragmentedReader {
            bytes: wire,
            offset: 0,
            maximum_read,
        };
        let result = read_stream_response(&mut reader, &mut body_file, maximum_body);
        drop(body_file);
        let body = fs::read(&body_path).expect("read body sink");
        fs::remove_dir_all(directory).expect("remove test directory");
        result.map(|response| (response, body))
    }

    #[test]
    fn stream_parser_accepts_fragmented_chunks_and_exact_final_trailers() {
        let (response, body) = parse_stream_wire(valid_stream_wire(), 1, 1024)
            .expect("one-byte fragmentation must parse");
        assert_eq!(response.status, 200);
        assert_eq!(response.body_bytes, 5);
        assert_eq!(response.body_digest, sha256_prefixed(b"abcde"));
        assert_eq!(body, b"abcde");
        assert_eq!(response.trailers.len(), 2);
    }

    #[test]
    fn stream_runtime_proof_trailer_requires_canonical_bounded_bytes_and_matching_digest() {
        let (response, _) =
            parse_stream_wire(valid_stream_wire(), 2, 1024).expect("valid stream response");
        let (proof, digest) = decode_stream_runtime_proof(&response).expect("valid proof trailers");
        assert_eq!(proof, json!({}));
        assert_eq!(digest, sha256_prefixed(b"{}"));

        let mut wrong_digest = response;
        wrong_digest.trailers.insert(
            STREAM_PROOF_SHA256_TRAILER.to_string(),
            sha256_prefixed(b"different"),
        );
        assert!(decode_stream_runtime_proof(&wrong_digest)
            .expect_err("wrong proof digest")
            .contains("mismatch"));

        let mut padded = wrong_digest;
        padded.trailers.insert(
            STREAM_PROOF_B64_TRAILER.to_string(),
            general_purpose::URL_SAFE.encode(b"{}"),
        );
        assert!(decode_stream_runtime_proof(&padded)
            .expect_err("padded proof")
            .contains("unpadded"));

        let oversized_bytes = vec![0u8; MAX_RUNTIME_PROOF_BYTES + 1];
        let oversized_encoded = general_purpose::URL_SAFE_NO_PAD.encode(&oversized_bytes);
        let mut oversized = padded;
        oversized
            .trailers
            .insert(STREAM_PROOF_B64_TRAILER.to_string(), oversized_encoded);
        oversized.trailers.insert(
            STREAM_PROOF_SHA256_TRAILER.to_string(),
            sha256_prefixed(&oversized_bytes),
        );
        assert!(decode_stream_runtime_proof(&oversized)
            .expect_err("oversized proof")
            .contains("oversized"));
    }

    #[test]
    fn stream_parser_rejects_invalid_head_framing_and_declarations() {
        let cases = [
            (
                "status",
                "HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "version",
                "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "content length",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "transfer coding",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "duplicate header",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "obs-fold",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n folded\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256\r\n\r\n0\r\n\r\n",
            ),
            (
                "missing trailer",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64\r\n\r\n0\r\n\r\n",
            ),
            (
                "duplicate declaration",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-B64\r\n\r\n0\r\n\r\n",
            ),
            (
                "extra declaration",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256, ETag\r\n\r\n0\r\n\r\n",
            ),
        ];
        for (label, wire) in cases {
            assert!(
                parse_stream_wire(wire.as_bytes().to_vec(), 7, 1024).is_err(),
                "accepted {label}"
            );
        }
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nX-Fill: {}\r\n\r\n",
            "a".repeat(MAX_RESPONSE_HEAD_BYTES)
        );
        assert!(parse_stream_wire(oversized.into_bytes(), 4096, 1024).is_err());
    }

    #[test]
    fn stream_parser_rejects_noncanonical_chunks_limits_and_truncation() {
        for chunked in [
            "1;x=y\r\na\r\n",
            "01\r\na\r\n",
            "A\r\n",
            "10000000000000000\r\n",
            "1\r\na\n",
            "2\r\na",
        ] {
            let wire = [stream_head("").as_bytes(), chunked.as_bytes()].concat();
            assert!(parse_stream_wire(wire, 3, 1024).is_err());
        }
        let oversized_line = format!("{}{}\r\n", stream_head(""), "a".repeat(129));
        assert!(parse_stream_wire(oversized_line.into_bytes(), 16, 1024).is_err());
        assert!(parse_stream_wire(valid_stream_wire(), 4, 4).is_err());
        let mut truncated = valid_stream_wire();
        truncated.truncate(truncated.len() - 2);
        assert!(parse_stream_wire(truncated, 2, 1024).is_err());
    }

    #[test]
    fn stream_parser_rejects_bad_trailers_and_bytes_after_completion() {
        let proof = b"{}";
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(proof);
        let digest = sha256_prefixed(proof);
        let cases = [
            format!(
                "0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nX-Extra: value\r\nX-Serverware-Stream-Proof-SHA256: {digest}\r\n\r\n"
            ),
            format!(
                "0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nContent-Length: 0\r\nX-Serverware-Stream-Proof-SHA256: {digest}\r\n\r\n"
            ),
            format!(
                "0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\n X-Serverware-Stream-Proof-SHA256: {digest}\r\n\r\n"
            ),
            format!(
                "0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nX-Serverware-Stream-Proof-SHA256: {digest}\r\n\r\n"
            ),
            format!("0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\n\r\n"),
            format!(
                "0\r\nX-Serverware-Stream-Proof-B64: {encoded}\r\nX-Serverware-Stream-Proof-SHA256: {digest}\r\n\r\nextra"
            ),
        ];
        for trailer_block in cases {
            let wire = [stream_head("").as_bytes(), trailer_block.as_bytes()].concat();
            assert!(parse_stream_wire(wire, 5, 1024).is_err());
        }
        let oversized = format!(
            "{}0\r\nX-Serverware-Stream-Proof-B64: {}\r\n",
            stream_head(""),
            "a".repeat(MAX_TRAILER_LINE_BYTES)
        );
        assert!(parse_stream_wire(oversized.into_bytes(), 4096, 1024).is_err());
    }

    fn production_proof(verifier_key: &SigningKey) -> (Value, [u8; 32], SigningKey) {
        let nonce_bytes = [7u8; 32];
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let instance_id = "spiffe://prod.serverware/decision-gate/test";
        let identity_digest = sha256_prefixed(instance_id.as_bytes());
        let selected_headers = json!({
            "content-length":"32",
            "x-serverware-client-request-digest":digest(0),
            "x-serverware-operation-digest":digest(2),
            "x-serverware-policy-hash":digest(3),
            "x-serverware-request-digest":digest(1),
            "x-serverware-response-body-sha256":digest(4),
        });
        let selected_headers_digest = sha256_prefixed(canonical_json(&selected_headers).as_bytes());
        let tls_channel_binding = json!({
            "type":"tls-exporter",
            "value":general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]),
        });
        let response_key = SigningKey::from_bytes(&[9u8; 32]);
        let (response_public_key_pem, response_key_id) = public_key_material(&response_key);
        let issued_at = now_unix();
        let dispatch_started_at_epoch_ms = issued_at * 1000;
        let dispatch_expires_at_epoch_ms = dispatch_started_at_epoch_ms + 30_000;
        let reservation_expires_at_epoch_ms = dispatch_started_at_epoch_ms + 30_000;
        let release_authority = json!({
            "authority_mode":"atomic",
            "grant_id":"grant:proof-test",
            "approval_id":"approval:proof-test",
            "credential_ref":"credential:proof-test",
            "credential_version":7,
            "request_digest":digest(1),
            "operation_digest":digest(2),
            "attempt_id":digest(12),
            "consumption_identity_digest":digest(8),
            "authorization_state_at_upstream_dispatch":"dispatching",
            "authorization_state_observed_at_epoch_ms":dispatch_started_at_epoch_ms,
            "reservation_expires_at_epoch_ms":reservation_expires_at_epoch_ms,
            "dispatch_expires_at_epoch_ms":dispatch_expires_at_epoch_ms,
        });
        let dispatch_body = canonical_json(&json!({
            "apiVersion":"serverware.releaseAuthorization/v1",
            "ok":true,
            "authorized":true,
            "state":"dispatching",
            "reason":"dispatching",
            "attemptId":digest(12),
            "bindingDigest":digest(8),
            "idempotentReplay":false,
            "grantId":"grant:proof-test",
            "approvalRequestId":"approval:proof-test",
            "reservationExpiresAtEpochMs":reservation_expires_at_epoch_ms,
            "dispatchStartedAtEpochMs":dispatch_started_at_epoch_ms,
            "dispatchExpiresAtEpochMs":dispatch_expires_at_epoch_ms,
            "completionOutcome":null,
            "retryAfterSeconds":0,
            "quotas":[],
            "store":{"backend":"postgres","ha":true},
        }))
        .into_bytes();
        let control_plane_nonce = general_purpose::URL_SAFE_NO_PAD.encode([20u8; 32]);
        let control_plane_key_id = digest(21);
        let control_plane_response_statement = json!({
            "version":"serverware.responseSignature/v2",
            "issued_at_ms":dispatch_started_at_epoch_ms,
            "request":{
                "method":"POST",
                "path":"/api/data-plane/release-authorizations/dispatch",
                "query_sha256":sha256_prefixed(b""),
            },
            "status_code":200,
            "body_sha256":sha256_prefixed(&dispatch_body),
            "nonce":control_plane_nonce,
            "response_signing_key_id":control_plane_key_id,
            "context":{
                "runtime_manifest_digest":digest(22),
                "policy_bundle_digest":digest(3),
                "provenance_digest":digest(7),
                "image_signatures_digest":digest(24),
                "source_tree_digest":digest(25),
            },
        });
        let control_plane_response_statement =
            canonical_json(&control_plane_response_statement).into_bytes();
        let dispatch_request_body = canonical_json(&json!({
            "apiVersion":"serverware.releaseAuthorizationDispatch/v1",
            "attemptId":digest(12),
            "bindingDigest":digest(8),
        }))
        .into_bytes();
        let control_plane_authorization_receipt = json!({
            "apiVersion":"serverware.controlPlaneAuthorizationReceipt/v1",
            "kind":"ControlPlaneAuthorizationReceipt",
            "principal_id":"demo-agent",
            "route_id":"route:proof-test",
            "release_authority":release_authority,
            "request":{
                "method":"POST",
                "path":"/api/data-plane/release-authorizations/dispatch",
                "query":"",
                "nonce":control_plane_nonce,
                "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_request_body),
                "body_sha256":sha256_prefixed(&dispatch_request_body),
            },
            "response":{
                "status":200,
                "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_body),
                "body_sha256":sha256_prefixed(&dispatch_body),
                "response_signing_key_id":control_plane_key_id,
                "statement_b64":general_purpose::URL_SAFE_NO_PAD.encode(&control_plane_response_statement),
                "statement_sha256":sha256_prefixed(&control_plane_response_statement),
                "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode([26u8; 64])),
            },
        });
        let selected_raw_policy_headers_b64 = json!({
            "content-encoding":[],
            "content-length":[general_purpose::URL_SAFE_NO_PAD.encode(b"32")],
            "content-type":[general_purpose::URL_SAFE_NO_PAD.encode(b"application/json")],
        });
        let upstream_body_digest = digest(11);
        let upstream_canonical_digest = sha256_prefixed(
            canonical_json(&json!({
                "status":200,
                "selected_raw_policy_headers_b64":selected_raw_policy_headers_b64,
                "body_digest":upstream_body_digest,
            }))
            .as_bytes(),
        );
        let upstream_response = json!({
            "status":200,
            "selected_raw_policy_headers_b64":selected_raw_policy_headers_b64,
            "body_digest":upstream_body_digest,
            "canonical_digest":upstream_canonical_digest,
        });
        let statement = json!({
            "apiVersion":"serverware.proxyResponseStatement/v2",
            "issued_at_unix":issued_at,
            "client_nonce":nonce,
            "client_request_digest":digest(0),
            "principal_id":"demo-agent",
            "route_id":"route:proof-test",
            "request_digest":digest(1),
            "operation_digest":digest(2),
            "release_authority":release_authority,
            "control_plane_authorization_receipt":control_plane_authorization_receipt,
            "upstream_response":upstream_response,
            "response":{
                "status":200,
                "selected_headers":selected_headers,
                "selected_headers_digest":selected_headers_digest,
                "body_digest":digest(4),
            },
            "policy_digest":digest(3),
            "runtime_manifest_digest":digest(5),
            "data_plane_binary_digest":digest(6),
            "release_digest":digest(7),
            "server_instance":{"id":instance_id,"identity_digest":identity_digest},
            "tls_channel_binding":tls_channel_binding,
        });
        let statement_digest = sha256_prefixed(canonical_json(&statement).as_bytes());
        let response_signature = response_key.sign(canonical_json(&statement).as_bytes());
        let attested_claims = json!({
            "server_statement_sha256":statement_digest,
            "server_statement_api_version":"serverware.proxyResponseStatement/v2",
            "issued_at_unix":issued_at,
            "client_nonce_sha256":sha256_prefixed(&nonce_bytes),
            "client_request_digest":digest(0),
            "principal_id":"demo-agent",
            "route_id":"route:proof-test",
            "request_digest":digest(1),
            "operation_digest":digest(2),
            "release_authority":release_authority,
            "control_plane_authorization_receipt_sha256":sha256_prefixed(canonical_json(&control_plane_authorization_receipt).as_bytes()),
            "upstream_response":upstream_response,
            "response_status":200,
            "selected_response_headers_digest":selected_headers_digest,
            "response_body_digest":digest(4),
            "policy_digest":digest(3),
            "runtime_manifest_digest":digest(5),
            "data_plane_binary_digest":digest(6),
            "release_digest":digest(7),
            "server_instance_id":instance_id,
            "server_instance_identity_digest":identity_digest,
            "tls_channel_binding_type":"tls-exporter",
            "tls_channel_binding_sha256":sha256_prefixed(canonical_json(&tls_channel_binding).as_bytes()),
            "response_signing_key_id":response_key_id,
        });
        let quote = json!({
            "format":"aws-nitro-attestation-document",
            "body_b64":general_purpose::URL_SAFE_NO_PAD.encode([10u8; 96]),
        });
        let (_, verifier_key_id) = public_key_material(verifier_key);
        let verifier_statement = json!({
            "verifier_key_id":verifier_key_id,
            "outcome":"verified",
            "environment":"production",
            "trust_basis":"vendor-root-certificate-chain",
            "vendor_quote_verified":true,
            "certificate_chain_verified":true,
            "revocation_checked":true,
            "debug":false,
            "verified_at_unix":issued_at,
            "expires_at_unix":issued_at + 300,
            "tee_platform":"aws-nitro",
            "quote_provider":"aws-nitro-enclaves",
            "vendor_quote_sha256":sha256_prefixed(canonical_json(&quote).as_bytes()),
            "server_statement_sha256":statement_digest,
            "response_signing_key_id":response_key_id,
            "attested_claims":attested_claims,
        });
        let verifier_signature = verifier_key.sign(canonical_json(&verifier_statement).as_bytes());
        (
            json!({
                "apiVersion":"serverware.proxyResponseRuntimeProof/v2",
                "kind":"ServerwareProxyResponseRuntimeProof",
                "server_statement":statement,
                "server_statement_sha256":statement_digest,
                "server_signature":{
                    "algorithm":"Ed25519",
                    "key_id":response_key_id,
                    "public_key_pem":response_public_key_pem,
                    "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(response_signature.to_bytes())),
                },
                "vendor_tee":{
                    "platform":"aws-nitro",
                    "provider":"aws-nitro-enclaves",
                    "quote_sha256":sha256_prefixed(canonical_json(&quote).as_bytes()),
                    "quote":quote,
                    "trusted_verifier":{
                        "apiVersion":"serverware.vendorTeeVerification/v1",
                        "kind":"ServerwareVendorTeeVerification",
                        "statement":verifier_statement,
                        "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(verifier_signature.to_bytes())),
                    },
                },
            }),
            nonce_bytes,
            response_key,
        )
    }

    fn resign_server_statement(proof: &mut Value, response_key: &SigningKey) {
        let statement = proof["server_statement"].clone();
        let canonical = canonical_json(&statement);
        proof["server_statement_sha256"] = Value::String(sha256_prefixed(canonical.as_bytes()));
        proof["server_signature"]["signature"] = Value::String(format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD
                .encode(response_key.sign(canonical.as_bytes()).to_bytes())
        ));
    }

    fn resign_streaming_statement(proof: &mut Value, response_key: &SigningKey) {
        let statement = proof["streaming_response_statement"].clone();
        let canonical = canonical_json(&statement);
        proof["streaming_response_statement_sha256"] =
            Value::String(sha256_prefixed(canonical.as_bytes()));
        proof["server_signature"]["signature"] = Value::String(format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD
                .encode(response_key.sign(canonical.as_bytes()).to_bytes())
        ));
    }

    fn resign_streaming_attestation(proof: &mut Value, verifier_key: &SigningKey) {
        let statement = proof["streaming_response_statement"].clone();
        let statement_digest = sha256_prefixed(canonical_json(&statement).as_bytes());
        let response = &statement["released_response"];
        let upstream = &statement["upstream_response"];
        let tls = &statement["tls_channel_binding"];
        let server_instance = &statement["server_instance"];
        let raw_headers_digest = sha256_prefixed(
            canonical_json(&upstream["selected_raw_policy_headers_b64"]).as_bytes(),
        );
        let attested_claims = json!({
            "streaming_response_statement_api_version":"serverware.streamingResponseStatement/v1",
            "streaming_response_statement_sha256":statement_digest,
            "issued_at_unix":statement["issued_at_unix"],
            "client_nonce_sha256":sha256_prefixed(
                &general_purpose::URL_SAFE_NO_PAD
                    .decode(statement["client_nonce"].as_str().expect("client nonce"))
                    .expect("decode client nonce")
            ),
            "client_request_digest":statement["client_request_digest"],
            "principal_id":statement["principal_id"],
            "route_id":statement["route_id"],
            "request_digest":statement["request_digest"],
            "operation_digest":statement["operation_digest"],
            "release_authority":statement["release_authority"],
            "authorization_binding_digest":statement["authorization_binding_validation"]["binding_digest"],
            "control_plane_authorization_receipt_sha256":statement["control_plane_authorization_receipt_sha256"],
            "upstream_status":upstream["status"],
            "upstream_selected_raw_policy_headers_digest":raw_headers_digest,
            "upstream_body_digest":upstream["body_digest"],
            "upstream_body_bytes":upstream["body_bytes"],
            "upstream_canonical_digest":upstream["canonical_digest"],
            "released_response_status":response["status"],
            "released_response_content_type":response["content_type"],
            "selected_response_wire_headers_digest":response["selected_wire_headers_digest"],
            "released_response_body_digest":response["body_digest"],
            "released_response_body_bytes":response["body_bytes"],
            "response_framing":response["framing"],
            "response_completion":response["completion"],
            "response_trailer_names":response["trailer_names"],
            "policy_digest":statement["policy_digest"],
            "runtime_manifest_digest":statement["runtime_manifest_digest"],
            "data_plane_binary_digest":statement["data_plane_binary_digest"],
            "release_digest":statement["release_digest"],
            "server_instance_id":server_instance["id"],
            "server_instance_identity_digest":server_instance["identity_digest"],
            "tls_channel_binding_type":tls["type"],
            "tls_exporter_label":tls["exporter_label"],
            "tls_channel_binding_sha256":sha256_prefixed(canonical_json(tls).as_bytes()),
            "response_signing_key_id":proof["server_signature"]["key_id"],
        });
        let trusted = proof["vendor_tee"]["trusted_verifier"]
            .as_object_mut()
            .expect("trusted verifier");
        let mut verifier_statement = trusted["statement"].clone();
        verifier_statement
            .as_object_mut()
            .expect("verifier statement")
            .remove("server_statement_sha256");
        verifier_statement["streaming_response_statement_sha256"] = Value::String(statement_digest);
        verifier_statement["attested_claims"] = attested_claims;
        trusted.insert("statement".to_string(), verifier_statement.clone());
        trusted.insert(
            "signature".to_string(),
            Value::String(format!(
                "ed25519:{}",
                general_purpose::URL_SAFE_NO_PAD.encode(
                    verifier_key
                        .sign(canonical_json(&verifier_statement).as_bytes())
                        .to_bytes()
                )
            )),
        );
    }

    fn streaming_proof(verifier_key: &SigningKey) -> (Value, [u8; 32], SigningKey) {
        let (buffered, nonce_bytes, response_key) = production_proof(verifier_key);
        let mut statement = buffered["server_statement"].clone();
        let authority = statement["release_authority"].clone();
        let binding = json!({
            "attempt_id":authority["attempt_id"],
            "flow_id":authority["attempt_id"],
            "principal_id":statement["principal_id"],
            "route_id":statement["route_id"],
            "credential_id":authority["credential_ref"],
            "credential_version":authority["credential_version"],
            "policy_hash":statement["policy_digest"],
            "request_digest":statement["request_digest"],
            "operation_digest":statement["operation_digest"],
            "operation_context":{},
            "require_jit_grant":true,
            "shared_quotas":[],
        });
        let binding_digest = sha256_prefixed(canonical_json_ensure_ascii(&binding).as_bytes());
        let binding_commitment = json!({
            "attempt_id":binding["attempt_id"],
            "flow_id":binding["flow_id"],
            "principal_id":binding["principal_id"],
            "route_id":binding["route_id"],
            "credential_id":binding["credential_id"],
            "credential_version":binding["credential_version"],
            "policy_hash":binding["policy_hash"],
            "request_digest":binding["request_digest"],
            "operation_digest":binding["operation_digest"],
            "operation_context_digest":sha256_prefixed(
                canonical_json_ensure_ascii(&binding["operation_context"]).as_bytes()
            ),
            "require_jit_grant":binding["require_jit_grant"],
            "shared_quotas":binding["shared_quotas"],
        });
        statement["release_authority"]["consumption_identity_digest"] =
            Value::String(binding_digest.clone());
        statement["control_plane_authorization_receipt"]["release_authority"]
            ["consumption_identity_digest"] = Value::String(binding_digest.clone());

        let request_body = canonical_json(&json!({
            "apiVersion":"serverware.releaseAuthorizationDispatch/v1",
            "attemptId":statement["release_authority"]["attempt_id"],
            "bindingDigest":binding_digest,
        }))
        .into_bytes();
        statement["control_plane_authorization_receipt"]["request"]["body_b64"] =
            Value::String(general_purpose::URL_SAFE_NO_PAD.encode(&request_body));
        statement["control_plane_authorization_receipt"]["request"]["body_sha256"] =
            Value::String(sha256_prefixed(&request_body));

        let encoded_response = statement["control_plane_authorization_receipt"]["response"]
            ["body_b64"]
            .as_str()
            .expect("receipt response body");
        let mut response_body: Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(encoded_response)
                .expect("decode receipt response body"),
        )
        .expect("parse receipt response body");
        response_body["bindingDigest"] = Value::String(binding_digest.clone());
        let response_body = canonical_json(&response_body).into_bytes();
        let response_body_digest = sha256_prefixed(&response_body);
        statement["control_plane_authorization_receipt"]["response"]["body_b64"] =
            Value::String(general_purpose::URL_SAFE_NO_PAD.encode(&response_body));
        statement["control_plane_authorization_receipt"]["response"]["body_sha256"] =
            Value::String(response_body_digest.clone());

        let encoded_response_statement = statement["control_plane_authorization_receipt"]
            ["response"]["statement_b64"]
            .as_str()
            .expect("receipt response statement");
        let mut response_statement: Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(encoded_response_statement)
                .expect("decode receipt response statement"),
        )
        .expect("parse receipt response statement");
        response_statement["body_sha256"] = Value::String(response_body_digest);
        let response_statement = canonical_json(&response_statement).into_bytes();
        statement["control_plane_authorization_receipt"]["response"]["statement_b64"] =
            Value::String(general_purpose::URL_SAFE_NO_PAD.encode(&response_statement));
        statement["control_plane_authorization_receipt"]["response"]["statement_sha256"] =
            Value::String(sha256_prefixed(&response_statement));

        let receipt_digest = sha256_prefixed(
            canonical_json(&statement["control_plane_authorization_receipt"]).as_bytes(),
        );
        statement["control_plane_authorization_receipt_sha256"] = Value::String(receipt_digest);
        statement["authorization_binding_validation"] = json!({
            "status":"validated",
            "binding_commitment":binding_commitment,
            "binding_digest":binding_digest,
        });
        let upstream = statement["upstream_response"]
            .as_object_mut()
            .expect("upstream response");
        upstream.insert("body_bytes".to_string(), json!(32));
        let upstream_canonical = json!({
            "status":upstream["status"],
            "selected_raw_policy_headers_b64":upstream["selected_raw_policy_headers_b64"],
            "body_digest":upstream["body_digest"],
            "body_bytes":upstream["body_bytes"],
        });
        upstream.insert(
            "canonical_digest".to_string(),
            Value::String(sha256_prefixed(
                canonical_json(&upstream_canonical).as_bytes(),
            )),
        );
        let selected_wire_headers = json!({
            "connection":"close",
            "content-type":"application/json",
            "trailer":"X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256",
            "transfer-encoding":"chunked",
        });
        let selected_wire_headers_digest =
            sha256_prefixed(canonical_json(&selected_wire_headers).as_bytes());
        statement["released_response"] = json!({
            "status":200,
            "content_type":"application/json",
            "selected_wire_headers":selected_wire_headers,
            "selected_wire_headers_digest":selected_wire_headers_digest,
            "body_digest":digest(4),
            "body_bytes":32,
            "framing":"http1.1-chunked-trailers",
            "completion":"normal-eof",
            "trailer_names":[
                "X-Serverware-Stream-Proof-B64",
                "X-Serverware-Stream-Proof-SHA256"
            ],
        });
        statement
            .as_object_mut()
            .expect("statement")
            .remove("response");
        statement["apiVersion"] =
            Value::String("serverware.streamingResponseStatement/v1".to_string());
        statement["tls_channel_binding"]["exporter_label"] =
            Value::String("EXPORTER-Serverware-Proxy-Stream-v1".to_string());
        let canonical = canonical_json(&statement);
        let statement_digest = sha256_prefixed(canonical.as_bytes());
        let signature = response_key.sign(canonical.as_bytes());
        let mut proof = json!({
            "apiVersion":"serverware.streamingResponseRuntimeProof/v1",
            "kind":"ServerwareStreamingResponseRuntimeProof",
            "streaming_response_statement":statement,
            "streaming_response_statement_sha256":statement_digest,
            "server_signature":{
                "algorithm":"Ed25519",
                "key_id":buffered["server_signature"]["key_id"],
                "public_key_pem":buffered["server_signature"]["public_key_pem"],
                "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            },
            "vendor_tee":buffered["vendor_tee"],
        });
        resign_streaming_attestation(&mut proof, verifier_key);
        (proof, nonce_bytes, response_key)
    }

    fn streaming_statement_with_quota(window_kind: &str, window_seconds: Option<u64>) -> Value {
        let verifier_key = SigningKey::from_bytes(&[11u8; 32]);
        let (proof, _, _) = streaming_proof(&verifier_key);
        let mut statement = proof["streaming_response_statement"].clone();
        let mut quota = json!({
            "counter_key":digest(30),
            "constraint_id":"quota:proof-test",
            "operation":"tweets.create",
            "window_kind":window_kind,
            "max_count":1,
        });
        if let Some(window_seconds) = window_seconds {
            quota
                .as_object_mut()
                .expect("quota commitment")
                .insert("window_seconds".to_string(), json!(window_seconds));
        }
        statement["authorization_binding_validation"]["binding_commitment"]["shared_quotas"] =
            json!([quota]);
        statement
    }

    #[test]
    fn streaming_authorization_binding_accepts_fixed_and_calendar_quota_commitments() {
        for (window_kind, window_seconds) in [
            ("fixed", Some(86_400)),
            ("utcDay", None),
            ("utcIsoWeek", None),
            ("utcMonth", None),
        ] {
            let statement = streaming_statement_with_quota(window_kind, window_seconds);
            let binding = validate_streaming_authorization_binding(&statement)
                .unwrap_or_else(|error| panic!("valid {window_kind} quota: {error}"));
            let quota = &binding["shared_quotas"][0];
            assert_eq!(quota["window_kind"], window_kind);
            assert_eq!(
                quota.get("window_seconds").and_then(Value::as_u64),
                window_seconds
            );
        }
    }

    #[test]
    fn streaming_authorization_binding_rejects_quota_shape_substitution() {
        let fixed_without_seconds = streaming_statement_with_quota("fixed", None);
        assert!(
            validate_streaming_authorization_binding(&fixed_without_seconds)
                .expect_err("fixed quota without window_seconds")
                .contains("missing or unexpected fields")
        );

        let calendar_with_seconds = streaming_statement_with_quota("utcDay", Some(86_400));
        assert!(
            validate_streaming_authorization_binding(&calendar_with_seconds)
                .expect_err("calendar quota with window_seconds")
                .contains("missing or unexpected fields")
        );

        let mut missing_window_kind = streaming_statement_with_quota("fixed", Some(60));
        missing_window_kind["authorization_binding_validation"]["binding_commitment"]
            ["shared_quotas"][0]
            .as_object_mut()
            .expect("quota commitment")
            .remove("window_kind");
        assert!(
            validate_streaming_authorization_binding(&missing_window_kind)
                .expect_err("quota without window_kind")
                .contains("window_kind is invalid")
        );

        let mut unexpected_field = streaming_statement_with_quota("utcMonth", None);
        unexpected_field["authorization_binding_validation"]["binding_commitment"]["shared_quotas"]
            [0]
        .as_object_mut()
        .expect("quota commitment")
        .insert("calendar_window".to_string(), json!("utcMonth"));
        assert!(validate_streaming_authorization_binding(&unexpected_field)
            .expect_err("quota with unexpected field")
            .contains("missing or unexpected fields"));

        let unknown_window_kind = streaming_statement_with_quota("sliding", None);
        assert!(
            validate_streaming_authorization_binding(&unknown_window_kind)
                .expect_err("quota with unknown window_kind")
                .contains("window_kind is invalid")
        );
    }

    fn captured_stream_response() -> StreamResponse {
        StreamResponse {
            status: 200,
            headers: BTreeMap::from([
                ("connection".to_string(), "close".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "trailer".to_string(),
                    "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256".to_string(),
                ),
                ("transfer-encoding".to_string(), "chunked".to_string()),
            ]),
            trailers: BTreeMap::new(),
            body_digest: digest(4),
            body_bytes: 32,
        }
    }

    fn streaming_expectations<'a>(
        nonce: &'a str,
        exporter: &'a str,
    ) -> RuntimeProofExpectations<'a> {
        RuntimeProofExpectations {
            nonce,
            tls_exporter: exporter,
            peer_spiffe_id: "spiffe://prod.serverware/decision-gate/test",
            peer_leaf_digest: Box::leak(Box::new(digest(9))),
            client_request_digest: Box::leak(Box::new(digest(0))),
            principal_id: "demo-agent",
            max_age_seconds: 300,
        }
    }

    #[test]
    fn streaming_runtime_proof_rejects_wrong_hash_count_exporter_version_and_signature() {
        let verifier_key = SigningKey::from_bytes(&[11u8; 32]);
        let (proof, nonce_bytes, response_key) = streaming_proof(&verifier_key);
        let response = captured_stream_response();
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let exporter = general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
        let expectations = streaming_expectations(&nonce, &exporter);
        let capture = verify_stream_runtime_proof(&proof, &response, &expectations)
            .expect("valid streaming runtime proof");
        assert_eq!(
            capture["apiVersion"],
            "serverware.streamingProxyResponseCapture/v1"
        );
        let directory = test_directory("stream-verifier");
        let verifier_path = directory.join("verifier.pem");
        fs::write(&verifier_path, public_key_material(&verifier_key).0)
            .expect("write stream verifier key");
        let statement = &proof["streaming_response_statement"];
        assert_eq!(
            verify_vendor_tee_for_mode(
                &proof,
                statement,
                &nonce_bytes,
                Some(&verifier_path),
                Some("spiffe://prod.serverware/decision-gate/test"),
                300,
                true,
            )
            .expect("valid streaming attestation"),
            "production"
        );
        let mut wrong_attestation = proof.clone();
        wrong_attestation["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]
            ["released_response_body_bytes"] = json!(31);
        let verifier_statement =
            wrong_attestation["vendor_tee"]["trusted_verifier"]["statement"].clone();
        wrong_attestation["vendor_tee"]["trusted_verifier"]["signature"] = Value::String(format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(
                verifier_key
                    .sign(canonical_json(&verifier_statement).as_bytes())
                    .to_bytes()
            )
        ));
        assert!(verify_vendor_tee_for_mode(
            &wrong_attestation,
            &wrong_attestation["streaming_response_statement"],
            &nonce_bytes,
            Some(&verifier_path),
            Some("spiffe://prod.serverware/decision-gate/test"),
            300,
            true,
        )
        .expect_err("attested claim substitution")
        .contains("do not exactly match"));
        fs::remove_dir_all(directory).expect("remove stream verifier directory");

        let mut wrong_hash = proof.clone();
        wrong_hash["streaming_response_statement"]["released_response"]["body_digest"] =
            Value::String(digest(5));
        resign_streaming_statement(&mut wrong_hash, &response_key);
        assert!(
            verify_stream_runtime_proof(&wrong_hash, &response, &expectations)
                .expect_err("wrong projected hash")
                .contains("body digest")
        );

        let mut wrong_count = proof.clone();
        wrong_count["streaming_response_statement"]["released_response"]["body_bytes"] = json!(31);
        resign_streaming_statement(&mut wrong_count, &response_key);
        assert!(
            verify_stream_runtime_proof(&wrong_count, &response, &expectations)
                .expect_err("wrong projected count")
                .contains("byte count")
        );

        let mut wrong_exporter = proof.clone();
        wrong_exporter["streaming_response_statement"]["tls_channel_binding"]["value"] =
            Value::String(general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]));
        resign_streaming_statement(&mut wrong_exporter, &response_key);
        assert!(
            verify_stream_runtime_proof(&wrong_exporter, &response, &expectations)
                .expect_err("wrong exporter")
                .contains("TLS exporter")
        );

        let mut wrong_version = proof.clone();
        wrong_version["apiVersion"] =
            Value::String("serverware.proxyResponseRuntimeProof/v2".to_string());
        assert!(
            verify_stream_runtime_proof(&wrong_version, &response, &expectations)
                .expect_err("wrong runtime version")
                .contains("wrong type")
        );

        let mut unexpected_claim = proof.clone();
        unexpected_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]
            ["unexpected"] = json!(true);
        assert!(
            verify_stream_runtime_proof(&unexpected_claim, &response, &expectations)
                .expect_err("unexpected attested claim")
                .contains("missing or unexpected fields")
        );

        let mut wrong_signature = proof;
        wrong_signature["server_signature"]["signature"] = Value::String(format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
        ));
        assert!(
            verify_stream_runtime_proof(&wrong_signature, &response, &expectations)
                .expect_err("wrong signature")
                .contains("verification failed")
        );
    }

    #[test]
    fn staged_stream_body_is_anonymous_and_released_only_after_verification() {
        let verifier_key = SigningKey::from_bytes(&[11u8; 32]);
        let (proof, nonce_bytes, _) = streaming_proof(&verifier_key);
        let response = captured_stream_response();
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let exporter = general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
        let expectations = streaming_expectations(&nonce, &exporter);
        let directory = test_directory("staging");
        let target = directory.join("verified.body");

        {
            let mut staged = StagedBody::create(target.clone()).expect("create staged body");
            staged
                .file_mut()
                .expect("staging file")
                .write_all(&[4u8; 32])
                .expect("write staged body");
            assert_eq!(
                fs::read_dir(&directory)
                    .expect("read staging directory")
                    .count(),
                0,
                "unverified response bytes must not have a directory entry"
            );
            assert!(!target.exists());
            let mut invalid = proof.clone();
            invalid["apiVersion"] = Value::String("wrong".to_string());
            assert!(verify_stream_runtime_proof(&invalid, &response, &expectations).is_err());
        }
        assert_eq!(
            fs::read_dir(&directory)
                .expect("read staging directory after close")
                .count(),
            0
        );
        assert!(!target.exists());

        let mut staged = StagedBody::create(target.clone()).expect("recreate staged body");
        staged
            .file_mut()
            .expect("staging file")
            .write_all(&[4u8; 32])
            .expect("write staged body");
        verify_stream_runtime_proof(&proof, &response, &expectations)
            .expect("verify before release");
        assert!(!target.exists());
        let released = staged
            .release(&sha256_prefixed(&[4u8; 32]), 32)
            .expect("atomically release body");
        assert_eq!(released.path, target);
        assert_eq!(released.publication, BodyPublication::Published);
        assert_eq!(fs::read(&target).expect("read released body"), [4u8; 32]);
        assert_eq!(file_mode(&target), 0o400);

        let mut overwrite = StagedBody::create(target.clone()).expect("stage overwrite attempt");
        overwrite
            .file_mut()
            .expect("overwrite staging file")
            .write_all(b"replacement")
            .expect("write overwrite attempt");
        assert!(overwrite
            .release(&sha256_prefixed(b"replacement"), 11)
            .is_err());
        assert_eq!(fs::read(&target).expect("original body remains"), [4u8; 32]);
        fs::remove_dir_all(directory).expect("remove staging test directory");
    }

    #[test]
    fn streaming_proof_output_is_atomically_published_without_replacement() {
        let directory = test_directory("proof-no-replace");
        let target = directory.join("proof.json");
        fs::write(&target, b"existing").expect("create competing proof output");
        assert!(atomic_write_private_noreplace(&target, b"replacement").is_err());
        assert_eq!(fs::read(&target).expect("read original proof"), b"existing");

        let fresh = directory.join("fresh-proof.json");
        atomic_write_private_noreplace(&fresh, b"verified").expect("publish fresh proof");
        assert_eq!(fs::read(&fresh).expect("read fresh proof"), b"verified");
        assert_eq!(file_mode(&fresh), 0o400);
        fs::remove_dir_all(directory).expect("remove proof output test directory");
    }

    #[test]
    fn streaming_proof_is_the_commit_marker_and_failed_publication_removes_body() {
        let directory = test_directory("proof-commit-marker");
        let body = directory.join("body.bin");
        let proof = directory.join("proof.json");
        fs::write(&proof, b"existing-proof").expect("create competing proof");
        let mut staged = StagedBody::create(body.clone()).expect("stage body");
        staged
            .file_mut()
            .expect("staging file")
            .write_all(b"verified-body")
            .expect("write verified body");
        assert!(publish_verified_stream_outputs(
            staged,
            &proof,
            b"new-proof",
            &sha256_prefixed(b"verified-body"),
            13,
        )
        .is_err());
        assert!(!body.exists());
        assert_eq!(
            fs::read(&proof).expect("original proof remains"),
            b"existing-proof"
        );
        fs::remove_dir_all(directory).expect("remove commit marker test directory");
    }

    #[test]
    fn streaming_publication_recovers_an_exact_crash_orphan_body() {
        let directory = test_directory("proof-orphan-recovery");
        let body = directory.join("body.bin");
        let proof = directory.join("proof.json");
        fs::write(&body, b"verified-body").expect("create crash-orphaned body");
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600))
            .expect("make orphan body private");
        let mut staged = StagedBody::create(body.clone()).expect("stage repeated body");
        staged
            .file_mut()
            .expect("staging file")
            .write_all(b"verified-body")
            .expect("write repeated verified body");
        let recovered = publish_verified_stream_outputs(
            staged,
            &proof,
            b"verified-proof",
            &sha256_prefixed(b"verified-body"),
            13,
        )
        .expect("recover exact crash orphan");
        assert_eq!(recovered, body);
        assert_eq!(
            fs::read(&body).expect("read recovered body"),
            b"verified-body"
        );
        assert_eq!(
            fs::read(&proof).expect("read recovered proof"),
            b"verified-proof"
        );
        assert_eq!(file_mode(&body), 0o400);
        assert_eq!(file_mode(&proof), 0o400);
        fs::remove_dir_all(directory).expect("remove orphan recovery test directory");
    }

    #[test]
    fn losing_publisher_that_reuses_body_never_removes_it() {
        let directory = test_directory("proof-reused-body-loss");
        let body = directory.join("body.bin");
        let proof = directory.join("proof.json");
        fs::write(&body, b"verified-body").expect("create shared body");
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600))
            .expect("make shared body private");
        fs::write(&proof, b"winning-proof").expect("create winning proof");

        let result = publish_verified_stream_outputs(
            stage_body(body.clone(), b"verified-body"),
            &proof,
            b"losing-proof",
            &sha256_prefixed(b"verified-body"),
            13,
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(&body).expect("shared body remains"),
            b"verified-body"
        );
        assert_eq!(
            fs::read(&proof).expect("winning proof remains"),
            b"winning-proof"
        );
        fs::remove_dir_all(directory).expect("remove reused-body race directory");
    }

    #[test]
    fn concurrent_publishers_retain_the_single_winning_body() {
        const PUBLISHERS: usize = 8;
        let directory = test_directory("concurrent-publishers");
        let body = directory.join("body.bin");
        let proof = directory.join("proof.json");
        let barrier = Arc::new(Barrier::new(PUBLISHERS));
        let mut publishers = Vec::new();
        for index in 0..PUBLISHERS {
            let staged = stage_body(body.clone(), b"verified-body");
            let barrier = Arc::clone(&barrier);
            let proof = proof.clone();
            publishers.push(thread::spawn(move || {
                let payload = format!("proof-{index}");
                barrier.wait();
                (
                    payload.clone(),
                    publish_verified_stream_outputs(
                        staged,
                        &proof,
                        payload.as_bytes(),
                        &sha256_prefixed(b"verified-body"),
                        13,
                    ),
                )
            }));
        }

        let results = publishers
            .into_iter()
            .map(|publisher| publisher.join().expect("publisher thread"))
            .collect::<Vec<_>>();
        let winners = results
            .iter()
            .filter(|(_, result)| result.is_ok())
            .collect::<Vec<_>>();
        assert_eq!(winners.len(), 1);
        assert_eq!(
            fs::read(&body).expect("winning body remains"),
            b"verified-body"
        );
        assert_eq!(
            fs::read(&proof).expect("read winning proof"),
            winners[0].0.as_bytes()
        );
        fs::remove_dir_all(directory).expect("remove concurrent publisher directory");
    }

    #[test]
    fn orphan_body_open_rejects_symlinks_without_following_them() {
        let directory = test_directory("orphan-nofollow");
        let actual = directory.join("actual.bin");
        let body = directory.join("body.bin");
        let proof = directory.join("proof.json");
        fs::write(&actual, b"verified-body").expect("create symlink target");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o600))
            .expect("make symlink target private");
        symlink(&actual, &body).expect("create body symlink");

        let error = publish_verified_stream_outputs(
            stage_body(body.clone(), b"verified-body"),
            &proof,
            b"proof",
            &sha256_prefixed(b"verified-body"),
            13,
        )
        .expect_err("symlink body must be rejected");
        assert!(error.contains("without following symlinks"));
        assert!(!proof.exists());
        assert_eq!(
            fs::read(&actual).expect("symlink target remains"),
            b"verified-body"
        );
        fs::remove_dir_all(directory).expect("remove nofollow directory");
    }

    #[test]
    fn body_substitution_after_validation_aborts_before_proof_commit() {
        let directory = test_directory("body-inode-swap");
        let body = directory.join("body.bin");
        let displaced = directory.join("displaced.bin");
        let proof = directory.join("proof.json");
        fs::write(&body, b"verified-body").expect("create orphan body");
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600))
            .expect("make orphan body private");

        let error = publish_verified_stream_outputs_with_precommit(
            stage_body(body.clone(), b"verified-body"),
            &proof,
            b"proof",
            &sha256_prefixed(b"verified-body"),
            13,
            || {
                fs::rename(&body, &displaced)
                    .map_err(|err| format!("displace verified body: {err}"))?;
                fs::write(&body, b"verified-body")
                    .map_err(|err| format!("replace verified body path: {err}"))?;
                fs::set_permissions(&body, fs::Permissions::from_mode(0o400))
                    .map_err(|err| format!("make replacement private: {err}"))?;
                Ok(())
            },
        )
        .expect_err("inode substitution must abort publication");
        assert!(error.contains("stream body output entry changed before proof commit"));
        assert!(!proof.exists());
        assert_eq!(
            fs::read(&body).expect("replacement remains"),
            b"verified-body"
        );
        assert_eq!(
            fs::read(&displaced).expect("verified descriptor inode remains"),
            b"verified-body"
        );
        fs::remove_dir_all(directory).expect("remove inode swap directory");
    }

    #[test]
    fn cleanup_quarantines_and_retains_a_substitution_after_validation() {
        let directory = test_directory("cleanup-substitution");
        let body = directory.join("body.bin");
        let displaced = directory.join("owned-body.bin");
        let released = stage_body(body.clone(), b"verified-body")
            .release(&sha256_prefixed(b"verified-body"), 13)
            .expect("release owned body");

        let error = released
            .remove_owned_unpublished_with_prequarantine(|| {
                fs::rename(&body, &displaced)
                    .map_err(|err| format!("displace owned body: {err}"))?;
                fs::write(&body, b"substitution")
                    .map_err(|err| format!("create substituted body: {err}"))?;
                fs::set_permissions(&body, fs::Permissions::from_mode(0o600))
                    .map_err(|err| format!("make substituted body private: {err}"))?;
                Ok(())
            })
            .expect_err("substituted inode must never be unlinked");
        assert!(error.contains("substituted or unsafe inode"));
        assert_eq!(
            fs::read(&displaced).expect("owned body remains displaced"),
            b"verified-body"
        );
        let quarantined = fs::read_dir(&directory)
            .expect("read cleanup directory")
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".serverware-retained.")
            })
            .expect("substituted inode is retained for manual review");
        assert_eq!(
            fs::read(quarantined.path()).expect("read quarantined substitution"),
            b"substitution"
        );
        fs::remove_dir_all(directory).expect("remove cleanup substitution directory");
    }

    #[test]
    fn stream_output_resolution_rejects_parent_and_symlinked_intermediate_components() {
        let parent_components = test_directory("parent-components");
        let parent_error = ResolvedOutputTarget::resolve(
            &parent_components.join("child/../proof.json"),
            "test output",
            true,
            false,
        )
        .err()
        .expect("parent traversal must be rejected");
        assert!(parent_error.contains("must not contain '..'"));
        fs::remove_dir_all(parent_components).expect("remove parent component directory");

        let symlink_parent = test_directory("symlink-output-ancestor");
        let actual = symlink_parent.join("actual");
        let nested = actual.join("nested");
        fs::create_dir(&actual).expect("create actual output ancestor");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700))
            .expect("make actual output ancestor private");
        fs::create_dir(&nested).expect("create nested output directory");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .expect("make nested output directory private");
        let linked = symlink_parent.join("linked");
        symlink(&actual, &linked).expect("create intermediate output symlink");
        let error = ResolvedOutputTarget::resolve(
            &linked.join("nested/proof.json"),
            "test output",
            true,
            true,
        )
        .err()
        .expect("symlinked intermediate output ancestor must be rejected");
        assert!(error.contains("without following symlinks"));
        fs::remove_dir_all(symlink_parent).expect("remove symlink output ancestor directory");
    }

    #[test]
    fn ancestor_substitution_during_traversal_stays_on_opened_directory_fds() {
        let root = test_directory("ancestor-substitution");
        let anchor = root.join("anchor");
        let displaced = root.join("opened-anchor");
        fs::create_dir(&anchor).expect("create traversal anchor");
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700))
            .expect("make traversal anchor private");
        let mut substituted = false;
        let target = ResolvedOutputTarget::resolve_with_hook(
            &anchor.join("final/body.bin"),
            "test output",
            true,
            false,
            |component, _| {
                if component == OsStr::new("anchor") && !substituted {
                    fs::rename(&anchor, &displaced)
                        .map_err(|err| format!("displace opened ancestor: {err}"))?;
                    fs::create_dir(&anchor)
                        .map_err(|err| format!("create substituted ancestor: {err}"))?;
                    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700))
                        .map_err(|err| format!("make substituted ancestor private: {err}"))?;
                    let substituted_final = anchor.join("final");
                    fs::create_dir(&substituted_final)
                        .map_err(|err| format!("create substituted final directory: {err}"))?;
                    fs::set_permissions(&substituted_final, fs::Permissions::from_mode(0o700))
                        .map_err(|err| {
                            format!("make substituted final directory private: {err}")
                        })?;
                    substituted = true;
                }
                Ok(())
            },
        )
        .expect("resolve through retained ancestor descriptors");
        assert!(substituted);
        assert_eq!(
            target.directory.identity,
            FileIdentity::from_metadata(
                &fs::metadata(displaced.join("final")).expect("opened final metadata")
            )
        );
        assert_ne!(
            target.directory.identity,
            FileIdentity::from_metadata(
                &fs::metadata(anchor.join("final")).expect("substituted final metadata")
            )
        );
        let mut probe = target
            .directory
            .create_new(OsStr::new("probe"))
            .expect("create descriptor-relative probe");
        probe.write_all(b"opened").expect("write probe");
        assert_eq!(
            fs::read(displaced.join("final/probe")).expect("read opened-directory probe"),
            b"opened"
        );
        assert!(!anchor.join("final/probe").exists());
        fs::remove_dir_all(root).expect("remove ancestor substitution directory");
    }

    #[test]
    fn body_and_proof_targets_share_final_directory_identity() {
        let root = test_directory("same-directory-identity");
        let output = root.join("new/private/output");
        let body = ResolvedOutputTarget::resolve(
            &output.join("body.bin"),
            "stream body output",
            true,
            false,
        )
        .expect("resolve body target and create parents");
        let proof = ResolvedOutputTarget::resolve(
            &output.join("./proof.json"),
            "stream proof output",
            true,
            true,
        )
        .expect("resolve proof target");
        assert_eq!(body.directory.identity, proof.directory.identity);
        assert_eq!(
            fs::metadata(&output).expect("output metadata").mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("new"))
                .expect("created ancestor metadata")
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(root).expect("remove same-directory identity directory");
    }

    #[test]
    fn stale_publication_scavenging_is_exact_bounded_and_preserves_final_names() {
        let directory = test_directory("stale-scavenging");
        let body_name = OsStr::new("body.bin");
        let proof_name = OsStr::new("proof.json");
        let target = ResolvedOutputTarget::resolve(
            &directory.join(body_name),
            "stream body output",
            true,
            false,
        )
        .expect("resolve scavenging directory");
        let stale_body = verified_body_temporary_name(body_name, 41, &[0x11; 16]);
        let stale_quarantine = quarantine_name(42, &[0x22; 16]);
        let fresh_proof = proof_temporary_name(proof_name, 43, &[0x33; 16]);
        let near_miss = OsString::from(format!(
            ".body.bin.44.{}.verified.tmp.extra",
            hex::encode([0x44; 16])
        ));
        for name in [&stale_body, &stale_quarantine, &fresh_proof, &near_miss] {
            fs::write(directory.join(name), b"temporary").expect("write cleanup fixture");
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
                .expect("make cleanup fixture private");
        }
        fs::write(directory.join(body_name), b"final-body").expect("write final body fixture");
        fs::write(directory.join(proof_name), b"final-proof").expect("write final proof fixture");
        fs::set_permissions(directory.join(body_name), fs::Permissions::from_mode(0o400))
            .expect("make final body read-only");
        fs::set_permissions(
            directory.join(proof_name),
            fs::Permissions::from_mode(0o400),
        )
        .expect("make final proof read-only");
        for name in [&stale_body, &stale_quarantine, &near_miss] {
            make_stale(&directory.join(name));
        }
        let _lock = PublicationLock::acquire(&target.directory, body_name)
            .expect("acquire publication lock for scavenging");
        assert_eq!(
            target
                .directory
                .scavenge_stale_entries(body_name, proof_name)
                .expect("scavenge stale publication entries"),
            2
        );
        assert!(!directory.join(stale_body).exists());
        assert!(!directory.join(stale_quarantine).exists());
        assert!(directory.join(fresh_proof).exists());
        assert!(directory.join(near_miss).exists());
        assert_eq!(fs::read(directory.join(body_name)).unwrap(), b"final-body");
        assert_eq!(
            fs::read(directory.join(proof_name)).unwrap(),
            b"final-proof"
        );
        fs::remove_dir_all(directory).expect("remove stale scavenging directory");
    }

    #[test]
    fn stale_scavenging_caps_removals_per_lock_hold() {
        let directory = test_directory("bounded-scavenging");
        let body_name = OsStr::new("body.bin");
        let proof_name = OsStr::new("proof.json");
        let target = ResolvedOutputTarget::resolve(
            &directory.join(body_name),
            "stream body output",
            true,
            false,
        )
        .expect("resolve bounded scavenging directory");
        for index in 0..MAX_SCAVENGE_REMOVALS + 4 {
            let name = quarantine_name(100 + index as u32, &[index as u8; 16]);
            fs::write(directory.join(&name), b"stale").expect("write bounded stale fixture");
            fs::set_permissions(directory.join(&name), fs::Permissions::from_mode(0o600))
                .expect("make bounded stale fixture private");
            make_stale(&directory.join(name));
        }
        let _lock = PublicationLock::acquire(&target.directory, body_name)
            .expect("acquire publication lock for bounded scavenging");
        assert_eq!(
            target
                .directory
                .scavenge_stale_entries(body_name, proof_name)
                .expect("perform bounded stale cleanup"),
            MAX_SCAVENGE_REMOVALS
        );
        let remaining = fs::read_dir(&directory)
            .expect("read bounded cleanup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".serverware-quarantine.")
            })
            .count();
        assert_eq!(remaining, 4);
        fs::remove_dir_all(directory).expect("remove bounded scavenging directory");
    }

    #[test]
    fn stale_scavenging_refuses_unsafe_and_substituted_entries() {
        let directory = test_directory("unsafe-scavenging");
        let body_name = OsStr::new("body.bin");
        let proof_name = OsStr::new("proof.json");
        let target = ResolvedOutputTarget::resolve(
            &directory.join(body_name),
            "stream body output",
            true,
            false,
        )
        .expect("resolve unsafe scavenging directory");
        let symlink_name = verified_body_temporary_name(body_name, 51, &[0x51; 16]);
        let hardlink_name = proof_temporary_name(proof_name, 52, &[0x52; 16]);
        let wrong_mode_name = quarantine_name(53, &[0x53; 16]);
        let outside = directory.join("outside");
        fs::write(&outside, b"outside").expect("write outside fixture");
        symlink(&outside, directory.join(&symlink_name)).expect("create stale symlink fixture");
        fs::hard_link(&outside, directory.join(&hardlink_name))
            .expect("create stale hard-link fixture");
        fs::write(directory.join(&wrong_mode_name), b"wrong-mode")
            .expect("write wrong-mode fixture");
        fs::set_permissions(
            directory.join(&wrong_mode_name),
            fs::Permissions::from_mode(0o644),
        )
        .expect("set unsafe fixture mode");
        make_stale(&outside);
        make_stale(&directory.join(&wrong_mode_name));
        let _lock = PublicationLock::acquire(&target.directory, body_name)
            .expect("acquire publication lock for unsafe scavenging");
        assert_eq!(
            target
                .directory
                .scavenge_stale_entries(body_name, proof_name)
                .expect("skip unsafe stale entries"),
            0
        );
        assert!(fs::symlink_metadata(directory.join(&symlink_name))
            .expect("symlink fixture remains")
            .file_type()
            .is_symlink());
        assert!(directory.join(&hardlink_name).exists());
        assert!(directory.join(&wrong_mode_name).exists());

        let substituted_name = verified_body_temporary_name(body_name, 54, &[0x54; 16]);
        let displaced = directory.join("displaced-owned-temp");
        fs::write(directory.join(&substituted_name), b"owned-temp")
            .expect("write substitution candidate");
        fs::set_permissions(
            directory.join(&substituted_name),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make substitution candidate private");
        make_stale(&directory.join(&substituted_name));
        let error = target
            .directory
            .scavenge_stale_entries_with_hook(body_name, proof_name, |name| {
                if name == substituted_name {
                    fs::rename(directory.join(name), &displaced)
                        .map_err(|err| format!("displace stale cleanup candidate: {err}"))?;
                    fs::write(directory.join(name), b"substitution")
                        .map_err(|err| format!("write stale substitution: {err}"))?;
                    fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
                        .map_err(|err| format!("make stale substitution private: {err}"))?;
                    make_stale(&directory.join(name));
                }
                Ok(())
            })
            .expect_err("substituted stale entry must be retained");
        assert!(error.contains("substituted or unsafe inode"));
        assert_eq!(fs::read(displaced).unwrap(), b"owned-temp");
        let retained = fs::read_dir(&directory)
            .expect("read retained substitution directory")
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".serverware-retained.")
            })
            .expect("substitution retained under a non-scavenged name");
        assert_eq!(fs::read(retained.path()).unwrap(), b"substitution");
        fs::remove_dir_all(directory).expect("remove unsafe scavenging directory");
    }

    #[test]
    fn stream_outputs_reject_insecure_and_split_directories() {
        let insecure = test_directory("insecure-output");
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755))
            .expect("make output directory insecure");
        let error = StagedBody::create(insecure.join("body.bin"))
            .err()
            .expect("world-readable output directory must be rejected");
        assert!(error.contains("exact-mode 0700"));
        assert!(error.contains("same-UID processes are trusted"));
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o700))
            .expect("restore output directory for cleanup");
        fs::remove_dir_all(insecure).expect("remove insecure output directory");

        let body_directory = test_directory("split-body-output");
        let proof_directory = test_directory("split-proof-output");
        let body = body_directory.join("body.bin");
        let proof = proof_directory.join("proof.json");
        let error = publish_verified_stream_outputs(
            stage_body(body.clone(), b"verified-body"),
            &proof,
            b"proof",
            &sha256_prefixed(b"verified-body"),
            13,
        )
        .expect_err("split output directories must be rejected");
        assert!(error.contains("must resolve through directory fds to the same"));
        assert!(!body.exists());
        assert!(!proof.exists());
        fs::remove_dir_all(body_directory).expect("remove split body directory");
        fs::remove_dir_all(proof_directory).expect("remove split proof directory");
    }

    #[test]
    fn production_vendor_receipt_requires_pinned_valid_signature_and_exact_claims() {
        let verifier_key = SigningKey::from_bytes(&[11u8; 32]);
        let (verifier_pem, _) = public_key_material(&verifier_key);
        let key_path = env::temp_dir().join(format!(
            "serverware-proof-verifier-{}-{}.pem",
            std::process::id(),
            now_unix()
        ));
        fs::write(&key_path, verifier_pem).expect("write test verifier key");
        let (proof, nonce_bytes, _) = production_proof(&verifier_key);
        let statement = proof.get("server_statement").expect("statement");
        assert_eq!(
            verify_vendor_tee(
                &proof,
                statement,
                &nonce_bytes,
                Some(&key_path),
                Some("spiffe://prod.serverware/decision-gate/test"),
                300,
            )
            .expect("valid production vendor receipt"),
            "production"
        );
        assert!(verify_vendor_tee(
            &proof,
            statement,
            &nonce_bytes,
            None,
            Some("spiffe://prod.serverware/decision-gate/test"),
            300,
        )
        .expect_err("production evidence without verifier key")
        .contains("--verifier-key"));

        let mut tampered = proof.clone();
        tampered["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]
            ["request_digest"] = Value::String(digest(0));
        let tampered_statement = tampered["vendor_tee"]["trusted_verifier"]["statement"].clone();
        let signature = verifier_key.sign(canonical_json(&tampered_statement).as_bytes());
        tampered["vendor_tee"]["trusted_verifier"]["signature"] = Value::String(format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ));
        assert!(verify_vendor_tee(
            &tampered,
            tampered.get("server_statement").expect("statement"),
            &nonce_bytes,
            Some(&key_path),
            Some("spiffe://prod.serverware/decision-gate/test"),
            300,
        )
        .expect_err("signed but false attested claims")
        .contains("do not exactly match"));
        fs::remove_file(key_path).expect("remove test verifier key");
    }

    #[test]
    fn runtime_v2_requires_exact_atomic_release_authority() {
        let verifier_key = SigningKey::from_bytes(&[11u8; 32]);
        let (proof, nonce_bytes, response_key) = production_proof(&verifier_key);
        let selected = proof["server_statement"]["response"]["selected_headers"]
            .as_object()
            .expect("selected headers");
        let response = HttpResponse {
            status: 200,
            headers: selected
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        value.as_str().expect("header value").to_string(),
                    )
                })
                .collect(),
            body: vec![4; 32],
        };
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let tls_exporter = general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
        let expectations = RuntimeProofExpectations {
            nonce: &nonce,
            tls_exporter: &tls_exporter,
            peer_spiffe_id: "spiffe://prod.serverware/decision-gate/test",
            peer_leaf_digest: &digest(9),
            client_request_digest: &digest(0),
            principal_id: "demo-agent",
            max_age_seconds: 300,
        };
        let capture = verify_runtime_proof(&proof, &response, &expectations)
            .expect("valid authority-bound runtime proof");
        assert_eq!(capture["apiVersion"], "serverware.proxyResponseCapture/v2");
        assert_eq!(
            capture["release_authority"],
            proof["server_statement"]["release_authority"]
        );
        assert_eq!(
            capture["upstream_response"],
            proof["server_statement"]["upstream_response"]
        );

        let mut missing = proof.clone();
        missing["server_statement"]
            .as_object_mut()
            .expect("statement")
            .remove("release_authority");
        resign_server_statement(&mut missing, &response_key);
        assert!(verify_runtime_proof(&missing, &response, &expectations)
            .expect_err("missing v3 authority must fail closed")
            .contains("release_authority"));

        let mut mismatched = proof.clone();
        let substituted_request_digest = Value::String(digest(10));
        mismatched["server_statement"]["request_digest"] = substituted_request_digest.clone();
        mismatched["server_statement"]["release_authority"]["request_digest"] =
            substituted_request_digest;
        resign_server_statement(&mut mismatched, &response_key);
        assert!(verify_runtime_proof(&mismatched, &response, &expectations)
            .expect_err("mismatched v3 authority must fail closed")
            .contains("control-plane authorization receipt authority substitution"));

        let mut partial_grant = proof.clone();
        partial_grant["server_statement"]["release_authority"]["approval_id"] = Value::Null;
        resign_server_statement(&mut partial_grant, &response_key);
        assert!(
            verify_runtime_proof(&partial_grant, &response, &expectations)
                .expect_err("partial grant identity must fail closed")
                .contains("must be paired")
        );

        let mut invalid_credential = proof.clone();
        invalid_credential["server_statement"]["release_authority"]["credential_ref"] = Value::Null;
        resign_server_statement(&mut invalid_credential, &response_key);
        assert!(
            verify_runtime_proof(&invalid_credential, &response, &expectations)
                .expect_err("credential identity and version mismatch must fail closed")
                .contains("inconsistent")
        );

        let mut invalid_attempt = proof.clone();
        invalid_attempt["server_statement"]["release_authority"]["attempt_id"] =
            Value::String("attempt:not-a-digest".to_string());
        resign_server_statement(&mut invalid_attempt, &response_key);
        assert!(
            verify_runtime_proof(&invalid_attempt, &response, &expectations)
                .expect_err("non-digest attempt identity must fail closed")
                .contains("must be canonical lowercase sha256")
        );

        let mut invalid_time = proof.clone();
        let issued_at = invalid_time["server_statement"]["issued_at_unix"]
            .as_u64()
            .expect("issued at");
        invalid_time["server_statement"]["release_authority"]
            ["authorization_state_observed_at_epoch_ms"] = json!((issued_at + 2) * 1000);
        resign_server_statement(&mut invalid_time, &response_key);
        assert!(
            verify_runtime_proof(&invalid_time, &response, &expectations)
                .expect_err("post-statement authorization observation must fail closed")
                .contains("temporally invalid")
        );

        let mut raw_header_tamper = proof.clone();
        raw_header_tamper["server_statement"]["upstream_response"]
            ["selected_raw_policy_headers_b64"]["content-type"] =
            json!([general_purpose::URL_SAFE_NO_PAD.encode(b"text/plain")]);
        resign_server_statement(&mut raw_header_tamper, &response_key);
        assert!(
            verify_runtime_proof(&raw_header_tamper, &response, &expectations)
                .expect_err("raw upstream header tamper must fail closed")
                .contains("canonical upstream response binding")
        );

        let mut false_completion_claim = proof.clone();
        let authority = false_completion_claim["server_statement"]["release_authority"]
            .as_object_mut()
            .expect("release authority");
        authority.remove("authorization_state_at_upstream_dispatch");
        authority.insert(
            "completion_outcome".to_string(),
            Value::String("forwarded".to_string()),
        );
        resign_server_statement(&mut false_completion_claim, &response_key);
        assert!(
            verify_runtime_proof(&false_completion_claim, &response, &expectations)
                .expect_err("inline proof must reject a forwarded completion claim")
                .contains("completion_outcome")
        );

        let mut mismatched_upstream_status = proof.clone();
        mismatched_upstream_status["server_statement"]["upstream_response"]["status"] = json!(201);
        resign_server_statement(&mut mismatched_upstream_status, &response_key);
        assert!(
            verify_runtime_proof(&mismatched_upstream_status, &response, &expectations)
                .expect_err("mismatched upstream status must fail closed")
                .contains("upstream_response.status must match response.status")
        );

        let mut legacy = proof;
        legacy["apiVersion"] = Value::String("serverware.proxyResponseRuntimeProof/v1".to_string());
        assert!(verify_runtime_proof(&legacy, &response, &expectations)
            .expect_err("legacy runtime proofs must not satisfy v3 collection")
            .contains("wrong type"));
    }
}
