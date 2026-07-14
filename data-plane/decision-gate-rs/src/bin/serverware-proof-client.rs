use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Serverware-Proxy-Response-v1";
const MAX_RESPONSE_HEAD_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

struct Args {
    proxy: String,
    url: Url,
    ca: PathBuf,
    out: PathBuf,
    collector_key: PathBuf,
    verifier_key: Option<PathBuf>,
    expected_server_instance_id: Option<String>,
    client_nonce: Option<[u8; 32]>,
    proxy_headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    timeout_seconds: u64,
    max_age_seconds: u64,
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
    max_age_seconds: u64,
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization failed")
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

fn parse_args() -> Result<Args, String> {
    let mut proxy = None;
    let mut url = None;
    let mut ca = None;
    let mut out = None;
    let mut collector_key = None;
    let mut verifier_key = None;
    let mut expected_server_instance_id = None;
    let mut client_nonce = None;
    let mut proxy_headers = Vec::new();
    let mut request_headers = Vec::new();
    let mut timeout_seconds = 20u64;
    let mut max_age_seconds = 300u64;
    let mut values = env::args().skip(1);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--proxy" => proxy = Some(value),
            "--url" => url = Some(Url::parse(&value).map_err(|err| format!("parse --url: {err}"))?),
            "--ca" => ca = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            "--collector-key" => collector_key = Some(PathBuf::from(value)),
            "--verifier-key" => verifier_key = Some(PathBuf::from(value)),
            "--expected-server-instance-id" => expected_server_instance_id = Some(value),
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
            _ => return Err(format!("unknown argument {flag}")),
        }
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
    if let Some(instance_id) = expected_server_instance_id.as_deref() {
        if !instance_id.starts_with("spiffe://") || instance_id.len() <= "spiffe://".len() {
            return Err("--expected-server-instance-id must be a non-empty SPIFFE ID".to_string());
        }
    }
    Ok(Args {
        proxy: proxy.ok_or("--proxy is required")?,
        url,
        ca: ca.ok_or("--ca is required")?,
        out: out.ok_or("--out is required")?,
        collector_key: collector_key.ok_or("--collector-key is required")?,
        verifier_key,
        expected_server_instance_id,
        client_nonce,
        proxy_headers,
        request_headers,
        timeout_seconds,
        max_age_seconds,
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
    )
}

fn canonical_client_proof_request(
    url: &Url,
    request_headers: &[(String, String)],
) -> Result<Value, String> {
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
        "apiVersion":"serverware.clientProofRequest/v1",
        "method":"GET",
        "scheme":url.scheme().to_ascii_lowercase(),
        "authority":canonical_authority(url),
        "path":url.path(),
        "query":query,
        "headers":headers,
        "body_sha256":sha256_prefixed(b""),
    }))
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
        if buffer.len() > maximum {
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

fn atomic_write_private(path: &Path, payload: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or("proof output path must have a parent directory")?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("create output directory {}: {err}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("proof"),
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|err| format!("create proof temporary file {}: {err}", temporary.display()))?;
        file.write_all(payload)
            .map_err(|err| format!("write proof temporary file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("sync proof temporary file: {err}"))?;
        fs::rename(&temporary, path)
            .map_err(|err| format!("replace proof output {}: {err}", path.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| format!("sync proof output directory: {err}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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

fn verify_vendor_tee(
    proof: &Value,
    statement: &Value,
    nonce_bytes: &[u8],
    verifier_key_path: Option<&Path>,
    expected_server_instance_id: Option<&str>,
    max_age_seconds: u64,
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
    if verifier_statement
        .get("server_statement_sha256")
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
    let response = required_object(statement, "response")?;
    let response_value = Value::Object(response.clone());
    let tls_channel_binding = required_object(statement, "tls_channel_binding")?;
    let nonce = required_string(statement, "client_nonce")?;
    if general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes) != nonce {
        return Err("server statement nonce bytes mismatch".to_string());
    }
    let issued_at = required_u64(statement, "issued_at_unix")?;
    if issued_at > now.saturating_add(30) || now.saturating_sub(issued_at) > max_age_seconds {
        return Err("server response statement is stale".to_string());
    }
    let expected_claims = json!({
        "server_statement_sha256":statement_digest,
        "server_statement_api_version":"serverware.proxyResponseStatement/v1",
        "issued_at_unix":issued_at,
        "client_nonce_sha256":sha256_prefixed(nonce_bytes),
        "client_request_digest":required_digest(statement, "client_request_digest")?,
        "request_digest":required_digest(statement, "request_digest")?,
        "operation_digest":required_digest(statement, "operation_digest")?,
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
    });
    if verifier_statement.get("attested_claims") != Some(&expected_claims) {
        return Err(
            "vendor TEE attested claims do not exactly match the response statement".to_string(),
        );
    }
    Ok("production")
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
    let max_age_seconds = expectations.max_age_seconds;
    if proof.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.proxyResponseRuntimeProof/v1")
        || proof.get("kind").and_then(Value::as_str) != Some("ServerwareProxyResponseRuntimeProof")
    {
        return Err("runtime response proof has the wrong type".to_string());
    }
    let statement = proof
        .get("server_statement")
        .filter(|value| value.is_object())
        .ok_or("runtime proof is missing server_statement")?;
    if statement.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.proxyResponseStatement/v1")
    {
        return Err("server response statement has the wrong version".to_string());
    }
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
    required_digest(statement, "request_digest")?;
    required_digest(statement, "operation_digest")?;
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
        "apiVersion":"serverware.proxyResponseCapture/v1",
        "environment":"production",
        "collection_mode":"external-client-capture",
        "captured_at_unix":now_unix(),
        "client_nonce":nonce,
        "client_request_digest":expected_client_request_digest,
        "request_digest":required_string(statement, "request_digest")?,
        "operation_digest":required_string(statement, "operation_digest")?,
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

fn collect(args: Args) -> Result<Value, String> {
    let canonical_client_request =
        canonical_client_proof_request(&args.url, &args.request_headers)?;
    let expected_client_request_digest =
        sha256_prefixed(canonical_json(&canonical_client_request).as_bytes());
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
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nX-Serverware-Proof-Nonce: {nonce}\r\n"
    );
    for (name, value) in &args.request_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .map_err(|err| format!("write proof request: {err}"))?;
    tls.flush()
        .map_err(|err| format!("flush proof request: {err}"))?;
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
    external_capture["client_request"] = canonical_client_request;
    let collector_key = load_collector_key(&args.collector_key)?;
    let (collector_public_key_pem, collector_key_id) = public_key_material(&collector_key);
    let collector_signature = collector_key.sign(canonical_json(&external_capture).as_bytes());
    let proof = json!({
        "apiVersion":"serverware.proxyResponseProof/v2",
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
        "request_digest":capture.get("request_digest"),
        "operation_digest":capture.get("operation_digest"),
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

    fn digest(byte: u8) -> String {
        sha256_prefixed(&[byte; 32])
    }

    #[test]
    fn client_request_digest_is_computed_from_client_observable_material() {
        let url = Url::parse("https://EXAMPLE.com.:443/a%20b?z=2&a=one%20two&a=one").unwrap();
        let canonical = canonical_client_proof_request(
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

    fn production_proof(verifier_key: &SigningKey) -> (Value, [u8; 32]) {
        let nonce_bytes = [7u8; 32];
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let instance_id = "spiffe://prod.serverware/decision-gate/test";
        let identity_digest = sha256_prefixed(instance_id.as_bytes());
        let selected_headers = json!({
            "content-length":"2",
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
        let (_, response_key_id) = public_key_material(&response_key);
        let issued_at = now_unix();
        let statement = json!({
            "apiVersion":"serverware.proxyResponseStatement/v1",
            "issued_at_unix":issued_at,
            "client_nonce":nonce,
            "client_request_digest":digest(0),
            "request_digest":digest(1),
            "operation_digest":digest(2),
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
        let attested_claims = json!({
            "server_statement_sha256":statement_digest,
            "server_statement_api_version":"serverware.proxyResponseStatement/v1",
            "issued_at_unix":issued_at,
            "client_nonce_sha256":sha256_prefixed(&nonce_bytes),
            "client_request_digest":digest(0),
            "request_digest":digest(1),
            "operation_digest":digest(2),
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
                "server_statement":statement,
                "server_signature":{"key_id":response_key_id},
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
        )
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
        let (proof, nonce_bytes) = production_proof(&verifier_key);
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
}
