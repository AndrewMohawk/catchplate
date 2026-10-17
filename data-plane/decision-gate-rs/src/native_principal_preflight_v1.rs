//! Public wire recipes, never principal authentication or a TLS owner.
//!
//! The runtime authenticates the actual request and constructs the statement.
//! The independent receiver authenticates its quote and own expectations. The
//! separate request exporter is secret: it must never be included in evidence,
//! unlike the existing public session exporter. Its HMAC avoids publishing
//! guessable raw commitments to identity headers or proxy tokens.

use crate::{canonical_json_bytes, decode_canonical_json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const EVIDENCE_SELECTOR: &str = "principal-v3";
pub const REQUEST_EXPORTER_LABEL: &[u8] = b"EXPORTER-Catchplate-Native-Principal-Request-v1";
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_STATEMENT_BYTES: usize = 4096;
const REQUEST_DOMAIN: &[u8] = b"catchplate/native-principal-request-binding/v1\0";
const NONCE_DOMAIN: &[u8] = b"catchplate/native-principal-session-challenge/v1\0";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    method: String,
    target: String,
    http_version: String,
    headers: BTreeMap<String, String>,
}

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native principal request binding violates its fixed profile".into()) }
}

fn token(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
        || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Normalize nothing: both owners supply the exact lower-case map used by the
/// real HTTP head. Values must already be trim-stable and contain no controls.
/// Only authentication headers may vary; this cannot select a method or route.
pub fn request_original(method: &str, target: &str, http_version: &str,
    headers: &BTreeMap<String, String>) -> Result<Vec<u8>, String> {
    require(method == "GET" && target == "/attestation" && http_version == "HTTP/1.1"
        && !headers.is_empty() && headers.len() <= 128)?;
    let mut size = 128usize;
    for (name, value) in headers {
        require(!name.is_empty() && name.len() <= 128 && name.bytes().all(token)
            && !value.is_empty() && value.len() <= 8192 && value.trim() == value
            && !value.chars().any(char::is_control))?;
        size = size.checked_add(name.len()).and_then(|size| size.checked_add(value.len()))
            .and_then(|size| size.checked_add(8)).ok_or("native principal request size overflow")?;
        require(size <= MAX_REQUEST_BYTES)?;
    }
    let get = |name: &str| headers.get(name).map(String::as_str);
    require(get("x-catchplate-ingress-evidence") == Some(EVIDENCE_SELECTOR)
        && get("host").is_some() && get("content-length").is_none()
        && get("transfer-encoding").is_none())?;
    match get("connection") {
        Some("close") => require(get("x-catchplate-ingress-continuation").is_none())?,
        Some("keep-alive") => require(get("x-catchplate-ingress-continuation") == Some("connect-v1"))?,
        _ => return Err("native principal request connection profile differs".into()),
    }
    let challenge = get("x-catchplate-ingress-challenge").ok_or("native principal challenge is absent")?;
    require(challenge.len() == 43)?;
    let decoded = URL_SAFE_NO_PAD.decode(challenge).map_err(|_| "native principal challenge encoding differs")?;
    require(decoded.len() == 32 && decoded.iter().any(|byte| *byte != 0)
        && URL_SAFE_NO_PAD.encode(&decoded) == challenge)?;
    let raw = canonical_json_bytes(&Request { method: method.into(), target: target.into(),
        http_version: http_version.into(), headers: headers.clone() })
        .map_err(|_| "encode native principal request original")?;
    require(raw.len() <= MAX_REQUEST_BYTES)?;
    Ok(raw)
}

/// HMAC-SHA256(secret exporter, domain || request_length:u64BE || exact request).
/// The actual connection exports this separate key with raw challenge context.
/// This function accepts bytes, not a successful TLS or authentication verdict.
pub fn request_binding(secret_exporter: [u8; 32], original: &[u8]) -> Result<[u8; 32], String> {
    require(secret_exporter != [0; 32] && !original.is_empty() && original.len() <= MAX_REQUEST_BYTES)?;
    let request: Request = decode_canonical_json(original)
        .map_err(|_| "native principal request original is not canonical")?;
    require(request_original(&request.method, &request.target, &request.http_version,
        &request.headers)? == original)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret_exporter);
    let mut context = hmac::Context::with_key(&key);
    context.update(REQUEST_DOMAIN);
    context.update(&(original.len() as u64).to_be_bytes());
    context.update(original);
    let signed = context.sign();
    let mut result = [0u8; 32];
    result.copy_from_slice(signed.as_ref());
    Ok(result)
}

/// New domain; never a reinterpretation of the existing v1/v2 session nonce.
/// The source-owned statement must additionally pass its exact typed contract
/// and genuine principal/quote admission at the respective server/receiver.
pub fn derive_nonce(challenge: [u8; 32], exporter: [u8; 32],
    statement_original: &[u8]) -> Result<[u8; 32], String> {
    require(challenge != [0; 32] && exporter != [0; 32] && !statement_original.is_empty()
        && statement_original.len() <= MAX_STATEMENT_BYTES)?;
    let _: serde_json::Value = decode_canonical_json(statement_original)
        .map_err(|_| "native principal statement original is not canonical")?;
    let mut hash = Sha256::new();
    hash.update(NONCE_DOMAIN);
    hash.update(challenge);
    hash.update(exporter);
    hash.update(Sha256::digest(statement_original));
    Ok(hash.finalize().into())
}
