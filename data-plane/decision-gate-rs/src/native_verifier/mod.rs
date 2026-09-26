//! Standalone, offline verification of the original native response envelope.
//!
//! No network, subprocess, environment configuration, private key or copied
//! verifier result participates. Successful output proves only the fixed local
//! signature/quote profile; it is not an actionable production admission.

mod cbor;
mod certificates;
mod cli;
mod config;
mod json;
mod nitro;
mod statement;
mod ingress;
mod ingress_certificates;
mod ingress_cli;
mod ingress_config;

use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn run() -> Result<(), String> { cli::run() }
pub(crate) fn run_ingress() -> Result<(), String> { ingress_cli::run() }

pub(super) fn verify_ingress(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8])
    -> Result<Vec<u8>, String> {
    let result = ingress::verify(raw, expectations_raw, trust_roots_raw)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native ingress verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native ingress verdict exceeds its bound")?;
    Ok(bytes)
}

fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8])
    -> Result<Vec<u8>, String> {
    let expected = config::Expectations::parse(expectations_raw)?;
    let roots = config::TrustRoots::parse(trust_roots_raw)?;
    let result = statement::verify(raw, &expected, &roots)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "encode native verdict")?;
    ensure(!bytes.is_empty() && bytes.len() < 4096, "native verdict exceeds its bound")?;
    Ok(bytes)
}

fn ensure(condition: bool, error: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_owned()) }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| "missing native text field".to_owned())
}

fn uint(value: &Value, key: &str) -> Result<u64, String> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| "missing native unsigned integer".to_owned())
}

fn exact(value: &Value, fields: &[&str]) -> Result<(), String> {
    let map = value.as_object().ok_or("native value must be an object")?;
    ensure(map.len() == fields.len() && fields.iter().all(|key| map.contains_key(*key)),
        "native object fields are not exact")
}

fn digest(value: &[u8]) -> [u8; 32] { Sha256::digest(value).into() }
fn digest_text(value: &[u8]) -> String { format!("sha256:{}", hex::encode(value)) }
fn b64(value: &[u8]) -> String { general_purpose::URL_SAFE_NO_PAD.encode(value) }

fn decode_b64(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= maximum.saturating_mul(4).saturating_add(2) / 3,
        "native base64url exceeds its bound")?;
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| "native base64url is invalid")?;
    ensure(!bytes.is_empty() && bytes.len() <= maximum && b64(&bytes) == value,
        "native base64url is not canonical")?;
    Ok(bytes)
}

fn fixed_b64<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode_b64(value, N)?.try_into().map_err(|_| "native base64url size differs".to_owned())
}

fn parse_digest<const N: usize>(value: &str, prefix: &str, nonzero: bool) -> Result<[u8; N], String> {
    let encoded = value.strip_prefix(prefix).ok_or("native digest prefix differs")?;
    ensure(encoded.len() == N * 2
        && encoded.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native digest is not canonical")?;
    let mut result = [0; N];
    hex::decode_to_slice(encoded, &mut result).map_err(|_| "native digest is invalid")?;
    ensure(!nonzero || result != [0; N], "native digest must be nonzero")?;
    Ok(result)
}

fn now_seconds() -> Result<u64, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native verifier clock is invalid")?.as_secs();
    ensure(now > 0, "native verifier clock is invalid")?;
    Ok(now)
}

fn fresh(issued: u64, now: u64, expected: &config::Expectations) -> Result<(), String> {
    ensure(issued > 0
        && issued <= now.checked_add(expected.future_skew).ok_or("native age overflow")?
        && now.saturating_sub(issued) <= expected.max_age, "native evidence is not fresh")
}

/// Exact canonical ASCII PEM armor; DER is parsed by the appropriate key or
/// certificate verifier. No permissive PEM prefix/suffix or multi-object load.
fn pem_der(pem: &str, label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    ensure(!pem.is_empty() && pem.len() <= maximum && pem.is_ascii(), "native PEM exceeds its bound")?;
    let head = format!("-----BEGIN {label}-----\n");
    let tail = format!("-----END {label}-----\n");
    let body = pem.strip_prefix(&head).and_then(|text| text.strip_suffix(&tail))
        .ok_or("native PEM armor differs")?;
    let compact: String = body.chars().filter(|ch| *ch != '\n').collect();
    let bytes = general_purpose::STANDARD.decode(&compact).map_err(|_| "native PEM base64 is invalid")?;
    ensure(!bytes.is_empty(), "native PEM is empty")?;
    let encoded = general_purpose::STANDARD.encode(&bytes);
    let mut canonical = head;
    for line in encoded.as_bytes().chunks(64) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| "native PEM cannot be encoded")?);
        canonical.push('\n');
    }
    canonical.push_str(&tail);
    ensure(canonical == pem, "native PEM is not canonical")?;
    Ok(bytes)
}
