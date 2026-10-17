//! Closed public-original request for the one native bootstrap exchange.
//! Decoding is data extraction, not caller, setup, target or signing authority.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::collections::BTreeMap;

pub(crate) const PATH: &str = "/_catchplate/native-enrollment/bootstrap";
pub(crate) const MAX_REQUEST_BYTES: usize = 192 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    delegation_base64url: String,
    setup_authorization_base64url: String,
    target_request_base64url: String,
}

/// Public original bytes only; never an authenticated or installed result.
pub(crate) struct BootstrapRequestOriginalsV1 {
    delegation: Vec<u8>,
    setup: Vec<u8>,
    target: Vec<u8>,
}

impl BootstrapRequestOriginalsV1 {
    pub(crate) fn delegation_original(&self) -> &[u8] { &self.delegation }
    pub(crate) fn setup_original(&self) -> &[u8] { &self.setup }
    pub(crate) fn target_request_original(&self) -> &[u8] { &self.target }
}

fn invalid() -> String { "native bootstrap exchange original is invalid".to_owned() }
fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err(invalid()) }
}

fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    require(!value.is_empty() && value.len() <= (maximum * 4 + 2) / 3
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))?;
    let original = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
    require(!original.is_empty() && original.len() <= maximum
        && URL_SAFE_NO_PAD.encode(&original) == value)?;
    Ok(original)
}

pub(crate) fn decode_original(raw: &[u8]) -> Result<BootstrapRequestOriginalsV1, String> {
    require(raw.len() > 1 && raw.len() <= MAX_REQUEST_BYTES && raw.last() == Some(&b'\n'))?;
    let body = &raw[..raw.len() - 1];
    // Flat fixed strings/base64 need no escape, container nesting or JSON
    // whitespace. Bound parser shape before allocating decoded originals.
    require(body.is_ascii() && !body.iter().any(|byte| matches!(byte, b'\n' | b'\r' | b'\\')))?;
    let (mut quoted, mut depth, mut strings) = (false, 0usize, 0usize);
    for byte in body {
        if *byte == b'"' {
            quoted = !quoted;
            if quoted { strings += 1; require(strings <= 8)?; }
        } else if !quoted {
            match byte {
                b'{' => { depth += 1; require(depth == 1)?; }
                b'}' => { require(depth == 1)?; depth -= 1; }
                b'[' | b']' => return Err(invalid()),
                _ => {},
            }
        }
    }
    require(!quoted && depth == 0 && strings == 8)?;
    let value: Request = serde_json::from_slice(body).map_err(|_| invalid())?;
    require(value.api_version == "catchplate.nativeEnrollmentBootstrapRequest/v1")?;
    let fields: BTreeMap<&str, &str> = [
        ("apiVersion", value.api_version.as_str()),
        ("delegationBase64url", value.delegation_base64url.as_str()),
        ("setupAuthorizationBase64url", value.setup_authorization_base64url.as_str()),
        ("targetRequestBase64url", value.target_request_base64url.as_str()),
    ].into_iter().collect();
    require(serde_json::to_vec(&fields).map_err(|_| invalid())?.as_slice() == body)?;
    Ok(BootstrapRequestOriginalsV1 {
        delegation: decode(&value.delegation_base64url, 32 * 1024)?,
        setup: decode(&value.setup_authorization_base64url, 32 * 1024)?,
        target: decode(&value.target_request_base64url, 64 * 1024)?,
    })
}
