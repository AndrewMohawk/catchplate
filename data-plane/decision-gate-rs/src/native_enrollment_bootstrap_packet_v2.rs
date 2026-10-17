//! Bounded data-only decoding of the exact unsigned bootstrap packet original.
//! No signature, policy, caller identity, key possession, or effect is admitted.
//! Consumers must verify every original under their existing clock and roots.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::collections::BTreeMap;

pub(crate) const MAX_PACKET_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Packet {
    api_version: String,
    purpose: String,
    delegation_base64url: String,
    setup_authorization_base64url: String,
    target_request_base64url: String,
    target_issuer_certificate_der_base64url: String,
    policy_requirements_base64url: String,
}

/// Decoded bytes only, never a verified-authority carrier.
pub(crate) struct BootstrapPacketOriginalsV2 {
    delegation: Vec<u8>,
    setup: Vec<u8>,
    request: Vec<u8>,
    issuer: Vec<u8>,
    requirements: Vec<u8>,
}

impl BootstrapPacketOriginalsV2 {
    pub(crate) fn delegation_original(&self) -> &[u8] { &self.delegation }
    pub(crate) fn setup_original(&self) -> &[u8] { &self.setup }
    pub(crate) fn target_request_original(&self) -> &[u8] { &self.request }
    pub(crate) fn target_issuer_original(&self) -> &[u8] { &self.issuer }
    pub(crate) fn policy_requirements_original(&self) -> &[u8] { &self.requirements }
}

fn invalid() -> String { "native bootstrap packet original is invalid".into() }
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

pub(crate) fn decode_original(packet: &[u8]) -> Result<BootstrapPacketOriginalsV2, String> {
    require(packet.len() > 1 && packet.len() <= MAX_PACKET_BYTES && packet.last() == Some(&b'\n'))?;
    let body = &packet[..packet.len() - 1];
    // Every accepted field/value is fixed ASCII or base64url. No escape, nested
    // object, array, or extra framing is needed; bound shape before decoding.
    require(body.is_ascii() && !body.iter().any(|byte| matches!(byte, b'\n' | b'\r' | b'\\')))?;
    let (mut quoted, mut depth, mut strings) = (false, 0usize, 0usize);
    for byte in body {
        if *byte == b'"' {
            quoted = !quoted;
            if quoted { strings += 1; require(strings <= 14)?; }
        } else if !quoted {
            match byte {
                b'{' => { depth += 1; require(depth == 1)?; }
                b'}' => { require(depth == 1)?; depth -= 1; }
                b'[' | b']' => return Err(invalid()),
                _ => {},
            }
        }
    }
    require(!quoted && depth == 0 && strings == 14)?;
    let value: Packet = serde_json::from_slice(body).map_err(|_| invalid())?;
    require(value.api_version == "catchplate.nativeEnrollmentPacket/v2" && value.purpose == "workload-bootstrap")?;
    let fields: BTreeMap<&str, &str> = [
        ("apiVersion", value.api_version.as_str()), ("purpose", value.purpose.as_str()),
        ("delegationBase64url", value.delegation_base64url.as_str()),
        ("setupAuthorizationBase64url", value.setup_authorization_base64url.as_str()),
        ("targetRequestBase64url", value.target_request_base64url.as_str()),
        ("targetIssuerCertificateDerBase64url", value.target_issuer_certificate_der_base64url.as_str()),
        ("policyRequirementsBase64url", value.policy_requirements_base64url.as_str()),
    ].into_iter().collect();
    require(serde_json::to_vec(&fields).map_err(|_| invalid())?.as_slice() == body)?;
    Ok(BootstrapPacketOriginalsV2 {
        delegation: decode(&value.delegation_base64url, 32 * 1024)?,
        setup: decode(&value.setup_authorization_base64url, 32 * 1024)?,
        request: decode(&value.target_request_base64url, 64 * 1024)?,
        issuer: decode(&value.target_issuer_certificate_der_base64url, 64 * 1024)?,
        requirements: decode(&value.policy_requirements_base64url, 64 * 1024)?,
    })
}
