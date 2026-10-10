//! Explicit whole-JSON buffering for generic REST; never an opaque or streaming fallback.
use crate::{
    normalized_media_type, sensitive_json_value_from_slice, validate_response_header_allowlist,
    ResponseSecretGuard, SensitiveResponseBytes, MAX_BUFFERED_RESPONSE_BODY_BYTES,
    SAFE_RESPONSE_HEADERS, SensitiveReleasedHeaders,
};
use reqwest::{header::HeaderMap, StatusCode};
use serde_json::{json, Map, Value};
use std::io::{self, Write};

pub(crate) const MODE: &str = "bufferedPassthrough";
pub(crate) const JSON_OR_EMPTY_204_MODE: &str = "bufferedJsonOrEmpty204V1";
pub(crate) const JSON_OR_EMPTY_204_V2_MODE: &str = "bufferedJsonOrEmpty204V2";
pub(crate) const JSON_OR_EMPTY_204_PRESENCE: &str = "jsonOrEmpty204V1";
const MAX_ERROR_BYTES: u64 = 65_536;

pub(crate) fn supported_mode(mode: &str) -> bool {
    matches!(mode, MODE | JSON_OR_EMPTY_204_MODE | JSON_OR_EMPTY_204_V2_MODE)
}

pub(crate) fn json_or_empty_204_mode(mode: &str) -> bool {
    matches!(mode, JSON_OR_EMPTY_204_MODE | JSON_OR_EMPTY_204_V2_MODE)
}

fn validate_profile_with_headers(profile: &Map<String, Value>, error: bool, safe_headers: &[&str]) -> Result<u64, String> {
    let allowed: &[&str] = if error {
        &[
            "mode",
            "bodyFormat",
            "maxBodyBytes",
            "contentTypes",
            "allowedHeaders",
            "onInvalid",
        ]
    } else {
        &[
            "mode",
            "bodyFormat",
            "maxBodyBytes",
            "contentTypes",
            "allowedHeaders",
            "error",
        ]
    };
    if profile.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("bufferedPassthrough profile contains an unsupported field".to_string());
    }
    if !profile.get("mode").and_then(Value::as_str).is_some_and(supported_mode)
        || profile.get("bodyFormat").and_then(Value::as_str) != Some("json")
        || profile.get("contentTypes") != Some(&json!(["application/json"]))
    {
        return Err(
            "bufferedPassthrough requires bodyFormat json and exactly application/json".to_string(),
        );
    }
    let maximum = if error {
        MAX_ERROR_BYTES
    } else {
        MAX_BUFFERED_RESPONSE_BODY_BYTES
    };
    let limit = profile
        .get("maxBodyBytes")
        .and_then(Value::as_u64)
        .filter(|limit| (1..=maximum).contains(limit))
        .ok_or_else(|| {
            format!("bufferedPassthrough maxBodyBytes must be between 1 and {maximum}")
        })?;
    if safe_headers == SAFE_RESPONSE_HEADERS {
        validate_response_header_allowlist(profile, "bufferedPassthrough")?;
    }
    // The shared validator also accepts mixed-case names for old profiles.
    // The additive profile is deliberately canonical, matching its schema/compiler.
    if profile
        .get("allowedHeaders")
        .and_then(Value::as_array)
        .is_none_or(|headers| {
            headers.len() > safe_headers.len()
                || headers.iter().any(|header| {
                    header
                        .as_str()
                        .is_none_or(|name| !safe_headers.contains(&name))
                })
        })
    {
        return Err(
            "bufferedPassthrough allowedHeaders must be canonical safe response headers"
                .to_string(),
        );
    }
    if error && profile.get("onInvalid").and_then(Value::as_str) != Some("block") {
        return Err("bufferedPassthrough invalid error responses must block".to_string());
    }
    Ok(limit)
}

pub(crate) fn validate_contract(
    adapter_type: &str,
    response: &Map<String, Value>,
) -> Result<(), String> {
    validate_contract_with_headers(adapter_type, response, &SAFE_RESPONSE_HEADERS)
}

/// The extra names are reachable only through the entire closed GitHub profile.
/// An ordinary V2 response with the same allowedHeaders is still refused.
pub(crate) fn validate_github_contract(config: &Value, constraints: &[Value]) -> Result<(), String> {
    crate::github_issues::validate_config(config, constraints)?;
    validate_contract_with_headers("generic.rest", config["response"].as_object().ok_or("GitHub response missing")?,
        crate::github_issues::RESPONSE_HEADERS)
}

fn validate_contract_with_headers(adapter_type: &str, response: &Map<String, Value>, safe_headers: &[&str]) -> Result<(), String> {
    if adapter_type != "generic.rest" {
        return Err("bufferedPassthrough is only supported by generic.rest".to_string());
    }
    validate_profile_with_headers(response, false, safe_headers)?;
    let error = response
        .get("error")
        .and_then(Value::as_object)
        .ok_or("bufferedPassthrough requires an explicit bufferedPassthrough error profile")?;
    validate_profile_with_headers(error, true, safe_headers)?;
    if response.get("mode") != error.get("mode") {
        return Err("whole JSON success and error profiles must use the same mode".into());
    }
    Ok(())
}

/// Check both halves before any adapter/profile-specific early return. A new
/// envelope cannot silently broaden an older profile, including projected modes.
pub(crate) fn validate_envelope_pairing(
    adapter_type: &str,
    mode: Option<&str>,
    constraints: &[Value],
) -> Result<(), String> {
    if adapter_type == crate::npm_publish::ADAPTER {
        return crate::npm_publish::validate_envelope(mode, constraints);
    }
    if mode == Some(crate::npm_publish::MODE) {
        return Err("npmPublishJsonV1 requires its explicit npm publish adapter".into());
    }
    if adapter_type == crate::npm_metadata::ADAPTER {
        return crate::npm_metadata::validate_envelope(mode, constraints);
    }
    if mode == Some(crate::npm_metadata::MODE) {
        return Err("npmMetadataJsonV1 requires its explicit npm metadata adapter".into());
    }
    if adapter_type == crate::gmail_read::ADAPTER {
        return crate::gmail_read::validate_envelope(mode, constraints);
    }
    if mode == Some(crate::gmail_read::MODE) {
        return Err("gmailReadJsonV1 requires its explicit Gmail read adapter".into());
    }
    if constraints.iter().any(|constraint| constraint.get("unlistedHeaderPolicy").is_some()
        && constraint.get("type").and_then(Value::as_str) != Some("responseEnvelope"))
    {
        return Err("unlistedHeaderPolicy is only valid on an explicit V2 response envelope".into());
    }
    let envelopes = constraints.iter().filter(|constraint|
        constraint.get("type").and_then(Value::as_str) == Some("responseEnvelope")).collect::<Vec<_>>();
    let v2 = mode == Some(JSON_OR_EMPTY_204_V2_MODE);
    if envelopes.iter().any(|envelope| envelope.get("unlistedHeaderPolicy").is_some()) && !v2 {
        return Err("unlistedHeaderPolicy requires its explicit generic.rest V2 response profile".into());
    }
    if !mode.is_some_and(json_or_empty_204_mode) {
        if envelopes.iter().any(|envelope|
            envelope.get("bodyPresence").and_then(Value::as_str) == Some(JSON_OR_EMPTY_204_PRESENCE))
        {
            return Err("jsonOrEmpty204V1 requires its explicit generic.rest response profile".into());
        }
        return Ok(());
    }
    if adapter_type != "generic.rest" || envelopes.is_empty() || envelopes.iter().any(|envelope|
        envelope.get("phase").and_then(Value::as_str) != Some("response")
            || envelope.get("bodyPresence").and_then(Value::as_str) != Some(JSON_OR_EMPTY_204_PRESENCE)
            || (v2 && envelope.get("unlistedHeaderPolicy").and_then(Value::as_str) != Some(crate::response_metadata::POLICY))
            || envelope.get("contentTypes") != Some(&json!(["application/json"]))
            || !envelope.get("statusCodes").and_then(Value::as_array).is_some_and(|statuses| {
                let mut seen = std::collections::HashSet::new();
                (1..=16).contains(&statuses.len())
                    && statuses.iter().any(|status| status.as_u64() == Some(204))
                    && statuses.iter().all(|status| status.as_u64().is_some_and(|status|
                        seen.insert(status)
                            && ((200..=299).contains(&status) && status != 205 || (400..=599).contains(&status))))
            })
    ) {
        return Err("bufferedJsonOrEmpty204V1 requires exact JSON-or-empty-204 response envelopes".into());
    }
    Ok(())
}

/// Both success and error selections must be admitted by EVERY envelope, even
/// when their operation scopes differ. V1 and all older contracts are unchanged.
pub(crate) fn validate_v2_header_selection(response: &Value, constraints: &[Value]) -> Result<(), String> {
    if response.get("mode").and_then(Value::as_str) != Some(JSON_OR_EMPTY_204_V2_MODE) { return Ok(()); }
    let selected = [Some(response), response.get("error")].into_iter().flatten()
        .flat_map(|profile| profile.get("allowedHeaders").and_then(Value::as_array).into_iter().flatten())
        .filter_map(Value::as_str).collect::<std::collections::HashSet<_>>();
    for envelope in constraints.iter().filter(|constraint|
        constraint.get("type").and_then(Value::as_str) == Some("responseEnvelope"))
    {
        crate::validate_response_envelope_constraint("V2", "V2", envelope.as_object()
            .ok_or("V2 response envelope must be an object")?)?;
        let names = envelope.get("allowedResponseHeaderNames").and_then(Value::as_array)
            .ok_or("V2 response envelope header names missing")?;
        if names.iter().any(|name| name.as_str().is_none_or(|name|
            name.len() > 128 || crate::response_metadata::forbidden_listed_name(name)))
            || selected.iter().any(|name| !names.iter().any(|value| value.as_str() == Some(*name)))
        {
            return Err("V2 selected response headers must be admitted by every envelope".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_mode_constraints(mode: &str, constraints: &[Value]) -> Result<(), String> {
    validate_constraints(constraints)?;
    validate_envelope_pairing("generic.rest", Some(mode), constraints)
}

/// Reqwest may not expose bytes after a 204 as response-body bytes. Reject every
/// visible illegal framing declaration; the caller must additionally disable
/// upstream connection reuse for this profile. This is not raw-wire capture.
pub(crate) fn validate_empty_204_headers(headers: &HeaderMap) -> Result<(), Value> {
    if ["content-length", "transfer-encoding", "trailer"].iter().any(|name| headers.contains_key(*name)) {
        return Err(json!({"error":"response_empty_204_framing_forbidden"}));
    }
    let mut types = headers.get_all("content-type").iter();
    if let Some(value) = types.next() {
        if types.next().is_some() || value.to_str().ok().and_then(normalized_media_type).as_deref() != Some("application/json") {
            return Err(json!({"error":"response_json_content_type_mismatch"}));
        }
    }
    Ok(())
}

/// Only the additive, already-validated 204 release calls this serializer. Old
/// response modes keep their serializer and no content header is invented here.
pub(crate) fn serialize_empty_204(content_type: Option<&str>, headers: &SensitiveReleasedHeaders) -> SensitiveResponseBytes {
    let mut output = SensitiveResponseBytes::with_capacity(512);
    output.extend_from_slice(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n");
    if let Some(value) = content_type {
        output.extend_from_slice(b"Content-Type: "); output.extend_from_slice(value.as_bytes()); output.extend_from_slice(b"\r\n");
    }
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes()); output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes()); output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n"); output
}

pub(crate) fn validate_constraints(constraints: &[Value]) -> Result<(), String> {
    if constraints.iter().any(|constraint| {
        matches!(
            constraint.get("type").and_then(Value::as_str),
            Some("slidingWindowLimit" | "weightedBudget" | "traversalBudget" | "responseBinding")
        )
    }) {
        return Err(
            "bufferedPassthrough does not support durable or responseBinding constraints"
                .to_string(),
        );
    }
    Ok(())
}

struct InspectionBuffer {
    bytes: SensitiveResponseBytes,
    limit: usize,
    exceeded: bool,
}

impl Write for InspectionBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("response inspection body limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Inspect parsed JSON but return the original owner without rewriting its bytes.
/// Numeric/escape spelling and whitespace remain exact; the inspection serialization
/// is bounded independently and never emitted. All retained owners zeroize on drop.
pub(crate) fn inspect_body(
    adapter_type: &str,
    config: &Value,
    status: StatusCode,
    content_type: Option<&str>,
    body: SensitiveResponseBytes,
    secret_guard: &ResponseSecretGuard,
) -> Result<SensitiveResponseBytes, Value> {
    inspect_body_with_headers(adapter_type, config, status, content_type, body, secret_guard, &SAFE_RESPONSE_HEADERS)
}

pub(crate) fn inspect_github_body(route: &crate::Route, config: &Value, status: StatusCode,
    content_type: Option<&str>, body: SensitiveResponseBytes, secret_guard: &ResponseSecretGuard,
) -> Result<SensitiveResponseBytes, Value> {
    crate::github_issues::validate_route(route)
        .map_err(|_| json!({"error":"response_buffered_passthrough_profile_invalid"}))?;
    if content_type.is_some_and(|value| !crate::github_issues::is_json_content_type(value)) {
        return Err(json!({"error":"response_json_content_type_mismatch"}));
    }
    let expected = if status.is_client_error() || status.is_server_error() {
        &route.adapter_config["response"]["error"]
    } else { &route.adapter_config["response"] };
    if config != expected { return Err(json!({"error":"response_buffered_passthrough_profile_invalid"})); }
    inspect_body_with_headers("generic.rest", config, status, content_type, body, secret_guard,
        crate::github_issues::RESPONSE_HEADERS)
}

fn inspect_body_with_headers(adapter_type: &str, config: &Value, status: StatusCode, content_type: Option<&str>,
    body: SensitiveResponseBytes, secret_guard: &ResponseSecretGuard, safe_headers: &[&str],
) -> Result<SensitiveResponseBytes, Value> {
    let error = status.is_client_error() || status.is_server_error();
    if adapter_type != "generic.rest" || !(status.is_success() || error) {
        return Err(json!({"error":"response_buffered_passthrough_profile_invalid"}));
    }
    let limit = config
        .as_object()
        .and_then(|profile| validate_profile_with_headers(profile, error, safe_headers).ok())
        .ok_or_else(|| json!({"error":"response_buffered_passthrough_profile_invalid"}))?;
    if config.get("mode").and_then(Value::as_str).is_some_and(json_or_empty_204_mode) {
        if status == StatusCode::RESET_CONTENT {
            return Err(json!({"error":"response_status_invalid"}));
        }
        if status == StatusCode::NO_CONTENT {
            if !body.is_empty() { return Err(json!({"error":"response_empty_204_body_forbidden"})); }
            if let Some(value) = content_type {
                if normalized_media_type(value).as_deref() != Some("application/json") {
                    return Err(json!({"error":"response_json_content_type_mismatch"}));
                }
                if secret_guard.detects(value.as_bytes()) { return Err(json!({"error":"response_credential_reflection"})); }
            }
            return Ok(body);
        }
    }
    if content_type.and_then(normalized_media_type).as_deref() != Some("application/json") {
        return Err(json!({"error":"response_json_content_type_mismatch"}));
    }
    inspect_json_bytes(adapter_type, body, limit, secret_guard,
        config.get("mode").and_then(Value::as_str).is_some_and(json_or_empty_204_mode))
        .map(|(body, _inspection)| body)
}

/// Shared inspection primitive, not adapter admission. Callers independently
/// admit their exact profile/status/media contract before reaching this point.
pub(crate) fn inspect_json_bytes(
    adapter_type: &str,
    body: SensitiveResponseBytes,
    limit: u64,
    secret_guard: &ResponseSecretGuard,
    check_depth: bool,
) -> Result<(SensitiveResponseBytes, crate::SensitiveJsonValue), Value> {
    if body.len() as u64 > limit {
        return Err(json!({"error":"response_body_too_large","maxBodyBytes":limit}));
    }
    if secret_guard.detects(&body) {
        return Err(json!({"error":"response_credential_reflection"}));
    }
    if check_depth {
        crate::buffered_request::validate_container_depth(&body)
            .map_err(|()| json!({"error":"response_invalid_json","adapter":adapter_type}))?;
    }
    let value = sensitive_json_value_from_slice(&body)
        .map_err(|_| json!({"error":"response_invalid_json","adapter":adapter_type}))?;
    let mut inspection = InspectionBuffer {
        bytes: SensitiveResponseBytes::with_capacity(body.len()),
        limit: limit as usize,
        exceeded: false,
    };
    if serde_json::to_writer(&mut inspection, &*value).is_err() {
        return Err(if inspection.exceeded {
            json!({"error":"response_inspection_body_too_large","maxBodyBytes":limit})
        } else {
            json!({"error":"response_serialization_failed","adapter":adapter_type})
        });
    }
    if secret_guard.detects(&inspection.bytes) {
        return Err(json!({"error":"response_credential_reflection"}));
    }
    Ok((body, value))
}

#[cfg(test)]
#[path = "buffered_response_tests.rs"]
mod tests;
