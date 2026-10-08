//! Explicit whole-JSON buffering for generic REST; never an opaque or streaming fallback.
use crate::{
    normalized_media_type, sensitive_json_value_from_slice, validate_response_header_allowlist,
    ResponseSecretGuard, SensitiveResponseBytes, MAX_BUFFERED_RESPONSE_BODY_BYTES,
    SAFE_RESPONSE_HEADERS,
};
use reqwest::StatusCode;
use serde_json::{json, Map, Value};
use std::io::{self, Write};

pub(crate) const MODE: &str = "bufferedPassthrough";
const MAX_ERROR_BYTES: u64 = 65_536;

fn validate_profile(profile: &Map<String, Value>, error: bool) -> Result<u64, String> {
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
    if profile.get("mode").and_then(Value::as_str) != Some(MODE)
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
    validate_response_header_allowlist(profile, "bufferedPassthrough")?;
    // The shared validator also accepts mixed-case names for old profiles.
    // The additive profile is deliberately canonical, matching its schema/compiler.
    if profile
        .get("allowedHeaders")
        .and_then(Value::as_array)
        .is_none_or(|headers| {
            headers.len() > SAFE_RESPONSE_HEADERS.len()
                || headers.iter().any(|header| {
                    header
                        .as_str()
                        .is_none_or(|name| !SAFE_RESPONSE_HEADERS.contains(&name))
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
    if adapter_type != "generic.rest" {
        return Err("bufferedPassthrough is only supported by generic.rest".to_string());
    }
    validate_profile(response, false)?;
    let error = response
        .get("error")
        .and_then(Value::as_object)
        .ok_or("bufferedPassthrough requires an explicit bufferedPassthrough error profile")?;
    validate_profile(error, true)?;
    Ok(())
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
    let error = status.is_client_error() || status.is_server_error();
    if adapter_type != "generic.rest" || !(status.is_success() || error) {
        return Err(json!({"error":"response_buffered_passthrough_profile_invalid"}));
    }
    let limit = config
        .as_object()
        .and_then(|profile| validate_profile(profile, error).ok())
        .ok_or_else(|| json!({"error":"response_buffered_passthrough_profile_invalid"}))?;
    if content_type.and_then(normalized_media_type).as_deref() != Some("application/json") {
        return Err(json!({"error":"response_json_content_type_mismatch"}));
    }
    if body.len() as u64 > limit {
        return Err(json!({"error":"response_body_too_large","maxBodyBytes":limit}));
    }
    if secret_guard.detects(&body) {
        return Err(json!({"error":"response_credential_reflection"}));
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
    Ok(body)
}

#[cfg(test)]
#[path = "buffered_response_tests.rs"]
mod tests;
