//! Additive bounded JSON inspection without rewriting the authorized wire bytes.
use crate::{generic_operation_sources, sensitive_json_value_from_slice, validate_buffered_body_binding, MAX_BUFFERED_REQUEST_BODY_BYTES};
use reqwest::blocking::Request;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub(crate) const MODE: &str = "bufferedJsonPassthroughV1";
pub(crate) const MAX_JSON_CONTAINER_DEPTH: usize = 127;

fn bounded_string_list(value: Option<&Value>, max_items: usize, max_characters: usize) -> bool {
    value.and_then(Value::as_array).is_some_and(|values| {
        let mut seen = HashSet::new();
        values.len() <= max_items && values.iter().all(|value| value.as_str().is_some_and(|text|
            (1..=max_characters).contains(&text.chars().count()) && seen.insert(text)))
    })
}

pub(crate) fn validate_contract(request: &Map<String, Value>, constraints: &[Value]) -> Result<(), String> {
    if request.get("bodyMode").and_then(Value::as_str) != Some(MODE) {
        return Ok(());
    }
    const REQUIRED: &[&str] = &["allowedQueryKeys", "allowedHeaders", "allowedMediaTypes", "bodyMode", "maxBodyBytes", "operation", "valueRules"];
    if REQUIRED.iter().any(|key| !request.contains_key(*key))
        || request.keys().any(|key| !REQUIRED.contains(&key.as_str())
            && !matches!(key.as_str(), "discardHeaders" | "requiredHeaders")
            && !(key == "queryMode" && request.get(key).and_then(Value::as_str) == Some(crate::github_issues::MODE)))
    {
        return Err("bufferedJsonPassthroughV1 requires its closed request profile".into());
    }
    if request.get("allowedMediaTypes") != Some(&json!(["application/json"]))
        || request.get("maxBodyBytes").and_then(Value::as_u64)
            .is_none_or(|limit| !(1..=MAX_BUFFERED_REQUEST_BODY_BYTES).contains(&limit))
    {
        return Err("bufferedJsonPassthroughV1 requires exact JSON media and a bounded positive body limit".into());
    }
    if !bounded_string_list(request.get("allowedQueryKeys"), 64, 256)
        || !bounded_string_list(request.get("allowedHeaders"), 64, 128)
        || request.contains_key("discardHeaders") && !bounded_string_list(request.get("discardHeaders"), 16, 128)
        || request.get("requiredHeaders").is_some_and(|value| value.as_object().is_none_or(|headers| headers.len() > 16))
    {
        return Err("bufferedJsonPassthroughV1 requires bounded typed header and query lists".into());
    }
    let operation = request.get("operation").and_then(Value::as_object)
        .ok_or("bufferedJsonPassthroughV1 requires a typed operation")?;
    if operation.get("name").and_then(Value::as_str).is_none_or(|name| !(1..=128).contains(&name.chars().count()))
        || operation.keys().any(|key| !matches!(key.as_str(), "name" | "pathParams" | "bodySha256Field"))
    {
        return Err("bufferedJsonPassthroughV1 requires a named operation without body-field captures".into());
    }
    // Reuse the existing source validator for field syntax, list bounds,
    // reserved names and path/body-digest capture collisions.
    generic_operation_sources(operation, MODE)?;
    let rules = request.get("valueRules").and_then(Value::as_array)
        .filter(|rules| rules.len() <= 16)
        .ok_or("bufferedJsonPassthroughV1 requires a bounded valueRules array")?;
    let invalid_rule = |rule: &Value| !rule.is_object()
        || matches!(rule.get("source").and_then(Value::as_str), Some("jsonBody" | "formBody"));
    // Full source membership and predicate semantics remain in the existing
    // route-aware request-value validator, including these inline rules.
    if rules.iter().any(invalid_rule)
        || constraints.iter().any(|constraint| {
            !constraint.is_object()
                || matches!(constraint.get("type").and_then(Value::as_str), Some("jsonBody" | "formBody"))
                || constraint.get("type").and_then(Value::as_str) == Some("requestValue")
                    && constraint.get("rules").and_then(Value::as_array).is_none_or(|rules|
                        rules.iter().any(invalid_rule))
        })
    {
        return Err("bufferedJsonPassthroughV1 forbids body projection, streaming limits and JSON/form captures".into());
    }
    Ok(())
}

/// Count raw containers without treating quoted or escaped brackets as nesting.
/// JSON syntax remains the strict parser's responsibility. Shared only by the
/// additive whole-JSON modes; this does not change legacy parser limits.
pub(crate) fn validate_container_depth(bytes: &[u8]) -> Result<(), ()> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped { escaped = false; }
            else if *byte == b'\\' { escaped = true; }
            else if *byte == b'"' { in_string = false; }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_JSON_CONTAINER_DEPTH {
                        return Err(());
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

/// The parser is strict (including duplicate keys and trailing JSON data). The
/// parsed value is only inspected and zeroized; the caller retains its raw bytes.
pub(crate) fn inspect_body(bytes: &[u8], utf8_valid: Option<bool>) -> Result<(), Value> {
    validate_container_depth(bytes)
        .map_err(|()| json!({"error":"request_json_nesting_limit","status_code":400}))?;
    if utf8_valid == Some(false) || (!bytes.is_empty() && sensitive_json_value_from_slice(bytes).is_err()) {
        return Err(json!({"error":"request_json_invalid","status_code":400}));
    }
    Ok(())
}

/// Runs on the actual built request immediately before the unchanged dispatch
/// barrier. Streaming/unknown bodies cannot substitute for the authorized bytes.
pub(crate) fn validate_built_body(decision: &Value, request: &Request) -> Result<(), &'static str> {
    let bytes = match request.body() {
        Some(body) => body.as_bytes().ok_or("provider_request_body_not_buffered")?,
        None => &[],
    };
    validate_buffered_body_binding(decision, bytes)
        .map_err(|_| "provider_request_body_binding_mismatch")?;
    if request.headers().contains_key("transfer-encoding") {
        return Err("provider_request_body_framing_mismatch");
    }
    let mut lengths = request.headers().get_all("content-length").iter();
    if let Some(length) = lengths.next() {
        if lengths.next().is_some() || length.to_str().ok().and_then(|value| value.parse::<u64>().ok()) != Some(bytes.len() as u64) {
            return Err("provider_request_body_framing_mismatch");
        }
    }
    Ok(())
}
