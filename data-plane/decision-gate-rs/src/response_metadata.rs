//! V2-only bounded parsed metadata inspection. No raw upstream metadata is
//! included in errors, and discarded fields never enter shadow/proof selection.
use crate::{is_http_token_byte, ResponseSecretGuard};
use reqwest::header::HeaderMap;
use serde_json::{json, Value};
use std::collections::HashSet;

pub(crate) const POLICY: &str = "discardUnselectedV1";
pub(crate) fn uses_mode(mode: &str) -> bool {
    matches!(mode, crate::buffered_response::JSON_OR_EMPTY_204_V2_MODE | crate::gmail_read::MODE)
}
const TRANSPORT: &[&str] = &[
    "connection", "content-encoding", "content-length", "content-type", "keep-alive",
    "proxy-authenticate", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
];

fn forbidden(name: &str) -> bool {
    // Classification only. Never rewrite the actual or policy-listed name.
    let classified = name.to_ascii_lowercase().replace('_', "-");
    matches!(classified.as_str(), "authorization" | "proxy-authorization" | "cookie" | "set-cookie")
        || classified.starts_with("x-serverware-")
        || (classified != name && TRANSPORT.contains(&classified.as_str()))
}

pub(crate) fn forbidden_listed_name(name: &str) -> bool {
    forbidden(name) || TRANSPORT.contains(&name)
}

fn listed(constraint: &Value) -> impl Iterator<Item = &str> {
    constraint.get("allowedResponseHeaderNames").and_then(Value::as_array)
        .into_iter().flatten().filter_map(Value::as_str)
}

fn inspect_and_select(
    headers: &HeaderMap,
    selected: &HashSet<&str>,
    secret_guard: Option<&ResponseSecretGuard>,
) -> Result<HeaderMap, Value> {
    let mut fields = 0usize;
    let mut bytes = 0usize;
    // Bounds and grammar apply to every physical value, including discarded
    // duplicates. HeaderMap preserves values, but is not raw-wire evidence.
    for (name, value) in headers.iter() {
        fields += 1;
        bytes = bytes.saturating_add(name.as_str().len()).saturating_add(value.as_bytes().len());
        if fields > 128 || bytes > 65_536 || name.as_str().len() > 128 || value.as_bytes().len() > 8192 {
            return Err(json!({"error":"response_metadata_limit_exceeded"}));
        }
        if name.as_str().is_empty() || !name.as_str().bytes().all(is_http_token_byte)
            || !value.as_bytes().iter().all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
        {
            return Err(json!({"error":"response_metadata_invalid"}));
        }
    }
    // Scan the entire bounded set BEFORE selecting or copying any metadata.
    if secret_guard.is_some_and(|guard| headers.iter().any(|(name, value)|
        guard.detects(name.as_str().as_bytes()) || guard.detects(value.as_bytes())))
    {
        return Err(json!({"error":"response_credential_reflection"}));
    }
    for name in headers.keys() {
        if forbidden(name.as_str()) {
            return Err(json!({"error":"response_metadata_reserved_header"}));
        }
        if (TRANSPORT.contains(&name.as_str()) || selected.contains(name.as_str()))
            && headers.get_all(name).iter().count() != 1
        {
            return Err(json!({"error":"response_metadata_duplicate"}));
        }
    }
    let mut retained = HeaderMap::new();
    for (name, value) in headers.iter() {
        if TRANSPORT.contains(&name.as_str()) || selected.contains(name.as_str()) {
            retained.append(name.clone(), value.clone());
        }
    }
    Ok(retained)
}

/// The actual finalizer calls this before shadow observation and every early
/// 204 path. The union keeps all policy predicates available, never unlisted data.
pub(crate) fn prepare(
    headers: &HeaderMap,
    constraints: &[Value],
    secret_guard: &ResponseSecretGuard,
) -> Result<HeaderMap, Value> {
    let selected = constraints.iter()
        .filter(|constraint| constraint.get("type").and_then(Value::as_str) == Some("responseEnvelope"))
        .flat_map(listed).collect();
    inspect_and_select(headers, &selected, Some(secret_guard))
}

/// Reuse the original strict envelope/predicate evaluator with only this
/// envelope's semantic fields. Its transport and framing checks remain intact.
pub(crate) fn for_envelope(headers: &HeaderMap, constraint: &Value) -> Result<HeaderMap, Value> {
    inspect_and_select(headers, &listed(constraint).collect(), None)
}
