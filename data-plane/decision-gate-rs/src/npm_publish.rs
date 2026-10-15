//! Closed stock npm publish envelope. Tarball bytes are hashed, never extracted;
//! manifest URLs are inert metadata, never an authority to fetch another target.
use crate::{DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route,
    RouteMatch, SensitiveResponseBytes};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use zeroize::Zeroizing;

pub(crate) const ADAPTER: &str = "npm.publish.v1";
pub(crate) const MODE: &str = "npmPublishJsonV1";
pub(crate) const HOST: &str = crate::npm_metadata::HOST;
pub(crate) const PATH: &str = crate::npm_metadata::PATH;
pub(crate) const PLACEHOLDER: &str = crate::npm_metadata::PLACEHOLDER;
pub(crate) const CONTENT_TYPE_POLICY: &str = crate::npm_metadata::CONTENT_TYPE_POLICY;
pub(crate) const HEADERS: &[&str] = &["accept", "content-type", "npm-auth-type", "npm-command",
    "npm-in-ci", "npm-scope", "user-agent"];
pub(crate) const DISCARD: &[&str] = crate::npm_metadata::DISCARD;
pub(crate) const STATUSES: &[u16] = &[200, 201, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504];
pub(crate) const CONTENT_TYPES: &[&str] = &["application/json"];
pub(crate) const REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const TARBALL_BYTES: usize = 8 * 1024 * 1024;
const MANIFEST_BYTES: usize = 65_536;
const RESPONSE_BYTES: u64 = 65_536;

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(crate) fn tag(value: &str) -> bool {
    (1..=64).contains(&value.len()) && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

pub(crate) fn version(value: &str) -> bool {
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'));
    let identifiers = |value: &str, prerelease: bool| value.split('.').all(|part| {
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (!prerelease || !part.bytes().all(|b| b.is_ascii_digit()) || numeric(part))
    });
    if value.is_empty() || value.len() > 128 || !value.is_ascii() { return false; }
    let core = match value.split_once('+') {
        Some((core, build)) if identifiers(build, false) => core,
        Some(_) => return false,
        None => value,
    };
    let core = match core.split_once('-') {
        Some((core, pre)) if identifiers(pre, true) => core,
        Some(_) => return false,
        None => core,
    };
    core.split('.').count() == 3 && core.split('.').all(numeric)
}

pub(crate) fn request_profile() -> ProviderRequestProfile {
    ProviderRequestProfile { allowed_headers: HEADERS, allowed_query_keys: &[],
        allowed_media_types: CONTENT_TYPES, required_discard_headers: DISCARD,
        max_body_bytes: REQUEST_BYTES }
}

pub(crate) fn request_config() -> Value {
    json!({"allowedHeaders":HEADERS,"discardHeaders":DISCARD,"allowedQueryKeys":[],
        "allowedMediaTypes":CONTENT_TYPES,"maxBodyBytes":REQUEST_BYTES,"valueRules":[]})
}

pub(crate) fn response_profile(error: bool) -> Value {
    let mut value = json!({"mode":MODE,"maxBodyBytes":RESPONSE_BYTES,
        "contentTypes":CONTENT_TYPES,"allowedHeaders":[]});
    if error { value["onInvalid"] = json!("block"); }
    else { value["error"] = response_profile(true); }
    value
}

pub(crate) fn envelope(id: &str) -> Value {
    json!({"id":id,"type":"responseEnvelope","phase":"response","statusCodes":STATUSES,
        "contentTypePolicy":CONTENT_TYPE_POLICY,"bodyPresence":"required","contentTypes":CONTENT_TYPES,
        "allowedResponseHeaderNames":[],"responseHeaderRules":[],
        "unlistedHeaderPolicy":crate::response_metadata::POLICY})
}

fn validate_window(value: &Value) -> Result<(), String> {
    let bad = || "npm publish requires one increasing UTC daily window".to_string();
    let object = value.as_object().ok_or_else(bad)?;
    if !exact(object, &["id", "type", "phase", "timezone", "dailyWindows"])
        || value["id"].as_str().is_none_or(str::is_empty)
        || value["type"] != "requestTimeWindow" || value["phase"] != "request"
        || value["timezone"] != "UTC" { return Err(bad()); }
    let windows = value["dailyWindows"].as_array().ok_or_else(bad)?;
    if windows.len() != 1 { return Err(bad()); }
    let window = windows[0].as_object().ok_or_else(bad)?;
    if !exact(window, &["start", "end"]) { return Err(bad()); }
    let clock = |value: &Value| value.as_str().filter(|v| v.bytes().enumerate()
        .all(|(i, b)| if i == 2 { b == b':' } else { b.is_ascii_digit() }))
        .and_then(crate::parse_clock_minutes);
    let start = clock(&window["start"]).ok_or_else(bad)?;
    let end = clock(&window["end"]).ok_or_else(bad)?;
    if start >= end { return Err(bad()); }
    Ok(())
}

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    let ordinary = crate::operator_host_approvals::provider_constraints(constraints)?;
    let constraints = ordinary.as_ref();
    if mode != Some(MODE) || !(1..=2).contains(&constraints.len()) {
        return Err("npm publish requires its response envelope and optional daily window".into());
    }
    let mut response_id = None;
    let mut window_id = None;
    for constraint in constraints {
        let id = constraint["id"].as_str().filter(|id| !id.is_empty())
            .ok_or("npm publish constraint ID missing")?;
        match constraint["type"].as_str() {
            Some("responseEnvelope") if response_id.is_none() && constraint == &envelope(id) => {
                crate::validate_response_envelope_constraint(ADAPTER, id,
                    constraint.as_object().ok_or("npm publish envelope missing")?)?;
                response_id = Some(id);
            }
            Some("requestTimeWindow") if window_id.is_none() => {
                validate_window(constraint)?;
                window_id = Some(id);
            }
            _ => return Err("npm publish constraint differs from its closed contract".into()),
        }
    }
    if response_id.is_none() || response_id == window_id {
        return Err("npm publish response envelope or unique ID missing".into());
    }
    Ok(())
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("npm publish config must be an object")?;
    if !exact(object, &["credentialBinding", "package", "tag", "request", "response"])
        || config["request"] != request_config() || config["response"] != response_profile(false)
        || config["package"].as_str().is_none_or(|v| !crate::npm_metadata::package_name(v))
        || config["tag"].as_str().is_none_or(|v| !tag(v)) {
        return Err("npm publish config differs from its closed contract".into());
    }
    // Reuse the identical static bearer binding validator, without changing the
    // metadata adapter or admitting its GET operations on this PUT route.
    crate::npm_metadata::validate_config(&json!({"credentialBinding":config["credentialBinding"],
        "packages":[config["package"]],"request":crate::npm_metadata::request_config(),
        "response":crate::npm_metadata::response_profile(false)}),
        &[crate::npm_metadata::envelope("publish-binding-check")])?;
    validate_envelope(Some(MODE), constraints)
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route.get("adapter").and_then(|a| a.get("config"))
        .ok_or("npm publish adapter missing")?;
    validate_config(config, route.get("constraints").and_then(Value::as_array)
        .ok_or("npm publish constraints missing")?)?;
    let matcher = route.get("match").and_then(Value::as_object).ok_or("npm publish match missing")?;
    if matcher.get("scheme") != Some(&json!("https")) || matcher.get("host") != Some(&json!(HOST))
        || matcher.get("port") != Some(&json!(443)) || matcher.get("methods") != Some(&json!(["PUT"]))
        || matcher.get("paths") != Some(&json!([PATH])) || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader") != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER})) {
        return Err("npm publish route requires its exact PUT target and replacement contract".into());
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    if route.adapter_type != ADAPTER || route.scheme != "https" || route.host != HOST || route.port != 443
        || route.methods != HashSet::from(["PUT".to_string()]) || route.paths.len() != 1
        || !matches!(route.paths[0].segments.as_slice(), [PathSegment::Variable(name)] if name == "package")
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != DISCARD.iter().map(|v| v.to_string()).collect::<Vec<_>>()
        || route.jit != json!({}) || route.response_observation.is_some() {
        return Err("npm publish runtime route authority is invalid".into());
    }
    Ok(())
}

fn target_package(url: &Url) -> Result<String, Value> {
    let denied = || json!({"error":"npm_publish_target_denied","status_code":403});
    if url.scheme() != "https" || url.host_str() != Some(HOST) || url.port_or_known_default() != Some(443)
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || url.query().is_some() || crate::validate_canonical_raw_path(url.path()).is_err() {
        return Err(denied());
    }
    let segment = url.path().strip_prefix('/').filter(|v| !v.contains('/'))
        .filter(|v| crate::npm_package_segment(v)).ok_or_else(denied)?;
    let package = crate::decode_npm_scoped_name(segment);
    if !crate::npm_metadata::package_name(&package) { return Err(denied()); }
    Ok(package)
}

fn bounded_document(value: &Value) -> bool {
    let mut pending = vec![(value, 0usize)];
    let mut count = 0usize;
    while let Some((value, depth)) = pending.pop() {
        count += 1;
        if depth > 64 || count > 100_000 { return false; }
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(items) => {
                // Keys count as JSON string nodes at the child's depth too.
                count += items.len();
                if count > 100_000 || (!items.is_empty() && depth == 64) { return false; }
                pending.extend(items.values().map(|item| (item, depth + 1)));
            }
            _ => (),
        }
    }
    true
}

/// Conservative compact-JSON budget, not a serialization or byte rewrite.
/// A fixed numeric charge avoids Python/Rust float exponent spelling drift.
fn manifest_budget(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(_) => 320,
        Value::String(value) => serde_json::to_vec(value).map_or(usize::MAX, |v| v.len()),
        Value::Array(items) => items.iter().fold(2usize + items.len().saturating_sub(1),
            |sum, item| sum.saturating_add(manifest_budget(item))),
        Value::Object(items) => items.iter().fold(
            2usize + items.len().saturating_sub(1) + items.len(), |sum, (key, item)| {
                sum.saturating_add(serde_json::to_vec(key).map_or(usize::MAX, |v| v.len()))
                    .saturating_add(manifest_budget(item))
            }),
    }
}

fn payload_operation(req: &DecisionRequest, package: &str, selected_tag: &str) -> Result<Value, Value> {
    let bad = || json!({"error":"npm_publish_payload_invalid","status_code":403});
    if req.body.is_empty() || req.body.len() as u64 > REQUEST_BYTES { return Err(bad()); }
    let document = crate::strict_json_value_from_str(&req.body).map_err(|_| bad())?;
    if !bounded_document(&document) { return Err(bad()); }
    let object = document.as_object().ok_or_else(bad)?;
    let mut keys = vec!["_id", "name", "dist-tags", "versions", "access", "_attachments"];
    if object.contains_key("description") {
        if !document["description"].is_string() { return Err(bad()); }
        keys.push("description");
    }
    if !exact(object, &keys) || document["_id"] != package || document["name"] != package
        || !(document["access"].is_null() || matches!(document["access"].as_str(), Some("public" | "restricted"))) {
        return Err(bad());
    }
    let versions = document["versions"].as_object().filter(|v| v.len() == 1).ok_or_else(bad)?;
    let (selected_version, manifest) = versions.iter().next().ok_or_else(bad)?;
    if !version(selected_version) || !manifest.is_object() || manifest["name"] != package
        || manifest["version"] != selected_version.as_str()
        || manifest["_id"] != format!("{package}@{selected_version}")
        || manifest_budget(manifest) > MANIFEST_BYTES {
        return Err(bad());
    }
    if document["dist-tags"] != json!({selected_tag:selected_version}) {
        return Err(json!({"error":"npm_publish_tag_denied","status_code":403}));
    }
    let attachment_name = format!("{package}-{selected_version}.tgz");
    let attachments = document["_attachments"].as_object().filter(|v| v.len() == 1).ok_or_else(bad)?;
    let attachment = attachments.get(&attachment_name).and_then(Value::as_object).ok_or_else(bad)?;
    if !exact(attachment, &["content_type", "data", "length"])
        || attachment["content_type"] != "application/octet-stream" { return Err(bad()); }
    let length = attachment["length"].as_u64().filter(|n| (1..=TARBALL_BYTES as u64).contains(n)).ok_or_else(bad)?;
    let encoded = attachment["data"].as_str().ok_or_else(bad)?;
    // Bound decoded bytes from canonical padding BEFORE the decoder allocates.
    if encoded.is_empty() || encoded.len() > TARBALL_BYTES.div_ceil(3) * 4
        || !encoded.is_ascii() || encoded.len() % 4 != 0 { return Err(bad()); }
    let padding = encoded.len() - encoded.trim_end_matches('=').len();
    if padding > 2 { return Err(bad()); }
    let decoded_length = encoded.len() / 4 * 3 - padding;
    if decoded_length == 0 || decoded_length > TARBALL_BYTES || decoded_length as u64 != length {
        return Err(bad());
    }
    let tarball = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| bad())?);
    if tarball.len() != decoded_length || STANDARD.encode(tarball.as_slice()) != encoded { return Err(bad()); }
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(tarball.as_slice())));
    let shasum = hex::encode(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, tarball.as_slice()).as_ref());
    let dist = manifest["dist"].as_object().ok_or_else(bad)?;
    if !exact(dist, &["integrity", "shasum", "tarball"]) || dist["integrity"] != integrity
        || dist["shasum"] != shasum
        || dist["tarball"] != format!("http://{HOST}/{package}/-/{attachment_name}") { return Err(bad()); }
    Ok(json!({"operation":"npm.publish","packageName":package,"packageVersion":selected_version,
        "tag":selected_tag,"tarballIntegrity":integrity,"tarballShasum":shasum,
        "attachmentName":attachment_name,"attachmentBytes":decoded_length.to_string()}))
}

/// This runs before credential preparation, as well as at normalization.
pub(crate) fn validate_request(req: &DecisionRequest, url: &Url, route: &Route) -> Result<Value, Value> {
    validate_route(route).map_err(|_| json!({"error":"npm_publish_profile_invalid","status_code":500}))?;
    if req.method != "PUT" { return Err(json!({"error":"npm_publish_request_denied","status_code":403})); }
    let mut media = req.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    if media.next().is_none_or(|(_, value)| !is_json_content_type(value)) || media.next().is_some() {
        return Err(json!({"error":"npm_publish_content_type_denied","status_code":415}));
    }
    let package = target_package(url)?;
    if route.adapter_config["package"].as_str() != Some(package.as_str()) {
        return Err(json!({"error":"npm_publish_package_denied","status_code":403}));
    }
    payload_operation(req, &package, route.adapter_config["tag"].as_str().unwrap_or_default())
}

pub(crate) fn normalize_request(req: &DecisionRequest, url: &Url, matched: &RouteMatch<'_>) -> Result<(Value, Value), Value> {
    let operation = validate_request(req, url, matched.route)?;
    if matched.params.len() != 1 || matched.params.get("package").map(String::as_str) != url.path().strip_prefix('/')
        || matched.route.paths[0].matches_canonical(url.path()).as_ref() != Some(&matched.params) {
        return Err(json!({"error":"npm_publish_package_capture_denied","status_code":403}));
    }
    Ok((operation, json!({})))
}

pub(crate) fn is_json_content_type(value: &str) -> bool {
    crate::npm_metadata::response_content_type(value) == Some("application/json")
}

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>, config: &Value,
    body: SensitiveResponseBytes, guard: &ResponseSecretGuard) -> Result<SensitiveResponseBytes, Value> {
    target_package(url)?;
    let error = status.is_client_error() || status.is_server_error();
    if !STATUSES.contains(&status.as_u16()) || config != &response_profile(error)
        || content_type.is_none_or(|v| !is_json_content_type(v)) {
        return Err(json!({"error":"npm_publish_response_contract_invalid"}));
    }
    let (body, payload) = crate::buffered_response::inspect_json_bytes(ADAPTER, body, RESPONSE_BYTES, guard, true)?;
    if !payload.is_object() { return Err(json!({"error":"npm_publish_response_shape_invalid"})); }
    Ok(body)
}

#[cfg(test)]
#[path = "npm_publish_tests.rs"]
mod tests;
