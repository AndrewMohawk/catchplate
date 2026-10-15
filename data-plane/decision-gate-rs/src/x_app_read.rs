//! Exact app-only username lookup. No user OAuth, writes, queries or identity claims.
use crate::{DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route,
    RouteMatch, SensitiveResponseBytes};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub(crate) const ADAPTER: &str = "x.app_read.v1";
pub(crate) const MODE: &str = "xAppReadJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "xAppReadJsonUtf8V1";
pub(crate) const HOST: &str = "api.x.com";
pub(crate) const OPERATION: &str = "x.username.read";
pub(crate) const PLACEHOLDER: &str = "Bearer serverware-x-placeholder-v1";
pub(crate) const HEADERS: &[&str] = &["accept", "accept-language", "sec-fetch-mode", "user-agent"];
pub(crate) const DISCARD: &[&str] = &["accept-encoding"];
pub(crate) const STATUSES: &[u16] = &[200, 400, 401, 403, 404, 429, 500, 502, 503, 504];
const CONTENT_TYPES: &[&str] = &["application/json"];
const SUCCESS_BYTES: u64 = 1_048_576;
const ERROR_BYTES: u64 = 65_536;

/// Compiled support only: consumers must independently join current policy and
/// health. This is not a provider, credential or successful lookup observation.
pub(crate) fn gate_capability() -> Value {
    json!({"schema":"serverware.operatorXAppReadGate/v1","adapter":ADAPTER,"operation":OPERATION})
}

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(crate) fn username(value: &str) -> bool {
    (1..=15).contains(&value.len()) && value.bytes().all(|byte|
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) fn path(name: &str) -> String {
    format!("/2/users/by/username/{name}")
}

pub(crate) fn request_profile() -> ProviderRequestProfile {
    ProviderRequestProfile { allowed_headers: HEADERS, allowed_query_keys: &[],
        allowed_media_types: CONTENT_TYPES, required_discard_headers: DISCARD, max_body_bytes: 0 }
}

pub(crate) fn request_config() -> Value {
    json!({"allowedHeaders":HEADERS,"discardHeaders":DISCARD,"allowedQueryKeys":[],
        "allowedMediaTypes":CONTENT_TYPES,"maxBodyBytes":0,"valueRules":[]})
}

pub(crate) fn response_profile(error: bool) -> Value {
    let mut value = json!({"mode":MODE,"maxBodyBytes":if error { ERROR_BYTES } else { SUCCESS_BYTES },
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

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    let ordinary = crate::operator_host_approvals::provider_constraints(constraints)?;
    let constraints = ordinary.as_ref();
    if mode != Some(MODE) || constraints.len() != 1 {
        return Err("X app read requires its one exact response envelope".into());
    }
    let id = constraints[0].get("id").and_then(Value::as_str).filter(|id| !id.is_empty())
        .ok_or("X app read response envelope ID missing")?;
    if constraints[0] != envelope(id) {
        return Err("X app read response envelope differs from its closed contract".into());
    }
    crate::validate_response_envelope_constraint(ADAPTER, id,
        constraints[0].as_object().ok_or("X app read envelope must be an object")?)
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("X app read config must be an object")?;
    if !exact(object, &["credentialBinding", "username", "request", "response"])
        || config["request"] != request_config() || config["response"] != response_profile(false)
        || config["username"].as_str().is_none_or(|name| !username(name)) {
        return Err("X app read config differs from its closed contract".into());
    }
    let binding = config["credentialBinding"].as_object().ok_or("X app read binding missing")?;
    if !exact(binding, &["credentialType", "provider", "subjects", "secretClass"])
        || binding.get("credentialType") != Some(&json!("static"))
        || binding.get("provider") != Some(&json!("operator-demo"))
        || binding.get("secretClass") != Some(&json!("bearerToken"))
        || binding.get("subjects").and_then(Value::as_array).is_none_or(|subjects|
            subjects.len() != 1 || subjects[0].as_str().is_none_or(|subject|
                subject.is_empty() || subject.len() > 512 || subject.trim() != subject
                    || subject.chars().any(char::is_control))) {
        return Err("X app read requires one exact static operator bearer binding".into());
    }
    validate_envelope(Some(MODE), constraints)
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route.get("adapter").and_then(|value| value.get("config"))
        .ok_or("X app read adapter missing")?;
    validate_config(config, route.get("constraints").and_then(Value::as_array)
        .ok_or("X app read constraints missing")?)?;
    let matcher = route.get("match").and_then(Value::as_object).ok_or("X app read match missing")?;
    if matcher.get("scheme") != Some(&json!("https")) || matcher.get("host") != Some(&json!(HOST))
        || matcher.get("port") != Some(&json!(443)) || matcher.get("methods") != Some(&json!(["GET"]))
        || matcher.get("paths") != Some(&json!([path(config["username"].as_str().unwrap())]))
        || route.contains_key("jit") || route.contains_key("responseObservation")
        || route.get("credentialHeader") != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER})) {
        return Err("X app read requires its exact GET target and replacement contract".into());
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    let name = route.adapter_config["username"].as_str().unwrap();
    let exact_path = route.paths.len() == 1 && matches!(route.paths[0].segments.as_slice(),
        [PathSegment::Literal(a), PathSegment::Literal(b), PathSegment::Literal(c),
         PathSegment::Literal(d), PathSegment::Literal(e)]
        if a == "2" && b == "users" && c == "by" && d == "username" && e == name);
    if route.adapter_type != ADAPTER || route.scheme != "https" || route.host != HOST || route.port != 443
        || route.methods != HashSet::from(["GET".to_string()]) || !exact_path
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != DISCARD.iter().map(|name| name.to_string()).collect::<Vec<_>>()
        || route.jit != json!({}) || route.response_observation.is_some() {
        return Err("X app read runtime route authority is invalid".into());
    }
    Ok(())
}

fn target_username(url: &Url) -> Result<&str, Value> {
    let denied = || json!({"error":"x_app_read_target_denied","status_code":403});
    if url.scheme() != "https" || url.host_str() != Some(HOST) || url.port_or_known_default() != Some(443)
        || !url.username().is_empty() || url.password().is_some() || url.query().is_some()
        || url.fragment().is_some() || crate::validate_canonical_raw_path(url.path()).is_err() {
        return Err(denied());
    }
    url.path().strip_prefix("/2/users/by/username/").filter(|name| username(name)).ok_or_else(denied)
}

pub(crate) fn is_json_content_type(value: &str) -> bool {
    if !value.is_ascii() || value.len() > 8192 { return false; }
    match value.split_once(';') {
        None => value.eq_ignore_ascii_case("application/json"),
        Some((media, parameter)) => media.eq_ignore_ascii_case("application/json")
            && parameter.trim_start_matches([' ', '\t']).eq_ignore_ascii_case("charset=utf-8"),
    }
}

/// Runs before credential preparation, including the actual head/full-body
/// preparation paths. Shared admission owns framing and standard header guards.
pub(crate) fn validate_request(req: &DecisionRequest, url: &Url, route: &Route) -> Result<String, Value> {
    validate_route(route).map_err(|_| json!({"error":"x_app_read_profile_invalid","status_code":500}))?;
    if req.method != "GET" || !req.body.is_empty() {
        return Err(json!({"error":"x_app_read_request_denied","status_code":403}));
    }
    let name = target_username(url)?;
    if route.adapter_config["username"].as_str() != Some(name) {
        return Err(json!({"error":"x_app_read_username_denied","status_code":403}));
    }
    let mut media = req.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    if media.next().is_some_and(|(_, value)| !is_json_content_type(value)) || media.next().is_some() {
        return Err(json!({"error":"x_app_read_content_type_denied","status_code":415}));
    }
    for (name, value) in &req.headers {
        if (name.eq_ignore_ascii_case("accept") && !matches!(value.as_str(), "application/json" | "*/*"))
            || (name.eq_ignore_ascii_case("accept-language") && value != "*")
            || (name.eq_ignore_ascii_case("sec-fetch-mode") && value != "cors") {
            return Err(json!({"error":"x_app_read_header_denied","status_code":403}));
        }
    }
    Ok(name.to_string())
}

pub(crate) fn normalize_request(req: &DecisionRequest, url: &Url, matched: &RouteMatch<'_>)
    -> Result<(Value, Value), Value> {
    let name = validate_request(req, url, matched.route)?;
    if !matched.params.is_empty() || matched.route.paths[0].matches_canonical(url.path()).as_ref() != Some(&matched.params) {
        return Err(json!({"error":"x_app_read_path_denied","status_code":403}));
    }
    Ok((json!({"operation":OPERATION,"username":name}), json!({})))
}

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>,
    config: &Value, body: SensitiveResponseBytes, guard: &ResponseSecretGuard)
    -> Result<SensitiveResponseBytes, Value> {
    target_username(url)?;
    let error = status.is_client_error() || status.is_server_error();
    if !STATUSES.contains(&status.as_u16()) || config != &response_profile(error)
        || content_type.is_none_or(|value| !is_json_content_type(value)) {
        return Err(json!({"error":"x_app_read_response_contract_invalid"}));
    }
    let (body, payload) = crate::buffered_response::inspect_json_bytes(ADAPTER, body,
        if error { ERROR_BYTES } else { SUCCESS_BYTES }, guard, true)?;
    if !payload.is_object() { return Err(json!({"error":"x_app_read_response_shape_invalid"})); }
    // Provider error objects at HTTP 200 remain intact, not a lookup success or
    // token/account identity assertion.
    Ok(body)
}

#[cfg(test)]
#[path = "x_app_read_tests.rs"]
mod tests;
