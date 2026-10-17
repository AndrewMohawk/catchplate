//! Closed, keyless Alchemy JSON-RPC reads. The original request and response
//! bytes remain authoritative; parsing never rewrites their wire representation.
use crate::{DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route,
    RouteMatch, SensitiveResponseBytes};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub(crate) const ADAPTER: &str = "alchemy.rpc_read.v1";
pub(crate) const OPERATION: &str = "alchemy.rpc.read";
pub(crate) const MODE: &str = "alchemyRpcReadJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "alchemyRpcReadJsonUtf8V1";
pub(crate) const PLACEHOLDER: &str = "Bearer catchplate-alchemy-placeholder-v1";
pub(crate) const PATH: &str = "/v2";
pub(crate) const HEADERS: &[&str] = &["accept", "accept-language", "alchemy-ethers-sdk-method",
    "alchemy-ethers-sdk-version", "sec-fetch-mode", "user-agent"];
pub(crate) const DISCARD: &[&str] = &["accept-encoding"];
pub(crate) const CONTENT_TYPES: &[&str] = &["application/json"];
pub(crate) const STATUSES: &[u16] = &[200, 400, 401, 403, 404, 429, 500, 502, 503, 504];
pub(crate) const REQUEST_BYTES: u64 = 65_536;
pub(crate) const RESPONSE_BYTES: u64 = 65_536;

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(crate) fn host(chain: &str) -> Option<&'static str> {
    match chain {
        "eth-mainnet" => Some("eth-mainnet.g.alchemy.com"),
        "eth-sepolia" => Some("eth-sepolia.g.alchemy.com"),
        _ => None,
    }
}

pub(crate) fn gate_capability() -> Value {
    json!({"schema":"catchplate.operatorAlchemyRpcReadGate/v1","adapter":ADAPTER,"operation":OPERATION})
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

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    let ordinary = crate::operator_host_approvals::provider_constraints(constraints)?;
    let constraints = ordinary.as_ref();
    if mode != Some(MODE) || constraints.len() != 1 {
        return Err("Alchemy read requires its single closed response envelope".into());
    }
    let id = constraints[0]["id"].as_str().filter(|id| !id.is_empty())
        .ok_or("Alchemy read envelope ID missing")?;
    if constraints[0] != envelope(id) {
        return Err("Alchemy read response envelope differs from its closed contract".into());
    }
    crate::validate_response_envelope_constraint(ADAPTER, id,
        constraints[0].as_object().ok_or("Alchemy read envelope missing")?)
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("Alchemy read config must be an object")?;
    if !exact(object, &["credentialBinding", "chain", "request", "response"])
        || config["request"] != request_config() || config["response"] != response_profile(false)
        || config["chain"].as_str().and_then(host).is_none() {
        return Err("Alchemy read config differs from its closed contract".into());
    }
    let binding = config["credentialBinding"].as_object().ok_or("Alchemy read binding missing")?;
    let subjects = config["credentialBinding"]["subjects"].as_array();
    if !exact(binding, &["credentialType", "provider", "subjects", "secretClass"])
        || binding["credentialType"] != "static" || binding["provider"] != "operator-demo"
        || binding["secretClass"] != "bearerToken"
        || subjects.is_none_or(|values| values.len() != 1 || values[0].as_str().is_none_or(|s|
            s.is_empty() || s.len() > 512 || s.trim() != s || s.chars().any(char::is_control))) {
        return Err("Alchemy read requires one exact static operator bearer binding".into());
    }
    validate_envelope(Some(MODE), constraints)
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route.get("adapter").and_then(|a| a.get("config"))
        .ok_or("Alchemy read adapter missing")?;
    validate_config(config, route.get("constraints").and_then(Value::as_array)
        .ok_or("Alchemy read constraints missing")?)?;
    let matcher = route.get("match").and_then(Value::as_object).ok_or("Alchemy read match missing")?;
    let selected = config["chain"].as_str().and_then(host).ok_or("Alchemy read chain missing")?;
    if matcher.get("scheme") != Some(&json!("https")) || matcher.get("host") != Some(&json!(selected))
        || matcher.get("port") != Some(&json!(443)) || matcher.get("methods") != Some(&json!(["POST"]))
        || matcher.get("paths") != Some(&json!([PATH])) || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader") != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER})) {
        return Err("Alchemy read route requires its exact keyless POST target and replacement contract".into());
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    if route.adapter_type != ADAPTER || route.scheme != "https"
        || Some(route.host.as_str()) != route.adapter_config["chain"].as_str().and_then(host)
        || route.port != 443 || route.methods != HashSet::from(["POST".to_string()])
        || route.paths.len() != 1
        || !matches!(route.paths[0].segments.as_slice(), [PathSegment::Literal(segment)] if segment == "v2")
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != DISCARD.iter().map(|v| v.to_string()).collect::<Vec<_>>()
        || route.jit != json!({}) || route.response_observation.is_some() {
        return Err("Alchemy read runtime route authority is invalid".into());
    }
    Ok(())
}

fn target_chain(url: &Url) -> Result<&'static str, Value> {
    let denied = || json!({"error":"alchemy_rpc_target_denied","status_code":403});
    if url.scheme() != "https" || url.port_or_known_default() != Some(443)
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || url.query().is_some() || url.path() != PATH {
        return Err(denied());
    }
    match url.host_str() {
        Some("eth-mainnet.g.alchemy.com") => Ok("eth-mainnet"),
        Some("eth-sepolia.g.alchemy.com") => Ok("eth-sepolia"),
        _ => Err(denied()),
    }
}

pub(crate) fn request_id(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991)
        || value.as_str().is_some_and(|s| (1..=64).contains(&s.len())
            && s.bytes().all(|b| (0x20..=0x7e).contains(&b)))
}

pub(crate) fn is_json_content_type(value: &str) -> bool {
    crate::x_app_read::is_json_content_type(value)
}

pub(crate) fn validate_request(req: &DecisionRequest, url: &Url, route: &Route) -> Result<Value, Value> {
    validate_route(route).map_err(|_| json!({"error":"alchemy_rpc_policy_invalid","status_code":500}))?;
    let chain = target_chain(url)?;
    if req.method != "POST" || route.adapter_config["chain"] != chain {
        return Err(json!({"error":"alchemy_rpc_target_denied","status_code":403}));
    }
    let mut media = req.headers.iter().filter(|(name,_)| name.eq_ignore_ascii_case("content-type"));
    if media.next().is_none_or(|(_,value)| !is_json_content_type(value)) || media.next().is_some() {
        return Err(json!({"error":"request_content_type_denied","status_code":415}));
    }
    for (name, value) in &req.headers {
        if (name.eq_ignore_ascii_case("accept") && !matches!(value.as_str(), "application/json" | "*/*"))
            || (name.eq_ignore_ascii_case("accept-language") && value != "*")
            || (name.eq_ignore_ascii_case("sec-fetch-mode") && value != "cors") {
            return Err(json!({"error":"alchemy_rpc_header_denied","status_code":403}));
        }
    }
    let bad = || json!({"error":"alchemy_rpc_payload_invalid","status_code":403});
    if req.body.is_empty() || req.body.len() as u64 > REQUEST_BYTES { return Err(bad()); }
    let document = crate::strict_json_value_from_str(&req.body).map_err(|_| bad())?;
    let object = document.as_object().ok_or_else(bad)?;
    if !exact(object, &["jsonrpc", "id", "method", "params"])
        || document["jsonrpc"] != "2.0" || !request_id(&document["id"])
        || !matches!(document["method"].as_str(), Some("eth_chainId" | "eth_blockNumber"))
        || document["params"] != json!([]) { return Err(bad()); }
    Ok(json!({"operation":OPERATION,"chain":chain,"method":document["method"],"requestId":document["id"]}))
}

pub(crate) fn normalize_request(req: &DecisionRequest, url: &Url, matched: &RouteMatch<'_>)
    -> Result<(Value, Value), Value> {
    let operation = validate_request(req, url, matched.route)?;
    if !matched.params.is_empty() || matched.route.paths[0].matches_canonical(url.path()).as_ref() != Some(&matched.params) {
        return Err(json!({"error":"alchemy_rpc_target_denied","status_code":403}));
    }
    Ok((operation, json!({})))
}

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>,
    config: &Value, operation: &Value, body: SensitiveResponseBytes, guard: &ResponseSecretGuard)
    -> Result<SensitiveResponseBytes, Value> {
    let bad = || json!({"error":"alchemy_rpc_response_invalid","status_code":502});
    let chain = target_chain(url).map_err(|_| bad())?;
    if operation.as_object().is_none_or(|o| !exact(o, &["operation", "chain", "method", "requestId"]))
        || operation["operation"] != OPERATION || operation["chain"] != chain
        || !matches!(operation["method"].as_str(), Some("eth_chainId" | "eth_blockNumber"))
        || !request_id(&operation["requestId"]) || !STATUSES.contains(&status.as_u16())
        || config != &response_profile(status != StatusCode::OK)
        || content_type.is_none_or(|v| !is_json_content_type(v)) { return Err(bad()); }
    let (body, payload) = crate::buffered_response::inspect_json_bytes(ADAPTER, body, RESPONSE_BYTES, guard, true)?;
    let object = payload.as_object().ok_or_else(bad)?;
    if status == StatusCode::OK {
        if payload["jsonrpc"] != "2.0" || !request_id(&payload["id"])
            || payload["id"] != operation["requestId"]
            || object.contains_key("result") == object.contains_key("error") { return Err(bad()); }
        if let Some(error) = object.get("error") {
            let error = error.as_object().ok_or_else(bad)?;
            if error.get("code").and_then(Value::as_i64).is_none()
                || error.get("message").and_then(Value::as_str).is_none() { return Err(bad()); }
        }
    }
    Ok(body)
}

#[cfg(test)]
#[path = "alchemy_rpc_read_tests.rs"]
mod tests;
