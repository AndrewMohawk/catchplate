//! Additive, closed Gmail message-read authority. Legacy gmail.v1 is unchanged.
//! Unrestricted age means no age claim, not a synthetic long age window.
use crate::{
    canonical_gmail_message_id, is_http_token_byte, normalized_media_type,
    DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route, Snapshot,
    SensitiveResponseBytes,
};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

pub(crate) const ADAPTER: &str = "gmail.read.v1";
pub(crate) const MODE: &str = "gmailReadJsonV1";
pub(crate) const LIST_PATH: &str = "/gmail/v1/users/me/messages";
pub(crate) const GET_PATH: &str = "/gmail/v1/users/me/messages/{message_id}";
pub(crate) const HEADERS: &[&str] = &["accept", "accept-encoding", "user-agent", "x-goog-api-client"];
pub(crate) const ORDERED_HEADERS: &[&str] = &["accept", "user-agent", "x-goog-api-client"];
pub(crate) const ORDERED_DISCARD: &[&str] = &["accept-encoding"];
pub(crate) const QUERY_KEYS: &[&str] = &[
    "alt", "format", "includeSpamTrash", "labelIds", "maxResults", "metadataHeaders",
    "pageToken", "prettyPrint", "q",
];
pub(crate) const LIST_KEYS: &[&str] = &["alt", "includeSpamTrash", "labelIds", "maxResults", "pageToken", "prettyPrint", "q"];
pub(crate) const GET_KEYS: &[&str] = &["alt", "format", "metadataHeaders", "prettyPrint"];
const STATUSES: &[u16] = &[200, 400, 401, 403, 404, 429, 500, 502, 503, 504];
const SUCCESS_BYTES: u64 = 1_048_576;
const ERROR_BYTES: u64 = 65_536;

pub(crate) fn request_profile(ordered: bool) -> ProviderRequestProfile {
    ProviderRequestProfile {
        allowed_headers: if ordered { ORDERED_HEADERS } else { HEADERS },
        allowed_query_keys: QUERY_KEYS, allowed_media_types: &[],
        required_discard_headers: if ordered { ORDERED_DISCARD } else { &[] }, max_body_bytes: 0,
    }
}

fn exact_keys(object: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.contains_key(*key))
        && object.keys().all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

pub(crate) fn response_profile(error: bool) -> Value {
    let mut profile = json!({"mode":MODE,"maxBodyBytes":if error { ERROR_BYTES } else { SUCCESS_BYTES },
        "contentTypes":["application/json"],"allowedHeaders":[]});
    if error { profile["onInvalid"] = json!("block"); }
    else { profile["error"] = response_profile(true); }
    profile
}

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    let ordinary = crate::operator_host_approvals::provider_constraints(constraints)?;
    let constraints = ordinary.as_ref();
    if mode != Some(MODE) || constraints.len() != 1 {
        return Err("gmail.read.v1 requires its one explicit response envelope".into());
    }
    let envelope = constraints[0].as_object().ok_or("Gmail read envelope must be an object")?;
    if !exact_keys(envelope, &["id", "type", "phase", "statusCodes", "bodyPresence", "contentTypes",
        "allowedResponseHeaderNames", "responseHeaderRules", "unlistedHeaderPolicy"], &[])
        || envelope.get("type") != Some(&json!("responseEnvelope"))
        || envelope.get("phase") != Some(&json!("response"))
        || envelope.get("statusCodes") != Some(&json!(STATUSES))
        || envelope.get("bodyPresence") != Some(&json!("required"))
        || envelope.get("contentTypes") != Some(&json!(["application/json"]))
        || envelope.get("allowedResponseHeaderNames") != Some(&json!([]))
        || envelope.get("responseHeaderRules") != Some(&json!([]))
        || envelope.get("unlistedHeaderPolicy") != Some(&json!(crate::response_metadata::POLICY))
    {
        return Err("gmail.read.v1 response envelope differs from its closed contract".into());
    }
    crate::validate_response_envelope_constraint(ADAPTER, "gmail.read.response", envelope)
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("Gmail read config must be an object")?;
    if !exact_keys(object, &["credentialBinding", "request", "agePolicy", "response"], &[])
        || object.get("agePolicy") != Some(&json!({"mode":"unrestricted"}))
        || object.get("response") != Some(&response_profile(false))
    {
        return Err("gmail.read.v1 config or unsupported age/response policy".into());
    }
    let binding = object.get("credentialBinding").and_then(Value::as_object)
        .ok_or("Gmail read credential binding missing")?;
    if !exact_keys(binding, &["credentialType", "provider", "subjects", "clientIds", "requiredScopes"], &[])
        || binding.get("credentialType") != Some(&json!("oauth2"))
        || binding.get("provider") != Some(&json!("google"))
        || binding.get("requiredScopes") != Some(&json!(["https://www.googleapis.com/auth/gmail.readonly"]))
        || ["subjects", "clientIds"].iter().any(|key| binding.get(*key).and_then(Value::as_array)
            .is_none_or(|values| values.len() != 1 || values[0].as_str().is_none_or(|value|
                value.is_empty() || value.len() > 512 || value.trim() != value || value.chars().any(char::is_control))))
    {
        return Err("gmail.read.v1 requires an exact Google account and OAuth client binding".into());
    }
    let request = object.get("request").and_then(Value::as_object).ok_or("Gmail read request missing")?;
    let ordered = request.get("queryMode").and_then(Value::as_str) == Some(crate::request_query_compat::MODE);
    if !exact_keys(request, &["allowedHeaders", "allowedQueryKeys", "allowedMediaTypes", "maxBodyBytes", "valueRules"], &["discardHeaders", "queryMode"])
        || request.get("allowedHeaders") != Some(&json!(if ordered { ORDERED_HEADERS } else { HEADERS }))
        || request.get("allowedQueryKeys") != Some(&json!(QUERY_KEYS))
        || request.get("allowedMediaTypes") != Some(&json!([]))
        || request.get("maxBodyBytes") != Some(&json!(0))
        || request.get("valueRules") != Some(&json!([]))
        || (if ordered { request.get("discardHeaders") != Some(&json!(ORDERED_DISCARD)) }
            else { request.get("discardHeaders").is_some_and(|value| value != &json!([])) })
        || request.get("queryMode").is_some_and(|value| value.as_str() != Some(crate::request_query_compat::MODE))
    {
        return Err("gmail.read.v1 request profile differs from its closed contract".into());
    }
    validate_envelope(Some(MODE), constraints)
}

pub(crate) fn validate_policy_match(matcher: &Map<String, Value>) -> Result<(), String> {
    if matcher.get("scheme") != Some(&json!("https"))
        || matcher.get("host") != Some(&json!("gmail.googleapis.com"))
        || matcher.get("port") != Some(&json!(443))
        || matcher.get("methods") != Some(&json!(["GET"]))
        || matcher.get("paths") != Some(&json!([LIST_PATH, GET_PATH]))
    {
        return Err("gmail.read.v1 requires the two exact account-bound GET path shapes".into());
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    let paths = route.paths.iter().map(|path| {
        path.segments.iter().map(|segment| match segment {
            PathSegment::Literal(value) => Some(value.clone()),
            PathSegment::Variable(value) => Some(format!("{{{value}}}")),
            _ => None,
        }).collect::<Option<Vec<_>>>().map(|parts| format!("/{}", parts.join("/")))
    }).collect::<Option<Vec<_>>>().ok_or("Gmail read wildcard paths are forbidden")?;
    if route.adapter_type != ADAPTER || route.scheme != "https" || route.host != "gmail.googleapis.com"
        || route.port != 443 || route.methods != HashSet::from(["GET".to_string()])
        || paths != [LIST_PATH, GET_PATH] || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.discard_headers != if ordered_query(route) { vec!["accept-encoding".to_string()] } else { vec![] }
        || route.jit != json!({})
        || route.response_observation.is_some()
    {
        return Err("gmail.read.v1 runtime route authority is invalid or unsupported".into());
    }
    Ok(())
}

pub(crate) fn message_id(url: &Url) -> Result<Option<&str>, Value> {
    if url.scheme() != "https" || url.host_str() != Some("gmail.googleapis.com")
        || url.port_or_known_default() != Some(443) || !url.username().is_empty()
        || url.password().is_some() || url.fragment().is_some()
    {
        return Err(json!({"error":"gmail_read_target_denied","status_code":403}));
    }
    if url.path() == LIST_PATH { return Ok(None); }
    url.path().strip_prefix(&format!("{LIST_PATH}/"))
        .filter(|id| canonical_gmail_message_id(id)).map(Some)
        .ok_or_else(|| json!({"error":"gmail_read_target_denied","status_code":403}))
}

fn bounded_text(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len()) && !value.chars().any(char::is_control)
}

pub(crate) fn normalize_request(req: &DecisionRequest, headers: &BTreeMap<String, String>, url: &Url, route: &Route) -> Result<(Value, Value), Value> {
    validate_route(route).map_err(|_| json!({"error":"gmail_read_profile_invalid","status_code":500}))?;
    if req.method != "GET" || !req.body.is_empty()
        || headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("accept-encoding") && value != "identity")
    {
        return Err(json!({"error":"gmail_read_request_denied","status_code":403}));
    }
    let id = message_id(url)?;
    if ordered_query(route) {
        crate::request_query_compat::parse_gmail_query(url.query(), if id.is_some() { "gmail.message.get" } else { "gmail.messages.list" })
            .map_err(|_| json!({"error":"gmail_read_query_denied","status_code":403}))?;
    }
    let keys = if id.is_some() { GET_KEYS } else { LIST_KEYS };
    let mut seen = HashSet::new();
    for (key, value) in url.query_pairs() {
        if !keys.contains(&key.as_ref()) || (!ordered_query(route) && !seen.insert(key.to_string())) {
            return Err(json!({"error":"gmail_read_query_denied","status_code":403}));
        }
        let valid = match key.as_ref() {
            "alt" => value == "json",
            "prettyPrint" => matches!(value.as_ref(), "true" | "false"),
            "includeSpamTrash" => value == "false",
            "format" => matches!(value.as_ref(), "full" | "metadata"),
            "maxResults" => value.parse::<u64>().ok().is_some_and(|limit|
                (1..=500).contains(&limit) && limit.to_string() == value.as_ref()),
            "q" => bounded_text(&value, 0, 2048),
            "pageToken" => bounded_text(&value, 1, 4096),
            "labelIds" => (1..=128).contains(&value.len()) && value.bytes().all(|byte|
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
            "metadataHeaders" => (1..=128).contains(&value.len()) && value.bytes().all(is_http_token_byte),
            _ => false,
        };
        if !valid { return Err(json!({"error":"gmail_read_query_denied","status_code":403})); }
    }
    let operation = match id {
        Some(id) => json!({"operation":"gmail.message.get","gmailUser":"me","messageId":id}),
        None => json!({"operation":"gmail.messages.list","gmailUser":"me"}),
    };
    Ok((operation, json!({})))
}

/// The marker is optional: retained pre-query Gmail rows keep their original
/// canonical v1 behavior. Only newly and explicitly signed routes opt in.
pub(crate) fn ordered_query(route: &Route) -> bool {
    route.adapter_type == ADAPTER
        && route.adapter_config.pointer("/request/queryMode").and_then(Value::as_str)
            == Some(crate::request_query_compat::MODE)
}

pub(crate) fn allows_ordered_intake(snapshot: &Snapshot, principal: Option<&str>) -> bool {
    snapshot.routes.iter().any(|route| ordered_query(route) && validate_route(route).is_ok()
        && principal.is_none_or(|id| route.principals.iter().any(|allowed| allowed == "*" || allowed == id)))
}

/// Bounded syntax intake only. This never selects credential authority. The
/// unchanged strict parser admits the entire scheme/authority/path first.
pub(crate) fn parse_ordered_target(method: &str, target: &str) -> Result<(crate::RequestPathValidation, Url), String> {
    if method != "GET" { return Err("ordered Gmail query requires GET".into()); }
    let (base, raw_query) = match target.split_once('?') {
        Some((base, query)) => (base, Some(query)), None => (target, None),
    };
    let (path, base_url) = crate::parse_validated_absolute_target(base)?;
    let id = message_id(&base_url).map_err(|_| "ordered Gmail query target is outside the closed read shapes")?;
    crate::request_query_compat::parse_gmail_query(raw_query,
        if id.is_some() { "gmail.message.get" } else { "gmail.messages.list" })?;
    let url = Url::parse(target).map_err(|_| "ordered Gmail query URL is invalid")?;
    if url.scheme() != base_url.scheme() || url.host_str() != base_url.host_str()
        || url.port_or_known_default() != base_url.port_or_known_default()
        || url.path() != base_url.path() || url.query() != raw_query
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
    {
        return Err("URL parser changed the ordered Gmail request target".into());
    }
    Ok((path, url))
}

/// No route backtracking: an alternate grammar is admitted only for the one
/// route selected by the genuine principal and unchanged authority/path.
pub(crate) fn parse_target_for_route(snapshot: &Snapshot, method: &str, target: &str,
    client_ip: Option<&str>, headers: &BTreeMap<String, String>, authenticated_principal: Option<&str>)
    -> Result<(crate::RequestPathValidation, Url), String>
{
    if let Ok(parsed) = crate::parse_validated_absolute_target(target) { return Ok(parsed); }
    let parsed = parse_ordered_target(method, target)?;
    let lowered = crate::lower_headers(headers);
    let principal = match authenticated_principal {
        Some(id) => snapshot.principals.iter().find(|principal| principal.id == id),
        None => snapshot.identify_principal(client_ip, &lowered),
    }.ok_or("ordered Gmail query principal is unavailable")?;
    let matched = snapshot.match_route(&principal.id, method, &parsed.1)
        .ok_or("ordered Gmail query route is unavailable")?;
    if !ordered_query(matched.route) { return Err("selected route does not authorize ordered Gmail queries".into()); }
    validate_route(matched.route)?;
    Ok(parsed)
}

pub(crate) fn apply_route_rewrite(route: &Route, url: &mut Url, rewrite: &Value) -> Result<(), String> {
    if !ordered_query(route) { return crate::apply_rewrite(url, rewrite); }
    validate_route(route)?;
    if rewrite != &json!({}) { return Err("ordered Gmail query cannot be rewritten".into()); }
    let (_, preserved) = parse_ordered_target("GET", url.as_str())?;
    if preserved != *url { return Err("ordered Gmail query changed before dispatch".into()); }
    Ok(())
}

/// This is deliberately separate from the legacy canonical validator used by
/// approval/atomic/durable consumers. It admits v3 only against its signed route.
pub(crate) fn canonical_discard_headers(canonical: &Value, route: &Route) -> Result<Vec<String>, String> {
    if !ordered_query(route) { return crate::canonical_request_discard_headers(canonical, &route.discard_headers); }
    validate_route(route)?;
    let outer = canonical.as_object().ok_or("ordered canonical request must be an object")?;
    let request = canonical.get("request").and_then(Value::as_object).ok_or("ordered canonical request is missing")?;
    let fields = ["method", "scheme", "authority", "path", "query", "headers", "body_sha256", "discard_headers", "query_mode", "query_wire"];
    if !crate::object_has_exact_fields(outer, crate::CANONICAL_REQUEST_TOP_LEVEL_FIELDS)
        || canonical.get("v").and_then(Value::as_u64) != Some(3)
        || !crate::object_has_exact_fields(request, &fields)
        || request.get("query_mode").and_then(Value::as_str) != Some(crate::request_query_compat::MODE)
        || request.get("discard_headers") != Some(&json!(route.discard_headers))
        || request.get("method") != Some(&json!("GET"))
        || request.get("scheme") != Some(&json!("https"))
        || request.get("authority") != Some(&json!("gmail.googleapis.com"))
    { return Err("ordered canonical request contract mismatch".into()); }
    let raw = match request.get("query_wire") {
        Some(Value::Null) => None, Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err("ordered canonical query wire is missing or invalid".into()),
    };
    let path = request.get("path").and_then(Value::as_str).ok_or("ordered canonical path missing")?;
    let target = format!("https://gmail.googleapis.com{path}{}", raw.map(|wire| format!("?{wire}")).unwrap_or_default());
    let (_, url) = parse_ordered_target("GET", &target)?;
    let id = message_id(&url).map_err(|_| "ordered canonical Gmail target is invalid")?;
    let operation = canonical.get("operation").and_then(Value::as_object).ok_or("ordered canonical operation missing")?;
    let expected_operation = if id.is_some() { "gmail.message.get" } else { "gmail.messages.list" };
    if operation.get("operation").and_then(Value::as_str) != Some(expected_operation)
        || operation.get("gmailUser").and_then(Value::as_str) != Some("me")
        || id.is_some_and(|id| operation.get("messageId").and_then(Value::as_str) != Some(id))
        || id.is_none() && operation.contains_key("messageId")
    { return Err("ordered canonical operation differs from the target".into()); }
    let parsed = crate::request_query_compat::parse_gmail_query(raw, expected_operation)?;
    if request.get("query") != Some(&json!(parsed.pairs)) {
        return Err("ordered canonical pairs differ from exact query wire".into());
    }
    Ok(route.discard_headers.clone())
}

pub(crate) fn validate_canonical_url(canonical: &Value, route: &Route, method: &str, url: &Url) -> Result<(), String> {
    canonical_discard_headers(canonical, route)?;
    let request = &canonical["request"];
    let (_, parsed) = parse_ordered_target(method, url.as_str())?;
    if parsed != *url || request["method"] != json!(method)
        || request["scheme"] != json!(url.scheme())
        || request["authority"] != json!(crate::canonical_authority(url))
        || request["path"] != json!(url.path()) || request["query_wire"] != json!(url.query())
        || request["query"] != json!(crate::query_pairs(url))
    { return Err("ordered provider URL differs from the exact committed query".into()); }
    Ok(())
}

pub(crate) fn provider_url_for_decision(snapshot: &Snapshot, decision: &Value, method: &str, original: &Url) -> Result<Url, String> {
    let principal = decision.get("principal_id").and_then(Value::as_str).ok_or("provider principal missing")?;
    let matched = snapshot.match_route(principal, method, original).ok_or("provider route unavailable")?;
    if decision.get("route_id").and_then(Value::as_str) != Some(matched.route.id.as_str()) {
        return Err("provider selected route differs from decision".into());
    }
    if !ordered_query(matched.route) { return crate::provider_url_bound_to_decision(decision, method, original); }
    if decision.get("rewrite") != Some(&json!({})) { return Err("ordered provider URL cannot be rewritten".into()); }
    validate_canonical_url(decision.get("canonical_request").ok_or("provider canonical request missing")?, matched.route, method, original)?;
    Ok(original.clone())
}

pub(crate) fn validate_built_request(canonical: &Value, route: &Route, original: &Url,
    built: &reqwest::blocking::Request) -> Result<(), &'static str>
{
    if !ordered_query(route) || built.method().as_str() != "GET"
        || built.url().as_str() != original.as_str()
        || built.headers().contains_key("accept-encoding")
    {
        return Err("ordered_provider_request_changed_at_dispatch");
    }
    validate_canonical_url(canonical, route, built.method().as_str(), built.url())
        .map_err(|_| "ordered_provider_request_binding_invalid")
}

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>,
    config: &Value, body: SensitiveResponseBytes, guard: &ResponseSecretGuard) -> Result<SensitiveResponseBytes, Value>
{
    let error = status.is_client_error() || status.is_server_error();
    if !STATUSES.contains(&status.as_u16()) || config != &response_profile(error)
        || content_type.and_then(normalized_media_type).as_deref() != Some("application/json")
    {
        return Err(json!({"error":"gmail_read_response_contract_invalid"}));
    }
    let (body, payload) = crate::buffered_response::inspect_json_bytes(
        ADAPTER, body, if error { ERROR_BYTES } else { SUCCESS_BYTES }, guard, true,
    )?;
    let object = payload.as_object().ok_or_else(|| json!({"error":"gmail_read_response_shape_invalid"}))?;
    if error { return Ok(body); }
    match message_id(url)? {
        Some(id) => {
            if object.get("id").and_then(Value::as_str) != Some(id) {
                return Err(json!({"error":"gmail_read_response_id_mismatch"}));
            }
        }
        None => {
            let maximum = url.query_pairs().find(|(key, _)| key == "maxResults")
                .and_then(|(_, value)| value.parse::<usize>().ok()).unwrap_or(500).min(500);
            let mut seen_ids = HashSet::new();
            if object.get("messages").is_some_and(|messages| messages.as_array().is_none_or(|items|
                items.len() > maximum || items.iter().any(|item|
                    item.as_object().is_none() || item.get("id").and_then(Value::as_str).is_none_or(|id| !canonical_gmail_message_id(id) || !seen_ids.insert(id))
                        || item.get("threadId").is_some_and(|id| id.as_str().is_none_or(|id| !canonical_gmail_message_id(id))))))
                || object.get("nextPageToken").is_some_and(|token| token.as_str().is_none_or(|token| !bounded_text(token, 1, 4096)))
                || object.get("resultSizeEstimate").is_some_and(|count| count.as_u64().is_none())
            {
                return Err(json!({"error":"gmail_read_response_shape_invalid"}));
            }
        }
    }
    Ok(body)
}

#[cfg(test)]
#[path = "gmail_read_tests.rs"]
mod tests;
