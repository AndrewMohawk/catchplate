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
        || object.get("response") != Some(&response_profile(false))
    {
        return Err("gmail.read.v1 config or unsupported age/response policy".into());
    }
    let age = crate::gmail_read_age::parse_policy(&object["agePolicy"])
        .map_err(|_| "gmail.read.v1 age policy is invalid")?;
    if age != crate::gmail_read_age::AgePolicy::Unrestricted
        && config.pointer("/request/queryMode").and_then(Value::as_str)
            != Some(crate::request_query_compat::MODE)
    {
        return Err("restricted Gmail age requires orderedFormV1".into());
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
    crate::gmail_read_age::validate_request(
        crate::gmail_read_age::parse_policy(&route.adapter_config["agePolicy"])
            .map_err(|error| json!({"error":error.code(),"status_code":403}))?, url)
        .map_err(|error| json!({"error":error.code(),"status_code":403}))?;
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

/// Restricted age evidence is owned by the original request. Supplemental
/// reads reuse its exact lease and pinned client; they cannot obtain authority.
pub(crate) struct AgeExecution {
    policy: crate::gmail_read_age::AgePolicy,
    binding: crate::CredentialLeaseReleaseBinding,
    authorization: crate::SensitiveString,
    prepared: crate::PreparedUpstream,
    decision: crate::SensitiveJsonValue,
    url: Url,
    deadline: std::time::Instant,
    deadlines: crate::UpstreamSendDeadlines,
    principal_expiry: u128,
    anchor_wall: u128,
    anchor: std::time::Instant,
    previous_now: std::cell::Cell<u128>,
    evidence: Option<crate::gmail_read_age::ResponseAgeCheck>,
    probes: usize,
}

impl AgeExecution {
    pub(crate) fn prepare(
        state: &crate::GateState, snapshot: &std::sync::Arc<Snapshot>, decision: &Value,
        url: &Url, headers: &reqwest::header::HeaderMap, prepared: &crate::PreparedUpstream,
        binding: Option<&crate::CredentialLeaseReleaseBinding>, deadline: std::time::Instant,
        ordinary_terminal: bool,
    ) -> Result<Option<Self>, &'static str> {
        let matched = crate::decision_route_context(snapshot, decision, "GET", url)
            .map_err(|_| "gmail_read_age_parent_invalid")?;
        if matched.route.adapter_type != ADAPTER { return Ok(None); }
        let policy = crate::gmail_read_age::parse_policy(&matched.route.adapter_config["agePolicy"])
            .map_err(|error| error.code())?;
        if policy == crate::gmail_read_age::AgePolicy::Unrestricted { return Ok(None); }
        let binding = binding.ok_or("gmail_read_age_parent_binding_missing")?;
        if !ordinary_terminal || !state.policy_shadow.is_operator_demo() || state.is_production
            || binding.profile != crate::ReleaseProfile::Legacy
            || binding.request_authority.is_some() || binding.release_authorization.is_some()
            || state.atomic_release_authorization_enabled || state.native_secret_broker.is_some()
            || state.native_serving_privileges.is_some()
            || prepared.policy_hash != snapshot.hash || prepared.route_id != matched.route.id
            || prepared.host != "gmail.googleapis.com" || prepared.port != 443
            || binding.scope.route_id != matched.route.id
            || decision["principal_id"].as_str() != Some(binding.scope.principal_id.as_str())
            || matched.route.credential_ref.as_deref() != Some(binding.scope.credential_id.as_str())
        { return Err("gmail_read_age_parent_authority_unsupported"); }
        // This admission is the same ordinary Google owner used for the parent,
        // not a new authorization or a generic provider credential fallback.
        if !matches!(crate::operator_google_reconciliation::admitted(state, snapshot,
            &binding.scope, None, None).map_err(|_| "gmail_read_age_parent_authority_changed")?,
            Some(crate::operator_google_reconciliation::Admission::Google(_)))
        { return Err("gmail_read_age_parent_authority_unsupported"); }
        let authorization = headers.get(reqwest::header::AUTHORIZATION)
            .filter(|_| headers.get_all(reqwest::header::AUTHORIZATION).iter().count() == 1)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with("Bearer ") && value.len() > 7)
            .ok_or("gmail_read_age_parent_credential_missing")?;
        let principal_expiry = crate::operator_static_preparation::principal_expiry(snapshot, &binding.scope)
            .map_err(|_| "gmail_read_age_principal_expired")?;
        let deadlines = crate::UpstreamSendDeadlines {
            policy_expires_at_epoch_ms: crate::policy_upstream_send_deadline(snapshot, decision, "GET", url)
                .map_err(|_| "gmail_read_age_policy_deadline_invalid")?,
            ..Default::default()
        };
        let wall = crate::now_epoch_ms();
        let execution = Self { policy, binding: binding.clone(),
            authorization: crate::SensitiveString::new(authorization.to_owned()),
            prepared: prepared.clone(), decision: crate::SensitiveJsonValue::new(decision.clone()),
            url: url.clone(), deadline: deadline.min(binding.expires_at_monotonic), deadlines,
            principal_expiry, anchor_wall: wall, anchor: std::time::Instant::now(),
            previous_now: std::cell::Cell::new(wall), evidence: None, probes: 0 };
        execution.check_current(state, snapshot, false)?;
        Ok(Some(execution))
    }

    fn now(&self) -> Result<u128, &'static str> {
        let now = crate::gmail_read_age::checked_now_ms(self.anchor_wall, self.anchor.elapsed(),
            crate::now_epoch_ms(), self.previous_now.get()).map_err(|error| error.code())?;
        self.previous_now.set(now);
        Ok(now)
    }

    fn check_current(&self, state: &crate::GateState, snapshot: &std::sync::Arc<Snapshot>,
        require_evidence: bool) -> Result<(), &'static str>
    {
        let now = self.now()?;
        if std::time::Instant::now() >= self.deadline || now >= self.principal_expiry
            || self.deadlines.minimum_epoch_ms().is_some_and(|expiry| now >= u128::from(expiry))
        { return Err("gmail_read_age_deadline_expired"); }
        crate::validate_response_release_context(state, snapshot, &self.decision, "GET", &self.url)
            .map_err(|_| "gmail_read_age_parent_authority_changed")?;
        let authority = crate::acquire_upstream_send_authority(state, snapshot, Some(&self.binding))
            .map_err(|_| "gmail_read_age_parent_authority_changed")?;
        drop(authority);
        if require_evidence {
            self.evidence.as_ref().ok_or("gmail_read_age_evidence_missing")?
                .validate_release(now).map_err(|error| error.code())?;
        }
        Ok(())
    }

    fn inspect_metadata(mut response: reqwest::blocking::Response,
        guard: &ResponseSecretGuard, probe_deadline: std::time::Instant)
        -> Result<SensitiveResponseBytes, &'static str>
    {
        use std::io::Read;
        let headers = crate::response_metadata::prepare(response.headers(), &[], guard)
            .map_err(|_| "gmail_read_age_metadata_headers_invalid")?;
        if response.status() != StatusCode::OK
            || !crate::response_content_encoding_is_identity_or_absent(&headers)
            || headers.get(reqwest::header::CONTENT_TYPE).and_then(|value| value.to_str().ok())
                .and_then(normalized_media_type).as_deref() != Some("application/json")
        { return Err("gmail_read_age_metadata_response_invalid"); }
        let length = metadata_length(&headers)?;
        if length.is_some_and(|length| length > crate::gmail_read_age::MAX_METADATA_BYTES as u64) {
            return Err("gmail_read_age_metadata_too_large");
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        // The request timeout includes the body read. The absolute deadline is
        // checked again after the bounded read, so header success cannot reset it.
        (&mut response).take(crate::gmail_read_age::MAX_METADATA_BYTES as u64 + 1)
            .read_to_end(&mut bytes).map_err(|_| "gmail_read_age_metadata_read_failed")?;
        if std::time::Instant::now() >= probe_deadline { return Err("gmail_read_age_metadata_timeout"); }
        if bytes.len() > crate::gmail_read_age::MAX_METADATA_BYTES
            || length.is_some_and(|length| length != bytes.len() as u64)
        { return Err("gmail_read_age_metadata_length_invalid"); }
        let (bytes, _) = crate::buffered_response::inspect_json_bytes(ADAPTER,
            std::mem::take(&mut *bytes).into(), crate::gmail_read_age::MAX_METADATA_BYTES as u64, guard, true)
            .map_err(|_| "gmail_read_age_metadata_json_invalid")?;
        Ok(bytes)
    }

    pub(crate) fn inspect_success(&mut self, state: &crate::GateState,
        snapshot: &std::sync::Arc<Snapshot>, body: &[u8], guard: &ResponseSecretGuard)
        -> Result<Value, &'static str>
    {
        if self.evidence.is_some() { return Err("gmail_read_age_evidence_reused"); }
        self.check_current(state, snapshot, false)?;
        let mut evidence = crate::gmail_read_age::inspect_success(self.policy, &self.url, body, self.now()?)
            .map_err(|error| error.code())?;
        let total_deadline = self.deadline.min(std::time::Instant::now() + crate::gmail_read_age::TOTAL_TIMEOUT);
        while let Some(id) = evidence.next_metadata_id() {
            self.check_current(state, snapshot, false)?;
            if self.probes >= crate::gmail_read_age::MAX_MESSAGES { return Err("gmail_read_age_probe_limit"); }
            let id = crate::SensitiveString::new(id.to_owned());
            let url = crate::gmail_read_age::metadata_url(id.as_str()).map_err(|error| error.code())?;
            let now = self.now()?;
            let expiry = self.deadlines.minimum_epoch_ms().map(u128::from)
                .unwrap_or(self.principal_expiry).min(self.principal_expiry);
            let remaining_ms = u64::try_from(expiry.checked_sub(now)
                .ok_or("gmail_read_age_deadline_expired")?).map_err(|_| "gmail_read_age_deadline_invalid")?;
            let timeout = total_deadline.checked_duration_since(std::time::Instant::now())
                .ok_or("gmail_read_age_metadata_timeout")?.min(crate::gmail_read_age::PROBE_TIMEOUT)
                .min(std::time::Duration::from_millis(remaining_ms));
            if timeout.is_zero() { return Err("gmail_read_age_metadata_timeout"); }
            let probe_deadline = std::time::Instant::now() + timeout;
            let builder = self.prepared.client.get(url.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .header(reqwest::header::AUTHORIZATION, self.authorization.as_str());
            self.probes += 1;
            let mut probe_deadlines = self.deadlines;
            probe_deadlines.dispatch_expires_at_epoch_ms = Some(u64::try_from(now + timeout.as_millis())
                .map_err(|_| "gmail_read_age_deadline_invalid")?);
            let mut probe_binding = self.binding.clone();
            probe_binding.expires_at_monotonic = probe_binding.expires_at_monotonic.min(probe_deadline);
            let response = crate::send_upstream_request_with_final_check(
                state, snapshot, Some(&probe_binding), builder, Some(timeout), probe_deadlines, false, None,
                |built| {
                    if built.method() != reqwest::Method::GET || built.url() != &url
                        || built.body().is_some() || built.headers().len() != 3
                        || built.headers().get(reqwest::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()) != Some(self.authorization.as_str())
                        || built.headers().get(reqwest::header::ACCEPT).and_then(|value| value.to_str().ok()) != Some("application/json")
                        || built.headers().get(reqwest::header::ACCEPT_ENCODING).and_then(|value| value.to_str().ok()) != Some("identity")
                    { return Err("gmail_read_age_metadata_request_changed"); }
                    Ok(())
                }, |_| Ok(None), || {
                    if std::time::Instant::now() >= probe_deadline || self.now()? >= expiry {
                        return Err("gmail_read_age_metadata_timeout");
                    }
                    Ok(())
                }).map_err(|_| "gmail_read_age_metadata_send_failed")?;
            let bytes = Self::inspect_metadata(response, guard, probe_deadline)?;
            self.check_current(state, snapshot, false)?;
            evidence.record_metadata(id.as_str(), &bytes, self.now()?).map_err(|error| error.code())?;
        }
        if std::time::Instant::now() >= total_deadline { return Err("gmail_read_age_metadata_timeout"); }
        evidence.validate_release(self.now()?).map_err(|error| error.code())?;
        self.evidence = Some(evidence);
        self.check_current(state, snapshot, true)?;
        let crate::gmail_read_age::AgePolicy::RecentInternalDate { max_age_days } = self.policy
            else { return Err("gmail_read_age_policy_invalid"); };
        Ok(json!({"ok":true,"mode":MODE,"body_bytes_preserved":true,"allowed_fields_redacted":false,
            "adapter":ADAPTER,"age_policy":crate::gmail_read_age::MODE,"max_age_days":max_age_days,
            "metadata_probes":self.probes}))
    }

    fn write_deadline(&self) -> Result<std::time::Instant, &'static str> {
        let now = self.now()?;
        let expiry = self.evidence.as_ref().and_then(|evidence| evidence.earliest_expiry_ms())
            .unwrap_or(self.principal_expiry).min(self.principal_expiry)
            .min(self.deadlines.minimum_epoch_ms().map(u128::from).unwrap_or(self.principal_expiry));
        let millis = u64::try_from(expiry.checked_sub(now).ok_or("gmail_read_age_deadline_expired")?)
            .map_err(|_| "gmail_read_age_deadline_invalid")?;
        Ok(self.deadline.min(std::time::Instant::now() + std::time::Duration::from_millis(millis)))
    }

    /// A released audit records validation, not client delivery. A later change
    /// gets a distinct blocked terminal outcome; a partial write is never retried.
    pub(crate) fn write_response(&self, state: &crate::GateState, snapshot: &std::sync::Arc<Snapshot>,
        writer: &mut dyn crate::TerminalDeadlineWrite, response: &[u8]) -> bool
    {
        let check = self.check_current(state, snapshot, true).and_then(|()| self.write_deadline());
        let deadline = match check {
            Ok(deadline) => deadline,
            Err(error) => {
                let blocked = crate::block_forward_response(state, snapshot, &self.decision, "GET", &self.url,
                    StatusCode::OK, json!({"error":error,"stage":"gmail_age_terminal","client_delivery":"not_started"}));
                crate::write_snapshot_guarded_response(state, snapshot, writer, &blocked);
                return false;
            }
        };
        writer.set_terminal_write_deadline(Some(deadline));
        let written = {
            let mut guarded = AgeWriter { state, snapshot, execution: self, inner: writer };
            crate::write_snapshot_guarded_response(state, snapshot, &mut guarded, response)
        };
        writer.set_terminal_write_deadline(None);
        if !written {
            crate::enqueue_audit(state, "data_plane.response.blocked", crate::decision_audit_event(
                &self.decision, "GET", &self.url, "blocked", json!({"error":"gmail_read_age_terminal_write_refused",
                    "stage":"gmail_age_terminal","client_delivery":"incomplete_or_unknown"})));
        }
        written
    }
}

struct AgeWriter<'a> {
    state: &'a crate::GateState,
    snapshot: &'a std::sync::Arc<Snapshot>,
    execution: &'a AgeExecution,
    inner: &'a mut dyn crate::TerminalDeadlineWrite,
}

fn metadata_length(headers: &reqwest::header::HeaderMap) -> Result<Option<u64>, &'static str> {
    let length = crate::strict_response_content_length(headers)
        .map_err(|_| "gmail_read_age_metadata_length_invalid")?;
    if headers.contains_key(reqwest::header::TRANSFER_ENCODING)
        && (length.is_some() || headers.get_all(reqwest::header::TRANSFER_ENCODING).iter().count() != 1
            || headers.get(reqwest::header::TRANSFER_ENCODING).and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.trim().eq_ignore_ascii_case("chunked")))
    { return Err("gmail_read_age_metadata_framing_invalid"); }
    Ok(length)
}

impl std::io::Write for AgeWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.execution.check_current(self.state, self.snapshot, true)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        let written = self.inner.write(bytes)?;
        self.execution.check_current(self.state, self.snapshot, true)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.execution.check_current(self.state, self.snapshot, true)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        self.inner.flush()?;
        self.execution.check_current(self.state, self.snapshot, true)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
    }
}

#[cfg(test)]
#[path = "gmail_read_tests.rs"]
mod tests;
