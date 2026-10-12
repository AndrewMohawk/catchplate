//! Closed OAuth user-context posting transport. No consent, quota backend,
//! native authority or successful provider write is established by this module.
use crate::{Credential, DecisionRequest, PathSegment, ProviderRequestProfile,
    ResponseSecretGuard, Route, RouteMatch, SensitiveResponseBytes};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

pub(crate) const ADAPTER: &str = "x.post.v1";
pub(crate) const MODE: &str = "xPostJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "xPostJsonUtf8V1";
pub(crate) const OPERATION: &str = "tweets.write";
pub(crate) const HOST: &str = "api.x.com";
pub(crate) const PATH: &str = "/2/tweets";
pub(crate) const PLACEHOLDER: &str = "Bearer serverware-x-post-placeholder-v1";
pub(crate) const HEADERS: &[&str] = &["accept", "accept-language", "content-type", "sec-fetch-mode", "user-agent"];
pub(crate) const DISCARD: &[&str] = &["accept-encoding"];
pub(crate) const SCOPES: &[&str] = &["offline.access", "tweet.read", "tweet.write", "users.read"];
pub(crate) const STATUSES: &[u16] = &[201, 400, 401, 402, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504];
pub(crate) const REQUEST_BYTES: u64 = 32_768;
const TEXT_BYTES: usize = 16_384;
const SUCCESS_BYTES: u64 = 1_048_576;
const ERROR_BYTES: u64 = 65_536;
const CONTENT_TYPES: &[&str] = &["application/json"];
const QUOTA_ID: &str = "x-post-account-utc-day-v1";

fn exact(object: &Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
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
    let mut value = json!({"mode":MODE,"maxBodyBytes":if error {ERROR_BYTES} else {SUCCESS_BYTES},
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

pub(crate) fn quota(maximum: u64) -> Value {
    json!({"id":QUOTA_ID,"type":"rateLimit","max":maximum,"calendarWindow":"utcDay",
        "windowSemantics":"calendarUTC","store":"shared",
        "key":{"scope":["operation"],"operationFields":["providerAccount"]}})
}

fn quota_selection(constraints: &[Value]) -> Result<Option<u64>, String> {
    let mut selected = None;
    let mut envelope_seen = false;
    if !(1..=2).contains(&constraints.len()) { return Err("X post constraint roster invalid".into()); }
    for constraint in constraints {
        if constraint["type"] == "responseEnvelope" {
            let id = constraint["id"].as_str().filter(|id| !id.is_empty() && *id != QUOTA_ID)
                .ok_or("X post envelope ID missing or reserved")?;
            if envelope_seen || *constraint != envelope(id) {
                return Err("X post response envelope differs from its closed contract".into());
            }
            crate::validate_response_envelope_constraint(ADAPTER, id,
                constraint.as_object().ok_or("X post envelope missing")?)?;
            envelope_seen = true;
        } else {
            let maximum = constraint["max"].as_u64().filter(|n| (1..=1_000_000_000).contains(n))
                .ok_or("X post quota maximum invalid")?;
            if selected.is_some() || *constraint != quota(maximum) {
                return Err("X post quota differs from its closed account-day contract".into());
            }
            selected = Some(maximum);
        }
    }
    if !envelope_seen { return Err("X post response envelope missing".into()); }
    Ok(selected)
}

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    if mode != Some(MODE) { return Err("X post response mode invalid".into()); }
    quota_selection(constraints).map(|_| ())
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("X post config missing")?;
    if !exact(object, &["credentialBinding", "request", "response"])
        || config["request"] != request_config() || config["response"] != response_profile(false) {
        return Err("X post config differs from its closed contract".into());
    }
    let binding = config["credentialBinding"].as_object().ok_or("X post credential binding missing")?;
    if !exact(binding, &["credentialType", "provider", "subjects", "clientIds", "requiredScopes"])
        || binding["credentialType"] != "oauth2" || binding["provider"] != "x"
        || binding["requiredScopes"] != json!(SCOPES)
        || ["subjects", "clientIds"].iter().any(|key|
            binding[*key].as_array().is_none_or(|items| items.len() != 1 ||
                items[0].as_str().is_none_or(|s| s.is_empty() || s.len() > 512
                    || s.trim() != s || s.chars().any(char::is_control)))) {
        return Err("X post requires one exact OAuth subject and client with posting scopes".into());
    }
    validate_envelope(Some(MODE), constraints)
}

/// Additional provider-specific injection checks; shared admission still owns
/// exact signed subject/client identity and granted-scope superset validation.
pub(crate) fn validate_credential(credential: &Credential) -> Result<(), String> {
    if credential.injection.as_object().is_none_or(|object| !exact(object,
            &["type", "header", "field", "__serverwareCredentialType", "__serverwareOAuthClientId", "__serverwareGrantedScopes"]))
        || credential.kind() != "oauth2" || credential.provider != "x"
        || credential.injection["type"] != "bearer" || credential.injection["header"] != "Authorization"
        || credential.injection["field"] != "access_token" || credential.injection.get("prefix").is_some() {
        return Err("X post requires verified X OAuth Authorization access-token injection".into());
    }
    Ok(())
}

/// A second route/client/credential cannot bypass the same signed account's
/// selected ceiling. This validates policy consistency, not quota availability.
pub(crate) fn validate_policy_routes(routes: &[Value], credentials: &HashMap<String, Credential>) -> Result<(), String> {
    let mut accounts = HashMap::new();
    for route in routes.iter().filter(|route| route["adapter"]["type"] == ADAPTER) {
        let constraints = route["constraints"].as_array().ok_or("X post constraints missing")?;
        validate_config(&route["adapter"]["config"], constraints)?;
        let reference = route["credentialRef"].as_str().ok_or("X post credential missing")?;
        let credential = credentials.get(reference).ok_or("X post signed credential missing")?;
        validate_credential(credential)?;
        let subject = credential.provider_subject.as_deref().ok_or("X post signed subject missing")?;
        let selected = quota_selection(constraints)?;
        if accounts.insert(subject, selected).is_some_and(|previous| previous != selected) {
            return Err("X post routes for one account must select the same account-day quota".into());
        }
    }
    for route in routes {
        let Some(credential) = route["credentialRef"].as_str().and_then(|id| credentials.get(id)) else { continue; };
        if credential.provider != "x" || credential.provider_subject.as_deref()
            .and_then(|subject| accounts.get(subject)).is_none_or(Option::is_none) { continue; }
        let kind = route["adapter"]["type"].as_str().unwrap_or_default();
        let legacy_write = kind == "x.v2" && route["adapter"]["config"]["mode"] == "controlledWrite";
        let matcher = &route["match"];
        let mut generic_write = false;
        if kind == "generic.rest" && matcher["scheme"].as_str().unwrap_or("https") == "https"
            && matcher["host"] == HOST && matcher["port"].as_u64().unwrap_or(443) == 443
            && matcher["methods"].as_array().is_some_and(|methods| methods.iter().any(|m| m == "POST")) {
            for path in matcher["paths"].as_array().ok_or("generic X posting paths missing")? {
                let template = crate::compile_template(path.as_str().ok_or("generic X posting path invalid")?)?;
                generic_write |= template.matches_canonical(PATH).is_some();
            }
        }
        if legacy_write || generic_write {
            return Err("limited X post account has an overlapping legacy or generic write route".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route.get("adapter").and_then(|a| a.get("config")).ok_or("X post config missing")?;
    validate_config(config, route.get("constraints").and_then(Value::as_array).ok_or("X post constraints missing")?)?;
    let matcher = route.get("match").and_then(Value::as_object).ok_or("X post match missing")?;
    if matcher.get("scheme") != Some(&json!("https")) || matcher.get("host") != Some(&json!(HOST))
        || matcher.get("port") != Some(&json!(443)) || matcher.get("methods") != Some(&json!(["POST"]))
        || matcher.get("paths") != Some(&json!([PATH])) || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader") != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER})) {
        return Err("X post requires its exact POST target and placeholder replacement".into());
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    if route.adapter_type != ADAPTER || route.scheme != "https" || route.host != HOST || route.port != 443
        || route.methods != HashSet::from(["POST".to_string()]) || route.paths.len() != 1
        || !matches!(route.paths[0].segments.as_slice(), [PathSegment::Literal(a), PathSegment::Literal(b)] if a == "2" && b == "tweets")
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != DISCARD.iter().map(|name| name.to_string()).collect::<Vec<_>>()
        || route.jit != json!({}) || route.response_observation.is_some() {
        return Err("X post runtime route authority invalid".into());
    }
    Ok(())
}

fn target(url: &Url) -> Result<(), Value> {
    if url.scheme() != "https" || url.host_str() != Some(HOST) || url.port_or_known_default() != Some(443)
        || !url.username().is_empty() || url.password().is_some() || url.query().is_some()
        || url.fragment().is_some() || url.path() != PATH {
        return Err(json!({"error":"x_post_target_denied","status_code":403}));
    }
    Ok(())
}

pub(crate) fn is_json_content_type(value: &str) -> bool { crate::x_app_read::is_json_content_type(value) }

pub(crate) fn validate_request(req: &DecisionRequest, url: &Url, route: &Route) -> Result<(), Value> {
    validate_route(route).map_err(|_| json!({"error":"x_post_profile_invalid","status_code":500}))?;
    target(url)?;
    if req.url != "https://api.x.com/2/tweets" {
        return Err(json!({"error":"x_post_target_denied","status_code":403}));
    }
    if req.method != "POST" { return Err(json!({"error":"x_post_method_denied","status_code":403})); }
    let mut media = req.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    if media.next().is_none_or(|(_, value)| !is_json_content_type(value)) || media.next().is_some() {
        return Err(json!({"error":"x_post_content_type_denied","status_code":415}));
    }
    for (name, value) in &req.headers {
        if (name.eq_ignore_ascii_case("accept") && !matches!(value.as_str(), "application/json" | "*/*"))
            || (name.eq_ignore_ascii_case("accept-language") && value != "*")
            || (name.eq_ignore_ascii_case("sec-fetch-mode") && value != "cors") {
            return Err(json!({"error":"x_post_header_denied","status_code":403}));
        }
    }
    let bad = || json!({"error":"x_post_payload_invalid","status_code":403});
    if req.body.is_empty() || req.body.len() as u64 > REQUEST_BYTES { return Err(bad()); }
    let value = crate::sensitive_json_value_from_slice(req.body.as_bytes()).map_err(|_| bad())?;
    if value.as_object().is_none_or(|object| !exact(object, &["text"]))
        || value["text"].as_str().is_none_or(|text| text.is_empty() || text.len() > TEXT_BYTES || text.contains('\0')) {
        return Err(bad());
    }
    Ok(())
}

pub(crate) fn normalize_request(req: &DecisionRequest, url: &Url, matched: &RouteMatch<'_>) -> Result<(Value, Value), Value> {
    validate_request(req, url, matched.route)?;
    if !matched.params.is_empty() || matched.route.paths[0].matches_canonical(url.path()).as_ref() != Some(&matched.params) {
        return Err(json!({"error":"x_post_target_denied","status_code":403}));
    }
    Ok((json!({"operation":OPERATION}), json!({})))
}

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>, config: &Value,
    body: SensitiveResponseBytes, guard: &ResponseSecretGuard) -> Result<SensitiveResponseBytes, Value> {
    target(url)?;
    let error = status != StatusCode::CREATED;
    if !STATUSES.contains(&status.as_u16()) || config != &response_profile(error)
        || content_type.is_none_or(|value| !is_json_content_type(value)) {
        return Err(json!({"error":"x_post_response_contract_invalid"}));
    }
    let (body, value) = crate::buffered_response::inspect_json_bytes(ADAPTER, body,
        if error {ERROR_BYTES} else {SUCCESS_BYTES}, guard, true)?;
    if !value.is_object() { return Err(json!({"error":"x_post_response_shape_invalid"})); }
    Ok(body)
}

#[cfg(test)]
#[path = "x_post_tests.rs"]
mod tests;
