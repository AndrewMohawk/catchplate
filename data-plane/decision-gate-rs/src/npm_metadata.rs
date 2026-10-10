//! Closed package metadata lookup, not npm installation or legacy npm.registry.
use crate::{
    DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route, RouteMatch,
    SensitiveResponseBytes,
};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub(crate) const ADAPTER: &str = "npm.metadata.v1";
pub(crate) const MODE: &str = "npmMetadataJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "npmJsonUtf8V1";
pub(crate) const HOST: &str = "registry.npmjs.org";
pub(crate) const PATH: &str = "/{package}";
pub(crate) const PLACEHOLDER: &str = "Bearer serverware-npm-placeholder-v1";
pub(crate) const HEADERS: &[&str] = &[
    "accept",
    "npm-auth-type",
    "npm-command",
    "npm-in-ci",
    "npm-scope",
    "pacote-pkg-id",
    "pacote-req-type",
    "pacote-version",
    "user-agent",
];
pub(crate) const DISCARD: &[&str] = &["accept-encoding", "npm-session"];
pub(crate) const STATUSES: &[u16] = &[200, 400, 401, 403, 404, 429, 500, 502, 503, 504];
pub(crate) const CONTENT_TYPES: &[&str] =
    &["application/json", "application/vnd.npm.install-v1+json"];
const SUCCESS_BYTES: u64 = 1_048_576;
const ERROR_BYTES: u64 = 65_536;

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

/// Deliberately narrower than legacy registry names; there are no wildcards,
/// version selectors or normalization aliases in a signed package selection.
pub(crate) fn package_name(value: &str) -> bool {
    let part = |value: &str| {
        value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
    };
    !value.is_empty()
        && value.len() <= 214
        && crate::npm_package_name(value)
        && match value.strip_prefix('@') {
            Some(scoped) => scoped
                .split_once('/')
                .is_some_and(|(scope, package)| part(scope) && part(package)),
            None => part(value),
        }
}

pub(crate) fn request_profile() -> ProviderRequestProfile {
    ProviderRequestProfile {
        allowed_headers: HEADERS,
        allowed_query_keys: &[],
        allowed_media_types: &[],
        required_discard_headers: DISCARD,
        max_body_bytes: 0,
    }
}

pub(crate) fn request_config() -> Value {
    json!({"allowedHeaders":HEADERS,"discardHeaders":DISCARD,"allowedQueryKeys":[],
        "allowedMediaTypes":[],"maxBodyBytes":0,"valueRules":[]})
}

pub(crate) fn response_profile(error: bool) -> Value {
    let mut response = json!({"mode":MODE,"maxBodyBytes":if error { ERROR_BYTES } else { SUCCESS_BYTES },
        "contentTypes":CONTENT_TYPES,"allowedHeaders":[]});
    if error {
        response["onInvalid"] = json!("block");
    } else {
        response["error"] = response_profile(true);
    }
    response
}

pub(crate) fn envelope(id: &str) -> Value {
    json!({"id":id,"type":"responseEnvelope","phase":"response","statusCodes":STATUSES,
        "contentTypePolicy":CONTENT_TYPE_POLICY,"bodyPresence":"required","contentTypes":CONTENT_TYPES,
        "allowedResponseHeaderNames":[],"responseHeaderRules":[],"unlistedHeaderPolicy":crate::response_metadata::POLICY})
}

pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    if mode != Some(MODE) || constraints.len() != 1 {
        return Err("npm.metadata.v1 requires its one exact response envelope".into());
    }
    let id = constraints[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("npm metadata response envelope ID missing")?;
    if constraints[0] != envelope(id) {
        return Err("npm metadata response envelope differs from its closed contract".into());
    }
    crate::validate_response_envelope_constraint(
        ADAPTER,
        id,
        constraints[0]
            .as_object()
            .ok_or("npm metadata envelope must be an object")?,
    )
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config
        .as_object()
        .ok_or("npm metadata config must be an object")?;
    if !exact(
        object,
        &["credentialBinding", "packages", "request", "response"],
    ) || config["request"] != request_config()
        || config["response"] != response_profile(false)
    {
        return Err("npm metadata config differs from its closed contract".into());
    }
    let binding = config["credentialBinding"]
        .as_object()
        .ok_or("npm metadata credential binding missing")?;
    if !exact(
        binding,
        &["credentialType", "provider", "subjects", "secretClass"],
    ) || binding.get("credentialType") != Some(&json!("static"))
        || binding.get("provider") != Some(&json!("operator-demo"))
        || binding.get("secretClass") != Some(&json!("bearerToken"))
        || binding
            .get("subjects")
            .and_then(Value::as_array)
            .is_none_or(|subjects| {
                subjects.len() != 1
                    || subjects[0].as_str().is_none_or(|subject| {
                        subject.is_empty()
                            || subject.len() > 512
                            || subject.trim() != subject
                            || subject.chars().any(char::is_control)
                    })
            })
    {
        return Err("npm metadata requires one exact static operator bearer binding".into());
    }
    let packages = config["packages"]
        .as_array()
        .ok_or("npm metadata packages missing")?;
    if !(1..=64).contains(&packages.len())
        || packages
            .iter()
            .any(|value| value.as_str().is_none_or(|name| !package_name(name)))
        || packages
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err("npm metadata packages must be exact sorted unique canonical names".into());
    }
    validate_envelope(Some(MODE), constraints)
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route
        .get("adapter")
        .and_then(|adapter| adapter.get("config"))
        .ok_or("npm metadata adapter missing")?;
    validate_config(
        config,
        route
            .get("constraints")
            .and_then(Value::as_array)
            .ok_or("npm metadata constraints missing")?,
    )?;
    let matcher = route
        .get("match")
        .and_then(Value::as_object)
        .ok_or("npm metadata match missing")?;
    if matcher.get("scheme") != Some(&json!("https"))
        || matcher.get("host") != Some(&json!(HOST))
        || matcher.get("port") != Some(&json!(443))
        || matcher.get("methods") != Some(&json!(["GET"]))
        || matcher.get("paths") != Some(&json!([PATH]))
        || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader")
            != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
    {
        return Err(
            "npm metadata route requires its exact GET target and replacement contract".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    let exact_path = route.paths.len() == 1
        && matches!(route.paths[0].segments.as_slice(),
        [PathSegment::Variable(name)] if name == "package");
    if route.adapter_type != ADAPTER
        || route.scheme != "https"
        || route.host != HOST
        || route.port != 443
        || route.methods != HashSet::from(["GET".to_string()])
        || !exact_path
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header
            != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers
            != DISCARD
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        || route.jit != json!({})
        || route.response_observation.is_some()
    {
        return Err("npm metadata runtime route authority is invalid".into());
    }
    Ok(())
}

fn target_package(url: &Url) -> Result<String, Value> {
    let denied = || json!({"error":"npm_metadata_target_denied","status_code":403});
    if url.scheme() != "https"
        || url.host_str() != Some(HOST)
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || crate::validate_canonical_raw_path(url.path()).is_err()
    {
        return Err(denied());
    }
    let segment = url
        .path()
        .strip_prefix('/')
        .filter(|value| !value.contains('/'))
        .filter(|value| crate::npm_package_segment(value))
        .ok_or_else(denied)?;
    let package = crate::decode_npm_scoped_name(segment);
    if !package_name(&package) {
        return Err(denied());
    }
    Ok(package)
}

/// Called before credential preparation, independently of the later operation
/// normalization. The package selection is never inferred from response bytes.
pub(crate) fn validate_request(
    req: &DecisionRequest,
    url: &Url,
    route: &Route,
) -> Result<String, Value> {
    validate_route(route)
        .map_err(|_| json!({"error":"npm_metadata_profile_invalid","status_code":500}))?;
    if req.method != "GET" || !req.body.is_empty() {
        return Err(json!({"error":"npm_metadata_request_denied","status_code":403}));
    }
    let package = target_package(url)?;
    if !route.adapter_config["packages"]
        .as_array()
        .is_some_and(|packages| {
            packages
                .iter()
                .any(|allowed| allowed.as_str() == Some(package.as_str()))
        })
    {
        return Err(json!({"error":"npm_metadata_package_denied","status_code":403}));
    }
    Ok(package)
}

pub(crate) fn normalize_request(
    req: &DecisionRequest,
    url: &Url,
    matched: &RouteMatch<'_>,
) -> Result<(Value, Value), Value> {
    let package = validate_request(req, url, matched.route)?;
    if matched.params.len() != 1
        || matched.params.get("package").map(String::as_str) != url.path().strip_prefix('/')
        || matched.route.paths[0]
            .matches_canonical(url.path())
            .as_ref()
            != Some(&matched.params)
    {
        return Err(json!({"error":"npm_metadata_package_capture_denied","status_code":403}));
    }
    Ok((
        json!({"operation":"npm.metadata.read","package":package}),
        json!({}),
    ))
}

/// Provider-specific grammar; legacy npm.registry media admission is untouched.
pub(crate) fn is_json_content_type(value: &str) -> bool {
    response_content_type(value).is_some()
}

pub(crate) fn response_content_type(value: &str) -> Option<&'static str> {
    if !value.is_ascii() || value.len() > 8192 {
        return None;
    }
    let media = match value.split_once(';') {
        None => value,
        Some((media, parameter))
            if parameter
                .trim_start_matches([' ', '\t'])
                .eq_ignore_ascii_case("charset=utf-8") =>
        {
            media
        }
        Some(_) => return None,
    };
    CONTENT_TYPES
        .iter()
        .copied()
        .find(|expected| media.eq_ignore_ascii_case(expected))
}

pub(crate) fn inspect_response(
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    config: &Value,
    body: SensitiveResponseBytes,
    guard: &ResponseSecretGuard,
) -> Result<SensitiveResponseBytes, Value> {
    let package = target_package(url)?;
    let error = status.is_client_error() || status.is_server_error();
    if !STATUSES.contains(&status.as_u16())
        || config != &response_profile(error)
        || content_type.is_none_or(|value| !is_json_content_type(value))
    {
        return Err(json!({"error":"npm_metadata_response_contract_invalid"}));
    }
    let (body, payload) = crate::buffered_response::inspect_json_bytes(
        ADAPTER,
        body,
        if error { ERROR_BYTES } else { SUCCESS_BYTES },
        guard,
        true,
    )?;
    if !payload.is_object() {
        return Err(json!({"error":"npm_metadata_response_shape_invalid"}));
    }
    if !error && payload.get("name").and_then(Value::as_str) != Some(package.as_str()) {
        return Err(json!({"error":"npm_metadata_response_package_mismatch"}));
    }
    Ok(body)
}

#[cfg(test)]
#[path = "npm_metadata_tests.rs"]
mod tests;
