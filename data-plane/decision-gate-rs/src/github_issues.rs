//! Explicit repository-scoped GitHub compatibility; never a generic query bypass.
//! Numeric repository URLs are not request authority. Only response Link prefixes
//! may be rewritten into the already-signed named repository and current resource.
use crate::{DecisionRequest, PathSegment, Route};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Url,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

pub(crate) const MODE: &str = "githubRestV1";
pub(crate) const READ: &str = "github_issues_read_v1";
pub(crate) const WRITE: &str = "github_issues_write_v1";
pub(crate) const PLACEHOLDER: &str = "token serverware-github-placeholder-v1";
pub(crate) const HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "sec-fetch-mode",
    "user-agent",
    "x-github-api-version",
];
pub(crate) const QUERY: &[&str] = &[
    "assignee",
    "creator",
    "direction",
    "labels",
    "mentioned",
    "milestone",
    "page",
    "per_page",
    "since",
    "sort",
    "state",
];
pub(crate) const RESPONSE_HEADERS: &[&str] = &[
    "link",
    "retry-after",
    "x-github-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
    "x-ratelimit-used",
];
pub(crate) const STATUSES: &[u16] = &[
    200, 201, 204, 400, 401, 403, 404, 409, 410, 415, 422, 429, 500, 502, 503, 504,
];
const DISCARD: &[&str] = &["accept-encoding"];

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(crate) fn owner(value: &str) -> bool {
    (1..=39).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

fn repository_name(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn positive(value: &str, maximum: u64) -> bool {
    value
        .parse::<u64>()
        .ok()
        .is_some_and(|number| number > 0 && number <= maximum && number.to_string() == value)
}

fn repository(config: &Value) -> Result<(&str, &str), String> {
    let object = config
        .get("githubRepository")
        .and_then(Value::as_object)
        .ok_or("GitHub repository missing")?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or("GitHub repository name missing")?;
    let owner_value = object
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("GitHub repository owner missing")?;
    if !exact(object, &["owner", "name"]) || !owner(owner_value) || !repository_name(name) {
        return Err("GitHub repository identity invalid".into());
    }
    Ok((owner_value, name))
}

pub(crate) fn marked(config: &Value) -> bool {
    config.get("githubRepository").is_some()
        || config.get("operationBundle").is_some()
        || config.pointer("/request/queryMode").and_then(Value::as_str) == Some(MODE)
}

pub(crate) fn selected(route: &Route) -> bool {
    route.adapter_type == "generic.rest" && marked(&route.adapter_config)
}

fn operation(config: &Value) -> Result<&'static str, String> {
    match config.get("operationBundle").and_then(Value::as_str) {
        Some(READ) => Ok("github.issues.read"),
        Some(WRITE) => Ok("github.issues.write"),
        _ => Err("GitHub operation bundle invalid".into()),
    }
}

pub(crate) fn request_profile(bundle: &str) -> Value {
    json!({"allowedHeaders":HEADERS,"discardHeaders":DISCARD,"allowedQueryKeys":QUERY,
        "allowedMediaTypes":["application/json"],"bodyMode":crate::buffered_request::MODE,
        "maxBodyBytes":65536,"valueRules":[],"queryMode":MODE,
        "operation":{"name":if bundle == WRITE { "github.issues.write" } else { "github.issues.read" }}})
}

pub(crate) fn response_profile(error: bool) -> Value {
    let mut response = json!({"mode":crate::buffered_response::JSON_OR_EMPTY_204_V2_MODE,
        "bodyFormat":"json","maxBodyBytes":if error {65536} else {1048576},
        "contentTypes":["application/json"],"allowedHeaders":RESPONSE_HEADERS});
    if error {
        response["onInvalid"] = json!("block");
    } else {
        response["error"] = response_profile(true);
    }
    response
}

pub(crate) fn envelope(id: &str) -> Value {
    let rules = RESPONSE_HEADERS.iter().map(|name| {
        let (pattern, maximum) = match *name {
            "link" => ("^[ -~]{1,4096}$", 4096),
            "retry-after" => ("^[0-9]{1,10}$", 10),
            "x-github-request-id" => ("^[A-Za-z0-9:_-]{1,128}$", 128),
            "x-ratelimit-resource" => ("^[A-Za-z0-9_-]{1,64}$", 64),
            _ => ("^[0-9]{1,20}$", 20),
        };
        json!({"name":name,"required":false,"predicate":{"kind":"pattern","pattern":pattern,"maxLength":maximum}})
    }).collect::<Vec<_>>();
    json!({"id":id,"type":"responseEnvelope","phase":"response","statusCodes":STATUSES,
        "bodyPresence":"jsonOrEmpty204V1","contentTypes":["application/json"],
        "allowedResponseHeaderNames":RESPONSE_HEADERS,"responseHeaderRules":rules,
        "unlistedHeaderPolicy":crate::response_metadata::POLICY})
}

pub(crate) fn paths(config: &Value) -> Result<Vec<String>, String> {
    let (owner, name) = repository(config)?;
    let base = format!("/repos/{owner}/{name}/issues");
    Ok(vec![
        base.clone(),
        format!("{base}/{{issue_number}}"),
        format!("{base}/{{issue_number}}/comments"),
        format!("{base}/comments/{{comment_id}}"),
    ])
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config
        .as_object()
        .ok_or("GitHub profile must be an object")?;
    repository(config)?;
    operation(config)?;
    if !exact(
        object,
        &[
            "credentialMode",
            "credentialBinding",
            "githubRepository",
            "operationBundle",
            "request",
            "response",
        ],
    ) || config["credentialMode"] != json!("required")
        || config["request"]
            != request_profile(config["operationBundle"].as_str().unwrap_or_default())
        || config["response"] != response_profile(false)
        || constraints.len() != 1
    {
        return Err("GitHub profile differs from its closed contract".into());
    }
    let id = constraints[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("GitHub response envelope missing")?;
    if constraints[0] != envelope(id) {
        return Err("GitHub response envelope differs from its closed contract".into());
    }
    let binding = config
        .get("credentialBinding")
        .and_then(Value::as_object)
        .ok_or("GitHub credential binding missing")?;
    if !exact(
        binding,
        &["credentialType", "provider", "subjects", "secretClass"],
    ) || binding.get("credentialType") != Some(&json!("static"))
        || binding.get("secretClass") != Some(&json!("bearerToken"))
        || binding.get("provider") != Some(&json!("operator-demo"))
        || binding
            .get("subjects")
            .and_then(Value::as_array)
            .is_none_or(|subjects| {
                subjects.len() != 1
                    || subjects[0]
                        .as_str()
                        .is_none_or(|subject| subject.is_empty() || subject.chars().count() > 512)
            })
    {
        return Err("GitHub requires a static bearer credential binding".into());
    }
    Ok(())
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route
        .get("adapter")
        .and_then(|value| value.get("config"))
        .ok_or("GitHub adapter missing")?;
    validate_config(
        config,
        route
            .get("constraints")
            .and_then(Value::as_array)
            .ok_or("GitHub constraints missing")?,
    )?;
    let matcher = route
        .get("match")
        .and_then(Value::as_object)
        .ok_or("GitHub match missing")?;
    let methods = if config["operationBundle"] == WRITE {
        json!(["GET", "POST"])
    } else {
        json!(["GET"])
    };
    if matcher.get("scheme") != Some(&json!("https"))
        || matcher.get("host") != Some(&json!("api.github.com"))
        || matcher.get("port") != Some(&json!(443))
        || matcher.get("methods") != Some(&methods)
        || matcher.get("paths") != Some(&json!(paths(config)?))
        || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader")
            != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
    {
        return Err(
            "GitHub route requires its exact repository, methods and replacement contract".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    let actual_paths = route
        .paths
        .iter()
        .map(|path| {
            path.segments
                .iter()
                .map(|segment| match segment {
                    PathSegment::Literal(value) => Some(value.clone()),
                    PathSegment::Variable(value) => Some(format!("{{{value}}}")),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .map(|parts| format!("/{}", parts.join("/")))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("GitHub wildcard path refused")?;
    let methods = if route.adapter_config["operationBundle"] == WRITE {
        HashSet::from(["GET".to_string(), "POST".to_string()])
    } else {
        HashSet::from(["GET".to_string()])
    };
    if !selected(route)
        || route.scheme != "https"
        || route.host != "api.github.com"
        || route.port != 443
        || route.methods != methods
        || actual_paths != paths(&route.adapter_config)?
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header
            != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != ["accept-encoding"]
        || route.jit != json!({})
        || route.response_observation.is_some()
    {
        return Err("GitHub runtime route differs from signed profile".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resource {
    Issues,
    Issue,
    Comments(String),
    Comment,
}

fn target(url: &Url) -> Result<(&str, &str, Resource, String), String> {
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("GitHub target authority invalid".into());
    }
    let parts = url.path().split('/').collect::<Vec<_>>();
    if parts.len() < 5
        || parts[0] != ""
        || parts[1] != "repos"
        || !owner(parts[2])
        || !repository_name(parts[3])
        || parts[4] != "issues"
    {
        return Err("GitHub named repository target required".into());
    }
    let resource = match parts.as_slice() {
        [_, _, _, _, _] => Resource::Issues,
        [_, _, _, _, _, number] if positive(number, 9_007_199_254_740_991) => Resource::Issue,
        [_, _, _, _, _, number, "comments"] if positive(number, 9_007_199_254_740_991) => {
            Resource::Comments((*number).to_string())
        }
        [_, _, _, _, _, "comments", number] if positive(number, 9_007_199_254_740_991) => {
            Resource::Comment
        }
        _ => return Err("GitHub resource unsupported".into()),
    };
    Ok((
        parts[2],
        parts[3],
        resource,
        format!("/{}", parts[4..].join("/")),
    ))
}

fn since(value: &str) -> bool {
    if value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !matches!(bytes[10], b'T' | b't')
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .any(|index| !bytes[*index].is_ascii_digit())
        || &value[0..4] == "0000"
        || &value[17..19] > "59"
    {
        return false;
    }
    let tail = &value[19..];
    let zone = if let Some(fraction) = tail.strip_prefix('.') {
        let count = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=9).contains(&count) {
            return false;
        }
        &fraction[count..]
    } else {
        tail
    };
    if !(matches!(zone, "Z" | "z")
        || zone.len() == 6
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[3] == b':'
            && [1usize, 2, 4, 5]
                .iter()
                .all(|i| zone.as_bytes()[*i].is_ascii_digit())
            && &zone[1..3] < "24"
            && &zone[4..6] < "60")
    {
        return false;
    }
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

fn query(url: &Url, resource: &Resource, method: &str) -> Result<(), String> {
    let parsed = crate::request_query_compat::parse_query(url.query())
        .map_err(|_| "GitHub query wire invalid")?;
    let mut names = HashSet::new();
    for (name, value) in &parsed.pairs {
        let allowed = method == "GET"
            && match resource {
                Resource::Issues => QUERY.contains(&name.as_str()),
                Resource::Comments(_) => ["page", "per_page", "since"].contains(&name.as_str()),
                _ => false,
            };
        let valid = match name.as_str() {
            "page" => positive(value, 1_000_000),
            "per_page" => positive(value, 100),
            "state" => matches!(value.as_str(), "open" | "closed" | "all"),
            "sort" => matches!(value.as_str(), "created" | "updated" | "comments"),
            "direction" => matches!(value.as_str(), "asc" | "desc"),
            "since" => since(value),
            "milestone" => {
                matches!(value.as_str(), "*" | "none") || positive(value, 9_007_199_254_740_991)
            }
            "assignee" => matches!(value.as_str(), "*" | "none") || owner(value),
            "creator" | "mentioned" => owner(value),
            "labels" => (1..=1024).contains(&value.len()) && !value.chars().any(|c| c.is_control()),
            _ => false,
        };
        if !allowed || !valid || !names.insert(name) {
            return Err("GitHub query semantics invalid".into());
        }
    }
    Ok(())
}

pub(crate) fn parse_target(
    method: &str,
    raw: &str,
) -> Result<(crate::RequestPathValidation, Url), String> {
    if !matches!(method, "GET" | "POST")
        || raw.len() > 16384
        || !raw.starts_with("https://api.github.com/")
    {
        return Err("GitHub method or origin unsupported".into());
    }
    let (base, wire) = raw
        .split_once('?')
        .map_or((raw, None), |(base, query)| (base, Some(query)));
    let (path, base_url) = crate::parse_validated_absolute_target(base)?;
    let (_, _, resource, _) = target(&base_url)?;
    if method == "POST" && !matches!(resource, Resource::Issues | Resource::Comments(_)) {
        return Err("GitHub write target unsupported".into());
    }
    let url = Url::parse(raw).map_err(|_| "GitHub URL invalid")?;
    if url.query() != wire
        || url.path() != base_url.path()
        || url.scheme() != base_url.scheme()
        || url.host_str() != base_url.host_str()
        || url.port_or_known_default() != base_url.port_or_known_default()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("GitHub URL parser changed target".into());
    }
    query(&url, &resource, method)?;
    Ok((path, url))
}

pub(crate) fn admit_target(route: &Route, method: &str, url: &Url) -> Result<Resource, String> {
    validate_route(route)?;
    let (_, parsed) = parse_target(method, url.as_str())?;
    if parsed != *url {
        return Err("GitHub target changed".into());
    }
    let (actual_owner, actual_name, resource, _) = target(url)?;
    if (actual_owner, actual_name) != repository(&route.adapter_config)?
        || method == "POST" && route.adapter_config["operationBundle"] != WRITE
    {
        return Err("GitHub repository or write permission denied".into());
    }
    Ok(resource)
}

pub(crate) fn validate_request(
    req: &DecisionRequest,
    headers: &BTreeMap<String, String>,
    url: &Url,
    route: &Route,
) -> Result<(), Value> {
    let resource = admit_target(route, &req.method, url)
        .map_err(|_| json!({"error":"github_request_denied","status_code":403}))?;
    if headers
        .get("accept-language")
        .is_some_and(|value| value != "*")
        || headers
            .get("sec-fetch-mode")
            .is_some_and(|value| value != "cors")
        || headers.get("accept").is_some_and(|value| {
            ![
                "application/vnd.github.v3+json",
                "application/vnd.github+json",
                "application/json",
                "*/*",
            ]
            .contains(&value.as_str())
        })
        || headers.get("x-github-api-version").is_some_and(|value| {
            value.len() != 10
                || value.starts_with("0000-")
                || chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                    .ok()
                    .is_none_or(|date| date.format("%Y-%m-%d").to_string() != *value)
        })
        || headers.contains_key("accept-encoding")
        || req.method == "GET" && !req.body.is_empty()
    {
        return Err(json!({"error":"github_request_profile_denied","status_code":403}));
    }
    if req.method == "POST" {
        if req.body.len() > 65536 {
            return Err(json!({"error":"github_request_body_invalid","status_code":400}));
        }
        crate::buffered_request::validate_container_depth(req.body.as_bytes())
            .map_err(|()| json!({"error":"github_request_json_invalid","status_code":400}))?;
        let value = crate::sensitive_json_value_from_str(&req.body)
            .map_err(|_| json!({"error":"github_request_json_invalid","status_code":400}))?;
        let field = if resource == Resource::Issues {
            "title"
        } else {
            "body"
        };
        if value.as_object().is_none()
            || value
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|text| text.is_empty() || field == "title" && text.len() > 1024)
        {
            return Err(json!({"error":"github_request_body_invalid","status_code":400}));
        }
    }
    Ok(())
}

pub(crate) fn canonical_discard_headers(
    canonical: &Value,
    route: &Route,
) -> Result<Vec<String>, String> {
    validate_route(route)?;
    let outer = canonical
        .as_object()
        .ok_or("GitHub canonical request invalid")?;
    let request = canonical
        .get("request")
        .and_then(Value::as_object)
        .ok_or("GitHub canonical request missing")?;
    if !crate::object_has_exact_fields(outer, crate::CANONICAL_REQUEST_TOP_LEVEL_FIELDS)
        || canonical.get("v") != Some(&json!(3))
        || !exact(
            request,
            &[
                "method",
                "scheme",
                "authority",
                "path",
                "query",
                "headers",
                "body_sha256",
                "discard_headers",
                "query_mode",
                "query_wire",
            ],
        )
        || request.get("query_mode") != Some(&json!(MODE))
        || request.get("discard_headers") != Some(&json!(DISCARD))
        || request.get("scheme") != Some(&json!("https"))
        || request.get("authority") != Some(&json!("api.github.com"))
        || canonical.get("operation")
            != Some(&json!({"operation":operation(&route.adapter_config)?}))
    {
        return Err("GitHub canonical contract mismatch".into());
    }
    let wire = match request.get("query_wire") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err("GitHub canonical query invalid".into()),
    };
    let path = request
        .get("path")
        .and_then(Value::as_str)
        .ok_or("GitHub canonical path missing")?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or("GitHub canonical method missing")?;
    let raw = format!(
        "https://api.github.com{path}{}",
        wire.map(|query| format!("?{query}")).unwrap_or_default()
    );
    let (_, url) = parse_target(method, &raw)?;
    admit_target(route, method, &url)?;
    let parsed = crate::request_query_compat::parse_query(wire)
        .map_err(|_| "GitHub canonical query invalid")?;
    if request.get("query") != Some(&json!(parsed.pairs)) {
        return Err("GitHub canonical query pairs changed".into());
    }
    Ok(route.discard_headers.clone())
}

pub(crate) fn validate_canonical_url(
    canonical: &Value,
    route: &Route,
    method: &str,
    url: &Url,
) -> Result<(), String> {
    canonical_discard_headers(canonical, route)?;
    admit_target(route, method, url)?;
    let request = &canonical["request"];
    if request["method"] != json!(method)
        || request["scheme"] != json!(url.scheme())
        || request["authority"] != json!(crate::canonical_authority(url))
        || request["path"] != json!(url.path())
        || request["query_wire"] != json!(url.query())
        || request["query"] != json!(crate::query_pairs(url))
    {
        return Err("GitHub dispatch URL differs from commitment".into());
    }
    Ok(())
}

pub(crate) fn normalize_link(value: &str, current: &Url, route: &Route) -> Result<String, String> {
    let resource = admit_target(route, "GET", current)?;
    if !matches!(resource, Resource::Issues | Resource::Comments(_))
        || value.is_empty()
        || value.len() > 4096
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err("GitHub Link invalid".into());
    }
    let (owner, name, _, suffix) = target(current)?;
    let mut relations = HashSet::new();
    let mut links = Vec::new();
    // GitHub emits a closed, comma-separated list of <URL>; rel="name".
    // A literal comma inside the URL is data, so split only after its closing >.
    let mut rest = value;
    loop {
        let trimmed = rest.trim_start_matches(' ');
        let body = trimmed
            .strip_prefix('<')
            .ok_or("GitHub Link syntax invalid")?;
        let (raw, after) = body.split_once('>').ok_or("GitHub Link syntax invalid")?;
        if !raw.starts_with("https://api.github.com/") {
            return Err("GitHub Link origin invalid".into());
        }
        let rel = after
            .strip_prefix(';')
            .map(|value| value.trim_start_matches(' '))
            .and_then(|value| value.strip_prefix("rel=\""))
            .ok_or("GitHub Link relation invalid")?;
        let (relation, tail) = rel.split_once('"').ok_or("GitHub Link relation invalid")?;
        if !["next", "prev", "first", "last"].contains(&relation)
            || !relations.insert(relation)
            || links.len() >= 4
        {
            return Err("GitHub Link relation invalid".into());
        }
        let (base, wire) = raw
            .split_once('?')
            .map_or((raw, None), |(base, query)| (base, Some(query)));
        let (_, base_url) = crate::parse_validated_absolute_target(base)?;
        if base_url.scheme() != "https"
            || base_url.host_str() != Some("api.github.com")
            || base_url.port_or_known_default() != Some(443)
        {
            return Err("GitHub Link authority denied".into());
        }
        let expected = format!("/repos/{owner}/{name}{suffix}");
        if base_url.path() != expected {
            let numeric = base_url
                .path()
                .strip_prefix("/repositories/")
                .ok_or("GitHub Link repository denied")?;
            let (id, actual_suffix) = numeric
                .split_once('/')
                .ok_or("GitHub Link resource invalid")?;
            if !(1..=20).contains(&id.len())
                || id.starts_with('0')
                || !id.bytes().all(|byte| byte.is_ascii_digit())
                || format!("/{actual_suffix}") != suffix
            {
                return Err("GitHub Link resource denied".into());
            }
        }
        let normalized = format!(
            "https://api.github.com{expected}{}",
            wire.map(|query| format!("?{query}")).unwrap_or_default()
        );
        let (_, url) = parse_target("GET", &normalized)?;
        if admit_target(route, "GET", &url)? != resource {
            return Err("GitHub Link operation differs".into());
        }
        if !url.query_pairs().any(|(name, _)| name == "page") {
            return Err("GitHub Link page missing".into());
        }
        links.push(format!("<{normalized}>; rel=\"{relation}\""));
        let tail = tail.trim_start_matches(' ');
        if tail.is_empty() {
            break;
        }
        rest = tail.strip_prefix(',').ok_or("GitHub Link syntax invalid")?;
        if rest.is_empty() {
            return Err("GitHub Link syntax invalid".into());
        }
    }
    let result = links.join(", ");
    if result.len() > 4096 {
        return Err("GitHub Link normalized limit exceeded".into());
    }
    Ok(result)
}

/// Called only after V2 has bounded and scanned every physical upstream header.
pub(crate) fn prepare_response_headers(
    headers: &mut HeaderMap,
    current: &Url,
    method: &str,
    route: &Route,
    guard: &crate::ResponseSecretGuard,
) -> Result<(), Value> {
    if let Some(value) = headers.get("link") {
        if method != "GET" || headers.get_all("link").iter().count() != 1 {
            return Err(json!({"error":"github_response_link_denied"}));
        }
        let normalized = value
            .to_str()
            .ok()
            .and_then(|value| normalize_link(value, current, route).ok())
            .ok_or_else(|| json!({"error":"github_response_link_denied"}))?;
        if guard.detects(normalized.as_bytes()) {
            return Err(json!({"error":"response_credential_reflection"}));
        }
        headers.insert(
            "link",
            HeaderValue::from_str(&normalized)
                .map_err(|_| json!({"error":"github_response_link_denied"}))?,
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "github_issues_tests.rs"]
mod tests;
