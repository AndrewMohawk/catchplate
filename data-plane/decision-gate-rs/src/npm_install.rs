//! Closed registry installation operations. Gzip inspection never extracts an
//! archive, follows a metadata URL, or supplies authority to another request.
use crate::{DecisionRequest, PathSegment, ProviderRequestProfile, ResponseSecretGuard, Route,
    RouteMatch, SensitiveResponseBytes};
use flate2::bufread::GzDecoder;
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use zeroize::Zeroizing;

pub(crate) const ADAPTER: &str = "npm.install.v1";
pub(crate) const METADATA_MODE: &str = "npmInstallMetadataJsonV1";
pub(crate) const TARBALL_MODE: &str = "npmInstallTarballV1";
pub(crate) const AUDIT_MODE: &str = "npmInstallAuditJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "npmInstallContentV1";
pub(crate) const HOST: &str = crate::npm_metadata::HOST;
pub(crate) const PLACEHOLDER: &str = crate::npm_metadata::PLACEHOLDER;
pub(crate) const AUDIT_PATH: &str = "/-/npm/v1/security/advisories/bulk";
pub(crate) const DISCARD: &[&str] = crate::npm_metadata::DISCARD;
pub(crate) const STATUSES: &[u16] = crate::npm_metadata::STATUSES;
pub(crate) const AUDIT_REQUEST_BYTES: u64 = 65_536;
pub(crate) const AUDIT_DECODED_BYTES: usize = 262_144;
pub(crate) const TARBALL_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const TARBALL_DECODED_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const JSON_BYTES: u64 = 1_048_576;
pub(crate) const ERROR_BYTES: u64 = 65_536;
const JSON: &[&str] = &["application/json"];
const OCTET: &[&str] = &["application/octet-stream"];
const TARBALL_HEADERS: &[&str] = &["accept", "npm-auth-type", "npm-command", "npm-in-ci",
    "npm-scope", "pacote-integrity", "pacote-pkg-id", "pacote-req-type", "pacote-version", "user-agent"];
const AUDIT_HEADERS: &[&str] = &["accept", "content-type", "npm-auth-type", "npm-command",
    "npm-in-ci", "npm-scope", "user-agent"];

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn refused(error: &str) -> Value { json!({"error":error,"status_code":403}) }

fn mode(config: &Value) -> Result<&str, String> {
    match config["mode"].as_str() {
        Some(value @ ("metadata" | "tarball" | "audit")) => Ok(value),
        _ => Err("npm install mode refused".into()),
    }
}

pub(crate) fn gate_capability() -> Value {
    json!({"schema":"serverware.operatorNpmInstallGate/v1","adapter":ADAPTER,
        "modes":["metadata","tarball","audit"]})
}

pub(crate) fn supported_response_mode(value: &str) -> bool {
    matches!(value, METADATA_MODE | TARBALL_MODE | AUDIT_MODE)
}

pub(crate) fn route_paths(mode: &str) -> Result<Vec<&'static str>, String> {
    match mode {
        "metadata" => Ok(vec!["/{package}"]),
        "tarball" => Ok(vec!["/{package}/-/{filename}", "/{scope}/{package}/-/{filename}"]),
        "audit" => Ok(vec![AUDIT_PATH]),
        _ => Err("npm install mode refused".into()),
    }
}

pub(crate) fn request_profile(mode: &str) -> Result<ProviderRequestProfile, String> {
    let (headers, media, maximum) = match mode {
        "metadata" => (crate::npm_metadata::HEADERS, &[][..], 0),
        "tarball" => (TARBALL_HEADERS, &[][..], 0),
        "audit" => (AUDIT_HEADERS, JSON, AUDIT_REQUEST_BYTES),
        _ => return Err("npm install mode refused".into()),
    };
    Ok(ProviderRequestProfile { allowed_headers: headers, allowed_query_keys: &[],
        allowed_media_types: media, required_discard_headers: DISCARD, max_body_bytes: maximum })
}

pub(crate) fn request_config(mode: &str) -> Result<Value, String> {
    let profile = request_profile(mode)?;
    Ok(json!({"allowedHeaders":profile.allowed_headers,"discardHeaders":DISCARD,
        "allowedQueryKeys":[],"allowedMediaTypes":profile.allowed_media_types,
        "maxBodyBytes":profile.max_body_bytes,"valueRules":[]}))
}

pub(crate) fn response_profile(mode: &str, error: bool) -> Result<Value, String> {
    let (response_mode, types, maximum) = match mode {
        "metadata" => (METADATA_MODE, crate::npm_metadata::CONTENT_TYPES, JSON_BYTES),
        "tarball" => (TARBALL_MODE, if error { JSON } else { OCTET }, TARBALL_BYTES),
        "audit" => (AUDIT_MODE, JSON, JSON_BYTES),
        _ => return Err("npm install mode refused".into()),
    };
    let mut profile = json!({"mode":response_mode,"maxBodyBytes":if error { ERROR_BYTES } else { maximum },
        "contentTypes":types,"allowedHeaders":[]});
    if error { profile["onInvalid"] = json!("block"); }
    else { profile["error"] = response_profile(mode, true)?; }
    Ok(profile)
}

pub(crate) fn envelope(mode: &str, id: &str) -> Result<Value, String> {
    let types: &[&str] = match mode {
        "metadata" => crate::npm_metadata::CONTENT_TYPES,
        "tarball" => &["application/json", "application/octet-stream"],
        "audit" => JSON,
        _ => return Err("npm install mode refused".into()),
    };
    Ok(json!({"id":id,"type":"responseEnvelope","phase":"response","statusCodes":STATUSES,
        "contentTypePolicy":CONTENT_TYPE_POLICY,"bodyPresence":"required","contentTypes":types,
        "allowedResponseHeaderNames":[],"responseHeaderRules":[],
        "unlistedHeaderPolicy":crate::response_metadata::POLICY}))
}

pub(crate) fn validate_envelope(response_mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    let mode = match response_mode {
        Some(METADATA_MODE) => "metadata", Some(TARBALL_MODE) => "tarball", Some(AUDIT_MODE) => "audit",
        _ => return Err("npm install response mode refused".into()),
    };
    if constraints.len() != 1 { return Err("npm install requires exactly one envelope".into()); }
    let id = constraints[0]["id"].as_str().filter(|id| !id.is_empty())
        .ok_or("npm install envelope ID missing")?;
    if constraints[0] != envelope(mode, id)? { return Err("npm install envelope differs".into()); }
    crate::validate_response_envelope_constraint(ADAPTER, id,
        constraints[0].as_object().ok_or("npm install envelope missing")?)
}

pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let object = config.as_object().ok_or("npm install config missing")?;
    let mode = mode(config)?;
    if !exact(object, &["credentialBinding", "packages", "mode", "request", "response"])
        || config["request"] != request_config(mode)? || config["response"] != response_profile(mode, false)? {
        return Err("npm install config differs from its closed contract".into());
    }
    // Reuse only the unchanged binding/name validator; this does not reuse an
    // old grant or admit tarballs/audit to npm.metadata.v1.
    crate::npm_metadata::validate_config(&json!({"credentialBinding":config["credentialBinding"],
        "packages":config["packages"],"request":crate::npm_metadata::request_config(),
        "response":crate::npm_metadata::response_profile(false)}),
        &[crate::npm_metadata::envelope("install-binding-check")])?;
    validate_envelope(config["response"]["mode"].as_str(), constraints)
}

pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route.get("adapter").and_then(|value| value.get("config"))
        .ok_or("npm install adapter missing")?;
    validate_config(config, route.get("constraints").and_then(Value::as_array)
        .ok_or("npm install constraints missing")?)?;
    let mode = mode(config)?;
    let matcher = route.get("match").and_then(Value::as_object).ok_or("npm install match missing")?;
    if route.get("adapter").and_then(|value| value.get("type")).and_then(Value::as_str) != Some(ADAPTER)
        || matcher.get("scheme") != Some(&json!("https")) || matcher.get("host") != Some(&json!(HOST))
        || matcher.get("port") != Some(&json!(443))
        || matcher.get("methods") != Some(&json!([if mode == "audit" { "POST" } else { "GET" }]))
        || matcher.get("paths") != Some(&json!(route_paths(mode)?)) || route.contains_key("jit")
        || route.contains_key("responseObservation")
        || route.get("credentialHeader") != Some(&json!({"mode":"replaceExact","expectedValue":PLACEHOLDER})) {
        return Err("npm install route authority differs".into());
    }
    Ok(())
}

fn exact_path(actual: &crate::PathTemplate, expected: &str) -> bool {
    let segments = expected.trim_start_matches('/').split('/').collect::<Vec<_>>();
    actual.segments.len() == segments.len() && actual.segments.iter().zip(segments).all(|(actual, expected)|
        match actual {
            PathSegment::Literal(value) => value == expected,
            PathSegment::Variable(value) => expected == format!("{{{value}}}"),
            _ => false,
        })
}

pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    let mode = mode(&route.adapter_config)?;
    let paths = route_paths(mode)?;
    if route.adapter_type != ADAPTER || route.scheme != "https" || route.host != HOST || route.port != 443
        || route.methods != HashSet::from([if mode == "audit" { "POST".into() } else { "GET".into() }])
        || route.paths.len() != paths.len()
        || !route.paths.iter().zip(paths).all(|(actual, expected)| exact_path(actual, expected))
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header != Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}))
        || route.discard_headers != DISCARD.iter().map(|value| value.to_string()).collect::<Vec<_>>()
        || route.jit != json!({}) || route.response_observation.is_some() {
        return Err("npm install runtime authority differs".into());
    }
    Ok(())
}

fn target(url: &Url, mode: &str) -> Result<(String, Option<String>), Value> {
    let bad = || refused("npm_install_target_denied");
    if url.scheme() != "https" || url.host_str() != Some(HOST) || url.port_or_known_default() != Some(443)
        || !url.username().is_empty() || url.password().is_some() || url.query().is_some()
        || url.fragment().is_some() || crate::validate_canonical_raw_path(url.path()).is_err() {
        return Err(bad());
    }
    match mode {
        "metadata" => {
            let raw = url.path().strip_prefix('/').filter(|value| !value.contains('/')).ok_or_else(bad)?;
            let package = raw.replace("%2f", "/");
            if !crate::npm_metadata::package_name(&package) || raw != package.replace('/', "%2f") {
                return Err(bad());
            }
            Ok((package, None))
        }
        "tarball" => {
            if url.path().len() > 512 || url.path().contains('%') { return Err(bad()); }
            let segments = url.path().split('/').collect::<Vec<_>>();
            let (package, basename, filename) = match segments.as_slice() {
                ["", name, "-", filename] if !name.starts_with('@') => (name.to_string(), *name, *filename),
                ["", scope, name, "-", filename] if scope.starts_with('@') =>
                    (format!("{scope}/{name}"), *name, *filename),
                _ => return Err(bad()),
            };
            if !crate::npm_metadata::package_name(&package) { return Err(bad()); }
            let version = filename.strip_prefix(&format!("{basename}-")).and_then(|value| value.strip_suffix(".tgz"))
                .filter(|value| crate::npm_publish::version(value)).ok_or_else(bad)?;
            Ok((package, Some(version.to_string())))
        }
        "audit" if url.path() == AUDIT_PATH => Ok((String::new(), None)),
        _ => Err(bad()),
    }
}

fn selected(config: &Value, name: &str) -> bool {
    config["packages"].as_array().is_some_and(|packages|
        packages.iter().any(|package| package.as_str() == Some(name)))
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Result<Option<&'a str>, Value> {
    let mut matches = headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = matches.next().map(|(_, value)| value.as_str());
    if matches.next().is_some() { return Err(refused("npm_install_header_ambiguous")); }
    Ok(value)
}

pub(crate) fn admit_audit_head(route: &Route, method: &str, url: &Url,
    headers: &BTreeMap<String, String>, content_length: usize) -> Result<(), Value> {
    validate_route(route).map_err(|_| refused("npm_install_profile_invalid"))?;
    target(url, "audit")?;
    if mode(&route.adapter_config).ok() != Some("audit") || method != "POST"
        || !(1..=AUDIT_REQUEST_BYTES as usize).contains(&content_length)
        || header(headers, "transfer-encoding")?.is_some()
        || header(headers, "content-encoding")? != Some("gzip")
        || header(headers, "content-length")? != Some(content_length.to_string().as_str())
        || header(headers, "content-type")?.is_none_or(|value|
            response_content_type(value) != Some("application/json")) {
        return Err(refused("npm_install_audit_framing_denied"));
    }
    Ok(())
}

/// BufRead's single-member decoder leaves the exact unconsumed suffix visible.
/// All output, including a failing decode's partial output, has a zeroizing owner.
fn bounded_gzip(raw: &[u8], compressed_limit: u64, decoded_limit: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    if raw.is_empty() || raw.len() as u64 > compressed_limit { return Err(()); }
    let mut decoder = GzDecoder::new(raw);
    let mut output = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let count = decoder.read(&mut chunk[..]).map_err(|_| ())?;
        if count == 0 { break; }
        if count > decoded_limit.saturating_sub(output.len()) { return Err(()); }
        output.extend_from_slice(&chunk[..count]);
    }
    if output.is_empty() || !decoder.get_ref().is_empty() { return Err(()); }
    Ok(output)
}

fn audit_map(document: &Value) -> Result<Map<String, Value>, Value> {
    let bad = || refused("npm_install_audit_payload_denied");
    let object = document.as_object().filter(|value| (1..=64).contains(&value.len())).ok_or_else(bad)?;
    let mut normalized = Map::new();
    for (package, versions) in object {
        if !crate::npm_metadata::package_name(package) { return Err(bad()); }
        let versions = versions.as_array().filter(|value| (1..=128).contains(&value.len())).ok_or_else(bad)?;
        let mut values = versions.iter().map(|value| value.as_str().filter(|value| crate::npm_publish::version(value))
            .ok_or_else(bad)).collect::<Result<Vec<_>, _>>()?;
        values.sort_unstable();
        if values.windows(2).any(|pair| pair[0] == pair[1]) { return Err(bad()); }
        normalized.insert(package.clone(), json!(values));
    }
    Ok(normalized)
}

/// A serde-skipped ingress owner, never a deserializable decoded-body assertion.
#[derive(Clone)]
pub(crate) struct AuditBody {
    wire: Zeroizing<Vec<u8>>,
    decoded: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for AuditBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditBody([redacted])")
    }
}

impl AuditBody {
    pub(crate) fn from_wire(raw: &[u8]) -> Result<Self, Value> {
        let decoded = bounded_gzip(raw, AUDIT_REQUEST_BYTES, AUDIT_DECODED_BYTES)
            .map_err(|_| refused("npm_install_audit_gzip_denied"))?;
        crate::buffered_request::validate_container_depth(&decoded)
            .map_err(|_| refused("npm_install_audit_payload_denied"))?;
        let document = crate::sensitive_json_value_from_slice(&decoded)
            .map_err(|_| refused("npm_install_audit_payload_denied"))?;
        audit_map(&document)?;
        Ok(Self { wire: Zeroizing::new(raw.to_vec()), decoded })
    }
    pub(crate) fn wire(&self) -> &[u8] { &self.wire }
    pub(crate) fn decoded_text(&self) -> &str {
        // from_wire admitted strict JSON UTF8, and neither buffer is mutable outside this module.
        std::str::from_utf8(&self.decoded).expect("admitted npm audit JSON UTF8")
    }
    pub(crate) fn matches_wire(&self, raw: &[u8]) -> bool { self.wire.as_slice() == raw }
    fn operation(&self, config: &Value) -> Result<Value, Value> {
        let document = crate::sensitive_json_value_from_slice(&self.decoded)
            .map_err(|_| refused("npm_install_audit_payload_denied"))?;
        let versions = audit_map(&document)?;
        if versions.keys().any(|package| !selected(config, package)) {
            return Err(refused("npm_install_package_denied"));
        }
        Ok(json!({"operation":"npm.install.audit.read", "packages":versions.keys().collect::<Vec<_>>(),
            "packageVersions":versions}))
    }
}

pub(crate) fn validate_request(req: &DecisionRequest, url: &Url, route: &Route) -> Result<Value, Value> {
    validate_route(route).map_err(|_| json!({"error":"npm_install_profile_invalid","status_code":500}))?;
    let mode = mode(&route.adapter_config).map_err(|_| refused("npm_install_profile_invalid"))?;
    if req.url != format!("https://{HOST}{}", url.path()) {
        return Err(refused("npm_install_target_denied"));
    }
    let (package, version) = target(url, mode)?;
    if mode == "audit" {
        let owner = req.npm_install_audit_body.as_ref().ok_or_else(|| refused("npm_install_audit_ingress_required"))?;
        admit_audit_head(route, &req.method, url, &req.headers, owner.wire.len())?;
        if req.body != owner.decoded_text() || req.body_sha256.as_deref() != Some(crate::sha256_prefixed(owner.wire()).as_str())
            || req.forwarded_body_length != Some(owner.wire.len() as u64)
            || req.forwarded_body_utf8_valid != Some(std::str::from_utf8(owner.wire()).is_ok()) {
            return Err(refused("npm_install_audit_wire_binding_denied"));
        }
        return owner.operation(&route.adapter_config);
    }
    if req.method != "GET" || !req.body.is_empty() || req.forwarded_body_length.is_some_and(|value| value != 0)
        || req.npm_install_audit_body.is_some() || header(&req.headers, "transfer-encoding")?.is_some()
        || header(&req.headers, "content-type")?.is_some()
        || header(&req.headers, "content-encoding")?.is_some_and(|value| value != "identity") {
        return Err(refused("npm_install_request_denied"));
    }
    if !selected(&route.adapter_config, &package) { return Err(refused("npm_install_package_denied")); }
    Ok(if mode == "metadata" { json!({"operation":"npm.install.metadata.read","package":package}) }
        else { json!({"operation":"npm.install.tarball.read","package":package,"version":version}) })
}

pub(crate) fn normalize_request(req: &DecisionRequest, url: &Url, matched: &RouteMatch<'_>) -> Result<(Value, Value), Value> {
    let operation = validate_request(req, url, matched.route)?;
    if !matched.route.paths.iter().any(|path| path.matches_canonical(url.path()).as_ref() == Some(&matched.params)) {
        return Err(refused("npm_install_capture_denied"));
    }
    Ok((operation, json!({})))
}

pub(crate) fn response_content_type(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("application/octet-stream") { Some("application/octet-stream") }
    else { crate::npm_metadata::response_content_type(value) }
}

pub(crate) fn is_content_type(value: &str) -> bool { response_content_type(value).is_some() }

pub(crate) fn inspect_response(url: &Url, status: StatusCode, content_type: Option<&str>, profile: &Value,
    body: SensitiveResponseBytes, guard: &ResponseSecretGuard, config: &Value, operation: &Value,
) -> Result<SensitiveResponseBytes, Value> {
    let invalid = || json!({"error":"npm_install_response_contract_invalid"});
    let mode = mode(config).map_err(|_| invalid())?;
    validate_config(config, &[envelope(mode, "response-check").map_err(|_| invalid())?]).map_err(|_| invalid())?;
    let (package, version) = target(url, mode)?;
    let error = status.is_client_error() || status.is_server_error();
    let expected = response_profile(mode, error).map_err(|_| invalid())?;
    let media = content_type.and_then(response_content_type).ok_or_else(invalid)?;
    if !STATUSES.contains(&status.as_u16()) || profile != &expected
        || !expected["contentTypes"].as_array().is_some_and(|types| types.iter().any(|value| value == media)) {
        return Err(invalid());
    }
    let requested_packages = if mode == "audit" {
        let normalized = audit_map(&operation["packageVersions"]).map_err(|_| invalid())?;
        let expected_operation = json!({"operation":"npm.install.audit.read",
            "packages":normalized.keys().collect::<Vec<_>>(),"packageVersions":normalized});
        if operation != &expected_operation || normalized.keys().any(|package| !selected(config, package)) {
            return Err(invalid());
        }
        normalized.keys().cloned().collect::<HashSet<_>>()
    } else {
        let expected_operation = if mode == "metadata" {
            json!({"operation":"npm.install.metadata.read","package":package})
        } else { json!({"operation":"npm.install.tarball.read","package":package,"version":version}) };
        if operation != &expected_operation || !selected(config, &package) { return Err(invalid()); }
        HashSet::new()
    };
    if mode == "tarball" && !error {
        if guard.detects(&body) { return Err(json!({"error":"response_credential_reflection"})); }
        let decoded = bounded_gzip(&body, TARBALL_BYTES, TARBALL_DECODED_BYTES)
            .map_err(|_| json!({"error":"npm_install_tarball_gzip_denied"}))?;
        if guard.detects(&decoded) { return Err(json!({"error":"response_credential_reflection"})); }
        return Ok(body);
    }
    let (body, document) = crate::buffered_response::inspect_json_bytes(ADAPTER, body,
        if error { ERROR_BYTES } else { JSON_BYTES }, guard, true)?;
    let object = document.as_object().ok_or_else(invalid)?;
    if !error && mode == "metadata" && document["name"].as_str() != Some(package.as_str()) {
        return Err(json!({"error":"npm_install_response_package_mismatch"}));
    }
    if !error && mode == "audit" && object.iter().any(|(package, advisories)| !requested_packages.contains(package)
        || advisories.as_array().is_none_or(|items| items.iter().any(|value| !value.is_object()))) {
        return Err(json!({"error":"npm_install_audit_response_scope_denied"}));
    }
    Ok(body)
}

#[cfg(test)]
#[path = "npm_install_tests.rs"]
mod tests;
