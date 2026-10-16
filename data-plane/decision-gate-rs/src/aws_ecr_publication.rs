//! Closed ordinary-host ECR publication adapter. Public SDK signatures are an
//! admission format, never authentication or authorization. The control plane
//! owns verified artifacts, publication approval/state and exact-request signing.
use crate::{
    DecisionRequest, ProviderRequestProfile, ResponseSecretGuard, Route, RouteMatch,
    SensitiveResponseBytes,
};
use base64::{engine::general_purpose, Engine};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use time::{Date, Month, PrimitiveDateTime, Time};

pub(crate) const ADAPTER: &str = "aws.ecr.publish.v1";
pub(crate) const OPERATION: &str = "aws.ecr.publish";
pub(crate) const MODE: &str = "awsEcrPublicationJsonV1";
pub(crate) const CONTENT_TYPE_POLICY: &str = "awsEcrPublicationJsonUtf8V1";
pub(crate) const MEDIA: &str = "application/x-amz-json-1.1";
pub(crate) const HEADERS: &[&str] = &[
    "amz-sdk-invocation-id",
    "amz-sdk-request",
    "authorization",
    "user-agent",
    "x-amz-date",
    "x-amz-target",
];
pub(crate) const DISCARD: &[&str] = &["accept-encoding"];
pub(crate) const CONTENT_TYPES: &[&str] = &[MEDIA];
pub(crate) const ERROR_CONTENT_TYPES: &[&str] = &[MEDIA, "application/json"];
pub(crate) const STATUSES: &[u16] = &[200, 400, 401, 403, 404, 429, 500, 502, 503, 504];
pub(crate) const REQUEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const RESPONSE_BYTES: u64 = 25 * 1024 * 1024;
pub(crate) const ERROR_BYTES: u64 = 65_536;
pub(crate) const PART_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const DUMMY_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub(crate) const DUMMY_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const TARGET_PREFIX: &str = "AmazonEC2ContainerRegistry_V20150921.";
const PUBLICATION_PREFIX: &str = "ServerwarePublication/";

fn exact(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}
fn fields(object: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}
pub(crate) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn upload_id(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|v| uuid(&v.to_ascii_lowercase()))
}
fn region(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && value.len() <= 63
        && !value.starts_with("cn-")
        && parts[0].len() == 2
        && parts[0].bytes().all(|b| b.is_ascii_lowercase())
        && !parts[1].is_empty()
        && parts[1].bytes().all(|b| b.is_ascii_lowercase())
        && (1..=2).contains(&parts[2].len())
        && !parts[2].starts_with('0')
        && parts[2].bytes().all(|b| b.is_ascii_digit())
}
fn repository(value: &str) -> bool {
    fn segment(part: &str) -> bool {
        let bytes = part.as_bytes();
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let mut i = 0;
        while i < bytes.len() {
            let start = i;
            while i < bytes.len() && alnum(bytes[i]) {
                i += 1;
            }
            if i == start {
                return false;
            }
            if i == bytes.len() {
                return true;
            }
            match bytes[i] {
                b'.' => i += 1,
                b'_' => {
                    i += 1;
                    if i < bytes.len() && bytes[i] == b'_' {
                        i += 1;
                    }
                }
                b'-' => {
                    while i < bytes.len() && bytes[i] == b'-' {
                        i += 1;
                    }
                }
                _ => return false,
            }
        }
        false
    }
    (2..=256).contains(&value.len()) && value.split('/').all(segment)
}
fn tag(value: &str) -> bool {
    (1..=300).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
pub(crate) fn authority(config: &Value) -> Result<String, String> {
    let value = config["region"]
        .as_str()
        .filter(|v| region(v))
        .ok_or("ECR region invalid")?;
    Ok(format!("api.ecr.{value}.amazonaws.com"))
}
pub(crate) fn gate_capability() -> Value {
    json!({"schema":"serverware.operatorEcrPublicationGate/v1","adapter":ADAPTER,
        "operation":OPERATION,"signing":"exact_request_lease_v1","approval":"host_publication_review_v1"})
}
pub(crate) fn request_profile() -> ProviderRequestProfile {
    ProviderRequestProfile {
        allowed_headers: HEADERS,
        allowed_query_keys: &[],
        allowed_media_types: CONTENT_TYPES,
        required_discard_headers: DISCARD,
        max_body_bytes: REQUEST_BYTES,
    }
}
pub(crate) fn request_config() -> Value {
    json!({"allowedHeaders":HEADERS,"discardHeaders":DISCARD,"allowedQueryKeys":[],
        "allowedMediaTypes":CONTENT_TYPES,"maxBodyBytes":REQUEST_BYTES,"valueRules":[]})
}
pub(crate) fn response_profile(error: bool) -> Value {
    if error {
        json!({"mode":MODE,"maxBodyBytes":ERROR_BYTES,"contentTypes":ERROR_CONTENT_TYPES,
        "allowedHeaders":[],"onInvalid":"block"})
    } else {
        json!({"mode":MODE,"maxBodyBytes":RESPONSE_BYTES,"contentTypes":CONTENT_TYPES,
        "allowedHeaders":[],"error":response_profile(true)})
    }
}
pub(crate) fn envelope(id: &str) -> Value {
    json!({"id":id,"type":"responseEnvelope","phase":"response","statusCodes":STATUSES,
        "contentTypePolicy":CONTENT_TYPE_POLICY,"bodyPresence":"required","contentTypes":ERROR_CONTENT_TYPES,
        "allowedResponseHeaderNames":[],"responseHeaderRules":[],"unlistedHeaderPolicy":crate::response_metadata::POLICY})
}
pub(crate) fn validate_envelope(mode: Option<&str>, constraints: &[Value]) -> Result<(), String> {
    if mode != Some(MODE) || constraints.len() != 1 {
        return Err("ECR requires its sole response envelope".into());
    }
    let id = constraints[0]["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("ECR envelope ID missing")?;
    if constraints[0] != envelope(id) {
        return Err("ECR response envelope differs from its closed contract".into());
    }
    crate::validate_response_envelope_constraint(
        ADAPTER,
        id,
        constraints[0].as_object().ok_or("ECR envelope missing")?,
    )
}
pub(crate) fn validate_config(config: &Value, constraints: &[Value]) -> Result<(), String> {
    let bad = "ECR config differs from its closed contract";
    let object = config.as_object().ok_or(bad)?;
    if !exact(
        object,
        &[
            "credentialBinding",
            "registryId",
            "region",
            "repositoryName",
            "imageTag",
            "approval",
            "request",
            "response",
        ],
    ) || config["request"] != request_config()
        || config["response"] != response_profile(false)
        || config["approval"] != json!({"mode":"host_review_v1","scope":"publication"})
        || config["registryId"]
            .as_str()
            .is_none_or(|s| s.len() != 12 || !s.bytes().all(|b| b.is_ascii_digit()))
        || config["region"].as_str().is_none_or(|s| !region(s))
        || config["repositoryName"]
            .as_str()
            .is_none_or(|s| !repository(s))
        || config["imageTag"].as_str().is_none_or(|s| !tag(s))
    {
        return Err(bad.into());
    }
    let binding = config["credentialBinding"].as_object().ok_or(bad)?;
    if !exact(
        binding,
        &["credentialType", "provider", "subjects", "secretClass"],
    ) || binding["credentialType"] != "static"
        || binding["provider"] != "operator-demo"
        || binding["secretClass"] != "awsSigV4"
        || binding["subjects"]
            .as_array()
            .is_none_or(|v| v.len() != 1 || v[0].as_str().is_none_or(|s| !uuid(s)))
    {
        return Err("ECR requires one exact static operator AWS credential binding".into());
    }
    validate_envelope(Some(MODE), constraints)
}
pub(crate) fn validate_policy(route: &Map<String, Value>) -> Result<(), String> {
    let config = route
        .get("adapter")
        .and_then(|v| v.get("config"))
        .ok_or("ECR config missing")?;
    validate_config(
        config,
        route
            .get("constraints")
            .and_then(Value::as_array)
            .ok_or("ECR constraints missing")?,
    )?;
    let matcher = route
        .get("match")
        .and_then(Value::as_object)
        .ok_or("ECR route match missing")?;
    if matcher.get("scheme") != Some(&json!("https"))
        || matcher.get("host") != Some(&json!(authority(config)?))
        || matcher.get("port") != Some(&json!(443))
        || matcher.get("methods") != Some(&json!(["POST"]))
        || matcher.get("paths") != Some(&json!(["/"]))
        || route.contains_key("jit")
        || route.contains_key("credentialHeader")
        || route.contains_key("responseObservation")
    {
        return Err(
            "ECR requires its exact regional POST target without generic injection or approval"
                .into(),
        );
    }
    Ok(())
}
pub(crate) fn validate_route(route: &Route) -> Result<(), String> {
    validate_config(&route.adapter_config, &route.constraints)?;
    if route.adapter_type != ADAPTER
        || route.scheme != "https"
        || route.host != authority(&route.adapter_config)?
        || route.port != 443
        || route.methods != HashSet::from(["POST".to_owned()])
        || route.paths.len() != 1
        || route.paths[0].matches_canonical("/") != Some(Default::default())
        || route.credential_ref.as_deref().is_none_or(str::is_empty)
        || route.credential_header.is_some()
        || route.discard_headers != DISCARD.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        || route.jit != json!({})
        || route.response_observation.is_some()
    {
        return Err("ECR runtime route authority invalid".into());
    }
    Ok(())
}
fn target(url: &Url, config: &Value) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.query().is_none()
        && url.path() == "/"
        && authority(config).ok().as_deref() == url.host_str()
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 71
            && s.starts_with("sha256:")
            && s.as_bytes()[7..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    })
}
fn digests(value: &Value, max: usize) -> bool {
    value.as_array().is_some_and(|v| {
        !v.is_empty()
            && v.len() <= max
            && v.iter().all(digest)
            && v.iter()
                .filter_map(Value::as_str)
                .collect::<HashSet<_>>()
                .len()
                == v.len()
    })
}
fn number(value: &Value) -> Option<u64> {
    value.as_u64().filter(|n| *n <= i64::MAX as u64)
}
fn manifest_media(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some(
            "application/vnd.oci.image.manifest.v1+json"
                | "application/vnd.docker.distribution.manifest.v2+json"
        )
    )
}
// Bound structural allocation and reject floating/negative/exponent numeric
// tokens before the duplicate-preserving JSON parser creates the object graph.
fn document(bytes: &[u8], limit: u64) -> Result<Value, ()> {
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(());
    }
    let mut depth = 0i32;
    let mut punctuation = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    punctuation += 1;
                }
                b']' | b'}' => depth -= 1,
                b',' | b':' => punctuation += 1,
                b'0'..=b'9' | b'-' => {
                    let start = i;
                    while i < bytes.len()
                        && !matches!(bytes[i], b',' | b']' | b'}' | b' ' | b'\r' | b'\n' | b'\t')
                    {
                        i += 1;
                    }
                    let token = &bytes[start..i];
                    if token.is_empty()
                        || token.len() > 19
                        || !token.iter().all(u8::is_ascii_digit)
                        || token.len() > 1 && token[0] == b'0'
                        || std::str::from_utf8(token)
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .is_none_or(|n| n > i64::MAX as u64)
                    {
                        return Err(());
                    }
                    continue;
                }
                _ => {}
            }
        }
        if depth < 0 || depth > 8 || punctuation > 4096 {
            return Err(());
        }
        i += 1;
    }
    if quoted || depth != 0 {
        return Err(());
    }
    crate::strict_json_value_from_slice(bytes).map_err(|_| ())
}
fn body_valid(config: &Value, action: &str, body: &[u8]) -> bool {
    let Ok(value) = document(body, REQUEST_BYTES) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    if value["registryId"] != config["registryId"]
        || value["repositoryName"] != config["repositoryName"]
    {
        return false;
    }
    let common = ["registryId", "repositoryName"];
    match action {
        "BatchCheckLayerAvailability" => {
            fields(
                object,
                &["registryId", "repositoryName", "layerDigests"],
                &[],
            ) && digests(&value["layerDigests"], 100)
        }
        "InitiateLayerUpload" => exact(object, &common),
        "CompleteLayerUpload" => {
            fields(
                object,
                &["registryId", "repositoryName", "uploadId", "layerDigests"],
                &[],
            ) && upload_id(&value["uploadId"])
                && digests(&value["layerDigests"], 1)
        }
        "UploadLayerPart" => {
            if !fields(
                object,
                &[
                    "registryId",
                    "repositoryName",
                    "uploadId",
                    "partFirstByte",
                    "partLastByte",
                    "layerPartBlob",
                ],
                &[],
            ) || !upload_id(&value["uploadId"])
            {
                return false;
            }
            let (Some(first), Some(last), Some(encoded)) = (
                number(&value["partFirstByte"]),
                number(&value["partLastByte"]),
                value["layerPartBlob"].as_str(),
            ) else {
                return false;
            };
            let Ok(part) = general_purpose::STANDARD.decode(encoded) else {
                return false;
            };
            !part.is_empty()
                && part.len() <= PART_BYTES
                && general_purpose::STANDARD.encode(&part) == encoded
                && last.checked_sub(first).and_then(|n| n.checked_add(1)) == Some(part.len() as u64)
        }
        "PutImage" => {
            if !fields(
                object,
                &["registryId", "repositoryName", "imageManifest", "imageTag"],
                &["imageManifestMediaType", "imageDigest"],
            ) || value["imageTag"] != config["imageTag"]
            {
                return false;
            }
            let Some(manifest) = value["imageManifest"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4 * 1024 * 1024)
            else {
                return false;
            };
            (!object.contains_key("imageManifestMediaType")
                || manifest_media(&value["imageManifestMediaType"]))
                && (!object.contains_key("imageDigest")
                    || value["imageDigest"]
                        == format!(
                            "sha256:{}",
                            hex::encode(Sha256::digest(manifest.as_bytes()))
                        ))
        }
        _ => false,
    }
}
pub(crate) fn sdk_timestamp(value: &str) -> Option<u64> {
    let b = value.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |a: usize, z: usize| std::str::from_utf8(&b[a..z]).ok()?.parse::<u32>().ok();
    let date = Date::from_calendar_date(
        n(0, 4)? as i32,
        Month::try_from(n(4, 6)? as u8).ok()?,
        n(6, 8)? as u8,
    )
    .ok()?;
    let time = Time::from_hms(n(9, 11)? as u8, n(11, 13)? as u8, n(13, 15)? as u8).ok()?;
    u64::try_from(
        PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp(),
    )
    .ok()
}
fn dummy_signature(req: &DecisionRequest, config: &Value, action: &str) -> bool {
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let Some(seconds) = header("x-amz-date").and_then(sdk_timestamp) else {
        return false;
    };
    let Ok(credentials) = crate::aws_ecr_signing::Credentials::new(
        crate::aws_ecr_signing::CredentialKind::LongTerm,
        DUMMY_ACCESS_KEY.to_owned(),
        DUMMY_SECRET.to_owned(),
        None,
        None,
    ) else {
        return false;
    };
    // This timestamp is used only to reproduce a PUBLIC dummy signature. It is
    // not the trusted clock used for the real signed-request dispatch lease.
    let Ok(signed) = crate::aws_ecr_signing::sign(
        &credentials,
        config["region"].as_str().unwrap_or(""),
        action,
        req.body.as_bytes(),
        crate::aws_ecr_signing::ClockObservation {
            unix_seconds: seconds,
            monotonic_ns: 0,
        },
    ) else {
        return false;
    };
    let matches = signed.headers().all(|(name, expected)| {
        if name == "host" && header(name).is_none() {
            return true;
        }
        header(name).is_some_and(|actual| actual == expected)
    });
    matches
}
pub(crate) fn validate_request(
    req: &DecisionRequest,
    url: &Url,
    route: &Route,
) -> Result<Value, Value> {
    validate_route(route)
        .map_err(|_| json!({"error":"ecr_publication_policy_invalid","status_code":500}))?;
    let bad = || json!({"error":"ecr_publication_request_denied","status_code":403});
    if req.method != "POST" || !target(url, &route.adapter_config) {
        return Err(bad());
    }
    let mut seen = HashSet::new();
    for (name, value) in &req.headers {
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone())
            || value.len() > 2048
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || !HEADERS.contains(&name.as_str())
                && !["content-type", "host", "content-length"].contains(&name.as_str())
        {
            return Err(bad());
        }
        if name == "amz-sdk-invocation-id" && !uuid(&value.to_ascii_lowercase()) {
            return Err(bad());
        }
        if name == "amz-sdk-request" && !matches!(value.as_str(), "attempt=1" | "attempt=1; max=1")
        {
            return Err(bad());
        }
        if name == "content-length" && value != &req.body.len().to_string() {
            return Err(bad());
        }
    }
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    if header("content-type") != Some(MEDIA) {
        return Err(bad());
    }
    let action = header("x-amz-target")
        .and_then(|s| s.strip_prefix(TARGET_PREFIX))
        .filter(|s| crate::aws_ecr_signing::ACTIONS.contains(s))
        .ok_or_else(bad)?;
    let agent = header("user-agent").ok_or_else(bad)?;
    if agent.matches(PUBLICATION_PREFIX).count() != 1 {
        return Err(bad());
    }
    let publication = agent
        .split_ascii_whitespace()
        .find_map(|s| s.strip_prefix(PUBLICATION_PREFIX))
        .filter(|s| uuid(s))
        .ok_or_else(bad)?;
    if !body_valid(&route.adapter_config, action, req.body.as_bytes())
        || !dummy_signature(req, &route.adapter_config, action)
    {
        return Err(bad());
    }
    Ok(
        json!({"operation":OPERATION,"action":action,"publicationId":publication,
        "registryId":route.adapter_config["registryId"],"region":route.adapter_config["region"],
        "repositoryName":route.adapter_config["repositoryName"],"imageTag":route.adapter_config["imageTag"],
        "requestBodySha256":crate::sha256_prefixed(req.body.as_bytes())}),
    )
}
pub(crate) fn normalize_request(
    req: &DecisionRequest,
    url: &Url,
    matched: &RouteMatch<'_>,
) -> Result<(Value, Value), Value> {
    let operation = validate_request(req, url, matched.route)?;
    if !matched.params.is_empty() {
        return Err(json!({"error":"ecr_publication_request_denied","status_code":403}));
    }
    Ok((operation, json!({})))
}
pub(crate) fn is_content_type(value: &str) -> bool {
    value == MEDIA
}
pub(crate) fn inspect_response(
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    config: &Value,
    operation: &Value,
    body: SensitiveResponseBytes,
    guard: &ResponseSecretGuard,
) -> Result<SensitiveResponseBytes, Value> {
    let bad = || json!({"error":"ecr_publication_response_invalid","status_code":502});
    let error = status != StatusCode::OK;
    if operation["operation"] != OPERATION
        || !target(url, operation)
        || !STATUSES.contains(&status.as_u16())
        || config != &response_profile(error)
        || content_type.is_none_or(|v| {
            if error {
                !ERROR_CONTENT_TYPES.contains(&v)
            } else {
                !is_content_type(v)
            }
        })
    {
        return Err(bad());
    }
    // Full action-specific ACK validation and durable revision commit are done
    // by the publication owner before this response reaches the generic release.
    let (body, payload) = crate::buffered_response::inspect_json_bytes(
        ADAPTER,
        body,
        if error { ERROR_BYTES } else { RESPONSE_BYTES },
        guard,
        true,
    )?;
    if !payload.is_object() {
        return Err(bad());
    }
    Ok(body)
}

#[cfg(test)]
#[path = "aws_ecr_publication_tests.rs"]
mod tests;
