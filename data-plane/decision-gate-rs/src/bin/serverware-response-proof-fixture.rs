use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

const BUFFERED_REQUEST_VERSION: &str = "serverware.responseProofAttestationRequest/v2";
const BUFFERED_REQUEST_KIND: &str = "ServerwareResponseProofAttestationRequest";
const STREAMING_REQUEST_VERSION: &str = "serverware.streamingResponseProofAttestationRequest/v1";
const STREAMING_REQUEST_KIND: &str = "ServerwareStreamingResponseProofAttestationRequest";
const OBSERVATION_REQUEST_VERSION: &str =
    "serverware.responseObservationProofAttestationRequest/v1";
const OBSERVATION_REQUEST_KIND: &str = "ServerwareResponseObservationProofAttestationRequest";
const OBSERVATION_STATEMENT_VERSION: &str = "serverware.responseObservationStatement/v1";
const OBSERVATION_EXPORTER_LABEL: &str = "EXPORTER-Serverware-Response-Observation-v1";
const STREAMING_STATEMENT_VERSION: &str = "serverware.streamingResponseStatement/v1";
const STREAMING_EXPORTER_LABEL: &str = "EXPORTER-Serverware-Proxy-Stream-v1";
const STREAMING_TRAILERS: [&str; 2] = [
    "X-Serverware-Stream-Proof-B64",
    "X-Serverware-Stream-Proof-SHA256",
];

const STREAMING_REQUEST_FIELDS: [&str; 7] = [
    "apiVersion",
    "kind",
    "streaming_response_statement_api_version",
    "streaming_response_statement_sha256",
    "response_signing_key_id",
    "response_signing_public_key_pem",
    "attested_claims",
];

const STREAMING_CLAIM_FIELDS: [&str; 35] = [
    "streaming_response_statement_api_version",
    "streaming_response_statement_sha256",
    "issued_at_unix",
    "client_nonce_sha256",
    "client_request_digest",
    "principal_id",
    "route_id",
    "request_digest",
    "operation_digest",
    "release_authority",
    "authorization_binding_digest",
    "control_plane_authorization_receipt_sha256",
    "upstream_status",
    "upstream_selected_raw_policy_headers_digest",
    "upstream_body_digest",
    "upstream_body_bytes",
    "upstream_canonical_digest",
    "released_response_status",
    "released_response_content_type",
    "selected_response_wire_headers_digest",
    "released_response_body_digest",
    "released_response_body_bytes",
    "response_framing",
    "response_completion",
    "response_trailer_names",
    "policy_digest",
    "runtime_manifest_digest",
    "data_plane_binary_digest",
    "release_digest",
    "server_instance_id",
    "server_instance_identity_digest",
    "tls_channel_binding_type",
    "tls_exporter_label",
    "tls_channel_binding_sha256",
    "response_signing_key_id",
];

const OBSERVATION_CLAIM_FIELDS: [&str; 20] = [
    "server_statement_sha256",
    "server_statement_api_version",
    "issued_at_unix",
    "observation_id",
    "client_nonce_sha256",
    "request_aggregate_digest",
    "response_path",
    "upstream_attempt",
    "upstream_observation_digest",
    "emitted_response_digest",
    "policy_digest",
    "runtime_manifest_digest",
    "data_plane_binary_digest",
    "release_digest",
    "server_instance_id",
    "server_instance_identity_digest",
    "tls_exporter_label",
    "tls_channel_binding_sha256",
    "response_signing_key_id",
    "observation_source",
];

const RELEASE_AUTHORITY_FIELDS: [&str; 13] = [
    "authority_mode",
    "grant_id",
    "approval_id",
    "credential_ref",
    "credential_version",
    "request_digest",
    "operation_digest",
    "attempt_id",
    "consumption_identity_digest",
    "authorization_state_at_upstream_dispatch",
    "authorization_state_observed_at_epoch_ms",
    "reservation_expires_at_epoch_ms",
    "dispatch_expires_at_epoch_ms",
];

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization failed")
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn exact_object<'a>(
    value: &'a Value,
    expected_fields: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.len() != expected_fields.len()
        || object
            .keys()
            .any(|field| !expected_fields.contains(&field.as_str()))
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(format!("{label} has missing or unexpected fields"));
    }
    Ok(object)
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a string"))
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field} must be a non-negative integer"))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_digest<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    let value = required_string(object, field)?;
    if !is_sha256_digest(value) {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(value)
}

fn is_bounded_identity(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
}

fn optional_identity(object: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    match object.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if is_bounded_identity(value) => Ok(Some(value.clone())),
        _ => Err(format!("{field} must be null or a bounded identity")),
    }
}

fn response_key_id(public_key_pem: &str) -> Result<String, String> {
    let body = public_key_pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|value| value.strip_suffix("-----END PUBLIC KEY-----\n"))
        .ok_or("response_signing_public_key_pem is not canonical PEM")?;
    if body.is_empty()
        || body.len() > 1024
        || body
            .lines()
            .any(|line| line.is_empty() || line.len() > 64 || !line.is_ascii())
    {
        return Err("response_signing_public_key_pem is not canonical PEM".to_string());
    }
    let der = general_purpose::STANDARD
        .decode(body.lines().collect::<String>().as_bytes())
        .map_err(|_| "response_signing_public_key_pem is invalid base64")?;
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err("response_signing_public_key_pem is not an Ed25519 SPKI key".to_string());
    }
    Ok(sha256_prefixed(&der))
}

fn validate_release_authority(value: &Value, claims: &Map<String, Value>) -> Result<(), String> {
    let authority = exact_object(value, &RELEASE_AUTHORITY_FIELDS, "release_authority")?;
    if required_string(authority, "authority_mode")? != "atomic"
        || required_string(authority, "authorization_state_at_upstream_dispatch")? != "dispatching"
    {
        return Err("release_authority is not an atomic dispatch authority".to_string());
    }
    let grant_id = optional_identity(authority, "grant_id")?;
    let approval_id = optional_identity(authority, "approval_id")?;
    if grant_id.is_some() != approval_id.is_some() {
        return Err("release_authority grant and approval IDs must be paired".to_string());
    }
    let credential_ref = optional_identity(authority, "credential_ref")?;
    let credential_version = required_u64(authority, "credential_version")?;
    if credential_ref.is_some() != (credential_version > 0) {
        return Err("release_authority credential identity is inconsistent".to_string());
    }
    for field in [
        "request_digest",
        "operation_digest",
        "attempt_id",
        "consumption_identity_digest",
    ] {
        required_digest(authority, field)?;
    }
    if authority.get("request_digest") != claims.get("request_digest")
        || authority.get("operation_digest") != claims.get("operation_digest")
    {
        return Err("release_authority request identity does not match the claims".to_string());
    }
    let observed = required_u64(authority, "authorization_state_observed_at_epoch_ms")?;
    let dispatch_expires = required_u64(authority, "dispatch_expires_at_epoch_ms")?;
    let reservation_expires = match authority.get("reservation_expires_at_epoch_ms") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or("reservation_expires_at_epoch_ms must be null or an integer")?,
        ),
        None => return Err("reservation_expires_at_epoch_ms is missing".to_string()),
    };
    if observed == 0
        || dispatch_expires <= observed
        || reservation_expires.is_some_and(|expires| expires <= observed)
    {
        return Err("release_authority timestamps are inconsistent".to_string());
    }
    Ok(())
}

fn validate_streaming_request(request: &Value) -> Result<(Value, String, String), String> {
    let object = exact_object(
        request,
        &STREAMING_REQUEST_FIELDS,
        "streaming fixture request",
    )?;
    if required_string(object, "apiVersion")? != STREAMING_REQUEST_VERSION
        || required_string(object, "kind")? != STREAMING_REQUEST_KIND
        || required_string(object, "streaming_response_statement_api_version")?
            != STREAMING_STATEMENT_VERSION
    {
        return Err("streaming fixture request has the wrong type".to_string());
    }
    let statement_digest = required_digest(object, "streaming_response_statement_sha256")?;
    let key_id = required_digest(object, "response_signing_key_id")?;
    let public_key_pem = required_string(object, "response_signing_public_key_pem")?;
    if response_key_id(public_key_pem)? != key_id {
        return Err("response signing public key does not match its key ID".to_string());
    }
    let claims_value = object
        .get("attested_claims")
        .ok_or("streaming fixture request is missing attested_claims")?;
    let claims = exact_object(
        claims_value,
        &STREAMING_CLAIM_FIELDS,
        "streaming attested_claims",
    )?;
    if required_string(claims, "streaming_response_statement_api_version")?
        != STREAMING_STATEMENT_VERSION
        || required_digest(claims, "streaming_response_statement_sha256")? != statement_digest
        || required_digest(claims, "response_signing_key_id")? != key_id
    {
        return Err("streaming attested claims do not bind the request identity".to_string());
    }
    for field in [
        "client_nonce_sha256",
        "client_request_digest",
        "request_digest",
        "operation_digest",
        "authorization_binding_digest",
        "control_plane_authorization_receipt_sha256",
        "upstream_selected_raw_policy_headers_digest",
        "upstream_body_digest",
        "upstream_canonical_digest",
        "selected_response_wire_headers_digest",
        "released_response_body_digest",
        "policy_digest",
        "runtime_manifest_digest",
        "data_plane_binary_digest",
        "release_digest",
        "server_instance_identity_digest",
        "tls_channel_binding_sha256",
    ] {
        required_digest(claims, field)?;
    }
    if required_u64(claims, "issued_at_unix")? == 0 {
        return Err("issued_at_unix must be positive".to_string());
    }
    for field in ["principal_id", "route_id"] {
        if !is_bounded_identity(required_string(claims, field)?) {
            return Err(format!("{field} is not a bounded identity"));
        }
    }
    let upstream_status = required_u64(claims, "upstream_status")?;
    let released_status = required_u64(claims, "released_response_status")?;
    if upstream_status != released_status || !(200..=299).contains(&released_status) {
        return Err("streaming upstream and released status claims are inconsistent".to_string());
    }
    required_u64(claims, "upstream_body_bytes")?;
    required_u64(claims, "released_response_body_bytes")?;
    let content_type = required_string(claims, "released_response_content_type")?;
    if content_type.is_empty()
        || content_type.len() > 1024
        || content_type.chars().any(char::is_control)
    {
        return Err("released_response_content_type is invalid".to_string());
    }
    if required_string(claims, "response_framing")? != "http1.1-chunked-trailers"
        || required_string(claims, "response_completion")? != "normal-eof"
        || claims.get("response_trailer_names") != Some(&json!(STREAMING_TRAILERS))
        || required_string(claims, "tls_channel_binding_type")? != "tls-exporter"
        || required_string(claims, "tls_exporter_label")? != STREAMING_EXPORTER_LABEL
    {
        return Err("streaming framing, trailers, or TLS exporter claim is invalid".to_string());
    }
    let instance_id = required_string(claims, "server_instance_id")?;
    if !instance_id.starts_with("spiffe://")
        || !is_bounded_identity(instance_id)
        || claims.get("server_instance_identity_digest")
            != Some(&Value::String(sha256_prefixed(instance_id.as_bytes())))
    {
        return Err("server instance identity binding is invalid".to_string());
    }
    validate_release_authority(
        claims
            .get("release_authority")
            .ok_or("streaming claims are missing release_authority")?,
        claims,
    )?;
    Ok((
        claims_value.clone(),
        statement_digest.to_string(),
        key_id.to_string(),
    ))
}

fn validate_observation_request(request: &Value) -> Result<(Value, String, String), String> {
    let object = exact_object(
        request,
        &[
            "apiVersion",
            "kind",
            "server_statement_sha256",
            "response_signing_key_id",
            "response_signing_public_key_pem",
            "attested_claims",
        ],
        "response observation fixture request",
    )?;
    if required_string(object, "apiVersion")? != OBSERVATION_REQUEST_VERSION
        || required_string(object, "kind")? != OBSERVATION_REQUEST_KIND
    {
        return Err("response observation fixture request has the wrong type".to_string());
    }
    let statement_digest = required_digest(object, "server_statement_sha256")?;
    let key_id = required_digest(object, "response_signing_key_id")?;
    if response_key_id(required_string(object, "response_signing_public_key_pem")?)? != key_id {
        return Err(
            "response observation signing public key does not match its key ID".to_string(),
        );
    }
    let claims_value = object
        .get("attested_claims")
        .ok_or("response observation fixture request is missing attested_claims")?;
    let claims = exact_object(
        claims_value,
        &OBSERVATION_CLAIM_FIELDS,
        "response observation attested_claims",
    )?;
    if required_digest(claims, "server_statement_sha256")? != statement_digest
        || required_string(claims, "server_statement_api_version")? != OBSERVATION_STATEMENT_VERSION
        || required_digest(claims, "response_signing_key_id")? != key_id
    {
        return Err("response observation claims do not bind the request identity".to_string());
    }
    if required_u64(claims, "issued_at_unix")? == 0 {
        return Err("response observation issued_at_unix must be positive".to_string());
    }
    for field in [
        "observation_id",
        "client_nonce_sha256",
        "request_aggregate_digest",
        "emitted_response_digest",
        "policy_digest",
        "runtime_manifest_digest",
        "data_plane_binary_digest",
        "release_digest",
        "server_instance_identity_digest",
        "tls_channel_binding_sha256",
    ] {
        required_digest(claims, field)?;
    }
    let upstream_digest = match claims.get("upstream_observation_digest") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if is_sha256_digest(value) => Some(value.as_str()),
        _ => {
            return Err(
                "upstream_observation_digest must be null or a lowercase SHA-256 digest"
                    .to_string(),
            )
        }
    };
    let response_path = required_string(claims, "response_path")?;
    let upstream_attempt = required_string(claims, "upstream_attempt")?;
    if ![
        "local-reject-no-upstream-attempt",
        "dispatch-denied-no-upstream-attempt",
        "authorized-not-attempted",
        "upstream-attempt-outcome-unknown",
        "complete-upstream-response-released",
        "complete-upstream-response-blocked",
        "post-dispatch-local-failure",
    ]
    .contains(&response_path)
        || ![
            "not-started",
            "started-no-response",
            "headers-observed-body-incomplete",
            "complete",
        ]
        .contains(&upstream_attempt)
    {
        return Err("response observation lifecycle claim is invalid".to_string());
    }
    match response_path {
        "local-reject-no-upstream-attempt"
        | "dispatch-denied-no-upstream-attempt"
        | "authorized-not-attempted"
            if upstream_attempt != "not-started" || upstream_digest.is_some() =>
        {
            return Err("response observation no-attempt lifecycle is inconsistent".to_string())
        }
        "upstream-attempt-outcome-unknown"
            if !matches!(
                upstream_attempt,
                "started-no-response" | "headers-observed-body-incomplete"
            ) || (upstream_attempt == "started-no-response" && upstream_digest.is_some())
                || (upstream_attempt == "headers-observed-body-incomplete"
                    && upstream_digest.is_none()) =>
        {
            return Err("response observation unknown lifecycle is inconsistent".to_string())
        }
        "complete-upstream-response-released" | "complete-upstream-response-blocked"
            if upstream_attempt != "complete" || upstream_digest.is_none() =>
        {
            return Err("response observation complete lifecycle is inconsistent".to_string())
        }
        "post-dispatch-local-failure"
            if (upstream_attempt == "not-started")
                || (upstream_attempt == "started-no-response" && upstream_digest.is_some())
                || (matches!(
                    upstream_attempt,
                    "headers-observed-body-incomplete" | "complete"
                ) && upstream_digest.is_none()) =>
        {
            return Err("response observation post-dispatch lifecycle is inconsistent".to_string())
        }
        _ => {}
    }
    let instance_id = required_string(claims, "server_instance_id")?;
    if !instance_id.starts_with("spiffe://")
        || !is_bounded_identity(instance_id)
        || claims.get("server_instance_identity_digest")
            != Some(&Value::String(sha256_prefixed(instance_id.as_bytes())))
    {
        return Err("response observation server identity binding is invalid".to_string());
    }
    if required_string(claims, "tls_exporter_label")? != OBSERVATION_EXPORTER_LABEL
        || required_string(claims, "observation_source")? != "gate-authored"
    {
        return Err("response observation exporter or authority is invalid".to_string());
    }
    Ok((
        claims_value.clone(),
        statement_digest.to_string(),
        key_id.to_string(),
    ))
}

fn development_attestation(
    claims: Value,
    statement_digest: &str,
    key_id: &str,
    streaming: bool,
) -> Value {
    let quote = json!({
        "format":"serverware-development-fixture",
        "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(
            format!("development-only:{statement_digest}:{key_id}").repeat(2).as_bytes()
        ),
    });
    let mut verifier_statement = Map::from_iter([
        ("outcome".to_string(), json!("development-fixture")),
        ("environment".to_string(), json!("development")),
        ("debug".to_string(), json!(true)),
        ("response_signing_key_id".to_string(), json!(key_id)),
        ("attested_claims".to_string(), claims),
    ]);
    verifier_statement.insert(
        if streaming {
            "streaming_response_statement_sha256"
        } else {
            "server_statement_sha256"
        }
        .to_string(),
        json!(statement_digest),
    );
    json!({
        "vendor_tee":{
            "platform":"none-dev",
            "provider":"development-fixture",
            "quote_sha256":sha256_prefixed(canonical_json(&quote).as_bytes()),
            "quote":quote,
            "trusted_verifier":{
                "apiVersion":"serverware.vendorTeeVerification/v1",
                "kind":"ServerwareVendorTeeVerification",
                "statement":verifier_statement,
                "signature":null,
            },
        }
    })
}

fn run_with_input(input: &[u8]) -> Result<Value, String> {
    if input.len() > 65_536 {
        return Err("fixture request is too large".to_string());
    }
    let request: Value =
        serde_json::from_slice(input).map_err(|err| format!("parse fixture request: {err}"))?;
    if request.get("apiVersion").and_then(Value::as_str) == Some(STREAMING_REQUEST_VERSION) {
        let (claims, statement_digest, key_id) = validate_streaming_request(&request)?;
        return Ok(development_attestation(
            claims,
            &statement_digest,
            &key_id,
            true,
        ));
    }
    if request.get("apiVersion").and_then(Value::as_str) == Some(OBSERVATION_REQUEST_VERSION) {
        let (claims, statement_digest, key_id) = validate_observation_request(&request)?;
        return Ok(development_attestation(
            claims,
            &statement_digest,
            &key_id,
            false,
        ));
    }
    if request.get("apiVersion").and_then(Value::as_str) != Some(BUFFERED_REQUEST_VERSION)
        || request.get("kind").and_then(Value::as_str) != Some(BUFFERED_REQUEST_KIND)
    {
        return Err("fixture request has the wrong type".to_string());
    }
    let claims = request
        .get("attested_claims")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or("fixture request is missing attested_claims")?;
    let statement_digest = request
        .get("server_statement_sha256")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:") && value.len() == 71)
        .ok_or("fixture request is missing server_statement_sha256")?;
    let key_id = request
        .get("response_signing_key_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:") && value.len() == 71)
        .ok_or("fixture request is missing response_signing_key_id")?;
    Ok(development_attestation(
        claims,
        statement_digest,
        key_id,
        false,
    ))
}

fn run() -> Result<Value, String> {
    let mut input = Vec::new();
    io::stdin()
        .take(65_537)
        .read_to_end(&mut input)
        .map_err(|err| format!("read fixture request: {err}"))?;
    run_with_input(&input)
}

fn main() {
    match run() {
        Ok(output) => println!("{}", canonical_json(&output)),
        Err(error) => {
            eprintln!("{}", canonical_json(&json!({"ok":false,"error":error})));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn public_key() -> (String, String) {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(&[42u8; 32]);
        let encoded = general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n");
        (pem, sha256_prefixed(&der))
    }

    fn streaming_request() -> Value {
        let (pem, key_id) = public_key();
        let instance_id = "spiffe://prod.serverware/decision-gate/test";
        let release_authority = json!({
            "authority_mode":"atomic",
            "grant_id":"grant:test",
            "approval_id":"approval:test",
            "credential_ref":"credential:test",
            "credential_version":7,
            "request_digest":digest(3),
            "operation_digest":digest(4),
            "attempt_id":digest(5),
            "consumption_identity_digest":digest(6),
            "authorization_state_at_upstream_dispatch":"dispatching",
            "authorization_state_observed_at_epoch_ms":1_000,
            "reservation_expires_at_epoch_ms":2_000,
            "dispatch_expires_at_epoch_ms":3_000,
        });
        let claims = json!({
            "streaming_response_statement_api_version":STREAMING_STATEMENT_VERSION,
            "streaming_response_statement_sha256":digest(1),
            "issued_at_unix":1,
            "client_nonce_sha256":digest(2),
            "client_request_digest":digest(7),
            "principal_id":"agent:test",
            "route_id":"route:test",
            "request_digest":digest(3),
            "operation_digest":digest(4),
            "release_authority":release_authority,
            "authorization_binding_digest":digest(6),
            "control_plane_authorization_receipt_sha256":digest(8),
            "upstream_status":200,
            "upstream_selected_raw_policy_headers_digest":digest(9),
            "upstream_body_digest":digest(10),
            "upstream_body_bytes":1024,
            "upstream_canonical_digest":digest(11),
            "released_response_status":200,
            "released_response_content_type":"application/json",
            "selected_response_wire_headers_digest":digest(12),
            "released_response_body_digest":digest(13),
            "released_response_body_bytes":512,
            "response_framing":"http1.1-chunked-trailers",
            "response_completion":"normal-eof",
            "response_trailer_names":STREAMING_TRAILERS,
            "policy_digest":digest(14),
            "runtime_manifest_digest":digest(15),
            "data_plane_binary_digest":digest(16),
            "release_digest":digest(17),
            "server_instance_id":instance_id,
            "server_instance_identity_digest":sha256_prefixed(instance_id.as_bytes()),
            "tls_channel_binding_type":"tls-exporter",
            "tls_exporter_label":STREAMING_EXPORTER_LABEL,
            "tls_channel_binding_sha256":digest(18),
            "response_signing_key_id":key_id,
        });
        json!({
            "apiVersion":STREAMING_REQUEST_VERSION,
            "kind":STREAMING_REQUEST_KIND,
            "streaming_response_statement_api_version":STREAMING_STATEMENT_VERSION,
            "streaming_response_statement_sha256":digest(1),
            "response_signing_key_id":key_id,
            "response_signing_public_key_pem":pem,
            "attested_claims":claims,
        })
    }

    fn observation_request() -> Value {
        let (pem, key_id) = public_key();
        let instance_id = "spiffe://prod.serverware/decision-gate/test";
        let claims = json!({
            "server_statement_sha256":digest(1),
            "server_statement_api_version":OBSERVATION_STATEMENT_VERSION,
            "issued_at_unix":1,
            "observation_id":digest(2),
            "client_nonce_sha256":digest(3),
            "request_aggregate_digest":digest(4),
            "response_path":"local-reject-no-upstream-attempt",
            "upstream_attempt":"not-started",
            "upstream_observation_digest":null,
            "emitted_response_digest":digest(5),
            "policy_digest":digest(6),
            "runtime_manifest_digest":digest(7),
            "data_plane_binary_digest":digest(8),
            "release_digest":digest(9),
            "server_instance_id":instance_id,
            "server_instance_identity_digest":sha256_prefixed(instance_id.as_bytes()),
            "tls_exporter_label":OBSERVATION_EXPORTER_LABEL,
            "tls_channel_binding_sha256":digest(10),
            "response_signing_key_id":key_id,
            "observation_source":"gate-authored",
        });
        json!({
            "apiVersion":OBSERVATION_REQUEST_VERSION,
            "kind":OBSERVATION_REQUEST_KIND,
            "server_statement_sha256":digest(1),
            "response_signing_key_id":key_id,
            "response_signing_public_key_pem":pem,
            "attested_claims":claims,
        })
    }

    #[test]
    fn buffered_request_behavior_is_preserved() {
        let request = json!({
            "apiVersion":BUFFERED_REQUEST_VERSION,
            "kind":BUFFERED_REQUEST_KIND,
            "server_statement_sha256":digest(1),
            "response_signing_key_id":digest(2),
            "attested_claims":{"legacy":true},
        });
        let output = run_with_input(canonical_json(&request).as_bytes()).expect("buffered fixture");
        assert_eq!(
            output["vendor_tee"]["trusted_verifier"]["statement"]["server_statement_sha256"],
            digest(1)
        );
    }

    #[test]
    fn strict_streaming_request_is_attested() {
        let request = streaming_request();
        let output = run_with_input(canonical_json(&request).as_bytes()).expect("stream fixture");
        let verifier = &output["vendor_tee"]["trusted_verifier"]["statement"];
        assert_eq!(verifier["streaming_response_statement_sha256"], digest(1));
        assert_eq!(verifier["attested_claims"], request["attested_claims"]);
    }

    #[test]
    fn streaming_request_rejects_unknown_fields_and_identity_substitution() {
        let mut extra = streaming_request();
        extra["unexpected"] = json!(true);
        assert!(run_with_input(canonical_json(&extra).as_bytes())
            .unwrap_err()
            .contains("missing or unexpected fields"));

        let mut substituted = streaming_request();
        substituted["attested_claims"]["request_digest"] = digest(31).into();
        assert!(run_with_input(canonical_json(&substituted).as_bytes())
            .unwrap_err()
            .contains("request identity"));
    }

    #[test]
    fn streaming_request_rejects_wrong_wire_contract_and_key_binding() {
        let mut wrong_exporter = streaming_request();
        wrong_exporter["attested_claims"]["tls_exporter_label"] = json!("wrong");
        assert!(run_with_input(canonical_json(&wrong_exporter).as_bytes())
            .unwrap_err()
            .contains("framing, trailers, or TLS exporter"));

        let mut wrong_key = streaming_request();
        wrong_key["response_signing_key_id"] = digest(30).into();
        assert!(run_with_input(canonical_json(&wrong_key).as_bytes())
            .unwrap_err()
            .contains("public key does not match"));
    }

    #[test]
    fn strict_observation_request_is_attested() {
        let request = observation_request();
        let output = run_with_input(canonical_json(&request).as_bytes())
            .expect("response observation fixture");
        let verifier = &output["vendor_tee"]["trusted_verifier"]["statement"];
        assert_eq!(verifier["server_statement_sha256"], digest(1));
        assert_eq!(verifier["attested_claims"], request["attested_claims"]);
    }

    #[test]
    fn observation_request_rejects_unknown_claim_and_identity_substitution() {
        let mut extra = observation_request();
        extra["attested_claims"]["unexpected"] = json!(true);
        assert!(run_with_input(canonical_json(&extra).as_bytes())
            .unwrap_err()
            .contains("missing or unexpected fields"));

        let mut wrong_key = observation_request();
        wrong_key["attested_claims"]["response_signing_key_id"] = digest(30).into();
        assert!(run_with_input(canonical_json(&wrong_key).as_bytes())
            .unwrap_err()
            .contains("bind the request identity"));
    }

    #[test]
    fn observation_request_rejects_lifecycle_and_exporter_substitution() {
        let mut wrong_lifecycle = observation_request();
        wrong_lifecycle["attested_claims"]["upstream_attempt"] = json!("complete");
        wrong_lifecycle["attested_claims"]["upstream_observation_digest"] = json!(digest(31));
        assert!(run_with_input(canonical_json(&wrong_lifecycle).as_bytes())
            .unwrap_err()
            .contains("no-attempt lifecycle"));

        let mut wrong_exporter = observation_request();
        wrong_exporter["attested_claims"]["tls_exporter_label"] = json!("wrong");
        assert!(run_with_input(canonical_json(&wrong_exporter).as_bytes())
            .unwrap_err()
            .contains("exporter or authority"));
    }
}
