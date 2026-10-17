//! Reachable compound preparation and separately selected native custody.
//!
//! The signed CP response supplies unadmitted originals. We retain its actual
//! bytes and the real buffered CONNECT/request owner, repeat pure derivation,
//! and compare the claims with this request's current policy. Only the explicit
//! v26 owner can admit its independent pins, prepare the actual broker pair,
//! and obtain its purpose signature/fresh quote. The separate submission owner
//! can return only an authenticated pending denial, never a release permit.
use super::*;
use serde_json::value::RawValue;
use std::collections::BTreeMap;

pub(super) const PATH: &str = "/api/data-plane/release-authorizations/native-jit-prepare";
pub(super) const MAX_RESPONSE_BYTES: u64 = 512 * 1024;
const SCHEMA: &str = "catchplate.nativeReleaseJitPreparation/v1";
#[path = "native_release_jit_submission.rs"]
pub(super) mod submission;

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native compound preparation originals differ".to_owned()) }
}

// No caller-supplied authorization boolean. The borrowed original was created
// only by the actual buffered pipeline, and check_release repeats its checks.
pub(super) struct Request<'state, 'a> {
    pub(super) state: &'state GateState,
    pub(super) snapshot: &'a Arc<Snapshot>,
    pub(super) authentication: &'a AttestedResponseAuthenticationContext,
    pub(super) original: &'a native_buffered_request::ReleaseOriginals<'a>,
    pub(super) attempt_id: &'a str,
    pub(super) principal_id: &'a str,
    pub(super) route: &'a Route,
    pub(super) credential_ref: Option<&'a str>,
    pub(super) credential_version: u64,
    pub(super) policy_hash: &'a str,
    pub(super) request_digest: &'a str,
    pub(super) operation_digest: &'a str,
    pub(super) operation: &'a Value,
    pub(super) canonical: &'a Value,
    pub(super) request: &'a DecisionRequest,
    pub(super) durable: &'a ReleaseAuthorizationDurablePolicyBinding,
    pub(super) deadline: Instant,
}

impl Request<'_, '_> {
    fn check(&self) -> Result<(), String> {
        require(self.state.response_proof_signer.release_profile().is_native()
            && self.route.jit.get("required") == Some(&Value::Bool(true))
            && self.deadline <= self.original.deadline()
            && self.policy_hash == self.snapshot.hash
            && self.authentication.matches_snapshot(self.snapshot))?;
        custody_deadline_remaining(self.deadline, "native compound preparation")?;
        native_buffered_request::check_release(ReleaseProfile::Native, true, Some(self.original),
            self.state, self.snapshot, self.principal_id, self.request, self.route, self.canonical)
    }

    fn payload(&self) -> Result<Value, String> {
        let mut payload = release_authorization_reserve_payload(self.attempt_id, self.principal_id,
            self.route, self.credential_ref, self.credential_version, self.policy_hash,
            self.request_digest, self.operation_digest, self.operation, self.canonical, Some(self.durable));
        payload["apiVersion"] = json!(ReleaseProfile::Native.request_version(ReleaseOperation::Prepare, true)?);
        Ok(payload)
    }

    fn claims(&self) -> Result<Claims<'_>, String> {
        Ok(Claims {
            actor: self.state.server_instance_id.as_deref().ok_or("native compound actor absent")?,
            attempt_id: self.attempt_id, principal_id: self.principal_id, route: self.route,
            credential_ref: self.credential_ref, credential_version: self.credential_version,
            policy_hash: self.policy_hash, request_digest: self.request_digest,
            operation_digest: self.operation_digest, operation: self.operation,
            canonical: self.canonical, method: &self.request.method, durable: self.durable,
        })
    }
}

// A private pure projection, not an owner or an admission capability. Production
// creates it only from the retained Request; component tests can independently
// compare the actual Python producer's bytes without fabricating that owner.
struct Claims<'a> {
    actor: &'a str,
    attempt_id: &'a str,
    principal_id: &'a str,
    route: &'a Route,
    credential_ref: Option<&'a str>,
    credential_version: u64,
    policy_hash: &'a str,
    request_digest: &'a str,
    operation_digest: &'a str,
    operation: &'a Value,
    canonical: &'a Value,
    method: &'a str,
    durable: &'a ReleaseAuthorizationDurablePolicyBinding,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    api_version: String,
    principal_id: String,
    route_id: String,
    policy_hash: String,
    request_digest: String,
    operation_digest: String,
    approver_policy: Value,
    approver_policy_sha256: String,
    // These are JSON TEXT strings, not nested serde Values. In particular no
    // parent float or large integer is parsed and then reserialized here.
    runtime_input: Zeroizing<String>,
    parent_request: Zeroizing<String>,
    child_request: Zeroizing<String>,
}

// Deliberately private, non-Clone and without getters or a signing conversion.
// Retaining a signed claim is not admitting its independent source/config pins.
struct UnadmittedPreparation<'state, 'a> {
    request: Request<'state, 'a>,
    response: VerifiedReleaseAuthorizationHttpResponse,
    wire: Wire,
}

fn object(raw: &str) -> Result<BTreeMap<String, &RawValue>, String> {
    // Only used AFTER the library's recursive duplicate-free raw validation.
    serde_json::from_str(raw).map_err(|_| "native compound original object differs".to_owned())
}

fn same(raw: &RawValue, expected: &Value) -> Result<(), String> {
    let encoded = Zeroizing::new(native_response_profile::canonical_ascii_bytes(expected)?);
    require(raw.get().as_bytes() == encoded.as_slice())
}

fn field<'a>(values: &'a BTreeMap<String, &'a RawValue>, name: &str) -> Result<&'a RawValue, String> {
    values.get(name).copied().ok_or_else(|| "native compound original field absent".to_owned())
}

fn sorted_strings(value: &Value) -> Result<Value, String> {
    let mut values = value.as_array().ok_or("native compound policy array absent")?.clone();
    require(values.iter().all(Value::is_string))?;
    values.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    values.dedup();
    Ok(Value::Array(values))
}

fn route_policy(policy: &Value, route: &Route) -> Result<(), String> {
    native_approver_policy_v1::require_policy(policy, true)?;
    let users = sorted_strings(route.jit.pointer("/approvers/users")
        .ok_or("native compound approvers absent")?)?;
    let default_classes = json!(["hardware", "yubikey"]);
    let classes = sorted_strings(route.jit.pointer("/approvers/authn/allowedAuthenticatorClasses")
        .unwrap_or(&default_classes))?;
    require(policy["requiredRoles"] == json!(["approver"])
        && policy["allowAnyApproverId"] == false && policy["requireWebAuthn"] == true
        && policy["allowedApproverIds"] == users
        && Some(&policy["threshold"]) == route.jit.pointer("/approvers/quorum")
        && policy["credentialPolicy"]["allowedAuthenticatorClasses"] == classes
        && &policy["credentialPolicy"]["requireAttestationTrusted"] == route.jit
            .pointer("/approvers/authn/requireHardwareAttestation").unwrap_or(&Value::Bool(true)))?;
    for name in ["allowedCredentialRecordIds", "allowedAaguids", "requiredTrustBundleDigest",
        "minimumTrustBundleSequence", "counterPolicy", "maxAssertionAgeSeconds"] {
        if let Some(actual) = route.jit.pointer(&format!("/approvers/authn/{name}")) {
            let expected = if actual.is_array() { sorted_strings(actual)? } else { actual.clone() };
            require(policy["credentialPolicy"][name] == expected)?;
        }
    }
    // RP/origin and unspecified normalization defaults remain authenticated CP
    // claims, not a substitute for the future native cold admission policy.
    Ok(())
}

fn marshaled_set(value: &Value) -> Result<Value, String> {
    let values = value.as_array().ok_or("native compound policy set absent")?;
    let mut items = values.iter().map(|item| Ok((
        native_response_profile::canonical_ascii_bytes(item)?, item.clone())))
        .collect::<Result<Vec<_>, String>>()?;
    // The real Python facade sorts sets by their canonical JSON text, not by
    // the original Unicode string. Keep that distinction for non-ASCII IDs.
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(json!({"$authorityType":"set", "items":items.into_iter().map(|(_, item)| item).collect::<Vec<_>>()}))
}

fn route_uint(route: &Route, name: &str, default: u64, maximum: Option<u64>) -> Result<u64, String> {
    let number = match route.jit.get(name) {
        Some(value) => value.as_u64().ok_or("native compound JIT integer differs")?,
        None => default,
    }.max(1);
    Ok(maximum.map_or(number, |limit| number.min(limit)))
}

// Exact urllib.parse.urlencode/quote_plus spelling for the existing review
// projection. This encodes a display only; it never parses or forwards HTTP.
fn quote_plus(value: &str) -> String {
    let mut out = String::new();
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => { out.push('%'); out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 15) as usize] as char); }
        }
    }
    out
}

fn review_display(request: &Claims<'_>) -> Result<(String, Value), String> {
    let source = &request.canonical["request"];
    let text = |name: &str| source[name].as_str().ok_or("native compound canonical review text absent");
    let mut url = format!("{}://{}{}", text("scheme")?, text("authority")?, text("path")?);
    let query = canonical_request_query(request.canonical)?;
    let mut encoded = Vec::new();
    for (key, value) in query {
        let lower = key.to_lowercase();
        let sensitive = ["access_token", "api_key", "apikey", "auth", "authorization", "key", "token"].contains(&lower.as_str())
            || ["authorization", "password", "secret", "token"].iter().any(|part| lower.contains(part));
        encoded.push(format!("{}={}", quote_plus(&key), quote_plus(if sensitive { "redacted" } else { &value })));
    }
    if !encoded.is_empty() { url.push('?'); url.push_str(&encoded.join("&")); }
    require(url.len() <= 16 * 1024)?;
    let display = json!({"method":text("method")?, "url":url, "route_id":request.route.id,
        "principal":request.principal_id, "body_sha256":source["body_sha256"]});
    Ok((url, display))
}

fn validate_originals(wire: &Wire, request: &Claims<'_>) -> Result<(), String> {
    catchplate_decision_gate::native_secret_broker_v1::validate_release_jit_review_originals(
        wire.runtime_input.as_bytes(), wire.parent_request.as_bytes(), wire.child_request.as_bytes())?;
    let parent = object(&wire.parent_request)?;
    let arguments = object(field(&parent, "arguments")?.get())?;
    let quotas = expected_shared_release_authorization_quotas(request.route, request.principal_id,
        request.credential_ref, request.credential_version, request.operation)?;
    let actor = request.actor;
    require(actor == request.durable.actor_id)?;
    let expected = json!({
        "attempt_id":request.attempt_id, "flow_id":request.attempt_id,
        "principal_id":request.principal_id, "route_id":request.route.id,
        "credential_id":request.credential_ref.unwrap_or_default(), "credential_version":request.credential_version,
        "policy_hash":request.policy_hash, "request_digest":request.request_digest,
        "operation_digest":request.operation_digest, "operation_context":request.operation,
        "shared_quotas":quotas, "durable_policy_binding":request.durable,
        "require_jit_grant":true, "native_profile":true, "policy_aware_profile":false,
        "now_epoch_ms":null, "actor_id":actor, "authority_policy_hash":request.policy_hash,
        "authority_route_id":request.route.id, "expected_approver_policy_sha256":wire.approver_policy_sha256,
        "required_approver_roles":marshaled_set(&wire.approver_policy["requiredRoles"] )?,
        "allowed_approver_ids":marshaled_set(&wire.approver_policy["allowedApproverIds"] )?,
        "require_approver_webauthn":wire.approver_policy["requireWebAuthn"],
        "approval_threshold":wire.approver_policy["threshold"],
        "approver_credential_policy":wire.approver_policy["credentialPolicy"],
    });
    for (name, value) in expected.as_object().ok_or("native compound expected object")? {
        same(field(&arguments, name)?, value)?;
    }
    // reservation_ttl_seconds was bounded to1..300 by the pure raw validator.
    // It remains a signed CP claim; no independent cold TTL pin exists here.
    let child = object(field(&arguments, "jit_approval_request")?.get())?;
    for (name, value) in [
        ("method", json!(request.method)),
        ("pending_ttl_seconds", json!(route_uint(request.route, "pendingTtlSeconds", 300, Some(3600))?)),
        ("grant_ttl_seconds", json!(route_uint(request.route, "ttlSeconds", 30, Some(3600))?)),
        ("grant_max_uses", json!(route_uint(request.route, "maxUses", 1, None)?)),
    ] { same(field(&child, name)?, &value)?; }
    let runtime = object(&wire.runtime_input)?;
    let private = object(field(&runtime, "privateDocuments")?.get())?;
    let (url, display) = review_display(request)?;
    same(field(&private, "url")?, &json!(url))?;
    same(field(&private, "canonical_request")?, request.canonical)?;
    same(field(&private, "redacted_display")?, &display)
}

fn decode_wire(body: &[u8]) -> Result<Wire, String> {
    require(body.len() as u64 <= MAX_RESPONSE_BYTES && body.is_ascii())?;
    let wire: Wire = serde_json::from_slice(body)
        .map_err(|_| "native compound preparation response differs".to_owned())?;
    let canonical = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&wire)?);
    require(body == canonical.as_slice())?;
    Ok(wire)
}

fn validate_claims(wire: &Wire, claims: &Claims<'_>) -> Result<(), String> {
    require(wire.api_version == SCHEMA && wire.principal_id == claims.principal_id
        && wire.route_id == claims.route.id && wire.policy_hash == claims.policy_hash
        && wire.request_digest == claims.request_digest
        && wire.operation_digest == claims.operation_digest)?;
    route_policy(&wire.approver_policy, claims.route)?;
    require(native_policy_digest(&wire.approver_policy)? == wire.approver_policy_sha256)?;
    validate_originals(wire, claims)
}

impl UnadmittedPreparation<'_, '_> {
    fn check(&self) -> Result<(), String> {
        self.request.check()?;
        let response_original = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&self.wire)?);
        let request_original = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&self.request.payload()?)?);
        require(self.response.status == StatusCode::OK
            && self.response.body.len() as u64 <= MAX_RESPONSE_BYTES
            && self.response.body.as_slice() == response_original.as_slice()
            && self.response.request_body.as_slice() == request_original.as_slice()
            && self.response.authentication.key_id.as_str() == self.request.authentication.key_id
            && self.response.authentication.body_digest.as_str() == sha256_prefixed(&self.response.body)
            && self.response.authentication.statement.nonce.as_deref() == Some(self.response.response_nonce.as_str())
            && self.response.authentication.response_headers.iter().any(|header|
                header.name.as_str() == "cache-control" && header.value_b64.as_str() == "bm8tc3RvcmU"))?;
        validate_claims(&self.wire, &self.request.claims()?)?;
        self.request.check()
    }
}

/// Actual signed HTTP preparation and selected v26 custody, followed by one
/// pending-only submission. No success here can authorize provider dispatch.
/// The original request deadline is never restarted or installed on a shared
/// key/identity. No locks are acquired here across control-plane HTTP.
pub(super) fn prepare_and_submit<'state>(request: Request<'state, '_>,
    shadow: Option<&policy_core::ShadowRequestHandle>)
    -> Result<(RequestedReleaseAuthorization, ReleaseAuthorizationGuard<'state>), String> {
    request.check()?;
    let original_boottime_deadline = native_jit_review::freeze_deadline(request.deadline)?;
    let response = post_release_authorization_http_on_deadline(request.state, request.authentication,
        "native-jit-prepare", &request.payload()?, || {}, Some(request.deadline))?;
    request.check()?;
    require(response.status == StatusCode::OK)?;
    let wire = decode_wire(&response.body)?;
    let retained = UnadmittedPreparation { request, response, wire };
    retained.check()?;
    let evidence = native_jit_review::prepare(retained.request.state, retained.wire.runtime_input.as_bytes(),
        retained.wire.parent_request.as_bytes(), retained.wire.child_request.as_bytes(),
        retained.request.deadline, original_boottime_deadline)?;
    retained.check()?;
    // Submission consumes neither an invented pair nor cloned/resealed proof.
    // Both retained owners stay live through the one POST and final checks.
    submission::submit(retained, evidence, original_boottime_deadline, shadow)
}

#[cfg(test)]
#[path = "native_release_jit_preparation_tests.rs"]
mod tests;
