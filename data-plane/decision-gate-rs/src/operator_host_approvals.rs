//! Explicit host-trusted, one-use approval of an exact ordinary request.
//! A 428 ends the first request. Only an explicit identical client retry can
//! claim an approval; a lost claim response is never retried or refunded here.
use super::*;
use std::borrow::Cow;

const FLAG: &str = "CATCHPLATE_HOST_TRUSTED_APPROVALS_ENABLED";
const MARKER: &str = "hostTrustedApproval";
const POLICY: &str = "catchplate.hostTrustedApprovalPolicy/v1";
const REQUEST: &str = "catchplate.hostTrustedApprovalClaimRequest/v1";
const RESPONSE: &str = "catchplate.hostTrustedApprovalClaimResponse/v1";
const PATH: &str = "/api/data-plane/host-trusted-approvals/claim";
const ERROR: &str = "host_trusted_approval_unavailable";

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(ERROR.to_owned())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Marker {
    #[serde(rename = "type")]
    kind: String,
    schema: String,
    pending_ttl_seconds: u64,
    approval_ttl_seconds: u64,
}

pub(super) fn validate_marker(value: &Value) -> Result<(), String> {
    let marker: Marker = serde_json::from_value(value.clone()).map_err(|_| ERROR.to_owned())?;
    require(
        marker.kind == MARKER
            && marker.schema == POLICY
            && (30..=3600).contains(&marker.pending_ttl_seconds)
            && (1..=300).contains(&marker.approval_ttl_seconds),
    )
}

/// Typed providers keep their exact original envelope checks. This removes
/// only one independently validated marker, never another constraint.
pub(super) fn provider_constraints(values: &[Value]) -> Result<Cow<'_, [Value]>, String> {
    let mut found = false;
    for value in values.iter().filter(|value| value["type"] == MARKER) {
        require(!found)?;
        validate_marker(value)?;
        found = true;
    }
    Ok(if found {
        Cow::Owned(
            values
                .iter()
                .filter(|value| value["type"] != MARKER)
                .cloned()
                .collect(),
        )
    } else {
        Cow::Borrowed(values)
    })
}

pub(super) fn selected(route: &Route) -> bool {
    route
        .constraints
        .iter()
        .any(|value| value["type"] == MARKER)
}

fn compatible(
    constraints: &[Value],
    jit: bool,
    observation: bool,
    credential: bool,
    adapter: &str,
) -> Result<(), String> {
    provider_constraints(constraints)?;
    require(
        !jit && !observation
            && credential
            && matches!(
                adapter,
                "generic.rest"
                    | "gmail.read.v1"
                    | "npm.metadata.v1"
                    | "npm.install.v1"
                    | "npm.publish.v1"
                    | "x.app_read.v1"
                    | "x.post.v1"
                    | "alchemy.rpc_read.v1"
            )
            && !constraints.iter().any(|value| {
                matches!(
                    value["type"].as_str(),
                    Some(
                        "slidingWindowLimit"
                            | "weightedBudget"
                            | "traversalBudget"
                            | "responseBinding"
                    )
                ) || value["type"] == "rateLimit" && value["store"] == "shared"
            }),
    )
}

pub(super) fn validate_policy_route(route: &Value) -> Result<(), String> {
    compatible(
        route["constraints"].as_array().ok_or(ERROR)?,
        route.pointer("/jit/required") == Some(&Value::Bool(true)),
        route.get("responseObservation").is_some(),
        route["credentialRef"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        route
            .pointer("/adapter/type")
            .and_then(Value::as_str)
            .ok_or(ERROR)?,
    )
}

fn ordinary(state: &GateState) -> bool {
    state.host_trusted_approvals_enabled
        && !state.is_production
        && state.policy_shadow.is_operator_demo()
        && state.proxy_ingress_attestation.mode == operator_demo::INGRESS_MODE
        && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
        && !state.atomic_release_authorization_enabled
        && state.native_serving_privileges.is_none()
        && state.native_secret_broker.is_none()
        && state.native_runtime_lifetime.is_none()
        && state.native_policy_bytes.is_none()
        && state.policy_shadow_generation_control.is_none()
}

fn endpoint(state: &GateState) -> Result<Url, String> {
    let mut url = Url::parse(state.credential_lease_url.as_deref().ok_or(ERROR)?)
        .map_err(|_| ERROR.to_owned())?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/api/data-plane/credential-leases"
            && state
                .credential_lease_token
                .as_deref()
                .is_some_and(|value| !value.is_empty()),
    )?;
    url.set_path(PATH);
    Ok(url)
}

pub(super) fn configure(state: &mut GateState) -> Result<(), String> {
    state.host_trusted_approvals_enabled = match env::var(FLAG).as_deref() {
        Ok("1") => true,
        Ok("0") | Err(env::VarError::NotPresent) => false,
        _ => return Err(ERROR.to_owned()),
    };
    if state.host_trusted_approvals_enabled {
        require(ordinary(state))?;
        endpoint(state)?;
    }
    Ok(())
}

pub(super) fn capability(state: &GateState) -> Value {
    json!({"schema":"catchplate.hostTrustedApprovalRuntime/v1", "enabled":ordinary(state),
        "claim_request_version":REQUEST, "claim_response_version":RESPONSE})
}

pub(super) fn admit(state: &GateState, route: &Route) -> Result<bool, String> {
    if !selected(route) {
        return Ok(false);
    }
    compatible(
        &route.constraints,
        route.jit.get("required") == Some(&Value::Bool(true)),
        route.response_observation.is_some(),
        route
            .credential_ref
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        &route.adapter_type,
    )?;
    require(ordinary(state))?;
    Ok(true)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Outcome {
    api_version: String,
    status: String,
    approval_id: String,
    request_digest: String,
    operation_digest: String,
    pub(super) attempt_id: String,
    policy_hash: String,
    expires_at_epoch_ms: u64,
}

impl Outcome {
    pub(super) fn claimed(&self) -> bool {
        self.status == "claimed"
    }

    fn validate(&self, request: &Value, now: u128) -> Result<(), String> {
        let id = self.approval_id.as_bytes();
        require(
            id.len() == 36
                && id.iter().enumerate().all(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        *c == b'-'
                    } else {
                        c.is_ascii_digit() || (b'a'..=b'f').contains(c)
                    }
                })
                && id[14] == b'4'
                && matches!(id[19], b'8' | b'9' | b'a' | b'b'),
        )?;
        require(
            self.api_version == RESPONSE
                && matches!(
                    self.status.as_str(),
                    "pending" | "claimed" | "denied" | "expired" | "consumed"
                )
                && request["requestDigest"] == self.request_digest
                && request["operationDigest"] == self.operation_digest
                && request["attemptId"] == self.attempt_id
                && request["policyHash"] == self.policy_hash
                && (1..=9_007_199_254_740_991).contains(&self.expires_at_epoch_ms)
                && (!matches!(self.status.as_str(), "pending" | "claimed")
                    || now < u128::from(self.expires_at_epoch_ms)),
        )
    }

    pub(super) fn public(&self) -> Value {
        json!({"mode":"host_trusted", "status":self.status, "approval_id":self.approval_id,
            "attempt_id":self.attempt_id, "expires_at_epoch_ms":self.expires_at_epoch_ms})
    }

    pub(super) fn denial(&self, route: &Route, started: Instant) -> Value {
        let status = match self.status.as_str() {
            "pending" => 428,
            "denied" => 403,
            "expired" => 410,
            _ => 409,
        };
        let mut decision = deny_for_route(
            status,
            "Host-trusted request approval is required",
            json!({"error":"host_trusted_approval_required", "approval_id":self.approval_id,
                "approval_url":approval_url(&self.approval_id), "approval_status":self.status,
                "expires_at_epoch_ms":self.expires_at_epoch_ms,
                "retry_semantics":"explicit_identical_request_after_approval"}),
            route,
            started,
        );
        decision["action"] = json!("approval_required");
        decision["approval_id"] = json!(self.approval_id);
        decision["approval_url"] = json!(approval_url(&self.approval_id));
        decision["host_trusted_approval"] = self.public();
        decision
    }
}

pub(super) fn claim(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    route: &Route,
    principal_id: &str,
    credential_version: u64,
    canonical: &Value,
    request_digest: &str,
    operation_digest: &str,
) -> Result<Outcome, String> {
    require(admit(state, route)? && snapshot_is_active(state, snapshot))?;
    let attempt = random_request_attempt_id()?;
    let request = SensitiveJsonValue::new(json!({"apiVersion":REQUEST,
        "principalId":principal_id, "routeId":route.id, "credentialId":route.credential_ref,
        "credentialVersion":credential_version, "policyHash":snapshot.hash,
        "requestDigest":request_digest, "operationDigest":operation_digest,
        "attemptId":attempt, "canonicalRequest":canonical}));
    let body = Zeroizing::new(ReleaseProfile::Legacy.canonical_ascii_bytes(&*request)?);
    require(body.len() <= 64 * 1024 && credential_version > 0)?;
    // The configured internal client has redirects disabled. No transport or
    // HTTP-status retry: the server may already have irreversibly consumed it.
    let mut response = state
        .audit_client
        .post(endpoint(state)?)
        .header(
            "X-Catchplate-Data-Plane-Token",
            state.credential_lease_token.as_deref().ok_or(ERROR)?,
        )
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(3))
        .body(body.as_slice().to_vec())
        .send()
        .map_err(|_| ERROR.to_owned())?;
    require(response.status() == StatusCode::OK)?;
    let bytes = Zeroizing::new(read_bounded_control_plane_response_body(
        &mut response,
        8192,
        ERROR,
    )?);
    let outcome: Outcome = serde_json::from_slice(&bytes).map_err(|_| ERROR.to_owned())?;
    outcome.validate(&request, now_epoch_ms())?;
    require(snapshot_is_active(state, snapshot) && admit(state, route)?)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn marker() -> Value {
        json!({"type":MARKER,"schema":POLICY,
        "pendingTtlSeconds":300,"approvalTtlSeconds":60})
    }
    #[test]
    fn marker_is_closed_and_never_strips_other_constraints() {
        let envelope = json!({"type":"responseEnvelope"});
        assert_eq!(
            &*provider_constraints(&[envelope.clone(), marker()]).unwrap(),
            &[envelope]
        );
        assert!(provider_constraints(&[marker(), marker()]).is_err());
        let mut invalid = marker();
        invalid["phase"] = json!("response");
        assert!(validate_marker(&invalid).is_err());
        invalid = marker();
        invalid["pendingTtlSeconds"] = json!(true);
        assert!(validate_marker(&invalid).is_err());
        invalid = marker();
        invalid["approvalTtlSeconds"] = json!(301);
        assert!(validate_marker(&invalid).is_err());
    }
    #[test]
    fn claim_reply_is_exact_fresh_and_single_purpose() {
        let request = json!({"requestDigest":"request", "operationDigest":"operation",
            "attemptId":"attempt", "policyHash":"policy"});
        let mut reply = json!({"apiVersion":RESPONSE,"status":"claimed",
            "approvalId":"12345678-1234-4234-8234-123456789abc","requestDigest":"request",
            "operationDigest":"operation","attemptId":"attempt","policyHash":"policy",
            "expiresAtEpochMs":2000});
        let read = |value: &Value| serde_json::from_value::<Outcome>(value.clone()).unwrap();
        assert!(read(&reply).validate(&request, 1000).is_ok());
        assert!(read(&reply).validate(&request, 2000).is_err());
        reply["attemptId"] = json!("different");
        assert!(read(&reply).validate(&request, 1000).is_err());
        reply["attemptId"] = json!("attempt");
        reply["status"] = json!("consumed");
        assert!(!read(&reply).claimed());
        reply["allowed"] = json!(true);
        assert!(serde_json::from_value::<Outcome>(reply).is_err());
    }
}
