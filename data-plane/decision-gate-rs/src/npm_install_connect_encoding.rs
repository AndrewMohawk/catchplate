//! Narrow outer-CONNECT compatibility for npm's cached proxy-agent headers.
//! There is no encoded CONNECT body, decompression, or grant in this exception.
use super::*;

const AUTHORITY: &str = "registry.npmjs.org:443";
const REFUSED: &str = "npm_install_connect_encoding_denied";

fn ordinary_runtime(state: &GateState, snapshot: &Arc<Snapshot>) -> bool {
    state.policy_shadow.is_operator_demo()
        && !state.is_production
        && snapshot.policy_id == "catchplate-operator-demo"
        && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
        && state.proxy_ingress_attestation.mode == operator_demo::INGRESS_MODE
        && state.native_serving_privileges.is_none()
        && state.native_secret_broker.is_none()
        && state.native_policy_bytes.is_none()
        && state.native_runtime_lifetime.is_none()
        && state.native_upstream_relays.is_none()
        && state.native_enrollment_authorizer.is_none()
        && state.measured_refresh.is_none()
        && state.measured_cleanup.is_none()
        && state.measured_pending_retirement.is_none()
        && state.measured_capture_retirement.is_none()
        && state.measured_issuance.is_none()
        && state.measured_setup.is_none()
        && state.measured_static_credential.is_none()
        && state.measured_static_credential_rotation.is_none()
        && state.measured_reconnect.is_none()
        && state.measured_succession.is_none()
        && state.measured_audit.is_none()
        && state.measured_canary_delivery.is_none()
        && state.policy_shadow_generation_control.is_none()
        && !state.atomic_release_authorization_enabled
        && !state.credential_currentness.enabled()
        && state.credential_lease_recipient_attestation_command.is_none()
        && snapshot_is_active(state, snapshot)
        && policy_trust_is_fresh(state)
}

fn audit_route(route: &Route) -> bool {
    route.adapter_type == npm_install::ADAPTER
        && route.adapter_config["mode"] == "audit"
        && npm_install::validate_route(route).is_ok()
}

/// Syntax selection only. Authentication and this principal's exact grant are
/// checked again below; a signed route for somebody else supplies no authority.
pub(super) fn allows_intake(
    state: &GateState, snapshot: &Arc<Snapshot>, management_listener: bool,
) -> bool {
    !management_listener && ordinary_runtime(state, snapshot)
        && snapshot.routes.iter().any(audit_route)
}

pub(super) fn permits_head(
    method: &str, target: &str, headers: &BTreeMap<String, String>,
    content_length: usize, has_content_length: bool, prefetched_body: &[u8],
) -> bool {
    method == "CONNECT" && target == AUTHORITY
        && headers.get("host").map(String::as_str) == Some(AUTHORITY)
        && headers.get("content-encoding").map(String::as_str) == Some("gzip")
        && !headers.contains_key("transfer-encoding")
        && content_length == 0 && prefetched_body.is_empty()
        && has_content_length == headers.contains_key("content-length")
        && headers.get("content-length").is_none_or(|value| value == "0")
}

/// Called only after the actual CONNECT preflight and identity capture, before
/// TLS configuration or its 200 response. No outer header becomes an inner grant.
pub(super) fn require_authenticated(
    state: &GateState, snapshot: &Arc<Snapshot>, request: &IncomingRequest,
    authentication: &ConnectAuthentication,
) -> Result<(), &'static str> {
    if validate_identity_request_content_encoding(&request.headers).is_ok() {
        return Ok(());
    }
    if !ordinary_runtime(state, snapshot)
        || !request.body.is_empty()
        || !permits_head(&request.method, &request.target, &request.headers, 0,
            request.headers.contains_key("content-length"), &request.body)
    { return Err(REFUSED); }
    let principal = authentication.revalidate(snapshot).map_err(|_| REFUSED)?;
    let now = now_epoch_ms();
    if !matches!(&principal.proxy_authorization,
        Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms: Some(expiry), .. })
            if *expiry > now)
        || !matches!(&authentication.proxy_authorization_binding,
            Some(ConnectProxyAuthorizationBinding::BearerTokenSha256(_)
                | ConnectProxyAuthorizationBinding::BasicTransportTokenSha256 { .. }))
        || authentication.client_ip != request.client_ip
        || !principal.matches_at(request.client_ip.as_deref(), &request.headers,
            authentication.trusted_mtls_evidence.as_ref(), now)
    { return Err(REFUSED); }
    for route in snapshot.routes.iter().filter(|route| audit_route(route)
        && route.principals.iter().any(|id| id == &principal.id || id == "*"))
    {
        if state.policy_shadow.operator_effect_permit(snapshot, &route.id)
            .ok().flatten().is_some_and(|permit| permit.validate(&snapshot.hash).is_ok())
        {
            return Ok(());
        }
    }
    Err(REFUSED)
}
