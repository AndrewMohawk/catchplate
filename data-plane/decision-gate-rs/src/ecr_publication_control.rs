//! Ordinary authenticated-client ECR staging, never review/admin authority.
//! Only the current configured client token is admitted: managed-renewal overlap
//! remains valid for its existing proxy uses, but not for staging publications.
//! The application rechecks catalog ownership, token digest and policy hash.
use super::*;
use std::sync::atomic::AtomicUsize;

pub(super) const PATH: &str = "/v1/ecr/publications";
const INTERNAL_PATH: &str = "/api/data-plane/ecr-publications/client";
const MAX_JSON: usize = 16 * 1024;
const MAX_PART: usize = 4 * 1024 * 1024;
const MAX_RESPONSE: u64 = 64 * 1024;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation { Create, Status, Manifest, Part, Submit, Activate }

impl Operation {
    fn maximum(self) -> usize {
        match self { Self::Status => 0, Self::Manifest | Self::Part => MAX_PART,
            Self::Create => MAX_JSON, Self::Submit | Self::Activate => 64 }
    }
    fn content_type(self) -> Option<&'static str> {
        match self { Self::Status => None, Self::Manifest | Self::Part => Some("application/octet-stream"),
            _ => Some("application/json") }
    }
    fn method(self) -> &'static str { if self == Self::Status { "GET" } else { "POST" } }
}

fn uuid(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    })
}

fn operation(method: &str, target: &str) -> Option<Operation> {
    let suffix = target.strip_prefix(PATH)?;
    let selected = if suffix.is_empty() { Operation::Create } else {
        let parts: Vec<&str> = suffix.strip_prefix('/')?.split('/').collect();
        if !uuid(parts[0]) { return None; }
        match parts.as_slice() {
            [_] => Operation::Status,
            [_, "manifest"] => Operation::Manifest,
            [_, "submit"] => Operation::Submit,
            [_, "activate"] => Operation::Activate,
            [_, "blobs", digest, "parts", offset] if digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && offset.parse::<u64>().is_ok_and(|number| number.to_string() == *offset) => Operation::Part,
            _ => return None,
        }
    };
    (method == selected.method()).then_some(selected)
}

pub(super) fn reserved(target: &str) -> bool {
    target.starts_with(PATH) || Url::parse(target).is_ok_and(|url| url.path().starts_with(PATH))
}

fn ordinary(state: &GateState) -> bool {
    proxy_basic_transport::admitted_runtime(state)
        && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
        && state.native_policy_bytes.is_none() && state.native_upstream_relays.is_none()
        && state.native_enrollment_authorizer.is_none() && state.native_jit_review.is_none()
        && state.measured_refresh.is_none() && state.measured_cleanup.is_none()
        && state.measured_pending_retirement.is_none() && state.measured_capture_retirement.is_none()
        && state.measured_issuance.is_none() && state.measured_setup.is_none()
        && state.measured_static_credential.is_none() && state.measured_static_credential_rotation.is_none()
        && state.measured_reconnect.is_none() && state.measured_succession.is_none()
        && state.measured_audit.is_none() && !state.credential_currentness.enabled()
        && state.credential_lease_recipient_attestation_command.is_none()
        && state.response_observation_v2_client.is_none()
}

fn endpoint(lease: Option<&str>, target: &str) -> Result<Url, ()> {
    let suffix = target.strip_prefix(PATH).ok_or(())?;
    let mut url = Url::parse(lease.ok_or(())?).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some() || url.query().is_some()
        || url.fragment().is_some() || url.path() != "/api/data-plane/credential-leases" { return Err(()); }
    url.set_path(&format!("{INTERNAL_PATH}{suffix}"));
    Ok(url)
}

fn admit(head: &mut RequestHead) -> Result<Operation, StatusCode> {
    let selected = operation(&head.method, &head.target).ok_or(StatusCode::BAD_REQUEST)?;
    if head.headers.keys().any(|name| name.starts_with("x-serverware-") || name.starts_with("remote-")
        || matches!(name.as_str(), "cookie" | "origin" | "x-forwarded-user" | "x-auth-request-user")) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if head.headers.contains_key("authorization") == head.headers.contains_key("proxy-authorization") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Existing principal matching owns both Basic decoding and Bearer hashing.
    // Never forward either client credential header to the application.
    if let Some(value) = head.headers.remove("authorization") {
        head.headers.insert("proxy-authorization".to_owned(), value);
    }
    if head.headers.get("proxy-authorization").is_none_or(|value| value.is_empty() || value.len() > 2048) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if head.headers.contains_key("content-encoding") || head.headers.contains_key("transfer-encoding")
        || head.headers.contains_key("expect")
        || head.has_content_length && head.headers.get("content-length") != Some(&head.content_length.to_string()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if head.content_length > selected.maximum() { return Err(StatusCode::PAYLOAD_TOO_LARGE); }
    if selected == Operation::Status {
        if head.headers.contains_key("content-type") { return Err(StatusCode::BAD_REQUEST); }
    } else if !head.has_content_length || head.content_length == 0
        || head.headers.get("content-type").map(String::as_str) != selected.content_type() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(selected)
}

struct Authentication { identity: ConnectAuthentication, token_sha256: String }

fn current_token(principal: &Principal, header: &str, now: u128) -> Option<String> {
    let policy @ ProxyAuthorizationPolicy::BearerToken { token_sha256, expires_at_ms: Some(expiry), .. }
        = principal.proxy_authorization.as_ref()? else { return None; };
    if *expiry <= now || *expiry > proxy_basic_transport::MAX_EXPIRY { return None; }
    let provided = policy.presented_token_binding(header)?;
    let provided = provided.token_sha256()?;
    constant_time_eq(provided, token_sha256).then(|| provided.to_owned())
}

fn authenticate(snapshot: &Snapshot, head: &RequestHead, now: u128) -> Result<Authentication, ()> {
    let header = head.headers.get("proxy-authorization").ok_or(())?;
    let mut selected = snapshot.principals.iter().filter_map(|principal| {
        if !principal.matches_at(head.client_ip.as_deref(), &head.headers, None, now)
            || principal.id.is_empty() || principal.id.len() > 512
            || !principal.id.bytes().all(|byte| (33..=126).contains(&byte)) { return None; }
        current_token(principal, header, now).map(|digest| (principal, digest))
    });
    let (principal, token_sha256) = selected.next().ok_or(())?;
    if selected.next().is_some() { return Err(()); }
    let identity = ConnectAuthentication::capture_at(snapshot, &principal.id,
        head.client_ip.as_deref(), &head.headers, now).map_err(|_| ())?;
    Ok(Authentication { identity, token_sha256 })
}

impl Authentication {
    fn revalidate(&self, snapshot: &Snapshot) -> Result<(), ()> {
        let principal = self.identity.revalidate(snapshot).map_err(|_| ())?;
        let Some(ProxyAuthorizationPolicy::BearerToken { token_sha256, .. }) = &principal.proxy_authorization
            else { return Err(()); };
        // Reject overlap tokens even when ConnectAuthentication deliberately
        // permits them for an existing managed-renewal CONNECT session.
        if !constant_time_eq(token_sha256, &self.token_sha256) { return Err(()); }
        Ok(())
    }
}

struct Slot;
impl Slot {
    fn acquire() -> Option<Self> {
        ACTIVE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < 4).then_some(active + 1)).ok().map(|_| Self)
    }
}
impl Drop for Slot { fn drop(&mut self) { ACTIVE.fetch_sub(1, Ordering::AcqRel); } }

fn response(status: StatusCode, body: Vec<u8>) -> Vec<u8> {
    http_binary_response_with_headers(status, Some("application/json"), body,
        &[("Cache-Control".to_owned(), "no-store".to_owned()),
          ("Pragma".to_owned(), "no-cache".to_owned()),
          ("X-Content-Type-Options".to_owned(), "nosniff".to_owned())])
}
fn refusal(status: StatusCode) -> Vec<u8> {
    response(status, br#"{"error":"ecr_publication_refused"}"#.to_vec())
}

fn body_valid(selected: Operation, raw: &[u8]) -> bool {
    if raw.len() > selected.maximum() { return false; }
    match selected {
        Operation::Status => raw.is_empty(),
        Operation::Manifest | Operation::Part => !raw.is_empty(),
        _ => sensitive_json_value_from_slice(raw).is_ok_and(|value| value.as_object()
            .is_some_and(|object| selected == Operation::Create || object.is_empty())),
    }
}

fn forward(state: &GateState, snapshot: &Arc<Snapshot>, authentication: &Authentication,
        selected: Operation, target: &str, raw: &[u8], deadline: Instant) -> Result<Vec<u8>, ()> {
    let url = endpoint(state.credential_lease_url.as_deref(), target)?;
    let token = state.credential_lease_token.as_deref().filter(|value| !value.is_empty()).ok_or(())?;
    AttestedResponseAuthenticationContext::from_snapshot(snapshot, "ECR publication control").map_err(|_| ())?;
    authentication.revalidate(snapshot)?;
    if !snapshot_is_active(state, snapshot) { return Err(()); }
    let nonce = fresh_control_plane_response_nonce().map_err(|_| ())?;
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let client = control_plane_client_builder(remaining).map_err(|_| ())?
        .no_proxy().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())
        .http1_only().build().map_err(|_| ())?;
    let method = reqwest::Method::from_bytes(selected.method().as_bytes()).map_err(|_| ())?;
    let mut request = client.request(method, url.clone())
        .header("X-Serverware-Data-Plane-Token", token)
        .header("X-Serverware-Principal-Id", &authentication.identity.principal_id)
        .header("X-Serverware-Client-Token-Sha256", &authentication.token_sha256)
        .header("X-Serverware-Policy-Hash", &snapshot.hash)
        .header("X-Serverware-Response-Nonce", &nonce);
    if let Some(content_type) = selected.content_type() {
        request = request.header("Content-Type", content_type).body(raw.to_vec());
    }
    // No publication lock spans the owner transaction; the application checks
    // current catalog token/ownership and the exact signed policy hash again.
    authentication.revalidate(snapshot)?;
    if !snapshot_is_active(state, snapshot) { return Err(()); }
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let mut reply = request.timeout(remaining).send().map_err(|_| ())?;
    let status = reply.status();
    if reply.headers().get_all("content-type").iter().count() != 1
        || reply.headers().get("content-type").and_then(|value| value.to_str().ok()) != Some("application/json")
        || reply.headers().contains_key("content-encoding") { return Err(()); }
    let body = Zeroizing::new(read_bounded_control_plane_response_body(&mut reply, MAX_RESPONSE,
        "ECR publication control").map_err(|_| ())?);
    if Instant::now() >= deadline { return Err(()); }
    verify_control_plane_signed_response(snapshot, url.as_str(), selected.method(), &nonce,
        status, reply.headers(), &body, "ECR publication control").map_err(|_| ())?;
    if !matches!(status.as_u16(), 200 | 201 | 202) {
        return Ok(refusal(match status.as_u16() {
            400 | 401 | 403 | 404 | 408 | 409 | 413 | 415 | 422 | 429 => status,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }));
    }
    if !sensitive_json_value_from_slice(&body).map_err(|_| ())?.is_object() { return Err(()); }
    Ok(response(status, body.to_vec()))
}

pub(super) fn handle(state: &GateState, mut head: RequestHead, stream: &mut DirectProxyStream,
        management: bool, ingress: &ProxyIngressConfig) {
    let deadline = Instant::now() + Duration::from_secs(15);
    stream.restrict_operation_deadline(deadline);
    stream.reset_read_deadline(Duration::from_secs(5));
    stream.set_terminal_write_deadline(Some(deadline));
    let result = (|| {
        if management || !matches!(ingress, ProxyIngressConfig::OperatorDemoTlsEdge) || !ordinary(state) {
            return refusal(StatusCode::FORBIDDEN);
        }
        let selected = match admit(&mut head) { Ok(value) => value, Err(status) => return refusal(status) };
        let Some(_slot) = Slot::acquire() else { return refusal(StatusCode::TOO_MANY_REQUESTS); };
        if refresh_policy_snapshot(state, false).is_err() { return refusal(StatusCode::SERVICE_UNAVAILABLE); }
        let snapshot = current_snapshot(state);
        if !snapshot_is_active(state, &snapshot) { return refusal(StatusCode::SERVICE_UNAVAILABLE); }
        let authentication = match authenticate(&snapshot, &head, now_epoch_ms()) {
            Ok(value) => value, Err(()) => return refusal(StatusCode::UNAUTHORIZED),
        };
        let request = match read_request_body_from_head(stream, head, selected.maximum() as u64) {
            Ok(value) => value, Err(_) => return refusal(StatusCode::BAD_REQUEST),
        };
        if !body_valid(selected, &request.body) { return refusal(StatusCode::UNPROCESSABLE_ENTITY); }
        if refresh_policy_snapshot(state, false).is_err() { return refusal(StatusCode::SERVICE_UNAVAILABLE); }
        let snapshot = current_snapshot(state);
        if authentication.revalidate(&snapshot).is_err() { return refusal(StatusCode::UNAUTHORIZED); }
        forward(state, &snapshot, &authentication, selected, &request.target, &request.body, deadline)
            .unwrap_or_else(|_| refusal(StatusCode::SERVICE_UNAVAILABLE))
    })();
    let _ = stream.write_all(&result);
    let _ = stream.flush();
}

#[cfg(test)]
#[path = "ecr_publication_control_tests.rs"]
mod tests;
