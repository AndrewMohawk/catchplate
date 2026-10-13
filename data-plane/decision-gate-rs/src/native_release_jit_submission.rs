//! One retained, native-custody-backed pending submission. This cannot mint a
//! reservation or release capability, including on an authenticated response.
use super::*;
use serverware_decision_gate::native_jit_review_v1::SignedReleasePair;

pub(crate) const PATH: &str = "/api/data-plane/release-authorizations/native-jit-submit";
pub(crate) const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const SCHEMA: &str = "serverware.nativeJitPendingSubmission/v1";

pub(crate) fn signed_headers(headers: &[ControlPlaneAuthorizationReceiptResponseHeader]) -> Result<(), String> {
    for (name, value) in [("cache-control", "no-store"), ("content-type", "application/json")] {
        let expected = general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
        let mut matches = headers.iter().filter(|header| header.name.as_str() == name);
        require(matches.next().is_some_and(|header| header.value_b64.as_str() == expected)
            && matches.next().is_none())?;
    }
    require(!headers.iter().any(|header|
        control_plane_authorization_receipt_header_is_secret_bearing(header.name.as_str())))
}

fn approval_id(child_digest: &str) -> Result<String, String> {
    require(is_sha256_digest(child_digest))?;
    let identity = json!({"schema":"serverware.policyAuthorityDeterministicIdentity/v1",
        "operation":"jit.request", "requestDigest":child_digest, "purpose":"jit-approval-request"});
    let digest = sha256_prefixed(&native_response_profile::canonical_ascii_bytes(&identity)?);
    let mut compact = digest[7..39].as_bytes().to_vec();
    compact[12] = b'5';
    let nibble = (compact[16] as char).to_digit(16).ok_or("native pending identity differs")?;
    compact[16] = b"0123456789abcdef"[((nibble & 3) | 8) as usize];
    let compact = std::str::from_utf8(&compact).map_err(|_| "native pending identity encoding")?;
    Ok(format!("{}-{}-{}-{}-{}", &compact[..8], &compact[8..12], &compact[12..16],
        &compact[16..20], &compact[20..]))
}

fn payload(runtime: &str, parent: &str, child: &str, pair: &str, evidence: &str)
    -> Result<SensitiveJsonValue, String> {
    for (original, limit) in [(runtime, 512 * 1024), (parent, 512 * 1024),
        (child, 512 * 1024), (pair, 1024 * 1024), (evidence, 128 * 1024)] {
        require(!original.is_empty() && original.is_ascii() && original.len() <= limit)?;
    }
    let value = SensitiveJsonValue::new(json!({"schema":SCHEMA,
        "runtimeOriginal":runtime, "parentOriginal":parent, "childOriginal":child,
        "pairOriginal":pair, "evidenceOriginal":evidence}));
    // Escaping the literal originals can exceed the sum of their raw lengths.
    // Check the actual canonical body, not an estimated plaintext length.
    let body = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&*value)?);
    require(body.len() <= MAX_BODY_BYTES)?;
    Ok(value)
}

struct Expected {
    binding: String,
    quotas: Vec<ReleaseAuthorizationBindingQuota>,
    durable: ReleaseAuthorizationDurablePolicyBinding,
    approval_id: String,
    document_expiry_ns: u64,
}

fn expected(claims: &Claims<'_>, policy: &Value, child: &str, document_expiry_ns: u64)
    -> Result<Expected, String> {
    let quotas = expected_shared_release_authorization_quotas(claims.route, claims.principal_id,
        claims.credential_ref, claims.credential_version, claims.operation)?;
    let binding = ReleaseAuthorizationBinding {
        api_version: release_binding_version(ReleaseProfile::Native, true),
        attempt_id: claims.attempt_id.to_owned(), flow_id: claims.attempt_id.to_owned(),
        principal_id: claims.principal_id.to_owned(), route_id: claims.route.id.clone(),
        credential_id: claims.credential_ref.unwrap_or_default().to_owned(),
        credential_version: claims.credential_version, policy_hash: claims.policy_hash.to_owned(),
        request_digest: claims.request_digest.to_owned(), operation_digest: Some(claims.operation_digest.to_owned()),
        operation_context: claims.operation.clone(), require_jit_grant: true,
        approver_policy: Some(policy.clone()), shared_quotas: quotas.clone(),
        durable_policy: Some(claims.durable.clone()),
    };
    let encoded = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&binding)?);
    require(encoded.len() <= MAX_RELEASE_AUTHORIZATION_CANONICAL_REQUEST_BYTES)?;
    // The caller has already validated this complete raw child through the
    // actual broker. Read only its scalar digest; never recanonicalize parent.
    let child = object(child)?;
    let child_digest: String = serde_json::from_str(field(&child, "requestDigest")?.get())
        .map_err(|_| "native pending child digest absent")?;
    Ok(Expected { binding: sha256_prefixed(&encoded), quotas, durable: claims.durable.clone(),
        approval_id: approval_id(&child_digest)?, document_expiry_ns })
}

fn validate_pending(body: &[u8], attempt: &str, expected: &Expected, now: OffsetDateTime)
    -> Result<(), String> {
    const FIELDS: &[&str] = &["apiVersion", "ok", "authorized", "state", "reason", "attemptId",
        "bindingDigest", "idempotentReplay", "grantId", "approvalRequestId", "approvalStatus",
        "approvalExpiresAt", "approvalCreated", "reservationExpiresAtEpochMs", "dispatchStartedAtEpochMs",
        "dispatchExpiresAtEpochMs", "completionOutcome", "retryAfterSeconds", "quotas", "store", "durablePolicy"];
    const DURABLE: &[&str] = &["state", "attemptId", "claimDigest", "reservationId", "actorId",
        "reservationDeadlineAtEpochMs", "dispatchDeadlineAtEpochMs", "responseEvidenceDigest",
        "failureReason", "responseBodySha256", "uncertainty"];
    // The existing API returns ordinary UTF-8 JSON; authentication binds those
    // exact bytes. Only the five outbound original strings require ASCII.
    require(body.len() as u64 <= MAX_CONTROL_PLANE_RELEASE_AUTHORIZATION_RESPONSE_BYTES)?;
    let raw = SensitiveJsonValue::new(strict_json_value_from_slice(body)
        .map_err(|_| "native pending JSON differs")?);
    require(raw.as_object().is_some_and(|v| object_has_exact_fields(v, FIELDS))
        && raw["durablePolicy"].as_object().is_some_and(|v| object_has_exact_fields(v, DURABLE))
        && raw["store"] == json!({"backend":"postgres", "ha":true}))?;
    let response = parse_release_authorization_response(body, NATIVE_RELEASE_AUTHORIZATION_RESPONSE_V2)?;
    validate_release_authorization_binding(&response, attempt, Some(&expected.binding))?;
    validate_reserve_release_authorization_response_at(&response, attempt, true, &expected.quotas,
        utc_epoch_ms(now)?)?;
    validate_reserve_durable_policy_response(response.durable_policy.as_ref(), Some(&expected.durable),
        attempt, response.authorized, response.reservation_expires_at_epoch_ms)?;
    require(response.ok && !response.authorized && response.state == "denied"
        && response.reason == "jit_grant_unavailable" && !response.idempotent_replay
        && response.approval_request_id.as_deref() == Some(expected.approval_id.as_str())
        && response.approval_status.as_deref() == Some("pending")
        && response.approval_created == Some(true) && response.retry_after_seconds == 3)?;
    let expiry = OffsetDateTime::parse(response.approval_expires_at.as_deref()
        .ok_or("native pending expiry absent")?, &Rfc3339).map_err(|_| "native pending expiry differs")?;
    require(expiry > now && expiry.unix_timestamp_nanos()
        == i128::from(expected.document_expiry_ns / 1000) * 1000)
}

fn check_lifetime(retained: &UnadmittedPreparation<'_, '_>, boot: u64, seal: u64)
    -> Result<(), String> {
    retained.check()?;
    require(native_canary_transport::boottime_ns()? < boot)?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native pending wall clock unavailable")?.as_nanos();
    require(wall < u128::from(seal))
}

pub(super) fn submit<'state>(retained: UnadmittedPreparation<'state, '_>, evidence: SignedReleasePair,
    original_boot: u64, shadow: Option<&policy_core::ShadowRequestHandle>)
    -> Result<(RequestedReleaseAuthorization, ReleaseAuthorizationGuard<'state>), String> {
    let pair = SensitiveJsonValue::new(strict_json_value_from_slice(evidence.pair_original().as_bytes())
        .map_err(|_| "native pending pair differs")?);
    let seal = pair["scope"]["sealExpiresAtEpochNs"].as_u64().ok_or("native pending seal absent")?;
    let document = pair["scope"]["documentExpiresAtEpochNs"].as_u64().ok_or("native pending document absent")?;
    check_lifetime(&retained, original_boot, seal)?;
    let expected = expected(&retained.request.claims()?, &retained.wire.approver_policy,
        &retained.wire.child_request, document)?;
    let payload = payload(&retained.wire.runtime_input, &retained.wire.parent_request,
        &retained.wire.child_request, evidence.pair_original(), evidence.proof_original())?;
    // This locally narrows the original request; sampling Instant first cannot
    // extend the signed wall-clock seal. Original BOOTTIME is still checked.
    let opening = Instant::now();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native pending wall clock unavailable")?.as_nanos();
    let remaining = u128::from(seal).checked_sub(wall).filter(|v| *v > 0)
        .ok_or("native pending seal expired")?;
    let deadline = retained.request.deadline.min(opening.checked_add(Duration::from_nanos(
        u64::try_from(remaining).map_err(|_| "native pending seal overflow")?))
        .ok_or("native pending deadline overflow")?);
    let mut permits = Vec::new();
    // These existing intent categories include the legacy pending outcome.
    // The result says pendingOnly; no grant/quota/budget reservation is claimed.
    for kind in [ActiveMutableEffectKind::ReleaseReserve, ActiveMutableEffectKind::JitGrantReserve] {
        prepare_shadow_release_effect(shadow, retained.request.snapshot, &mut permits, kind,
            "native-jit-submit", &json!({"domain":"serverware.nativeJitPendingIntent/v1",
                "attemptId":retained.request.attempt_id, "bindingDigest":expected.binding,
                "pendingOnly":true}), &payload)?;
    }
    let result = (|| {
        check_lifetime(&retained, original_boot, seal)?;
        post_release_authorization_http_on_deadline(retained.request.state, retained.request.authentication,
            "native-jit-submit", &payload, || {}, Some(deadline))
    })();
    // A lost ACK is terminal and recorded before any post-IO currentness check.
    let (status, commitment) = match result.as_ref() {
        Ok(response) => (ActiveEffectCommitState::Committed, json!({"pendingOnly":true,
            "status":response.status.as_u16(), "responseBodySha256":sha256_prefixed(&response.body)})),
        Err(_) => (ActiveEffectCommitState::OutcomeUnknown, json!({"pendingOnly":true,
            "outcome":"control-plane-outcome-unknown"})),
    };
    commit_shadow_release_effects(shadow, permits, status, "native-jit-submit", &commitment)?;
    check_lifetime(&retained, original_boot, seal)?;
    let response = result?;
    require(response.status == StatusCode::OK
        && response.request_body.as_slice() == native_response_profile::canonical_ascii_bytes(&*payload)?.as_slice()
        && response.authentication.key_id.as_str() == retained.request.authentication.key_id
        && response.authentication.body_digest.as_str() == sha256_prefixed(&response.body)
        && response.authentication.statement.nonce.as_deref() == Some(response.response_nonce.as_str()))?;
    validate_pending(&response.body, retained.request.attempt_id, &expected, OffsetDateTime::now_utc())?;
    check_lifetime(&retained, original_boot, seal)?;
    let request = &retained.request;
    // This stage is deliberately not Reserved, so neither Drop nor a later
    // dispatch/completion attempt can generate a legacy cleanup or release RPC.
    let mut guard = ReleaseAuthorizationGuard::new_authenticated(request.state, request.authentication.clone(),
        ReleaseAuthorizationReservation { profile: ReleaseProfile::Native, preparation: None,
            attempt_id: request.attempt_id.to_owned(), binding_digest: expected.binding.clone(),
            principal_id: request.principal_id.to_owned(), route_id: request.route.id.clone(),
            credential_id: request.credential_ref.unwrap_or_default().to_owned(), credential_version: request.credential_version,
            policy_hash: request.policy_hash.to_owned(), request_digest: request.request_digest.to_owned(),
            operation_digest: Some(request.operation_digest.to_owned()), operation_context: Some(request.operation.clone()),
            grant_id: None, approval_request_id: Some(expected.approval_id), reservation_expires_at_epoch_ms: None,
            shared_quotas: Vec::new(), durable_policy: None, dispatch_started_at_epoch_ms: None,
            dispatch_expires_at_epoch_ms: None });
    guard.stage = ReleaseAuthorizationStage::PendingOnly;
    guard.terminal_releasable = Some(false);
    if let Some(finalization) = shadow { guard.bind_shadow_effects(finalization, request.snapshot); }
    Ok((RequestedReleaseAuthorization { profile: ReleaseProfile::Native, response,
        expected_binding_digest: expected.binding, expected_quotas: expected.quotas,
        expected_durable_policy: Some(expected.durable) }, guard))
}

#[cfg(test)]
#[path = "native_release_jit_submission_tests.rs"]
mod tests;
