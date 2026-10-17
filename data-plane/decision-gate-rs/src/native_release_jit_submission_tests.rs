//! Component wire/denial controls, not native owner, custody, HTTP or SQL
//! acceptance. Historical actual-ASGI originals exercise byte preservation;
//! the pending response below is an explicitly synthetic contract oracle.
use super::*;
use super::super::tests::Fixture;

const DOCUMENT: u64 = 2_000_000_000_123_456_789;
fn now() -> OffsetDateTime { OffsetDateTime::from_unix_timestamp(1_999_999_900).unwrap() }
fn expected_fixture(f: &Fixture) -> Expected {
    let wire = decode_wire(&f.body).unwrap();
    validate_claims(&wire, &f.claims()).unwrap();
    expected(&f.claims(), &wire.approver_policy, &wire.child_request, DOCUMENT).unwrap()
}
fn response(f: &Fixture, expected: &Expected) -> Value {
    json!({"apiVersion":"catchplate.nativeReleaseAuthorizationResponse/v2", "ok":true,
        "authorized":false,"state":"denied","reason":"jit_grant_unavailable",
        "attemptId":f.request["attemptId"],"bindingDigest":expected.binding,"idempotentReplay":false,
        "grantId":null,"approvalRequestId":expected.approval_id,"approvalStatus":"pending",
        "approvalExpiresAt":"2033-05-18T03:33:20.123456+00:00","approvalCreated":true,
        "reservationExpiresAtEpochMs":null,"dispatchStartedAtEpochMs":null,"dispatchExpiresAtEpochMs":null,
        "completionOutcome":null,"retryAfterSeconds":3,"quotas":[],"store":{"backend":"postgres","ha":true},
        "durablePolicy":{"state":"denied","attemptId":f.request["attemptId"],"claimDigest":f.durable.claim_digest,
            "actorId":f.durable.actor_id,"reservationId":null,"reservationDeadlineAtEpochMs":null,
            "dispatchDeadlineAtEpochMs":null,"responseEvidenceDigest":null,"failureReason":null,
            "responseBodySha256":null,"uncertainty":null}})
}
fn bytes(value: &Value) -> Vec<u8> { native_response_profile::canonical_ascii_bytes(value).unwrap() }
fn check(f: &Fixture, e: &Expected, value: &Value) -> Result<(), String> {
    validate_pending(&bytes(value), f.request["attemptId"].as_str().unwrap(), e, now())
}

#[test]
fn literal_originals_and_actual_escaped_aggregate_are_bounded() {
    let f = Fixture::load(); let wire = decode_wire(&f.body).unwrap();
    let parent = "{\"integer\":184467440737095516160,\"number\":1e-07}";
    let encoded = payload(&wire.runtime_input, parent, &wire.child_request, "{}", "{}").unwrap();
    assert_eq!(encoded["parentOriginal"], parent);
    assert_eq!(encoded["runtimeOriginal"], wire.runtime_input.as_str());
    assert_eq!(encoded.as_object().unwrap().len(), 6);
    assert_eq!(encoded["schema"], SCHEMA);
    assert!(payload("", parent, "{}", "{}", "{}").is_err());
    assert!(payload("é", parent, "{}", "{}", "{}").is_err());
    assert!(payload(&"x".repeat(512 * 1024 + 1), parent, "{}", "{}", "{}").is_err());
    // Every individual original fits; their JSON-escaped total does not.
    let half = "\\".repeat(512 * 1024); let whole = "\\".repeat(1024 * 1024);
    assert!(payload(&half, &half, &half, &whole, "{}").is_err());
}

#[test]
fn exact_pending_response_is_denial_not_a_release() {
    let f = Fixture::load(); let e = expected_fixture(&f); let value = response(&f, &e);
    check(&f, &e, &value).unwrap();
    let parsed = parse_release_authorization_response(&bytes(&value), NATIVE_RELEASE_AUTHORIZATION_RESPONSE_V2).unwrap();
    assert!(!parsed.authorized && parsed.grant_id.is_none() && parsed.quotas.is_empty());
    assert!(parsed.reservation_expires_at_epoch_ms.is_none());
    assert!(validated_durable_policy_reservation(parsed.durable_policy.as_ref(), Some(&e.durable)).unwrap().is_none());
}

#[test]
fn grant_reservation_replay_identity_and_durable_substitutions_fail() {
    let f = Fixture::load(); let e = expected_fixture(&f); let valid = response(&f, &e);
    for (name, changed) in [("authorized", json!(true)), ("state", json!("reserved")),
        ("reason", json!("jit_grant_expired")), ("grantId", json!("grant")),
        ("reservationExpiresAtEpochMs", json!(2_000_000_000_123u64)),
        ("dispatchStartedAtEpochMs", json!(1)), ("dispatchExpiresAtEpochMs", json!(2)),
        ("completionOutcome", json!("not_forwarded")), ("approvalStatus", json!("approved")),
        ("approvalCreated", json!(false)), ("idempotentReplay", json!(true)),
        ("retryAfterSeconds", json!(4)), ("approvalRequestId", json!("another")),
        ("attemptId", json!(format!("sha256:{}", "0".repeat(64)))),
        ("bindingDigest", json!(format!("sha256:{}", "0".repeat(64))))] {
        let mut bad = valid.clone(); bad[name] = changed; assert!(check(&f, &e, &bad).is_err(), "{name}");
    }
    for (name, changed) in [("actorId", json!("different-actor")), ("claimDigest", json!(format!("sha256:{}", "0".repeat(64)))),
        ("state", json!("reserved")), ("reservationId", json!("reserved")),
        ("reservationDeadlineAtEpochMs", json!(1)), ("dispatchDeadlineAtEpochMs", json!(1)),
        ("responseEvidenceDigest", json!("digest")), ("failureReason", json!("reason")),
        ("responseBodySha256", json!("digest")), ("uncertainty", json!("unknown"))] {
        let mut bad = valid.clone(); bad["durablePolicy"][name] = changed;
        assert!(check(&f, &e, &bad).is_err(), "durable {name}");
    }
}

#[test]
fn response_is_closed_duplicate_free_typed_and_store_bound() {
    let f = Fixture::load(); let e = expected_fixture(&f); let valid = response(&f, &e);
    for path in ["", "durablePolicy", "store"] {
        let mut bad = valid.clone(); let target = if path.is_empty() { &mut bad } else { &mut bad[path] };
        target["future"] = json!(true); assert!(check(&f, &e, &bad).is_err());
    }
    for name in ["grantId", "approvalCreated", "durablePolicy"] {
        let mut bad = valid.clone(); bad.as_object_mut().unwrap().remove(name);
        assert!(check(&f, &e, &bad).is_err());
    }
    for (name, changed) in [("ok", json!(1)), ("authorized", Value::Null), ("approvalCreated", json!(1)),
        ("retryAfterSeconds", json!(true)), ("apiVersion", json!("catchplate.releaseAuthorizationResponse/v2"))] {
        let mut bad = valid.clone(); bad[name] = changed; assert!(check(&f, &e, &bad).is_err());
    }
    let mut bad = valid.clone(); bad["store"]["backend"] = json!("sqlite"); assert!(check(&f, &e, &bad).is_err());
    let mut bad = valid.clone(); bad["store"]["ha"] = json!(false); assert!(check(&f, &e, &bad).is_err());
    let encoded = String::from_utf8(bytes(&valid)).unwrap();
    let duplicate = encoded.replacen("{", "{\"ok\":false,", 1);
    assert!(validate_pending(duplicate.as_bytes(), f.request["attemptId"].as_str().unwrap(), &e, now()).is_err());
}

#[test]
fn pending_expiry_uses_original_document_microseconds_without_renewal() {
    let f = Fixture::load(); let e = expected_fixture(&f); let valid = response(&f, &e);
    for changed in ["2033-05-18T03:33:20.123457+00:00", "2033-05-18T03:33:20.123455+00:00",
        "2033-05-18T03:33:20.123456789+00:00", "not-a-time"] {
        let mut bad = valid.clone(); bad["approvalExpiresAt"] = json!(changed);
        assert!(check(&f, &e, &bad).is_err());
    }
    let expired = OffsetDateTime::from_unix_timestamp_nanos(i128::from(DOCUMENT / 1000) * 1000).unwrap();
    assert!(validate_pending(&bytes(&valid), f.request["attemptId"].as_str().unwrap(), &e, expired).is_err());
}

#[test]
fn business_binding_changes_for_each_actual_caller_scope_and_child_id() {
    let f = Fixture::load(); let e = expected_fixture(&f); let wire = decode_wire(&f.body).unwrap();
    for name in ["principalId", "routeId", "credentialRef", "credentialVersion", "policyHash", "requestDigest", "operationDigest"] {
        let mut other = Fixture::load();
        if name == "routeId" { other.route.id.push_str("-changed"); }
        else if name == "credentialVersion" { other.request[name] = json!(999); }
        else { other.request[name] = json!("changed"); }
        let changed = expected(&other.claims(), &wire.approver_policy, &wire.child_request, DOCUMENT).unwrap();
        assert_ne!(e.binding, changed.binding, "{name}");
    }
    let child = object(&wire.child_request).unwrap();
    let digest: String = serde_json::from_str(child["requestDigest"].get()).unwrap();
    assert_eq!(approval_id(&digest).unwrap(), e.approval_id);
    assert_eq!(&e.approval_id[14..15], "5");
    assert!(matches!(&e.approval_id[19..20], "8" | "9" | "a" | "b"));
    assert_ne!(approval_id(&format!("sha256:{}", "0".repeat(64))).unwrap(), e.approval_id);
    assert!(approval_id("not-a-digest").is_err());
}

#[test]
fn signed_headers_are_exact_unique_and_never_secret_bearing() {
    let header = |name: &str, value: &str| ControlPlaneAuthorizationReceiptResponseHeader {
        name: SensitiveString::new(name.to_owned()), value_b64: SensitiveString::new(general_purpose::URL_SAFE_NO_PAD.encode(value)) };
    signed_headers(&[header("cache-control", "no-store"), header("content-type", "application/json")]).unwrap();
    for extra in [header("cache-control", "public"), header("content-type", "application/json"),
        header("set-cookie", "private"), header("authorization", "private")] {
        assert!(signed_headers(&[header("cache-control", "no-store"), header("content-type", "application/json"), extra]).is_err());
    }
    assert!(signed_headers(&[header("cache-control", "no-store")]).is_err());
}

#[test]
fn pending_guard_cannot_dispatch_or_complete_and_disarms_as_denial() {
    let state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
    let mut guard = ReleaseAuthorizationGuard::new(&state, ReleaseAuthorizationReservation {
        profile: ReleaseProfile::Legacy, preparation: None, attempt_id: "attempt".to_owned(),
        binding_digest: "binding".to_owned(), principal_id: "principal".to_owned(), route_id: "route".to_owned(),
        credential_id: String::new(), credential_version: 0, policy_hash: "policy".to_owned(), request_digest: "request".to_owned(),
        operation_digest: None, operation_context: None, grant_id: None, approval_request_id: Some("approval".to_owned()),
        reservation_expires_at_epoch_ms: None, shared_quotas: Vec::new(), durable_policy: None,
        dispatch_started_at_epoch_ms: None, dispatch_expires_at_epoch_ms: None });
    // Test-only construction of a non-authorizing lifecycle stage, not a
    // manufactured native owner or authenticated pending response.
    guard.stage = ReleaseAuthorizationStage::PendingOnly;
    assert!(guard.dispatch(&current_snapshot(&state)).is_err());
    assert!(guard.complete("not_forwarded", None).is_err());
    assert!(guard.retained_completion.is_none());
    guard.disarm_validated_denial().unwrap();
    assert_eq!(guard.stage, ReleaseAuthorizationStage::Completed);
    assert_eq!(guard.terminal_releasable, Some(false));
}

#[test]
fn actual_submit_is_once_retains_deadlines_and_never_falls_back() {
    // Source wiring assertion only. No successful native/HTTP admission claim.
    let source = include_str!("native_release_jit_submission.rs");
    let flow = source.split("pub(super) fn submit").nth(1).unwrap();
    assert_eq!(flow.matches("post_release_authorization_http_on_deadline(").count(), 1);
    assert!(!flow.contains("native_jit_review::prepare("));
    assert!(flow.find("commit_shadow_release_effects(").unwrap() < flow.find("let response = result?").unwrap());
    assert!(flow.find("validate_pending(").unwrap() < flow.find("guard.stage = ReleaseAuthorizationStage::PendingOnly").unwrap());
    assert!(flow.contains("Some(deadline)"));
    assert!(flow.contains("original_boot"));
    let main = include_str!("main.rs");
    let http = main.split("fn post_release_authorization_http_on_deadline").nth(1).unwrap();
    assert!(http.find("submission::MAX_BODY_BYTES").unwrap() < http.find("request.send()").unwrap());
    assert!(http.contains("if deadline.is_some() || single_attempt || operation == \"reserve\""));
    let drop = main.split("impl Drop for ReleaseAuthorizationGuard").nth(1).unwrap();
    assert!(drop.find("if self.stage == ReleaseAuthorizationStage::PendingOnly { return; }").unwrap()
        < drop.find("self.complete(").unwrap());
}
