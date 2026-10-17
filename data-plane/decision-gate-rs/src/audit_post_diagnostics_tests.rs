use super::super::tests::{test_gate_state, test_snapshot};
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::header::HeaderValue;
use serde_json::{json, Value};

fn raw_headers(bytes: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-catchplate-response-statement-b64",
        HeaderValue::from_str(&general_purpose::URL_SAFE_NO_PAD.encode(bytes)).unwrap(),
    );
    headers
}

fn headers(context: Value) -> HeaderMap {
    raw_headers(&serde_json::to_vec(&json!({"context": context})).unwrap())
}

fn context(snapshot: &Snapshot) -> Value {
    json!({"runtime_manifest_digest": "sha256:synthetic-runtime", "policy_bundle_digest": snapshot.hash,
        "provenance_digest": null, "image_signatures_digest": null, "source_tree_digest": null})
}

fn signed_headers(snapshot: &Snapshot, key: &SigningKey, context: Value) -> (HeaderMap, String) {
    use super::super::{
        canonical_json_ensure_ascii, control_plane_response_headers_binding, now_epoch_ms,
        sha256_prefixed,
    };
    let mut headers = HeaderMap::new();
    let nonce = general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]);
    let (headers_digest, header_count) = control_plane_response_headers_binding(&headers).unwrap();
    let body_digest = sha256_prefixed(b"{}");
    let key_id = snapshot.response_signing_key_id.as_ref().unwrap();
    let statement = canonical_json_ensure_ascii(&json!({
        "version": "catchplate.responseSignature/v3", "issued_at_ms": now_epoch_ms() as u64,
        "request": {"method": "POST", "path": "/api/data-plane/audit", "query_sha256": sha256_prefixed(b"")},
        "status_code": 200, "body_sha256": body_digest, "response_headers_sha256": headers_digest,
        "response_header_count": header_count, "nonce": nonce, "response_signing_key_id": key_id, "context": context,
    }));
    for (name, value) in [
        ("x-catchplate-response-key-id", key_id.clone()),
        ("x-catchplate-response-body-sha256", body_digest),
        (
            "x-catchplate-response-statement-sha256",
            sha256_prefixed(statement.as_bytes()),
        ),
        (
            "x-catchplate-response-statement-b64",
            general_purpose::URL_SAFE_NO_PAD.encode(statement.as_bytes()),
        ),
        (
            "x-catchplate-response-signature",
            format!(
                "ed25519:{}",
                general_purpose::URL_SAFE_NO_PAD.encode(key.sign(statement.as_bytes()).to_bytes())
            ),
        ),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).unwrap());
    }
    (headers, nonce)
}

#[test]
fn audit_diagnostic_never_formats_untrusted_error_message() {
    let secret = "https://private.invalid/?token=DO-NOT-PRINT\nHEADER:secret";
    for error in [
        AuditPostError::not_sent(secret),
        AuditPostError::other(secret),
        AuditPostError::local_too_large(secret),
        AuditPostError::authenticated_too_large(secret),
    ] {
        for phase in [Phase::Initial, Phase::Retry] {
            let output = line(&error, phase);
            assert!(!output.contains("private.invalid"));
            assert!(!output.contains("DO-NOT-PRINT"));
            assert!(!output.contains("secret"));
            assert!(!output.contains('\n'));
            assert!(output.is_ascii() && output.len() <= 320);
            assert!(output.contains("stage=unclassified"));
        }
    }
}

#[test]
fn audit_diagnostic_all_stage_labels_and_largest_fields_are_bounded() {
    for stage in [
        Stage::Unclassified,
        Stage::Preflight,
        Stage::Transport,
        Stage::ResponseBody,
        Stage::ServiceLifetime,
        Stage::SnapshotNotCurrent,
        Stage::SnapshotChanged,
        Stage::ResponseStatementParse,
        Stage::ResponseContextParse,
        Stage::ResponseContextPolicyMismatch,
        Stage::ResponseContextOtherMismatch,
        Stage::ResponseVerificationOther,
        Stage::HttpStatus,
        Stage::AckParse,
        Stage::AckInstanceMismatch,
        Stage::AckCountMismatch,
        Stage::AckDigestMismatch,
        Stage::AckContractMismatch,
    ] {
        let mut error = AuditPostError::authenticated_too_large("not emitted");
        error.diagnostic = Some(Diagnostic {
            stage,
            event_count: Some(u64::MAX),
            status: Some(u16::MAX),
            elapsed_ms: Some(u64::MAX),
            same_snapshot: Some(false),
            same_policy_sequence: Some(false),
        });
        let output = line(&error, Phase::Initial);
        assert!(output.len() <= 320 && output.is_ascii());
        assert_eq!(output.split_whitespace().count(), 9);
        assert!(!output.contains("not emitted"));
    }
}

#[test]
fn audit_diagnostic_preserves_error_kind_message_and_size_semantics() {
    let state = test_gate_state(test_snapshot(1));
    let attempt = Attempt::new(&state, 2);
    for original in [
        AuditPostError::not_sent("local"),
        AuditPostError::other("uncertain"),
        AuditPostError::local_too_large("local-size"),
        AuditPostError::authenticated_too_large("signed-size"),
    ] {
        let kind = original.kind;
        let message = original.message.clone();
        let size = original.request_too_large();
        let annotated = attempt.failure(Stage::Preflight, original);
        assert_eq!(annotated.kind, kind);
        assert_eq!(annotated.message, message);
        assert_eq!(annotated.request_too_large(), size);
    }
}

#[test]
fn audit_diagnostic_preflight_does_not_claim_http_or_snapshot_observation() {
    let state = test_gate_state(test_snapshot(1));
    let error =
        Attempt::new(&state, 2).failure(Stage::Preflight, AuditPostError::not_sent("refused"));
    let output = line(&error, Phase::Retry);
    assert!(output.contains("phase=retry"));
    assert!(output.contains("status=unknown event_count=2"));
    assert!(output.contains("same_snapshot=unknown same_policy_sequence=unknown"));
}

#[test]
fn audit_diagnostic_http200_retains_failure_and_same_snapshot_observation() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let mut attempt = Attempt::new(&state, 3);
    attempt.snapshot(&snapshot);
    attempt.status(StatusCode::OK);
    let error = attempt.failure(Stage::AckDigestMismatch, AuditPostError::other("refused"));
    let output = line(&error, Phase::Initial);
    assert_eq!(error.kind, AuditPostFailure::OutcomeUnknown);
    assert!(output.contains("stage=ack_digest_mismatch"));
    assert!(output.contains("status=200 event_count=3"));
    assert!(output.contains("same_snapshot=true same_policy_sequence=true"));
}

#[test]
fn audit_diagnostic_changed_policy_is_observed_without_changing_failure() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let mut attempt = Attempt::new(&state, 1);
    attempt.snapshot(&snapshot);
    attempt.status(StatusCode::OK);
    *state.snapshot.write().unwrap() = test_snapshot(2);
    let error = attempt.failure(Stage::SnapshotNotCurrent, AuditPostError::other("refused"));
    let output = line(&error, Phase::Retry);
    assert_eq!(error.kind, AuditPostFailure::OutcomeUnknown);
    assert!(output.contains("stage=snapshot_changed"));
    assert!(output.contains("same_snapshot=false same_policy_sequence=false"));
}

#[test]
fn audit_diagnostic_identity_change_is_distinct_from_sequence_change() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let mut attempt = Attempt::new(&state, 1);
    attempt.snapshot(&snapshot);
    *state.snapshot.write().unwrap() = Arc::new((*snapshot).clone());
    let error = attempt.failure(Stage::SnapshotNotCurrent, AuditPostError::other("refused"));
    assert!(line(&error, Phase::Initial).contains("same_snapshot=false same_policy_sequence=true"));
}

#[test]
fn audit_diagnostic_contended_snapshot_lock_never_blocks_original_failure() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let mut attempt = Attempt::new(&state, 1);
    attempt.snapshot(&snapshot);
    let _guard = state.snapshot.write().unwrap();
    let error = attempt.failure(Stage::SnapshotNotCurrent, AuditPostError::other("refused"));
    assert!(
        line(&error, Phase::Initial).contains("same_snapshot=unknown same_policy_sequence=unknown")
    );
}

#[test]
fn audit_diagnostic_null_policy_context_is_a_parse_category_not_acceptance() {
    let snapshot = test_snapshot(1);
    let mut value = context(&snapshot);
    value["policy_bundle_digest"] = Value::Null;
    let stage = verification_stage(
        "audit acknowledgement statement parse failed",
        &headers(value),
        &snapshot,
    );
    assert_eq!(stage, Stage::ResponseContextParse);
}

#[test]
fn audit_diagnostic_malformed_context_and_unknown_context_fields_are_classified() {
    let snapshot = test_snapshot(1);
    let mut extra = context(&snapshot);
    extra["unexpected"] = json!("not-logged");
    for value in [
        Value::Null,
        json!(2),
        json!([]),
        json!({}),
        extra,
        json!({"runtime_manifest_digest": false, "policy_bundle_digest": snapshot.hash}),
    ] {
        assert_eq!(
            verification_stage(
                "audit acknowledgement statement parse failed",
                &headers(value),
                &snapshot
            ),
            Stage::ResponseContextParse
        );
    }
}

#[test]
fn audit_diagnostic_general_statement_parse_failure_stays_distinct() {
    let snapshot = test_snapshot(1);
    assert_eq!(
        verification_stage(
            "audit acknowledgement statement parse failed",
            &raw_headers(b"not-json"),
            &snapshot
        ),
        Stage::ResponseStatementParse
    );
    assert_eq!(
        verification_stage(
            "audit acknowledgement statement parse failed",
            &headers(context(&snapshot)),
            &snapshot
        ),
        Stage::ResponseStatementParse
    );
}

#[test]
fn audit_diagnostic_policy_context_mismatch_does_not_disclose_either_digest() {
    let snapshot = test_snapshot(1);
    let mut value = context(&snapshot);
    value["policy_bundle_digest"] = json!("sensitive-untrusted-digest");
    let stage = verification_stage(
        "audit acknowledgement context mismatch",
        &headers(value),
        &snapshot,
    );
    assert_eq!(stage, Stage::ResponseContextPolicyMismatch);
    let state = test_gate_state(Arc::clone(&snapshot));
    let error =
        Attempt::new(&state, 1).failure(stage, AuditPostError::other("sensitive-untrusted-digest"));
    let output = line(&error, Phase::Initial);
    assert!(!output.contains("sensitive") && !output.contains(&snapshot.hash));
}

#[test]
fn audit_diagnostic_other_context_mismatch_remains_distinct() {
    let snapshot = test_snapshot(1);
    assert_eq!(
        verification_stage(
            "audit acknowledgement context mismatch",
            &headers(context(&snapshot)),
            &snapshot
        ),
        Stage::ResponseContextOtherMismatch
    );
}

#[test]
fn audit_diagnostic_unknown_or_injected_errors_cannot_select_known_category() {
    let snapshot = test_snapshot(1);
    for message in [
        "signature rejected secret",
        "audit acknowledgement context mismatch\nsecret",
        "prefix audit acknowledgement statement parse failed",
        "",
    ] {
        assert_eq!(
            verification_stage(message, &headers(Value::Null), &snapshot),
            Stage::ResponseVerificationOther
        );
    }
}

#[test]
fn audit_diagnostic_duplicate_or_oversized_headers_are_not_reparsed() {
    let snapshot = test_snapshot(1);
    let mut duplicate = headers(Value::Null);
    let value = duplicate["x-catchplate-response-statement-b64"].clone();
    duplicate.append("x-catchplate-response-statement-b64", value);
    let mut oversized = HeaderMap::new();
    oversized.insert(
        "x-catchplate-response-statement-b64",
        HeaderValue::from_str(&"a".repeat(MAX_CONTROL_PLANE_RESPONSE_HEADER_BYTES + 1)).unwrap(),
    );
    for value in [duplicate, oversized, HeaderMap::new()] {
        assert_eq!(
            verification_stage(
                "audit acknowledgement statement parse failed",
                &value,
                &snapshot
            ),
            Stage::ResponseStatementParse
        );
    }
}

#[test]
fn audit_diagnostic_decoded_statement_bound_is_retained() {
    let snapshot = test_snapshot(1);
    let oversized = raw_headers(&vec![b' '; MAX_CONTROL_PLANE_RESPONSE_STATEMENT_BYTES + 1]);
    assert_eq!(
        verification_stage(
            "audit acknowledgement statement parse failed",
            &oversized,
            &snapshot
        ),
        Stage::ResponseStatementParse
    );
}

#[test]
fn audit_diagnostic_classifies_actual_signed_context_rejections_without_accepting_them() {
    use super::super::{
        tests::test_snapshot_with_control_plane_response_key, verify_control_plane_signed_response,
    };
    let key = SigningKey::from_bytes(&[93u8; 32]);
    let snapshot = test_snapshot_with_control_plane_response_key(1, &key);
    let valid = serde_json::to_value(snapshot.attested_response_context.as_ref().unwrap()).unwrap();
    let (good_headers, nonce) = signed_headers(&snapshot, &key, valid.clone());
    assert!(verify_control_plane_signed_response(
        &snapshot,
        "http://fixture/api/data-plane/audit",
        "POST",
        &nonce,
        StatusCode::OK,
        &good_headers,
        b"{}",
        "audit acknowledgement"
    )
    .is_ok());
    for (field, value, expected) in [
        (
            "policy_bundle_digest",
            Value::Null,
            Stage::ResponseContextParse,
        ),
        (
            "policy_bundle_digest",
            json!("sha256:different-policy"),
            Stage::ResponseContextPolicyMismatch,
        ),
        (
            "runtime_manifest_digest",
            json!("sha256:different-runtime"),
            Stage::ResponseContextOtherMismatch,
        ),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        let (headers, nonce) = signed_headers(&snapshot, &key, changed);
        let error = verify_control_plane_signed_response(
            &snapshot,
            "http://fixture/api/data-plane/audit",
            "POST",
            &nonce,
            StatusCode::OK,
            &headers,
            b"{}",
            "audit acknowledgement",
        )
        .err()
        .unwrap();
        assert_eq!(verification_stage(&error, &headers, &snapshot), expected);
    }
}

#[test]
fn audit_diagnostic_keeps_invalid_signature_generic_and_rejected() {
    use super::super::{
        tests::test_snapshot_with_control_plane_response_key, verify_control_plane_signed_response,
    };
    let key = SigningKey::from_bytes(&[93u8; 32]);
    let snapshot = test_snapshot_with_control_plane_response_key(1, &key);
    let valid = serde_json::to_value(snapshot.attested_response_context.as_ref().unwrap()).unwrap();
    let (headers, nonce) = signed_headers(&snapshot, &SigningKey::from_bytes(&[94u8; 32]), valid);
    let error = verify_control_plane_signed_response(
        &snapshot,
        "http://fixture/api/data-plane/audit",
        "POST",
        &nonce,
        StatusCode::OK,
        &headers,
        b"{}",
        "audit acknowledgement",
    )
    .err()
    .unwrap();
    assert_eq!(
        verification_stage(&error, &headers, &snapshot),
        Stage::ResponseVerificationOther
    );
}
