//! Local deterministic contract/release fixtures; no provider traffic or credentials.
use super::*;
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use crate::{
    finalize_upstream_response, parse_buffered_response, read_request_head_from,
    response_policy_for_route, streaming_response_policy, validate_policy_capabilities,
    validate_policy_json_response, validate_route_response_release_mode, ForwardResult, GateState,
    SensitiveReleasedHeaders, Snapshot,
};
use reqwest::blocking::Client;
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

fn profile(maximum: u64) -> Value {
    json!({
        "mode":MODE,"bodyFormat":"json","maxBodyBytes":maximum,
        "contentTypes":["application/json"],"allowedHeaders":["etag"],
        "error":{
            "mode":MODE,"bodyFormat":"json","maxBodyBytes":512,
            "contentTypes":["application/json"],"allowedHeaders":["etag"],"onInvalid":"block"
        }
    })
}

fn inspected_ok(config: &Value, body: &[u8]) -> SensitiveResponseBytes {
    inspect_body(
        "generic.rest",
        config,
        StatusCode::OK,
        Some("application/json"),
        body.to_vec().into(),
        &ResponseSecretGuard::default(),
    )
    .expect("whole JSON fixture must pass inspection")
}

fn fixture() -> (Arc<Snapshot>, GateState, Value, Url) {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes[0].adapter_config["response"] = profile(1024);
    snapshot.routes[0].credential_ref = Some("credential:synthetic".into());
    snapshot.routes[0].constraints[0]["statusCodes"] = json!([200, 400]);
    snapshot.routes[0].constraints[0]["allowedResponseHeaderNames"] = json!(["etag"]);
    let snapshot = Arc::new(snapshot);
    let state = test_gate_state(Arc::clone(&snapshot));
    let decision = json!({
        "principal_id":"agent:test","route_id":"route:test",
        "policy_hash":snapshot.hash,"snapshot_epoch":snapshot.epoch,
        "request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":"generic.read"},
        "canonical_request":{"request":{
            "method":"GET","scheme":"https","authority":"example.test","path":"/resource"
        }}
    });
    (
        snapshot,
        state,
        decision,
        Url::parse("https://example.test/resource").unwrap(),
    )
}

fn upstream_response(status: u16, headers: &str, body: &[u8]) -> reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback response fixture");
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut wire = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("bounded response fixture: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        read_request_head_from(&mut stream, None).expect("fixture request head");
        stream.write_all(&wire).expect("fixture response write");
    });
    let response = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .get(format!("http://{address}/fixture"))
        .send()
        .expect("fixture response");
    server.join().expect("fixture server completion");
    response
}

fn finalized(
    snapshot: &Arc<Snapshot>,
    state: &GateState,
    decision: &Value,
    url: &Url,
    status: u16,
    headers: &str,
    body: &[u8],
    guard: &ResponseSecretGuard,
) -> SensitiveResponseBytes {
    match finalize_upstream_response(
        state,
        snapshot,
        decision,
        "GET",
        url,
        upstream_response(status, headers, body),
        guard,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    ) {
        ForwardResult::Buffered(response) => response,
        ForwardResult::Streamed => panic!("bufferedPassthrough must not stream"),
    }
}

fn response_json(response: &SensitiveResponseBytes, status: u16) -> Value {
    let parsed = parse_buffered_response(response).expect("complete buffered HTTP response");
    assert_eq!(parsed.status, status);
    serde_json::from_slice(parsed.body).expect("released or blocked JSON")
}

#[test]
fn buffered_passthrough_admission_requires_explicit_paired_bounded_profiles() {
    for credential in [false, true] {
        for limit in [1, MAX_BUFFERED_RESPONSE_BODY_BYTES] {
            let mut route = generic_policy_route("none", json!(limit));
            route["adapter"]["config"]["response"] = profile(limit);
            if credential {
                route["credentialRef"] = json!("credential:test");
            }
            validate_policy_capabilities(&policy_with_route(route))
                .expect("explicit bounded mode admission");
        }
    }
    let original = profile(1024);
    let mut invalid = Vec::new();
    for key in [
        "mode",
        "bodyFormat",
        "maxBodyBytes",
        "contentTypes",
        "allowedHeaders",
        "error",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(key);
        invalid.push(value);
    }
    for limit in [
        json!(0),
        json!(-1),
        json!(true),
        json!(1.5),
        json!("1024"),
        json!(MAX_BUFFERED_RESPONSE_BODY_BYTES + 1),
    ] {
        let mut value = original.clone();
        value["maxBodyBytes"] = limit;
        invalid.push(value);
    }
    for (key, value) in [
        ("allowedFields", json!([])),
        ("allowedFields", json!(["safe"])),
        ("bodyFormat", json!("text")),
        ("contentTypes", json!(["application/json", "text/plain"])),
        ("allowedHeaders", json!(["ETag"])),
        ("allowedHeaders", json!(["set-cookie"])),
        ("allowedHeaders", json!(["etag", "etag"])),
        ("maxLineBytes", json!(1024)),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        invalid.push(changed);
    }
    for (key, value) in [
        ("mode", json!("json")),
        ("bodyFormat", json!("text")),
        ("maxBodyBytes", json!(65537)),
        ("allowedFields", json!(["error"])),
        ("onInvalid", json!("allow")),
        ("contentTypes", json!([])),
        ("error", json!({})),
    ] {
        let mut changed = original.clone();
        changed["error"][key] = value;
        invalid.push(changed);
    }
    for value in invalid {
        assert!(validate_contract("generic.rest", value.as_object().unwrap()).is_err());
        let mut route = generic_policy_route("none", json!(1024));
        route["adapter"]["config"]["response"] = value;
        assert!(validate_policy_capabilities(&policy_with_route(route)).is_err());
    }
}

#[test]
fn buffered_passthrough_keeps_provider_durable_binding_and_legacy_modes_closed() {
    for provider in ["gmail.v1", "x.v2", "npm.registry"] {
        assert!(validate_contract(provider, profile(1024).as_object().unwrap()).is_err());
    }
    let (snapshot, _, _, _) = fixture();
    validate_route_response_release_mode(&snapshot.routes[0])
        .expect("generic credential mode admitted");
    assert!(streaming_response_policy(&response_policy_for_route(&snapshot.routes[0])).is_none());
    for kind in [
        "slidingWindowLimit",
        "weightedBudget",
        "traversalBudget",
        "responseBinding",
    ] {
        let mut route = snapshot.routes[0].clone();
        route.constraints.push(json!({"type":kind}));
        assert!(
            validate_route_response_release_mode(&route).is_err(),
            "runtime {kind}"
        );
        let mut wire_route = generic_policy_route("none", json!(1024));
        wire_route["adapter"]["config"]["response"] = profile(1024);
        wire_route["constraints"] = json!([{"type":kind}]);
        assert!(
            validate_policy_capabilities(&policy_with_route(wire_route)).is_err(),
            "admission {kind}"
        );
    }
    let mut old = generic_policy_route("none", json!(1024));
    old["adapter"]["config"]["response"]
        .as_object_mut()
        .unwrap()
        .remove("allowedFields");
    assert!(
        validate_policy_capabilities(&policy_with_route(old)).is_err(),
        "old json still requires projection"
    );
    let mut mixed = generic_policy_route("none", json!(1024));
    mixed["adapter"]["config"]["response"]["error"] = profile(1024)["error"].clone();
    assert!(
        validate_policy_capabilities(&policy_with_route(mixed)).is_err(),
        "old modes cannot opt into new errors"
    );
}

#[test]
fn buffered_passthrough_preserves_exact_body_bytes_without_projection_or_numeric_rewriting() {
    for body in [
        br#" {"unlisted":{"array":[{"id":1,"other":true},null]},"safe":"visible"} "#.as_slice(),
        br#"[1,{"unlisted":"preserved"},false,null]"#.as_slice(),
        br#""scalar""#.as_slice(),
        b"true",
        b"null",
        b"-123",
        "\"é😀\"".as_bytes(),
        b"18446744073709551617",
        b"1e3",
        b"[1E+3,0.100000000000000000001,-0.0]",
        b" \n { \"z\" : 2, \"id\" : 18446744073709551617, \"a\" : 1 }\t ",
        br#"{"spelling":"\u00e9\ud83d\ude00\/","original_key_order":true}"#.as_slice(),
    ] {
        let inspected = inspected_ok(&profile(1024), body);
        assert_eq!(
            inspected.as_slice(),
            body,
            "exact byte oracle, not a reparsed float comparison"
        );
    }
    let original: SensitiveResponseBytes = b"18446744073709551617".to_vec().into();
    let original_pointer = original.as_ptr();
    let released = inspect_body(
        "generic.rest",
        &profile(1024),
        StatusCode::OK,
        Some("application/json"),
        original,
        &ResponseSecretGuard::default(),
    )
    .unwrap();
    assert_eq!(
        released.as_ptr(),
        original_pointer,
        "return the original allocation, not a raw clone"
    );
}

#[test]
fn buffered_passthrough_rejects_duplicate_malformed_and_non_json_values() {
    for body in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"nested":{"a":1,"a":2}}"#.as_slice(),
        b"",
        b"{} []",
        b"{",
        b"NaN",
        b"Infinity",
        b"1e9999",
        b"\"\xff\"",
        br#""\ud800""#.as_slice(),
    ] {
        let error = inspect_body(
            "generic.rest",
            &profile(1024),
            StatusCode::OK,
            Some("application/json"),
            body.to_vec().into(),
            &ResponseSecretGuard::default(),
        )
        .err()
        .expect("invalid whole JSON must fail");
        assert_eq!(error["error"], "response_invalid_json");
    }
}

#[test]
fn buffered_passthrough_enforces_raw_and_inspection_limits_for_success_and_error() {
    for status in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        let mut selected = if status.is_success() {
            profile(3)
        } else {
            profile(3)["error"].clone()
        };
        selected["maxBodyBytes"] = json!(3);
        for (body, expected) in [
            (b"null".as_slice(), "response_body_too_large"),
            (b"1e3".as_slice(), "response_inspection_body_too_large"),
        ] {
            let error = inspect_body(
                "generic.rest",
                &selected,
                status,
                Some("application/json"),
                body.to_vec().into(),
                &ResponseSecretGuard::default(),
            )
            .err()
            .expect("raw or inspection byte expansion must exceed3");
            assert_eq!(error["error"], expected);
        }
        selected["maxBodyBytes"] = json!(6);
        let value = inspect_body(
            "generic.rest",
            &selected,
            status,
            Some("application/json"),
            b"1e3".to_vec().into(),
            &ResponseSecretGuard::default(),
        )
        .expect("exact inspection bound");
        assert_eq!(&*value, b"1e3", "inspection spelling is not emitted");
    }
}

#[test]
fn buffered_passthrough_blocks_raw_and_decoded_credential_reflection() {
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-provider-secret");
    let decoded = br#"{"unlisted":{"token":"\u0073ynthetic-provider-secret"}}"#;
    assert!(
        !guard.detects(decoded),
        "fixture must exercise normalized reflection detection"
    );
    for body in [
        br#"{"token":"synthetic-provider-secret"}"#.as_slice(),
        decoded.as_slice(),
    ] {
        let error = inspect_body(
            "generic.rest",
            &profile(1024),
            StatusCode::OK,
            Some("application/json"),
            body.to_vec().into(),
            &guard,
        )
        .err()
        .expect("secret reflection must block");
        assert_eq!(error["error"], "response_credential_reflection");
    }
}

#[test]
fn buffered_passthrough_finalizer_releases_whole_success_and_error_json_with_safe_headers() {
    let (snapshot, state, decision, url) = fixture();
    for status in [200, 400] {
        let body = br#" {"id":18446744073709551617,"unlisted":{"retain":[1e3,true,null]},"message":"\u0066ixture"} "#;
        let response = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            status,
            "Content-Type: application/json\r\nETag: safe-fixture\r\n",
            body,
            &ResponseSecretGuard::default(),
        );
        assert_eq!(
            response_json(&response, status),
            serde_json::from_slice::<Value>(body).unwrap()
        );
        let parsed = parse_buffered_response(&response).unwrap();
        assert_eq!(
            parsed.body, body,
            "exact large-integer/escape/exponent bytes through finalizer"
        );
        assert!(parsed.headers.contains_key("x-catchplate-policy-hash"));
        assert_eq!(
            parsed.headers.get("etag").map(|value| value.as_str()),
            Some("safe-fixture")
        );
    }
}

#[test]
fn buffered_passthrough_finalizer_preserves_media_encoding_header_and_envelope_denials() {
    let (snapshot, state, decision, url) = fixture();
    for (status, headers, error) in [
        (200, "", "response_json_content_type_missing"),
        (
            200,
            "Content-Type: text/plain\r\n",
            "response_json_content_type_mismatch",
        ),
        (
            200,
            "Content-Type: application/json\r\nContent-Type: application/json\r\n",
            "response_json_content_type_duplicate",
        ),
        (
            200,
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            "response_content_encoding_forbidden",
        ),
        (
            200,
            "Content-Type: application/json\r\nETag: one\r\nETag: two\r\n",
            "response_header_ambiguous",
        ),
        (
            200,
            "Content-Type: application/json\r\nX-Unlisted: denied\r\n",
            "response_envelope_header_denied",
        ),
        (
            201,
            "Content-Type: application/json\r\n",
            "response_envelope_status_denied",
        ),
        (
            302,
            "Content-Type: application/json\r\n",
            "response_redirect_not_allowed",
        ),
    ] {
        let response = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            status,
            headers,
            b"{}",
            &ResponseSecretGuard::default(),
        );
        assert_eq!(response_json(&response, 502)["error"], error);
    }
}

#[test]
fn buffered_passthrough_finalizer_rechecks_reflection_and_current_snapshot() {
    let (snapshot, state, decision, url) = fixture();
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-provider-secret");
    for (headers, body) in [
        (
            "Content-Type: application/json\r\nETag: synthetic-provider-secret\r\n",
            b"{}".as_slice(),
        ),
        (
            "Content-Type: application/json\r\n",
            br#"{"secret":"synthetic-provider-secret"}"#.as_slice(),
        ),
        (
            "Content-Type: application/json\r\n",
            br#"{"unlisted":"\u0073ynthetic-provider-secret"}"#.as_slice(),
        ),
    ] {
        let response = finalized(
            &snapshot, &state, &decision, &url, 200, headers, body, &guard,
        );
        assert_eq!(
            response_json(&response, 502)["error"],
            "response_credential_reflection"
        );
    }
    *state.snapshot.write().unwrap() = test_snapshot(2);
    let response = validate_policy_json_response(
        &state,
        &snapshot,
        &decision,
        "GET",
        &url,
        StatusCode::OK,
        Some("application/json"),
        &SensitiveReleasedHeaders::new(),
        b"{}".to_vec().into(),
        &profile(1024),
        "generic.rest",
        true,
        &Value::Null,
        &guard,
    );
    assert_eq!(
        response_json(&response, 502)["error"],
        "response_snapshot_revoked"
    );
}

#[test]
fn buffered_passthrough_keeps_whole_body_json_constraints_before_release() {
    let (snapshot, _, decision, url) = fixture();
    let mut snapshot = (*snapshot).clone();
    snapshot.routes[0].constraints.push(json!({
        "id":"required-response-field","type":"responseJson","phase":"response",
        "fields":{"safe":{"required":true,"type":"string","equals":"yes"}}
    }));
    let snapshot = Arc::new(snapshot);
    let state = test_gate_state(Arc::clone(&snapshot));
    let good = br#"{"safe":"yes","unlisted":[1,2,3]}"#;
    let response = finalized(
        &snapshot,
        &state,
        &decision,
        &url,
        200,
        "Content-Type: application/json\r\n",
        good,
        &ResponseSecretGuard::default(),
    );
    assert_eq!(
        response_json(&response, 200),
        serde_json::from_slice::<Value>(good).unwrap()
    );
    let response = finalized(
        &snapshot,
        &state,
        &decision,
        &url,
        200,
        "Content-Type: application/json\r\n",
        br#"{"unlisted":[1,2,3]}"#,
        &ResponseSecretGuard::default(),
    );
    assert!(response_json(&response, 502)["error"]
        .as_str()
        .unwrap()
        .starts_with("response_json_"));
}
