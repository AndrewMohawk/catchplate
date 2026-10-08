//! Deterministic synthetic fixtures only; no external provider or stored credential access.
use super::*;
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use base64::Engine as _;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

fn descriptor(value: &str) -> Value {
    json!({"mode":"replaceExact","expectedValue":value})
}

fn fixture(custom: bool) -> Arc<Snapshot> {
    let mut snapshot = (*test_snapshot(1)).clone();
    let injection = if custom {
        json!({"type":"header","name":"x-api-key"})
    } else {
        json!({"type":"bearer"})
    };
    snapshot.credentials.insert(
        "credential:test".into(),
        Credential {
            provider: "generic".into(),
            provider_subject: Some("account:test".into()),
            injection,
        },
    );
    snapshot.routes[0].credential_ref = Some("credential:test".into());
    snapshot.routes[0].credential_header = Some(descriptor(if custom {
        "CLIENT_DUMMY"
    } else {
        "Bearer SERVERWARE_PLACEHOLDER"
    }));
    snapshot.routes[0].adapter_config["credentialMode"] = json!("required");
    snapshot.routes[0]
        .adapter_config
        .as_object_mut()
        .unwrap()
        .remove("noCredentialProof");
    snapshot.routes[0].adapter_config["credentialBinding"] = json!({
        "credentialType":"static","provider":"generic","subjects":["account:test"],
        "secretClass":if custom {"customHeader"} else {"bearerToken"},
    });
    Arc::new(snapshot)
}

fn valid_headers(custom: bool) -> BTreeMap<String, String> {
    BTreeMap::from([(
        if custom { "X-Api-Key" } else { "Authorization" }.into(),
        if custom {
            "CLIENT_DUMMY"
        } else {
            "Bearer SERVERWARE_PLACEHOLDER"
        }
        .into(),
    )])
}

fn decision(snapshot: &Snapshot) -> Value {
    json!({
        "allowed":true,"principal_id":"agent:test","route_id":"route:test",
        "policy_hash":snapshot.hash,"snapshot_epoch":snapshot.epoch,
        "credential_ref":"credential:test","credential_version":7,
        "injection":{"plan":snapshot.credentials["credential:test"].injection},
    })
}

fn request(headers: BTreeMap<String, String>) -> DecisionRequest {
    serde_json::from_value(json!({
        "clientIp":"127.0.0.1","method":"GET","url":"https://example.test/resource",
        "headers":headers,
    }))
    .unwrap()
}

#[test]
fn credential_header_replacement_contract_is_closed_ascii_and_bounded() {
    let snapshot = fixture(false);
    let credential = &snapshot.credentials["credential:test"];
    for value in [
        "x".to_string(),
        "Bearer user-chosen dummy".into(),
        "x".repeat(1024),
        "a  b".into(),
    ] {
        assert!(profile(Some(&descriptor(&value)), Some(credential)).is_ok());
    }
    for value in [
        "".to_string(),
        "x".repeat(1025),
        " x".into(),
        "x ".into(),
        "x\tvalue".into(),
        "x\r\nvalue".into(),
        "\u{7f}".into(),
        "é".into(),
        "\0".into(),
    ] {
        assert!(profile(Some(&descriptor(&value)), Some(credential)).is_err());
    }
    for raw in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"mode":"replaceExact"}),
        json!({"mode":"replace","expectedValue":"x"}),
        json!({"mode":"replaceExact","expectedValue":1}),
        json!({"mode":"replaceExact","expectedValue":"x","optional":true}),
    ] {
        assert!(profile(Some(&raw), Some(credential)).is_err());
    }
    assert!(profile(Some(&descriptor("x")), None).is_err());
    assert!(profile(None, None).unwrap().is_none());
}

#[test]
fn credential_header_replacement_rejects_unsupported_and_reserved_targets() {
    for injection in [
        json!({}),
        json!({"type":"basic"}),
        json!({"type":"cookie"}),
        json!({"type":"query"}),
        json!({"type":"header","name":"Authorization"}),
    ] {
        let credential = Credential {
            provider: "generic".into(),
            provider_subject: None,
            injection,
        };
        assert!(profile(Some(&descriptor("x")), Some(&credential)).is_err());
    }
    for name in [
        "proxy-authorization",
        "Proxy_Authorization",
        "cookie",
        "host",
        "content-type",
        "content-length",
        "content_encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-serverware-proof",
        "X_Serverware_Workload",
    ] {
        let credential = Credential {
            provider: "generic".into(),
            provider_subject: None,
            injection: json!({"type":"header","name":name}),
        };
        assert!(
            profile(Some(&descriptor("x")), Some(&credential)).is_err(),
            "{name}"
        );
    }
    assert!(credential_injection_target(&json!({"type":"bearer","existingHeader":null})).is_err());
}

#[test]
fn credential_header_replacement_policy_rejects_identity_and_request_alias_collisions() {
    let mut route = generic_policy_route("none", json!(1024));
    route["credentialRef"] = json!("credential:test");
    route["credentialHeader"] = descriptor("CLIENT_DUMMY");
    let mut policy = policy_with_route(route);
    policy["credentials"][0]["injection"] = json!({"type":"header","name":"x-api-key"});
    policy["routes"][0]["adapter"]["config"]["credentialBinding"]["secretClass"] =
        json!("customHeader");
    validate_policy_capabilities(&policy).expect("route-scoped custom placeholder policy");
    let mut explicit_null = policy.clone();
    explicit_null["routes"][0]["credentialHeader"] = Value::Null;
    assert!(validate_policy_capabilities(&explicit_null).is_err());
    for field in ["allowedHeaders", "requiredHeaders", "discardHeaders"] {
        let mut bad = policy.clone();
        bad["routes"][0]["adapter"]["config"]["request"][field] = if field == "requiredHeaders" {
            json!({"x_api_key":{"type":"string","minLength":1,"maxLength":32}})
        } else {
            json!(["x_api_key"])
        };
        assert!(validate_policy_capabilities(&bad).is_err(), "{field}");
    }
    for wildcard in [false, true] {
        let mut bad = policy.clone();
        bad["principals"][0]["requiredHeaders"] = json!({"X_API_KEY":"identity"});
        if wildcard {
            bad["routes"][0]["principals"] = json!(["*"]);
        }
        assert!(validate_policy_capabilities(&bad)
            .unwrap_err()
            .contains("identity_collision"));
    }
    let mut missing = policy_with_route(generic_policy_route("none", json!(1024)));
    missing["routes"][0]["credentialHeader"] = descriptor("x");
    assert!(validate_policy_capabilities(&missing).is_err());
}

#[test]
fn credential_header_replacement_removes_only_the_exact_target() {
    for custom in [false, true] {
        let snapshot = fixture(custom);
        let mut headers = valid_headers(custom);
        headers.insert("x-unrelated".into(), "Bearer SERVERWARE_PLACEHOLDER".into());
        headers.insert("proxy-authorization".into(), "Bearer workload-auth".into());
        let original = headers.clone();
        remove_for_route(
            &snapshot,
            &snapshot.routes[0],
            &snapshot.principals[0],
            &mut headers,
        )
        .unwrap();
        assert_eq!(headers.len(), original.len() - 1);
        assert_eq!(headers["x-unrelated"], original["x-unrelated"]);
        assert_eq!(
            headers["proxy-authorization"],
            original["proxy-authorization"]
        );
        assert_eq!(original.len(), 3);
    }
}

#[test]
fn credential_header_replacement_denials_preserve_input_and_never_trim() {
    let snapshot = fixture(false);
    for (mut headers, expected) in [
        (BTreeMap::new(), "credential_existing_header_missing"),
        (
            BTreeMap::from([(
                "Authorization".into(),
                " Bearer SERVERWARE_PLACEHOLDER".into(),
            )]),
            "credential_existing_header_mismatch",
        ),
        (
            BTreeMap::from([(
                "Authorization".into(),
                "Bearer SERVERWARE_PLACEHOLDER ".into(),
            )]),
            "credential_existing_header_mismatch",
        ),
        (
            BTreeMap::from([("Authorization".into(), "Bearer actual-client-secret".into())]),
            "credential_existing_header_mismatch",
        ),
        (
            BTreeMap::from([
                (
                    "Authorization".into(),
                    "Bearer SERVERWARE_PLACEHOLDER".into(),
                ),
                (
                    "authorization".into(),
                    "Bearer SERVERWARE_PLACEHOLDER".into(),
                ),
            ]),
            "credential_existing_header_ambiguous",
        ),
    ] {
        let original = headers.clone();
        assert_eq!(
            remove_for_route(
                &snapshot,
                &snapshot.routes[0],
                &snapshot.principals[0],
                &mut headers
            ),
            Err(expected)
        );
        assert_eq!(headers, original);
        assert!(!expected.contains("actual-client-secret"));
    }
}

#[test]
fn credential_header_replacement_shared_credential_is_route_scoped() {
    let snapshot = fixture(false);
    let mut insertion_only = snapshot.routes[0].clone();
    insertion_only.id = "route:other-application".into();
    insertion_only.credential_header = None;
    let mut headers = valid_headers(false);
    remove_for_route(
        &snapshot,
        &insertion_only,
        &snapshot.principals[0],
        &mut headers,
    )
    .unwrap();
    assert_eq!(headers, valid_headers(false));
    assert!(reject_credential_injection_collision(
        &headers,
        &Url::parse("https://example.test/resource").unwrap(),
        &snapshot.credentials["credential:test"].injection
    )
    .is_err());
    remove_for_route(
        &snapshot,
        &snapshot.routes[0],
        &snapshot.principals[0],
        &mut headers,
    )
    .unwrap();
    assert!(headers.is_empty());
    assert!(snapshot.credentials["credential:test"]
        .injection
        .get("existingHeader")
        .is_none());
    let mut other_dummy = snapshot.routes[0].clone();
    other_dummy.id = "route:third-application".into();
    other_dummy.credential_header = Some(descriptor("Bearer THIRD_APP_DUMMY"));
    let mut original_dummy = valid_headers(false);
    assert_eq!(
        remove_for_route(
            &snapshot,
            &other_dummy,
            &snapshot.principals[0],
            &mut original_dummy
        ),
        Err("credential_existing_header_mismatch")
    );
    let mut third_app = BTreeMap::from([("authorization".into(), "Bearer THIRD_APP_DUMMY".into())]);
    remove_for_route(
        &snapshot,
        &other_dummy,
        &snapshot.principals[0],
        &mut third_app,
    )
    .unwrap();
    assert!(third_app.is_empty());
}

#[test]
fn credential_header_replacement_physical_and_json_duplicate_headers_are_rejected() {
    let mut wire = Cursor::new(b"GET https://example.test/resource HTTP/1.1\r\nHost: example.test\r\nAuthorization: dummy\r\nauthorization: dummy\r\n\r\n");
    assert!(read_request_head_from(&mut wire, None)
        .err()
        .unwrap()
        .contains("ambiguous"));
    assert!(strict_json_from_slice::<DecisionRequest>(br#"{"method":"GET","url":"https://example.test/resource","headers":{"authorization":"dummy","authorization":"dummy"}}"#).is_err());
    // HTTP field OWS is normalized by the existing parser, not by replacement.
    // Direct policy maps with leading/trailing whitespace remain mismatches above.
    let snapshot = fixture(false);
    let mut ows_wire = Cursor::new(b"GET https://example.test/resource HTTP/1.1\r\nHost: example.test\r\nAuthorization:\t Bearer SERVERWARE_PLACEHOLDER \t\r\n\r\n");
    let mut parsed = read_request_head_from(&mut ows_wire, None).unwrap();
    assert_eq!(
        parsed.headers["authorization"],
        "Bearer SERVERWARE_PLACEHOLDER"
    );
    remove_for_route(
        &snapshot,
        &snapshot.routes[0],
        &snapshot.principals[0],
        &mut parsed.headers,
    )
    .unwrap();
    assert!(!parsed.headers.contains_key("authorization"));
    assert_eq!(parsed.headers["host"], "example.test");
    let mut spaced_wire = Cursor::new(b"GET https://example.test/resource HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer  SERVERWARE_PLACEHOLDER\r\n\r\n");
    let mut spaced = read_request_head_from(&mut spaced_wire, None).unwrap();
    assert_eq!(
        remove_for_route(
            &snapshot,
            &snapshot.routes[0],
            &snapshot.principals[0],
            &mut spaced.headers
        ),
        Err("credential_existing_header_mismatch")
    );
    assert_eq!(
        spaced.headers["authorization"],
        "Bearer  SERVERWARE_PLACEHOLDER"
    );
}

#[test]
fn credential_header_replacement_decision_denies_before_lease_and_canonicalizes_success() {
    let snapshot = fixture(false);
    let state = test_gate_state(snapshot.clone());
    for headers in [
        BTreeMap::new(),
        BTreeMap::from([("authorization".into(), "not-the-dummy".into())]),
    ] {
        let denied = decide_internal_with_mode(
            &state,
            &snapshot,
            request(headers),
            Some("agent:test"),
            true,
            None,
        );
        assert_eq!(denied["status_code"], 403, "{denied}");
        assert!(
            denied["error"]
                .as_str()
                .or_else(|| denied.pointer("/payload/error").and_then(Value::as_str))
                .is_some_and(|code| code.starts_with("credential_existing_header_")),
            "{denied}"
        );
        assert!(state.credential_generations.lock().unwrap().is_empty());
        assert!(state.credential_leases.lock().unwrap().is_empty());
    }
    let metadata = BTreeMap::new();
    state.credential_generations.lock().unwrap().insert(
        CredentialLeaseScope::new("agent:test", "route:test", "credential:test"),
        CredentialLeaseGeneration {
            profile: ReleaseProfile::Legacy,
            policy_hash: snapshot.hash.clone(),
            version: 7,
            metadata_sha256: credential_lease_metadata_sha256(&metadata),
            metadata,
            expires_at_epoch_ms: now_epoch_ms() + 60_000,
            expires_at_monotonic: Instant::now() + Duration::from_secs(60),
        },
    );
    let allowed = decide_internal_with_mode(
        &state,
        &snapshot,
        request(valid_headers(false)),
        Some("agent:test"),
        true,
        None,
    );
    assert_eq!(allowed["would_allow"], true, "{allowed}");
    assert!(allowed
        .pointer("/canonical_request/request/headers/authorization")
        .is_none());
    assert!(state.credential_leases.lock().unwrap().is_empty());
}

#[test]
fn credential_header_replacement_preparation_denies_before_resolver() {
    struct Resolver(AtomicUsize);
    impl UpstreamResolver for Resolver {
        fn resolve(&self, _: &str, _: u16) -> Result<Vec<SocketAddr>, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err("synthetic resolver stop".into())
        }
    }
    let snapshot = fixture(false);
    let mut state = test_gate_state(snapshot.clone());
    let resolver = Arc::new(Resolver(AtomicUsize::new(0)));
    state.upstream_resolver = resolver.clone();
    let url = Url::parse("https://example.test/resource").unwrap();
    for value in [None, Some("wrong")] {
        let header = value
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        let wire = format!(
            "GET https://example.test/resource HTTP/1.1\r\nHost: example.test\r\n{header}\r\n"
        );
        let head = read_request_head_from(&mut Cursor::new(wire.into_bytes()), None).unwrap();
        assert!(
            prepare_upstream_for_forward(&state, &snapshot, &head, &url, Some("agent:test"))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    let wire = b"GET https://example.test/resource HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer SERVERWARE_PLACEHOLDER\r\n\r\n";
    let head = read_request_head_from(&mut Cursor::new(wire), None).unwrap();
    assert!(
        prepare_upstream_for_forward(&state, &snapshot, &head, &url, Some("agent:test")).is_err()
    );
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
}

#[test]
fn credential_header_replacement_preserves_original_client_proof_and_body() {
    let snapshot = fixture(true);
    let nonce = general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let mut original_headers = valid_headers(true);
    original_headers.insert(RESPONSE_PROOF_NONCE_HEADER.into(), nonce.clone());
    let original = IncomingRequest {
        method: "GET".into(),
        target: "https://example.test/resource".into(),
        headers: original_headers.clone(),
        body: Vec::new(),
        client_ip: None,
    };
    let context = ResponseProofContext {
        client_nonce: nonce,
        client_nonce_bytes: vec![7; 32],
        tls_exporter: "fixture-exporter".into(),
    };
    let before = client_proof_request_digest(&original, &context).unwrap();
    let retained =
        provider_visible_request_headers(&snapshot, &decision(&snapshot), &original.headers)
            .unwrap();
    assert!(!retained.contains_key("X-Api-Key"));
    assert_eq!(original.headers, original_headers);
    assert_eq!(
        before,
        client_proof_request_digest(&original, &context).unwrap()
    );
    let sanitized = IncomingRequest {
        method: original.method.clone(),
        target: original.target.clone(),
        headers: retained,
        body: Vec::new(),
        client_ip: None,
    };
    assert_ne!(
        before,
        client_proof_request_digest(&sanitized, &context).unwrap()
    );
    let body = b"{\"value\":\"CLIENT_DUMMY\"}".to_vec();
    let body_request = IncomingRequest {
        method: "POST".into(),
        target: original.target.clone(),
        headers: valid_headers(true),
        body: body.clone(),
        client_ip: None,
    };
    let mut copy = buffered_forward_decision_request(&body_request, None);
    remove_for_route(
        &snapshot,
        &snapshot.routes[0],
        &snapshot.principals[0],
        &mut copy.headers,
    )
    .unwrap();
    assert_eq!(body_request.body, body);
    assert_eq!(copy.body.as_bytes(), body);
}

#[test]
fn credential_header_replacement_final_headers_recheck_policy_and_identity() {
    let snapshot = fixture(true);
    let valid = decision(&snapshot);
    assert!(
        provider_visible_request_headers(&snapshot, &valid, &valid_headers(true))
            .unwrap()
            .is_empty()
    );
    for (field, value) in [
        ("policy_hash", json!("wrong")),
        ("snapshot_epoch", json!(99)),
        ("credential_ref", json!("other")),
        ("allowed", json!(false)),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(
            provider_visible_request_headers(&snapshot, &changed, &valid_headers(true)).is_err()
        );
    }
    let mut changed = valid.clone();
    changed["injection"]["plan"]["name"] = json!("x-other");
    assert!(provider_visible_request_headers(&snapshot, &changed, &valid_headers(true)).is_err());
    assert!(provider_visible_request_headers(
        &snapshot,
        &valid,
        &BTreeMap::from([("x-api-key".into(), "wrong".into())])
    )
    .is_err());
    let mut invalid = (*snapshot).clone();
    invalid.principals[0]
        .required_headers
        .insert("x_api_key".into(), "identity".into());
    assert!(provider_visible_request_headers(&invalid, &valid, &valid_headers(true)).is_err());
}

#[test]
fn credential_header_replacement_late_collision_and_behavior_binding_fail_closed() {
    let snapshot = fixture(false);
    let route = &snapshot.routes[0];
    let credential = &snapshot.credentials["credential:test"];
    let mut headers = HeaderMap::new();
    require_late_target_absent(&headers, route, credential).unwrap();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer unexpected"),
    );
    assert_eq!(
        require_late_target_absent(&headers, route, credential).unwrap_err(),
        "credential_injection_header_collision"
    );
    let mut absent = route.clone();
    absent.credential_header = None;
    assert!(require_late_target_absent(&headers, &absent, credential).is_ok());
    let behavior = compiled_snapshot_behavior_sha256(
        &snapshot.principals,
        &snapshot.credentials,
        &snapshot.routes,
    );
    let absent_behavior = compiled_snapshot_behavior_sha256(
        &snapshot.principals,
        &snapshot.credentials,
        &[absent.clone()],
    );
    assert_ne!(behavior, absent_behavior);
    let mut changed = route.clone();
    changed.credential_header = Some(descriptor("Bearer DIFFERENT_DUMMY"));
    assert_ne!(
        behavior,
        compiled_snapshot_behavior_sha256(&snapshot.principals, &snapshot.credentials, &[changed])
    );
    assert_eq!(
        absent_behavior,
        compiled_snapshot_behavior_sha256(&snapshot.principals, &snapshot.credentials, &[absent])
    );
}
