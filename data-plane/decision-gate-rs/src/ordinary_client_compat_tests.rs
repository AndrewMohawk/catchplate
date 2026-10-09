//! Deterministic additive-mode controls. Loopback fixtures never use credentials
//! or contact providers; parsed response evidence is not raw transport capture.
use super::*;
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use std::net::TcpListener;
use std::thread;

fn profile() -> Value {
    json!({"mode":buffered_response::JSON_OR_EMPTY_204_MODE,"bodyFormat":"json",
        "maxBodyBytes":65536,"contentTypes":["application/json"],"allowedHeaders":[],
        "error":{"mode":buffered_response::JSON_OR_EMPTY_204_MODE,"bodyFormat":"json",
            "maxBodyBytes":65536,"contentTypes":["application/json"],"allowedHeaders":[],"onInvalid":"block"}})
}

fn envelope() -> Value {
    json!({"id":"ordinary-response","type":"responseEnvelope","phase":"response",
        "statusCodes":[200,201,204,400,500],"bodyPresence":buffered_response::JSON_OR_EMPTY_204_PRESENCE,
        "contentTypes":["application/json"],"allowedResponseHeaderNames":[],"responseHeaderRules":[]})
}

fn request_profile() -> Value {
    json!({"bodyMode":buffered_request::MODE,"maxBodyBytes":65536,"allowedHeaders":[],
        "allowedQueryKeys":[],"allowedMediaTypes":["application/json"],
        "operation":{"name":"generic.write","bodySha256Field":"bodyDigest"},"valueRules":[]})
}

fn route() -> Value {
    let mut route = generic_policy_route(buffered_request::MODE, json!(65536));
    route["adapter"]["config"]["request"] = request_profile();
    route["adapter"]["config"]["response"] = profile();
    route["constraints"] = json!([envelope()]);
    route
}

#[test]
fn ordinary_compat_policy_contract_is_additive_and_exact() {
    for credential_bound in [false, true] {
        let mut value = route();
        if credential_bound { value["credentialRef"] = json!("credential:test"); }
        validate_policy_capabilities(&policy_with_route(value)).expect("additive exact contract");
    }
    for field in ["allowedQueryKeys", "allowedHeaders", "allowedMediaTypes", "maxBodyBytes", "operation", "valueRules"] {
        let mut value = route(); value["adapter"]["config"]["request"].as_object_mut().unwrap().remove(field);
        assert!(validate_policy_capabilities(&policy_with_route(value)).is_err(), "missing {field}");
    }
    // A missing mode is rejected by the route validator, not interpreted as the
    // additive profile. Direct helper checks intentionally no-op for old modes.
    let mut value = route(); value["adapter"]["config"]["request"].as_object_mut().unwrap().remove("bodyMode");
    assert!(validate_policy_capabilities(&policy_with_route(value)).is_err());
    for (field, invalid) in [
        ("unknownSetting", json!(true)), ("operation", json!(null)), ("operation", json!({})),
        ("operation", json!({"name":7})), ("operation", json!({"name":""})),
        ("operation", json!({"name":"x","unknown":true})),
        ("operation", json!({"name":"x","pathParams":"id"})),
        ("operation", json!({"name":"x","pathParams":["id","id"]})),
        ("operation", json!({"name":"x","bodySha256Field":"operation"})),
        ("operation", json!({"name":"x","pathParams":["id"],"bodySha256Field":"id"})),
        ("valueRules", json!(null)), ("valueRules", json!({})), ("valueRules", json!([null])),
        ("valueRules", json!([{}])), ("valueRules", json!([{"source":"unknown"}])),
        ("valueRules", json!(vec![json!({}); 17])),
        ("allowedHeaders", json!("accept")), ("allowedHeaders", json!([null])),
        ("allowedQueryKeys", json!(["q","q"])), ("allowedQueryKeys", json!([""])),
        ("discardHeaders", json!({})), ("requiredHeaders", json!([])),
    ] {
        let mut value = route(); value["adapter"]["config"]["request"][field] = invalid;
        assert!(validate_policy_capabilities(&policy_with_route(value)).is_err(), "invalid {field}");
    }
    let mut valid = request_profile(); valid["discardHeaders"] = json!([]); valid["requiredHeaders"] = json!({});
    buffered_request::validate_contract(valid.as_object().unwrap(), &[]).expect("both optional fields are explicit and typed");
    for key in ["allowedFields", "maxLineBytes", "maxItemBytes", "maxEventBytes", "maxPairBytes", "maxRecordBytes", "maxNestedBytes"] {
        let mut value = route(); value["adapter"]["config"]["request"][key] = json!([]);
        assert!(validate_policy_capabilities(&policy_with_route(value)).is_err(), "{key}");
    }
    for key in ["jsonFields", "formFields"] {
        let mut value = route(); value["adapter"]["config"]["request"]["operation"][key] = json!([]);
        assert!(validate_policy_capabilities(&policy_with_route(value)).is_err(), "even empty {key}");
    }
    for kind in ["jsonBody", "formBody"] {
        let config = request_profile();
        assert!(buffered_request::validate_contract(config.as_object().unwrap(), &[json!({"type":kind})]).is_err());
        let mut config = request_profile(); config["valueRules"] = json!([{"source":kind}]);
        assert!(buffered_request::validate_contract(config.as_object().unwrap(), &[]).is_err());
        assert!(buffered_request::validate_contract(request_profile().as_object().unwrap(),
            &[json!({"type":"requestValue","rules":[{"source":kind}]})]).is_err());
    }
    for kind in ["slidingWindowLimit", "weightedBudget", "traversalBudget", "responseBinding"] {
        assert!(buffered_response::validate_mode_constraints(buffered_response::JSON_OR_EMPTY_204_MODE,
            &[envelope(), json!({"type":kind})]).is_err());
    }
    for status in [205, 304] {
        let mut value = route(); value["constraints"][0]["statusCodes"] = json!([200,204,status]);
        assert!(validate_policy_capabilities(&policy_with_route(value)).is_err());
    }
    let mut value = route(); value["constraints"][0]["bodyPresence"] = json!("required");
    assert!(validate_policy_capabilities(&policy_with_route(value)).is_err());
    let mut value = route(); value["adapter"]["config"]["response"]["error"]["mode"] = json!(buffered_response::MODE);
    assert!(validate_policy_capabilities(&policy_with_route(value)).is_err());
    for old_mode in ["json", "headersOnly", buffered_response::MODE] {
        let mut old = generic_policy_route("none", json!(1024));
        if old_mode == buffered_response::MODE { old["adapter"]["config"]["response"] = profile(); }
        old["adapter"]["config"]["response"]["mode"] = json!(old_mode);
        old["adapter"]["config"]["response"]["error"]["mode"] = json!(old_mode);
        old["constraints"] = json!([envelope()]);
        let error = validate_policy_capabilities(&policy_with_route(old.clone())).unwrap_err();
        assert!(error.contains("jsonOrEmpty204V1 requires"), "old {old_mode}: {error}");
        let mut runtime = test_snapshot(1).routes[0].clone();
        runtime.adapter_config = old["adapter"]["config"].clone();
        runtime.constraints = vec![envelope()];
        assert!(validate_route_response_release_mode(&runtime).unwrap_err().contains("jsonOrEmpty204V1 requires"));
        runtime.constraints = test_snapshot(1).routes[0].constraints.clone();
        validate_route_response_release_mode(&runtime).expect("old profile with old envelope unchanged");
    }
    for adapter in ["gmail.v1", "x.v2", "npm.registry"] {
        for mode in ["json", "headersOnly", buffered_response::MODE, buffered_response::JSON_OR_EMPTY_204_MODE] {
            assert!(buffered_response::validate_envelope_pairing(adapter, Some(mode), &[envelope()]).is_err());
            let mut runtime = test_snapshot(1).routes[0].clone();
            runtime.adapter_type = adapter.into();
            runtime.adapter_config["response"] = profile();
            runtime.adapter_config["response"]["mode"] = json!(mode);
            runtime.adapter_config["response"]["error"]["mode"] = json!(mode);
            runtime.constraints = vec![envelope()];
            assert!(validate_route_response_release_mode(&runtime).is_err(), "{adapter}/{mode}");
            if mode == buffered_response::JSON_OR_EMPTY_204_MODE {
                runtime.constraints = test_snapshot(1).routes[0].constraints.clone();
                assert!(validate_route_response_release_mode(&runtime).is_err(), "new profile on {adapter}, including Gmail's implicit effective JSON mode");
            }
        }
    }
    // The reverse-pair guard itself must not apply whole-JSON durable refusals
    // to existing projected profiles.
    let mut projected = test_snapshot(1).routes[0].clone();
    projected.constraints.push(json!({"type":"slidingWindowLimit"}));
    validate_route_response_release_mode(&projected).expect("old projected durable mode unchanged");
    // The old projected request mode still needs its body allowlist for a credential.
    let mut old = generic_policy_route("json", json!(1024)); old["credentialRef"] = json!("credential:test");
    assert!(validate_policy_capabilities(&policy_with_route(old)).is_err());
}

#[test]
fn ordinary_compat_request_inspection_preserves_strict_raw_json_and_empty_digest() {
    let good: &[&[u8]] = &[b"", br#" {"unlisted":[1.2300,1e+02,-0.0,1e308],"text":"\\\"[{]}"} "#,
        br#"{"emoji":"\ud83d\ude00"}"#, b"null", b"true", b"-0e0", b"18446744073709551616"];
    for body in good {
        let original = body.to_vec(); buffered_request::inspect_body(body, Some(true)).expect("strict bounded value");
        assert_eq!(*body, original.as_slice());
        let decision = json!({"canonical_request":{"request":{"body_sha256":body_sha_bytes(body),
            "headers":{"content-length":body.len().to_string()}}}});
        let mut built = reqwest::blocking::Request::new(Method::POST, Url::parse("https://example.test/resource").unwrap());
        if !body.is_empty() { *built.body_mut() = Some(body.to_vec().into()); }
        buffered_request::validate_built_body(&decision, &built).expect("exact built bytes including empty");
        *built.body_mut() = Some(b"null ".to_vec().into());
        assert!(buffered_request::validate_built_body(&decision, &built).is_err());
    }
    for body in [b" ".as_slice(), br#"{"a":1,"a":2}"#, b"{}[]", b"-0", b"1e309", b"NaN", b"Infinity",
        br#"{"a":"\ud800"}"#, br#"{"\udfff":true}"#, &[0xff]] {
        assert!(buffered_request::inspect_body(body, Some(true)).is_err(), "invalid input must be refused");
    }
    assert!(buffered_request::inspect_body(b"{}", Some(false)).is_err());
    let at_limit = format!("{}0{}", "[".repeat(127), "]".repeat(127));
    buffered_request::inspect_body(at_limit.as_bytes(), Some(true)).expect("127 containers");
    let over = format!("{}0{}", "[".repeat(128), "]".repeat(128));
    assert_eq!(buffered_request::inspect_body(over.as_bytes(), Some(true)).unwrap_err()["error"], "request_json_nesting_limit");
    let quoted = format!("{{\"text\":\"{}\"}}", "[{}]".repeat(128));
    buffered_request::inspect_body(quoted.as_bytes(), Some(true)).expect("quoted braces do not count");
}

#[test]
fn ordinary_compat_final_built_body_denies_stream_substitution_digest_and_framing_changes() {
    let bytes = br#" {"value":1.00} "#;
    let decision = json!({"canonical_request":{"request":{"body_sha256":body_sha_bytes(bytes),
        "headers":{"content-length":bytes.len().to_string()}}}});
    let mut request = reqwest::blocking::Request::new(Method::POST, Url::parse("https://example.test/resource").unwrap());
    *request.body_mut() = Some(bytes.to_vec().into());
    buffered_request::validate_built_body(&decision, &request).unwrap();
    request.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
    assert!(buffered_request::validate_built_body(&decision, &request).is_err());
    request.headers_mut().clear(); request.headers_mut().insert("transfer-encoding", HeaderValue::from_static("chunked"));
    assert!(buffered_request::validate_built_body(&decision, &request).is_err());
    request.headers_mut().clear(); *request.body_mut() = Some(reqwest::blocking::Body::new(Cursor::new(bytes.to_vec())));
    assert_eq!(buffered_request::validate_built_body(&decision, &request), Err("provider_request_body_not_buffered"));
    let source = include_str!("main.rs");
    let buffered = source.split_once("let response = match send_upstream_request_with_current_lease_and_timeout_validated_and_finalized(").unwrap().1;
    assert!(buffered.find("buffered_request::validate_built_body").unwrap() < buffered.find("record_shadow_dispatch_barrier").unwrap());
}

#[test]
fn ordinary_compat_real_send_validates_built_bytes_before_dispatch_barrier() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/fixture", listener.local_addr().unwrap());
    let bytes = br#" {"value":1.00} "#;
    let decision = json!({"canonical_request":{"request":{"body_sha256":body_sha_bytes(bytes),
        "headers":{"content-length":bytes.len().to_string()}}}});
    for (body, expected_barrier_calls) in [(b"changed".as_slice(), 0), (bytes.as_slice(), 1)] {
        let barrier_calls = std::cell::Cell::new(0);
        let builder = Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap()
            .post(&target).body(body.to_vec());
        let result = send_upstream_request_with_current_lease_and_timeout_validated_and_finalized(
            &state, &snapshot, None, builder, None, UpstreamSendDeadlines::default(), false,
            |built| buffered_request::validate_built_body(&decision, built),
            |_| {
                barrier_calls.set(barrier_calls.get() + 1);
                Err("fixture stops before network dispatch".to_string())
            },
        );
        if expected_barrier_calls == 0 {
            assert!(matches!(result, Err(UpstreamSendError::CredentialAuthority("provider_request_body_binding_mismatch"))));
        } else {
            assert!(matches!(result, Err(UpstreamSendError::DispatchBarrier(_))));
        }
        assert_eq!(barrier_calls.get(), expected_barrier_calls);
        assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn ordinary_compat_real_adapter_preserves_body_commitment_and_scope_guards() {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_config["request"] = request_profile();
    route.constraints = vec![envelope()];
    let route_match = RouteMatch { route: &route, params: BTreeMap::new() };
    let mut request = DecisionRequest {
        client_ip: None, method: "POST".into(), url: "https://example.test/resource".into(),
        headers: BTreeMap::new(), body: String::new(), body_sha256: None,
        forwarded_body_length: None, forwarded_body_utf8_valid: Some(true),
        credential_metadata: BTreeMap::new(), gmail_proofs: Vec::new(), client_request_digest: None,
    };
    for body in ["", " {\"unlisted\": [1.00, true]} "] {
        request.body = body.to_string();
        request.body_sha256 = Some(body_sha_bytes(body.as_bytes()));
        let mut headers = BTreeMap::from([("content-length".into(), body.len().to_string())]);
        if !body.is_empty() { headers.insert("content-type".into(), "application/json".into()); }
        let url = Url::parse(&request.url).unwrap();
        let (operation, rewrite) = validate_adapter(&request, &headers, &url, &route_match).unwrap();
        assert_eq!(request.body, body);
        assert_eq!(operation["bodyDigest"], body_sha_bytes(body.as_bytes()));
        assert_eq!(rewrite, json!({}));
        headers.insert("content-type".into(), "text/plain".into());
        assert!(validate_adapter(&request, &headers, &url, &route_match).is_err());
        headers.remove("content-type");
        if !body.is_empty() { assert!(validate_adapter(&request, &headers, &url, &route_match).is_err()); }
        headers.insert("content-type".into(), "application/json".into());
        let query = Url::parse("https://example.test/resource?unlisted=1").unwrap();
        assert_eq!(validate_adapter(&request, &headers, &query, &route_match).unwrap_err()["error"], "generic_query_key_not_allowed");
        headers.insert("x-unlisted".into(), "value".into());
        assert_eq!(validate_adapter(&request, &headers, &url, &route_match).unwrap_err()["error"], "generic_header_not_allowed");
    }
}

#[test]
fn ordinary_compat_response_status_media_and_physical_framing_are_explicit() {
    let config = profile(); let guard = ResponseSecretGuard::default();
    for content_type in [None, Some("application/json"), Some("application/json; charset=utf-8")] {
        let mut headers = HeaderMap::new(); if let Some(value) = content_type { headers.insert("content-type", HeaderValue::from_str(value).unwrap()); }
        buffered_response::validate_empty_204_headers(&headers).unwrap();
        enforce_response_envelope(&envelope(), StatusCode::NO_CONTENT, &headers, Some(0), None).unwrap();
        let body = buffered_response::inspect_body("generic.rest", &config, StatusCode::NO_CONTENT,
            content_type, Vec::new().into(), &guard).unwrap(); assert!(body.is_empty());
        let wire = buffered_response::serialize_empty_204(content_type, &Vec::new());
        let parsed = parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status, 204); assert!(parsed.body.is_empty());
        assert!(!parsed.headers.contains_key("content-length")); assert!(!parsed.headers.contains_key("transfer-encoding"));
        assert_eq!(parsed.headers.get("content-type").map(|value| value.as_str()), content_type);
    }
    for name in ["content-length", "transfer-encoding", "trailer"] {
        let mut headers = HeaderMap::new(); headers.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_static("0"));
        assert!(buffered_response::validate_empty_204_headers(&headers).is_err());
    }
    let mut headers = HeaderMap::new(); headers.append("content-type", HeaderValue::from_static("application/json"));
    headers.append("content-type", HeaderValue::from_static("application/json"));
    assert!(buffered_response::validate_empty_204_headers(&headers).is_err());
    assert!(buffered_response::inspect_body("generic.rest", &config, StatusCode::NO_CONTENT, None, b"x".to_vec().into(), &guard).is_err());
    for status in [StatusCode::OK, StatusCode::RESET_CONTENT, StatusCode::NOT_MODIFIED, StatusCode::BAD_REQUEST] {
        let selected = if status.is_client_error() { &config["error"] } else { &config };
        assert!(buffered_response::inspect_body("generic.rest", selected, status, Some("application/json"), Vec::new().into(), &guard).is_err());
    }
    let mut old = config.clone(); old["mode"] = json!(buffered_response::MODE);
    assert!(buffered_response::inspect_body("generic.rest", &old, StatusCode::NO_CONTENT, None, Vec::new().into(), &guard).is_err());
    let at_limit = format!("{}0{}", "[".repeat(127), "]".repeat(127));
    assert_eq!(&*buffered_response::inspect_body("generic.rest", &config, StatusCode::OK,
        Some("application/json"), at_limit.as_bytes().to_vec().into(), &guard).unwrap(), at_limit.as_bytes());
    let over = format!("{}0{}", "[".repeat(128), "]".repeat(128));
    assert!(buffered_response::inspect_body("generic.rest", &config, StatusCode::OK,
        Some("application/json"), over.into_bytes().into(), &guard).is_err());
}

fn response_fixture() -> (Arc<Snapshot>, GateState, Value, Url) {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes[0].adapter_config["response"] = profile();
    snapshot.routes[0].constraints = vec![envelope()];
    let snapshot = Arc::new(snapshot); let state = test_gate_state(Arc::clone(&snapshot));
    let decision = json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":"generic.read"},"canonical_request":{"request":{"method":"GET","scheme":"https","authority":"example.test","path":"/resource"}}});
    (snapshot, state, decision, Url::parse("https://example.test/resource").unwrap())
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap(); return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("bounded loopback fixture: {error}"),
        }
    }
}

fn local_204(headers: &str) -> reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let wire = format!("HTTP/1.1 204 No Content\r\nConnection: close\r\n{headers}\r\n");
    let server = thread::spawn(move || { let mut stream = accept_bounded(&listener); read_request_head_from(&mut stream, None).unwrap(); stream.write_all(wire.as_bytes()).unwrap(); });
    let response = Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .get(format!("http://{address}/fixture")).send().unwrap();
    server.join().unwrap(); response
}

#[test]
fn ordinary_compat_204_runs_real_release_and_secret_checks_without_invented_metadata() {
    for (headers, expected) in [("", None), ("Content-Type: application/json; charset=utf-8\r\n", Some("application/json; charset=utf-8"))] {
        let (snapshot, state, decision, url) = response_fixture();
        let result = finalize_upstream_response(&state, &snapshot, &decision, "GET", &url, local_204(headers),
            &ResponseSecretGuard::default(), None, None, None, None, None, None, None, None, None, false);
        let ForwardResult::Buffered(wire) = result else { panic!("must remain buffered"); };
        let parsed = parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status, 204);
        assert!(parsed.body.is_empty()); assert!(!parsed.headers.contains_key("content-length"));
        assert_eq!(parsed.headers.get("content-type").map(|value| value.as_str()), expected);
        assert!(parsed.headers.contains_key("x-serverware-policy-hash"));
    }
    for headers in ["Content-Length: 0\r\n", "Content-Type: text/plain\r\n", "X-Unlisted: value\r\n", "Content-Encoding: gzip\r\n"] {
        let (snapshot, state, decision, url) = response_fixture();
        let result = finalize_upstream_response(&state, &snapshot, &decision, "GET", &url, local_204(headers),
            &ResponseSecretGuard::default(), None, None, None, None, None, None, None, None, None, false);
        let ForwardResult::Buffered(wire) = result else { panic!("must remain buffered"); };
        assert_ne!(parse_buffered_response(&wire).unwrap().status, 204, "{headers}");
    }
    let (snapshot, state, decision, url) = response_fixture(); let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-provider-secret");
    let result = finalize_upstream_response(&state, &snapshot, &decision, "GET", &url,
        local_204("Content-Type: application/json; marker=synthetic-provider-secret\r\n"),
        &guard, None, None, None, None, None, None, None, None, None, false);
    let ForwardResult::Buffered(wire) = result else { panic!("must remain buffered"); };
    let parsed = parse_buffered_response(&wire).unwrap(); assert_ne!(parsed.status, 204);
    assert!(!String::from_utf8_lossy(&wire).contains("synthetic-provider-secret"));

    for constraint in [
        json!({"id":"required-response-field","type":"responseJson","phase":"response",
            "fields":{"safe":{"required":true,"type":"string","equals":"yes"}}}),
        json!({"id":"response-age","type":"responseDateWindow","phase":"response",
            "dateFields":["created_at"],"formats":["epochMillis"],"maxAgeDays":1,"required":true}),
    ] {
        for applies in [false, true] {
            let (base, _, decision, url) = response_fixture();
            let mut snapshot = (*base).clone();
            let mut scoped = constraint.clone();
            scoped["operations"] = json!([if applies { "generic.read" } else { "generic.other" }]);
            snapshot.routes[0].constraints.push(scoped);
            let snapshot = Arc::new(snapshot); let state = test_gate_state(Arc::clone(&snapshot));
            let result = finalize_upstream_response(&state, &snapshot, &decision, "GET", &url, local_204(""),
                &ResponseSecretGuard::default(), None, None, None, None, None, None, None, None, None, false);
            let ForwardResult::Buffered(wire) = result else { panic!("must remain buffered"); };
            let parsed = parse_buffered_response(&wire).unwrap();
            if applies {
                assert_eq!(parsed.status, 502);
                let payload: Value = serde_json::from_slice(&parsed.body).unwrap();
                assert_eq!(payload["error"], "response_json_invalid");
                assert_eq!(payload["constraint_id"], constraint["id"]);
                assert!(!parsed.headers.contains_key("x-serverware-policy-hash"));
            } else {
                assert_eq!(parsed.status, 204, "unselected operation remains unaffected");
                assert!(parsed.body.is_empty());
            }
        }
    }
    for (header, expected_error) in [
        ("ETag: fixture-approved\r\n", None),
        ("ETag: wrong-value\r\n", Some("response_envelope_header_value_denied")),
        ("", Some("response_envelope_header_missing")),
    ] {
        let (base, _, decision, url) = response_fixture();
        let mut snapshot = (*base).clone();
        snapshot.routes[0].adapter_config["response"]["allowedHeaders"] = json!(["etag"]);
        snapshot.routes[0].constraints[0]["allowedResponseHeaderNames"] = json!(["etag"]);
        snapshot.routes[0].constraints[0]["responseHeaderRules"] = json!([{
            "name":"etag","required":true,"predicate":{"kind":"equals","value":"fixture-approved"}
        }]);
        let snapshot = Arc::new(snapshot); let state = test_gate_state(Arc::clone(&snapshot));
        let result = finalize_upstream_response(&state, &snapshot, &decision, "GET", &url, local_204(header),
            &ResponseSecretGuard::default(), None, None, None, None, None, None, None, None, None, false);
        let ForwardResult::Buffered(wire) = result else { panic!("must remain buffered"); };
        let parsed = parse_buffered_response(&wire).unwrap();
        if let Some(error) = expected_error {
            assert_eq!(parsed.status, 502);
            let payload: Value = serde_json::from_slice(&parsed.body).unwrap();
            assert_eq!(payload["error"], error);
        } else {
            assert_eq!(parsed.status, 204); assert!(parsed.body.is_empty());
            assert_eq!(parsed.headers.get("etag").map(|value| value.as_str()), Some("fixture-approved"));
            assert!(!parsed.headers.contains_key("content-type"));
            assert!(!parsed.headers.contains_key("content-length"));
        }
    }
}

#[test]
fn ordinary_compat_204_transport_never_reuses_a_connection_with_hidden_trailing_bytes() {
    for malformed in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut first = accept_bounded(&listener); read_request_head_from(&mut first, None).unwrap();
            let mut wire = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n".to_vec();
            if malformed { wire.extend_from_slice(b"illegal trailing bytes"); }
            first.write_all(&wire).unwrap();
            // A distinct accepted socket is required, including the legal nearby
            // control. No claim is made that Reqwest exposes all illegal bytes.
            let mut second = accept_bounded(&listener); read_request_head_from(&mut second, None).unwrap();
            second.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"fresh\":true}").unwrap();
        });
        let mut route = test_snapshot(1).routes[0].clone();
        assert!(reuse_idle_upstream_connections(&route, "GET"), "legacy safe-method policy unchanged");
        route.adapter_config["response"] = profile();
        let reuse = reuse_idle_upstream_connections(&route, "GET"); assert!(!reuse);
        let client = build_pinned_upstream_client(&UpstreamClientConfig {root_certificates: vec![], native_capture_tls: None}, "compat.example.test", address, reuse).unwrap();
        let target = format!("http://compat.example.test:{}/fixture", address.port());
        match client.get(&target).send() {
            Ok(mut first) => {
                assert_eq!(first.status(), StatusCode::NO_CONTENT);
                let mut observed = Vec::new();
                let read = first.read_to_end(&mut observed);
                if !malformed { read.unwrap(); }
                assert!(observed.is_empty());
            }
            Err(error) => assert!(malformed, "legal empty204 must succeed: {error}"),
        }
        let mut second = client.get(&target).send().unwrap(); assert_eq!(second.status(), StatusCode::OK);
        let mut body = String::new(); second.read_to_string(&mut body).unwrap(); assert_eq!(body, "{\"fresh\":true}");
        server.join().unwrap();
    }
}
