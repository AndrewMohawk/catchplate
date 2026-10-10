//! Closed contract controls and bounded loopback finalizer fixtures. No provider calls.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const CREDENTIAL: &str = "credential:npm-test";
const BASE: &str = "https://registry.npmjs.org";

fn config() -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":["synthetic-npm"],"secretClass":"bearerToken"},
        "packages":["@fixture/pkg","fixture"],"request":request_config(),"response":response_profile(false)})
}

fn route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into();
    route.adapter_config = config();
    route.host = HOST.into();
    route.methods = HashSet::from(["GET".into()]);
    route.paths = vec![compile_template(PATH).unwrap()];
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = DISCARD.iter().map(|name| name.to_string()).collect();
    route.constraints = vec![envelope("npm-metadata-response")];
    route.jit = json!({});
    route
}

fn snapshot() -> Arc<Snapshot> {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes = vec![route()];
    snapshot.credentials.insert(CREDENTIAL.into(), Credential { provider:"operator-demo".into(),
        provider_subject:Some("synthetic-npm".into()),
        injection:json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"}) });
    Arc::new(snapshot)
}

fn policy() -> Value {
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":HOST,"port":443,"methods":["GET"],"paths":[PATH]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope("npm-metadata-response")]});
    let mut policy = policy_with_route(wire.clone());
    policy["routes"] = json!([wire]);
    policy["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
        "providerSubject":"synthetic-npm","injection":{"type":"bearer","header":"Authorization"}}]);
    policy
}

fn request(method: &str, path: &str) -> DecisionRequest {
    serde_json::from_value(json!({"method":method,"url":format!("{BASE}{path}"),
        "headers":{"authorization":PLACEHOLDER,"accept":"application/vnd.npm.install-v1+json",
            "user-agent":"pacote/21.0.4 node/v24.11.1","npm-command":"view","npm-auth-type":"web",
            "npm-scope":"@fixture","npm-in-ci":"false","pacote-pkg-id":"registry:fixture",
            "pacote-req-type":"packument","pacote-version":"21.0.4",
            "accept-encoding":"gzip,deflate","npm-session":"synthetic-session"}}))
    .unwrap()
}

fn admitted(mut req: DecisionRequest, snapshot: &Snapshot) -> (DecisionRequest, Url, Value, Value) {
    let route = &snapshot.routes[0];
    let (_, url) = parse_validated_absolute_target(&req.url).unwrap();
    credential_header_replacement::remove_for_route(
        snapshot,
        route,
        &snapshot.principals[0],
        &mut req.headers,
    )
    .unwrap();
    req.headers = discard_declared_request_headers(&req.headers, &route.discard_headers).unwrap();
    validate_provider_request_admission(&req, &url, route).unwrap();
    let headers = canonical_forwarded_request_headers(
        &req.headers,
        &url,
        decision_request_body_length(&req).unwrap(),
        &snapshot.credentials[CREDENTIAL].injection,
    )
    .unwrap();
    let matched = RouteMatch {
        route,
        params: route.paths[0].matches_canonical(url.path()).unwrap(),
    };
    let (operation, rewrite) = validate_adapter(&req, &headers, &url, &matched).unwrap();
    assert_eq!(rewrite, json!({}));
    let canonical = canonical_request(
        &req,
        &headers,
        &url,
        &snapshot.principals[0],
        route,
        7,
        &snapshot.hash,
        &operation,
    );
    (req, url, operation, canonical)
}

#[test]
fn npm_metadata_contract_and_embedded_schema_are_closed() {
    validate_policy_capabilities(&policy()).unwrap();
    validate_route(&route()).unwrap();
    validate_route_response_release_mode(&route()).unwrap();
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/adapters/npm.metadata.v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&config()));
    let embedded = closed_embedded_policy_schema().unwrap();
    assert!(embedded["$defs"]
        .get("adapter_npm_metadata_v1__root")
        .is_some());
    for (pointer, value) in [
        ("/routes/0/match/host", json!("registry.example")),
        ("/routes/0/match/port", json!(444)),
        ("/routes/0/match/scheme", json!("http")),
        ("/routes/0/match/methods", json!(["GET", "HEAD"])),
        ("/routes/0/match/paths", json!(["/**"])),
        (
            "/routes/0/credentialHeader/expectedValue",
            json!("Bearer other"),
        ),
        (
            "/routes/0/adapter/config/request/discardHeaders",
            json!(["npm-session"]),
        ),
        (
            "/routes/0/adapter/config/request/allowedQueryKeys",
            json!(["write"]),
        ),
        ("/routes/0/adapter/config/request/maxBodyBytes", json!(1)),
        ("/routes/0/adapter/config/response/mode", json!("json")),
        (
            "/routes/0/adapter/config/response/error/maxBodyBytes",
            json!(65537),
        ),
        ("/credentials/0/providerSubject", json!("different")),
        ("/credentials/0/provider", json!("npm")),
        ("/credentials/0/injection/type", json!("header")),
        ("/credentials/0/injection/header", json!("X-Token")),
        (
            "/routes/0/constraints/0/contentTypePolicy",
            json!("githubJsonUtf8V1"),
        ),
        ("/routes/0/constraints/0/statusCodes", json!([200, 201])),
    ] {
        let mut changed = policy();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_policy_capabilities(&changed).is_err(), "{pointer}");
    }
    for field in ["jit", "responseObservation"] {
        let mut changed = policy();
        changed["routes"][0][field] = json!({});
        assert!(validate_policy_capabilities(&changed).is_err());
    }
    for field in ["field", "prefix"] {
        let mut changed = policy();
        changed["credentials"][0]["injection"][field] = json!("wrong");
        assert!(validate_policy_capabilities(&changed).is_err());
    }
}

#[test]
fn npm_metadata_startup_policy_schema_validators_compile_and_remain_closed() {
    // Exercise the same cached v1/v2 schema compiler used by policy startup,
    // not only the standalone adapter validator. This is structural validation,
    // not a signature, authority-classifier or serving acceptance claim.
    let embedded = closed_embedded_policy_schema().unwrap();
    let root = &embedded["$defs"]["adapter_npm_metadata_v1__root"];
    assert_eq!(
        root["properties"]["packages"]["items"]["$ref"],
        "#/$defs/adapter_npm_metadata_v1__packageName"
    );
    let package = &embedded["$defs"]["adapter_npm_metadata_v1__packageName"];
    assert_eq!(package["type"], "string");
    assert_eq!(package["maxLength"], 214);
    assert!(package["pattern"]
        .as_str()
        .is_some_and(|pattern| !pattern.is_empty()));
    for version in ["serverware.policy/v1", policy_route_authority::BUNDLE] {
        let mut raw = policy();
        raw["apiVersion"] = json!(version);
        raw["kind"] = json!("PolicyBundle");
        raw["metadata"] = json!({"id":"npm-startup-schema-fixture","sequence":1,"rollbackEpoch":1});
        if version == policy_route_authority::BUNDLE {
            let placeholder = format!("sha256:{}", "0".repeat(64));
            raw["routeAuthority"] = json!({"apiVersion":"serverware.compiledRouteAuthority/v1",
                "genericOperations":[],"mappingSha256":placeholder,"routeAuthorityRootSha256":placeholder,
                "operationAuthorityRootSha256":placeholder});
        }
        validate_policy_schema(&raw)
            .expect("startup must compile and resolve the embedded npm adapter");
        for packages in [
            json!(["Fixture"]),
            json!(["@fixture%2fpkg"]),
            json!(["fixture", "fixture"]),
        ] {
            let mut changed = raw.clone();
            changed["routes"][0]["adapter"]["config"]["packages"] = packages;
            assert!(validate_policy_schema(&changed).is_err());
        }
        let mut changed = raw.clone();
        changed["routes"][0]["adapter"]["config"]["request"]["maxBodyBytes"] = json!(1);
        assert!(validate_policy_schema(&changed).is_err());
        changed = raw;
        changed["routes"][0]["adapter"]["config"]["unknown"] = json!(true);
        assert!(validate_policy_schema(&changed).is_err());
    }
}

#[test]
fn npm_metadata_v2_authority_is_exactly_source_classified_read() {
    let pin = |value: &Value| {
        sha256_prefixed(policy_route_authority::canonical(value).unwrap().as_bytes())
    };
    let mut raw = policy();
    raw["apiVersion"] = json!(policy_route_authority::BUNDLE);
    let operations = json!([{"operationName":"npm.metadata.read","operation":"read","requestAuthorityClass":"read"}]);
    let profile = json!({"apiVersion":"serverware.compiledRouteAuthority/v1",
        "routeSha256":sha256_prefixed(b"route:test"),"signedRouteSha256":pin(&raw["routes"][0]),
        "adapterType":ADAPTER,"operations":operations,"signedPrincipalsSha256":pin(&raw["principals"]),
        "signedCredentialsSha256":pin(&raw["credentials"]),"signedDefaultsSha256":pin(&raw["defaults"]),
        "principalSha256s":[sha256_prefixed(b"agent:test")]});
    let profile_pin = pin(&profile);
    let profiles = json!([{"routeId":"route:test","compiledSemanticProfileSha256":profile_pin,"profile":profile}]);
    let entries = json!([{"routeSha256":profile["routeSha256"],"compiledSemanticProfileSha256":profile_pin,
        "operationName":"npm.metadata.read","operation":"read","requestAuthorityClass":"read"}]);
    raw["routeAuthority"] = json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
        "mappingSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthority/v1","profiles":profiles})),
        "routeAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles})),
        "operationAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))});
    let snapshot = snapshot();
    let compiled = policy_route_authority::admit(&raw, &snapshot.routes)
        .unwrap()
        .unwrap();
    assert!(compiled
        .binding(
            &snapshot.principals[0],
            &snapshot.routes[0],
            &json!({"operation":"npm.metadata.read","package":"fixture"})
        )
        .is_ok());
    assert!(compiled
        .binding(
            &snapshot.principals[0],
            &snapshot.routes[0],
            &json!({"operation":"npm.publish","package":"fixture"})
        )
        .is_err());
    let mut override_attempt = raw.clone();
    override_attempt["routeAuthority"]["genericOperations"] = json!([{
        "routeId":"route:test","operationName":"npm.metadata.read","operation":"write"}]);
    assert!(policy_route_authority::admit(&override_attempt, &snapshot.routes).is_err());
    raw["routes"][0]["adapter"]["config"]["packages"] = json!(["other"]);
    assert!(policy_route_authority::admit(&raw, &snapshot.routes).is_err());
}

#[test]
fn npm_metadata_package_allowlist_is_sorted_unique_bounded_and_canonical() {
    for name in ["fixture", "f.1_2-3", "@fixture/pkg"] {
        assert!(package_name(name));
    }
    for name in [
        "",
        "*",
        "Fixture",
        ".hidden",
        "_hidden",
        "pkg~old",
        "pkg@1",
        "@scope/pkg/extra",
        "@Scope/pkg",
        "@scope/_pkg",
        "@scope%2fpkg",
        "-",
        "@/pkg",
        "pkg/path",
    ] {
        assert!(!package_name(name), "{name}");
    }
    assert!(package_name(&"a".repeat(214)));
    assert!(!package_name(&"a".repeat(215)));
    for packages in [
        json!([]),
        json!(["fixture", "fixture"]),
        json!(["fixture", "@fixture/pkg"]),
        json!(["*"]),
        json!(["@fixture%2fpkg"]),
    ] {
        let mut changed = config();
        changed["packages"] = packages;
        assert!(validate_config(&changed, &[envelope("npm")]).is_err());
    }
    for count in [64, 65] {
        let mut changed = config();
        changed["packages"] = json!((0..count).map(|n| format!("p{n:02}")).collect::<Vec<_>>());
        assert_eq!(
            validate_config(&changed, &[envelope("npm")]).is_ok(),
            count == 64
        );
    }
}

#[test]
fn npm_metadata_scoped_capture_replacement_and_discard_are_canonical() {
    let snapshot = snapshot();
    for (path, package) in [("/fixture", "fixture"), ("/@fixture%2fpkg", "@fixture/pkg")] {
        let (req, url, operation, canonical) = admitted(request("GET", path), &snapshot);
        assert_eq!(
            operation,
            json!({"operation":"npm.metadata.read","package":package})
        );
        assert_eq!(url.path(), path);
        assert!(!req.headers.contains_key("authorization"));
        for name in DISCARD {
            assert!(!req.headers.contains_key(*name));
        }
        assert_eq!(canonical["v"], 2);
        assert_eq!(canonical["request"]["discard_headers"], json!(DISCARD));
        assert_eq!(canonical["operation"]["package"], package);
        let matched = RouteMatch {
            route: &snapshot.routes[0],
            params: BTreeMap::from([("wrong".into(), path[1..].into())]),
        };
        assert!(normalize_request(&req, &url, &matched).is_err());
    }
    let first = admitted(request("GET", "/fixture"), &snapshot).3;
    let mut second = request("GET", "/fixture");
    second
        .headers
        .insert("npm-session".into(), "another".into());
    second.headers.insert("accept-encoding".into(), "br".into());
    assert_eq!(
        canonical_request_digest_profile(&first, ReleaseProfile::Legacy),
        canonical_request_digest_profile(&admitted(second, &snapshot).3, ReleaseProfile::Legacy)
    );
    for header in [None, Some("Bearer unrelated")] {
        let mut req = request("GET", "/fixture");
        req.headers.remove("authorization");
        if let Some(header) = header {
            req.headers.insert("authorization".into(), header.into());
        }
        assert!(credential_header_replacement::remove_for_route(
            &snapshot,
            &snapshot.routes[0],
            &snapshot.principals[0],
            &mut req.headers
        )
        .is_err());
    }
}

#[test]
fn npm_metadata_denials_precede_credential_preparation() {
    let snapshot = snapshot();
    let state = test_gate_state(Arc::clone(&snapshot));
    for target in [
        "https://registry.npmjs.org:443/fixture",
        "https://REGISTRY.NPMJS.ORG/fixture",
        "https://registry.npmjs.org./fixture",
        "https://user@registry.npmjs.org/fixture",
        "https://registry.npmjs.org/fixture#fragment",
        "https://other.example/fixture",
        "http://registry.npmjs.org/fixture",
    ] {
        let mut req = request("GET", "/fixture");
        req.url = target.into();
        assert_eq!(
            decide_internal(&state, &snapshot, req, Some("agent:test"))["allowed"],
            false,
            "{target}"
        );
    }
    for (method, path) in [
        ("GET", "/unselected"),
        ("GET", "/@fixture%2fother"),
        ("GET", "/fixture/-/fixture-1.tgz"),
        ("GET", "/-/whoami"),
        ("GET", "/fixture/1.0.0"),
        ("HEAD", "/fixture"),
        ("POST", "/fixture"),
        ("GET", "/fixture?"),
        ("GET", "/fixture?write=true"),
        ("GET", "/@fixture%2Fpkg"),
        ("GET", "/@fixture/pkg"),
        ("GET", "/@fixture%252fpkg"),
        ("GET", "/%66ixture"),
    ] {
        let decision =
            decide_internal(&state, &snapshot, request(method, path), Some("agent:test"));
        assert_eq!(decision["allowed"], false, "{method} {path}");
    }
    for variant in 0..3 {
        let mut req = request("GET", "/fixture");
        match variant {
            0 => req.body = "{}".into(),
            1 => {
                req.headers
                    .insert("content-type".into(), "application/json".into());
            }
            _ => {
                req.headers.insert("npm-otp".into(), "synthetic".into());
            }
        }
        assert_eq!(
            decide_internal(&state, &snapshot, req, Some("agent:test"))["allowed"],
            false
        );
    }
    assert_eq!(
        state
            .credential_lease_refresh_success
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        state
            .credential_lease_refresh_failed
            .load(Ordering::Relaxed),
        0
    );
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
}

#[test]
fn npm_metadata_standard_header_guards_apply_before_discard() {
    for (name, value) in [
        ("npm-session", "bad\r\nvalue".into()),
        (
            "user-agent",
            "x".repeat(MAX_CANONICAL_REQUEST_HEADER_VALUE_BYTES + 1),
        ),
    ] {
        let mut req = request("GET", "/fixture");
        req.headers.insert(name.into(), value);
        assert!(discard_declared_request_headers(&req.headers, &route().discard_headers).is_err());
    }
    let mut req = request("GET", "/fixture");
    req.headers.insert("Npm-Session".into(), "duplicate".into());
    assert!(discard_declared_request_headers(&req.headers, &route().discard_headers).is_err());
}

fn inspected(
    status: u16,
    media: &str,
    body: &[u8],
    guard: &ResponseSecretGuard,
) -> Result<SensitiveResponseBytes, Value> {
    let status = StatusCode::from_u16(status).unwrap();
    inspect_response(
        &Url::parse(&format!("{BASE}/fixture")).unwrap(),
        status,
        Some(media),
        &response_profile(!status.is_success()),
        body.to_vec().into(),
        guard,
    )
}

#[test]
fn npm_metadata_whole_response_preserves_dynamic_fields_and_number_spelling() {
    let body=br#" { "name":"fixture", "versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/fixture/-/fixture-1.tgz"}}}, "dist-tags":{"latest":"1.0.0"}, "future":18446744073709551617, "n":1e2 } "#;
    for media in CONTENT_TYPES {
        assert_eq!(
            &*inspected(200, media, body, &ResponseSecretGuard::default()).unwrap(),
            body
        );
    }
    for status in &STATUSES[1..] {
        let body = br#" {"error":"synthetic","detail":{"future":true}} "#;
        assert_eq!(
            &*inspected(
                *status,
                "application/json",
                body,
                &ResponseSecretGuard::default()
            )
            .unwrap(),
            body
        );
    }
}

#[test]
fn npm_metadata_media_grammar_is_profile_specific_and_closed() {
    for media in [
        "application/json",
        "application/json; charset=UTF-8",
        "APPLICATION/JSON;charset=utf-8",
        "application/vnd.npm.install-v1+json",
        "application/vnd.npm.install-v1+json; charset=utf-8",
    ] {
        assert!(is_json_content_type(media), "{media}");
    }
    for media in [
        "application/other+json",
        "text/json",
        "application/json; charset=latin-1",
        "application/json; charset=\"utf-8\"",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; profile=x",
        "application/json ; charset=utf-8",
        " application/json",
        "application/json ",
        "application/vnd.npm.install-v1+json; charset=utf-8 ",
    ] {
        assert!(!is_json_content_type(media), "{media}");
    }
    assert!(!github_issues::is_json_content_type(CONTENT_TYPES[1]));
    for adapter in ["generic.rest", "npm.registry", "gmail.read.v1"] {
        assert!(buffered_response::validate_envelope_pairing(
            adapter,
            Some(MODE),
            &[envelope("npm")]
        )
        .is_err());
    }
}

#[test]
fn npm_metadata_strict_json_identity_and_limits_fail_closed() {
    for body in [
        b"[]".as_slice(),
        br#"{"name":"different"}"#,
        br#"{"name":null}"#,
        b"{}",
        br#"{"name":"fixture","name":"fixture"}"#,
        br#"{"name":"fixture","n":NaN}"#,
        br#"{"name":"fixture","n":-0}"#,
        br#"{"name":"fixture"}{}"#,
    ] {
        assert!(inspected(
            200,
            "application/json",
            body,
            &ResponseSecretGuard::default()
        )
        .is_err());
    }
    for status in [201, 204, 206, 302, 418] {
        assert!(inspected(
            status,
            "application/json",
            b"{}",
            &ResponseSecretGuard::default()
        )
        .is_err());
    }
    assert!(inspected(
        404,
        "application/json",
        b"[]",
        &ResponseSecretGuard::default()
    )
    .is_err());
    for (status, limit) in [(200, SUCCESS_BYTES), (404, ERROR_BYTES)] {
        let prefix = if status == 200 {
            "{\"name\":\"fixture\",\"x\":\""
        } else {
            "{\"error\":\""
        };
        let body = format!(
            "{prefix}{}\"}}",
            "a".repeat(limit as usize - prefix.len() - 2)
        );
        assert_eq!(body.len(), limit as usize);
        assert!(inspected(
            status,
            "application/json",
            body.as_bytes(),
            &ResponseSecretGuard::default()
        )
        .is_ok());
        let oversized = format!("{body} ");
        assert_eq!(
            inspected(
                status,
                "application/json",
                oversized.as_bytes(),
                &ResponseSecretGuard::default()
            )
            .err()
            .unwrap()["error"],
            "response_body_too_large"
        );
    }
    let depth = format!(
        "{{\"name\":\"fixture\",\"x\":{}0{}}}",
        "[".repeat(130),
        "]".repeat(130)
    );
    assert!(inspected(
        200,
        "application/json",
        depth.as_bytes(),
        &ResponseSecretGuard::default()
    )
    .is_err());
}

#[test]
fn npm_metadata_scans_raw_decoded_and_discarded_metadata_before_release() {
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-secret");
    for body in [
        br#"{"name":"fixture","x":"synthetic-secret"}"#.as_slice(),
        br#"{"name":"fixture","x":"\u0073ynthetic-secret"}"#,
    ] {
        assert_eq!(
            inspected(200, "application/json", body, &guard)
                .err()
                .unwrap()["error"],
            "response_credential_reflection"
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("x-unselected", HeaderValue::from_static("synthetic-secret"));
    assert_eq!(
        response_metadata::prepare(&headers, &[envelope("npm")], &guard)
            .err()
            .unwrap()["error"],
        "response_credential_reflection"
    );
    headers.insert("x-unselected", HeaderValue::from_static("ordinary"));
    assert!(
        !response_metadata::prepare(&headers, &[envelope("npm")], &guard)
            .unwrap()
            .contains_key("x-unselected")
    );
    headers.insert(
        "x-unselected",
        HeaderValue::from_str(&"a".repeat(8193)).unwrap(),
    );
    assert_eq!(
        response_metadata::prepare(&headers, &[envelope("npm")], &guard)
            .err()
            .unwrap()["error"],
        "response_metadata_limit_exceeded"
    );
}

fn fixture() -> (Arc<Snapshot>, GateState, Value, Url) {
    let snapshot = snapshot();
    let state = test_gate_state(Arc::clone(&snapshot));
    let decision = json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":"npm.metadata.read","package":"fixture"},"canonical_request":{"request":{
            "method":"GET","scheme":"https","authority":HOST,"path":"/fixture"}}});
    (
        snapshot,
        state,
        decision,
        Url::parse(&format!("{BASE}/fixture")).unwrap(),
    )
}

fn upstream(status: u16, extra: &str, body: &[u8]) -> reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut wire = format!(
        "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("bounded local npm response fixture: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        read_request_head_from(&mut stream, None).unwrap();
        stream.write_all(&wire).unwrap();
    });
    let response = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .get(format!("http://{address}/fixture"))
        .send()
        .unwrap();
    server.join().unwrap();
    response
}

fn finalized(
    snapshot: &Arc<Snapshot>,
    state: &GateState,
    decision: &Value,
    url: &Url,
    response: reqwest::blocking::Response,
    guard: &ResponseSecretGuard,
) -> SensitiveResponseBytes {
    match finalize_upstream_response(
        state, snapshot, decision, "GET", url, response, guard, None, None, None, None, None, None,
        None, None, None, false,
    ) {
        ForwardResult::Buffered(wire) => wire,
        ForwardResult::Streamed => panic!("npm metadata must buffer"),
    }
}

#[test]
fn npm_metadata_real_finalizer_preserves_full_and_corgi_media_and_whole_bytes() {
    let (snapshot, state, decision, url) = fixture();
    for media in CONTENT_TYPES {
        for (status, body) in [
            (
                200,
                br#" {"name":"fixture","versions":{},"dist-tags":{},"future":true} "#.as_slice(),
            ),
            (404, br#"{"error":"not found","extra":true}"#),
        ] {
            let headers=format!("Content-Type: {media}; charset=utf-8\r\nServer: synthetic\r\nX-Cache: ordinary\r\n");
            let wire = finalized(
                &snapshot,
                &state,
                &decision,
                &url,
                upstream(status, &headers, body),
                &ResponseSecretGuard::default(),
            );
            let parsed = parse_buffered_response(&wire).unwrap();
            assert_eq!(parsed.status, status);
            assert_eq!(parsed.body, body);
            assert_eq!(
                parsed
                    .headers
                    .get("content-type")
                    .map(|value| value.as_str()),
                Some(*media)
            );
            assert!(!parsed.headers.contains_key("server"));
            assert!(!parsed.headers.contains_key("x-cache"));
        }
    }
}

#[test]
fn npm_metadata_real_finalizer_refuses_reflection_compression_cookies_and_duplicate_media() {
    let (snapshot, state, decision, url) = fixture();
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-secret");
    for headers in [
        "Content-Type: application/json\r\nX-Discarded: synthetic-secret\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: application/json\r\nSet-Cookie: forbidden=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n",
        "Content-Type: application/json; profile=unapproved\r\n",
    ] {
        let wire = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            upstream(200, headers, br#"{"name":"fixture"}"#),
            &guard,
        );
        assert_eq!(parse_buffered_response(&wire).unwrap().status, 502);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-secret"));
    }
}

#[test]
fn npm_metadata_real_finalizer_keeps_identity_status_and_snapshot_guards() {
    let (snapshot, state, decision, url) = fixture();
    for (status, body) in [
        (200, br#"{"name":"different"}"#.as_slice()),
        (201, br#"{"name":"fixture"}"#),
        (404, b"not json"),
    ] {
        let wire = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            upstream(status, "Content-Type: application/json\r\n", body),
            &ResponseSecretGuard::default(),
        );
        assert_eq!(parse_buffered_response(&wire).unwrap().status, 502);
    }
    *state.snapshot.write().unwrap() = test_snapshot(2);
    let wire = finalized(
        &snapshot,
        &state,
        &decision,
        &url,
        upstream(
            200,
            "Content-Type: application/json\r\n",
            br#"{"name":"fixture"}"#,
        ),
        &ResponseSecretGuard::default(),
    );
    let parsed = parse_buffered_response(&wire).unwrap();
    assert_eq!(parsed.status, 502);
    assert_eq!(
        serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],
        "response_snapshot_revoked"
    );
}

#[test]
fn npm_metadata_does_not_admit_legacy_registry_or_generic_media_shortcuts() {
    for adapter in ["npm.registry", "generic.rest", "gmail.read.v1"] {
        let mut changed = route();
        changed.adapter_type = adapter.into();
        assert!(validate_route_response_release_mode(&changed).is_err());
    }
    let mut legacy = route();
    legacy.adapter_type = "npm.registry".into();
    let req = request("GET", "/fixture");
    let url = Url::parse(&req.url).unwrap();
    let matched = RouteMatch {
        route: &legacy,
        params: legacy.paths[0].matches_canonical(url.path()).unwrap(),
    };
    assert!(validate_adapter(&req, &req.headers, &url, &matched).is_err());
    assert!(npm_operation(&url, "GET", "").is_err());
    assert!(!reuse_idle_upstream_connections(&route(), "GET"));
}
