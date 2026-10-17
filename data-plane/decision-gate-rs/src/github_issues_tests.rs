//! Closed profile controls plus bounded synthetic loopback response fixtures.
//! These tests do not contact GitHub or certify a particular SDK distribution.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const BASE: &str = "https://api.github.com/repos/fixture-owner/fixture-repo/issues";
const CREDENTIAL: &str = "credential:github-test";

fn config(bundle: &str) -> Value {
    json!({"credentialMode":"required","credentialBinding":{"credentialType":"static",
        "provider":"operator-demo","subjects":["synthetic-github"],"secretClass":"bearerToken"},
        "githubRepository":{"owner":"fixture-owner","name":"fixture-repo"},"operationBundle":bundle,
        "request":request_profile(bundle),"response":response_profile(false)})
}

fn route(bundle: &str) -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.host = "api.github.com".into();
    route.methods = if bundle == WRITE {
        HashSet::from(["GET".into(), "POST".into()])
    } else {
        HashSet::from(["GET".into()])
    };
    route.adapter_config = config(bundle);
    route.paths = paths(&route.adapter_config)
        .unwrap()
        .iter()
        .map(|path| compile_template(path).unwrap())
        .collect();
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = vec!["accept-encoding".into()];
    route.constraints = vec![envelope("github-response")];
    route.jit = json!({});
    route
}

fn snapshot(bundle: &str) -> Arc<Snapshot> {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes = vec![route(bundle)];
    snapshot.credentials.insert(CREDENTIAL.into(), Credential {
        provider:"operator-demo".into(), provider_subject:Some("synthetic-github".into()),
        injection:json!({"type":"bearer","header":"Authorization","__catchplateCredentialType":"static"}),
    });
    Arc::new(snapshot)
}

fn policy(bundle: &str) -> Value {
    let config = config(bundle);
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":"api.github.com","port":443,
            "methods":if bundle==WRITE {json!(["GET","POST"])} else {json!(["GET"])},"paths":paths(&config).unwrap()},
        "adapter":{"type":"generic.rest","config":config},"constraints":[envelope("github-response")]});
    let mut policy = policy_with_route(wire.clone());
    policy["routes"] = json!([wire]);
    policy["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
        "providerSubject":"synthetic-github","secretClass":"bearerToken","injection":{"type":"bearer","header":"Authorization"}}]);
    policy
}

fn request(method: &str, target: &str, body: &str) -> DecisionRequest {
    let mut req: DecisionRequest = serde_json::from_value(json!({"method":method,"url":target,"body":body,
        "headers":{"accept":"application/vnd.github.v3+json","accept-language":"*","sec-fetch-mode":"cors",
            "user-agent":"octokit-rest.js/22.0.1 synthetic-fixture",
            "accept-encoding":"br, gzip, deflate, zstd","authorization":PLACEHOLDER}})).unwrap();
    if method == "POST" {
        req.headers.insert(
            "content-type".into(),
            "application/json; charset=utf-8".into(),
        );
    }
    req
}

fn material(
    snapshot: &Snapshot,
    method: &str,
    target: &str,
    body: &str,
) -> (DecisionRequest, Url, Value, Value) {
    let route = &snapshot.routes[0];
    let mut req = request(method, target, body);
    let (_, url) = provider_query::parse_target_for_route(
        snapshot,
        method,
        target,
        None,
        &req.headers,
        Some("agent:test"),
    )
    .unwrap();
    credential_header_replacement::remove_for_route(
        snapshot,
        route,
        &snapshot.principals[0],
        &mut req.headers,
    )
    .unwrap();
    req.headers = discard_declared_request_headers(&req.headers, &route.discard_headers).unwrap();
    let headers = canonical_forwarded_request_headers(
        &req.headers,
        &url,
        decision_request_body_length(&req).unwrap(),
        &snapshot.credentials[CREDENTIAL].injection,
    )
    .unwrap();
    let matched = RouteMatch {
        route,
        params: route
            .paths
            .iter()
            .find_map(|path| path.matches(url.path()))
            .unwrap(),
    };
    let (operation, rewrite) = validate_adapter(&req, &headers, &url, &matched).unwrap();
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
    let decision = json!({"allowed":true,"principal_id":"agent:test","route_id":route.id,
        "snapshot_epoch":snapshot.epoch,"policy_hash":snapshot.hash,"credential_ref":CREDENTIAL,"credential_version":7,
        "discard_headers":route.discard_headers,"operation":operation,"rewrite":rewrite,"canonical_request":canonical,
        "request_digest":canonical_request_digest_profile(&canonical,ReleaseProfile::Legacy),"operation_digest":operation_digest(&canonical)});
    (req, url, canonical, decision)
}

#[test]
fn github_contract_is_closed_and_exactly_repository_bound() {
    for bundle in [READ, WRITE] {
        validate_policy_capabilities(&policy(bundle)).unwrap();
        validate_route(&route(bundle)).unwrap();
        validate_route_response_release_mode(&route(bundle)).unwrap();
    }
    for variant in 0..10 {
        let mut changed = policy(WRITE);
        match variant {
            0 => changed["routes"][0]["match"]["host"] = json!("other.example"),
            1 => changed["routes"][0]["match"]["methods"] = json!(["GET", "POST", "DELETE"]),
            2 => {
                changed["routes"][0]["match"]["paths"] =
                    json!(["/repos/fixture-owner/fixture-repo/**"])
            }
            3 => changed["routes"][0]["adapter"]["config"]["githubRepository"]["id"] = json!(1729),
            4 => changed["routes"][0]["adapter"]["config"]["request"]["discardHeaders"] = json!([]),
            5 => changed["routes"][0]["credentialHeader"]["expectedValue"] = json!("different"),
            6 => changed["routes"][0]["jit"] = json!({}),
            7 => changed["routes"][0]["responseObservation"] = json!({}),
            8 => changed["credentials"][0]["injection"]["field"] = json!("access_token"),
            _ => changed["routes"][0]["constraints"][0]["responseHeaderRules"] = json!([]),
        }
        assert!(
            validate_policy_capabilities(&changed).is_err(),
            "variant {variant}"
        );
    }
    let legacy = test_snapshot(1);
    assert!(!selected(&legacy.routes[0]));
    assert!(!provider_query::ordered_query(&legacy.routes[0]));
    for bad in ["", "-owner", "owner-", "a/b", "ümlaut"] {
        assert!(!owner(bad));
    }
    for bad in ["", ".", "..", "a/b"] {
        assert!(!repository_name(bad));
    }
    // Matching V2 header names alone never select the typed repository capability.
    assert!(buffered_response::validate_contract(
        "generic.rest",
        response_profile(false).as_object().unwrap()
    )
    .is_err());
    assert!(buffered_response::inspect_body(
        "generic.rest",
        &response_profile(false),
        StatusCode::OK,
        Some("application/json"),
        b"[]".to_vec().into(),
        &ResponseSecretGuard::default()
    )
    .is_err());
    for (field, value) in [
        ("provider", json!("other")),
        ("subjects", json!([])),
        ("subjects", json!(["a", "b"])),
        ("subjects", json!(["x".repeat(513)])),
    ] {
        let mut changed = config(WRITE);
        changed["credentialBinding"][field] = value;
        assert!(validate_config(&changed, &[envelope("github-response")]).is_err());
    }
    for marker in [Value::Null, json!("unknown"), json!(false)] {
        let mut changed = policy(WRITE);
        changed["routes"][0]["constraints"][0]["contentTypePolicy"] = marker;
        assert!(validate_policy_capabilities(&changed).is_err());
    }
    let mut missing = policy(WRITE);
    missing["routes"][0]["constraints"][0]
        .as_object_mut()
        .unwrap()
        .remove("contentTypePolicy");
    assert!(validate_policy_capabilities(&missing).is_err());
    let mut legacy_route = legacy.routes[0].clone();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    validate_response_envelopes(&legacy_route, StatusCode::OK, &headers, Some(2), None).unwrap();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    assert_eq!(
        validate_response_envelopes(&legacy_route, StatusCode::OK, &headers, Some(2), None)
            .unwrap_err()["error"],
        "response_envelope_content_type_denied"
    );
    legacy_route.constraints[0]["contentTypePolicy"] = json!(CONTENT_TYPE_POLICY);
    assert!(validate_route_response_release_mode(&legacy_route).is_err());
    assert!(
        validate_response_envelopes(&legacy_route, StatusCode::OK, &headers, Some(2), None)
            .is_err()
    );
}

#[test]
fn github_stock_headers_and_all_issue_comment_operations_preserve_bytes() {
    let snapshot = snapshot(WRITE);
    for (method, suffix, body) in [
        (
            "GET",
            "?per_page=1&state=open&labels=fixture%2Ctriaged&page=1",
            "",
        ),
        ("GET", "/11", ""),
        ("GET", "/11/comments?per_page=1&page=1", ""),
        ("GET", "/comments/101", ""),
        (
            "POST",
            "",
            r#" {"title":"Synthetic fixture issue","body":"Fixture body \u2603","labels":["fixture"]} "#,
        ),
        (
            "POST",
            "/11/comments",
            r#"{"body":"Synthetic fixture comment"}"#,
        ),
    ] {
        let target = format!("{BASE}{suffix}");
        let (req, url, canonical, decision) = material(&snapshot, method, &target, body);
        assert_eq!(req.body, body);
        assert_eq!(url.as_str(), target);
        assert_eq!(
            canonical["operation"],
            json!({"operation":"github.issues.write"})
        );
        assert_eq!(
            canonical["request"]["body_sha256"],
            sha256_prefixed(body.as_bytes())
        );
        for stripped in [
            "authorization",
            "accept-encoding",
            "proxy-authorization",
            "connection",
        ] {
            assert!(canonical["request"]["headers"].get(stripped).is_none());
        }
        assert_eq!(canonical["request"]["headers"]["host"], "api.github.com");
        assert_eq!(canonical["request"]["headers"]["accept-language"], "*");
        assert_eq!(canonical["request"]["headers"]["sec-fetch-mode"], "cors");
        if method == "GET" {
            assert!(canonical["request"]["headers"]
                .get("content-length")
                .is_none());
        }
        assert_eq!(
            allowed_decision_discard_headers(&snapshot, &decision).unwrap(),
            vec!["accept-encoding"]
        );
    }
}

#[test]
fn github_go_sdk_reactions_accept_is_exact_and_scoped() {
    // Official go-github v74.0.0 constant, deliberately without +json.
    const PREVIEW: &str = "application/vnd.github.squirrel-girl-preview";
    for bundle in [READ, WRITE] {
        let snapshot = snapshot(bundle);
        let route = &snapshot.routes[0];
        validate_policy_capabilities(&policy(bundle)).unwrap();
        let (mut req, url, old_canonical, _) = material(&snapshot, "GET", BASE, "");
        req.headers.insert("accept".into(), PREVIEW.into());
        let headers = canonical_forwarded_request_headers(
            &req.headers, &url, decision_request_body_length(&req).unwrap(),
            &snapshot.credentials[CREDENTIAL].injection,
        ).unwrap();
        let matched = RouteMatch { route, params: BTreeMap::new() };
        let (operation, _) = validate_adapter(&req, &headers, &url, &matched).unwrap();
        assert_eq!(operation, old_canonical["operation"]);
        let canonical = canonical_request(&req, &headers, &url, &snapshot.principals[0],
            route, 7, &snapshot.hash, &operation);
        assert_eq!(canonical["request"]["headers"]["accept"], PREVIEW);
        assert_ne!(canonical_request_digest_profile(&canonical, ReleaseProfile::Legacy),
            canonical_request_digest_profile(&old_canonical, ReleaseProfile::Legacy));
        assert_eq!(route.adapter_config["request"]["valueRules"], json!([]));
        assert_eq!(route.credential_ref.as_deref(), Some(CREDENTIAL));
        for accept in [
            "application/vnd.github.squirrel-girl-preview+json",
            "application/vnd.github.mockingbird-preview+json",
            "application/vnd.other.squirrel-girl-preview",
            "application/vnd.github.squirrel-girl-preview, application/json",
            "application/vnd.github.squirrel-girl-preview;q=1",
            " application/vnd.github.squirrel-girl-preview",
            "application/vnd.github.squirrel-girl-preview ",
            "APPLICATION/VND.GITHUB.SQUIRREL-GIRL-PREVIEW",
        ] {
            let mut changed = headers.clone();
            changed.insert("accept".into(), accept.into());
            assert!(validate_adapter(&req, &changed, &url, &matched).is_err(), "{accept}");
        }
        let mut duplicate = req.headers.clone();
        duplicate.insert("Accept".into(), PREVIEW.into());
        assert_eq!(canonical_forwarded_request_headers(&duplicate, &url, Some(0),
            &snapshot.credentials[CREDENTIAL].injection).unwrap_err(), "request_header_ambiguous");
        for target in [BASE.replace("fixture-repo", "other"), BASE.replace("api.github.com", "other.example"),
                       BASE.replace("https://", "http://")] {
            let mut changed = req.clone();
            changed.url = target.clone();
            assert!(validate_adapter(&changed, &headers, &Url::parse(&target).unwrap(), &matched).is_err());
        }
        if bundle == READ {
            let mut changed = req.clone();
            changed.method = "POST".into();
            changed.body = r#"{"title":"not granted"}"#.into();
            assert!(validate_adapter(&changed, &headers, &url, &matched).is_err());
        }
    }
    // Generic non-GitHub routes do not inherit a new allowed header or profile.
    let legacy = test_snapshot(1);
    let route = &legacy.routes[0];
    let req = request("GET", "https://example.test/resource", "");
    let headers = BTreeMap::from([("accept".into(), PREVIEW.into())]);
    let denied = validate_adapter(&req, &headers, &Url::parse(&req.url).unwrap(),
        &RouteMatch { route, params: BTreeMap::new() }).unwrap_err();
    assert_eq!(denied["error"], "generic_header_not_allowed");
}

#[test]
fn github_request_scope_values_and_body_refuse_without_broadening_generic() {
    let snapshot = snapshot(WRITE);
    let route = &snapshot.routes[0];
    for (method, suffix) in [
        ("PATCH", "/11"),
        ("DELETE", "/comments/101"),
        ("POST", "/11"),
        ("GET", "/01"),
        ("GET", "/9007199254740992"),
        ("GET", "?page=0"),
        ("GET", "?page=01"),
        ("GET", "?per_page=101"),
        ("GET", "?state=unknown"),
        ("GET", "?page=1&page=2"),
        ("GET", "?labels=a&labels=b"),
        ("GET", "/11?state=open"),
        ("GET", "/11/comments?labels=a"),
        ("POST", "?page=1"),
        ("GET", "?since=2024-02-30T00:00:00Z"),
        ("GET", "?since=2024-01-01T00:00:60Z"),
        ("GET", "?since=2024-01-01T00:00:00%2B01:60"),
        ("GET", "?since=0000-01-01T00:00:00Z"),
        ("GET", "?since=1900-02-29T00:00:00Z"),
        ("GET", "?since=2024-01-01T24:00:00Z"),
        ("GET", "?since=2024-01-01T00:60:00Z"),
        ("GET", "?since=2024-01-01T00:00:00%2B24:00"),
        ("GET", "?since=2024-01-01T00:00:00.1234567890Z"),
    ] {
        assert!(
            admit_target(
                route,
                method,
                &Url::parse(&format!("{BASE}{suffix}")).unwrap()
            )
            .is_err(),
            "{method} {suffix}"
        );
    }
    for target in [
        "https://api.github.com/repositories/1729/issues",
        "https://api.github.com/repos/other/fixture-repo/issues",
        "https://other.example/repos/fixture-owner/fixture-repo/issues",
    ] {
        assert!(admit_target(route, "GET", &Url::parse(target).unwrap()).is_err());
    }
    assert!(admit_target(
        &super::tests::route(READ),
        "POST",
        &Url::parse(BASE).unwrap()
    )
    .is_err());
    for body in [
        "{}",
        "[]",
        r#"{"title":""}"#,
        r#"{"title":"a","title":"b"}"#,
        r#"{"title":"x","value":NaN}"#,
    ] {
        let req = request("POST", BASE, body);
        assert!(
            validate_request(&req, &BTreeMap::new(), &Url::parse(BASE).unwrap(), route).is_err()
        );
    }
    for body in [
        format!(r#"{{"title":"{}"}}"#, "a".repeat(1025)),
        format!(r#"{{"title":"x","body":"{}"}}"#, "a".repeat(65536)),
        format!(
            r#"{{"title":"x","body":{}{}}}"#,
            "[".repeat(128),
            "]".repeat(128)
        ),
    ] {
        assert!(validate_request(
            &request("POST", BASE, &body),
            &BTreeMap::new(),
            &Url::parse(BASE).unwrap(),
            route
        )
        .is_err());
    }
    for suffix in [
        "?since=2024-02-29T01:02:03.123456789Z",
        "?since=2000-02-29t01:02:03z",
        "?since=0001-01-01T00:00:00Z",
        "?since=9999-12-31T23:59:59Z",
        "?since=2024-02-29T01:02:03.1%2B23:59",
        "?labels=triage+needed",
        "?milestone=*&assignee=none",
    ] {
        assert!(admit_target(
            route,
            "GET",
            &Url::parse(&format!("{BASE}{suffix}")).unwrap()
        )
        .is_ok());
    }
    assert!(parse_target("GET", &format!("{BASE}?labels=owner's&page=2")).is_err());
    assert!(parse_target("GET", &format!("{BASE}?labels=owner%27s&page=2")).is_ok());
}

#[test]
fn github_physical_replacement_and_header_ambiguity_stay_fail_closed() {
    let snapshot = snapshot(WRITE);
    let route = &snapshot.routes[0];
    for variant in 0..4 {
        let mut req = request("GET", BASE, "");
        req.headers.insert("accept".into(), "application/vnd.github.squirrel-girl-preview".into());
        match variant {
            0 => {
                req.headers.remove("authorization");
            }
            1 => {
                req.headers
                    .insert("authorization".into(), "Bearer unknown".into());
            }
            2 => {
                req.headers
                    .insert("Authorization".into(), PLACEHOLDER.into());
            }
            _ => {
                req.headers
                    .insert("authorization".into(), format!("{PLACEHOLDER} "));
            }
        }
        let before = req.headers.clone();
        assert!(credential_header_replacement::remove_for_route(
            &snapshot,
            route,
            &snapshot.principals[0],
            &mut req.headers
        )
        .is_err());
        assert_eq!(req.headers, before);
    }
    for value in ["gzip\r\ninjected: x", "gzip\n"] {
        let mut headers = BTreeMap::from([("accept-encoding".into(), value.into())]);
        assert!(discard_declared_request_headers(&headers, &route.discard_headers).is_err());
        headers.insert("Accept-Encoding".into(), "gzip".into());
        assert!(discard_declared_request_headers(&headers, &route.discard_headers).is_err());
    }
    let (req, url, _, _) = material(&snapshot, "GET", BASE, "");
    for (name, value) in [
        ("accept-language", "en"),
        ("sec-fetch-mode", "no-cors"),
        ("accept", "text/html"),
        ("x-github-api-version", "2024-02-30"),
        ("x-github-api-version", "0000-01-01"),
        ("x-github-api-version", "1900-02-29"),
        ("x-github-api-version", "2024-2-29"),
        ("x-github-api-version", "2024-02-29Z"),
        ("x-github-api-version", "2024-13-01"),
        ("x-unexpected", "value"),
        ("accept-encoding", "gzip"),
    ] {
        let mut headers = req.headers.clone();
        headers.insert(name.into(), value.into());
        let matched = RouteMatch {
            route,
            params: BTreeMap::new(),
        };
        assert!(
            validate_adapter(&req, &headers, &url, &matched).is_err(),
            "{name}"
        );
    }
    for value in [
        "0001-01-01",
        "2000-02-29",
        "2022-11-28",
        "2024-02-29",
        "9999-12-31",
    ] {
        let mut headers = req.headers.clone();
        headers.insert("x-github-api-version".into(), value.into());
        let matched = RouteMatch {
            route,
            params: BTreeMap::new(),
        };
        assert!(
            validate_adapter(&req, &headers, &url, &matched).is_ok(),
            "{value}"
        );
    }
}

#[test]
fn github_actual_http_and_connect_intake_preserve_order_without_legacy_backtracking() {
    let snapshot = snapshot(WRITE);
    let target = format!("{BASE}?per_page=1&state=open&labels=fixture%2Ctriaged&page=1");
    let wire = format!(
        "GET {target} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: {PLACEHOLDER}\r\n\r\n"
    );
    assert!(read_request_head_from(&mut std::io::Cursor::new(wire.as_bytes()), None).is_err());
    let head = read_request_head_with_ordered_query_from(
        &mut std::io::Cursor::new(wire.as_bytes()),
        None,
        true,
    )
    .unwrap();
    let (_, url) = provider_query::parse_target_for_route(
        &snapshot,
        "GET",
        &head.target,
        None,
        &head.headers,
        Some("agent:test"),
    )
    .unwrap();
    assert_eq!(url.as_str(), target);
    let inner = target.strip_prefix("https://api.github.com").unwrap();
    let absolute = connect_inner_target_with_parser(inner, "api.github.com", 443, |raw| {
        provider_query::parse_target_for_route(
            &snapshot,
            "GET",
            raw,
            None,
            &head.headers,
            Some("agent:test"),
        )
    })
    .unwrap();
    assert_eq!(absolute, target);
    assert!(provider_query::parse_target_for_route(
        &snapshot,
        "GET",
        &target,
        None,
        &head.headers,
        Some("wrong")
    )
    .is_err());
    let mut legacy = (*snapshot).clone();
    legacy.routes[0].adapter_config = config(READ);
    legacy.routes[0]
        .adapter_config
        .as_object_mut()
        .unwrap()
        .remove("githubRepository");
    legacy.routes[0]
        .adapter_config
        .as_object_mut()
        .unwrap()
        .remove("operationBundle");
    legacy.routes[0].adapter_config["request"]
        .as_object_mut()
        .unwrap()
        .remove("queryMode");
    assert!(provider_query::parse_target_for_route(
        &legacy,
        "GET",
        &target,
        None,
        &head.headers,
        Some("agent:test")
    )
    .is_err());
    let mut ambiguous = (*snapshot).clone();
    let mut other = ambiguous.routes[0].clone();
    other.id = "route:other".into();
    ambiguous.routes.push(other);
    assert!(provider_query::parse_target_for_route(
        &ambiguous,
        "GET",
        &target,
        None,
        &head.headers,
        Some("agent:test")
    )
    .is_err());
}

#[test]
fn github_canonical_v3_and_final_built_request_pin_wire_body_and_discard() {
    let snapshot = snapshot(WRITE);
    let route = &snapshot.routes[0];
    let mut digests = HashSet::new();
    for suffix in [
        "",
        "?",
        "?labels=a+b&page=1",
        "?labels=a%20b&page=1",
        "?page=1&labels=a%20b",
        "?labels=a%2Bb",
    ] {
        let target = format!("{BASE}{suffix}");
        let (req, url, canonical, decision) = material(&snapshot, "GET", &target, "");
        assert_eq!(canonical["v"], 3);
        assert_eq!(canonical["request"]["query_mode"], MODE);
        assert_eq!(canonical["request"]["query_wire"], json!(url.query()));
        assert!(digests.insert(operation_digest(&canonical)));
        assert!(canonical_request_discard_headers(&canonical, &route.discard_headers).is_err());
        for profile in [ReleaseProfile::PolicyAware, ReleaseProfile::Native] {
            assert!(
                allowed_decision_discard_headers_profile(&snapshot, &decision, profile).is_err()
            );
        }
        let client = Client::builder().no_proxy().build().unwrap();
        let mut built = client.get(url.clone()).build().unwrap();
        provider_query::validate_built_request(&canonical, route, &url, &built).unwrap();
        buffered_request::validate_built_body(&decision, &built).unwrap();
        assert_eq!(
            provider_query::provider_url_for_decision(&snapshot, &decision, &req.method, &url)
                .unwrap(),
            url
        );
        built
            .headers_mut()
            .insert("accept-encoding", HeaderValue::from_static("gzip"));
        assert!(provider_query::validate_built_request(&canonical, route, &url, &built).is_err());
        for field in ["query_wire", "query", "query_mode", "discard_headers"] {
            let mut changed = canonical.clone();
            changed["request"][field] = json!("wrong");
            assert!(
                validate_canonical_url(&changed, route, "GET", &url).is_err(),
                "{field}"
            );
        }
    }
    let body = r#" {"title":"Exact body","extra":1.2300} "#;
    let (_, url, canonical, decision) = material(&snapshot, "POST", BASE, body);
    let client = Client::builder().no_proxy().build().unwrap();
    let built = client
        .post(url.clone())
        .body(body.to_string())
        .build()
        .unwrap();
    provider_query::validate_built_request(&canonical, route, &url, &built).unwrap();
    buffered_request::validate_built_body(&decision, &built).unwrap();
    let changed = client
        .post(url)
        .body(body.trim().to_string())
        .build()
        .unwrap();
    assert!(buffered_request::validate_built_body(&decision, &changed).is_err());
}

#[test]
fn github_pagination_normalization_confers_no_numeric_or_cross_resource_authority() {
    let route = route(WRITE);
    let current = Url::parse(BASE).unwrap();
    for id in ["1729", "99999999999999999999"] {
        let link=format!("<https://api.github.com/repositories/{id}/issues?per_page=1&state=open&page=2>; rel=\"next\"");
        assert_eq!(
            normalize_link(&link, &current, &route).unwrap(),
            format!("<{BASE}?per_page=1&state=open&page=2>; rel=\"next\"")
        );
    }
    let comments = Url::parse(&format!("{BASE}/11/comments?per_page=1&page=1")).unwrap();
    assert_eq!(
        normalize_link(
            "<https://api.github.com/repositories/1729/issues/11/comments?page=2>; rel=\"next\"",
            &comments,
            &route
        )
        .unwrap(),
        format!("<{BASE}/11/comments?page=2>; rel=\"next\"")
    );
    for raw in [
        "https://evil.example/repositories/1729/issues?page=2",
        "https://api.github.com/repos/other/fixture-repo/issues?page=2",
        "https://api.github.com/repositories/1729/issues/11/comments?page=2",
        "https://api.github.com/repositories/0/issues?page=2",
        "https://api.github.com/repositories/01/issues?page=2",
        "https://api.github.com/repositories/1729/issues?page=2&page=3",
        "https://api.github.com/repositories/1729/issues?page=2#fragment",
        "https://user@api.github.com/repositories/1729/issues?page=2",
    ] {
        assert!(
            normalize_link(&format!("<{raw}>; rel=\"next\""), &current, &route).is_err(),
            "{raw}"
        );
    }
    let one = format!("<{BASE}?page=2>; rel=\"next\"");
    assert!(normalize_link(&format!("{one}, {one}"), &current, &route).is_err());
    assert!(normalize_link(&format!("<{BASE}?page=2>; rel=\"other\""), &current, &route).is_err());
    assert!(normalize_link(&one, &Url::parse(&format!("{BASE}/11")).unwrap(), &route).is_err());
    for spacing in ["", " ", "   "] {
        assert_eq!(
            normalize_link(
                &format!("  <{BASE}?page=2>;{spacing}rel=\"next\"  "),
                &current,
                &route
            )
            .unwrap(),
            one
        );
    }
    assert!(normalize_link(&format!("<{BASE}>; rel=\"next\""), &current, &route).is_err());
    assert!(normalize_link(&format!("<{BASE}?page=2>;\trel=\"next\""), &current, &route).is_err());
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("fixture-owner/fixture-repo");
    let mut headers = HeaderMap::new();
    headers.insert(
        "link",
        HeaderValue::from_static(
            "<https://api.github.com/repositories/1729/issues?page=2>; rel=\"next\"",
        ),
    );
    let mut selected = response_metadata::prepare(&headers, &route.constraints, &guard).unwrap();
    assert_eq!(
        prepare_response_headers(&mut selected, &current, "GET", &route, &guard).unwrap_err()
            ["error"],
        "response_credential_reflection"
    );
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
                Err(error) => panic!("bounded synthetic upstream: {error}"),
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
    let method = decision["canonical_request"]["request"]["method"]
        .as_str()
        .unwrap();
    match finalize_upstream_response(
        state, snapshot, decision, method, url, response, guard, None, None, None, None, None,
        None, None, None, None, false,
    ) {
        ForwardResult::Buffered(wire) => wire,
        ForwardResult::Streamed => panic!("GitHub responses must buffer"),
    }
}

#[test]
fn github_real_finalizer_keeps_json_status_rate_metadata_and_normalized_pagination() {
    let snapshot = snapshot(WRITE);
    let state = test_gate_state(Arc::clone(&snapshot));
    for (method, status, content_type, body) in [
        (
            "GET",
            200,
            "application/json",
            br#" [ {"id":11,"number":11,"extra":{"kept":true}} ] "#.as_slice(),
        ),
        (
            "GET",
            200,
            "application/json; charset=utf-8",
            br#"[{"id":11,"number":11}]"#,
        ),
        (
            "POST",
            201,
            "Application/JSON;Charset=UTF-8",
            br#" {"id":12,"number":12,"body":"kept"} "#,
        ),
        (
            "GET",
            404,
            "application/json;\tcharset=utf-8",
            br#"{"message":"Not Found"}"#,
        ),
        (
            "GET",
            429,
            "application/json; charset=utf-8",
            br#"{"message":"rate limited","extra":true}"#,
        ),
    ] {
        let request_body = if method == "POST" {
            r#"{"title":"new"}"#
        } else {
            ""
        };
        let (_, url, _, decision) = material(&snapshot, method, BASE, request_body);
        let link = if status == 200 {
            "Link: <https://api.github.com/repositories/1729/issues?per_page=1&page=2>; rel=\"next\"\r\n"
        } else {
            ""
        };
        let headers=format!("Content-Type: {content_type}\r\nServer: synthetic\r\n{link}Retry-After: 1\r\nX-RateLimit-Remaining: 42\r\nX-GitHub-Request-Id: SYNTHETIC:1\r\n");
        let wire = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            upstream(status, &headers, body),
            &ResponseSecretGuard::default(),
        );
        let parsed = parse_buffered_response(&wire).unwrap();
        assert_eq!(
            parsed.status,
            status,
            "{}",
            String::from_utf8_lossy(&parsed.body)
        );
        assert_eq!(parsed.body, body);
        let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(!text.contains("server: synthetic"));
        assert!(text.contains("x-ratelimit-remaining: 42"));
        if status == 200 {
            assert!(text.contains("/repos/fixture-owner/fixture-repo/issues?per_page=1&page=2"));
            assert!(!text.contains("/repositories/"));
        }
    }
}

#[test]
fn github_real_finalizer_retains_disclosure_framing_link_and_freshness_guards() {
    let snapshot = snapshot(WRITE);
    let state = test_gate_state(Arc::clone(&snapshot));
    let (_, url, _, decision) = material(&snapshot, "GET", BASE, "");
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-provider-secret");
    for value in [
        "application/json; charset=iso-8859-1",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; profile=fixture",
        "application/json; charset=\"utf-8\"",
        "application/json; charset =utf-8",
        "application/problem+json",
        " application/json",
        "application/json ",
        "application/json; charset=utf-8 ",
    ] {
        assert!(!is_json_content_type(value), "{value}");
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_str(value).unwrap());
        assert!(
            validate_response_envelopes(
                &snapshot.routes[0],
                StatusCode::OK,
                &headers,
                Some(2),
                None
            )
            .is_err(),
            "{value}"
        );
        assert!(
            validate_response_envelopes(
                &snapshot.routes[0],
                StatusCode::NO_CONTENT,
                &headers,
                Some(0),
                None
            )
            .is_err(),
            "{value}"
        );
        assert!(
            buffered_response::inspect_github_body(
                &snapshot.routes[0],
                &response_profile(false),
                StatusCode::OK,
                Some(value),
                b"[]".to_vec().into(),
                &guard
            )
            .is_err(),
            "{value}"
        );
    }
    for value in [
        None,
        Some("application/json"),
        Some("application/json; charset=utf-8"),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert("content-type", HeaderValue::from_str(value).unwrap());
        }
        validate_response_envelopes(
            &snapshot.routes[0],
            StatusCode::NO_CONTENT,
            &headers,
            Some(0),
            None,
        )
        .unwrap();
    }
    for extra in [
        "X-Unselected: synthetic-provider-secret\r\n",
        "Content-Encoding: gzip\r\n",
        "Set-Cookie: forbidden=1\r\n",
        "Content-Type: application/json\r\n",
        "Link: <https://other.example/issues?page=2>; rel=\"next\"\r\n",
        "X-RateLimit-Remaining: 1\r\nX-RateLimit-Remaining: 2\r\n",
    ] {
        let wire = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            upstream(
                200,
                &format!("Content-Type: application/json\r\n{extra}"),
                b"[]",
            ),
            &guard,
        );
        assert_eq!(
            parse_buffered_response(&wire).unwrap().status,
            502,
            "{extra}"
        );
    }
    for body in [
        br#"{"secret":"synthetic-provider-secret"}"#.as_slice(),
        br#"{"secret":"\u0073ynthetic-provider-secret"}"#,
        br#"{"x":1,"x":2}"#,
    ] {
        let wire = finalized(
            &snapshot,
            &state,
            &decision,
            &url,
            upstream(200, "Content-Type: application/json\r\n", body),
            &guard,
        );
        assert_eq!(parse_buffered_response(&wire).unwrap().status, 502);
    }
    *state.snapshot.write().unwrap() = test_snapshot(2);
    let wire = finalized(
        &snapshot,
        &state,
        &decision,
        &url,
        upstream(200, "Content-Type: application/json\r\n", b"[]"),
        &guard,
    );
    let parsed = parse_buffered_response(&wire).unwrap();
    assert_eq!(parsed.status, 502);
    assert_eq!(
        serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],
        "response_snapshot_revoked"
    );
}

#[test]
fn github_unsupported_proof_and_controlled_consumers_refuse_before_lease() {
    let snapshot = snapshot(WRITE);
    let mut state = test_gate_state(Arc::clone(&snapshot));
    let target = format!("{BASE}?per_page=1&state=open&page=1");
    state.atomic_release_authorization_enabled = true;
    let result = decide_internal(
        &state,
        &snapshot,
        request("GET", &target, ""),
        Some("agent:test"),
    );
    assert_eq!(
        result["payload"]["error"],
        "ordered_query_release_profile_unsupported"
    );
    state.atomic_release_authorization_enabled = false;
    for nonce in [
        RESPONSE_PROOF_NONCE_HEADER,
        STREAM_RESPONSE_PROOF_NONCE_HEADER,
        RESPONSE_OBSERVATION_NONCE_HEADER,
    ] {
        let mut req = request("GET", &target, "");
        req.headers.insert(nonce.into(), "synthetic".into());
        let result = decide_internal(&state, &snapshot, req, Some("agent:test"));
        assert_eq!(
            result["payload"]["error"],
            "response_metadata_v2_proof_unsupported"
        );
    }
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.audit_queue.lock().unwrap().is_empty());
}
