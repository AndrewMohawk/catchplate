//! Real non-preview ordinary decisions with synthetic admitted operator profiles.
//! No provider, broker, socket, environment mutation, or successful guard stub.
//! A deliberately absent broker is the positive acquisition boundary, not an
//! end-to-end publication claim. The per-call clock affects semantic admission
//! only; real principal/cache expiry and acquisition deadlines remain intact.
use super::*;
use crate::operator_static_preparation_diagnostics::capture;
use crate::tests::{test_gate_state, test_snapshot};
use base64::Engine as _;
use sha2::{Digest, Sha512};

const TOKEN: &str = "synthetic-ordinary-client-token";
const CREDENTIAL: &str = "credential:ordinary";
const SUBJECT: &str = "synthetic-ordinary-account";
const PACKAGE: &str = "@fixture/ordinary";
const BASE: &str = "https://registry.npmjs.org";

fn binding() -> Value {
    json!({"credentialType":"static","provider":"operator-demo",
        "subjects":[SUBJECT],"secretClass":"bearerToken"})
}

fn generic_route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.host = npm_publish::HOST.into();
    route.resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    route.methods = HashSet::from(["GET".into()]);
    route.paths = vec![compile_template("/resource/{owner}").unwrap()];
    route.credential_ref = Some(CREDENTIAL.into());
    route.adapter_config["credentialMode"] = json!("required");
    route.adapter_config.as_object_mut().unwrap().remove("noCredentialProof");
    route.adapter_config["credentialBinding"] = binding();
    route.jit = json!({});
    route
}

fn npm_route(publish: bool) -> Route {
    let mut route = generic_route();
    route.id = if publish { "route:publish" } else { "route:metadata" }.into();
    route.paths = vec![compile_template(npm_publish::PATH).unwrap()];
    route.credential_header = Some(json!({"mode":"replaceExact",
        "expectedValue":npm_publish::PLACEHOLDER}));
    route.discard_headers = npm_publish::DISCARD.iter().map(|value| value.to_string()).collect();
    if publish {
        route.methods = HashSet::from(["PUT".into()]);
        route.adapter_type = npm_publish::ADAPTER.into();
        route.adapter_config = json!({"credentialBinding":binding(),"package":PACKAGE,"tag":"fixture",
            "request":npm_publish::request_config(),"response":npm_publish::response_profile(false)});
        route.constraints = vec![npm_publish::envelope("publish-response"), json!({
            "id":"publish-hour","type":"requestTimeWindow","phase":"request","timezone":"UTC",
            "dailyWindows":[{"start":"12:00","end":"13:00"}]
        })];
        npm_publish::validate_route(&route).unwrap();
    } else {
        route.adapter_type = npm_metadata::ADAPTER.into();
        route.adapter_config = json!({"credentialBinding":binding(),"packages":[PACKAGE],
            "request":npm_metadata::request_config(),"response":npm_metadata::response_profile(false)});
        route.constraints = vec![npm_metadata::envelope("metadata-response")];
        npm_metadata::validate_route(&route).unwrap();
    }
    validate_route_response_release_mode(&route).unwrap();
    route
}

fn fixture(routes: Vec<Route>, operator: bool) -> (GateState, Arc<Snapshot>) {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.policy_id = "serverware-operator-demo".into();
    snapshot.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(TOKEN.as_bytes()), source_cidrs: vec![],
        expires_at_ms: Some(now_epoch_ms() + 60_000), basic_transport: None, managed_renewal: None,
    });
    snapshot.routes = routes;
    snapshot.credentials.insert(CREDENTIAL.into(), Credential {
        provider: "operator-demo".into(), provider_subject: Some(SUBJECT.into()),
        injection: json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"}),
    });
    let snapshot = Arc::new(snapshot);
    let mut state = test_gate_state(Arc::clone(&snapshot));
    if operator {
        // Validates the actual policy identity, finite bearer principal, public
        // resolution policy and fixed registry origin; no forged profile permit.
        state.policy_shadow = ShadowRuntime::new_operator_demo(
            operator_demo::test_publish_dispatch_profile(&snapshot));
        state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    }
    state.binary_digest = sha256_prefixed(b"synthetic-ordinary-gate");
    assert!(state.credential_lease_url.is_none());
    assert!(state.rate_limit_consume_url.is_none());
    (state, snapshot)
}

fn request(method: &str, path: &str, body: &str) -> DecisionRequest {
    serde_json::from_value(json!({"method":method,"url":format!("{BASE}{path}"),
        "headers":{"proxy-authorization":format!("Bearer {TOKEN}")},"body":body})).unwrap()
}

fn npm_request(publish: bool) -> DecisionRequest {
    let mut req = request(if publish { "PUT" } else { "GET" }, "/@fixture%2fordinary", "");
    req.headers.insert("authorization".into(), npm_publish::PLACEHOLDER.into());
    req.headers.insert("accept".into(), if publish { "*/*" } else { "application/json" }.into());
    req.headers.insert("npm-command".into(), "publish".into());
    req.headers.insert("accept-encoding".into(), "gzip,deflate".into());
    req.headers.insert("npm-session".into(), "synthetic-session".into());
    if publish {
        let bytes = b"inert synthetic archive bytes; never extracted";
        let version = "1.2.3";
        let attachment = format!("{PACKAGE}-{version}.tgz");
        req.headers.insert("content-type".into(), "application/json".into());
        req.body = json!({"_id":PACKAGE,"name":PACKAGE,"access":null,"dist-tags":{"fixture":version},
            "versions":{version:{"name":PACKAGE,"version":version,"_id":format!("{PACKAGE}@{version}"),
                "dist":{"integrity":format!("sha512-{}", general_purpose::STANDARD.encode(Sha512::digest(bytes))),
                    "shasum":hex::encode(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY,bytes).as_ref()),
                    "tarball":format!("http://registry.npmjs.org/{PACKAGE}/-/{attachment}")}}},
            "_attachments":{attachment:{"content_type":"application/octet-stream",
                "data":general_purpose::STANDARD.encode(bytes),"length":bytes.len()}}}).to_string();
    }
    req
}

fn at(state: &GateState, snapshot: &Arc<Snapshot>, req: DecisionRequest, time: &str) -> (Value, Vec<String>, usize) {
    let observed = u128::try_from(parse_rfc3339_ms(time).unwrap()).unwrap();
    capture(false, || decide_internal_with_mode_and_shadow(
        state, snapshot, req, None, false, None, None, Some(observed)))
}

fn assert_untouched(state: &GateState, lines: &[String], count: usize) {
    assert!(lines.is_empty());
    assert_eq!(count, 0);
    assert!(state.credential_lease_activity.lock().unwrap().is_empty());
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
    assert!(state.grants.lock().unwrap().is_empty());
    assert!(state.pinned_upstream_clients.lock().unwrap().entries.is_empty());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
}

fn assert_acquisition_boundary(state: &GateState, result: &(Value, Vec<String>, usize)) {
    assert_eq!(result.0["status_code"], 503, "{}", result.0);
    assert_eq!(result.0["payload"]["error"], "credential_generation_missing");
    assert_eq!(result.2, 1);
    assert_eq!(result.1.len(), 1);
    let diagnostic: Value = serde_json::from_str(&result.1[0]).unwrap();
    assert_eq!(diagnostic["stage"], "generation_refresh");
    assert_eq!(state.credential_lease_activity.lock().unwrap().len(), 1);
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
    assert!(state.pinned_upstream_clients.lock().unwrap().entries.is_empty());
}

fn seed_pair(state: &GateState, snapshot: &Snapshot) {
    let scope = CredentialLeaseScope::new("agent:test", &snapshot.routes[0].id, CREDENTIAL);
    let metadata: BTreeMap<String, Value> = serde_json::from_value(json!({
        "provider":"operator-demo","provider_subject":SUBJECT,"secret_class":"bearerToken","oauth":false})).unwrap();
    let hash = credential_lease_metadata_sha256(&metadata);
    let expires_at_epoch_ms = now_epoch_ms() + 60_000;
    let expires_at_monotonic = Instant::now() + Duration::from_secs(60);
    state.credential_generations.lock().unwrap().insert(scope.clone(), CredentialLeaseGeneration {
        profile: ReleaseProfile::Legacy, policy_hash: snapshot.hash.clone(), version: 7,
        metadata: metadata.clone(), metadata_sha256: hash.clone(), expires_at_epoch_ms, expires_at_monotonic,
    });
    state.credential_leases.lock().unwrap().insert(CredentialLeaseCacheKey::new_bound(&scope, None, None), SecretLease {
        profile: ReleaseProfile::Legacy, scope, version: 7,
        secret: Zeroizing::new("synthetic-ordinary-static-secret".into()), metadata, metadata_sha256: hash,
        policy_hash: snapshot.hash.clone(), request_authority: None, release_authorization: None,
        expires_at_epoch_ms, expires_at_monotonic,
    });
}

#[test]
fn ordinary_operator_npm_closed_window_denies_before_acquisition() {
    for time in ["2026-07-14T11:59:59.999Z", "2026-07-14T13:00:00Z"] {
        let (state, snapshot) = fixture(vec![npm_route(true), npm_route(false)], true);
        let (decision, lines, count) = at(&state, &snapshot, npm_request(true), time);
        assert_eq!(decision["status_code"], 403, "{decision}");
        assert_eq!(decision["payload"]["error"], "request_time_daily_window_denied");
        assert_untouched(&state, &lines, count);
    }
}

#[test]
fn ordinary_operator_npm_open_window_and_metadata_reach_acquisition() {
    for (publish, time) in [(true, "2026-07-14T12:00:00Z"),
        (true, "2026-07-14T12:59:59.999Z"), (false, "2026-07-14T13:00:00Z")] {
        let (state, snapshot) = fixture(vec![npm_route(true), npm_route(false)], true);
        let result = at(&state, &snapshot, npm_request(publish), time);
        assert_acquisition_boundary(&state, &result);
    }
}

#[test]
fn ordinary_request_value_operation_and_date_denials_precede_effects() {
    let cases = [
        (json!({"id":"owner","type":"requestValue","phase":"request","rules":[{
            "source":"pathParam","name":"owner","predicate":{"kind":"equals","value":"approved"}}]}),
            "/resource/denied", "request_value_predicate_denied"),
        (json!({"id":"operation","type":"operationPolicy","phase":"request",
            "deniedOperations":["generic.read"]}), "/resource/approved", "credential_operation_denied"),
        (json!({"id":"date","type":"queryDateWindow","phase":"request","parameters":["at"],
            "formats":["rfc3339"],"maxAgeDays":1,"required":true}),
            "/resource/approved?at=2026-07-12T11%3A59%3A59Z", "query_date_window_exceeded"),
    ];
    for operator in [true, false] {
        for (constraint, path, error) in &cases {
            let mut route = generic_route();
            route.adapter_config["request"]["allowedQueryKeys"] = json!(["at"]);
            route.constraints.push(constraint.clone());
            route.constraints.push(json!({"id":"quota","type":"rateLimit","max":1,
                "windowSeconds":60,"store":"local"}));
            let (state, snapshot) = fixture(vec![route], operator);
            let req = request("GET", path, "");
            parse_validated_absolute_target(&req.url).expect("semantic fixture uses a canonical target");
            let (decision, lines, count) = at(&state, &snapshot, req, "2026-07-14T12:00:00Z");
            assert_eq!(decision["status_code"], 403, "{decision}");
            assert_eq!(decision["payload"]["error"], *error);
            assert_untouched(&state, &lines, count);
        }
    }
}

#[test]
fn ordinary_response_binding_missing_and_noncanonical_sources_precede_acquisition() {
    for (body, error) in [("{}", "response_binding_source_missing"),
        (r#"{"amount":"001"}"#, "response_binding_source_invalid")] {
        let mut route = generic_route();
        route.methods = HashSet::from(["POST".into()]);
        route.adapter_config["request"] = json!({"allowedHeaders":["content-type"],"allowedQueryKeys":[],
            "allowedMediaTypes":["application/json"],"bodyMode":"json","maxBodyBytes":512,
            "operation":{"name":"generic.read","jsonFields":["amount"]},"valueRules":[]});
        route.adapter_config["response"]["allowedFields"] = json!(["amount"]);
        route.constraints.extend([json!({"id":"body","type":"jsonBody","allowedFields":["amount"]}),
            json!({"id":"reply","type":"responseBinding","phase":"response","successStatusCodes":[200],
                "contentTypes":["application/json"],"operations":["generic.read"],"bindings":[{
                    "id":"amount","operationField":"amount","responseField":"amount","comparison":"canonicalInteger"}]})]);
        let (state, snapshot) = fixture(vec![route], true);
        let mut req = request("POST", "/resource/approved", body);
        req.headers.insert("content-type".into(), "application/json".into());
        let (decision, lines, count) = at(&state, &snapshot, req, "2026-07-14T12:00:00Z");
        assert_eq!(decision["status_code"], 403, "{decision}");
        assert_eq!(decision["payload"]["error"], error);
        assert_untouched(&state, &lines, count);
    }
}

#[test]
fn ordinary_capture_and_provider_account_bind_before_canonical_quota_once() {
    let mut route = generic_route();
    route.constraints.extend([
        json!({"id":"capture-owner","type":"requestValue","phase":"request","rules":[{
            "source":"pathParam","name":"owner","capture":"selectedOwner",
            "predicate":{"kind":"equals","value":"approved"}}]}),
        json!({"id":"account-once","type":"rateLimit","max":1,"windowSeconds":60,"store":"local",
            "key":{"scope":["route","operation"],"operationFields":["providerAccount"]}}),
        json!({"id":"reply","type":"responseBinding","phase":"response","successStatusCodes":[200],
            "contentTypes":["application/json"],"operations":["generic.read"],"bindings":[{
                "id":"owner","operationField":"selectedOwner","responseField":"safe","comparison":"exactString"}]}),
    ]);
    let (state, snapshot) = fixture(vec![route], true);
    seed_pair(&state, &snapshot);
    let (decision, lines, count) = at(&state, &snapshot, request("GET", "/resource/approved", ""), "2026-07-14T12:00:00Z");
    assert_eq!(decision["allowed"], true, "{decision}");
    assert!(decision.get("preview").is_none());
    assert_eq!(decision["policy_effect_results"]["legacy_rate_limits_committed"], true);
    assert_eq!(decision["credential_version"], 7);
    let expected = json!({"operation":"generic.read","selectedOwner":"approved",
        "providerAccount":sha256_prefixed(b"operator-demo\0synthetic-ordinary-account")});
    assert_eq!(decision["operation"], expected);
    assert_eq!(decision["canonical_request"]["operation"], expected);
    assert_eq!(decision["request_digest"], canonical_request_digest_profile(&decision["canonical_request"], ReleaseProfile::Legacy));
    assert_eq!(decision["operation_digest"], operation_digest_profile(&decision["canonical_request"], ReleaseProfile::Legacy));
    assert!(lines.is_empty());
    assert_eq!(count, 0);
    let counters = state.constraint_rate_counters.lock().unwrap();
    assert_eq!(counters.len(), 1);
    assert_eq!(counters.values().next().unwrap().count, 1);
    drop(counters);
    let (denied, _, _) = at(&state, &snapshot, request("GET", "/resource/approved", ""), "2026-07-14T12:00:00Z");
    assert_eq!(denied["status_code"], 403, "{denied}");
    assert_eq!(denied["payload"]["error"], "credential_rate_limit_exceeded");
    assert_eq!(denied["payload"]["store"], "local");
    assert_eq!(state.constraint_rate_counters.lock().unwrap().values().next().unwrap().count, 1);
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
}

#[test]
fn ordinary_x_semantic_denial_precedes_generation_metadata() {
    let mut route = generic_route();
    route.host = "api.x.com".into();
    route.paths = vec![compile_template("/2/users/me").unwrap()];
    route.adapter_type = "x.v2".into();
    let profile = provider_request_profile("x.v2", Some("readOnly")).unwrap().unwrap();
    route.adapter_config = json!({"mode":"readOnly","blockWrites":true,"appIds":["synthetic-x-app"],
        "allowedReadOperations":["users.read"],"credentialBinding":{"credentialType":"oauth2","provider":"x",
            "subjects":["synthetic-x-account"],"clientIds":["synthetic-x-app"],"requiredScopes":["users.read"]},
        "request":{"allowedHeaders":profile.allowed_headers,"allowedQueryKeys":profile.allowed_query_keys,
            "allowedMediaTypes":profile.allowed_media_types,"discardHeaders":[],"maxBodyBytes":profile.max_body_bytes,"valueRules":[]},
        "response":generic_route().adapter_config["response"]});
    route.constraints.push(json!({"id":"deny-users","type":"operationPolicy","phase":"request",
        "deniedOperations":["users.read"]}));
    let (state, snapshot) = fixture(vec![route], false);
    let mut changed = (*snapshot).clone();
    changed.credentials.insert(CREDENTIAL.into(), Credential { provider:"x".into(),
        provider_subject:Some("synthetic-x-account".into()),injection:json!({"type":"bearer","header":"Authorization",
            "field":"access_token","__serverwareCredentialType":"oauth2","__serverwareOAuthClientId":"synthetic-x-app",
            "__serverwareGrantedScopes":["users.read"]}) });
    let snapshot = Arc::new(changed);
    *state.snapshot.write().unwrap() = Arc::clone(&snapshot);
    let mut req = request("GET", "/2/users/me", "");
    req.url = "https://api.x.com/2/users/me".into();
    let (decision, lines, count) = at(&state, &snapshot, req, "2026-07-14T12:00:00Z");
    assert_eq!(decision["status_code"], 403, "{decision}");
    assert_eq!(decision["payload"]["error"], "credential_operation_denied");
    assert_untouched(&state, &lines, count);
}
