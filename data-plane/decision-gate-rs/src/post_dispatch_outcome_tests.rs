//! Real bounded loopback TLS, production decisions/send checks/finalizers.
//! Profile admission and the Alchemy credential cache are explicitly synthetic.
//! This is not full proxy ingress, native custody, an authority-ledger receipt,
//! or a real registry/Alchemy operation. No public DNS or provider is contacted.
use super::*;
use crate::tests::{generic_policy_route, test_gate_state, test_snapshot};
use std::sync::atomic::{AtomicBool, AtomicUsize};

const HOST: &str = "registry.npmjs.org";
const TARGET: &str = "https://registry.npmjs.org/resource";
const CANARY: &str = "synthetic-post-dispatch-secret-canary";
const PUT_BODY: &[u8] = br#"{"safe":true}"#;

struct Peer {
    address: SocketAddr,
    certificate: Vec<u8>,
    stop: Arc<AtomicBool>,
    arrivals: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<IncomingRequest>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Peer {
    fn new(host: &str, reply: Vec<u8>, after_effect: Option<Box<dyn FnOnce() + Send>>) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::new(vec![host.to_owned()]).unwrap();
        parameters.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
        let certificate = parameters.self_signed(&key).unwrap().der().to_vec();
        let tls = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![CertificateDer::from(certificate.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        ).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let arrivals = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stopped, accepted, received) = (stop.clone(), arrivals.clone(), requests.clone());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut after_effect = after_effect;
            while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => panic!("local receiver accept failed"),
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut stream = StreamOwned::new(ServerConnection::new(tls.clone()).unwrap(), stream);
                let head = read_request_head_from(&mut stream, None).expect("complete local request head");
                let request = read_request_body_from_head(&mut stream, head, 4096)
                    .expect("complete local request body");
                // The synthetic provider effect happens BEFORE any reply, only
                // after the real method/target/body have arrived completely.
                received.lock().unwrap().push(request);
                if let Some(callback) = after_effect.take() { callback(); }
                if !reply.is_empty() { stream.write_all(&reply).expect("local response write"); }
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Self { address, certificate, stop, arrivals, requests, worker: Some(worker) }
    }

    fn client(&self, host: &str) -> Client {
        Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .resolve(host, self.address)
            .add_root_certificate(reqwest::Certificate::from_der(&self.certificate).unwrap())
            .timeout(Duration::from_secs(3)).build().unwrap()
    }

    fn finish(mut self, method: &str, path: &str, body: &[u8], count: usize) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().expect("bounded local receiver");
        assert_eq!(self.arrivals.load(Ordering::SeqCst), count, "unexpected retry/connection");
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), count, "unexpected provider effect count");
        for request in requests.iter() {
            assert_eq!(request.method, method);
            assert_eq!(request.target, path);
            assert!(request.body == body, "provider received different original bytes");
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn reply(status: u16, body: &[u8], extra: &str, declared_extra: usize) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len() + declared_extra).into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn enable_audit(state: &mut GateState) {
    // A retained in-process queue only: no worker, audit HTTP request or ACK.
    state.audit_url = Some("http://127.0.0.1:1/not-contacted".into());
    state.audit_token = Some("synthetic-audit-token".into());
}

fn fixture(method: &str) -> (Arc<GateState>, Arc<Snapshot>, Value) {
    let mut held = (*test_snapshot(1)).clone();
    held.policy_id = "serverware-operator-demo".into();
    held.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(b"synthetic-app-token"), source_cidrs: vec![],
        expires_at_ms: Some(now_epoch_ms() + 60_000), basic_transport: None,
    });
    let route = &mut held.routes[0];
    route.host = HOST.into();
    route.methods = HashSet::from([method.to_owned()]);
    route.resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    route.adapter_config = generic_policy_route(if method == "GET" { "none" } else { "json" }, json!(1024))
        ["adapter"]["config"].clone();
    route.constraints[0]["statusCodes"] = json!([200, 201]);
    route.adapter_config["response"]["allowedHeaders"] = json!(["etag"]);
    route.constraints[0]["allowedResponseHeaderNames"] = json!(["etag"]);
    let profile = operator_demo::test_publish_dispatch_profile(&held);
    let snapshot = Arc::new(held);
    let mut state = test_gate_state(snapshot.clone());
    state.policy_shadow = ShadowRuntime::new_operator_demo(profile);
    state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    enable_audit(&mut state);
    let request: DecisionRequest = serde_json::from_value(json!({
        "method":method,"url":TARGET,
        "headers":if method == "GET" {json!({})} else {json!({"content-type":"application/json"})},
        "body":if method == "GET" {""} else {std::str::from_utf8(PUT_BODY).unwrap()},
    })).unwrap();
    let decision = decide_internal(&state, &snapshot, request, Some("agent:test"));
    assert_eq!(decision["allowed"], true, "real synthetic policy decision must allow");
    assert_eq!(decision["action"], "allow");
    (Arc::new(state), snapshot, decision)
}

fn send(state: &GateState, snapshot: &Arc<Snapshot>, peer: &Peer, method: &str,
    deadlines: UpstreamSendDeadlines) -> Result<reqwest::blocking::Response, UpstreamSendError> {
    let mut builder = peer.client(HOST).request(Method::from_bytes(method.as_bytes()).unwrap(), TARGET);
    if method != "GET" { builder = builder.header("content-type", "application/json").body(PUT_BODY); }
    send_upstream_request_with_current_lease(state, snapshot, None, builder, deadlines, false)
}

fn finalize(state: &GateState, snapshot: &Arc<Snapshot>, decision: &Value, method: &str,
    target: &str, response: reqwest::blocking::Response) -> SensitiveResponseBytes {
    let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings(CANARY);
    match finalize_upstream_response(state, snapshot, decision, method, &Url::parse(target).unwrap(),
        response, &guard, None, None, None, None, None, None, None, None, None, false) {
        ForwardResult::Buffered(wire) => wire,
        ForwardResult::Streamed => panic!("fixture must remain buffered"),
    }
}

fn assert_outcome(value: &Value, dispatch: &str, may_have_committed: bool) {
    assert_eq!(value["upstreamDispatch"], dispatch);
    assert_eq!(value["providerOutcome"], "unknown");
    assert_eq!(value["retryProviderRequest"], false);
    assert_eq!(value["providerOperationMayHaveCommitted"], may_have_committed);
    assert!(!value.to_string().contains(CANARY), "public outcome leaked synthetic secret");
}

fn assert_blocked(state: &GateState, wire: &[u8], status: u16, upstream: u16,
    error: &str, may_have_committed: bool) {
    assert!(!String::from_utf8_lossy(wire).contains(CANARY), "wire leaked synthetic secret");
    let parsed = parse_buffered_response(wire).unwrap();
    assert_eq!(parsed.status, status);
    let value: Value = serde_json::from_slice(parsed.body).unwrap();
    assert_eq!(value["error"], error);
    assert_eq!(value["upstream_status"], upstream);
    assert_outcome(&value, "response_received", may_have_committed);
    let queue = state.audit_queue.lock().unwrap();
    let blocked = queue.iter().filter(|entry| entry.event_type == "data_plane.response.blocked").collect::<Vec<_>>();
    assert_eq!(blocked.len(), 1);
    let event = &blocked[0].event;
    assert_eq!(event["outcome"], "blocked");
    assert_eq!(event["upstream_status"], upstream);
    let audit_error = event.get("error").or_else(|| event.pointer("/response_validation/error"));
    assert_eq!(audit_error, Some(&json!(error)));
    assert_outcome(event, "response_received", may_have_committed);
    assert!(queue.iter().all(|entry| entry.event_type != "data_plane.response.released"));
    assert!(queue.iter().all(|entry| !entry.event.to_string().contains(CANARY)));
}

#[test]
fn put_effect_precedes_malformed_reflected_and_truncated_replies_without_retry() {
    for (body, extra, missing, error) in [
        (b"{".to_vec(), String::new(), 0, "response_invalid_json"),
        (format!("{{\"safe\":\"{CANARY}\"}}").into_bytes(), String::new(), 0, "response_credential_reflection"),
        (b"{}".to_vec(), format!("ETag: {CANARY}\r\n"), 0, "response_credential_reflection"),
        (b"{".to_vec(), String::new(), 64, "upstream_body_failed"),
        (b"{}".to_vec(), String::new(), 1024, "response_body_too_large"),
    ] {
        let (state, snapshot, decision) = fixture("PUT");
        let peer = Peer::new(HOST, reply(201, &body, &extra, missing), None);
        let response = send(&state, &snapshot, &peer, "PUT", UpstreamSendDeadlines::default()).unwrap();
        let wire = finalize(&state, &snapshot, &decision, "PUT", TARGET, response);
        assert_blocked(&state, &wire, 409, 201, error, true);
        peer.finish("PUT", "/resource", PUT_BODY, 1);
    }
}

#[test]
fn get_rejected_response_retains_502_without_claiming_a_write_or_retry() {
    for (missing, error) in [(0, "response_invalid_json"), (64, "upstream_body_failed")] {
        let (state, snapshot, decision) = fixture("GET");
        let peer = Peer::new(HOST, reply(200, b"{", "", missing), None);
        let response = send(&state, &snapshot, &peer, "GET", UpstreamSendDeadlines::default()).unwrap();
        let wire = finalize(&state, &snapshot, &decision, "GET", TARGET, response);
        assert_blocked(&state, &wire, 502, 200, error, false);
        peer.finish("GET", "/resource", b"", 1);
    }
}

#[test]
fn original_deadline_presend_refusal_has_zero_provider_arrivals() {
    let (state, snapshot, _) = fixture("PUT");
    let peer = Peer::new(HOST, reply(201, b"{}", "", 0), None);
    let result = send(&state, &snapshot, &peer, "PUT", UpstreamSendDeadlines {
        policy_expires_at_epoch_ms: Some(1), ..UpstreamSendDeadlines::default()
    });
    assert!(matches!(&result, Err(UpstreamSendError::CredentialAuthority("upstream_send_authority_expired"))));
    assert!(result.err().unwrap().observed_dispatch().is_none());
    assert!(state.audit_queue.lock().unwrap().iter().all(|entry|
        entry.event.get("upstreamDispatch").is_none()));
    peer.finish("PUT", "/resource", PUT_BODY, 0);
}

#[test]
fn actual_postsend_profile_invalidation_is_not_a_predispatch_barrier_failure() {
    let (state, snapshot, decision) = fixture("PUT");
    let mut next = (*snapshot).clone();
    next.epoch += 1; next.policy_sequence += 1;
    next.hash = sha256_prefixed(b"synthetic-next-policy");
    let prepared = state.policy_shadow.prepare_operator_reload(&snapshot, &next).unwrap();
    let changed = state.clone();
    let peer = Peer::new(HOST, reply(201, b"{\"safe\":true}", "", 0), Some(Box::new(move || {
        // This mutates the real Profile generation after the provider effect.
        // It deliberately does not attempt a snapshot write while execute holds
        // its read guard; no successful permit/error is fabricated.
        changed.policy_shadow.commit_operator_reload(prepared).unwrap();
    })));
    let result = send(&state, &snapshot, &peer, "PUT", UpstreamSendDeadlines::default());
    assert!(matches!(&result, Err(UpstreamSendError::PostDispatch {
        dispatch: post_dispatch_outcome::Dispatch::ResponseReceived, ..
    })));
    let error = result.err().unwrap();
    let wire = post_dispatch_outcome::response(&snapshot, &decision, "PUT", &Url::parse(TARGET).unwrap(),
        error.observed_dispatch().unwrap(), StatusCode::BAD_GATEWAY,
        error.with_observed_status(provider_operation_outcome_unknown()));
    let parsed = parse_buffered_response(&wire).unwrap();
    assert_eq!(parsed.status, 409);
    let value: Value = serde_json::from_slice(parsed.body).unwrap();
    assert_eq!(value["error"], "provider_operation_outcome_unknown");
    assert_eq!(value["upstream_status"], 201);
    assert_outcome(&value, "response_received", true);
    peer.finish("PUT", "/resource", PUT_BODY, 1);
}

#[test]
fn provider_effect_with_lost_reply_is_attempted_unknown_not_retry_authority() {
    let (state, snapshot, decision) = fixture("PUT");
    let peer = Peer::new(HOST, vec![], None);
    let result = send(&state, &snapshot, &peer, "PUT", UpstreamSendDeadlines::default());
    assert!(matches!(&result, Err(UpstreamSendError::Request(_))));
    let wire = post_dispatch_outcome::response(&snapshot, &decision, "PUT", &Url::parse(TARGET).unwrap(),
        result.err().unwrap().observed_dispatch().unwrap(), StatusCode::BAD_GATEWAY,
        provider_operation_outcome_unknown());
    assert_outcome(&serde_json::from_slice::<Value>(parse_buffered_response(&wire).unwrap().body).unwrap(), "attempted", true);
    assert_eq!(parse_buffered_response(&wire).unwrap().status, 409);
    peer.finish("PUT", "/resource", PUT_BODY, 1);
}

fn alchemy_fixture() -> (GateState, Arc<Snapshot>, Value, DecisionRequest) {
    let mut held = (*test_snapshot(1)).clone();
    let route = &mut held.routes[0];
    route.host = "eth-mainnet.g.alchemy.com".into();
    route.adapter_type = alchemy_rpc_read::ADAPTER.into();
    route.methods = HashSet::from(["POST".into()]);
    route.paths = vec![compile_template("/v2").unwrap()];
    route.credential_ref = Some("synthetic-alchemy".into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":alchemy_rpc_read::PLACEHOLDER}));
    route.discard_headers = alchemy_rpc_read::DISCARD.iter().map(|name| name.to_string()).collect();
    route.adapter_config = json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":["synthetic-account"],"secretClass":"bearerToken"},"chain":"eth-mainnet",
        "request":alchemy_rpc_read::request_config(),"response":alchemy_rpc_read::response_profile(false)});
    route.constraints = vec![alchemy_rpc_read::envelope("response")];
    route.jit = json!({});
    held.credentials.insert("synthetic-alchemy".into(), Credential {provider:"operator-demo".into(),
        provider_subject:Some("synthetic-account".into()),
        injection:json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"})});
    let snapshot = Arc::new(held);
    let mut state = test_gate_state(snapshot.clone());
    enable_audit(&mut state);
    let scope = CredentialLeaseScope::new("agent:test", "route:test", "synthetic-alchemy");
    let metadata: BTreeMap<String, Value> = serde_json::from_value(json!({"provider":"operator-demo",
        "provider_subject":"synthetic-account","secret_class":"bearerToken","oauth":false})).unwrap();
    state.credential_generations.lock().unwrap().insert(scope.clone(), CredentialLeaseGeneration {
        profile:ReleaseProfile::Legacy, policy_hash:snapshot.hash.clone(), version:7,
        metadata_sha256:credential_lease_metadata_sha256(&metadata), metadata:metadata.clone(),
        expires_at_epoch_ms:now_epoch_ms()+60_000,
        expires_at_monotonic:Instant::now()+Duration::from_secs(60),
    });
    // Synthetic retained lease, not acquisition or a native authority claim.
    state.credential_leases.lock().unwrap().insert(CredentialLeaseCacheKey::new_bound(&scope, None, None), SecretLease {
        profile:ReleaseProfile::Legacy, scope, version:7, secret:Zeroizing::new(CANARY.into()),
        metadata_sha256:credential_lease_metadata_sha256(&metadata), metadata, policy_hash:snapshot.hash.clone(),
        request_authority:None, release_authorization:None, expires_at_epoch_ms:now_epoch_ms()+60_000,
        expires_at_monotonic:Instant::now()+Duration::from_secs(60),
    });
    let request: DecisionRequest = serde_json::from_value(json!({"method":"POST","url":"https://eth-mainnet.g.alchemy.com/v2",
        "headers":{"authorization":alchemy_rpc_read::PLACEHOLDER,"accept":"application/json","content-type":"application/json"},
        "body":"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}"})).unwrap();
    let decision = decide_internal(&state, &snapshot, request.clone(), Some("agent:test"));
    assert_eq!(decision["allowed"], true, "actual Alchemy adapter/decision must admit fixture");
    (state, snapshot, decision, request)
}

#[test]
fn exact_alchemy_post_read_uses_real_adapter_and_response_finalizer() {
    let (state, snapshot, decision, request) = alchemy_fixture();
    assert_eq!(decision["operation"], json!({"operation":"alchemy.rpc.read","chain":"eth-mainnet","method":"eth_chainId","requestId":1}));
    let peer = Peer::new("eth-mainnet.g.alchemy.com", reply(200, b"{", "", 64), None);
    // Same original POST URL/body over verified local TLS. This finalizer control
    // does not claim acquisition/dispatch authority for the synthetic cache.
    let response = peer.client("eth-mainnet.g.alchemy.com").post(&request.url)
        .header("content-type", "application/json").body(request.body.clone()).send().unwrap();
    let wire = finalize(&state, &snapshot, &decision, "POST", &request.url, response);
    assert_blocked(&state, &wire, 502, 200, "upstream_body_failed", false);
    peer.finish("POST", "/v2", request.body.as_bytes(), 1);
    for (pointer, value) in [
        ("/allowed", json!(false)), ("/action", json!("deny")), ("/adapter", json!("generic.rest")),
        ("/route_id", json!("other")), ("/policy_hash", json!(sha256_prefixed(b"other"))),
        ("/snapshot_epoch", json!(2)), ("/operation/method", json!("eth_sendRawTransaction")),
        ("/operation/requestId", json!(true)), ("/canonical_request/operation/method", json!("eth_blockNumber")),
    ] {
        let mut changed = decision.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let value = post_dispatch_outcome::annotate(&snapshot, &changed, "POST", &Url::parse(&request.url).unwrap(),
            post_dispatch_outcome::Dispatch::ResponseReceived, json!({"error":"synthetic"}));
        assert_outcome(&value, "response_received", true);
    }
}

#[test]
fn valid_put_response_is_not_relabelled_as_unknown() {
    let (state, snapshot, decision) = fixture("PUT");
    let peer = Peer::new(HOST, reply(201, PUT_BODY, "", 0), None);
    let response = send(&state, &snapshot, &peer, "PUT", UpstreamSendDeadlines::default()).unwrap();
    let wire = finalize(&state, &snapshot, &decision, "PUT", TARGET, response);
    let parsed = parse_buffered_response(&wire).unwrap();
    assert_eq!(parsed.status, 201);
    assert_eq!(serde_json::from_slice::<Value>(parsed.body).unwrap(), json!({"safe":true}));
    assert!(state.audit_queue.lock().unwrap().iter().any(|entry| entry.event_type == "data_plane.response.released"));
    assert!(state.audit_queue.lock().unwrap().iter().all(|entry| entry.event.get("upstreamDispatch").is_none()));
    peer.finish("PUT", "/resource", PUT_BODY, 1);
}

#[test]
fn buffered_caller_routes_actual_postsend_errors_to_unknown_without_not_forwarded() {
    // Source wiring control, NOT execution of release-ledger refund/Drop paths.
    // The sibling runtime test above independently produces the real error.
    let source = include_str!("main.rs");
    let core = source.split_once("fn forward_absolute_request_inner_with_prepared<'a>(").unwrap().1
        .split_once("\n#[cfg(test)]\nfn forward_absolute_request_inner<'a>(").unwrap().0;
    let arm = core.split_once("Err(error @ (UpstreamSendError::Request(_) | UpstreamSendError::PostDispatch { .. })) => {")
        .unwrap().1.split_once("\n    };\n    let received_status").unwrap().0;
    for required in ["error.observed_dispatch()", "data_plane.response.blocked",
        "post_dispatch_outcome::annotate", "provider_operation_outcome_unknown()",
        "finalize_shadow_post_dispatch_unknown", "shadow_finalization = None", "StatusCode::CONFLICT"] {
        assert!(arm.contains(required), "missing post-send wiring: {required}");
    }
    assert!(!arm.contains("complete_not_forwarded"));
    assert!(!arm.contains("authorized-not-attempted"));
    let normalized = arm.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("let proof_response_unavailable = response_proof_requested && matches!(dispatch, post_dispatch_outcome::Dispatch::ResponseReceived);"));
    let guarded = arm.find("let proof_response_unavailable =").unwrap();
    let audit = arm.find("enqueue_audit(").unwrap();
    let unknown = arm.find("finalize_shadow_post_dispatch_unknown(").unwrap();
    let cleared = arm.find("shadow_finalization = None;").unwrap();
    let refusal = arm.find("if proof_response_unavailable {").unwrap();
    let closed = arm.find("return ForwardResult::Streamed;").unwrap();
    let ordinary = arm.find("buffered!(response);").unwrap();
    assert!(guarded < audit && audit < unknown && unknown < cleared
        && cleared < refusal && refusal < closed && closed < ordinary);
    for forbidden in ["observe_upstream_headers(", "selected_raw_policy_headers_b64(",
        "response_proof_upstream_canonical_digest(", "attach_response_proof(",
        "write_response_observation_proof("] {
        assert!(!arm.contains(forbidden), "unvalidated response reached proof material: {forbidden}");
    }
    let outer = source.split_once("fn forward_absolute_request_to<W: TerminalDeadlineWrite>(").unwrap().1
        .split_once("\nfn request_streaming_preflight(").unwrap().0;
    let (buffered, streamed) = outer.split_once("match result {").unwrap().1
        .split_once("ForwardResult::Streamed =>").unwrap();
    assert!(buffered.contains("ForwardResult::Buffered(mut response) =>"));
    assert!(buffered.contains("attach_response_proof("));
    assert!(buffered.contains("write_response_observation_proof("));
    // Streamed returns false, with no fallback proof attachment/write afterwards.
    assert_eq!(streamed.split_whitespace().collect::<Vec<_>>().join(" "), "false, } }");
}
