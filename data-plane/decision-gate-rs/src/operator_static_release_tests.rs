//! Real signed loopback audit/lease protocols under the parent publication
//! fixture. This proves preparation and final send-authority checks, not a
//! provider send, native admission, or deployed operator startup.
use super::*;
use crate::tests::signed_audit_test_response;

const TARGET: &str = "https://api.example.com/resource";

fn configured() -> RenewalFixture {
    let mut fixture = RenewalFixture::new(Arc::new(|_| {}));
    let endpoint = format!("http://{}", fixture.listener.local_addr().unwrap());
    let state = Arc::get_mut(&mut fixture.state).unwrap();
    state.audit_url = Some(format!("{endpoint}/api/data-plane/audit"));
    state.audit_token = Some("synthetic-release-audit".into());
    state.server_instance_id = Some("test-instance".into());
    fixture
}

fn admitted_decision(fixture: &RenewalFixture) -> Value {
    let request = serde_json::from_value(json!({"method":"GET", "url":TARGET,
        "headers":{"proxy-authorization":format!("Bearer {TOKEN}")}, "body":""})).unwrap();
    let decision = decide_internal(&fixture.state, &fixture.snapshot, request, Some("agent:test"));
    assert_eq!(decision["allowed"], true, "actual ordinary decision: {decision}");
    assert_eq!(decision["action"], "allow");
    assert_eq!(decision["jit"]["required"], false);
    assert_eq!(decision["credential_version"], 7);
    decision
}

// The barrier is the receiver having read the complete real audit request.
// Its signed ACK is withheld until the test releases it. No guard or clock is
// replaced; all network activity stays on this bounded synthetic authority.
struct Receiver {
    entered: mpsc::Receiver<Value>,
    release: mpsc::Sender<()>,
    stop: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<Vec<(String, Value)>>>,
}

impl Receiver {
    fn start(fixture: &RenewalFixture, mode: &'static str) -> Self {
        let listener = fixture.listener.try_clone().unwrap();
        let authority = Arc::clone(&fixture.authority);
        let (entered, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut calls = Vec::new();
            let limit = Instant::now() + Duration::from_secs(6);
            while Instant::now() < limit {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let (mut stream, request) = receive(stream);
                        assert!(calls.len() < 4, "no protocol retry or request replay");
                        let response = if request.method == "GET" {
                            calls.push(("attestation".into(), Value::Null));
                            http_response("200 OK", authority.attestation(&request))
                        } else if request.target == "/api/data-plane/audit" {
                            assert_eq!(request.method, "POST");
                            let body: Value = strict_json_from_slice(&request.body).unwrap();
                            assert!(!calls.iter().any(|(kind, _)| kind == "audit"), "no audit replay");
                            calls.push(("audit".into(), body.clone()));
                            entered.send(body).unwrap();
                            released.recv_timeout(WAIT).unwrap();
                            if mode == "lost-ack" { continue; }
                            if mode == "unsigned-ack" {
                                http_response("200 OK", json!({"ok":true}))
                            } else {
                                signed_audit_test_response(&authority.key, &authority.snapshot, &request,
                                    if mode == "failed-ack" { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK },
                                    1, &sha256_prefixed(&request.body), "test-instance")
                            }
                        } else {
                            assert_eq!(request.method, "POST");
                            assert_eq!(request.target, "/api/data-plane/credential-leases");
                            assert!(!calls.iter().any(|(kind, _)| kind == "lease"), "no lease retry");
                            let body: Value = strict_json_from_slice(&request.body).unwrap();
                            assert_eq!(body["purpose"], "dispatchSecret");
                            assert_eq!(body["expectedCredentialVersion"], 7);
                            assert_eq!(body["policyHash"], authority.snapshot.hash);
                            calls.push(("lease".into(), body));
                            material_response(&authority.key, &authority.snapshot, &request,
                                if mode == "wrong-version" { 8 } else { 7 },
                                if mode == "short-secret" { 100 } else { 4_000 })
                        };
                        stream.write_all(&response).unwrap();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        match stopped.recv_timeout(Duration::from_millis(5)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                        }
                    }
                    Err(error) => panic!("synthetic receiver failed: {error}"),
                }
            }
            calls
        });
        Self { entered: received, release, stop, thread: Some(thread) }
    }

    fn finish(mut self) -> Vec<(String, Value)> {
        let _ = self.stop.send(());
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.release.send(());
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn launch(fixture: &RenewalFixture, decision: Value, deadline: Instant)
    -> (mpsc::Receiver<Result<Option<SecretLease>, String>>, thread::JoinHandle<()>)
{
    let state = Arc::clone(&fixture.state);
    let snapshot = Arc::clone(&fixture.snapshot);
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = preparation::prepare_release_if_admitted(&state, &snapshot, &decision,
            "GET", &Url::parse(TARGET).unwrap(), false, deadline);
        let _ = sent.send(result);
    });
    (received, worker)
}

fn wait_past(deadline: Instant) {
    // Real finite expiration, not a replacement clock or a scheduling sleep.
    let (_held, receiver) = mpsc::channel::<()>();
    assert!(matches!(receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())
        + Duration::from_millis(2)), Err(mpsc::RecvTimeoutError::Timeout)));
}

fn assert_calls(calls: &[(String, Value)], leases: usize) {
    assert_eq!(calls.iter().map(|(kind, _)| kind.as_str()).collect::<Vec<_>>(),
        if leases == 0 { vec!["attestation", "audit"] } else { vec!["attestation", "audit", "lease"] });
    let events = calls[1].1["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eventType"], "data_plane.credential.release_started");
    assert_eq!(events[0]["event"]["principal_id"], "agent:test");
    assert_eq!(events[0]["event"]["route_id"], "route:test");
    assert_eq!(events[0]["event"]["credential_ref"], "static-account");
    assert_eq!(events[0]["event"]["credential_version"], 7);
    assert_eq!(events[0]["event"]["outcome"], "release_started");
    assert!(!serde_json::to_string(&events).unwrap().contains(SECRET));
}

#[test]
fn operator_static_release_delayed_ack_selects_fresh_binding() {
    let fixture = configured();
    let deadline = Instant::now() + Duration::from_secs(5); // before decision
    let decision = admitted_decision(&fixture);
    seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 300);
    let old = credential_lease_for_release(&fixture.state, &fixture.snapshot, &decision,
        &fixture.scope.credential_id, 7).unwrap();
    let old_binding = credential_lease_release_binding(&old);
    let receiver = Receiver::start(&fixture, "ok");
    let (result, worker) = launch(&fixture, decision, deadline);
    receiver.entered.recv_timeout(WAIT).unwrap();
    assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    wait_past(old_binding.expires_at_monotonic);
    assert!(!credential_lease_still_releasable(&fixture.state, &fixture.snapshot, &old_binding));
    receiver.release.send(()).unwrap();
    let fresh = result.recv_timeout(WAIT).unwrap().unwrap().expect("admitted release");
    worker.join().unwrap();
    assert_calls(&receiver.finish(), 1);
    assert_eq!(fresh.version, 7);
    assert_eq!(fresh.scope, fixture.scope);
    assert_eq!(fresh.metadata, old.metadata);
    assert_eq!(fresh.policy_hash, fixture.snapshot.hash);
    assert!(fresh.expires_at_monotonic > old_binding.expires_at_monotonic);
    let binding = credential_lease_release_binding(&fresh);
    assert_eq!(binding.expires_at_monotonic, fresh.expires_at_monotonic);
    assert!(credential_lease_upstream_send_timeout(&fixture.state, &fixture.snapshot,
        Some(&binding)).unwrap().unwrap() >= Duration::from_millis(250));
    assert!(!credential_lease_still_releasable(&fixture.state, &fixture.snapshot, &old_binding));
    // A renewed cache never revives an already bound request. Actual send path
    // rejects its old binding before a target connection, without retrying it.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let client = reqwest::blocking::Client::builder().no_proxy().timeout(WAIT).build().unwrap();
    assert!(matches!(send_upstream_request_with_current_lease(&fixture.state, &fixture.snapshot,
        Some(&old_binding), client.get(format!("http://{}/", target.local_addr().unwrap())),
        UpstreamSendDeadlines::default(), false), Err(UpstreamSendError::CredentialAuthority(_))));
    assert_eq!(target.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn operator_static_release_failed_or_uncertain_ack_never_fetches() {
    for mode in ["failed-ack", "unsigned-ack", "lost-ack"] {
        let fixture = configured();
        let deadline = Instant::now() + Duration::from_secs(5);
        let decision = admitted_decision(&fixture);
        seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 0);
        let receiver = Receiver::start(&fixture, mode);
        let (result, worker) = launch(&fixture, decision, deadline);
        receiver.entered.recv_timeout(WAIT).unwrap();
        receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().is_err());
        worker.join().unwrap();
        assert_calls(&receiver.finish(), 0);
        assert_eq!(fixture.state.audit_required_failed.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn operator_static_release_generation_drift_refuses_before_fetch() {
    for mode in ["version", "metadata", "snapshot"] {
        let fixture = configured();
        let deadline = Instant::now() + Duration::from_secs(5);
        let decision = admitted_decision(&fixture);
        seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 0);
        let receiver = Receiver::start(&fixture, "ok");
        let (result, worker) = launch(&fixture, decision, deadline);
        receiver.entered.recv_timeout(WAIT).unwrap();
        match mode {
            "version" => {
                cache_scoped_credential_generation(&fixture.state, &fixture.snapshot,
                    &fixture.scope, generation(&fixture.snapshot, 8, 60_000)).unwrap();
            }
            "metadata" => {
                let mut values = fixture.state.credential_generations.lock().unwrap();
                let pin = values.get_mut(&fixture.scope).unwrap();
                pin.metadata.insert("synthetic_drift".into(), json!(true));
                pin.metadata_sha256 = credential_lease_metadata_sha256(&pin.metadata);
            }
            _ => *fixture.state.snapshot.write().unwrap() = Arc::new((*fixture.snapshot).clone()),
        }
        receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().is_err());
        worker.join().unwrap();
        assert_calls(&receiver.finish(), 0);
        assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn operator_static_release_bad_material_is_terminal_without_retry() {
    for mode in ["short-secret", "wrong-version"] {
        let fixture = configured();
        let deadline = Instant::now() + Duration::from_secs(5);
        let decision = admitted_decision(&fixture);
        seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 0);
        let receiver = Receiver::start(&fixture, mode);
        let (result, worker) = launch(&fixture, decision, deadline);
        receiver.entered.recv_timeout(WAIT).unwrap();
        receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().is_err());
        worker.join().unwrap();
        assert_calls(&receiver.finish(), 1);
    }
}

#[test]
fn operator_static_release_original_deadline_and_expired_app_refuse() {
    let fixture = configured();
    let deadline = Instant::now() + Duration::from_millis(350); // never rearmed after ACK
    let decision = admitted_decision(&fixture);
    seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 0);
    let receiver = Receiver::start(&fixture, "ok");
    let (result, worker) = launch(&fixture, decision, deadline);
    receiver.entered.recv_timeout(WAIT).unwrap();
    wait_past(deadline);
    receiver.release.send(()).unwrap();
    assert!(result.recv_timeout(WAIT).unwrap().is_err());
    worker.join().unwrap();
    assert_calls(&receiver.finish(), 0);

    // Separate pre-audit refusals use the real finite-principal admission,
    // without claiming this modified snapshot is a signed published policy.
    for expired_app in [false, true] {
        let mut fixture = configured();
        let decision = admitted_decision(&fixture);
        if expired_app {
            let mut expired = (*fixture.snapshot).clone();
            match &mut expired.principals[0].proxy_authorization {
                Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms, .. }) =>
                    *expires_at_ms = Some(now_epoch_ms().saturating_sub(1)),
                _ => panic!("finite bearer principal required"),
            }
            fixture.snapshot = Arc::new(expired);
            *fixture.state.snapshot.write().unwrap() = Arc::clone(&fixture.snapshot);
        }
        let deadline = if expired_app { Instant::now() + WAIT } else { Instant::now() };
        assert!(preparation::prepare_release_if_admitted(&fixture.state, &fixture.snapshot,
            &decision, "GET", &Url::parse(TARGET).unwrap(), false, deadline).is_err());
        no_effects(&fixture.state, &fixture.listener);
        assert_eq!(fixture.state.audit_sent.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn operator_static_release_exclusions_and_malformed_decisions_do_no_io() {
    for mode in ["proof", "digest", "atomic-decision", "production", "native", "currentness", "atomic"] {
        let mut fixture = configured();
        let mut decision = admitted_decision(&fixture);
        let state = Arc::get_mut(&mut fixture.state).unwrap();
        match mode {
            "digest" => decision["client_request_digest"] = json!(sha256_prefixed(b"synthetic proof")),
            "atomic-decision" => decision["release_authorization"] = json!({"synthetic":true}),
            "production" => state.is_production = true,
            "native" => state.native_policy_bytes = Some(vec![0_u8].into()),
            "atomic" => state.atomic_release_authorization_enabled = true,
            "currentness" => state.credential_currentness = credential_currentness::LocalHolder::new(Some(
                serverware_decision_gate::native_currentness_v1::Configuration {
                    profile: serverware_decision_gate::native_currentness_v1::PROFILE.into(),
                    deployment_id: "synthetic-release".into(),
                })),
            _ => {}
        }
        assert!(preparation::prepare_release_if_admitted(state, &fixture.snapshot, &decision,
            "GET", &Url::parse(TARGET).unwrap(), mode == "proof", Instant::now() + WAIT)
            .unwrap().is_none());
        no_effects(state, &fixture.listener);
        assert_eq!(state.audit_sent.load(Ordering::Relaxed), 0);
    }
    for mode in ["deny", "version", "canonical", "target"] {
        let fixture = configured();
        let mut decision = admitted_decision(&fixture);
        match mode {
            "deny" => decision["allowed"] = json!(false),
            "version" => decision["credential_version"] = json!(8),
            "canonical" => decision["canonical_request"]["credential_version"] = json!(7),
            _ => {}
        }
        let url = Url::parse(if mode == "target" { "https://api.example.com/other" } else { TARGET }).unwrap();
        assert!(preparation::prepare_release_if_admitted(&fixture.state, &fixture.snapshot,
            &decision, "GET", &url, false, Instant::now() + WAIT).is_err());
        no_effects(&fixture.state, &fixture.listener);
    }
}
