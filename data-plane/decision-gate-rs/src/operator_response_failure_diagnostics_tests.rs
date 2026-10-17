//! Bounded, synthetic diagnostics only. No sockets, provider requests, filesystem
//! or environment changes. Actual forwarder controls stop at an inert resolver
//! failure or the existing thread-local post-decision failure seam before send.
//! Every observation uses a local counter/sink, never the process stderr budget.
use super::*;
use crate::tests::{test_custody_response_proof_signer, test_gate_state, test_snapshot};
use crate::*;
use std::collections::BTreeSet;
use std::sync::Barrier;
use std::thread;

const CANARY: &str = "synthetic-secret-canary https://private.invalid/path?token=secret\nAuthorization: Bearer secret";
// Independent expected vocabulary: adding a production category requires an
// explicit review of this list, not deriving the oracle from reason().
const REASONS: &[&str] = &[
    "policy_shadow_custody_unavailable", "policy_shadow_accounting_unavailable",
    "policy_trust_root_stale", "credential_generation_missing",
    "response_release_barrier_invalid", "admitted_content_encoding_invalid",
    "allowed_decision_principal_invalid", "allowed_decision_invalid",
    "provider_request_binding_mismatch", "provider_request_body_binding_mismatch",
    "upstream_resolution_unavailable", "upstream_transport_preparation_failed",
    "credential_lease_unavailable", "credential_lease_changed_before_release",
    "required_credential_audit_unavailable", "request_policy_deadline_invalid",
    "dispatch_barrier_unavailable", "upstream_send_authority_expired",
    "credential_lease_expired_before_upstream_send",
    "credential_lease_lifetime_insufficient_for_upstream_send",
    "operator_google_authorization_changed_before_upstream_send",
    "native_broker_owner_unavailable_before_upstream_send",
    "credential_runtime_owner_changed_before_upstream_send",
    "credential_runtime_profile_changed_before_upstream_send",
    "policy_trust_stale_before_upstream_send",
    "credential_release_authorization_expired_before_upstream_send",
    "credential_request_authority_expired_before_upstream_send",
    "policy_snapshot_revoked_before_upstream_send",
    "credential_currentness_blocked_before_upstream_send",
    "credential_lease_changed_before_upstream_send",
    "credential_generation_changed_before_upstream_send",
];

fn fixture() -> (GateState, Arc<Snapshot>) {
    let mut held = (*test_snapshot(1)).clone();
    held.policy_id = "catchplate-operator-demo".into();
    held.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(b"synthetic-response-observation-client"),
        source_cidrs: vec![], expires_at_ms: Some(now_epoch_ms() + 60_000), basic_transport: None, managed_renewal: None,
    });
    held.routes[0].host = "registry.npmjs.org".into();
    held.routes[0].resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    let profile = operator_demo::test_publish_dispatch_profile(&held);
    let snapshot = Arc::new(held);
    let mut state = test_gate_state(Arc::clone(&snapshot));
    state.policy_shadow = ShadowRuntime::new_operator_demo(profile);
    state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    (state, snapshot)
}

fn response(body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn error_response(code: &str) -> Vec<u8> {
    response(json!({"error":code,"detail":CANARY}).to_string().as_bytes())
}

fn assert_observation(wire: &[u8], reason: &'static str, response_shape: &'static str) {
    assert_eq!(inspect_response(wire), Some(Observation { reason, response_shape }));
}

fn record(line: &str) -> Value {
    assert!(line.len() < 512);
    assert!(line.ends_with('\n'));
    assert_eq!(line.bytes().filter(|b| *b == b'\n').count(), 1);
    let value: Value = serde_json::from_str(line).unwrap();
    let fields: BTreeSet<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(fields, BTreeSet::from([
        "schema", "ordinal", "boundary", "reason", "response_shape", "write_completed",
    ]));
    assert_eq!(value["schema"], "catchplate.operatorBuffered503Observation/v1");
    assert!((1..=64).contains(&value["ordinal"].as_u64().unwrap()));
    assert!(["upstream_preparation", "buffered_terminal"].contains(&value["boundary"].as_str().unwrap()));
    assert!(["error", "decision", "unclassified"].contains(&value["response_shape"].as_str().unwrap()));
    let reason = value["reason"].as_str().unwrap();
    assert!(reason == "other_503" || REASONS.contains(&reason));
    assert!(value["write_completed"].is_boolean());
    for forbidden in [CANARY, "synthetic-secret-canary", "private.invalid", "Authorization",
        "agent:test", "route:test", "registry.npmjs.org", "sha256:", "detail", "payload"] {
        assert!(!line.contains(forbidden));
    }
    value
}

#[test]
fn operator_response_diagnostic_closed_reason_codes_and_shapes() {
    let (state, _) = fixture();
    assert_eq!(REASONS.len(), 31);
    assert_eq!(REASONS.iter().copied().collect::<BTreeSet<_>>().len(), REASONS.len());
    for code in REASONS.iter().copied().chain(["other_503"]) {
        let wire = error_response(code);
        assert_observation(&wire, code, "error");
        let decision = response(json!({"action":"deny","allowed":false,"status_code":503,
            "reason":CANARY,"payload":{"error":code,"detail":CANARY},"route_id":CANARY}).to_string().as_bytes());
        assert_observation(&decision, code, "decision");
        let (_, lines, count) = capture(false, || {
            observe(&state, Boundary::UpstreamPreparation, &wire, false);
            observe(&state, Boundary::BufferedTerminal, &decision, true);
        });
        assert_eq!((lines.len(), count), (2, 2));
        for (index, line) in lines.iter().enumerate() {
            let value = record(line);
            assert_eq!(value["ordinal"], index + 1);
            assert_eq!(value["reason"], code);
            assert_eq!(value["boundary"], if index == 0 { "upstream_preparation" } else { "buffered_terminal" });
            assert_eq!(value["response_shape"], if index == 0 { "error" } else { "decision" });
            assert_eq!(value["write_completed"], index == 1);
        }
    }
    for code in [CANARY, "", "credential_generation_missing extra", "prefix credential_generation_missing",
        "Credential_generation_missing", "response_proof_unavailable"] {
        assert_observation(&error_response(code), "other_503", "error");
    }
}

#[test]
fn operator_response_diagnostic_strict_json_and_ambiguity() {
    // Escaped keys/values have their JSON meanings, never raw-string matching.
    assert_observation(&response(br#"{"\u0065rror":"credential\u005fgeneration_missing","detail":"synthetic-secret-canary\nAuthorization"}"#),
        "credential_generation_missing", "error");
    let bad = [
        r#"{"error":"credential_generation_missing","error":"required_credential_audit_unavailable"}"#,
        r#"{"error":"credential_generation_missing","\u0065rror":"credential_generation_missing"}"#,
        r#"{"error":"credential_generation_missing","allowed":false}"#,
        r#"{"error":"credential_generation_missing","action":"deny"}"#,
        r#"{"error":"credential_generation_missing","status_code":503}"#,
        r#"{"error":"credential_generation_missing","payload":{}}"#,
        r#"{"error":false}"#, r#"{"error":{"error":"credential_generation_missing"}}"#,
        r#"{"decision":{"action":"deny","allowed":false,"status_code":503,"payload":{"error":"credential_generation_missing"}}}"#,
        r#"{"action":"allow","allowed":false,"status_code":503,"payload":{"error":"credential_generation_missing"}}"#,
        r#"{"action":"deny","allowed":true,"status_code":503,"payload":{"error":"credential_generation_missing"}}"#,
        r#"{"action":"deny","allowed":false,"status_code":403,"payload":{"error":"credential_generation_missing"}}"#,
        r#"{"action":"deny","allowed":false,"status_code":"503","payload":{"error":"credential_generation_missing"}}"#,
        r#"{"action":"deny","allowed":false,"status_code":503.0,"payload":{"error":"credential_generation_missing"}}"#,
        r#"{"action":"deny","allowed":false,"status_code":503,"payload":{"error":null}}"#,
        r#"{"action":"deny","allowed":false,"status_code":503,"payload":{"error":"credential_generation_missing","error":"other"}}"#,
        r#"{"error":"credential_generation_missing","detail":"\ud800"}"#,
        r#"{"error":"credential_generation_missing","detail":NaN}"#,
        r#"{"error":"credential_generation_missing"}{}"#, r#"{"error":"credential_generation_missing""#,
        "[]", "null", "503", "not JSON",
    ];
    let (state, _) = fixture();
    for body in bad {
        let wire = response(body.as_bytes());
        assert_observation(&wire, "other_503", "unclassified");
        let (_, lines, count) = capture(false, || observe(&state, Boundary::BufferedTerminal, &wire, true));
        assert_eq!((lines.len(), count), (1, 1));
        assert_eq!(record(&lines[0])["response_shape"], "unclassified");
    }
    assert_observation(&response(b"{\"error\":\"\xff\"}"), "other_503", "unclassified");
}

#[test]
fn operator_response_diagnostic_strict_http_framing() {
    let body = br#"{"error":"credential_generation_missing"}"#;
    let n = body.len();
    for headers in [
        format!("Content-Type: application/json\r\nContent-Length: {}", n - 1),
        format!("Content-Type: application/json\r\nContent-Length: {}", n + 1),
        format!("Content-Type: application/json\r\nContent-Length: 0{n}"),
        format!("Content-Type: application/json\r\nContent-Length: +{n}"),
        format!("Content-Type: application/json\r\nContent-Length: {n}\r\nContent-Length: {n}"),
        format!("Content-Type: application/json\r\nContent-Length: {n}\r\nTransfer-Encoding: chunked"),
        format!("Content-Type: application/json\r\nContent-Length: {n}\r\nContent-Encoding: identity"),
        format!("Content-Type: application/json; charset=utf-8\r\nContent-Length: {n}"),
        format!("Content-Type: text/plain\r\nContent-Length: {n}"),
        format!("Content-Length: {n}"), "Content-Type: application/json".into(),
    ] {
        let mut wire = format!("HTTP/1.1 503 Service Unavailable\r\n{headers}\r\n\r\n").into_bytes();
        wire.extend_from_slice(body);
        assert_observation(&wire, "other_503", "unclassified");
    }
    let mut appended = response(body);
    appended.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
    assert_observation(&appended, "other_503", "unclassified");
    let complete = response(body);
    for length in [13, 20, complete.len() - 1] {
        assert_observation(&complete[..length], "other_503", "unclassified");
    }
    assert_observation(b"HTTP/1.1 503 Service Unavailable\nContent-Type: application/json\n\n{}", "other_503", "unclassified");
}

#[test]
fn operator_response_diagnostic_bounded_parser() {
    let mut body = br#"{"error":"credential_generation_missing"}"#.to_vec();
    body.resize(16 * 1024, b' ');
    assert_observation(&response(&body), "credential_generation_missing", "error");
    body.push(b' ');
    assert_observation(&response(&body), "other_503", "unclassified");
    let body = br#"{"error":"credential_generation_missing"}"#;
    let prefix = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Pad: ", body.len());
    let mut head = prefix.into_bytes();
    head.resize(8 * 1024 - 4, b'x');
    head.extend_from_slice(b"\r\n\r\n");
    let mut at_bound = head.clone();
    at_bound.extend_from_slice(body);
    assert_observation(&at_bound, "credential_generation_missing", "error");
    head.insert(8 * 1024 - 4, b'x');
    head.extend_from_slice(body);
    assert_observation(&head, "other_503", "unclassified");
    let mut oversized = b"HTTP/1.1 503 ".to_vec();
    oversized.resize(24 * 1024 + 1, b'x');
    assert_observation(&oversized, "other_503", "unclassified");
}

#[test]
fn operator_response_diagnostic_non503_silent() {
    let (state, _) = fixture();
    let counter = AtomicUsize::new(0);
    for prefix in ["", "HTTP/1.1 200 OK", "HTTP/1.1 403 Forbidden", "HTTP/1.1 502 Bad Gateway",
        "HTTP/1.1 5030 Other", "HTTP/1.1 503", "HTTP/1.0 503 Unavailable", "HTTP/2 503", "http/1.1 503 Unavailable"] {
        let wire = format!("{prefix}\r\n\r\n{{\"error\":\"credential_generation_missing\"}}");
        assert_eq!(inspect_response(wire.as_bytes()), None);
        observe_with(&state, Boundary::BufferedTerminal, wire.as_bytes(), true, &counter,
            |_| panic!("non-503 response invoked diagnostic sink"));
    }
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn operator_response_diagnostic_owner_exclusions_silent() {
    let wire = error_response("credential_generation_missing");
    for exclusion in ["production", "nonoperator", "policy-aware", "native"] {
        let (mut state, _) = fixture();
        match exclusion {
            "production" => state.is_production = true,
            "nonoperator" => state.policy_shadow = ShadowRuntime::new_inactive_for_forwarding_tests(),
            _ => {
                state.response_proof_signer = test_custody_response_proof_signer("synthetic-control-key".into());
                let ResponseProofSigner::Custody(signer) = &mut state.response_proof_signer else { unreachable!() };
                signer.release_profile = if exclusion == "native" { ReleaseProfile::Native } else { ReleaseProfile::PolicyAware };
            }
        }
        let (_, lines, count) = capture(false, || {
            observe(&state, Boundary::UpstreamPreparation, &wire, false);
            observe(&state, Boundary::BufferedTerminal, &wire, true);
        });
        assert!(lines.is_empty());
        assert_eq!(count, 0);
    }
}

#[test]
fn operator_response_diagnostic_sequential_cap() {
    let (state, _) = fixture();
    let wire = error_response("credential_generation_missing");
    let (_, lines, count) = capture(false, || {
        for _ in 0..192 { observe(&state, Boundary::BufferedTerminal, &wire, true); }
    });
    assert_eq!((lines.len(), count), (64, 64));
    for (index, line) in lines.iter().enumerate() { assert_eq!(record(line)["ordinal"], index + 1); }
    for initial in [64, usize::MAX] {
        let counter = AtomicUsize::new(initial);
        observe_with(&state, Boundary::BufferedTerminal, &wire, true, &counter,
            |_| panic!("saturated counter invoked sink"));
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
}

#[test]
fn operator_response_diagnostic_concurrent_cap() {
    let (state, _) = fixture();
    let counter = AtomicUsize::new(0);
    let barrier = Barrier::new(8);
    let wire = error_response("credential_generation_missing");
    let lines = thread::scope(|threads| {
        let workers = (0..8).map(|_| threads.spawn(|| {
            let mut lines = Vec::new();
            barrier.wait();
            for _ in 0..32 {
                observe_with(&state, Boundary::BufferedTerminal, &wire, true, &counter, |line| {
                    lines.push(String::from_utf8(line.to_vec()).unwrap()); Ok(())
                });
            }
            lines
        })).collect::<Vec<_>>();
        workers.into_iter().flat_map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(counter.load(Ordering::Relaxed), 64);
    assert_eq!(lines.len(), 64);
    let mut ordinals = lines.iter().map(|line| record(line)["ordinal"].as_u64().unwrap()).collect::<Vec<_>>();
    ordinals.sort_unstable();
    assert_eq!(ordinals, (1..=64).collect::<Vec<u64>>());
}

#[test]
fn operator_response_diagnostic_failed_sink_spends_bounded_budget() {
    let (state, _) = fixture();
    let wire = error_response("credential_generation_missing");
    let counter = AtomicUsize::new(0);
    let mut calls = 0;
    for _ in 0..192 {
        observe_with(&state, Boundary::BufferedTerminal, &wire, false, &counter, |_| {
            calls += 1; Err(io::Error::new(io::ErrorKind::BrokenPipe, CANARY))
        });
    }
    assert_eq!((counter.load(Ordering::Relaxed), calls), (64, 64));
}

#[test]
fn operator_response_diagnostic_borrowed_response_unchanged() {
    let (state, _) = fixture();
    for written in [false, true] {
        for sink_fails in [false, true] {
            let result = ForwardResult::buffered(error_response(CANARY));
            let ForwardResult::Buffered(bytes) = &result else { unreachable!() };
            let before = bytes.to_vec();
            let pointer = bytes.as_ptr();
            let (returned, lines, count) = capture(sink_fails, || {
                observe(&state, Boundary::BufferedTerminal, bytes, written);
                written
            });
            assert_eq!(returned, written);
            let ForwardResult::Buffered(bytes) = result else { panic!("observer changed result variant") };
            assert_eq!(bytes.as_ptr(), pointer);
            assert_eq!(&*bytes, before.as_slice());
            assert_eq!(count, 1);
            assert_eq!(lines.len(), usize::from(!sink_fails));
            if !sink_fails { assert_eq!(record(&lines[0])["reason"], "other_503"); }
        }
    }
}

struct InertResolver { fails: bool, calls: AtomicUsize }
impl UpstreamResolver for InertResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        assert_eq!((host, port), ("registry.npmjs.org", 443));
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fails { Err(CANARY.into()) } else { Ok(vec!["93.184.216.34:443".parse().unwrap()]) }
    }
}

fn request() -> IncomingRequest {
    IncomingRequest { method: "GET".into(), target: "https://registry.npmjs.org/resource".into(),
        headers: BTreeMap::new(), body: vec![], client_ip: Some("127.0.0.1".into()) }
}

#[derive(Default)]
struct Writer { bytes: Vec<u8>, fail_write: bool, fail_flush: bool, writes: usize, flushes: usize }
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_write { return Err(io::Error::new(io::ErrorKind::BrokenPipe, CANARY)); }
        self.bytes.extend_from_slice(bytes); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush { Err(io::Error::new(io::ErrorKind::BrokenPipe, CANARY)) } else { Ok(()) }
    }
}
impl TerminalDeadlineWrite for Writer { fn set_terminal_write_deadline(&mut self, _: Option<Instant>) {} }

// Restore the pre-existing thread-local fault seam even when an assertion fails.
struct ForcedTerminal;
impl ForcedTerminal {
    fn new() -> Self { force_forwarder_post_decision_failure("buffered"); Self }
}
impl Drop for ForcedTerminal { fn drop(&mut self) { let _ = take_forwarder_post_decision_failure("buffered"); } }

fn assert_no_authority_side_effects(state: &GateState) {
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
    assert!(state.grants.lock().unwrap().is_empty());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
    assert!(state.credential_lease_url.is_none());
    assert!(state.audit_url.is_none());
}

#[test]
fn operator_response_diagnostic_actual_preparation_response_preserved() {
    for sink_fails in [false, true] {
        for writer_failure in ["none", "write", "flush"] {
            let (mut state, snapshot) = fixture();
            let resolver = Arc::new(InertResolver { fails: true, calls: AtomicUsize::new(0) });
            state.upstream_resolver = resolver.clone();
            let expected = json_status_response(StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"upstream_resolution_unavailable"}));
            let mut writer = Writer { fail_write: writer_failure == "write", fail_flush: writer_failure == "flush", ..Writer::default() };
            let (returned, lines, count) = capture(sink_fails, || forward_absolute_request_to(
                &state, &snapshot, request(), Some("agent:test"), false, &mut writer, None, None));
            // This early refusal always closes, even after a complete write.
            assert!(!returned);
            assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
            assert_eq!(writer.bytes, if writer_failure == "write" { vec![] } else { expected });
            assert_eq!((writer.writes, writer.flushes), (1, usize::from(writer_failure != "write")));
            assert_eq!(count, 1);
            assert_eq!(lines.len(), usize::from(!sink_fails));
            if !sink_fails {
                let value = record(&lines[0]);
                assert_eq!(value["boundary"], "upstream_preparation");
                assert_eq!(value["reason"], "upstream_resolution_unavailable");
                assert_eq!(value["response_shape"], "error");
                assert_eq!(value["write_completed"], writer_failure == "none");
            }
            assert_no_authority_side_effects(&state);
        }
    }
}

#[test]
fn operator_response_diagnostic_actual_buffered_response_preserved() {
    for sink_fails in [false, true] {
        for writer_failure in ["none", "write", "flush"] {
            let (mut state, snapshot) = fixture();
            let resolver = Arc::new(InertResolver { fails: false, calls: AtomicUsize::new(0) });
            state.upstream_resolver = resolver.clone();
            let expected = override_response_connection(json_status_response(StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"test_post_decision_forwarder_failure","branch":"buffered"})), false);
            let mut writer = Writer { fail_write: writer_failure == "write", fail_flush: writer_failure == "flush", ..Writer::default() };
            let _forced = ForcedTerminal::new();
            let (returned, lines, count) = capture(sink_fails, || forward_absolute_request_to(
                &state, &snapshot, request(), Some("agent:test"), false, &mut writer, None, None));
            assert!(!take_forwarder_post_decision_failure("buffered"), "actual buffered failure seam was not consumed");
            assert_eq!(returned, writer_failure == "none");
            assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
            assert_eq!(writer.bytes.as_slice(), if writer_failure == "write" { &[][..] } else { &expected[..] });
            assert_eq!((writer.writes, writer.flushes), (1, usize::from(writer_failure != "write")));
            assert_eq!(count, 1);
            assert_eq!(lines.len(), usize::from(!sink_fails));
            if !sink_fails {
                let value = record(&lines[0]);
                assert_eq!(value["boundary"], "buffered_terminal");
                assert_eq!(value["reason"], "other_503");
                assert_eq!(value["response_shape"], "error");
                assert_eq!(value["write_completed"], writer_failure == "none");
            }
            assert_no_authority_side_effects(&state);
        }
    }
}

#[test]
fn operator_response_diagnostic_actual_proof_response_silent() {
    // A real buffered-proof request reaches the same preparation 503, but the
    // ordinary diagnostic remains silent. No proof signing or provider send.
    let (mut state, snapshot) = fixture();
    let resolver = Arc::new(InertResolver { fails: true, calls: AtomicUsize::new(0) });
    state.upstream_resolver = resolver.clone();
    let context = ResponseProofContext { client_nonce: "synthetic-nonce".into(),
        client_nonce_bytes: vec![7; 32], tls_exporter: "synthetic-exporter".into() };
    let mut proof_request = request();
    proof_request.headers.insert(RESPONSE_PROOF_NONCE_HEADER.into(), context.client_nonce.clone());
    let mut wire = Vec::new();
    let (returned, lines, count) = capture(false, || forward_absolute_request_to(
        &state, &snapshot, proof_request, Some("agent:test"), false, &mut wire,
        Some(ResponseProofRequestContext::Buffered(&context)), None));
    assert!(!returned);
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    assert_eq!(wire, json_status_response(StatusCode::SERVICE_UNAVAILABLE,
        json!({"error":"upstream_resolution_unavailable"})));
    assert!(lines.is_empty());
    assert_eq!(count, 0);
    assert_no_authority_side_effects(&state);
}
