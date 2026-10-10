//! Closed diagnostic observations, not new credential or dispatch authority.
//! Reuses the parent admitted synthetic fixture; no sockets, environment edits,
//! process-global diagnostic counters, provider requests, or timing sleeps.
use super::*;
use crate::operator_static_preparation_diagnostics::{capture, Attempt, Stage};
use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;
use std::thread;

const ERROR_CANARY: &str = "synthetic-secret-canary https://private.invalid/path?token=secret\nAuthorization: Bearer secret";

fn record(line: &str) -> Value {
    assert!(line.len() < 512);
    assert!(line.ends_with('\n'));
    assert_eq!(line.bytes().filter(|byte| *byte == b'\n').count(), 1);
    let value: Value = serde_json::from_str(line).unwrap();
    let fields: BTreeSet<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(fields, BTreeSet::from([
        "schema", "ordinal", "stage", "error_code", "scope_sha256", "policy_sha256",
    ]));
    assert_eq!(value["schema"], "serverware.operatorStaticPreparationFailure/v1");
    assert!((1..=64).contains(&value["ordinal"].as_u64().unwrap()));
    assert!(is_sha256_digest(value["scope_sha256"].as_str().unwrap()));
    assert!(value["policy_sha256"].is_null()
        || is_sha256_digest(value["policy_sha256"].as_str().unwrap()));
    for forbidden in [ERROR_CANARY, "synthetic-secret-canary", "private.invalid", "Authorization", SECRET, SUBJECT,
        "agent:test", "route:test", "static-account"] {
        assert!(!line.contains(forbidden));
    }
    value
}

#[test]
fn operator_static_diagnostic_closed_record_and_stage_enum() {
    let (state, snapshot, scope, _) = fixture();
    let mut public_snapshot = (*snapshot).clone();
    public_snapshot.hash = sha256_prefixed(b"synthetic diagnostic public policy");
    let stages = [
        (Stage::AdmissionDeadline, "admission_deadline"),
        (Stage::GenerationLookup, "generation_lookup"),
        (Stage::GenerationRefresh, "generation_refresh"),
        (Stage::GenerationMargin, "generation_margin"),
        (Stage::Binding, "binding"),
        (Stage::PairBeforeSecret, "pair_before_secret"),
        (Stage::SecretRefresh, "secret_refresh"),
        (Stage::FinalAdmission, "final_admission"),
        (Stage::FinalPair, "final_pair"),
        (Stage::FinalDeadline, "final_deadline"),
    ];
    let attempt = Attempt::after_admission(&state, &public_snapshot, &scope);
    let (_, lines, count) = capture(false, || {
        for (stage, _) in stages {
            assert_eq!(attempt.observe::<()>(stage, Err(ERROR_CANARY.to_owned())), Err(ERROR_CANARY.to_owned()));
        }
    });
    assert_eq!(count, stages.len());
    assert_eq!(lines.len(), stages.len());
    let expected_scope = digest_json(&json!({
        "principal_id": "agent:test", "route_id": "route:test", "credential_id": "static-account",
    }));
    for (index, (line, (_, label))) in lines.iter().zip(stages).enumerate() {
        let value = record(line);
        assert_eq!(value["ordinal"], index + 1);
        assert_eq!(value["stage"], label);
        assert_eq!(value["error_code"], "other");
        assert_eq!(value["scope_sha256"], expected_scope);
        assert_eq!(value["policy_sha256"], public_snapshot.hash);
    }
    // An unexpected hash is not copied into the diagnostic as an arbitrary string.
    public_snapshot.hash = ERROR_CANARY.to_owned();
    let attempt = Attempt::after_admission(&state, &public_snapshot, &scope);
    let (_, lines, count) = capture(false, || attempt.observe::<()>(Stage::Binding, Err(ERROR_CANARY.to_owned())));
    assert_eq!(count, 1);
    assert_eq!(record(&lines[0])["policy_sha256"], Value::Null);
}

#[test]
fn operator_static_diagnostic_exact_error_classification() {
    let (state, snapshot, scope, _) = fixture();
    let attempt = Attempt::after_admission(&state, &snapshot, &scope);
    // Independent public category expectations; exception text never becomes a field.
    let cases = [
        ("operator static credential preparation unavailable", "static_preparation_unavailable"),
        ("credential lease singleflight timed out", "singleflight_timeout"),
        ("custody I/O deadline exceeded during native credential original operation", "operation_deadline"),
        ("custody I/O deadline exceeded during credential original request", "operation_deadline"),
        ("currentness drain exceeded its original deadline; no acknowledgement", "cache_admission_deadline"),
        ("credential lease response has an invalid Content-Length", "response_body_contract"),
        ("credential lease response Content-Length does not match the streamed body", "response_body_contract"),
        ("credential lease response statement parse failed", "response_statement_parse"),
        ("credential lease response context mismatch", "response_context_mismatch"),
        ("credential lease response statement binding mismatch", "response_binding_mismatch"),
        ("credential lease response request binding mismatch", "response_binding_mismatch"),
        ("credential lease response statement is outside the clock window", "response_clock_window"),
        ("credential lease response signing key is not attested", "response_signing_key"),
        ("parse_credential_lease_envelope", "envelope_decode"),
        ("parse_credential_lease_envelope_contract", "envelope_decode"),
        ("credential lease envelope does not match its exact versioned shape", "envelope_decode"),
        ("credential lease envelope binding or expiry mismatch", "envelope_binding_or_expiry"),
        ("credential lease AEAD authentication failed", "envelope_authentication"),
        ("parse_decrypted_credential_lease_set", "material_decode"),
        ("parse_decrypted_credential_lease_set_contract", "material_decode"),
        ("decrypted credential lease set binding mismatch", "material_binding_mismatch"),
        ("credential lease expired during verification", "material_expired"),
        ("credential lease metadata digest mismatch", "metadata_digest_mismatch"),
        ("credential generation binding or expiry is invalid", "generation_cache_invalid"),
        ("credential lease metadata or expiry is invalid", "secret_cache_invalid"),
        ("credential generation owner profile changed before caching", "generation_profile_changed"),
        ("credential generation cache capacity exhausted", "generation_cache_capacity"),
        ("credential lease cache capacity exhausted", "secret_cache_capacity"),
        ("credential secret lease generation is stale or invalid", "secret_generation_stale"),
        ("credential secret lease has no cached generation", "generation_cache_missing"),
        ("dispatch secret fetch requires a cached credential generation", "generation_cache_missing"),
        ("credential generation or metadata changed during secret fetch", "generation_changed_during_secret_fetch"),
        ("credential lease version regression rejected", "version_regression"),
        ("credential metadata changed without a version increment", "metadata_changed_same_version"),
        ("credential provider metadata does not match signed policy", "runtime_binding_mismatch"),
        ("credential subject metadata does not match signed policy", "runtime_binding_mismatch"),
        ("runtime route credential binding is inconsistent", "runtime_binding_mismatch"),
        ("static credential scopes metadata does not exactly match signed policy", "runtime_binding_mismatch"),
        ("static credential class metadata does not match route binding", "runtime_binding_mismatch"),
        ("policy snapshot changed while credential lease was fetched", "snapshot_changed"),
        ("policy snapshot changed before credential generation caching", "snapshot_changed"),
        ("policy snapshot changed before credential lease caching", "snapshot_changed"),
        ("policy snapshot was revoked before credential lease refresh", "snapshot_changed"),
        ("fetch credential leases: ", "fetch_transport"),
        ("read credential lease response: ", "response_body_read"),
        ("credential lease response exceeds ", "response_body_bound"),
        ("credential lease response signature verification failed: ", "response_signature"),
        ("credential lease response unfamiliar ", "response_authentication_other"),
        ("credential lease control plane returned HTTP ", "response_http_status"),
        ("decode credential lease server public key: ", "envelope_decode"),
        ("decode credential lease AEAD nonce: ", "envelope_decode"),
        ("decode credential lease ciphertext: ", "envelope_decode"),
        ("credential lease singleflight timed out unexpected suffix", "other"),
        ("prefix credential lease singleflight timed out", "other"),
        ("credential lease URL is not configured", "other"),
        ("", "other"),
    ];
    for (error, expected) in cases {
        let error = if error.ends_with(' ') { format!("{error}{ERROR_CANARY}") } else { error.to_owned() };
        let (result, lines, count) = capture(false, || attempt.observe::<()>(Stage::GenerationRefresh, Err(error.clone())));
        assert_eq!(result, Err(error));
        assert_eq!((lines.len(), count), (1, 1));
        let value = record(&lines[0]);
        assert_eq!(value["error_code"], expected);
        assert_eq!(value["stage"], "generation_refresh");
    }
}

#[test]
fn operator_static_diagnostic_sequential_cap() {
    let (state, snapshot, scope, _) = fixture();
    let attempt = Attempt::after_admission(&state, &snapshot, &scope);
    let (_, lines, count) = capture(false, || {
        for _ in 0..192 {
            assert_eq!(attempt.observe(Stage::Binding, Ok::<_, String>(17)), Ok(17));
        }
        for _ in 0..192 {
            assert_eq!(attempt.observe::<()>(Stage::FinalPair, Err(ERROR_CANARY.to_owned())), Err(ERROR_CANARY.to_owned()));
        }
    });
    assert_eq!((lines.len(), count), (64, 64));
    for (index, line) in lines.iter().enumerate() {
        assert_eq!(record(line)["ordinal"], index + 1);
    }
    // An already saturated or impossible counter cannot wrap or invoke the sink.
    for initial in [64, usize::MAX] {
        let counter = AtomicUsize::new(initial);
        assert_eq!(attempt.observe_with_for_test::<()>(Stage::Binding, Err(ERROR_CANARY.to_owned()), &counter,
            |_| panic!("saturated diagnostic called its sink")), Err(ERROR_CANARY.to_owned()));
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
}

#[test]
fn operator_static_diagnostic_concurrent_cap() {
    let (state, snapshot, scope, _) = fixture();
    let counter = AtomicUsize::new(0);
    let barrier = Barrier::new(8);
    let lines = thread::scope(|threads| {
        let mut workers = Vec::new();
        for _ in 0..8 {
            let attempt = Attempt::after_admission(&state, &snapshot, &scope);
            let counter = &counter;
            let barrier = &barrier;
            workers.push(threads.spawn(move || {
                let mut lines = Vec::new();
                barrier.wait();
                for _ in 0..32 {
                    let error = ERROR_CANARY.to_owned();
                    let pointer = error.as_ptr();
                    let returned = attempt.observe_with_for_test::<()>(Stage::FinalPair, Err(error), counter, |line| {
                        lines.push(String::from_utf8(line.to_vec()).unwrap());
                        Ok(())
                    }).unwrap_err();
                    assert_eq!(returned.as_ptr(), pointer);
                    assert_eq!(returned, ERROR_CANARY);
                }
                lines
            }));
        }
        workers.into_iter().flat_map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(counter.load(Ordering::Relaxed), 64);
    assert_eq!(lines.len(), 64);
    let mut ordinals = lines.iter().map(|line| record(line)["ordinal"].as_u64().unwrap()).collect::<Vec<_>>();
    ordinals.sort_unstable();
    assert_eq!(ordinals, (1..=64).collect::<Vec<u64>>());
}

#[test]
fn operator_static_diagnostic_sink_failure_preserves_result() {
    let (state, snapshot, scope, _) = fixture();
    let attempt = Attempt::after_admission(&state, &snapshot, &scope);
    let error = ERROR_CANARY.to_owned();
    let error_pointer = error.as_ptr();
    let (returned, lines, count) = capture(true, || attempt.observe::<()>(Stage::SecretRefresh, Err(error)));
    let returned = returned.unwrap_err();
    assert_eq!(returned, ERROR_CANARY);
    assert_eq!(returned.as_ptr(), error_pointer);
    assert!(lines.is_empty());
    assert_eq!(count, 1);

    let counter = AtomicUsize::new(0);
    let mut calls = 0;
    for _ in 0..192 {
        let returned = attempt.observe_with_for_test::<()>(Stage::FinalDeadline, Err(ERROR_CANARY.to_owned()), &counter, |_| {
            calls += 1;
            Err(io::Error::new(io::ErrorKind::BrokenPipe, ERROR_CANARY))
        });
        assert_eq!(returned, Err(ERROR_CANARY.to_owned()));
    }
    assert_eq!((calls, counter.load(Ordering::Relaxed)), (64, 64));
    let value = Box::new([19u8; 32]);
    let pointer = value.as_ptr();
    let returned = attempt.observe_with_for_test(Stage::Binding, Ok::<_, String>(value), &counter,
        |_| panic!("successful observation called its sink")).unwrap();
    assert_eq!(returned.as_ptr(), pointer);
    assert_eq!(*returned, [19u8; 32]);
    assert_eq!(counter.load(Ordering::Relaxed), 64);
}

#[test]
fn operator_static_diagnostic_successful_preparation_silent() {
    let (state, snapshot, scope, _) = fixture();
    let (result, lines, count) = capture(false, || preparation::prepare_if_admitted(&state, &snapshot, &scope, false));
    let info = result.unwrap().unwrap();
    assert_eq!(info.version, 7);
    assert!(info.secret_available);
    assert_pair(&state, &snapshot, &scope);
    assert!(state.credential_lease_url.is_none());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert!(lines.is_empty());
    assert_eq!(count, 0);
}

#[test]
fn operator_static_diagnostic_excluded_and_pre_admission_paths_silent() {
    // Repeat the original real admission controls under the local observation
    // sink: proof, production, native owner, atomic release, wrong ingress,
    // JIT, OAuth and inactive shadow still return their original excluded result.
    let (_, lines, count) = capture(false, super::operator_static_excluded_owners_and_requests_keep_old_path);
    assert!(lines.is_empty());
    assert_eq!(count, 0);

    let (mut state, snapshot, scope, _) = fixture();
    let (result, lines, count) = capture(false, || preparation::prepare_on_deadline(
        &state, &snapshot, &scope, Instant::now() - Duration::from_millis(1)));
    assert_eq!(result.err().unwrap(), "custody I/O deadline exceeded during native credential original operation");
    assert!(lines.is_empty());
    assert_eq!(count, 0);
    assert_pair(&state, &snapshot, &scope);

    // The helper also retains its redundant immutable exclusions; invoking it
    // directly here tests logging only, never grants admission to preparation.
    for production in [true, false] {
        state.is_production = production;
        if !production { state.policy_shadow = ShadowRuntime::new_inactive_for_forwarding_tests(); }
        let attempt = Attempt::after_admission(&state, &snapshot, &scope);
        let (returned, lines, count) = capture(false, || attempt.observe::<()>(Stage::Binding, Err(ERROR_CANARY.to_owned())));
        assert_eq!(returned, Err(ERROR_CANARY.to_owned()));
        assert!(lines.is_empty());
        assert_eq!(count, 0);
    }
}

#[test]
fn operator_static_diagnostic_selected_refresh_failure_preserved() {
    for generation_missing in [true, false] {
        for fail_write in [false, true] {
            let (state, snapshot, scope, _) = fixture();
            assert!(preparation::admitted(&state, &snapshot, &scope, None, None).unwrap());
            assert!(state.credential_lease_url.is_none());
            if generation_missing { state.credential_generations.lock().unwrap().clear(); }
            state.credential_leases.lock().unwrap().clear();
            let (result, lines, count) = capture(fail_write, || preparation::prepare_if_admitted(&state, &snapshot, &scope, false));
            // The real singleflight acquisition refuses before constructing a
            // request or contacting anything. Logging preserves this exact error.
            assert_eq!(result.err().unwrap(), "credential lease URL is not configured");
            assert_eq!(count, 1);
            if fail_write {
                assert!(lines.is_empty());
            } else {
                assert_eq!(lines.len(), 1);
                let value = record(&lines[0]);
                assert_eq!(value["stage"], if generation_missing { "generation_refresh" } else { "secret_refresh" });
                assert_eq!(value["error_code"], "other");
            }
            assert!(state.credential_leases.lock().unwrap().is_empty());
            assert_eq!(state.credential_generations.lock().unwrap().len(), if generation_missing { 0 } else { 1 });
            assert!(state.credential_lease_flights.lock().unwrap().is_empty());
            assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
        }
    }
}
