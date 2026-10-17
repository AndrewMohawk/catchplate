//! Deterministic loopback receiver fixtures; no live service or native authority.
use super::*;
use crate::tests::{
    signed_audit_test_response, test_audit_event, test_audit_event_id, test_gate_state,
    test_snapshot_with_control_plane_response_key,
};
use crate::{
    audit_status, enqueue_audit_event, flush_audit_batch, http_response, pop_audit_batch,
    read_request_body_from_head, read_request_head_from, reserve_required_audit, sha256_prefixed,
    IncomingRequest, Snapshot,
};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn fixture() -> (GateState, SigningKey, Arc<Snapshot>, TcpListener) {
    let key = SigningKey::from_bytes(&[81; 32]);
    let snapshot = test_snapshot_with_control_plane_response_key(1, &key);
    let mut state = test_gate_state(Arc::clone(&snapshot));
    let listener = TcpListener::bind("127.0.0.1:0").expect("isolated audit listener");
    listener.set_nonblocking(true).unwrap();
    state.audit_url = Some(format!(
        "http://{}/api/data-plane/audit",
        listener.local_addr().unwrap()
    ));
    state.audit_token = Some("local-audit-test-fixture".into());
    state.server_instance_id = Some("test-instance".into());
    (state, key, snapshot, listener)
}

fn receive(listener: &TcpListener) -> (TcpStream, IncomingRequest) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("bounded audit fixture accept: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let head = read_request_head_from(&mut stream, None).expect("audit request head");
    let request = read_request_body_from_head(
        &mut stream,
        head,
        MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES as u64,
    )
    .expect("bounded audit request body");
    (stream, request)
}

fn events(request: &IncomingRequest) -> Vec<Value> {
    serde_json::from_slice::<Value>(&request.body).unwrap()["events"]
        .as_array()
        .unwrap()
        .clone()
}

fn ids(request: &IncomingRequest) -> Vec<String> {
    events(request)
        .iter()
        .map(|event| event["eventId"].as_str().unwrap().to_owned())
        .collect()
}

// Models the receiver's existing all-new or all-existing contract. In
// particular, this oracle does NOT permit a mixed replay/new append.
fn commit_or_replay(request: &IncomingRequest, stored: &mut BTreeMap<String, Value>) {
    let batch = events(request);
    let present = batch
        .iter()
        .filter(|event| stored.contains_key(event["eventId"].as_str().unwrap()))
        .count();
    assert!(
        present == 0 || present == batch.len(),
        "producer created a partial-replay batch"
    );
    for event in batch {
        let id = event["eventId"].as_str().unwrap().to_owned();
        if let Some(original) = stored.get(&id) {
            assert_eq!(&event, original);
        } else {
            stored.insert(id, event);
        }
    }
}

fn acknowledge(
    mut stream: TcpStream,
    request: &IncomingRequest,
    key: &SigningKey,
    snapshot: &Snapshot,
    status: StatusCode,
) {
    let response = signed_audit_test_response(
        key,
        snapshot,
        request,
        status,
        if status.is_success() {
            events(request).len() as u64
        } else {
            0
        },
        &sha256_prefixed(&request.body),
        "test-instance",
    );
    stream
        .write_all(&response)
        .expect("signed audit acknowledgement");
}

fn queued(state: &GateState, count: u64) -> Vec<AuditEvent> {
    state
        .audit_queue
        .lock()
        .unwrap()
        .extend((1..=count).map(|id| {
            test_audit_event(
                id,
                "data_plane.retry_fixture",
                json!({"marker": id}),
                id % 2 == 1,
            )
        }));
    pop_audit_batch(state)
}

fn assert_drained(state: &GateState, sent: u64) {
    assert!(state.audit_queue.lock().unwrap().is_empty());
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_pending_batches.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_sent.load(Ordering::Relaxed), sent);
    assert_eq!(state.audit_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_required_failed.load(Ordering::Relaxed), 0);
}

#[test]
fn audit_retry_pre_send_refusal_still_allows_later_authenticated_size_split() {
    for refusal in ["missing-token", "invalid-header", "missing-trust"] {
        let (mut state, key, snapshot, listener) = fixture();
        let token = state.audit_token.clone();
        match refusal {
            "missing-token" => state.audit_token = None,
            "invalid-header" => state.audit_token = Some("invalid\nfixture".into()),
            "missing-trust" => {
                let mut untrusted = (*snapshot).clone();
                untrusted.response_verifying_key = None;
                *state.snapshot.write().unwrap() = Arc::new(untrusted);
            }
            _ => unreachable!(),
        }
        let batch = queued(&state, 2);
        let original = serialized_body(&batch).unwrap().to_vec();
        let error = flush_audit_batch(&state, batch).expect_err(refusal);
        assert_eq!(error.kind, AuditPostFailure::NotSent, "{refusal}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        {
            let pending = state.legacy_audit_pending.lock().unwrap();
            let batch = pending.batches.front().unwrap();
            assert_eq!(batch.body.as_slice(), original.as_slice());
            assert!(!batch.outcome_uncertain, "{refusal}");
        }
        assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 1);
        assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 1);
        assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 2);

        state.audit_token = token;
        *state.snapshot.write().unwrap() = Arc::clone(&snapshot);
        let server = thread::spawn(move || {
            let mut stored = BTreeMap::new();
            let (stream, rejected) = receive(&listener);
            assert_eq!(rejected.body, original);
            acknowledge(
                stream,
                &rejected,
                &key,
                &snapshot,
                StatusCode::PAYLOAD_TOO_LARGE,
            );
            for id in 1..=2 {
                let (stream, child) = receive(&listener);
                assert_eq!(ids(&child), vec![test_audit_event_id(id)]);
                commit_or_replay(&child, &mut stored);
                acknowledge(stream, &child, &key, &snapshot, StatusCode::OK);
            }
            stored.len()
        });
        retry(&state).expect("pre-send failure must not poison a later proven rejection");
        assert_eq!(server.join().unwrap(), 2);
        assert_eq!(state.audit_send_failed.load(Ordering::Relaxed), 4);
        assert_drained(&state, 2);
    }
}

#[test]
fn audit_retry_local_size_limit_does_not_attempt_transport() {
    let (state, _, _, listener) = fixture();
    let oversized = vec![b' '; MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES + 1];
    let error = post_serialized_legacy_audit_batch(&state, &oversized, 1)
        .expect_err("local wire bound must reject before transport");
    assert_eq!(error.kind, AuditPostFailure::LocalTooLarge);
    assert!(error.request_too_large());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn audit_retry_lost_ack_keeps_exact_batch_separate_from_fresh_events() {
    let (state, key, snapshot, listener) = fixture();
    let server = thread::spawn(move || {
        let mut stored = BTreeMap::new();
        let (stream, original) = receive(&listener);
        commit_or_replay(&original, &mut stored);
        drop(stream); // Durable commit happened, but its acknowledgement was lost.
        let (stream, replay) = receive(&listener);
        assert_eq!(original.body, replay.body);
        assert_ne!(
            original.headers["x-catchplate-response-nonce"],
            replay.headers["x-catchplate-response-nonce"]
        );
        commit_or_replay(&replay, &mut stored);
        acknowledge(stream, &replay, &key, &snapshot, StatusCode::OK);
        let (stream, fresh) = receive(&listener);
        assert_eq!(events(&fresh).len(), 1);
        commit_or_replay(&fresh, &mut stored);
        acknowledge(stream, &fresh, &key, &snapshot, StatusCode::OK);
        stored.len()
    });
    assert!(flush_audit_batch(&state, queued(&state, 2)).is_err());
    let health = audit_status(&state);
    assert_eq!(health["queue_depth"], 0);
    assert_eq!(health["pending_retry_events"], 2);
    assert_eq!(health["reserved"], 1);
    assert_eq!(health["in_flight_optional"], 1);
    assert!(enqueue_audit_event(
        &state,
        "data_plane.fresh",
        json!({"fresh": true}),
        false
    ));
    retry(&state).expect("exact replay acknowledgement");
    flush_audit_batch(&state, pop_audit_batch(&state))
        .expect("fresh event follows resolved original");
    assert_eq!(server.join().unwrap(), 3);
    assert_drained(&state, 3);
}

#[test]
fn audit_retry_split_siblings_stay_distinct_after_first_child_loses_ack() {
    let (state, key, snapshot, listener) = fixture();
    let server = thread::spawn(move || {
        let mut stored = BTreeMap::new();
        let (stream, root) = receive(&listener);
        assert_eq!(
            ids(&root),
            (1..=4).map(test_audit_event_id).collect::<Vec<_>>()
        );
        acknowledge(
            stream,
            &root,
            &key,
            &snapshot,
            StatusCode::PAYLOAD_TOO_LARGE,
        );
        let (stream, earlier) = receive(&listener);
        assert_eq!(
            ids(&earlier),
            vec![test_audit_event_id(1), test_audit_event_id(2)]
        );
        commit_or_replay(&earlier, &mut stored);
        drop(stream);
        let (stream, replay) = receive(&listener);
        assert_eq!(earlier.body, replay.body);
        commit_or_replay(&replay, &mut stored);
        acknowledge(stream, &replay, &key, &snapshot, StatusCode::OK);
        let (stream, later) = receive(&listener);
        assert_eq!(
            ids(&later),
            vec![test_audit_event_id(3), test_audit_event_id(4)]
        );
        commit_or_replay(&later, &mut stored);
        acknowledge(stream, &later, &key, &snapshot, StatusCode::OK);
        let (stream, fresh) = receive(&listener);
        assert_eq!(events(&fresh).len(), 1);
        commit_or_replay(&fresh, &mut stored);
        acknowledge(stream, &fresh, &key, &snapshot, StatusCode::OK);
        stored.len()
    });
    assert!(flush_audit_batch(&state, queued(&state, 4)).is_err());
    assert_eq!(state.audit_pending_batches.load(Ordering::Relaxed), 2);
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 4);
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 2);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 2);
    assert!(enqueue_audit_event(
        &state,
        "data_plane.fresh",
        json!({"fresh": true}),
        false
    ));
    retry(&state).expect("retry earlier child, then unchanged later child");
    flush_audit_batch(&state, pop_audit_batch(&state)).unwrap();
    assert_eq!(server.join().unwrap(), 5);
    assert_eq!(state.audit_send_failed.load(Ordering::Relaxed), 6);
    assert_drained(&state, 5);
}

#[test]
fn audit_retry_uncertain_original_is_not_split_by_a_later_signed_413() {
    let (mut state, key, snapshot, listener) = fixture();
    let server = thread::spawn(move || {
        let mut stored = BTreeMap::new();
        let (stream, original) = receive(&listener);
        commit_or_replay(&original, &mut stored);
        drop(stream);
        let (stream, rejected_replay) = receive(&listener);
        assert_eq!(original.body, rejected_replay.body);
        acknowledge(
            stream,
            &rejected_replay,
            &key,
            &snapshot,
            StatusCode::PAYLOAD_TOO_LARGE,
        );
        let (stream, accepted_replay) = receive(&listener);
        assert_eq!(original.body, accepted_replay.body);
        commit_or_replay(&accepted_replay, &mut stored);
        acknowledge(stream, &accepted_replay, &key, &snapshot, StatusCode::OK);
        stored.len()
    });
    let error = flush_audit_batch(&state, queued(&state, 2)).unwrap_err();
    assert_eq!(error.kind, AuditPostFailure::OutcomeUnknown);
    let token = state.audit_token.take();
    let error = retry(&state).expect_err("later local refusal does not resolve the first POST");
    assert_eq!(error.kind, AuditPostFailure::NotSent);
    assert!(
        state
            .legacy_audit_pending
            .lock()
            .unwrap()
            .batches
            .front()
            .unwrap()
            .outcome_uncertain
    );
    state.audit_token = token;
    let error = retry(&state).expect_err("413 cannot resolve an earlier lost ACK");
    assert_eq!(error.kind, AuditPostFailure::AuthenticatedTooLarge);
    assert!(
        state
            .legacy_audit_pending
            .lock()
            .unwrap()
            .batches
            .front()
            .unwrap()
            .outcome_uncertain
    );
    assert_eq!(state.audit_pending_batches.load(Ordering::Relaxed), 1);
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 2);
    retry(&state).expect("original eventually acknowledged");
    assert_eq!(server.join().unwrap(), 2);
    assert_drained(&state, 2);
}

#[test]
fn audit_retry_pending_optional_and_required_slots_share_the_queue_bound() {
    let (mut state, key, snapshot, listener) = fixture();
    state.audit_queue_max = 3;
    let server = thread::spawn(move || {
        let (stream, original) = receive(&listener);
        drop(stream);
        let (stream, replay) = receive(&listener);
        assert_eq!(original.body, replay.body);
        acknowledge(stream, &replay, &key, &snapshot, StatusCode::OK);
    });
    assert!(flush_audit_batch(&state, queued(&state, 2)).is_err());
    let mut reservation = reserve_required_audit(&state).expect("last free slot");
    assert!(reserve_required_audit(&state).is_none());
    assert!(!enqueue_audit_event(
        &state,
        "data_plane.optional",
        json!({}),
        false
    ));
    assert!(reservation.commit("data_plane.required", json!({"new": true})));
    assert_eq!(state.audit_queue.lock().unwrap().len(), 1);
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 1);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 1);
    assert!(reserve_required_audit(&state).is_none());
    retry(&state).unwrap();
    server.join().unwrap();
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 0);
    assert!(state.audit_queue.lock().unwrap()[0].required);
    assert!(enqueue_audit_event(
        &state,
        "data_plane.optional",
        json!({}),
        false
    ));
    assert_eq!(state.audit_sent.load(Ordering::Relaxed), 2);
}

#[test]
fn audit_retry_pre_send_cancellation_returns_both_kinds_of_slots() {
    let (state, _, _, _) = fixture();
    let batch = queued(&state, 2);
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 1);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 1);
    requeue_audit_batch(&state, batch);
    assert_eq!(state.audit_reserved.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_inflight_optional.load(Ordering::Relaxed), 0);
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 0);
    assert_eq!(
        state
            .audit_queue
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>(),
        vec![test_audit_event_id(1), test_audit_event_id(2)]
    );
}

#[test]
fn audit_retry_unsigned_413_cannot_split_or_discard_the_pending_original() {
    let (state, key, snapshot, listener) = fixture();
    let server = thread::spawn(move || {
        let (mut stream, original) = receive(&listener);
        stream
            .write_all(&http_response(
                "413 Payload Too Large",
                json!({"error": "untrusted fixture"}),
            ))
            .unwrap();
        drop(stream);
        let (stream, replay) = receive(&listener);
        assert_eq!(original.body, replay.body);
        acknowledge(stream, &replay, &key, &snapshot, StatusCode::OK);
    });
    let error = flush_audit_batch(&state, queued(&state, 2)).unwrap_err();
    assert_eq!(error.kind, AuditPostFailure::OutcomeUnknown);
    assert!(
        !error.request_too_large(),
        "an unauthenticated 413 must not authorize splitting"
    );
    assert_eq!(state.audit_pending_events.load(Ordering::Relaxed), 2);
    retry(&state).unwrap();
    server.join().unwrap();
    assert_drained(&state, 2);
}
