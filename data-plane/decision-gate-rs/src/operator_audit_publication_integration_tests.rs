//! Bounded loopback integration, not a deployed-service or native acceptance test.
//!
//! Uses the existing validated operator Profile fixture, not fixed-path
//! Selection::admit/startup-marker admission. The receiver's committed record
//! models SQLite authority; actual SQLite transactions have separate Python
//! tests. Policy signatures, dev-quote signatures, forced refresh, HTTP POST,
//! complete ACK verification, flock exclusion and file materialization are real.
use super::{profile, public_deployment, signed_policy, Scratch};
use crate::operator_audit_publication::{Owner, TestPhase, LOCK_NAME};
use crate::tests::{signed_audit_test_response, test_audit_event_id, test_gate_state};
use crate::{
    canonical_json, compile_signed_snapshot, current_snapshot, digest_json, file_mtime,
    http_response, load_snapshot_on_deadline, post_serialized_legacy_audit_batch,
    read_request_body_from_head, read_request_head_from, response_proof_signing_material,
    sha256_prefixed, unsigned_quote, AttestedResponseContext, AuditPostFailure, GateState,
    IncomingRequest, PolicyTrustRoot, PolicyTrustRootSource, ShadowRuntime, Snapshot,
    MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const WAIT: Duration = Duration::from_secs(2);
const OBSERVE: Duration = Duration::from_millis(75);
const INSTANCE: &str = "test-instance";
const SERVICE_TOKEN: &str = "synthetic-audit-service-token";
type Hook = Arc<dyn Fn(TestPhase) + Send + Sync>;

struct SignedPolicy {
    bytes: Vec<u8>,
    snapshot: Snapshot,
}

struct Authority {
    policy_pem: String,
    policy_key_id: String,
    response_key: SigningKey,
    response_pem: String,
    response_key_id: String,
    quote_key: SigningKey,
    quote_pem: String,
    quote_key_id: String,
    binary_digest: String,
    committed: Mutex<Arc<SignedPolicy>>,
}

impl Authority {
    fn current(&self) -> Arc<SignedPolicy> {
        Arc::clone(&self.committed.lock().unwrap())
    }

    fn attestation(&self, request: &IncomingRequest) -> Value {
        assert_eq!(request.method, "GET");
        let url = url::Url::parse(&format!("http://127.0.0.1{}", request.target)).unwrap();
        assert_eq!(url.path(), "/attestation");
        let query: Vec<_> = url.query_pairs().collect();
        assert_eq!(query.len(), 1);
        assert_eq!(query[0].0, "nonce");
        let policy = self.current();
        let snapshot = &policy.snapshot;
        let high_water = json!({
            "store":"sqlite", "policyId":snapshot.policy_id,
            "sequence":snapshot.policy_sequence, "rollbackEpoch":snapshot.rollback_epoch,
            "policyHash":snapshot.hash, "updatedAt":"2026-10-08T00:00:00Z",
        });
        let mut document = json!({
            "nonce":query[0].1,
            "policy_signing_key_id":self.policy_key_id,
            "response_signing_key_id":self.response_key_id,
            "policy_bundle_digest":snapshot.hash,
            "policy_sequence":snapshot.policy_sequence,
            "rollback_epoch":snapshot.rollback_epoch,
            "policy_high_water_digest":digest_json(&high_water),
            "data_plane_binary_digest":self.binary_digest,
            "runtime_manifest_digest":sha256_prefixed(b"operator-ordering-runtime"),
        });
        let mut quote = json!({
            "provider":"dev-signed-quote", "claims":document.clone(),
            "quote_signing_public_key_pem":self.quote_pem,
            "quote_signing_key_id":self.quote_key_id,
        });
        let signature = self.quote_key.sign(canonical_json(&unsigned_quote(&quote)).as_bytes());
        quote["signature"] = json!(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())));
        document["quote"] = quote;
        document["policy_signing_public_key_pem"] = json!(self.policy_pem);
        document["response_signing_public_key_pem"] = json!(self.response_pem);
        document["policy_high_water"] = high_water;
        document
    }

    fn answer_attestation(&self, listener: &TcpListener) {
        let (mut stream, request) = receive(listener);
        stream.write_all(&http_response("200 OK", self.attestation(&request))).unwrap();
    }

    fn acknowledgement(&self, request: &IncomingRequest, corruption: Option<&str>) -> Vec<u8> {
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/api/data-plane/audit");
        assert_eq!(request.headers.get("x-serverware-data-plane-token").map(String::as_str), Some(SERVICE_TOKEN));
        assert_eq!(request.body, body());
        let mut snapshot = self.current().snapshot.clone();
        if corruption == Some("context") {
            snapshot.attested_response_context.as_mut().unwrap().policy_bundle_digest =
                sha256_prefixed(b"wrong-response-policy-context");
        }
        let wrong_key = SigningKey::from_bytes(&[93; 32]);
        signed_audit_test_response(
            if corruption == Some("signature") { &wrong_key } else { &self.response_key },
            &snapshot, request, StatusCode::OK,
            if corruption == Some("count") { 2 } else { 1 },
            &if corruption == Some("digest") { sha256_prefixed(b"different batch") }
                else { sha256_prefixed(&request.body) },
            if corruption == Some("instance") { "another-instance" } else { INSTANCE },
        )
    }
}

struct Fixture {
    state: Arc<GateState>,
    authority: Arc<Authority>,
    next: Arc<SignedPolicy>,
    listener: TcpListener,
    policy_path: PathBuf,
    original_mtime: SystemTime,
    // Declared last so all pinned files/state drop before owned scratch removal.
    scratch: Scratch,
}

impl Fixture {
    fn new(hook: Hook) -> Self {
        let scratch = Scratch::new();
        let policy_path = scratch.0.join("policy-bundle.json");
        let (policy_key, policy_pem, policy_key_id) = response_proof_signing_material().unwrap();
        let (response_key, response_pem, response_key_id) = response_proof_signing_material().unwrap();
        let (quote_key, quote_pem, quote_key_id) = response_proof_signing_material().unwrap();
        let binary_digest = sha256_prefixed(b"operator-ordering-test-binary");
        let bundle = |sequence| {
            let raw = signed_policy(&policy_key, &policy_key_id, sequence, false);
            let trust = PolicyTrustRoot {
                verifying_key: policy_key.verifying_key(), key_id: policy_key_id.clone(),
                attested_policy_hash: None, attested_data_plane_binary_digest: None,
                response_verifying_key: None, response_signing_key_id: None,
                attested_response_context: None,
            };
            // This local compile builds the synthetic receiver's authority record.
            // The gate below loads again through a real signed HTTP attestation.
            let mut snapshot = compile_signed_snapshot(raw.clone(), trust, &binary_digest, true).unwrap();
            snapshot.response_verifying_key = Some(response_key.verifying_key());
            snapshot.response_signing_key_id = Some(response_key_id.clone());
            snapshot.attested_response_context = Some(AttestedResponseContext {
                runtime_manifest_digest: sha256_prefixed(b"operator-ordering-runtime"),
                policy_bundle_digest: snapshot.hash.clone(), provenance_digest: None,
                image_signatures_digest: None, source_tree_digest: None,
            });
            Arc::new(SignedPolicy { bytes: serde_json::to_vec(&raw).unwrap(), snapshot })
        };
        let initial = bundle(1);
        let next = bundle(2);
        let authority = Arc::new(Authority {
            policy_pem, policy_key_id, response_key, response_pem, response_key_id,
            quote_key, quote_pem, quote_key_id, binary_digest,
            committed: Mutex::new(Arc::clone(&initial)),
        });
        write_private(&policy_path, &initial.bytes);
        let original_mtime = file_mtime(policy_path.to_str().unwrap()).unwrap();
        write_private(&scratch.0.join(LOCK_NAME), &[]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let trust = PolicyTrustRootSource::AttestedControlPlane {
            url: format!("{endpoint}/attestation"),
            expected_quote_key_id: Some(authority.quote_key_id.clone()),
            verifier: None, native_transport: None,
        };
        let bootstrap_listener = listener.try_clone().unwrap();
        let bootstrap_authority = Arc::clone(&authority);
        let bootstrap = thread::spawn(move || bootstrap_authority.answer_attestation(&bootstrap_listener));
        let snapshot = Arc::new(load_snapshot_on_deadline(policy_path.to_str().unwrap(), &trust,
            &authority.binary_digest, Some(Instant::now() + Duration::from_secs(5))).unwrap());
        bootstrap.join().unwrap();
        assert_eq!(snapshot.hash, initial.snapshot.hash);
        assert!(snapshot.attested_response_context.is_some());
        let mut state = test_gate_state(Arc::clone(&snapshot));
        state.policy_path = policy_path.to_string_lossy().into_owned();
        state.binary_digest = authority.binary_digest.clone();
        state.policy_trust_root_source = trust;
        state.policy_high_water_path = Some(scratch.0.join("high-water.json"));
        state.policy_shadow = ShadowRuntime::new_operator_demo(profile(&snapshot, public_deployment()));
        state.operator_audit_publication = Some(Arc::new(Owner::open(&policy_path).unwrap().with_test_hook(hook)));
        state.audit_url = Some(format!("{endpoint}/api/data-plane/audit"));
        state.audit_token = Some(SERVICE_TOKEN.into());
        state.server_instance_id = Some(INSTANCE.into());
        *state.policy_mtime.lock().unwrap() = Some(original_mtime);
        *state.policy_trust_refresh_due.lock().unwrap() = Instant::now() + Duration::from_secs(60);
        Self { state: Arc::new(state), authority, next, listener, policy_path, original_mtime, scratch }
    }

    fn writer(&self) -> File {
        OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.scratch.0.join(LOCK_NAME)).unwrap()
    }

    fn materialize_next(&self) {
        let stage = self.scratch.0.join("next-policy-stage.json");
        write_private(&stage, &self.next.bytes);
        let staged = OpenOptions::new().read(true).write(true).open(&stage).unwrap();
        staged.set_times(FileTimes::new().set_modified(self.original_mtime)).unwrap();
        staged.sync_all().unwrap();
        fs::rename(stage, &self.policy_path).unwrap();
        File::open(&self.scratch.0).unwrap().sync_all().unwrap();
        assert_eq!(file_mtime(self.policy_path.to_str().unwrap()), Some(self.original_mtime));
        assert_eq!(fs::read(&self.policy_path).unwrap(), self.next.bytes);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn receive(listener: &TcpListener) -> (TcpStream, IncomingRequest) {
    let deadline = Instant::now() + WAIT;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("bounded synthetic receive: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    let head = read_request_head_from(&mut stream, None).unwrap();
    let request = read_request_body_from_head(&mut stream, head, MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES as u64).unwrap();
    (stream, request)
}

fn body() -> Vec<u8> {
    serde_json::to_vec(&json!({"events":[{
        "eventId":test_audit_event_id(1),
        "eventType":"data_plane.synthetic_ordering", "event":{"marker":"bounded-local-only"},
    }]})).unwrap()
}

fn exclusive(file: &File) -> bool {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        true
    } else {
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        false
    }
}

fn assert_no_contact(listener: &TcpListener) {
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn publication_publisher_first_waits_for_same_mtime_materialization_then_signed_ack() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let fixture = Fixture::new(Arc::new(move |phase| {
        if phase == TestPhase::BeforeSharedLock {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
        }
    }));
    let previous = current_snapshot(&fixture.state);
    let publisher = fixture.writer();
    assert!(exclusive(&publisher));
    // Model the committed SQLite B / still-materialized A interval under EX.
    *fixture.authority.committed.lock().unwrap() = Arc::clone(&fixture.next);
    assert_ne!(fixture.authority.current().snapshot.hash, previous.hash);
    let (done_tx, done_rx) = mpsc::channel();
    let state = Arc::clone(&fixture.state);
    let sender = thread::spawn(move || done_tx.send(post_serialized_legacy_audit_batch(&state, &body(), 1)).unwrap());
    entered_rx.recv_timeout(WAIT).unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(done_rx.recv_timeout(OBSERVE), Err(mpsc::RecvTimeoutError::Timeout)));
    assert_no_contact(&fixture.listener);
    assert_eq!(current_snapshot(&fixture.state).hash, previous.hash);
    fixture.materialize_next();
    assert_no_contact(&fixture.listener);
    drop(publisher);
    // Exactly one fresh attestation is required despite the identical mtime and
    // a not-yet-due background refresh. The audit ACK is bound to B, never A.
    fixture.authority.answer_attestation(&fixture.listener);
    let (mut stream, request) = receive(&fixture.listener);
    stream.write_all(&fixture.authority.acknowledgement(&request, None)).unwrap();
    done_rx.recv_timeout(WAIT).unwrap().expect("settled B signed ACK");
    sender.join().unwrap();
    assert_eq!(current_snapshot(&fixture.state).hash, fixture.next.snapshot.hash);
    assert_eq!(fixture.state.policy_high_water.lock().unwrap().policy_hash, fixture.next.snapshot.hash);
    assert!(fixture.state.policy_shadow.serving_ready(&current_snapshot(&fixture.state)));
    assert!(!fixture.state.policy_shadow.serving_ready(&previous));
    assert_eq!(fixture.state.policy_reload_failed.load(Ordering::Relaxed), 0);
    assert_no_contact(&fixture.listener);
    assert!(exclusive(&fixture.writer()));
}

#[test]
fn publication_post_first_excludes_publisher_through_ack_tail_and_full_verification() {
    let (verified_tx, verified_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let fixture = Fixture::new(Arc::new(move |phase| {
        if phase == TestPhase::AckVerified {
            verified_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
        }
    }));
    let (done_tx, done_rx) = mpsc::channel();
    let state = Arc::clone(&fixture.state);
    let sender = thread::spawn(move || done_tx.send(post_serialized_legacy_audit_batch(&state, &body(), 1)).unwrap());
    fixture.authority.answer_attestation(&fixture.listener);
    let (mut stream, request) = receive(&fixture.listener);
    let response = fixture.authority.acknowledgement(&request, None);
    let (prefix, tail) = response.split_at(response.len() - 1);
    stream.write_all(prefix).unwrap();
    let publisher = fixture.writer();
    assert!(!exclusive(&publisher), "publisher must wait for the complete HTTP body");
    assert!(matches!(verified_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    stream.write_all(tail).unwrap();
    verified_rx.recv_timeout(WAIT).unwrap();
    // This checkpoint is after the unchanged signature and all ACK bindings,
    // not merely after send/headers/body receipt. The real permit is still held.
    assert!(!exclusive(&publisher), "publisher must wait through full ACK verification");
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release_tx.send(()).unwrap();
    done_rx.recv_timeout(WAIT).unwrap().expect("fully authenticated A ACK");
    sender.join().unwrap();
    assert!(exclusive(&publisher));
    assert_eq!(fixture.state.policy_reload_failed.load(Ordering::Relaxed), 0);
    assert_no_contact(&fixture.listener);
}

#[test]
fn publication_signed_ack_negatives_still_refuse_and_release_shared_ownership() {
    for (corruption, expected) in [
        ("signature", "signature verification failed"),
        ("context", "context mismatch"),
        ("instance", "instance binding mismatch"),
        ("count", "binding mismatch"),
        ("digest", "binding mismatch"),
    ] {
        let verified = Arc::new(AtomicU64::new(0));
        let count = Arc::clone(&verified);
        let fixture = Fixture::new(Arc::new(move |phase| {
            if phase == TestPhase::AckVerified { count.fetch_add(1, Ordering::Relaxed); }
        }));
        let authority = Arc::clone(&fixture.authority);
        let listener = fixture.listener.try_clone().unwrap();
        let server = thread::spawn(move || {
            authority.answer_attestation(&listener);
            let (mut stream, request) = receive(&listener);
            stream.write_all(&authority.acknowledgement(&request, Some(corruption))).unwrap();
        });
        let error = post_serialized_legacy_audit_batch(&fixture.state, &body(), 1).expect_err(corruption);
        server.join().unwrap();
        assert_eq!(error.kind, AuditPostFailure::OutcomeUnknown, "{corruption}");
        assert!(error.message.contains(expected), "{corruption}: {}", error.message);
        assert_eq!(verified.load(Ordering::Relaxed), 0, "{corruption}");
        assert!(exclusive(&fixture.writer()), "{corruption}");
        assert_eq!(fixture.state.audit_sent.load(Ordering::Relaxed), 0);
        assert_no_contact(&fixture.listener);
    }
}
