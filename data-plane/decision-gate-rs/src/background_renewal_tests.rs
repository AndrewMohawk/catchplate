//! Finite executor controls with real signed policy/quote/material verification.
//! Synthetic loopback authority only: no provider or native custody acceptance.
use super::*;
#[path = "operator_static_release_tests.rs"]
mod release_tests;
use crate::operator_audit_publication::{Owner, TestPhase, LOCK_NAME};
use crate::operator_background_renewal::execute;
use std::os::fd::AsRawFd;

const WAIT: Duration = Duration::from_secs(3);
type Hook = Arc<dyn Fn(TestPhase) + Send + Sync>;

fn task(snapshot: &Arc<Snapshot>, scope: &CredentialLeaseScope, purpose: CredentialLeasePurpose)
    -> CredentialLeaseRenewalTask
{
    CredentialLeaseRenewalTask {
        snapshot: Arc::clone(snapshot),
        key: CredentialLeaseGenerationKey::new(snapshot, scope, purpose, None),
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

fn no_effects(state: &GateState, listener: &TcpListener) {
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
}

// Unlike a response-key graft onto a file-trust snapshot, this authority can
// survive the executor's actual forced signed-attestation synchronization.
struct Authority {
    raw: Value,
    snapshot: Arc<Snapshot>,
    key: SigningKey,
    pem: String,
    key_id: String,
    binary: String,
}

impl Authority {
    fn new(sequence: u64, key: SigningKey, pem: String, key_id: String) -> Self {
        let mut raw = signed_policy(&key, &key_id, sequence, false);
        raw["credentials"] = json!([{"id":"static-account", "credentialType":"static",
            "provider":"operator-demo", "providerSubject":SUBJECT,
            "injection":{"type":"bearer", "header":"Authorization"}}]);
        let route = &mut raw["routes"][0];
        route["match"]["methods"] = json!(["GET"]);
        route["credentialRef"] = json!("static-account");
        route["adapter"]["config"]["credentialMode"] = json!("required");
        route["adapter"]["config"].as_object_mut().unwrap().remove("noCredentialProof");
        route["adapter"]["config"]["credentialBinding"] = json!({"credentialType":"static",
            "provider":"operator-demo", "subjects":[SUBJECT], "secretClass":"bearerToken"});
        let signature = key.sign(canonical_json(&signature_payload(&raw)).as_bytes());
        raw["metadata"]["signature"] = json!(format!("ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())));
        let binary = sha256_prefixed(b"synthetic-background-renewal");
        let trust = PolicyTrustRoot {
            verifying_key: key.verifying_key(), key_id: key_id.clone(),
            attested_policy_hash: None, attested_data_plane_binary_digest: None,
            response_verifying_key: None, response_signing_key_id: None,
            attested_response_context: None,
        };
        let mut snapshot = compile_signed_snapshot(raw.clone(), trust, &binary, true).unwrap();
        snapshot.response_verifying_key = Some(key.verifying_key());
        snapshot.response_signing_key_id = Some(key_id.clone());
        snapshot.attested_response_context = Some(AttestedResponseContext {
            runtime_manifest_digest: sha256_prefixed(b"synthetic-renewal-runtime"),
            policy_bundle_digest: snapshot.hash.clone(), provenance_digest: None,
            image_signatures_digest: None, source_tree_digest: None,
        });
        Self { raw, snapshot: Arc::new(snapshot), key, pem, key_id, binary }
    }

    fn attestation(&self, request: &IncomingRequest) -> Value {
        assert_eq!(request.method, "GET");
        let url = url::Url::parse(&format!("http://127.0.0.1{}", request.target)).unwrap();
        assert_eq!(url.path(), "/attestation");
        let query: Vec<_> = url.query_pairs().collect();
        assert_eq!(query.len(), 1);
        assert_eq!(query[0].0, "nonce");
        let snapshot = &self.snapshot;
        let high_water = json!({"store":"sqlite", "policyId":snapshot.policy_id,
            "sequence":snapshot.policy_sequence, "rollbackEpoch":snapshot.rollback_epoch,
            "policyHash":snapshot.hash, "updatedAt":"2026-10-10T00:00:00Z"});
        let mut document = json!({"nonce":query[0].1,
            "policy_signing_key_id":self.key_id, "response_signing_key_id":self.key_id,
            "policy_bundle_digest":snapshot.hash, "policy_sequence":snapshot.policy_sequence,
            "rollback_epoch":snapshot.rollback_epoch, "policy_high_water_digest":digest_json(&high_water),
            "data_plane_binary_digest":self.binary,
            "runtime_manifest_digest":snapshot.attested_response_context.as_ref().unwrap().runtime_manifest_digest});
        let mut quote = json!({"provider":"dev-signed-quote", "claims":document.clone(),
            "quote_signing_public_key_pem":self.pem, "quote_signing_key_id":self.key_id});
        let signature = self.key.sign(canonical_json(&unsigned_quote(&quote)).as_bytes());
        quote["signature"] = json!(format!("ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())));
        document["quote"] = quote;
        document["policy_signing_public_key_pem"] = json!(self.pem);
        document["response_signing_public_key_pem"] = json!(self.pem);
        document["policy_high_water"] = high_water;
        document
    }
}

struct RenewalFixture {
    state: Arc<GateState>,
    snapshot: Arc<Snapshot>,
    scope: CredentialLeaseScope,
    authority: Arc<Authority>,
    listener: TcpListener,
    scratch: Scratch,
}

impl RenewalFixture {
    fn new(hook: Hook) -> Self {
        let scratch = Scratch::new();
        let (key, pem, key_id) = response_proof_signing_material().unwrap();
        let authority = Arc::new(Authority::new(1, key, pem, key_id));
        let path = scratch.0.join("policy-bundle.json");
        fs::write(&path, serde_json::to_vec(&authority.raw).unwrap()).unwrap();
        fs::write(scratch.0.join(LOCK_NAME), []).unwrap();
        fs::set_permissions(scratch.0.join(LOCK_NAME), fs::Permissions::from_mode(0o600)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let snapshot = Arc::clone(&authority.snapshot);
        let scope = CredentialLeaseScope::new("agent:test", "route:test", "static-account");
        let mut state = test_gate_state(Arc::clone(&snapshot));
        state.policy_path = path.to_string_lossy().into_owned();
        state.binary_digest = authority.binary.clone();
        state.policy_trust_root_source = PolicyTrustRootSource::AttestedControlPlane {
            url: format!("{endpoint}/attestation"), expected_quote_key_id: Some(authority.key_id.clone()),
            verifier: None, native_transport: None,
        };
        state.policy_high_water_path = Some(scratch.0.join("high-water.json"));
        state.policy_shadow = ShadowRuntime::new_operator_demo(profile(&snapshot, public_deployment()));
        state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
        state.operator_audit_publication = Some(Arc::new(Owner::open(&path).unwrap().with_test_hook(hook)));
        state.credential_lease_url = Some(format!("{endpoint}/api/data-plane/credential-leases"));
        state.credential_lease_token = Some("synthetic-renewal-service".into());
        seed(&state, &snapshot, &scope, 60_000, 60_000);
        Self { state: Arc::new(state), snapshot, scope, authority, listener, scratch }
    }

    fn due(&self, purpose: CredentialLeasePurpose) -> CredentialLeaseRenewalTask {
        seed(&self.state, &self.snapshot, &self.scope,
            if purpose == CredentialLeasePurpose::GenerationMetadata { 0 } else { 60_000 }, 0);
        mark_credential_lease_activity(&self.state, &self.snapshot, &self.scope);
        assert_eq!(credential_lease_background_renewal_status(&self.state, &self.snapshot,
            &self.scope, purpose), CredentialLeaseRenewalStatus::Due);
        task(&self.snapshot, &self.scope, purpose)
    }

    fn server(&self, authority: Arc<Authority>, methods: Vec<&'static str>)
        -> thread::JoinHandle<Vec<Value>>
    {
        let listener = self.listener.try_clone().unwrap();
        thread::spawn(move || {
            let mut material = Vec::new();
            for method in methods {
                let mut poll = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                assert_eq!(unsafe { libc::poll(&mut poll, 1, WAIT.as_millis() as i32) }, 1,
                    "bounded synthetic receiver expected one connection");
                let (stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(false).unwrap();
                let (mut stream, request) = receive(stream);
                assert_eq!(request.method, method);
                let response = if method == "GET" {
                    http_response("200 OK", authority.attestation(&request))
                } else {
                    assert_eq!(request.target, "/api/data-plane/credential-leases");
                    let body: Value = strict_json_from_slice(&request.body).unwrap();
                    assert_eq!(body["policyHash"], authority.snapshot.hash);
                    material.push(body);
                    material_response(&authority.key, &authority.snapshot, &request, 7, 4_000)
                };
                stream.write_all(&response).unwrap();
            }
            material
        })
    }
}

fn checkpoint() -> (Hook, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    (Arc::new(move |phase| {
        if phase == TestPhase::BeforeSharedLock {
            entered.send(()).unwrap();
            released.lock().unwrap().recv_timeout(WAIT).unwrap();
        }
    }), received, release)
}

#[test]
fn background_renewal_stale_cold_and_foreground_fresh_tasks_do_no_io() {
    let fixture = RenewalFixture::new(Arc::new(|_| {}));
    let work = fixture.due(CredentialLeasePurpose::GenerationMetadata);
    fixture.state.credential_lease_activity.lock().unwrap().clear();
    assert!(execute(&fixture.state, &work).is_ok());
    mark_credential_lease_activity(&fixture.state, &fixture.snapshot, &fixture.scope);
    seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 60_000);
    assert!(execute(&fixture.state, &work).is_ok());
    // Even an equal epoch/hash is not the captured active Arc.
    *fixture.state.snapshot.write().unwrap() = Arc::new((*fixture.snapshot).clone());
    fixture.state.credential_lease_activity.lock().unwrap().clear();
    mark_credential_lease_activity(&fixture.state, &fixture.snapshot, &fixture.scope);
    assert!(fixture.state.credential_lease_activity.lock().unwrap().is_empty());
    let pending = Arc::new(Mutex::new(HashSet::from([work.key.clone()])));
    fixture.state.credential_lease_renewal_queued.store(1, Ordering::Relaxed);
    {
        let _guard = CredentialLeaseRenewalPendingGuard { pending: Arc::clone(&pending),
            state: Arc::clone(&fixture.state), key: work.key.clone() };
        assert!(execute(&fixture.state, &work).is_ok());
    }
    assert!(pending.lock().unwrap().is_empty());
    assert_eq!(fixture.state.credential_lease_renewal_queued.load(Ordering::Relaxed), 0);
    no_effects(&fixture.state, &fixture.listener);
}

#[test]
fn background_renewal_exact_purpose_and_expired_budget_do_no_io() {
    let fixture = RenewalFixture::new(Arc::new(|_| {}));
    let mut work = fixture.due(CredentialLeasePurpose::GenerationMetadata);
    let generation_expiry = {
        let values = fixture.state.credential_generations.lock().unwrap();
        (values[&fixture.scope].expires_at_epoch_ms, values[&fixture.scope].expires_at_monotonic)
    };
    let secret_expiry = {
        let values = fixture.state.credential_leases.lock().unwrap();
        let value = &values[&CredentialLeaseCacheKey::new_bound(&fixture.scope, None, None)];
        (value.expires_at_epoch_ms, value.expires_at_monotonic)
    };
    let wrong_purpose = task(&fixture.snapshot, &fixture.scope, CredentialLeasePurpose::DispatchSecret);
    assert_eq!(credential_lease_background_renewal_status(&fixture.state, &fixture.snapshot,
        &fixture.scope, wrong_purpose.key.purpose), CredentialLeaseRenewalStatus::Ineligible);
    assert!(execute(&fixture.state, &wrong_purpose).is_ok());
    work.deadline = Instant::now();
    assert!(execute(&fixture.state, &work).is_err());
    work.key.policy_hash = sha256_prefixed(b"different queued authority");
    assert!(execute(&fixture.state, &work).is_err());
    // Missing/expired finite application expiry is not background authority,
    // even when the exact current Arc has freshly marked activity.
    for expiry in [None, Some(now_epoch_ms())] {
        let mut expired = (*fixture.snapshot).clone();
        match &mut expired.principals[0].proxy_authorization {
            Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms, .. }) =>
                *expires_at_ms = expiry,
            _ => panic!("fixture requires finite application principal"),
        }
        let expired = Arc::new(expired);
        *fixture.state.snapshot.write().unwrap() = Arc::clone(&expired);
        mark_credential_lease_activity(&fixture.state, &expired, &fixture.scope);
        let expired_work = task(&expired, &fixture.scope, CredentialLeasePurpose::GenerationMetadata);
        assert_eq!(credential_lease_background_renewal_status(&fixture.state, &expired,
            &fixture.scope, expired_work.key.purpose), CredentialLeaseRenewalStatus::Ineligible);
        assert!(execute(&fixture.state, &expired_work).is_ok());
    }
    let generations = fixture.state.credential_generations.lock().unwrap();
    let retained = &generations[&fixture.scope];
    assert_eq!(retained.version, 7);
    assert_eq!(retained.policy_hash, fixture.snapshot.hash);
    assert_eq!(retained.metadata, metadata());
    assert_eq!((retained.expires_at_epoch_ms, retained.expires_at_monotonic), generation_expiry);
    drop(generations);
    let leases = fixture.state.credential_leases.lock().unwrap();
    let lease = &leases[&CredentialLeaseCacheKey::new_bound(&fixture.scope, None, None)];
    assert_eq!(lease.version, 7);
    assert_eq!(lease.secret.as_str(), SECRET);
    assert_eq!((lease.expires_at_epoch_ms, lease.expires_at_monotonic), secret_expiry);
    drop(leases);
    no_effects(&fixture.state, &fixture.listener);
}

#[test]
fn background_renewal_after_lane_fresh_and_cold_rechecks_share_exact_result() {
    for fresh in [true, false] {
        let (hook, entered, release) = checkpoint();
        let fixture = RenewalFixture::new(hook);
        let work = fixture.due(CredentialLeasePurpose::GenerationMetadata);
        let key = work.key.clone();
        let state = Arc::clone(&fixture.state);
        let leader = thread::spawn(move || execute(&state, &work));
        entered.recv_timeout(WAIT).unwrap();
        let flight = Arc::clone(&fixture.state.credential_lease_flights.lock().unwrap()[&key]);
        let (waiting, observed) = mpsc::sync_channel(1);
        *flight.follower_wait_hook.lock().unwrap() = Some(waiting);
        let state = Arc::clone(&fixture.state);
        let snapshot = Arc::clone(&fixture.snapshot);
        let scope = fixture.scope.clone();
        let follower = thread::spawn(move || ensure_scoped_credential_generation_on_deadline(
            &state, &snapshot, &scope, Some(Instant::now() + Duration::from_secs(10))));
        observed.recv_timeout(WAIT).unwrap();
        if fresh {
            seed(&fixture.state, &fixture.snapshot, &fixture.scope, 60_000, 60_000);
        } else {
            fixture.state.credential_lease_activity.lock().unwrap().clear();
        }
        let server = fixture.server(Arc::clone(&fixture.authority), vec!["GET"]);
        release.send(()).unwrap();
        let result = leader.join().unwrap();
        let follower = follower.join().unwrap();
        if fresh {
            result.unwrap();
            assert_eq!(follower.unwrap().version, 7);
        } else {
            assert_eq!(result.unwrap_err(), follower.err().expect("cold flight must fail"));
            assert!(fixture.state.credential_lease_activity.lock().unwrap().is_empty());
            let generations = fixture.state.credential_generations.lock().unwrap();
            assert!(!credential_generation_valid_after(&generations[&fixture.scope],
                &fixture.snapshot, now_epoch_ms(), Instant::now()));
        }
        assert!(server.join().unwrap().is_empty());
        no_effects(&fixture.state, &fixture.listener);
    }
}

#[test]
fn background_renewal_signed_static_due_scope_acquires_exactly_once() {
    let fixture = RenewalFixture::new(Arc::new(|_| {}));
    let purpose = CredentialLeasePurpose::GenerationMetadata;
    let work = fixture.due(purpose);
    let server = fixture.server(Arc::clone(&fixture.authority), vec!["GET", "POST"]);
    execute(&fixture.state, &work).unwrap();
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["purpose"], serde_json::to_value(purpose).unwrap());
    assert_eq!(credential_lease_background_renewal_status(&fixture.state, &fixture.snapshot,
        &fixture.scope, purpose), CredentialLeaseRenewalStatus::Fresh);
    assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
    assert!(fixture.state.credential_lease_flights.lock().unwrap().is_empty());
    assert_eq!(fixture.listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn background_renewal_static_secret_never_queues_or_hands_an_expired_flight_to_foreground() {
    let fixture = RenewalFixture::new(Arc::new(|_| {
        panic!("on-demand static secrets must not enter the background publication lane");
    }));
    let work = fixture.due(CredentialLeasePurpose::DispatchSecret);
    let original_deadline = work.deadline;
    let original = fixture.state.credential_generations.lock().unwrap()[&fixture.scope].clone();
    let writer = fs::OpenOptions::new().read(true).write(true)
        .open(fixture.scratch.0.join(LOCK_NAME)).unwrap();
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);

    // The coordinator excludes this otherwise-due task, and the worker also
    // refuses to elect a stale queued secret task before any publication wait.
    assert!(active_credential_lease_background_candidates(&fixture.state, &fixture.snapshot,
        CREDENTIAL_LEASE_RENEW_BEFORE).is_empty());
    execute(&fixture.state, &work).unwrap();
    assert_eq!(work.deadline, original_deadline);
    no_effects(&fixture.state, &fixture.listener);
    {
        let mut values = fixture.state.credential_generations.lock().unwrap();
        let retained = values.get_mut(&fixture.scope).unwrap();
        assert_eq!(retained.expires_at_epoch_ms, original.expires_at_epoch_ms);
        assert_eq!(retained.expires_at_monotonic, original.expires_at_monotonic);
        // Deterministically model expiry during the held publication interval;
        // only shorten both clocks, never change the version or extend a lease.
        retained.expires_at_epoch_ms = now_epoch_ms();
        retained.expires_at_monotonic = Instant::now();
    }
    assert_eq!(credential_lease_background_renewal_status(&fixture.state, &fixture.snapshot,
        &fixture.scope, CredentialLeasePurpose::DispatchSecret), CredentialLeaseRenewalStatus::Ineligible);
    execute(&fixture.state, &work).unwrap();
    let candidates = active_credential_lease_background_candidates(&fixture.state, &fixture.snapshot,
        CREDENTIAL_LEASE_RENEW_BEFORE);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].scope, fixture.scope);
    assert_eq!(candidates[0].purpose, CredentialLeasePurpose::GenerationMetadata);
    no_effects(&fixture.state, &fixture.listener);
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) }, 0);

    // The foreground now owns both actual signed/encrypted acquisitions. It
    // cannot inherit a failed background secret flight or renew this deadline.
    let server = fixture.server(Arc::clone(&fixture.authority), vec!["POST", "POST"]);
    let info = preparation::prepare_on_deadline(&fixture.state, &fixture.snapshot,
        &fixture.scope, original_deadline).unwrap();
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["purpose"], "generationMetadata");
    assert_eq!(requests[1]["purpose"], "dispatchSecret");
    assert_eq!(requests[1]["expectedCredentialVersion"], original.version);
    assert_eq!(requests[1]["expectedMetadataSha256"], original.metadata_sha256);
    assert_eq!(info.version, original.version);
    assert_eq!(info.metadata, original.metadata);
    assert!(info.secret_available);
    assert_eq!(work.deadline, original_deadline);
    assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
    assert!(fixture.state.credential_lease_flights.lock().unwrap().is_empty());
    assert_eq!(fixture.listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn background_renewal_publisher_first_reloads_without_retargeting_or_hot_transfer() {
    let (hook, entered, release) = checkpoint();
    let fixture = RenewalFixture::new(hook);
    let work = fixture.due(CredentialLeasePurpose::GenerationMetadata);
    let writer = fs::OpenOptions::new().read(true).write(true)
        .open(fixture.scratch.0.join(LOCK_NAME)).unwrap();
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let state = Arc::clone(&fixture.state);
    let worker = thread::spawn(move || execute(&state, &work));
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(fixture.listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let next = Arc::new(Authority::new(2, fixture.authority.key.clone(),
        fixture.authority.pem.clone(), fixture.authority.key_id.clone()));
    fs::write(&fixture.state.policy_path, serde_json::to_vec(&next.raw).unwrap()).unwrap();
    let server = fixture.server(Arc::clone(&next), vec!["GET"]);
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) }, 0);
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(server.join().unwrap().is_empty());
    let active = current_snapshot(&fixture.state);
    assert_eq!(active.hash, next.snapshot.hash);
    assert_ne!(active.hash, fixture.snapshot.hash);
    assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version, 7);
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    assert_eq!(credential_lease_hot_scope_count(&fixture.state, &active), 0);
    assert!(credential_generations_ready(&fixture.state, &active));
    mark_credential_lease_activity(&fixture.state, &fixture.snapshot, &fixture.scope);
    assert!(active_credential_lease_background_candidates(&fixture.state, &active,
        CREDENTIAL_LEASE_RENEW_BEFORE).is_empty());
    mark_credential_lease_activity(&fixture.state, &active, &fixture.scope);
    assert_eq!(credential_lease_hot_scope_count(&fixture.state, &active), 1);
    assert_eq!(credential_lease_background_renewal_status(&fixture.state, &active, &fixture.scope,
        CredentialLeasePurpose::GenerationMetadata), CredentialLeaseRenewalStatus::Due);
    no_effects(&fixture.state, &fixture.listener);
}

#[test]
fn background_renewal_publication_wait_keeps_original_deadline_and_cache() {
    let fixture = RenewalFixture::new(Arc::new(|_| {}));
    let mut work = fixture.due(CredentialLeasePurpose::GenerationMetadata);
    work.deadline = Instant::now() + Duration::from_millis(80);
    let writer = fs::OpenOptions::new().read(true).write(true)
        .open(fixture.scratch.0.join(LOCK_NAME)).unwrap();
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let original = work.deadline;
    assert!(execute(&fixture.state, &work).is_err());
    assert_eq!(work.deadline, original);
    assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version, 7);
    assert_eq!(fixture.state.credential_leases.lock().unwrap().len(), 1);
    assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) }, 0);
    no_effects(&fixture.state, &fixture.listener);
}
