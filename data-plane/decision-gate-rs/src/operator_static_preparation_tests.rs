//! Synthetic admitted Profile and signed/encrypted loopback lease controls.
//! No provider dispatch, fixed-path deployment admission, or process env edits.
use super::*;
use crate::operator_static_preparation as preparation;
use crate::tests::{
    signed_control_plane_test_response, signed_encrypted_dispatch_credential_response,
    test_snapshot_with_control_plane_response_key,
};
use crate::*;

#[path = "operator_static_preparation_diagnostics_tests.rs"]
mod diagnostics_tests;
#[path = "background_renewal_tests.rs"]
mod background_renewal_tests;

const SUBJECT: &str = "synthetic-static-account";
const SECRET: &str = "synthetic-static-secret";

fn metadata() -> BTreeMap<String, Value> {
    serde_json::from_value(
        json!({"provider":"operator-demo", "provider_subject":SUBJECT,
        "secret_class":"bearerToken", "oauth":false}),
    )
    .unwrap()
}

fn generation(snapshot: &Snapshot, version: u64, millis: u64) -> CredentialLeaseGeneration {
    let metadata = metadata();
    CredentialLeaseGeneration {
        profile: ReleaseProfile::Legacy,
        policy_hash: snapshot.hash.clone(),
        version,
        metadata_sha256: credential_lease_metadata_sha256(&metadata),
        metadata,
        expires_at_epoch_ms: now_epoch_ms() + u128::from(millis),
        expires_at_monotonic: Instant::now() + Duration::from_millis(millis),
    }
}

fn seed(
    state: &GateState,
    snapshot: &Snapshot,
    scope: &CredentialLeaseScope,
    metadata_ms: u64,
    secret_ms: u64,
) {
    let pin = generation(snapshot, 7, metadata_ms);
    let lease = SecretLease {
        profile: ReleaseProfile::Legacy,
        scope: scope.clone(),
        version: 7,
        secret: Zeroizing::new(SECRET.to_owned()),
        metadata: pin.metadata.clone(),
        metadata_sha256: pin.metadata_sha256.clone(),
        policy_hash: snapshot.hash.clone(),
        request_authority: None,
        release_authorization: None,
        expires_at_epoch_ms: now_epoch_ms() + u128::from(secret_ms),
        expires_at_monotonic: Instant::now() + Duration::from_millis(secret_ms),
    };
    state
        .credential_generations
        .lock()
        .unwrap()
        .insert(scope.clone(), pin);
    state
        .credential_leases
        .lock()
        .unwrap()
        .insert(CredentialLeaseCacheKey::new_bound(scope, None, None), lease);
}

fn fixture() -> (GateState, Arc<Snapshot>, CredentialLeaseScope, SigningKey) {
    let key = SigningKey::from_bytes(&[119; 32]);
    let mut snapshot = (*test_snapshot_with_control_plane_response_key(1, &key)).clone();
    snapshot.policy_id = "serverware-operator-demo".to_owned();
    snapshot.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(TOKEN.as_bytes()),
        source_cidrs: vec![],
        expires_at_ms: Some(now_epoch_ms() + 60_000),
        basic_transport: None,
    });
    snapshot.credentials.insert(
        "static-account".to_owned(),
        Credential {
            provider: "operator-demo".to_owned(),
            provider_subject: Some(SUBJECT.to_owned()),
            injection: json!({"type":"bearer","header":"Authorization"}),
        },
    );
    let route = &mut snapshot.routes[0];
    route.host = "api.example.com".to_owned();
    route.resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    route.methods = HashSet::from(["GET".to_owned()]);
    route.credential_ref = Some("static-account".to_owned());
    route.adapter_config["credentialMode"] = json!("required");
    route
        .adapter_config
        .as_object_mut()
        .unwrap()
        .remove("noCredentialProof");
    route.adapter_config["credentialBinding"] = json!({"credentialType":"static","provider":"operator-demo",
        "subjects":[SUBJECT],"secretClass":"bearerToken"});
    let snapshot = Arc::new(snapshot);
    let admitted = profile(&snapshot, public_deployment());
    admitted.validate_snapshot(&snapshot).unwrap();
    let mut state = test_gate_state(Arc::clone(&snapshot));
    state.policy_shadow = ShadowRuntime::new_operator_demo(admitted);
    state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    state.binary_digest = sha256_prefixed(b"synthetic-static-gate");
    let scope = CredentialLeaseScope::new("agent:test", "route:test", "static-account");
    seed(&state, &snapshot, &scope, 60_000, 60_000);
    (state, snapshot, scope, key)
}

fn receive(mut stream: TcpStream) -> (TcpStream, IncomingRequest) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let head = read_request_head_from(&mut stream, None).unwrap();
    let incoming = read_request_body_from_head(&mut stream, head, 64 * 1024).unwrap();
    (stream, incoming)
}

// Same actual v2 encryption/v3 material protocol as the established broker
// fixture, with explicit TTL to test final margin refusal, not clock patches.
fn material_response(
    key: &SigningKey,
    snapshot: &Snapshot,
    incoming: &IncomingRequest,
    version: u64,
    ttl_ms: u64,
) -> Vec<u8> {
    let request: CredentialLeaseRequest = strict_json_from_slice(&incoming.body).unwrap();
    let now = now_epoch_ms() as u64;
    let aad = json!({"apiVersion":"serverware.credentialLeaseEnvelope/v2","algorithm":"X25519-HKDF-SHA256-AES-256-GCM",
        "recipientKeyId":request.recipient_key_id,"recipientNonce":request.recipient_nonce,"policyHash":request.policy_hash,
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"principalId":request.principal_id,
        "routeId":request.route_id,"credentialId":request.credential_id,"issuedAtEpochMs":now,"expiresAtEpochMs":now+ttl_ms});
    let mut credential = json!({"credentialId":request.credential_id,"credentialVersion":version,
        "metadataSha256":credential_lease_metadata_sha256(&metadata()),"metadata":metadata()});
    if request.purpose == CredentialLeasePurpose::DispatchSecret {
        credential["secret"] = json!(SECRET);
    }
    let plaintext = json!({"apiVersion":"serverware.credentialLeaseSet/v3","purpose":request.purpose,
        "requestBindingSha256":credential_lease_request_binding_sha256(&request),"releaseAuthorization":null,
        "recipientKeyId":request.recipient_key_id,"recipientNonce":request.recipient_nonce,"policyHash":request.policy_hash,
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"principalId":request.principal_id,
        "routeId":request.route_id,"credentialId":request.credential_id,"issuedAtEpochMs":now,"expiresAtEpochMs":now+ttl_ms,
        "credentials":[credential]});
    let recipient: [u8; 32] = general_purpose::URL_SAFE_NO_PAD
        .decode(&request.recipient_public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce = general_purpose::URL_SAFE_NO_PAD
        .decode(&request.recipient_nonce)
        .unwrap();
    let secret = X25519StaticSecret::from([109u8; 32]);
    let shared = secret.diffie_hellman(&X25519PublicKey::from(recipient));
    let aad_bytes = canonical_json(&aad).into_bytes();
    let mut info = b"serverware:credential-lease-envelope:v2\0".to_vec();
    info.extend_from_slice(&Sha256::digest(&aad_bytes));
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce).extract(shared.as_bytes());
    let mut key_bytes = [0u8; 32];
    prk.expand(&[info.as_slice()], Aes256KeyLength)
        .unwrap()
        .fill(&mut key_bytes)
        .unwrap();
    let cipher =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap());
    let mut ciphertext = canonical_json(&plaintext).into_bytes();
    cipher
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key([110u8; 12]),
            aead::Aad::from(aad_bytes.as_slice()),
            &mut ciphertext,
        )
        .unwrap();
    let mut envelope = aad;
    envelope["serverEphemeralPublicKey"] =
        json!(general_purpose::URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&secret).as_bytes()));
    envelope["aeadNonce"] = json!(general_purpose::URL_SAFE_NO_PAD.encode([110u8; 12]));
    envelope["ciphertext"] = json!(general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext));
    envelope["ciphertextSha256"] = json!(sha256_prefixed(&ciphertext));
    signed_control_plane_test_response(
        key,
        snapshot,
        incoming,
        &request.recipient_nonce,
        now,
        StatusCode::OK,
        envelope,
    )
}

struct Broker {
    stop: mpsc::Sender<()>,
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<Vec<Value>>,
}

impl Broker {
    fn finish(self) -> Vec<Value> {
        let _ = self.stop.send(());
        self.thread.join().unwrap()
    }
}

fn broker(
    mut state: GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    key: SigningKey,
    mode: &'static str,
) -> (Arc<GateState>, Broker) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    state.credential_lease_url = Some(format!(
        "http://{}/api/data-plane/credential-leases",
        listener.local_addr().unwrap()
    ));
    state.credential_lease_token = Some("synthetic-static-service-token".to_owned());
    let state = Arc::new(state);
    let (stop, stopped) = mpsc::channel();
    let (entered_send, entered) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let server_state = Arc::clone(&state);
    let snapshot = Arc::clone(snapshot);
    let scope = scope.clone();
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = Vec::new();
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let (mut stream, incoming) = receive(stream);
                    let request: CredentialLeaseRequest =
                        strict_json_from_slice(&incoming.body).unwrap();
                    requests.push(strict_json_from_slice::<Value>(&incoming.body).unwrap());
                    assert!(requests.len() <= 4, "unbounded synthetic acquisition");
                    if matches!(mode, "hold" | "deadline") && requests.len() == 1 {
                        entered_send.send(()).unwrap();
                        released.recv_timeout(Duration::from_secs(3)).unwrap();
                    }
                    if mode == "race" {
                        cache_scoped_credential_generation(
                            &server_state,
                            &snapshot,
                            &scope,
                            generation(&snapshot, 8, 60_000),
                        )
                        .unwrap();
                    }
                    let response = if mode == "error" {
                        signed_control_plane_test_response(
                            &key,
                            &snapshot,
                            &incoming,
                            &request.recipient_nonce,
                            now_epoch_ms() as u64,
                            StatusCode::CONFLICT,
                            json!({"detail":"synthetic refusal"}),
                        )
                    } else if request.purpose == CredentialLeasePurpose::GenerationMetadata {
                        material_response(
                            &key,
                            &snapshot,
                            &incoming,
                            7,
                            if mode == "short-metadata" { 500 } else { 4_000 },
                        )
                    } else if mode == "short-secret" {
                        material_response(&key, &snapshot, &incoming, 7, 500)
                    } else {
                        signed_encrypted_dispatch_credential_response(
                            &key,
                            &snapshot,
                            &incoming,
                            &request.recipient_nonce,
                            SECRET,
                            if mode == "wrong-generation" { 8 } else { 7 },
                            metadata(),
                        )
                    };
                    // A short captured deadline deliberately closes the client.
                    let _ = stream.write_all(&response);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stopped.try_recv().is_ok() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "synthetic broker exceeded its fixed bound"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("synthetic broker failed: {error}"),
            }
        }
        requests
    });
    (
        state,
        Broker {
            stop,
            entered,
            release,
            thread,
        },
    )
}

fn assert_pair(state: &GateState, snapshot: &Snapshot, scope: &CredentialLeaseScope) {
    let leases = state.credential_leases.lock().unwrap();
    let generations = state.credential_generations.lock().unwrap();
    let epoch = now_epoch_ms() + 1_000;
    let monotonic = Instant::now() + Duration::from_secs(1);
    let generation = &generations[scope];
    let lease = &leases[&CredentialLeaseCacheKey::new_bound(scope, None, None)];
    assert!(credential_generation_valid_after(
        generation, snapshot, epoch, monotonic
    ));
    assert!(credential_secret_lease_valid_after(
        lease, snapshot, epoch, monotonic
    ));
    assert_eq!(generation.version, 7);
    assert_eq!(lease.version, generation.version);
    assert_eq!(lease.metadata_sha256, generation.metadata_sha256);
}

#[test]
fn operator_static_fresh_pair_no_fetch() {
    let (state, snapshot, scope, _) = fixture();
    assert!(state.credential_lease_url.is_none());
    let info = preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
        .unwrap()
        .unwrap();
    assert_eq!(info.version, 7);
    assert!(info.secret_available);
    assert_pair(&state, &snapshot, &scope);
    assert_eq!(
        state
            .credential_lease_refresh_success
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn operator_static_near_expiry_pair_two_signed_calls() {
    let (state, snapshot, scope, key) = fixture();
    seed(&state, &snapshot, &scope, 500, 500);
    let (state, server) = broker(state, &snapshot, &scope, key, "success");
    let info = preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
        .unwrap()
        .unwrap();
    assert_eq!(info.version, 7);
    assert!(info.secret_available);
    assert_pair(&state, &snapshot, &scope);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["purpose"], "generationMetadata");
    assert_eq!(requests[1]["purpose"], "dispatchSecret");
    assert_eq!(requests[1]["expectedCredentialVersion"], 7);
    assert_ne!(requests[0]["recipientNonce"], requests[1]["recipientNonce"]);
    assert_ne!(requests[0]["recipientKeyId"], requests[1]["recipientKeyId"]);
}

#[test]
fn operator_static_near_expiry_secret_one_call() {
    let (state, snapshot, scope, key) = fixture();
    seed(&state, &snapshot, &scope, 60_000, 500);
    let (state, server) = broker(state, &snapshot, &scope, key, "success");
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .unwrap()
            .secret_available
    );
    assert_pair(&state, &snapshot, &scope);
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["purpose"], "dispatchSecret");
}

#[test]
fn operator_static_short_or_mismatched_material_never_retries() {
    for mode in [
        "short-metadata",
        "short-secret",
        "wrong-generation",
        "error",
    ] {
        let (state, snapshot, scope, key) = fixture();
        seed(
            &state,
            &snapshot,
            &scope,
            if mode == "short-metadata" {
                500
            } else {
                60_000
            },
            500,
        );
        let (state, server) = broker(state, &snapshot, &scope, key, mode);
        assert!(
            preparation::prepare_if_admitted(&state, &snapshot, &scope, false).is_err(),
            "{mode}"
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 1, "{mode}");
        assert_eq!(
            requests[0]["purpose"],
            if mode == "short-metadata" {
                "generationMetadata"
            } else {
                "dispatchSecret"
            }
        );
    }
}

#[test]
fn operator_static_excluded_owners_and_requests_keep_old_path() {
    let (mut state, snapshot, scope, _) = fixture();
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, true)
            .unwrap()
            .is_none()
    );
    state.is_production = true;
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .is_none()
    );
    state.is_production = false;
    state.native_policy_bytes = Some(vec![0u8].into());
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .is_none()
    );
    state.native_policy_bytes = None;
    state.atomic_release_authorization_enabled = true;
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .is_none()
    );
    state.atomic_release_authorization_enabled = false;
    state.proxy_ingress_attestation.mode = "development-raw";
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .is_none()
    );
    state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    for google in [false, true] {
        let mut excluded = (*snapshot).clone();
        if google {
            excluded
                .credentials
                .get_mut(&scope.credential_id)
                .unwrap()
                .provider = "google".to_owned();
            excluded
                .credentials
                .get_mut(&scope.credential_id)
                .unwrap()
                .injection["__serverwareCredentialType"] = json!("oauth2");
        } else {
            excluded.routes[0].jit["required"] = json!(true);
        }
        let excluded = Arc::new(excluded);
        *state.snapshot.write().unwrap() = Arc::clone(&excluded);
        assert!(
            preparation::prepare_if_admitted(&state, &excluded, &scope, false)
                .unwrap()
                .is_none()
        );
    }
    *state.snapshot.write().unwrap() = Arc::clone(&snapshot);
    state.policy_shadow = ShadowRuntime::new_inactive_for_forwarding_tests();
    assert!(
        preparation::prepare_if_admitted(&state, &snapshot, &scope, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        state
            .credential_lease_refresh_success
            .load(Ordering::Relaxed),
        0
    );
}

fn app_expiry(snapshot: &Snapshot, expiry: u128, basic: bool) -> Arc<Snapshot> {
    let mut candidate = snapshot.clone();
    let mut config = json!({"scheme":"Bearer","tokenId":"a1111111-1111-4111-8111-111111111111",
        "tokenSha256":sha256_prefixed("a".repeat(43).as_bytes()),"expiresAtEpochMs":expiry});
    if basic {
        config["basicTransport"] = json!({"username":"a1111111-1111-4111-8111-111111111111"});
    }
    candidate.principals[0].proxy_authorization =
        crate::parse_proxy_authorization(Some(&config), "agent:test").unwrap();
    Arc::new(candidate)
}

fn assert_deadline_refusal(
    state: Arc<GateState>,
    snapshot: Arc<Snapshot>,
    scope: CredentialLeaseScope,
    server: Broker,
    deadline: Instant,
) {
    let worker_state = Arc::clone(&state);
    let (result_send, result_recv) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = preparation::prepare_on_deadline(&worker_state, &snapshot, &scope, deadline);
        result_send.send(result).unwrap();
    });
    // The broker withholds its response until the acquisition has returned.
    // This observes the deadline itself, not a race against a fixed sleep.
    server.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let result = result_recv.recv_timeout(Duration::from_secs(2));
    let _ = server.release.send(());
    worker.join().unwrap();
    assert_eq!(server.finish().len(), 1);
    assert!(result
        .expect("acquisition must finish before broker response")
        .is_err());
    assert_eq!(
        state
            .credential_lease_refresh_success
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn operator_static_captured_deadline_and_expired_apps_refuse() {
    let (state, snapshot, scope, _) = fixture();
    assert!(preparation::prepare_on_deadline(&state, &snapshot, &scope, Instant::now()).is_err());
    assert_eq!(
        CREDENTIAL_LEASE_SINGLEFLIGHT_TIMEOUT,
        Duration::from_secs(15)
    );
    for basic in [false, true] {
        let expired = app_expiry(&snapshot, now_epoch_ms() - 1, basic);
        *state.snapshot.write().unwrap() = Arc::clone(&expired);
        assert!(preparation::prepare_if_admitted(&state, &expired, &scope, false).is_err());
        let (mut state, snapshot, scope, key) = fixture();
        let expiring = app_expiry(&snapshot, now_epoch_ms() + 1_000, basic);
        state.policy_shadow =
            ShadowRuntime::new_operator_demo(profile(&expiring, public_deployment()));
        *state.snapshot.write().unwrap() = Arc::clone(&expiring);
        seed(&state, &expiring, &scope, 60_000, 100);
        let (state, server) = broker(state, &expiring, &scope, key, "deadline");
        assert_deadline_refusal(
            state,
            expiring,
            scope,
            server,
            Instant::now() + Duration::from_secs(4),
        );
    }
    let (state, snapshot, scope, key) = fixture();
    seed(&state, &snapshot, &scope, 60_000, 100);
    let (state, server) = broker(state, &snapshot, &scope, key, "deadline");
    assert_deadline_refusal(
        state,
        snapshot,
        scope,
        server,
        Instant::now() + Duration::from_millis(500),
    );
}

#[test]
fn operator_static_concurrent_generation_change_refuses() {
    let (state, snapshot, scope, key) = fixture();
    seed(&state, &snapshot, &scope, 60_000, 100);
    let (state, server) = broker(state, &snapshot, &scope, key, "race");
    assert!(preparation::prepare_if_admitted(&state, &snapshot, &scope, false).is_err());
    assert_eq!(server.finish().len(), 1);
    assert_eq!(
        state.credential_generations.lock().unwrap()[&scope].version,
        8
    );
}

#[test]
fn operator_static_singleflight_followers_share_acquisition() {
    let (state, snapshot, scope, key) = fixture();
    seed(&state, &snapshot, &scope, 60_000, 100);
    let (state, server) = broker(state, &snapshot, &scope, key, "hold");
    let leader_state = Arc::clone(&state);
    let leader_snapshot = Arc::clone(&snapshot);
    let leader_scope = scope.clone();
    let leader = thread::spawn(move || {
        preparation::prepare_if_admitted(&leader_state, &leader_snapshot, &leader_scope, false)
    });
    server.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let flight_key = CredentialLeaseGenerationKey::new(
        &snapshot,
        &scope,
        CredentialLeasePurpose::DispatchSecret,
        None,
    );
    let flight = state.credential_lease_flights.lock().unwrap()[&flight_key].clone();
    let (wait_send, wait_recv) = mpsc::sync_channel(1);
    *flight.follower_wait_hook.lock().unwrap() = Some(wait_send);
    let follower_state = Arc::clone(&state);
    let follower_snapshot = Arc::clone(&snapshot);
    let follower_scope = scope.clone();
    let follower = thread::spawn(move || {
        preparation::prepare_if_admitted(
            &follower_state,
            &follower_snapshot,
            &follower_scope,
            false,
        )
    });
    wait_recv.recv_timeout(Duration::from_secs(2)).unwrap();
    server.release.send(()).unwrap();
    assert_eq!(leader.join().unwrap().unwrap().unwrap().version, 7);
    assert_eq!(follower.join().unwrap().unwrap().unwrap().version, 7);
    assert_eq!(server.finish().len(), 1);
    assert_pair(&state, &snapshot, &scope);
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
}
