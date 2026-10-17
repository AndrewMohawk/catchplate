//! Synthetic loopback protocol controls. These validate admitted Profile policy
//! fixtures, not fixed-path Selection::admit, Google consent, or live deployment.
use super::*;
use crate::operator_google_profile::Profile as GoogleProfile;
use crate::operator_google_reconciliation as reconciliation;
use crate::tests::{
    signed_control_plane_test_response, signed_encrypted_dispatch_credential_response,
    test_snapshot_with_control_plane_response_key,
};
use crate::*;

const CLIENT: &str = "123-synthetic.apps.googleusercontent.com";
const CALLBACK: &str = "https://operator.example.com/api/oauth/callback/google";
const SUBJECT: &str = "synthetic-google-subject";

fn google() -> GoogleProfile {
    GoogleProfile::parse(
        Some("operator-google-v1"),
        true,
        Some(CLIENT),
        Some(CALLBACK),
    )
    .unwrap()
    .unwrap()
}

fn metadata() -> BTreeMap<String, Value> {
    serde_json::from_value(json!({"provider":"google","provider_subject":SUBJECT,
        "oauth":true,"managed":true,"provider_identity_verified":true,"oauth_client_id":CLIENT,
        "scopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"]}))
    .unwrap()
}

fn generation(snapshot: &Snapshot, version: u64) -> CredentialLeaseGeneration {
    let metadata = metadata();
    CredentialLeaseGeneration {
        profile: ReleaseProfile::Legacy,
        policy_hash: snapshot.hash.clone(),
        version,
        metadata_sha256: credential_lease_metadata_sha256(&metadata),
        metadata,
        expires_at_epoch_ms: now_epoch_ms() + 60_000,
        expires_at_monotonic: Instant::now() + Duration::from_secs(60),
    }
}

fn fixture() -> (GateState, Arc<Snapshot>, CredentialLeaseScope, SigningKey) {
    let key = SigningKey::from_bytes(&[109; 32]);
    let mut snapshot = (*test_snapshot_with_control_plane_response_key(1, &key)).clone();
    snapshot.policy_id = "catchplate-operator-demo".to_owned();
    snapshot.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(TOKEN.as_bytes()),
        source_cidrs: vec![],
        expires_at_ms: Some(now_epoch_ms() + 60_000),
        basic_transport: None, managed_renewal: None,
    });
    snapshot.credentials.insert("google-account".to_owned(), Credential {
        provider: "google".to_owned(), provider_subject: Some(SUBJECT.to_owned()),
        injection: json!({"type":"bearer","header":"Authorization","field":"access_token",
            "__catchplateCredentialType":"oauth2","__catchplateOAuthClientId":CLIENT,
            "__catchplateGrantedScopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"]}),
    });
    let route = &mut snapshot.routes[0];
    route.host = "gmail.googleapis.com".to_owned();
    route.resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    route.methods = HashSet::from(["GET".to_owned()]);
    route.credential_ref = Some("google-account".to_owned());
    route.adapter_config["credentialMode"] = json!("required");
    route
        .adapter_config
        .as_object_mut()
        .unwrap()
        .remove("noCredentialProof");
    route.adapter_config["credentialBinding"] = json!({"credentialType":"oauth2","provider":"google",
        "subjects":[SUBJECT],"clientIds":[CLIENT],"requiredScopes":["https://www.googleapis.com/auth/gmail.readonly"]});
    let snapshot = Arc::new(snapshot);
    let mut admitted = profile(
        &snapshot,
        Deployment::parse(r#"["https://gmail.googleapis.com"]"#, None).unwrap(),
    );
    admitted.google = Some(google());
    admitted.validate_snapshot(&snapshot).unwrap();
    let mut state = test_gate_state(Arc::clone(&snapshot));
    state.policy_shadow = ShadowRuntime::new_operator_demo(admitted);
    state.binary_digest = sha256_prefixed(b"synthetic-google-gate");
    let scope = CredentialLeaseScope::new("agent:test", "route:test", "google-account");
    state
        .credential_generations
        .lock()
        .unwrap()
        .insert(scope.clone(), generation(&snapshot, 7));
    (state, snapshot, scope, key)
}

fn request(
    state: &GateState,
    snapshot: &Snapshot,
    scope: &CredentialLeaseScope,
) -> CredentialLeaseRequest {
    let public = [5u8; 32];
    CredentialLeaseRequest {
        api_version: "catchplate.credentialLeaseRequest/v3".to_owned(),
        purpose: CredentialLeasePurpose::DispatchSecret,
        principal_id: scope.principal_id.clone(),
        route_id: scope.route_id.clone(),
        credential_id: scope.credential_id.clone(),
        expected_credential_version: Some(7),
        expected_metadata_sha256: Some(generation(snapshot, 7).metadata_sha256),
        request_authority: None,
        release_authorization: None,
        recipient_public_key: general_purpose::URL_SAFE_NO_PAD.encode(public),
        recipient_key_id: sha256_prefixed(&public),
        recipient_nonce: general_purpose::URL_SAFE_NO_PAD.encode([6u8; 32]),
        policy_hash: snapshot.hash.clone(),
        data_plane_binary_digest: state.binary_digest.clone(),
        max_ttl_seconds: 5,
        recipient_attestation: None,
    }
}

fn outcome(request: &CredentialLeaseRequest, wire: &Value, version: u64) -> Value {
    let issued = now_epoch_ms() as u64;
    json!({"apiVersion":"catchplate.operatorCredentialLeaseNoEnvelope/v1",
        "capability":"operator-google-v1","outcome":"noSecretEnvelopeIssued",
        "reason":"generationAdvancedBeforeEnvelope","purpose":"dispatchSecret",
        "profileBindingSha256":google().binding_digest(),
        "requestBodySha256":digest_json_ensure_ascii(wire),
        "requestBindingSha256":credential_lease_request_binding_sha256(request),
        "policyHash":request.policy_hash,"scope":{"principalId":request.principal_id,
            "routeId":request.route_id,"credentialId":request.credential_id},
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"recipientKeyId":request.recipient_key_id,
        "recipientNonceSha256":sha256_prefixed(&general_purpose::URL_SAFE_NO_PAD.decode(&request.recipient_nonce).unwrap()),
        "expectedCredentialVersion":request.expected_credential_version,
        "expectedMetadataSha256":request.expected_metadata_sha256,
        "observedCredentialVersion":version,"observedMetadataSha256":credential_lease_metadata_sha256(&metadata()),
        "issuedAtEpochMs":issued,"expiresAtEpochMs":issued+5_000})
}

fn verify(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    request: &CredentialLeaseRequest,
    body: &Value,
    deadline: Option<Instant>,
) -> bool {
    reconciliation::verify_outcome(
        state,
        snapshot,
        scope,
        request,
        &credential_lease_request_wire_value(request).unwrap(),
        &credential_lease_request_binding_sha256(request),
        &generation(snapshot, 7),
        &serde_json::to_vec(body).unwrap(),
        deadline,
    )
    .is_ok()
}

#[test]
fn google_cold_profile_requires_explicit_operator_and_canonical_public_configuration() {
    assert!(GoogleProfile::parse(None, true, None, None)
        .unwrap()
        .is_none());
    assert!(GoogleProfile::parse(Some(""), true, None, None)
        .unwrap()
        .is_none());
    assert!(GoogleProfile::parse(
        Some("operator-google-v1"),
        false,
        Some(CLIENT),
        Some(CALLBACK)
    )
    .is_err());
    assert!(GoogleProfile::parse(Some("1"), true, Some(CLIENT), Some(CALLBACK)).is_err());
    for client in [
        "bad",
        " leading.apps.googleusercontent.com",
        "a.b.apps.googleusercontent.com",
    ] {
        assert!(GoogleProfile::parse(
            Some("operator-google-v1"),
            true,
            Some(client),
            Some(CALLBACK)
        )
        .is_err());
    }
    for callback in [
        "http://operator.example.com/api/oauth/callback/google",
        "https://operator.example.com:443/api/oauth/callback/google",
        "https://Operator.example.com/api/oauth/callback/google",
        "https://127.0.0.1/api/oauth/callback/google",
        "https://operator.internal/api/oauth/callback/google",
        "https://operator.example.com/api/oauth/callback/google?x=1",
    ] {
        assert!(GoogleProfile::parse(
            Some("operator-google-v1"),
            true,
            Some(CLIENT),
            Some(callback)
        )
        .is_err());
    }
    assert_ne!(
        google().binding_digest(),
        GoogleProfile::parse(
            Some("operator-google-v1"),
            true,
            Some(CLIENT),
            Some("https://other.example.com/api/oauth/callback/google")
        )
        .unwrap()
        .unwrap()
        .binding_digest()
    );
}

#[test]
fn google_no_envelope_body_requires_every_exact_binding_and_closed_types() {
    let (state, snapshot, scope, _) = fixture();
    let request = request(&state, &snapshot, &scope);
    let wire = credential_lease_request_wire_value(&request).unwrap();
    let original = outcome(&request, &wire, 8);
    assert_eq!(original.as_object().unwrap().len(), 19);
    let deadline = Some(Instant::now() + Duration::from_secs(2));
    assert!(verify(
        &state, &snapshot, &scope, &request, &original, deadline
    ));
    for field in [
        "apiVersion",
        "capability",
        "outcome",
        "reason",
        "purpose",
        "profileBindingSha256",
        "requestBodySha256",
        "requestBindingSha256",
        "policyHash",
        "dataPlaneBinaryDigest",
        "recipientKeyId",
        "recipientNonceSha256",
        "expectedMetadataSha256",
        "observedMetadataSha256",
    ] {
        let mut body = original.clone();
        body[field] = json!("wrong");
        assert!(
            !verify(&state, &snapshot, &scope, &request, &body, deadline),
            "{field}"
        );
    }
    for field in ["principalId", "routeId", "credentialId"] {
        let mut body = original.clone();
        body["scope"][field] = json!("other");
        assert!(!verify(
            &state, &snapshot, &scope, &request, &body, deadline
        ));
    }
    for field in original.as_object().unwrap().keys() {
        let mut body = original.clone();
        body.as_object_mut().unwrap().remove(field);
        assert!(
            !verify(&state, &snapshot, &scope, &request, &body, deadline),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("extra", json!(true)),
        ("observedCredentialVersion", json!(7)),
        ("observedCredentialVersion", json!(true)),
        ("expectedCredentialVersion", json!(8)),
        ("expiresAtEpochMs", json!(0)),
        ("expiresAtEpochMs", json!(now_epoch_ms() + 60_000)),
        ("issuedAtEpochMs", json!(0)),
    ] {
        let mut body = original.clone();
        body[field] = value;
        assert!(!verify(
            &state, &snapshot, &scope, &request, &body, deadline
        ));
    }
    assert!(!verify(
        &state, &snapshot, &scope, &request, &original, None
    ));
    assert!(!verify(
        &state,
        &snapshot,
        &scope,
        &request,
        &original,
        Some(Instant::now())
    ));
    let duplicate = serde_json::to_string(&original).unwrap().replacen(
        '{',
        "{\"purpose\":\"dispatchSecret\",",
        1,
    );
    assert!(reconciliation::verify_outcome(
        &state,
        &snapshot,
        &scope,
        &request,
        &wire,
        &credential_lease_request_binding_sha256(&request),
        &generation(&snapshot, 7),
        duplicate.as_bytes(),
        deadline
    )
    .is_err());
}

#[test]
fn google_no_envelope_binds_original_full_wire_not_projected_request() {
    let (state, snapshot, scope, _) = fixture();
    let request = request(&state, &snapshot, &scope);
    let wire = credential_lease_request_wire_value(&request).unwrap();
    let mut crossed = wire.clone();
    crossed["recipientPublicKey"] = json!(general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]));
    let body = outcome(&request, &crossed, 8);
    assert!(!verify(
        &state,
        &snapshot,
        &scope,
        &request,
        &body,
        Some(Instant::now() + Duration::from_secs(2))
    ));
}

#[test]
fn google_reconciliation_does_not_admit_ordinary_or_controlled_profiles() {
    let (mut state, snapshot, scope, _) = fixture();
    assert!(
        reconciliation::admitted(&state, &snapshot, &scope, None, None)
            .unwrap()
            .is_some()
    );
    state.atomic_release_authorization_enabled = true;
    assert!(reconciliation::admitted(&state, &snapshot, &scope, None, None).is_err());
    state.atomic_release_authorization_enabled = false;
    state.credential_lease_recipient_attestation_command = Some("must-not-run".to_owned());
    assert!(reconciliation::admitted(&state, &snapshot, &scope, None, None).is_err());
    state.credential_lease_recipient_attestation_command = None;
    state.policy_shadow = ShadowRuntime::new_operator_demo(profile(
        &snapshot,
        Deployment::parse(r#"["https://gmail.googleapis.com"]"#, None).unwrap(),
    ));
    assert!(
        reconciliation::admitted(&state, &snapshot, &scope, None, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn google_invalidation_retains_floor_and_preserves_concurrent_newer_generation() {
    let (state, snapshot, scope, _) = fixture();
    let expected = generation(&snapshot, 7);
    reconciliation::invalidate_exact(
        &state,
        &snapshot,
        &scope,
        &expected,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let retained = state.credential_generations.lock().unwrap()[&scope].clone();
    assert_eq!(retained.version, 7);
    assert!(!credential_generation_valid_after(
        &retained,
        &snapshot,
        now_epoch_ms(),
        Instant::now()
    ));
    assert!(cache_scoped_credential_generation(
        &state,
        &snapshot,
        &scope,
        generation(&snapshot, 6)
    )
    .is_err());
    cache_scoped_credential_generation(&state, &snapshot, &scope, generation(&snapshot, 9))
        .unwrap();
    reconciliation::invalidate_exact(
        &state,
        &snapshot,
        &scope,
        &expected,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let retained = state.credential_generations.lock().unwrap()[&scope].clone();
    assert_eq!(retained.version, 9);
    assert!(credential_generation_valid_after(
        &retained,
        &snapshot,
        now_epoch_ms(),
        Instant::now()
    ));
}

fn receive(listener: &TcpListener) -> (TcpStream, IncomingRequest) {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let head = read_request_head_from(&mut stream, None).unwrap();
                let request = read_request_body_from_head(&mut stream, head, 64 * 1024).unwrap();
                return (stream, request);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("synthetic credential request unavailable: {error}"),
        }
    }
}

fn metadata_response(
    key: &SigningKey,
    snapshot: &Snapshot,
    incoming: &IncomingRequest,
    version: u64,
) -> Vec<u8> {
    let request: CredentialLeaseRequest = strict_json_from_slice(&incoming.body).unwrap();
    assert_eq!(request.purpose, CredentialLeasePurpose::GenerationMetadata);
    let now = now_epoch_ms() as u64;
    let aad = json!({"apiVersion":"catchplate.credentialLeaseEnvelope/v2","algorithm":"X25519-HKDF-SHA256-AES-256-GCM",
        "recipientKeyId":request.recipient_key_id,"recipientNonce":request.recipient_nonce,"policyHash":request.policy_hash,
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"principalId":request.principal_id,
        "routeId":request.route_id,"credentialId":request.credential_id,"issuedAtEpochMs":now,"expiresAtEpochMs":now+4_000});
    let plaintext = json!({"apiVersion":"catchplate.credentialLeaseSet/v3","purpose":"generationMetadata",
        "requestBindingSha256":credential_lease_request_binding_sha256(&request),"releaseAuthorization":null,
        "recipientKeyId":request.recipient_key_id,"recipientNonce":request.recipient_nonce,"policyHash":request.policy_hash,
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"principalId":request.principal_id,
        "routeId":request.route_id,"credentialId":request.credential_id,"issuedAtEpochMs":now,"expiresAtEpochMs":now+4_000,
        "credentials":[{"credentialId":request.credential_id,"credentialVersion":version,
            "metadataSha256":credential_lease_metadata_sha256(&metadata()),"metadata":metadata()}]});
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
    let mut info = b"catchplate:credential-lease-envelope:v2\0".to_vec();
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

fn run_flow(
    mode: &'static str,
) -> (
    Result<CredentialLeaseInfo, String>,
    Vec<Value>,
    GateState,
    Arc<Snapshot>,
    CredentialLeaseScope,
) {
    let (mut state, snapshot, scope, key) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    state.credential_lease_url = Some(format!(
        "http://{}/api/data-plane/credential-leases",
        listener.local_addr().unwrap()
    ));
    state.credential_lease_token = Some("synthetic-service-token".to_owned());
    let server_snapshot = Arc::clone(&snapshot);
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        let count = if matches!(mode, "success" | "second-conflict") {
            3
        } else if matches!(mode, "stale-metadata" | "observed-digest-mismatch") {
            2
        } else {
            1
        };
        for step in 0..count {
            let (mut stream, incoming) = receive(&listener);
            let wire: Value = strict_json_from_slice(&incoming.body).unwrap();
            let request: CredentialLeaseRequest = strict_json_from_slice(&incoming.body).unwrap();
            requests.push(wire.clone());
            if mode == "interrupted" {
                drop(stream);
                continue;
            }
            let response = if step == 1 {
                metadata_response(
                    &key,
                    &server_snapshot,
                    &incoming,
                    if mode == "stale-metadata" { 7 } else { 8 },
                )
            } else if step == 2 && mode == "success" {
                signed_encrypted_dispatch_credential_response(
                    &key,
                    &server_snapshot,
                    &incoming,
                    &request.recipient_nonce,
                    r#"{"access_token":"synthetic-access-token"}"#,
                    8,
                    metadata(),
                )
            } else {
                let mut body = outcome(&request, &wire, if step == 2 { 9 } else { 8 });
                match mode {
                    "ordinary-409" => body = json!({"detail":"generation changed"}),
                    "profile-mismatch" => {
                        body["profileBindingSha256"] = json!(sha256_prefixed(b"other-profile"))
                    }
                    "nonce-mismatch" => {
                        body["recipientNonceSha256"] = json!(sha256_prefixed(&[11u8; 32]))
                    }
                    "key-mismatch" => body["recipientKeyId"] = json!(sha256_prefixed(&[12u8; 32])),
                    "body-mismatch" => {
                        body["requestBodySha256"] = json!(sha256_prefixed(b"other-request"))
                    }
                    "observed-digest-mismatch" => {
                        body["observedMetadataSha256"] = json!(sha256_prefixed(b"other-metadata"))
                    }
                    "expired-proof" => {
                        body["issuedAtEpochMs"] = json!(now_epoch_ms() - 6_000);
                        body["expiresAtEpochMs"] = json!(now_epoch_ms() - 1_000);
                    }
                    _ => {}
                }
                let signing = if mode == "bad-signature" {
                    SigningKey::from_bytes(&[108; 32])
                } else {
                    key.clone()
                };
                signed_control_plane_test_response(
                    &signing,
                    &server_snapshot,
                    &incoming,
                    &request.recipient_nonce,
                    now_epoch_ms() as u64,
                    StatusCode::CONFLICT,
                    body,
                )
            };
            stream.write_all(&response).unwrap();
        }
        requests
    });
    let result = ensure_scoped_credential_lease(&state, &snapshot, &scope, None);
    let requests = server.join().unwrap();
    (result, requests, state, snapshot, scope)
}

#[test]
fn google_signed_no_envelope_reconciles_once_using_fresh_nonces_and_encrypted_material() {
    let (result, requests, state, snapshot, scope) = run_flow("success");
    let info = result.expect("one definite pre-envelope advance reconciles");
    assert_eq!(info.version, 8);
    assert!(info.secret_available);
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .map(|value| value["purpose"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["dispatchSecret", "generationMetadata", "dispatchSecret"]
    );
    assert_eq!(
        requests
            .iter()
            .map(|value| value["recipientNonce"].as_str().unwrap())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        requests
            .iter()
            .map(|value| value["recipientKeyId"].as_str().unwrap())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert_eq!(requests[0]["expectedCredentialVersion"], 7);
    assert_eq!(requests[2]["expectedCredentialVersion"], 8);
    assert_eq!(
        state.credential_generations.lock().unwrap()[&scope].version,
        8
    );
    assert!(
        cached_credential_lease_info(&state, &snapshot, &scope)
            .unwrap()
            .secret_available
    );
    assert_eq!(
        state
            .credential_lease_refresh_failed
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn google_second_definite_conflict_is_terminal_without_another_request() {
    let (result, requests, state, _, _) = run_flow("second-conflict");
    assert!(result.is_err());
    assert_eq!(requests.len(), 3);
    assert!(state.credential_leases.lock().unwrap().is_empty());
}

#[test]
fn google_signed_ordinary_conflict_mismatches_and_uncertainty_never_reacquire() {
    for mode in [
        "ordinary-409",
        "profile-mismatch",
        "nonce-mismatch",
        "key-mismatch",
        "body-mismatch",
        "bad-signature",
        "interrupted",
        "expired-proof",
    ] {
        let (result, requests, state, _, _) = run_flow(mode);
        assert!(result.is_err(), "{mode}");
        assert_eq!(requests.len(), 1, "{mode}");
        assert!(state.credential_leases.lock().unwrap().is_empty());
    }
}

#[test]
fn google_fresh_metadata_must_prove_the_observed_generation_before_secret_reacquisition() {
    for mode in ["stale-metadata", "observed-digest-mismatch"] {
        let (result, requests, state, _, _) = run_flow(mode);
        assert!(result.is_err(), "{mode}");
        assert_eq!(requests.len(), 2, "{mode}");
        assert!(state.credential_leases.lock().unwrap().is_empty());
    }
}

#[test]
fn google_no_envelope_cannot_cross_snapshot_replacement_or_application_expiry() {
    let (state, snapshot, scope, _) = fixture();
    let request = request(&state, &snapshot, &scope);
    let body = outcome(
        &request,
        &credential_lease_request_wire_value(&request).unwrap(),
        8,
    );
    let deadline = Some(Instant::now() + Duration::from_secs(1));
    *state.snapshot.write().unwrap() = Arc::new((*snapshot).clone());
    assert!(!verify(
        &state, &snapshot, &scope, &request, &body, deadline
    ));
    *state.snapshot.write().unwrap() = Arc::clone(&snapshot);
    let mut expired = (*snapshot).clone();
    if let Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms, .. }) =
        expired.principals[0].proxy_authorization.as_mut()
    {
        *expires_at_ms = Some(now_epoch_ms() - 1);
    }
    let expired = Arc::new(expired);
    *state.snapshot.write().unwrap() = Arc::clone(&expired);
    assert!(!verify(&state, &expired, &scope, &request, &body, deadline));
}

#[test]
fn google_singleflight_waiter_receives_cached_success_not_reconciliation_authority() {
    let (mut state, snapshot, scope, key) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    state.credential_lease_url = Some(format!(
        "http://{}/api/data-plane/credential-leases",
        listener.local_addr().unwrap()
    ));
    state.credential_lease_token = Some("synthetic-service-token".to_owned());
    let state = Arc::new(state);
    let (entered_send, entered_recv) = mpsc::sync_channel(1);
    let (release_send, release_recv) = mpsc::sync_channel(1);
    let server_snapshot = Arc::clone(&snapshot);
    let server = thread::spawn(move || {
        let mut nonces = HashSet::new();
        for step in 0..3 {
            let (mut stream, incoming) = receive(&listener);
            let request: CredentialLeaseRequest = strict_json_from_slice(&incoming.body).unwrap();
            assert!(nonces.insert(request.recipient_nonce.clone()));
            let response = if step == 0 {
                entered_send.send(()).unwrap();
                release_recv.recv_timeout(Duration::from_secs(2)).unwrap();
                let wire = strict_json_from_slice(&incoming.body).unwrap();
                signed_control_plane_test_response(
                    &key,
                    &server_snapshot,
                    &incoming,
                    &request.recipient_nonce,
                    now_epoch_ms() as u64,
                    StatusCode::CONFLICT,
                    outcome(&request, &wire, 8),
                )
            } else if step == 1 {
                metadata_response(&key, &server_snapshot, &incoming, 8)
            } else {
                signed_encrypted_dispatch_credential_response(
                    &key,
                    &server_snapshot,
                    &incoming,
                    &request.recipient_nonce,
                    r#"{"access_token":"synthetic-access-token"}"#,
                    8,
                    metadata(),
                )
            };
            stream.write_all(&response).unwrap();
        }
        nonces.len()
    });
    let leader_state = Arc::clone(&state);
    let leader_snapshot = Arc::clone(&snapshot);
    let leader_scope = scope.clone();
    let leader = thread::spawn(move || {
        ensure_scoped_credential_lease(&leader_state, &leader_snapshot, &leader_scope, None)
    });
    entered_recv.recv_timeout(Duration::from_secs(2)).unwrap();
    let (follower_send, follower_recv) = mpsc::sync_channel(1);
    let flight_key = CredentialLeaseGenerationKey::new(
        &snapshot,
        &scope,
        CredentialLeasePurpose::DispatchSecret,
        None,
    );
    let flight = state.credential_lease_flights.lock().unwrap()[&flight_key].clone();
    *flight.follower_wait_hook.lock().unwrap() = Some(follower_send);
    let waiter_state = Arc::clone(&state);
    let waiter_snapshot = Arc::clone(&snapshot);
    let waiter_scope = scope.clone();
    let waiter = thread::spawn(move || {
        ensure_scoped_credential_lease(&waiter_state, &waiter_snapshot, &waiter_scope, None)
    });
    follower_recv.recv_timeout(Duration::from_secs(2)).unwrap();
    release_send.send(()).unwrap();
    assert_eq!(leader.join().unwrap().unwrap().version, 8);
    assert_eq!(waiter.join().unwrap().unwrap().version, 8);
    assert_eq!(server.join().unwrap(), 3);
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
}

#[test]
fn google_original_deadline_bounds_initial_lookup_waiter_and_cache_mutation() {
    let (state, snapshot, scope, _) = fixture();
    let original = Instant::now() + Duration::from_millis(30);
    assert_eq!(
        reconciliation::operation_deadline(&state, &snapshot, &scope, None, None, Some(original))
            .unwrap(),
        Some(original)
    );
    assert!(ensure_scoped_credential_lease_on_deadline(
        &state,
        &snapshot,
        &scope,
        None,
        None,
        Some(Instant::now())
    )
    .is_err());
    let authority = state.upstream_dispatch_authority.acquire_send();
    let opened = Instant::now();
    assert!(cache_scoped_credential_generation_on_deadline(
        &state,
        &snapshot,
        &scope,
        generation(&snapshot, 8),
        Some(opened + Duration::from_millis(20))
    )
    .is_err());
    assert!(opened.elapsed() < Duration::from_secs(1));
    drop(authority);
    assert_eq!(
        state.credential_generations.lock().unwrap()[&scope].version,
        7
    );
}
