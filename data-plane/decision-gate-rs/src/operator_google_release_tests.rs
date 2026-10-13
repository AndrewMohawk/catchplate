//! Synthetic signed loopback authority, real publication owner/ACK/encryption.
//! These controls do not prove a Google request, native admission or deployment.
use super::*;
use crate::*;
use crate::operator_google_preparation::Request;
use crate::operator_google_profile::Profile as GoogleProfile;
use crate::operator_audit_publication::{Owner, LOCK_NAME};
use crate::tests::{signed_audit_test_response, signed_control_plane_test_response};
use std::os::fd::AsRawFd;

const CLIENT: &str = "123-synthetic.apps.googleusercontent.com";
const CALLBACK: &str = "https://operator.example.com/api/oauth/callback/google";
const SUBJECT: &str = "synthetic-google-subject";
const SECRET: &str = r#"{"access_token":"synthetic-google-release-secret"}"#;
const TARGET: &str = "https://gmail.googleapis.com/resource";
const WAIT: Duration = Duration::from_secs(3);

#[path = "operator_x_release_tests.rs"]
mod x_release;
#[path = "operator_x_quota_release_tests.rs"]
mod quota_release;

fn google() -> GoogleProfile {
    GoogleProfile::parse(Some("operator-google-v1"), true, Some(CLIENT), Some(CALLBACK))
        .unwrap().unwrap()
}

fn metadata() -> BTreeMap<String, Value> {
    serde_json::from_value(json!({"provider":"google", "provider_subject":SUBJECT,
        "oauth":true, "managed":true, "provider_identity_verified":true, "oauth_client_id":CLIENT,
        "scopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"]})).unwrap()
}

fn generation(snapshot: &Snapshot, version: u64, millis: u64) -> CredentialLeaseGeneration {
    let metadata = metadata();
    CredentialLeaseGeneration { profile: ReleaseProfile::Legacy, policy_hash: snapshot.hash.clone(),
        version, metadata_sha256: credential_lease_metadata_sha256(&metadata), metadata,
        expires_at_epoch_ms: now_epoch_ms() + u128::from(millis),
        expires_at_monotonic: Instant::now() + Duration::from_millis(millis) }
}

fn seed(fixture: &Fixture, secret_ms: u64) {
    let mut pin = generation(&fixture.snapshot, 7, 60_000);
    pin.metadata = fixture.authority.metadata();
    pin.metadata_sha256 = credential_lease_metadata_sha256(&pin.metadata);
    let lease = SecretLease { profile: ReleaseProfile::Legacy, scope: fixture.scope.clone(), version: 7,
        secret: Zeroizing::new(SECRET.into()), metadata: pin.metadata.clone(),
        metadata_sha256: pin.metadata_sha256.clone(), policy_hash: fixture.snapshot.hash.clone(),
        request_authority: None, release_authorization: None,
        expires_at_epoch_ms: now_epoch_ms() + u128::from(secret_ms),
        expires_at_monotonic: Instant::now() + Duration::from_millis(secret_ms) };
    fixture.state.credential_generations.lock().unwrap().insert(fixture.scope.clone(), pin);
    fixture.state.credential_leases.lock().unwrap()
        .insert(CredentialLeaseCacheKey::new_bound(&fixture.scope, None, None), lease);
}

// Same genuine signed-policy/attestation setup used by background_renewal_tests,
// with a Google OAuth credential and independently validated cold profile.
struct Authority {
    raw: Value,
    snapshot: Arc<Snapshot>,
    key: SigningKey,
    pem: String,
    key_id: String,
    binary: String,
    x: bool,
}

impl Authority {
    fn new(app_ttl: u64) -> Self {
        Self::for_provider(app_ttl, false)
    }

    fn for_provider(app_ttl: u64, x: bool) -> Self {
        Self::for_provider_with_quota(app_ttl, x, false)
    }

    fn for_provider_with_quota(app_ttl: u64, x: bool, quota: bool) -> Self {
        assert!(!quota || x);
        let (key, pem, key_id) = response_proof_signing_material().unwrap();
        let mut raw = signed_policy(&key, &key_id, 1, false);
        raw["principals"][0]["proxyAuthorization"]["expiresAtEpochMs"] = json!(now_epoch_ms() + u128::from(app_ttl));
        raw["credentials"] = json!([{"id":"google-account", "credentialType":"oauth2", "provider":"google",
            "providerSubject":SUBJECT, "oauthClientId":CLIENT,
            "scopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"],
            "injection":{"type":"bearer", "header":"Authorization", "field":"access_token"}}]);
        let route = &mut raw["routes"][0];
        route["match"]["host"] = json!("gmail.googleapis.com");
        route["match"]["methods"] = json!(["GET"]);
        route["credentialRef"] = json!("google-account");
        route["adapter"]["config"]["credentialMode"] = json!("required");
        route["adapter"]["config"].as_object_mut().unwrap().remove("noCredentialProof");
        route["adapter"]["config"]["credentialBinding"] = json!({"credentialType":"oauth2", "provider":"google",
            "subjects":[SUBJECT], "clientIds":[CLIENT], "requiredScopes":["https://www.googleapis.com/auth/gmail.readonly"]});
        if x {
            use crate::operator_x_profile::tests::{CLIENT, SUBJECT};
            raw["credentials"] = json!([{"id":"x-account","credentialType":"oauth2","provider":"x",
                "providerSubject":SUBJECT,"oauthClientId":CLIENT,"scopes":x_post::SCOPES,
                "injection":{"type":"bearer","header":"Authorization","field":"access_token"}}]);
            raw["routes"][0] = json!({"id":"route:test","principals":["agent:test"],"credentialRef":"x-account",
                "credentialHeader":{"mode":"replaceExact","expectedValue":x_post::PLACEHOLDER},
                "match":{"scheme":"https","host":"api.x.com","port":443,"methods":["POST"],"paths":["/2/tweets"]},
                "adapter":{"type":x_post::ADAPTER,"config":{"credentialBinding":{"credentialType":"oauth2",
                    "provider":"x","subjects":[SUBJECT],"clientIds":[CLIENT],"requiredScopes":x_post::SCOPES},
                    "request":x_post::request_config(),"response":x_post::response_profile(false)}},
                "constraints":[x_post::envelope("x-envelope")]});
            if quota { raw["routes"][0]["constraints"].as_array_mut().unwrap().push(x_post::quota(4)); }
        }
        let signature = key.sign(canonical_json(&signature_payload(&raw)).as_bytes());
        raw["metadata"]["signature"] = json!(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())));
        let binary = sha256_prefixed(b"synthetic-google-release-gate");
        let trust = PolicyTrustRoot { verifying_key: key.verifying_key(), key_id: key_id.clone(),
            attested_policy_hash: None, attested_data_plane_binary_digest: None,
            response_verifying_key: None, response_signing_key_id: None, attested_response_context: None };
        let mut snapshot = compile_signed_snapshot(raw.clone(), trust, &binary, true).unwrap();
        snapshot.response_verifying_key = Some(key.verifying_key());
        snapshot.response_signing_key_id = Some(key_id.clone());
        snapshot.attested_response_context = Some(AttestedResponseContext {
            runtime_manifest_digest: sha256_prefixed(b"synthetic-google-release-runtime"),
            policy_bundle_digest: snapshot.hash.clone(), provenance_digest: None,
            image_signatures_digest: None, source_tree_digest: None });
        Self { raw, snapshot: Arc::new(snapshot), key, pem, key_id, binary, x }
    }

    fn metadata(&self) -> BTreeMap<String, Value> {
        if !self.x { return metadata(); }
        let metadata = serde_json::from_value(json!({"provider":"x.oauth2","provider_id":"x","oauth":true,
            "provider_subject":crate::operator_x_profile::tests::SUBJECT,"provider_identity_verified":true,
            "oauth_client_id":crate::operator_x_profile::tests::CLIENT,"x_app_id":crate::operator_x_profile::tests::CLIENT,
            "scopes":x_post::SCOPES,"expires_at_epoch_ms":4_070_908_800_000u64})).unwrap();
        // Match the app's closed public lease projection, not its display DTO.
        validate_credential_generation_metadata(&metadata).unwrap();
        metadata
    }

    fn target(&self) -> (&'static str, &'static str) {
        if self.x { ("POST","https://api.x.com/2/tweets") } else { ("GET",TARGET) }
    }

    fn attestation(&self, request: &IncomingRequest) -> Value {
        assert_eq!(request.method, "GET");
        let url = Url::parse(&format!("http://127.0.0.1{}", request.target)).unwrap();
        assert_eq!(url.path(), "/attestation");
        let query: Vec<_> = url.query_pairs().collect();
        assert_eq!(query.len(), 1);
        assert_eq!(query[0].0, "nonce");
        let snapshot = &self.snapshot;
        let high_water = json!({"store":"sqlite", "policyId":snapshot.policy_id,
            "sequence":snapshot.policy_sequence, "rollbackEpoch":snapshot.rollback_epoch,
            "policyHash":snapshot.hash, "updatedAt":"2026-10-12T00:00:00Z"});
        let mut document = json!({"nonce":query[0].1, "policy_signing_key_id":self.key_id,
            "response_signing_key_id":self.key_id, "policy_bundle_digest":snapshot.hash,
            "policy_sequence":snapshot.policy_sequence, "rollback_epoch":snapshot.rollback_epoch,
            "policy_high_water_digest":digest_json(&high_water), "data_plane_binary_digest":self.binary,
            "runtime_manifest_digest":snapshot.attested_response_context.as_ref().unwrap().runtime_manifest_digest});
        let mut quote = json!({"provider":"dev-signed-quote", "claims":document.clone(),
            "quote_signing_public_key_pem":self.pem, "quote_signing_key_id":self.key_id});
        let signature = self.key.sign(canonical_json(&unsigned_quote(&quote)).as_bytes());
        quote["signature"] = json!(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())));
        document["quote"] = quote;
        document["policy_signing_public_key_pem"] = json!(self.pem);
        document["response_signing_public_key_pem"] = json!(self.pem);
        document["policy_high_water"] = high_water;
        document
    }
}

struct Fixture {
    state: Arc<GateState>, snapshot: Arc<Snapshot>, scope: CredentialLeaseScope,
    authority: Arc<Authority>, listener: TcpListener, _scratch: Scratch,
}

impl Fixture {
    fn new(app_ttl: u64) -> Self {
        Self::for_provider(app_ttl, false)
    }

    fn for_provider(app_ttl: u64, x: bool) -> Self {
        Self::for_provider_with_quota(app_ttl, x, false)
    }

    fn for_provider_with_quota(app_ttl: u64, x: bool, quota: bool) -> Self {
        let scratch = Scratch::new();
        let authority = Arc::new(Authority::for_provider_with_quota(app_ttl, x, quota));
        let path = scratch.0.join("policy-bundle.json");
        fs::write(&path, serde_json::to_vec(&authority.raw).unwrap()).unwrap();
        fs::write(scratch.0.join(LOCK_NAME), []).unwrap();
        fs::set_permissions(scratch.0.join(LOCK_NAME), fs::Permissions::from_mode(0o600)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let snapshot = Arc::clone(&authority.snapshot);
        let deployment = Deployment::parse(
            if x {r#"["https://api.x.com"]"#} else {r#"["https://gmail.googleapis.com"]"#}, None).unwrap();
        let mut admitted = if quota {
            // Install the separately admitted X profile before validation: a
            // limited policy must not pass the default quota-free profile.
            Profile { deployment: Arc::new(deployment), google: None, managed_google: None, managed_x: None,
                active: Arc::new(RwLock::new(ApprovedPolicy {
                    high_water: policy_high_water_for(&snapshot), targets: BTreeSet::new() })) }
        } else { profile(&snapshot, deployment) };
        if x {
            let manifest_path=scratch.0.join("operator-x-configuration.json");
            fs::write(&manifest_path,crate::operator_x_profile::tests::manifest(true).to_string()).unwrap();
            fs::set_permissions(&manifest_path,fs::Permissions::from_mode(0o600)).unwrap();
            let owner=Owner::open(&path).unwrap();
            let permit=owner.acquire(Instant::now()+WAIT).unwrap();
            let configuration=if quota { crate::operator_x_profile::test_load_with_quota(&manifest_path,&permit) }
                else { crate::operator_x_profile::test_load(&manifest_path,&permit) }.unwrap();
            admitted.managed_x=Some(Arc::new(RwLock::new(configuration.state)));
        } else { admitted.google = Some(google()); }
        let approved = admitted.validate_snapshot(&snapshot).unwrap();
        if quota { *admitted.active.write().unwrap() = approved; }
        let mut state = test_gate_state(Arc::clone(&snapshot));
        state.policy_path = path.to_string_lossy().into_owned();
        state.binary_digest = authority.binary.clone();
        state.policy_trust_root_source = PolicyTrustRootSource::AttestedControlPlane {
            url: format!("{endpoint}/attestation"), expected_quote_key_id: Some(authority.key_id.clone()),
            verifier: None, native_transport: None };
        state.policy_high_water_path = Some(scratch.0.join("high-water.json"));
        state.policy_shadow = ShadowRuntime::new_operator_demo(admitted);
        state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
        state.operator_audit_publication = Some(Arc::new(Owner::open(&path).unwrap()));
        state.credential_lease_url = Some(format!("{endpoint}/api/data-plane/credential-leases"));
        state.credential_lease_token = Some("synthetic-google-lease-service".into());
        state.audit_url = Some(format!("{endpoint}/api/data-plane/audit"));
        state.audit_token = Some("synthetic-google-audit-service".into());
        state.server_instance_id = Some("test-instance".into());
        state.operator_x_quota_enabled = quota;
        let fixture = Self { state: Arc::new(state), snapshot,
            scope: CredentialLeaseScope::new("agent:test", "route:test", if x {"x-account"} else {"google-account"}),
            authority, listener, _scratch: scratch };
        if !quota { seed(&fixture, 60_000); }
        fixture
    }

    fn request(&self, deadline: Instant) -> (Request, Value) {
        self.request_expected(deadline, 7)
    }

    fn request_expected(&self, deadline: Instant, version: u64) -> (Request, Value) {
        let mut owner = Request::new(deadline);
        let (method,target)=self.authority.target();
        let mut wire=json!({"method":method, "url":target,
            "headers":{"proxy-authorization":format!("Bearer {TOKEN}")}, "body":""});
        if self.authority.x {
            wire["headers"]["authorization"]=json!(x_post::PLACEHOLDER);
            wire["headers"]["content-type"]=json!("application/json");
            wire["body"]=json!("{\"text\":\"synthetic release test\"}");
        }
        let input=serde_json::from_value(wire).unwrap();
        // Exercise the actual forwarding-decision owner propagation, not a
        // separately acquired pin followed by an owner-less preview decision.
        let (decision, release) = decide_internal_for_forward_with_shadow(&self.state,
            &self.snapshot, input, Some("agent:test"), None, Some(&mut owner), None);
        assert!(release.is_none());
        assert_eq!(decision["allowed"], true, "actual ordinary decision: {decision}");
        assert_eq!(decision["credential_version"], version);
        (owner, decision)
    }
}

// Actual X25519/HKDF/AES-GCM v2 envelope and signed v3 material; explicit
// short TTL and changed metadata are negative material, not verifier stubs.
fn material(authority: &Authority, incoming: &IncomingRequest, mode: &str) -> Vec<u8> {
    let original: Value = strict_json_from_slice(&incoming.body).unwrap();
    let quota = original["apiVersion"] == "serverware.operatorXQuotaCredentialLeaseRequest/v1";
    let request: CredentialLeaseRequest = if quota {
        assert!(authority.x);
        let mut ordinary = original.clone();
        ordinary.as_object_mut().unwrap().remove("operatorXQuota");
        ordinary["apiVersion"] = json!("serverware.credentialLeaseRequest/v3");
        serde_json::from_value(ordinary).unwrap()
    } else { strict_json_from_slice(&incoming.body).unwrap() };
    let now = now_epoch_ms() as u64;
    let ttl = if mode == "short-secret" { 100 }
        else if request.purpose == CredentialLeasePurpose::GenerationMetadata { 5_000 }
        else { 4_000 };
    let expires = if quota { original["operatorXQuota"]["expiresAtEpochMs"].as_u64().unwrap() } else { now + ttl };
    let request_binding = if quota { digest_json_ensure_ascii(&original) }
        else { credential_lease_request_binding_sha256(&request) };
    let version = if matches!(mode,"wrong-version"|"predecision-advance") { 8 } else { 7 };
    let mut values = authority.metadata();
    if mode == "wrong-metadata" { values.insert("synthetic_drift".into(), json!(true)); }
    let aad = json!({"apiVersion":"serverware.credentialLeaseEnvelope/v2", "algorithm":"X25519-HKDF-SHA256-AES-256-GCM",
        "recipientKeyId":request.recipient_key_id, "recipientNonce":request.recipient_nonce,
        "policyHash":request.policy_hash, "dataPlaneBinaryDigest":request.data_plane_binary_digest,
        "principalId":request.principal_id,"routeId":request.route_id,"credentialId":request.credential_id,
        "issuedAtEpochMs":now,"expiresAtEpochMs":expires});
    let mut credential = json!({"credentialId":request.credential_id,"credentialVersion":version,
        "metadataSha256":credential_lease_metadata_sha256(&values),"metadata":values});
    if request.purpose == CredentialLeasePurpose::DispatchSecret { credential["secret"] = json!(SECRET); }
    let plaintext = json!({"apiVersion":"serverware.credentialLeaseSet/v3","purpose":request.purpose,
        "requestBindingSha256":request_binding,"releaseAuthorization":null,
        "recipientKeyId":request.recipient_key_id,"recipientNonce":request.recipient_nonce,
        "policyHash":request.policy_hash,"dataPlaneBinaryDigest":request.data_plane_binary_digest,
        "principalId":request.principal_id,"routeId":request.route_id,"credentialId":request.credential_id,
        "issuedAtEpochMs":now,"expiresAtEpochMs":expires,"credentials":[credential]});
    let recipient: [u8;32] = URL_SAFE_NO_PAD.decode(&request.recipient_public_key).unwrap().try_into().unwrap();
    let nonce = URL_SAFE_NO_PAD.decode(&request.recipient_nonce).unwrap();
    let secret = X25519StaticSecret::from([109u8;32]);
    let shared = secret.diffie_hellman(&X25519PublicKey::from(recipient));
    let aad_bytes = canonical_json(&aad).into_bytes();
    let mut info = b"serverware:credential-lease-envelope:v2\0".to_vec();
    info.extend_from_slice(&Sha256::digest(&aad_bytes));
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce).extract(shared.as_bytes());
    let mut key_bytes = [0u8;32];
    prk.expand(&[info.as_slice()], Aes256KeyLength).unwrap().fill(&mut key_bytes).unwrap();
    let cipher = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap());
    let mut ciphertext = canonical_json(&plaintext).into_bytes();
    cipher.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([110u8;12]),
        aead::Aad::from(aad_bytes.as_slice()), &mut ciphertext).unwrap();
    let mut envelope = aad;
    envelope["serverEphemeralPublicKey"] = json!(URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&secret).as_bytes()));
    envelope["aeadNonce"] = json!(URL_SAFE_NO_PAD.encode([110u8;12]));
    envelope["ciphertext"] = json!(URL_SAFE_NO_PAD.encode(&ciphertext));
    envelope["ciphertextSha256"] = json!(sha256_prefixed(&ciphertext));
    if quota {
        // Independent literal API/store contract. The real owner must verify
        // this signed wrapper and decrypt the inner full-request-bound lease.
        let binding = json!({"principal_id":original["principalId"],"route_id":original["routeId"],
            "credential_id":original["credentialId"],"credential_version":original["expectedCredentialVersion"],
            "credential_metadata_digest":original["expectedMetadataSha256"],"policy_hash":original["policyHash"],
            "request_digest":original["operatorXQuota"]["requestDigest"],
            "operation_digest":original["operatorXQuota"]["operationDigest"],
            "attempt_nonce":original["operatorXQuota"]["attemptNonce"],
            "recipient_digest":digest_json_ensure_ascii(&json!({"recipientKeyId":original["recipientKeyId"],"recipientNonce":original["recipientNonce"]})),
            "request_binding_digest":request_binding,"expires_at_epoch_ms":expires});
        envelope = json!({"apiVersion":"serverware.operatorXQuotaCredentialLeaseResponse/v1",
            "requestBindingSha256":request_binding,"credentialLease":envelope,
            "reservation":{"schema":"serverware.operatorXPostingQuotaReservation/v1",
                "reservation_id":"11111111-1111-4111-8111-111111111111",
                "bucket_key":sha256_prefixed(b"synthetic-x-account-day"),"utc_day":now/86_400_000,
                "expires_at_epoch_ms":expires,"binding_digest":digest_json_ensure_ascii(&binding)}});
    }
    signed_control_plane_test_response(&authority.key, &authority.snapshot, incoming,
        &request.recipient_nonce, now, StatusCode::OK, envelope)
}

fn advanced(authority: &Authority, incoming: &IncomingRequest, foreign_google: bool) -> Vec<u8> {
    let request: CredentialLeaseRequest = strict_json_from_slice(&incoming.body).unwrap();
    let wire: Value = strict_json_from_slice(&incoming.body).unwrap();
    let now = now_epoch_ms() as u64;
    let x_profile=crate::operator_x_profile::parse(
        crate::operator_x_profile::tests::manifest(true).to_string().as_bytes()).unwrap().state.profile.unwrap();
    let selected_x=authority.x && !foreign_google;
    let binding=if selected_x {x_profile.binding_digest().to_owned()} else {google().binding_digest().to_owned()};
    let body = json!({"apiVersion":"serverware.operatorCredentialLeaseNoEnvelope/v1",
        "capability":if selected_x {crate::operator_x_profile::CAPABILITY} else {"operator-google-v1"},"outcome":"noSecretEnvelopeIssued",
        "reason":"generationAdvancedBeforeEnvelope","purpose":"dispatchSecret",
        "profileBindingSha256":binding,"requestBodySha256":digest_json_ensure_ascii(&wire),
        "requestBindingSha256":credential_lease_request_binding_sha256(&request),"policyHash":request.policy_hash,
        "scope":{"principalId":request.principal_id,"routeId":request.route_id,"credentialId":request.credential_id},
        "dataPlaneBinaryDigest":request.data_plane_binary_digest,"recipientKeyId":request.recipient_key_id,
        "recipientNonceSha256":sha256_prefixed(&URL_SAFE_NO_PAD.decode(&request.recipient_nonce).unwrap()),
        "expectedCredentialVersion":request.expected_credential_version,"expectedMetadataSha256":request.expected_metadata_sha256,
        "observedCredentialVersion":8,"observedMetadataSha256":credential_lease_metadata_sha256(&authority.metadata()),
        "issuedAtEpochMs":now,"expiresAtEpochMs":now+5_000});
    signed_control_plane_test_response(&authority.key, &authority.snapshot, incoming,
        &request.recipient_nonce, now, StatusCode::CONFLICT, body)
}

struct Receiver {
    entered: mpsc::Receiver<Value>, release: mpsc::Sender<()>, stop: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<Vec<(String, Value)>>>,
}

impl Receiver {
    fn start(fixture: &Fixture, mode: &'static str) -> Self {
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
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(WAIT)).unwrap();
                        stream.set_write_timeout(Some(WAIT)).unwrap();
                        let head = read_request_head_from(&mut stream, None).unwrap();
                        let request = read_request_body_from_head(&mut stream, head, 64 * 1024).unwrap();
                        assert!(calls.len() < 5, "bounded authority transcript; no retry/replay");
                        let response = if request.method == "GET" {
                            calls.push(("attestation".into(), Value::Null));
                            http_response("200 OK", authority.attestation(&request))
                        } else if request.target == "/api/data-plane/audit" {
                            let body: Value = strict_json_from_slice(&request.body).unwrap();
                            assert!(!calls.iter().any(|(kind,_)| kind == "audit"), "no audit replay");
                            calls.push(("audit".into(), body.clone()));
                            entered.send(body).unwrap();
                            released.recv_timeout(WAIT).unwrap();
                            if mode == "lost-ack" { continue; }
                            if mode == "unsigned-ack" { http_response("200 OK", json!({"ok":true})) }
                            else { signed_audit_test_response(&authority.key, &authority.snapshot, &request,
                                if mode == "failed-ack" { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK },
                                1, &sha256_prefixed(&request.body), "test-instance") }
                        } else {
                            assert_eq!(request.method, "POST");
                            assert_eq!(request.target, "/api/data-plane/credential-leases");
                            let body: Value = strict_json_from_slice(&request.body).unwrap();
                            let purpose = body["purpose"].as_str().unwrap().to_owned();
                            let second=mode=="predecision-advance" && calls.iter().any(|(kind,_)|kind=="dispatchSecret");
                            assert!(!calls.iter().any(|(kind,_)| kind == &purpose) || (second && purpose=="dispatchSecret"
                                && calls.iter().filter(|(kind,_)|kind=="dispatchSecret").count()==1), "no material retry");
                            if purpose == "dispatchSecret" { assert_eq!(body["expectedCredentialVersion"], if second {8} else {7}); }
                            assert_eq!(body["policyHash"], authority.snapshot.hash);
                            calls.push((purpose, body));
                            if matches!(mode,"advanced"|"cross-provider") || (mode=="predecision-advance" && !second) {
                                advanced(&authority, &request, mode=="cross-provider") }
                            else { material(&authority, &request, mode) }
                        };
                        // Expired caller budgets may close the socket before a
                        // late ACK; closure is not permission to retry anything.
                        let _ = stream.write_all(&response);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        match stopped.recv_timeout(Duration::from_millis(5)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                        }
                    }
                    Err(error) => panic!("synthetic Google authority failed: {error}"),
                }
            }
            calls
        });
        Self { entered:received, release, stop, thread:Some(thread) }
    }
    fn finish(mut self) -> Vec<(String,Value)> {
        let _ = self.stop.send(());
        self.thread.take().unwrap().join().unwrap()
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.release.send(()); let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn launch(fixture: &Fixture, mut owner: Request, decision: Value)
    -> (mpsc::Receiver<(Request, Result<Option<SecretLease>, String>)>, thread::JoinHandle<()>)
{
    let state = Arc::clone(&fixture.state); let snapshot = Arc::clone(&fixture.snapshot);
    let (method,target)=fixture.authority.target();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = owner.prepare_release_if_admitted(&state, &snapshot, &decision,
            method, &Url::parse(target).unwrap(), false);
        let _ = sent.send((owner, result));
    });
    (received, worker)
}

fn wait_past(deadline: Instant) {
    let (_held, receiver) = mpsc::channel::<()>();
    assert!(matches!(receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())
        + Duration::from_millis(2)), Err(mpsc::RecvTimeoutError::Timeout)));
}

fn assert_calls(calls: &[(String,Value)], material: &[&str]) {
    let mut expected = vec!["attestation", "audit"]; expected.extend_from_slice(material);
    assert_eq!(calls.iter().map(|(kind,_)| kind.as_str()).collect::<Vec<_>>(), expected);
    let events = calls[1].1["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eventType"], "data_plane.credential.release_started");
    for (key,value) in [("principal_id","agent:test"),("route_id","route:test"),("credential_ref","google-account")] {
        assert_eq!(events[0]["event"][key], value);
    }
    assert_eq!(events[0]["event"]["credential_version"], 7);
    assert!(!serde_json::to_string(events).unwrap().contains("synthetic-google-release-secret"));
}

fn no_material(fixture: &Fixture) {
    assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.state.credential_lease_refresh_failed.load(Ordering::Relaxed), 0);
}

#[test]
fn operator_google_release_delayed_ack_selects_fresh_same_generation() {
    let fixture = Fixture::new(60_000);
    let (owner, decision) = fixture.request(Instant::now() + Duration::from_secs(5));
    seed(&fixture, 300);
    let old = credential_lease_for_release(&fixture.state, &fixture.snapshot, &decision, "google-account", 7).unwrap();
    let old_binding = credential_lease_release_binding(&old);
    let receiver = Receiver::start(&fixture, "ok");
    let (result, worker) = launch(&fixture, owner, decision.clone());
    receiver.entered.recv_timeout(WAIT).unwrap();
    no_material(&fixture);
    wait_past(old_binding.expires_at_monotonic);
    receiver.release.send(()).unwrap();
    let (mut owner, result) = result.recv_timeout(WAIT).unwrap(); worker.join().unwrap();
    let fresh = result.unwrap().unwrap();
    assert_eq!(fresh.version, old.version); assert_eq!(fresh.metadata, old.metadata);
    assert_eq!(fresh.metadata_sha256, old.metadata_sha256); assert_eq!(fresh.scope, fixture.scope);
    assert!(fresh.expires_at_monotonic > old_binding.expires_at_monotonic);
    assert!(!credential_lease_still_releasable(&fixture.state, &fixture.snapshot, &old_binding));
    assert!(credential_lease_upstream_send_timeout(&fixture.state, &fixture.snapshot,
        Some(&credential_lease_release_binding(&fresh))).unwrap().is_some());
    assert!(owner.prepare_release_if_admitted(&fixture.state, &fixture.snapshot, &decision,
        "GET", &Url::parse(TARGET).unwrap(), false).is_err(), "request attempt cannot be replayed");
    assert_calls(&receiver.finish(), &["dispatchSecret"]);
    let target = TcpListener::bind("127.0.0.1:0").unwrap(); target.set_nonblocking(true).unwrap();
    let client = reqwest::blocking::Client::builder().no_proxy().timeout(WAIT).build().unwrap();
    assert!(matches!(send_upstream_request_with_current_lease(&fixture.state, &fixture.snapshot,
        Some(&old_binding), client.get(format!("http://{}/", target.local_addr().unwrap())),
        UpstreamSendDeadlines::default(), false), Err(UpstreamSendError::CredentialAuthority(_))));
    assert_eq!(target.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn operator_google_release_failed_unsigned_lost_ack_never_fetches() {
    for mode in ["failed-ack","unsigned-ack","lost-ack"] {
        let fixture = Fixture::new(60_000);
        let (owner, decision) = fixture.request(Instant::now() + Duration::from_secs(5));
        seed(&fixture, 0);
        let receiver = Receiver::start(&fixture, mode);
        let (result, worker) = launch(&fixture, owner, decision);
        receiver.entered.recv_timeout(WAIT).unwrap(); receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().1.is_err()); worker.join().unwrap();
        assert_calls(&receiver.finish(), &[]); no_material(&fixture);
        assert_eq!(fixture.state.audit_required_failed.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn operator_google_release_post_ack_generation_metadata_snapshot_drift_refuses() {
    for mode in ["version","metadata","snapshot"] {
        let fixture = Fixture::new(60_000);
        let (owner, decision) = fixture.request(Instant::now() + Duration::from_secs(5));
        seed(&fixture, 0);
        let receiver = Receiver::start(&fixture, "ok");
        let (result, worker) = launch(&fixture, owner, decision);
        receiver.entered.recv_timeout(WAIT).unwrap();
        match mode {
            "version" => cache_scoped_credential_generation(&fixture.state, &fixture.snapshot,
                &fixture.scope, generation(&fixture.snapshot, 8, 60_000)).unwrap(),
            "metadata" => {
                let mut generations = fixture.state.credential_generations.lock().unwrap();
                let current = generations.get_mut(&fixture.scope).unwrap();
                current.metadata.insert("synthetic_drift".into(), json!(true));
                current.metadata_sha256 = credential_lease_metadata_sha256(&current.metadata);
            }
            _ => *fixture.state.snapshot.write().unwrap() = Arc::new((*fixture.snapshot).clone()),
        }
        receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().1.is_err()); worker.join().unwrap();
        assert_calls(&receiver.finish(), &[]); no_material(&fixture);
    }
}

#[test]
fn operator_google_release_both_clocks_must_have_margin() {
    for mode in ["secret-wall","secret-monotonic","metadata-wall","metadata-monotonic"] {
        let fixture = Fixture::new(60_000);
        let (owner, decision) = fixture.request(Instant::now() + Duration::from_secs(5));
        let receiver = Receiver::start(&fixture, "ok");
        let (result, worker) = launch(&fixture, owner, decision);
        receiver.entered.recv_timeout(WAIT).unwrap();
        if mode.starts_with("secret") {
            let mut leases = fixture.state.credential_leases.lock().unwrap();
            let lease = leases.get_mut(&CredentialLeaseCacheKey::new_bound(&fixture.scope,None,None)).unwrap();
            if mode.ends_with("wall") { lease.expires_at_epoch_ms = now_epoch_ms() + 500; }
            else { lease.expires_at_monotonic = Instant::now() + Duration::from_millis(500); }
        } else {
            let mut generations = fixture.state.credential_generations.lock().unwrap();
            let generation = generations.get_mut(&fixture.scope).unwrap();
            if mode.ends_with("wall") { generation.expires_at_epoch_ms = now_epoch_ms() + 500; }
            else { generation.expires_at_monotonic = Instant::now() + Duration::from_millis(500); }
        }
        receiver.release.send(()).unwrap();
        let fresh = result.recv_timeout(WAIT).unwrap().1.unwrap().unwrap(); worker.join().unwrap();
        assert_eq!(fresh.version, 7);
        assert!(credential_lease_upstream_send_timeout(&fixture.state, &fixture.snapshot,
            Some(&credential_lease_release_binding(&fresh))).unwrap().is_some());
        assert_calls(&receiver.finish(), if mode.starts_with("secret") { &["dispatchSecret"] } else { &["generationMetadata"] });
    }
}

#[test]
fn operator_google_release_short_changed_material_terminal_without_retry() {
    for mode in ["short-secret","wrong-version","wrong-metadata"] {
        let fixture = Fixture::new(60_000);
        let (owner, decision) = fixture.request(Instant::now() + Duration::from_secs(5));
        seed(&fixture, 0);
        let receiver = Receiver::start(&fixture, mode);
        let (result, worker) = launch(&fixture, owner, decision);
        receiver.entered.recv_timeout(WAIT).unwrap(); receiver.release.send(()).unwrap();
        assert!(result.recv_timeout(WAIT).unwrap().1.is_err()); worker.join().unwrap();
        assert_calls(&receiver.finish(), &["dispatchSecret"]);
    }
}

#[test]
fn operator_google_release_original_deadline_and_app_expiry_include_ack_wait() {
    for app_expiry in [false,true] {
        let fixture = Fixture::new(if app_expiry { 900 } else { 60_000 });
        let original = Instant::now() + if app_expiry { Duration::from_secs(5) } else { Duration::from_millis(350) };
        let (owner, decision) = fixture.request(original);
        seed(&fixture, 0);
        let receiver = Receiver::start(&fixture, "ok");
        let (result, worker) = launch(&fixture, owner, decision);
        receiver.entered.recv_timeout(WAIT).unwrap();
        let deadline = if app_expiry {
            let expiry = match &fixture.snapshot.principals[0].proxy_authorization {
                Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms:Some(expiry),.. }) => *expiry,
                _ => panic!("finite app required"),
            };
            Instant::now() + Duration::from_millis(u64::try_from(expiry.saturating_sub(now_epoch_ms())).unwrap())
        } else { original };
        wait_past(deadline);
        // The original deadline must bound the blocking ACK itself. A check
        // only after receiving a late ACK would not establish this property.
        let finished = result.recv_timeout(Duration::from_millis(500)).unwrap();
        assert!(finished.1.is_err()); worker.join().unwrap();
        receiver.release.send(()).unwrap();
        assert_calls(&receiver.finish(), &[]); no_material(&fixture);
    }
    let fixture = Fixture::new(60_000);
    let mut expired = Request::new(Instant::now());
    assert!(expired.acquire_if_admitted(&fixture.state,&fixture.snapshot,&fixture.scope,false).is_err());
    assert_eq!(fixture.listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn operator_google_release_publication_lock_wait_is_inside_original_deadline() {
    let fixture = Fixture::new(60_000);
    let original = Instant::now() + Duration::from_millis(350);
    let (mut owner, decision) = fixture.request(original);
    // Independent open description: this is the actual retained publication
    // inode, not a mocked Owner or synchronization callback returning success.
    let lock = fs::File::open(fixture._scratch.0.join(LOCK_NAME)).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    assert!(owner.prepare_release_if_admitted(&fixture.state, &fixture.snapshot, &decision,
        "GET", &Url::parse(TARGET).unwrap(), false).is_err());
    assert!(Instant::now() < original + Duration::from_millis(500), "publication wait restarted the request budget");
    assert_eq!(fixture.listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock,
        "publication contention must precede even the attestation request");
    no_material(&fixture);
    assert_eq!(fixture.state.audit_sent.load(Ordering::Relaxed), 0);
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
}

#[test]
fn operator_google_release_canonical_scope_version_and_proof_cannot_be_substituted() {
    for mode in ["version","canonical","scope","target","proof"] {
        let fixture = Fixture::new(60_000);
        let (mut owner, mut decision) = fixture.request(Instant::now() + Duration::from_secs(5));
        match mode {
            "version" => decision["credential_version"] = json!(8),
            "canonical" => decision["canonical_request"]["credential_version"] = json!("8"),
            "scope" => decision["principal_id"] = json!("agent:other"),
            _ => {}
        }
        let url = Url::parse(if mode == "target" { "https://gmail.googleapis.com/other" } else { TARGET }).unwrap();
        let result = owner.prepare_release_if_admitted(&fixture.state,&fixture.snapshot,&decision,"GET",&url,mode=="proof");
        assert!(!matches!(result,Ok(Some(_))), "changed release cannot select a secret");
        assert_eq!(fixture.listener.accept().unwrap_err().kind(),io::ErrorKind::WouldBlock);
        assert_eq!(fixture.state.audit_sent.load(Ordering::Relaxed),0); no_material(&fixture);
    }
    // A genuine OAuth policy cannot admit opaque generic response streaming.
    // Re-sign the altered original and require the real compiler's refusal;
    // do not manufacture a compiled snapshot to exercise an impossible route.
    let authority = Authority::new(60_000);
    let mut raw = authority.raw.clone();
    raw["routes"][0]["adapter"]["config"]["response"]["mode"] = json!("stream");
    raw["routes"][0]["adapter"]["config"]["response"]["allowedFields"] = json!([]);
    let signature = authority.key.sign(canonical_json(&signature_payload(&raw)).as_bytes());
    raw["metadata"]["signature"] = json!(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())));
    let trust = PolicyTrustRoot { verifying_key: authority.key.verifying_key(), key_id: authority.key_id.clone(),
        attested_policy_hash: None, attested_data_plane_binary_digest: None,
        response_verifying_key: None, response_signing_key_id: None, attested_response_context: None };
    assert_eq!(compile_signed_snapshot(raw, trust, &authority.binary, true).err()
        .expect("OAuth generic response stream must be refused"),
        "route route:test credential-bearing generic.rest response mode must be explicitly buffered");
}

#[test]
fn operator_google_release_signed_generation_advance_is_not_second_reconciliation() {
    let fixture = Fixture::new(60_000);
    let (owner,decision) = fixture.request(Instant::now()+Duration::from_secs(5));
    seed(&fixture,0);
    let receiver = Receiver::start(&fixture,"advanced");
    let (result,worker) = launch(&fixture,owner,decision.clone());
    receiver.entered.recv_timeout(WAIT).unwrap(); receiver.release.send(()).unwrap();
    let (mut owner,result) = result.recv_timeout(WAIT).unwrap(); worker.join().unwrap();
    assert!(result.is_err());
    assert!(owner.prepare_release_if_admitted(&fixture.state,&fixture.snapshot,&decision,
        "GET",&Url::parse(TARGET).unwrap(),false).is_err());
    assert_calls(&receiver.finish(),&["dispatchSecret"]);
    assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version,7);
    assert_eq!(fixture.state.credential_lease_refresh_success.load(Ordering::Relaxed),0);
}
