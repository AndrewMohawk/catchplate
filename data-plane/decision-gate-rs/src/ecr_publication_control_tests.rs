//! Synthetic parser/authentication and fixed-loopback machine transport controls.
//! No provider, catalog database, approval action, public TLS or live deployment.
use super::*;
use std::io::Cursor;
use std::sync::mpsc;
use std::thread;

const ID: &str = "11111111-1111-4111-8111-111111111111";
const WAIT: Duration = Duration::from_secs(2);
fn token() -> String { "a".repeat(43) }
fn configuration(expiry: u64) -> Value {
    json!({"scheme":"Bearer", "tokenId":ID, "tokenSha256":sha256_prefixed(token().as_bytes()),
        "expiresAtEpochMs":expiry, "basicTransport":{"username":ID}})
}
fn snapshot(config: &Value, signing_key: &SigningKey) -> Arc<Snapshot> {
    let mut value = (*crate::tests::test_snapshot_with_control_plane_response_key(1, signing_key)).clone();
    value.policy_id = "serverware-operator-demo".into();
    value.principals[0].proxy_authorization = parse_proxy_authorization(Some(config), "agent:test").unwrap();
    Arc::new(value)
}
fn head(method: &str, target: &str, body: &[u8], content_type: Option<&str>) -> RequestHead {
    let content_type = content_type.map(|value| format!("Content-Type: {value}\r\n")).unwrap_or_default();
    let raw = format!("{method} {target} HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n{content_type}\r\n", token(), body.len());
    read_request_head_from(&mut Cursor::new(raw.into_bytes()), Some("127.0.0.1".into())).unwrap()
}

#[test]
fn ecr_control_routes_are_closed_and_never_review_or_admin() {
    let digest = "a".repeat(64);
    for (method, suffix, expected) in [("POST", "".to_owned(), Operation::Create),
        ("GET", format!("/{ID}"), Operation::Status), ("POST", format!("/{ID}/manifest"), Operation::Manifest),
        ("POST", format!("/{ID}/blobs/{digest}/parts/0"), Operation::Part),
        ("POST", format!("/{ID}/submit"), Operation::Submit),
        ("POST", format!("/{ID}/activate"), Operation::Activate)] {
        let path = format!("{PATH}{suffix}");
        assert!(reserved(&path));
        assert_eq!(operation(method, &path), Some(expected));
        for altered in [format!("{path}?x=1"), format!("{path}#fragment"), format!("{path}/"),
            format!("https://proxy.example.com{path}")] {
            assert!(reserved(&altered)); assert!(operation(method, &altered).is_none());
        }
    }
    for suffix in ["/review".to_owned(), format!("/{ID}/approve"), format!("/{ID}/deny"),
        format!("/{ID}/blobs/{digest}/parts/01"), format!("/{ID}/blobs/{digest}/parts/-1"),
        format!("/{ID}/blobs/{digest}/parts/18446744073709551616"), format!("/{ID}/../activate")]
    { assert!(operation("POST", &format!("{PATH}{suffix}")).is_none()); }
    assert!(operation("DELETE", &format!("{PATH}/{ID}")).is_none());
    assert!(operation("POST", "/api/data-plane/ecr-publications/client").is_none());
    assert_eq!(endpoint(Some("https://control.example.com/api/data-plane/credential-leases"),
        &format!("{PATH}/{ID}/submit")).unwrap().as_str(),
        format!("https://control.example.com{INTERNAL_PATH}/{ID}/submit"));
    for lease in ["https://user:password@control.example.com/api/data-plane/credential-leases",
        "https://control.example.com/api/data-plane/credential-leases?alternate=1",
        "https://control.example.com/api/admin", "file:///api/data-plane/credential-leases"] {
        assert!(endpoint(Some(lease), PATH).is_err());
    }
}

#[test]
fn ecr_control_framing_body_and_caller_identity_headers_are_bounded() {
    for forbidden in ["x-serverware-principal-id", "x-serverware-data-plane-token", "x-serverware-client-token-sha256",
        "x-serverware-policy-hash", "x-serverware-admin-token", "x-serverware-response-nonce", "cookie", "remote-user"] {
        let mut request = head("POST", PATH, b"{}", Some("application/json"));
        request.headers.insert(forbidden.into(), "caller-controlled".into());
        assert_eq!(admit(&mut request).err(), Some(StatusCode::UNAUTHORIZED));
    }
    let mut request = head("POST", PATH, b"{}", Some("application/json"));
    request.headers.insert("proxy-authorization".into(), format!("Bearer {}", token()));
    assert_eq!(admit(&mut request).err(), Some(StatusCode::UNAUTHORIZED));
    for name in ["content-encoding", "transfer-encoding", "expect"] {
        let mut request = head("POST", PATH, b"{}", Some("application/json"));
        request.headers.insert(name.into(), "unsupported".into());
        assert_eq!(admit(&mut request).err(), Some(StatusCode::BAD_REQUEST));
    }
    let path = format!("{PATH}/{ID}/manifest");
    let mut request = head("POST", &path, b"raw", Some("application/octet-stream"));
    request.content_length = MAX_PART;
    request.headers.insert("content-length".into(), MAX_PART.to_string());
    assert_eq!(admit(&mut request), Ok(Operation::Manifest));
    request.content_length += 1;
    request.headers.insert("content-length".into(), request.content_length.to_string());
    assert_eq!(admit(&mut request).err(), Some(StatusCode::PAYLOAD_TOO_LARGE));
    assert!(body_valid(Operation::Manifest, &[0, 255, 0]));
    assert!(body_valid(Operation::Submit, b" \n{}\n"));
    assert!(!body_valid(Operation::Submit, b"{\"approved\":true}"));
    assert!(!body_valid(Operation::Create, b"[]"));
    assert!(!body_valid(Operation::Status, b"{}"));
}

#[test]
fn ecr_control_authenticates_current_basic_or_bearer_and_denies_revoked_expired_or_overlap() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let now = now_epoch_ms();
    let config = configuration((now + 60_000) as u64);
    let current = snapshot(&config, &key);
    for basic in [false, true] {
        let mut request = head("POST", PATH, b"{}", Some("application/json"));
        if basic { request.headers.insert("authorization".into(), format!("Basic {}",
            general_purpose::STANDARD.encode(format!("{ID}:{}", token())))); }
        admit(&mut request).unwrap();
        let accepted = authenticate(&current, &request, now).unwrap();
        assert_eq!(accepted.identity.principal_id, "agent:test");
        assert_eq!(accepted.token_sha256, sha256_prefixed(token().as_bytes()));
        assert!(accepted.revalidate(&current).is_ok());
        let mut revoked = (*current).clone(); revoked.principals.clear();
        assert!(accepted.revalidate(&revoked).is_err());
        assert!(authenticate(&current, &request, now + 60_000).is_err());
        let mut rotated = config.clone(); rotated["tokenSha256"] = json!(sha256_prefixed(b"replacement"));
        assert!(accepted.revalidate(&snapshot(&rotated, &key)).is_err());
        // Existing managed overlap remains valid for normal proxy auth, but
        // may not stage a new publication using a retired token generation.
        rotated["managedRenewal"] = json!({"schema":"serverware.proxyTokenRenewal/v1",
            "enrollmentId":ID, "enrollmentExpiresAtEpochMs":(now + 120_000) as u64,
            "rotatedAtEpochMs":(now - 1) as u64,
            "previousToken":{"tokenSha256":sha256_prefixed(token().as_bytes()),
                "originalExpiresAtEpochMs":(now + 60_000) as u64, "expiresAtEpochMs":(now + 30_000) as u64}});
        let overlap = snapshot(&rotated, &key);
        assert!(overlap.principals[0].matches_at(request.client_ip.as_deref(), &request.headers, None, now));
        assert!(authenticate(&overlap, &request, now).is_err());
    }
    let mut request = head("POST", PATH, b"{}", Some("application/json"));
    admit(&mut request).unwrap();
    assert!(authenticate(&crate::tests::test_snapshot(1), &request, now).is_err());
    let mut ambiguous = (*current).clone(); ambiguous.principals.push(ambiguous.principals[0].clone());
    assert!(authenticate(&ambiguous, &request, now).is_err());
}

fn loopback_reply(status: Option<StatusCode>, signed: bool, body: Value) -> Result<Vec<u8>, ()> {
    let key = SigningKey::from_bytes(&[19; 32]);
    let snapshot = snapshot(&configuration((now_epoch_ms() + 60_000) as u64), &key);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let lease_url = format!("http://{}/api/data-plane/credential-leases", listener.local_addr().unwrap());
    let mut request = head("POST", PATH, b" \n{}\n", Some("application/json"));
    admit(&mut request).unwrap();
    let auth = authenticate(&snapshot, &request, now_epoch_ms()).unwrap();
    let expected_hash = snapshot.hash.clone();
    let signer_snapshot = snapshot.clone();
    let (stop, stopped) = mpsc::channel();
    let receiver = thread::spawn(move || {
        let mut count = 0;
        let until = Instant::now() + Duration::from_secs(4);
        while Instant::now() < until {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    count += 1; assert_eq!(count, 1, "no retry after possible commit");
                    stream.set_read_timeout(Some(WAIT)).unwrap(); stream.set_write_timeout(Some(WAIT)).unwrap();
                    let head = read_request_head_from(&mut stream, None).unwrap();
                    let request = read_request_body_from_head(&mut stream, head, MAX_JSON as u64).unwrap();
                    assert_eq!(request.target, INTERNAL_PATH); assert_eq!(request.method, "POST");
                    assert_eq!(request.body, b" \n{}\n");
                    assert_eq!(request.headers.get("x-serverware-principal-id").map(String::as_str), Some("agent:test"));
                    assert_eq!(request.headers.get("x-serverware-client-token-sha256"), Some(&sha256_prefixed(token().as_bytes())));
                    assert_eq!(request.headers.get("x-serverware-policy-hash"), Some(&expected_hash));
                    assert_eq!(request.headers.get("x-serverware-data-plane-token").map(String::as_str), Some("synthetic-machine-token"));
                    assert!(!request.headers.contains_key("authorization") && !request.headers.contains_key("proxy-authorization"));
                    if let Some(status) = status {
                        let raw = if signed { crate::tests::signed_control_plane_test_response(&key, &signer_snapshot,
                            &request, request.headers.get("x-serverware-response-nonce").unwrap(), now_epoch_ms() as u64,
                            status, body.clone()) } else { response(status, serde_json::to_vec(&body).unwrap()) };
                        let _ = stream.write_all(&raw);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stopped.recv_timeout(Duration::from_millis(5)).is_ok() { break; }
                }
                Err(error) => panic!("loopback accept: {error}"),
            }
        }
        count
    });
    let mut state = crate::tests::test_gate_state(snapshot.clone());
    state.credential_lease_url = Some(lease_url); state.credential_lease_token = Some("synthetic-machine-token".into());
    let result = forward(&state, &snapshot, &auth, Operation::Create, PATH, b" \n{}\n", Instant::now() + WAIT);
    let _ = stop.send(()); assert_eq!(receiver.join().unwrap(), 1);
    result
}

#[test]
fn ecr_control_relay_verifies_signed_response_and_never_retries() {
    let result = loopback_reply(Some(StatusCode::CREATED), true, json!({"publication_id":ID})).unwrap();
    let parsed = parse_buffered_response(&result).unwrap();
    assert_eq!(parsed.status, 201); assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap(), json!({"publication_id":ID}));
    let result = loopback_reply(Some(StatusCode::CONFLICT), true, json!({"detail":"PRIVATE-BACKEND-CANARY"})).unwrap();
    let parsed = parse_buffered_response(&result).unwrap(); assert_eq!(parsed.status, 409);
    assert_eq!(parsed.body, br#"{"error":"ecr_publication_refused"}"#);
    assert!(loopback_reply(Some(StatusCode::OK), false, json!({"unsigned":true})).is_err());
    assert!(loopback_reply(Some(StatusCode::OK), true, json!({"oversized":"a".repeat(MAX_RESPONSE as usize)})).is_err());
    assert!(loopback_reply(None, false, Value::Null).is_err());
}
