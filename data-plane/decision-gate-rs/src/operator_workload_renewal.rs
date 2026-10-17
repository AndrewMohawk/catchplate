//! Fixed machine renewal transport; enrolled-key authority remains in the
//! transactional application owner. This is never native or admin authority.
use super::*;
use std::sync::atomic::AtomicUsize;

pub(super) const PATH: &str = "/v1/workload/renew";
const INTERNAL_PATH: &str = "/api/operator-demo/workloads/renew";
const MAX_REQUEST: usize = 4096;
const MAX_RESPONSE: usize = 8192;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie",
    "x-catchplate-admin-token", "x-catchplate-bootstrap-token", "x-catchplate-data-plane-token",
    "remote-user", "remote-groups", "remote-email", "remote-name", "origin"];

fn ordinary(state: &GateState) -> bool {
    proxy_basic_transport::admitted_runtime(state)
        && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
        && state.native_policy_bytes.is_none()
        && state.native_upstream_relays.is_none()
        && state.native_enrollment_authorizer.is_none()
        && state.native_jit_review.is_none()
        && state.measured_refresh.is_none() && state.measured_cleanup.is_none()
        && state.measured_pending_retirement.is_none() && state.measured_capture_retirement.is_none()
        && state.measured_issuance.is_none() && state.measured_setup.is_none()
        && state.measured_static_credential.is_none() && state.measured_static_credential_rotation.is_none()
        && state.measured_reconnect.is_none() && state.measured_succession.is_none()
        && state.measured_audit.is_none() && !state.credential_currentness.enabled()
        && state.credential_lease_recipient_attestation_command.is_none()
        && state.response_observation_v2_client.is_none()
}

fn endpoint(lease: Option<&str>) -> Result<Url, ()> {
    let mut url = Url::parse(lease.ok_or(())?).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some()
        || url.path() != "/api/data-plane/credential-leases" { return Err(()); }
    url.set_path(INTERNAL_PATH);
    Ok(url)
}

pub(super) fn capability(state: &GateState) -> Value {
    if !ordinary(state) || endpoint(state.credential_lease_url.as_deref()).is_err() {
        return Value::Null;
    }
    json!({"schema":"catchplate.proxyTokenRenewal/v1", "path":PATH,
        "overlap_seconds":300, "max_request_bytes":MAX_REQUEST, "max_response_bytes":MAX_RESPONSE})
}

pub(super) fn reserved(target: &str) -> bool {
    // Absolute-form and query variants are reserved too, but never admitted.
    target.split(['?', '#']).next() == Some(PATH)
        || Url::parse(target).is_ok_and(|url| url.path() == PATH)
}

fn admit(head: &RequestHead) -> Result<(), StatusCode> {
    if head.method != "POST" || head.target != PATH { return Err(StatusCode::BAD_REQUEST); }
    if CREDENTIAL_HEADERS.iter().any(|name| head.headers.contains_key(*name)) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if head.headers.get("content-type").map(String::as_str) != Some("application/json")
        || head.headers.contains_key("content-encoding") || head.headers.contains_key("transfer-encoding")
        || !head.has_content_length
        || head.headers.get("content-length") != Some(&head.content_length.to_string()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if head.content_length == 0 || head.content_length > MAX_REQUEST {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(())
}

fn closed_request(raw: &[u8]) -> bool {
    const STRINGS: &[&str] = &["schema", "audience", "application_id", "enrollment_id",
        "operation_id", "token_sha256", "signature"];
    const INTEGERS: &[&str] = &["expected_token_generation", "issued_at_epoch_ms",
        "expires_at_epoch_ms", "token_expires_at_epoch_ms"];
    let Ok(value) = sensitive_json_value_from_slice(raw) else { return false; };
    let Some(object) = value.as_object() else { return false; };
    object.len() == STRINGS.len() + INTEGERS.len()
        && STRINGS.iter().all(|key| object.get(*key).and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty() && text.len() <= 512))
        && INTEGERS.iter().all(|key| object.get(*key).and_then(Value::as_u64)
            .is_some_and(|number| number > 0 && number <= 9_007_199_254_740_991))
        && object.get("schema").and_then(Value::as_str) == Some("catchplate.workloadTokenRenewal/v1")
}

struct Slot;
impl Slot {
    fn acquire() -> Option<Self> {
        ACTIVE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |active| (active < 4).then_some(active + 1)).ok().map(|_| Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) { ACTIVE.fetch_sub(1, Ordering::AcqRel); }
}

fn response(status: StatusCode, body: Vec<u8>) -> Vec<u8> {
    http_binary_response_with_headers(status, Some("application/json"), body,
        &[("Cache-Control".to_owned(), "no-store".to_owned()),
          ("Pragma".to_owned(), "no-cache".to_owned()),
          ("X-Content-Type-Options".to_owned(), "nosniff".to_owned())])
}

fn refusal(status: StatusCode) -> Vec<u8> {
    response(status, br#"{"error":"workload_renewal_refused"}"#.to_vec())
}

fn forward(state: &GateState, raw: &[u8], deadline: Instant) -> Result<Vec<u8>, ()> {
    let url = endpoint(state.credential_lease_url.as_deref())?;
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    // No inherited proxy, redirect, credentials, automatic retry or caller
    // URL. Even an unknown committed outcome is returned without resending.
    let client = control_plane_client_builder(remaining).map_err(|_| ())?
        .no_proxy().redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never()).http1_only().build().map_err(|_| ())?;
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let mut reply = client.post(url).header("content-type", "application/json")
        .body(raw.to_vec()).timeout(remaining).send().map_err(|_| ())?;
    let status = reply.status();
    if status != StatusCode::OK {
        return Ok(refusal(match status.as_u16() {
            400 | 401 | 404 | 408 | 409 | 413 | 422 | 429 => status,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }));
    }
    if reply.headers().get_all("content-type").iter().count() != 1
        || reply.headers().get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
        || reply.headers().contains_key("content-encoding")
        || reply.content_length().is_some_and(|length| length > MAX_RESPONSE as u64) {
        return Err(());
    }
    let mut body = Zeroizing::new(Vec::new());
    Read::take(&mut reply, (MAX_RESPONSE + 1) as u64).read_to_end(&mut body).map_err(|_| ())?;
    if body.len() > MAX_RESPONSE || Instant::now() >= deadline { return Err(()); }
    let value = sensitive_json_value_from_slice(&body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.len() != 4 || !["operation", "application", "policy"].iter()
        .all(|key| object.get(*key).is_some_and(Value::is_object))
        || object.get("revision").and_then(Value::as_u64).is_none() { return Err(()); }
    Ok(response(status, body.to_vec()))
}

pub(super) fn handle(state: &GateState, head: RequestHead, stream: &mut DirectProxyStream,
        management: bool, ingress: &ProxyIngressConfig) {
    let deadline = Instant::now() + Duration::from_secs(15);
    stream.restrict_operation_deadline(deadline);
    stream.reset_read_deadline(Duration::from_secs(5));
    stream.set_terminal_write_deadline(Some(deadline));
    let result = (|| {
        if management || !matches!(ingress, ProxyIngressConfig::OperatorDemoTlsEdge) || !ordinary(state) {
            return refusal(StatusCode::FORBIDDEN);
        }
        if let Err(status) = admit(&head) { return refusal(status); }
        let Some(_slot) = Slot::acquire() else { return refusal(StatusCode::TOO_MANY_REQUESTS); };
        let request = match read_request_body_from_head(stream, head, MAX_REQUEST as u64) {
            Ok(request) => request,
            Err(_) => return refusal(StatusCode::BAD_REQUEST),
        };
        if !closed_request(&request.body) { return refusal(StatusCode::UNPROCESSABLE_ENTITY); }
        // No publication read lock is held across this call: the store owns
        // its transactional update and exclusive signed-policy publication.
        forward(state, &request.body, deadline).unwrap_or_else(|_| refusal(StatusCode::SERVICE_UNAVAILABLE))
    })();
    let _ = stream.write_all(&result);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    const WAIT: Duration = Duration::from_secs(2);

    // Real fixed-origin HTTP only. This fixture does not assert production
    // profile, enrolled-key issuance, SQLite or public TLS-edge acceptance.
    struct Receiver {
        lease_url: String,
        stop: mpsc::Sender<()>,
        thread: Option<thread::JoinHandle<usize>>,
    }

    impl Receiver {
        fn start(expected: &[u8], reply: impl FnOnce(&str) -> Option<Vec<u8>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let lease_url = format!("{origin}/api/data-plane/credential-leases");
            let reply = reply(&origin);
            let expected = expected.to_vec();
            let (stop, stopped) = mpsc::channel();
            let thread = thread::spawn(move || {
                let mut attempts = 0;
                let deadline = Instant::now() + Duration::from_secs(4);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            attempts += 1;
                            assert!(attempts <= 2, "bounded loopback request count");
                            assert!(peer.ip().is_loopback());
                            stream.set_nonblocking(false).unwrap();
                            stream.set_read_timeout(Some(WAIT)).unwrap();
                            stream.set_write_timeout(Some(WAIT)).unwrap();
                            let head = read_request_head_from(&mut stream, None).unwrap();
                            let request = read_request_body_from_head(&mut stream, head, MAX_REQUEST as u64).unwrap();
                            assert_eq!(request.method, "POST");
                            assert_eq!(request.target, INTERNAL_PATH);
                            assert_eq!(request.body, expected, "forward the exact original bytes");
                            assert_eq!(request.headers.get("content-type").map(String::as_str), Some("application/json"));
                            assert!(CREDENTIAL_HEADERS.iter().all(|name| !request.headers.contains_key(*name)));
                            if let Some(reply) = &reply {
                                // Oversized/header-refused responses may be closed before
                                // the receiver finishes writing. The caller asserts result.
                                let _ = stream.write_all(reply);
                            }
                            // None deliberately loses the acknowledgement after receiving
                            // the complete operation. It must not trigger another POST.
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            match stopped.recv_timeout(Duration::from_millis(5)) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                Err(mpsc::RecvTimeoutError::Timeout) => {}
                            }
                        }
                        Err(error) => panic!("bounded renewal loopback accept: {error}"),
                    }
                }
                attempts
            });
            Self { lease_url, stop, thread: Some(thread) }
        }

        fn state(&self) -> GateState {
            let mut state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
            state.credential_lease_url = Some(self.lease_url.clone());
            state.credential_lease_token = Some("synthetic-service-token-must-not-forward".into());
            state.audit_token = Some("synthetic-audit-token-must-not-forward".into());
            state.management_token = Some("synthetic-admin-token-must-not-forward".into());
            state
        }

        fn finish(mut self) -> usize {
            let _ = self.stop.send(());
            self.thread.take().unwrap().join().unwrap()
        }
    }

    impl Drop for Receiver {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        }
    }

    fn request_bytes() -> Vec<u8> {
        // Whitespace is intentional: forwarding must not reserialize a proof.
        format!(" \n{}\n", json!({"schema":"catchplate.workloadTokenRenewal/v1",
            "audience":"https://proxy.example.com/v1/workload/renew",
            "application_id":"12345678-1234-4234-8234-123456789abc",
            "enrollment_id":"22345678-1234-4234-8234-123456789abc",
            "operation_id":"32345678-1234-4234-8234-123456789abc",
            "token_sha256":format!("sha256:{}", "4".repeat(64)), "signature":"5".repeat(128),
            "expected_token_generation":1, "issued_at_epoch_ms":1800000000000u64,
            "expires_at_epoch_ms":1800000060000u64, "token_expires_at_epoch_ms":1800003600000u64})).into_bytes()
    }

    fn reply_bytes(status: &str, body: &[u8], extra: &str) -> Vec<u8> {
        let mut result = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", body.len()).into_bytes();
        result.extend_from_slice(body);
        result
    }

    fn valid_reply() -> Vec<u8> {
        br#"{"operation":{"operation_id":"synthetic"},"application":{"id":"synthetic"},"revision":2,"policy":{"activation":"pending"}}"#.to_vec()
    }

    #[test]
    fn loopback_exact_post_and_bounded_public_reply() {
        let raw = request_bytes();
        assert!(closed_request(&raw));
        let body = valid_reply();
        let receiver = Receiver::start(&raw, |_| Some(reply_bytes("200 OK", &body, "")));
        let response = forward(&receiver.state(), &raw, Instant::now() + WAIT).unwrap();
        assert_eq!(receiver.finish(), 1);
        let parsed = parse_buffered_response(&response).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, body);
        assert!(parsed.body.len() <= MAX_RESPONSE);
        assert_eq!(parsed.headers.get("cache-control").map(|v| v.as_str()), Some("no-store"));
    }

    #[test]
    fn loopback_error_status_is_sanitized_without_retry() {
        let raw = request_bytes();
        for (status, expected) in [("401 Unauthorized", 401), ("409 Conflict", 409), ("500 Internal Server Error", 503)] {
            let receiver = Receiver::start(&raw, |_| Some(reply_bytes(status, b"private-backend-error-canary", "")));
            let response = forward(&receiver.state(), &raw, Instant::now() + WAIT).unwrap();
            assert_eq!(receiver.finish(), 1);
            let parsed = parse_buffered_response(&response).unwrap();
            assert_eq!(parsed.status, expected);
            assert_eq!(parsed.body, br#"{"error":"workload_renewal_refused"}"#);
        }
    }

    #[test]
    fn loopback_redirects_are_not_followed() {
        let raw = request_bytes();
        for status in ["302 Found", "307 Temporary Redirect", "308 Permanent Redirect"] {
            let receiver = Receiver::start(&raw, |origin| Some(reply_bytes(status, b"", &format!("Location: {origin}/must-not-follow\r\n"))));
            let response = forward(&receiver.state(), &raw, Instant::now() + WAIT).unwrap();
            assert_eq!(receiver.finish(), 1);
            assert_eq!(parse_buffered_response(&response).unwrap().status, 503);
        }
    }

    #[test]
    fn loopback_oversized_malformed_and_ambiguous_replies_refuse() {
        let raw = request_bytes();
        let valid = valid_reply();
        let mut cases = vec![reply_bytes("200 OK", &vec![b'x'; MAX_RESPONSE + 1], ""),
            reply_bytes("200 OK", b"{", ""), reply_bytes("200 OK", b"{}", ""),
            reply_bytes("200 OK", &valid, "Content-Type: application/json\r\n"),
            reply_bytes("200 OK", &valid, "Content-Encoding: identity\r\n")];
        let duplicate = format!("{{\"revision\":9,{}", std::str::from_utf8(&valid).unwrap().trim_start_matches('{'));
        cases.push(reply_bytes("200 OK", duplicate.as_bytes(), ""));
        // No declared length: the actual stream cap, not only a header check,
        // must refuse a close-delimited oversized response.
        let mut streamed = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".to_vec();
        streamed.extend(vec![b'x'; MAX_RESPONSE + 1]);
        cases.push(streamed);
        for reply in cases {
            let receiver = Receiver::start(&raw, |_| Some(reply));
            let result = forward(&receiver.state(), &raw, Instant::now() + WAIT);
            assert_eq!(receiver.finish(), 1);
            assert!(result.is_err());
        }
    }

    #[test]
    fn loopback_lost_acknowledgement_has_exactly_one_attempt() {
        let raw = request_bytes();
        let receiver = Receiver::start(&raw, |_| None);
        let result = forward(&receiver.state(), &raw, Instant::now() + WAIT);
        assert_eq!(receiver.finish(), 1);
        assert!(result.is_err(), "unknown outcome cannot be success or retry");
    }

    #[test]
    fn loopback_expired_original_deadline_makes_no_contact() {
        let raw = request_bytes();
        let receiver = Receiver::start(&raw, |_| Some(reply_bytes("200 OK", &valid_reply(), "")));
        let result = forward(&receiver.state(), &raw, Instant::now() - Duration::from_millis(1));
        assert!(result.is_err());
        assert_eq!(receiver.finish(), 0);
    }

    #[test]
    fn fixed_target_and_endpoint() {
        for target in [PATH.to_owned(), format!("{PATH}?x=1"), format!("https://example.com{PATH}")] {
            assert!(reserved(&target));
        }
        assert!(!reserved("/v1/workload/other"));
        assert_eq!(endpoint(Some("http://catchplate:3000/api/data-plane/credential-leases")).unwrap().as_str(),
            "http://catchplate:3000/api/operator-demo/workloads/renew");
        for url in ["http://user@catchplate/api/data-plane/credential-leases",
            "http://catchplate/api/data-plane/credential-leases?x=1", "http://catchplate/other",
            "file:///api/data-plane/credential-leases"] { assert!(endpoint(Some(url)).is_err()); }
    }

    #[test]
    fn exact_request_rejects_duplicate_extra_nested_and_wrong_scalar() {
        let value = json!({"schema":"catchplate.workloadTokenRenewal/v1", "audience":"https://example.com",
            "application_id":"app", "enrollment_id":"grant", "operation_id":"op", "token_sha256":"digest",
            "signature":"proof", "expected_token_generation":1, "issued_at_epoch_ms":1,
            "expires_at_epoch_ms":2, "token_expires_at_epoch_ms":3});
        let raw = serde_json::to_vec(&value).unwrap();
        assert!(closed_request(&raw));
        let mut changed = value.clone(); changed["extra"] = json!(1);
        assert!(!closed_request(&serde_json::to_vec(&changed).unwrap()));
        changed = value.clone(); changed["expected_token_generation"] = json!(true);
        assert!(!closed_request(&serde_json::to_vec(&changed).unwrap()));
        changed = value.clone(); changed["audience"] = json!({"nested":1});
        assert!(!closed_request(&serde_json::to_vec(&changed).unwrap()));
        let duplicate = format!("{{\"schema\":\"bad\",{}", std::str::from_utf8(&raw).unwrap().trim_start_matches('{'));
        assert!(!closed_request(duplicate.as_bytes()));
    }

    #[test]
    fn admission_reserves_method_query_and_credentials() {
        fn head(method: &str, path: &str, extra: &str) -> RequestHead {
            let raw = format!("{method} {path} HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Type: application/json\r\nContent-Length: 1\r\n{extra}\r\n");
            read_request_head_from(&mut Cursor::new(raw.into_bytes()), None).unwrap()
        }
        assert!(admit(&head("POST", PATH, "")).is_ok());
        for method in ["GET", "PUT", "DELETE", "OPTIONS"] { assert!(admit(&head(method, PATH, "")).is_err()); }
        assert!(admit(&head("POST", &format!("{PATH}?x=1"), "")).is_err());
        for name in CREDENTIAL_HEADERS {
            assert_eq!(admit(&head("POST", PATH, &format!("{name}: inert\r\n"))), Err(StatusCode::UNAUTHORIZED));
        }
    }
}
