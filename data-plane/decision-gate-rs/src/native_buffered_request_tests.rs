//! Real synthetic TLS/projection controls, NOT native quote/custody admission.
use super::*;
use crate::tests::{test_gate_state, test_snapshot};
use rustls::ClientConnection;

fn tls_pair() -> (ClientConnection, ServerConnection, Arc<ProxyIngressTlsConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["outer.example".to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let server_config = Arc::new(ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots.clone())).build().unwrap())
        .with_single_cert(vec![server_cert.der().clone(), ca.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(server_key.serialize_der()))).unwrap());
    let client_config = rustls::ClientConfig::builder().with_root_certificates(roots)
        .with_client_auth_cert(vec![client_cert.der().clone(), ca.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(client_key.serialize_der()))).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config),
        rustls::pki_types::ServerName::try_from("outer.example").unwrap()).unwrap();
    let mut outer = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    // Complete genuine rustls mutual authentication in memory, with no provider.
    for _ in 0..8 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() { outer.read_tls(&mut io::Cursor::new(bytes)).unwrap(); outer.process_new_packets().unwrap(); }
        let mut bytes = Vec::new();
        outer.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() { client.read_tls(&mut io::Cursor::new(bytes)).unwrap(); client.process_new_packets().unwrap(); }
        if !outer.is_handshaking() && !client.is_handshaking() { break; }
    }
    assert!(!outer.is_handshaking() && !client.is_handshaking());
    assert!(outer.peer_certificates().is_some());
    let configuration = Arc::new(ProxyIngressTlsConfig {
        server_config: Arc::clone(&server_config),
        client_trust_certificates: Arc::new(vec![ca.der().clone()]),
        client_trust_bundle_original: None, workload_identity_trust: None,
        native_owner: None, // Deliberately cannot claim genuine native admission.
    });
    (client, outer, configuration)
}

fn deliver_plaintext(client: &mut ClientConnection, server: &mut ServerConnection,
    plaintext: &[u8], close_notify: bool) {
    client.writer().write_all(plaintext).unwrap();
    if close_notify { client.send_close_notify(); }
    let mut records = Vec::new();
    while client.wants_write() { assert!(client.write_tls(&mut records).unwrap() > 0); }
    if !records.is_empty() {
        let mut records = io::Cursor::new(records);
        while records.position() < records.get_ref().len() as u64 {
            assert!(server.read_tls(&mut records).unwrap() > 0);
            server.process_new_packets().unwrap();
        }
    }
}

fn imported_transport(plaintext: &[u8], close_notify: bool)
    -> (RetainedProxyIngressTls, ClientConnection, TcpStream) {
    let (mut client, mut outer, configuration) = tls_pair();
    deliver_plaintext(&mut client, &mut outer, plaintext, close_notify);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(1)).unwrap();
    let (socket, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    let outer = RetainedProxyIngressTls {
        connection: RetainedProxyIngressConnection::Imported(outer),
        sock: DeadlineIo::new(GateSocket::Tcp(socket),
            Duration::from_secs(1), Duration::from_secs(1)),
        configuration,
    };
    (outer, client, peer)
}

fn transport() -> (StreamOwned<ServerConnection, DirectProxyStream>, Arc<ProxyIngressTlsConfig>) {
    let (outer, _, peer) = imported_transport(b"", false);
    drop(peer); // Original projection fixtures do no socket I/O.
    let configuration = Arc::clone(&outer.configuration);
    let inner = ServerConnection::new(Arc::clone(&configuration.server_config)).unwrap();
    (StreamOwned::new(inner, DirectProxyStream::MutualTls(outer)), configuration)
}

fn authentication(snapshot: &Snapshot, tls: &RetainedProxyIngressTls) -> ConnectAuthentication {
    let evidence = trusted_mtls_evidence_from_verified_peer(tls.connection().peer_certificates().unwrap(),
        &tls.configuration.client_trust_certificates).unwrap();
    ConnectAuthentication::capture_with_mtls(snapshot, "agent:test", None, &BTreeMap::new(), Some(&evidence)).unwrap()
}

fn request() -> IncomingRequest {
    IncomingRequest { method: "POST".to_owned(), target: "https://example.test/resource".to_owned(),
        headers: BTreeMap::from([("x-identity".to_owned(), "private-value".to_owned()),
            ("x-discard".to_owned(), "discard-me".to_owned()),
            ("content-encoding".to_owned(), "identity".to_owned())]),
        body: b"{}".to_vec(), client_ip: None }
}

#[test]
fn retains_actual_outer_tls_and_ends_borrow_before_writer_reuse() {
    let (mut tls, configuration) = transport();
    let snapshot = test_snapshot(1);
    let inner = &tls.conn as *const ServerConnection;
    let mut writer = ConnectOperationIo(&mut tls);
    let auth = authentication(&snapshot, writer.retained_proxy_ingress().unwrap());
    let context = Context { authentication: &auth, deadline: Instant::now() + Duration::from_secs(30) };
    let request = request();
    {
        let ingress = Ingress::FromWriter(&context);
        let (held_context, outer) = ingress.originals(Some(&writer));
        let outer = outer.unwrap();
        assert_ne!(outer.connection() as *const ServerConnection, inner);
        assert!(Arc::ptr_eq(&outer.configuration, &configuration));
        assert_eq!(outer.connection().protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        assert!(outer.native_connection().is_none());
        let original = BorrowedRequest::retain(held_context, outer, &request, &snapshot, None);
        assert!(std::ptr::eq(original.request, &request));
        assert!(std::ptr::eq(original.context.authentication, &auth));
        assert!(Arc::ptr_eq(original.snapshot, &snapshot));
        assert!(original.check(&test_gate_state(Arc::clone(&snapshot)), &snapshot, "agent:test").is_err());
        let proof_ingress = Ingress::Borrowed(&context, Some(outer));
        assert!(std::ptr::eq(proof_ingress.originals(None).1.unwrap(), outer));
    }
    writer.set_terminal_write_deadline(Some(Instant::now() + Duration::from_secs(1)));
    assert!(writer.retained_proxy_ingress().unwrap().sock.operation_deadline.is_none());
    let plain = DeadlineIo::new(io::Cursor::new(Vec::<u8>::new()), Duration::from_secs(1), Duration::from_secs(1));
    assert!(plain.retained_proxy_ingress().is_none());
}

#[test]
fn real_header_stripping_and_enrichment_retain_exact_final_projection() {
    let (mut tls, _) = transport();
    let snapshot = test_snapshot(1);
    let writer = ConnectOperationIo(&mut tls);
    let outer = writer.retained_proxy_ingress().unwrap();
    let auth = authentication(&snapshot, outer);
    let context = Context { authentication: &auth, deadline: Instant::now() + Duration::from_secs(30) };
    let original_request = request();
    let original = BorrowedRequest::retain(&context, outer, &original_request, &snapshot, None);
    let mut decision = buffered_forward_decision_request(&original_request, None);
    let pipeline = original.begin(&decision).unwrap();
    let mut principal = snapshot.principals[0].clone();
    principal.required_headers.insert("x-identity".to_owned(), "private-value".to_owned());
    let stripped = strip_principal_required_headers(&decision.headers, &principal);
    replace_string_map(&mut decision.headers, stripped);
    let retained = discard_declared_request_headers(&decision.headers, &["x-discard".to_owned()]).unwrap();
    replace_string_map(&mut decision.headers, retained);
    let encoded = admitted_request_encoding_headers(&decision, &decision.headers).unwrap();
    replace_string_map(&mut decision.headers, encoded);
    decision.credential_metadata.insert("credential:test".to_owned(), BTreeMap::from([("generation".to_owned(), json!(2))]));
    decision.gmail_proofs.push(SensitiveString::new("retained-proof-fixture".to_owned()));
    assert!(!decision.headers.contains_key("x-identity") && !decision.headers.contains_key("x-discard"));
    let canonical = json!({"request":{"body_sha256":body_sha_bytes(&original_request.body)}});
    let release = pipeline.retain_release(&decision, &snapshot.routes[0], &canonical).unwrap();
    assert!(release.check_projection(&decision, &snapshot.routes[0], &canonical).is_ok());
    assert!(std::ptr::eq(release.request, &decision));
    assert_eq!(release.request.credential_metadata["credential:test"]["generation"], 2);
    assert_eq!(release.request.gmail_proofs[0].as_str(), "retained-proof-fixture");
    assert!(release.check_projection(&decision.clone(), &snapshot.routes[0], &canonical).is_err());
    assert!(release.check_projection(&decision, &snapshot.routes[0].clone(), &canonical).is_err());
    assert!(release.check_projection(&decision, &snapshot.routes[0], &canonical.clone()).is_err());
}

#[test]
fn original_projection_and_stable_fields_refuse_substitution() {
    let (mut tls, _) = transport();
    let snapshot = test_snapshot(1);
    let writer = ConnectOperationIo(&mut tls);
    let outer = writer.retained_proxy_ingress().unwrap();
    let auth = authentication(&snapshot, outer);
    let context = Context { authentication: &auth, deadline: Instant::now() + Duration::from_secs(30) };
    let request = request();
    let original = BorrowedRequest::retain(&context, outer, &request, &snapshot, None);
    let initial = buffered_forward_decision_request(&request, None);
    for field in 0..8 {
        let mut changed = initial.clone();
        match field {
            0 => { changed.headers.clear(); },
            1 => { changed.body.push('x'); },
            2 => { changed.method = "GET".to_owned(); },
            3 => { changed.url.push_str("?other=1"); },
            4 => { changed.client_ip = Some("127.0.0.2".to_owned()); },
            5 => { changed.body_sha256 = Some(sha256_prefixed(b"other")); },
            6 => { changed.credential_metadata.insert("other".to_owned(), BTreeMap::new()); },
            _ => { changed.client_request_digest = Some(sha256_prefixed(b"other")); },
        }
        assert!(original.begin(&changed).is_err());
    }
    let pipeline = original.begin(&initial).unwrap();
    let mut changed = initial.clone();
    changed.body.push('x');
    assert!(pipeline.retain_release(&changed, &snapshot.routes[0], &Value::Null).is_err());
}

#[test]
fn compressed_body_owner_must_retain_the_exact_original_wire() {
    fn gzip(mtime: u32) -> Vec<u8> {
        let mut encoder = flate2::GzBuilder::new().mtime(mtime)
            .write(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"{\"fixture-package\":[\"1.0.0\"]}").unwrap();
        encoder.finish().unwrap()
    }
    let (mut tls, _) = transport();
    let snapshot = test_snapshot(1);
    let writer = ConnectOperationIo(&mut tls);
    let outer = writer.retained_proxy_ingress().unwrap();
    let auth = authentication(&snapshot, outer);
    let context = Context { authentication: &auth, deadline: Instant::now() + Duration::from_secs(30) };
    let mut request = request();
    request.headers.insert("content-encoding".to_owned(), "gzip".to_owned());
    request.body = gzip(1);
    let original = BorrowedRequest::retain(&context, outer, &request, &snapshot, None);
    let mut decision = buffered_forward_decision_request(&request, None);
    let body = npm_install::AuditBody::from_wire(&request.body).unwrap();
    decision.body = body.decoded_text().to_owned();
    decision.npm_install_audit_body = Some(body);
    assert!(original.begin(&decision).is_ok());
    let alternate = gzip(2);
    assert_ne!(alternate, request.body);
    let swapped = npm_install::AuditBody::from_wire(&alternate).unwrap();
    assert_eq!(swapped.decoded_text(), decision.body);
    decision.npm_install_audit_body = Some(swapped);
    assert!(original.begin(&decision).is_err());
}

#[test]
fn request_clock_clips_original_caps_without_shortening_later_keepalive_requests() {
    let opening = Instant::now();
    let first = request_deadline(opening, Duration::from_secs(90), None).unwrap();
    assert_eq!(first, opening + Duration::from_secs(30));
    assert_eq!(request_deadline(opening, Duration::from_secs(3), None).unwrap(), opening + Duration::from_secs(3));
    let connection = opening + Duration::from_secs(20);
    assert_eq!(request_deadline(opening, Duration::from_secs(90), Some(connection)).unwrap(), connection);
    let later = opening + Duration::from_secs(10);
    assert_eq!(request_deadline(later, Duration::from_secs(90), None).unwrap(), later + Duration::from_secs(30));
    assert_eq!(request_deadline(later, Duration::from_secs(90), Some(connection)).unwrap(), connection);
    let elapsed = opening.checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(request_deadline(opening, Duration::from_secs(90), Some(elapsed)).unwrap(), elapsed);
    assert!(custody_deadline_remaining(elapsed, "test original deadline").is_err());
    let (mut tls, _) = transport();
    let snapshot = test_snapshot(1);
    let auth = authentication(&snapshot, ConnectOperationIo(&mut tls).retained_proxy_ingress().unwrap());
    let state = test_gate_state(snapshot);
    assert!(Context::open(&state, &tls.sock, &auth).unwrap().is_none());
    tls.sock.restrict_operation_deadline(connection);
    tls.sock.reset_read_deadline(Duration::from_secs(90));
    tls.sock.reset_write_deadline(Duration::from_secs(90));
    let DirectProxyStream::MutualTls(outer) = &tls.sock else { panic!("outer TLS absent"); };
    assert_eq!(outer.sock.operation_deadline, Some(connection));
    assert_eq!(first, opening + Duration::from_secs(30));
}

#[test]
fn native_jit_missing_context_refuses_while_legacy_and_nonjit_keep_their_boundary() {
    let snapshot = test_snapshot(1);
    let state = test_gate_state(Arc::clone(&snapshot));
    let request = buffered_forward_decision_request(&request(), None);
    for profile in [ReleaseProfile::Legacy, ReleaseProfile::PolicyAware, ReleaseProfile::Native] {
        assert!(check_release(profile, false, None, &state, &snapshot, "agent:test",
            &request, &snapshot.routes[0], &Value::Null).is_ok());
        assert_eq!(check_release(profile, true, None, &state, &snapshot, "agent:test",
            &request, &snapshot.routes[0], &Value::Null).is_err(), profile.is_native());
    }
}

#[test]
fn actual_connect_entry_and_release_io_keep_originals_and_account_attempts() {
    // Supplemental integration source guard; the typed TLS/projection controls
    // above do not claim native hardware, caller-purpose or sealing admission.
    let source = include_str!("main.rs");
    let connect = source.split_once("fn handle_connect_request(").unwrap().1
        .split_once("\nfn health_response(").unwrap().0;
    assert!(connect.find("native_buffered_request::Context::open(").unwrap()
        < connect.find("read_request_head_with_intake_from(").unwrap());
    assert!(connect.contains("native_request_context.as_ref()"));
    let decision = source.split_once("fn decide_internal_with_mode_and_shadow_and_google<'a>(").unwrap().1
        .split_once("\nfn http_response(").unwrap().0;
    assert!(decision.find("original.begin(&req)").unwrap() < decision.find("let mut req = req;").unwrap());
    assert!(decision.contains("if preview || !state.response_proof_signer.release_profile().is_native()"));
    assert!(decision.contains("streaming_response_policy(&response_policy_for_route(route)).is_some()"));
    let reserve = source.split_once("fn request_release_authorization_with_connect<'a>(").unwrap().1
        .split_once("\nfn validate_requested_release_authorization(").unwrap().0;
    assert!(reserve.find("native_buffered_request::check_release(").unwrap()
        < reserve.find("prepare_release_policy(").unwrap());
    let send = reserve.find("let response_result = post_release_authorization_http_on_deadline(").unwrap();
    let accounted = reserve[send..].find("commit_shadow_release_effects(").unwrap() + send;
    let final_check = reserve.rfind("native_buffered_request::check_release(").unwrap();
    assert!(send < accounted && accounted < final_check);
    assert!(reserve.contains("original.deadline().min(fallback)"));
}

#[test]
fn imported_tls_preserves_buffered_http_flush_and_authenticated_close() {
    let wire = b"POST /resource HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\n{}";
    let (mut outer, client, peer) = imported_transport(wire, false);
    assert!(outer.native_connection().is_none());
    let head = read_request_head_from(&mut outer, None).unwrap();
    assert_eq!(head.prefetched_body, b"{}");
    let request = read_request_body_from_head(&mut outer, head, 2).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/resource");
    assert_eq!(request.body, b"{}");
    // Decrypted data and the nonblocking prefetch check do not read the socket.
    assert!(outer.sock.read_started.is_none());
    assert_eq!(outer.read_plaintext(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(outer.sock.read_started.is_none());
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    for fragment in reply.chunks(3) { outer.write_all(fragment).unwrap(); }
    outer.flush().unwrap();
    outer.send_close_notify().unwrap();
    outer.flush().unwrap();
    let mut remote = StreamOwned::new(client, peer);
    let mut received = Vec::new();
    remote.read_to_end(&mut received).unwrap();
    assert_eq!(received, reply);
    // Authenticated TLS EOF, not a raw socket drop, terminated read_to_end.
    assert_eq!(remote.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn original_deadline_blocks_outer_and_inner_buffered_plaintext_without_consuming_it() {
    let elapsed = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    let later = Instant::now() + Duration::from_secs(30);
    let (outer, _, _peer) = imported_transport(b"outer retained", false);
    let mut direct = DirectProxyStream::MutualTls(outer);
    direct.restrict_operation_deadline(elapsed);
    direct.restrict_operation_deadline(later);
    direct.reset_read_deadline(Duration::from_secs(90));
    direct.reset_write_deadline(Duration::from_secs(90));
    direct.set_terminal_write_deadline(None);
    let mut buffer = [0xa5; 32];
    assert_eq!(direct.read(&mut buffer).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(direct.write(b"not sent").unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(direct.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(buffer, [0xa5; 32]);
    let DirectProxyStream::MutualTls(outer) = &mut direct else { panic!("outer TLS absent"); };
    assert_eq!(outer.sock.operation_deadline, Some(elapsed));
    assert!(outer.sock.read_started.is_none() && outer.sock.write_started.is_none());
    // Inspect the test's IMPORTED connection only: the real guard above must
    // leave already decrypted data untouched, not manufacture an EOF.
    let RetainedProxyIngressConnection::Imported(connection) = &mut outer.connection
        else { panic!("synthetic fixture acquired a native owner"); };
    let read = connection.reader().read(&mut buffer).unwrap();
    assert_eq!(&buffer[..read], b"outer retained");

    let (mut client, mut inner, _) = tls_pair();
    deliver_plaintext(&mut client, &mut inner, b"inner retained", false);
    let (outer, _, _peer) = imported_transport(b"", false);
    let mut nested = StreamOwned::new(inner, DirectProxyStream::MutualTls(outer));
    nested.sock.restrict_operation_deadline(elapsed);
    nested.sock.reset_read_deadline(Duration::from_secs(90));
    nested.sock.reset_write_deadline(Duration::from_secs(90));
    let mut writer = ConnectOperationIo(&mut nested);
    writer.set_terminal_write_deadline(None);
    assert_eq!(writer.read(&mut buffer).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(writer.write(b"not sent").unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    let read = nested.conn.reader().read(&mut buffer).unwrap();
    assert_eq!(&buffer[..read], b"inner retained");
}

#[test]
fn continuation_checks_actual_prefetch_and_authenticated_eof_without_native_admission() {
    fn head(extra: &[u8]) -> RequestHead {
        let mut wire = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n".to_vec();
        wire.extend_from_slice(extra);
        wire.extend_from_slice(b"\r\n");
        read_request_head_from(&mut io::Cursor::new(wire), None).unwrap()
    }
    let (outer, _, _peer) = imported_transport(b"", false);
    let mut stream = DirectProxyStream::MutualTls(outer);
    // This is only the existing parsed-head/prefetch check. No quote, native
    // configuration or successful attestation/continuation is constructed.
    assert!(native_ingress_attestation::continuation_head_valid(&head(b""), &mut stream));
    for extra in [
        b"x-catchplate-ingress-continuation: connect-v1\r\n".as_slice(),
        b"x-catchplate-ingress-challenge: unwanted\r\n".as_slice(),
        b"x-catchplate-ingress-evidence: client-trust-v2\r\n".as_slice(),
        b"Content-Length: 1\r\n".as_slice(),
    ] {
        assert!(!native_ingress_attestation::continuation_head_valid(&head(extra), &mut stream));
    }
    let wire = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nprefetched";
    let prefetched = read_request_head_from(&mut io::Cursor::new(wire), None).unwrap();
    assert_eq!(prefetched.prefetched_body, b"prefetched");
    assert!(!native_ingress_attestation::continuation_head_valid(&prefetched, &mut stream));
    let DirectProxyStream::MutualTls(outer) = &stream else { panic!("outer TLS absent"); };
    assert!(outer.sock.read_started.is_none());

    let (outer, _, _peer) = imported_transport(b"prefetched", false);
    let mut stream = DirectProxyStream::MutualTls(outer);
    assert!(!native_ingress_attestation::continuation_head_valid(&head(b""), &mut stream));
    let DirectProxyStream::MutualTls(outer) = &mut stream else { panic!("outer TLS absent"); };
    let mut remaining = [0; 16];
    let count = outer.read_plaintext(&mut remaining).unwrap();
    assert_eq!(&remaining[..count], b"refetched");
    assert!(outer.sock.read_started.is_none());

    let (outer, _, _peer) = imported_transport(b"", true);
    let mut stream = DirectProxyStream::MutualTls(outer);
    assert!(!native_ingress_attestation::continuation_head_valid(&head(b""), &mut stream));
}
