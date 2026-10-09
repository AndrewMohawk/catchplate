//! V2 parsed-header and actual release-path controls. Loopback only; no provider
//! or claim that the HTTP library exposes every physical wire byte.
use super::*;
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use std::net::TcpListener;
use std::thread;

fn profile() -> Value {
    json!({"mode":buffered_response::JSON_OR_EMPTY_204_V2_MODE,"bodyFormat":"json",
        "maxBodyBytes":65536,"contentTypes":["application/json"],"allowedHeaders":[],
        "error":{"mode":buffered_response::JSON_OR_EMPTY_204_V2_MODE,"bodyFormat":"json",
            "maxBodyBytes":65536,"contentTypes":["application/json"],"allowedHeaders":[],"onInvalid":"block"}})
}

fn envelope() -> Value {
    json!({"id":"metadata-response","type":"responseEnvelope","phase":"response",
        "statusCodes":[200,204,400,500],"bodyPresence":"jsonOrEmpty204V1",
        "unlistedHeaderPolicy":"discardUnselectedV1","contentTypes":["application/json"],
        "allowedResponseHeaderNames":[],"responseHeaderRules":[]})
}

fn listed_etag(envelope: &mut Value, required: bool) {
    envelope["allowedResponseHeaderNames"] = json!(["etag"]);
    envelope["responseHeaderRules"] = json!([{"name":"etag","required":required,
        "predicate":{"kind":"equals","value":"approved"}}]);
}

fn fixture() -> (Arc<Snapshot>, GateState, Value, Url) {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes[0].adapter_config["response"] = profile();
    snapshot.routes[0].constraints = vec![envelope()];
    let snapshot = Arc::new(snapshot);
    let state = test_gate_state(Arc::clone(&snapshot));
    let decision = json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":"generic.read"},"canonical_request":{"request":{"method":"GET",
            "scheme":"https","authority":"example.test","path":"/resource"}}});
    (snapshot, state, decision, Url::parse("https://example.test/resource").unwrap())
}

fn headers(fields: &[(&str, &[u8])]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        headers.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_bytes(value).unwrap());
    }
    headers
}

fn prepare(headers: &HeaderMap) -> Result<HeaderMap, Value> {
    response_metadata::prepare(headers, &[envelope()], &ResponseSecretGuard::default())
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("bounded response fixture: {error}"),
        }
    }
}

fn upstream(status: u16, extra: &str, body: &[u8]) -> reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let framing = if status == 204 { String::new() } else { format!("Content-Length: {}\r\n", body.len()) };
    let mut wire = format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\n{framing}{extra}\r\n").into_bytes();
    wire.extend_from_slice(body);
    let server = thread::spawn(move || {
        let mut stream = accept_bounded(&listener);
        read_request_head_from(&mut stream, None).unwrap();
        stream.write_all(&wire).unwrap();
    });
    let response = Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .get(format!("http://{address}/fixture")).send().unwrap();
    server.join().unwrap();
    response
}

fn finalize(snapshot: &Arc<Snapshot>, state: &GateState, decision: &Value, url: &Url,
    response: reqwest::blocking::Response, guard: &ResponseSecretGuard) -> SensitiveResponseBytes
{
    match finalize_upstream_response(state, snapshot, decision, "GET", url, response, guard,
        None, None, None, None, None, None, None, None, None, false)
    {
        ForwardResult::Buffered(wire) => wire,
        ForwardResult::Streamed => panic!("V2 must remain buffered"),
    }
}

#[test]
fn response_metadata_v2_contract_pairs_both_directions_and_every_selection() {
    let mut route = generic_policy_route("none", json!(65536));
    route["adapter"]["config"]["response"] = profile(); route["constraints"] = json!([envelope()]);
    validate_policy_capabilities(&policy_with_route(route.clone())).unwrap();
    for mode in ["json", "headersOnly", buffered_response::MODE, buffered_response::JSON_OR_EMPTY_204_MODE] {
        let mut old = route.clone(); old["adapter"]["config"]["response"]["mode"] = json!(mode);
        old["adapter"]["config"]["response"]["error"]["mode"] = json!(mode);
        assert!(validate_policy_capabilities(&policy_with_route(old)).is_err());
    }
    for adapter in ["gmail.v1", "x.v2", "npm.registry"] {
        assert!(buffered_response::validate_envelope_pairing(adapter, Some(buffered_response::JSON_OR_EMPTY_204_V2_MODE), &[envelope()]).is_err());
    }
    for mode in ["json", buffered_response::JSON_OR_EMPTY_204_MODE, buffered_response::JSON_OR_EMPTY_204_V2_MODE] {
        for marker in [Value::Null, json!(response_metadata::POLICY)] {
            assert!(buffered_response::validate_envelope_pairing("generic.rest", Some(mode),
                &[envelope(), json!({"type":"responseJson","unlistedHeaderPolicy":marker})]).is_err());
        }
    }
    for value in [Value::Null, json!("discard"), json!(false)] {
        let mut invalid = route.clone(); invalid["constraints"][0]["unlistedHeaderPolicy"] = value;
        assert!(validate_policy_capabilities(&policy_with_route(invalid)).is_err());
    }
    let mut missing = route.clone(); missing["constraints"][0].as_object_mut().unwrap().remove("unlistedHeaderPolicy");
    assert!(validate_policy_capabilities(&policy_with_route(missing)).is_err());
    let mut mixed = route.clone(); mixed["adapter"]["config"]["response"]["error"]["mode"] = json!(buffered_response::JSON_OR_EMPTY_204_MODE);
    assert!(validate_policy_capabilities(&policy_with_route(mixed)).is_err());
    for error in [false, true] {
        let mut selected = profile();
        if error { selected["error"]["allowedHeaders"] = json!(["etag"]); } else { selected["allowedHeaders"] = json!(["etag"]); }
        let mut first = envelope(); listed_etag(&mut first, false);
        buffered_response::validate_v2_header_selection(&selected, &[first.clone()]).unwrap();
        assert!(buffered_response::validate_v2_header_selection(&selected, &[first, envelope()]).is_err());
    }
    for reserved in ["x-serverware-policy-hash", "x_serverware_policy_hash", "content_type", "set_cookie", "proxy_authorization"] {
        let mut invalid = envelope(); invalid["allowedResponseHeaderNames"] = json!([reserved]);
        invalid["responseHeaderRules"] = json!([{"name":reserved,"required":false,"predicate":{"kind":"equals","value":"x"}}]);
        assert!(buffered_response::validate_v2_header_selection(&profile(), &[invalid]).is_err());
    }
    let (snapshot, _, _, _) = fixture(); validate_route_response_release_mode(&snapshot.routes[0]).unwrap();
    for kind in ["slidingWindowLimit", "weightedBudget", "traversalBudget", "responseBinding"] {
        assert!(buffered_response::validate_mode_constraints(buffered_response::JSON_OR_EMPTY_204_V2_MODE, &[envelope(), json!({"type":kind})]).is_err());
    }
}

#[test]
fn response_metadata_v2_physical_limits_and_ascii_are_inclusive() {
    let mut fields = HeaderMap::new();
    for _ in 0..128 { fields.append("x-extra", HeaderValue::from_static("a")); }
    assert!(prepare(&fields).unwrap().is_empty());
    fields.append("x-extra", HeaderValue::from_static("a"));
    assert_eq!(prepare(&fields).unwrap_err()["error"], "response_metadata_limit_exceeded");
    let name = "x".repeat(128); let value = vec![b'a'; 8192];
    assert!(prepare(&headers(&[(&name, &value)])).is_ok());
    for (name, value) in [("x".repeat(129), vec![b'a']), ("x".into(), vec![b'a';8193])] {
        assert_eq!(prepare(&headers(&[(&name, &value)])).unwrap_err()["error"], "response_metadata_limit_exceeded");
    }
    let mut total = HeaderMap::new();
    for _ in 0..8 { total.append("x", HeaderValue::from_bytes(&vec![b'a';8191]).unwrap()); }
    assert!(prepare(&total).is_ok()); // 8 * (1 + 8191) == 65536.
    total.append("x", HeaderValue::from_static(""));
    assert_eq!(prepare(&total).unwrap_err()["error"], "response_metadata_limit_exceeded");
    assert!(prepare(&headers(&[("x-meta", b"\t visible ~ ")])).is_ok());
    assert_eq!(prepare(&headers(&[("x-meta", &[0x80])])).unwrap_err()["error"], "response_metadata_invalid");
    for invalid in [b"\r".as_slice(), b"\n", &[0x01], &[0x7f]] {
        match HeaderValue::from_bytes(invalid) {
            Err(_) => {}, // The actual HTTP type already rejects control bytes.
            Ok(value) => { let mut fields = HeaderMap::new(); fields.insert("x-meta", value); assert!(prepare(&fields).is_err()); }
        }
    }
    for invalid in [b"bad name".as_slice(), b"bad\rname", &[0xff]] { assert!(HeaderName::from_bytes(invalid).is_err()); }
}

#[test]
fn response_metadata_v2_reserved_aliases_and_listed_duplicates_never_discard() {
    let extras = headers(&[("server", b"synthetic"), ("x-cache", b"one"), ("x-cache", b"two")]);
    assert!(prepare(&extras).unwrap().is_empty());
    for name in ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-serverware-proof",
        "proxy_authorization", "set_cookie", "x_serverware_proof", "content_type", "proxy_connection", "transfer_encoding"]
    {
        assert_eq!(prepare(&headers(&[(name,b"synthetic")])).unwrap_err()["error"], "response_metadata_reserved_header");
    }
    for name in ["connection", "content-type", "content-length", "content-encoding", "keep-alive", "proxy-authenticate",
        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]
    {
        assert_eq!(prepare(&headers(&[(name,b"one"),(name,b"two")])).unwrap_err()["error"], "response_metadata_duplicate");
    }
    let mut selected = envelope(); listed_etag(&mut selected, false);
    let duplicated = headers(&[("etag",b"approved"),("etag",b"approved")]);
    assert_eq!(response_metadata::prepare(&duplicated, &[envelope(),selected], &ResponseSecretGuard::default()).unwrap_err()["error"], "response_metadata_duplicate");
}

#[test]
fn response_metadata_v2_scans_every_discarded_name_and_value_before_selection() {
    let mut guard = ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-provider-secret");
    for fields in [headers(&[("x-unused",b"synthetic-provider-secret")]),
        headers(&[("x-synthetic-provider-secret",b"unused")]),
        headers(&[("x-unused",b"clean"),("x-unused",b"synthetic-provider-secret")])]
    {
        let error = response_metadata::prepare(&fields, &[envelope()], &guard).unwrap_err();
        assert_eq!(error, json!({"error":"response_credential_reflection"}));
        assert!(!error.to_string().contains("synthetic-provider-secret"));
    }
    let retained = response_metadata::prepare(&headers(&[("x-unused",b"unselected-metadata"),
        ("content-type",b"application/json")]), &[envelope()], &guard).unwrap();
    assert!(!retained.contains_key("x-unused"));
    let proof_fields = selected_raw_policy_headers_b64(&profile(), &retained);
    assert!(!proof_fields.contains_key("x-unused"));
    assert!(!serde_json::to_string(&proof_fields).unwrap().contains("unselected-metadata"));
}

#[test]
fn response_metadata_v2_real_finalizer_preserves_json_error_and_empty204_bytes() {
    let json = b"\n{\"large\":18446744073709551617,\"escaped\":\"\\u0061\",\"exp\":1e+02}\r\n";
    for status in [200,400,500,204] {
        let (snapshot,state,decision,url) = fixture();
        let body = if status == 204 { b"".as_slice() } else { json.as_slice() };
        let content_type = if status == 204 { "application/json; charset=utf-8" } else { "application/json" };
        let extra = format!("Content-Type: {content_type}\r\nServer: synthetic\r\nX-Cache: one\r\nX-Cache: two\r\n");
        let wire = finalize(&snapshot,&state,&decision,&url,upstream(status,&extra,body),&ResponseSecretGuard::default());
        let parsed = parse_buffered_response(&wire).unwrap();
        assert_eq!(parsed.status,status); assert_eq!(parsed.body,body);
        assert!(parsed.headers.contains_key("x-serverware-policy-hash"));
        assert!(!parsed.headers.contains_key("server")); assert!(!parsed.headers.contains_key("x-cache"));
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic\r\n"));
        if status == 204 {
            for name in ["content-length","transfer-encoding","trailer"] { assert!(!parsed.headers.contains_key(name)); }
            assert_eq!(parsed.headers["content-type"].as_str(),content_type);
        }
    }
    let (base,_,decision,url) = fixture(); let mut snapshot = (*base).clone();
    snapshot.routes[0].adapter_config["response"]["allowedHeaders"] = json!(["etag"]);
    snapshot.routes[0].adapter_config["response"]["error"]["allowedHeaders"] = json!(["etag"]);
    listed_etag(&mut snapshot.routes[0].constraints[0],true);
    let snapshot = Arc::new(snapshot); let state = test_gate_state(Arc::clone(&snapshot));
    for (etag,error) in [("ETag: approved\r\n",None),("ETag: wrong\r\n",Some("response_envelope_header_value_denied")),
        ("",Some("response_envelope_header_missing")),("ETag: approved\r\nETag: approved\r\n",Some("response_metadata_duplicate"))]
    {
        let wire = finalize(&snapshot,&state,&decision,&url,upstream(204,&format!("Server: discard\r\n{etag}"),b""),&ResponseSecretGuard::default());
        let parsed = parse_buffered_response(&wire).unwrap();
        if let Some(error) = error { assert_eq!(parsed.status,502); assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],error); }
        else { assert_eq!(parsed.status,204); assert_eq!(parsed.headers["etag"].as_str(),"approved"); assert!(!parsed.headers.contains_key("content-type")); }
    }
}

#[test]
fn response_metadata_v2_real_finalizer_blocks_framing_secrets_and_semantic_bypasses() {
    for extra in ["Content-Length: 0\r\n", "Trailer: x-test\r\n", "Content-Type: text/plain\r\n",
        "Content-Encoding: gzip\r\n", "Set-Cookie: synthetic=value\r\n", "Content_Type: application/json\r\n",
        "X-Unlisted: synthetic-provider-secret\r\n", "X-Synthetic-Provider-Secret: safe\r\n"]
    {
        let (snapshot,state,decision,url) = fixture(); let mut guard = ResponseSecretGuard::default();
        guard.add_text_encodings("synthetic-provider-secret");
        let wire = finalize(&snapshot,&state,&decision,&url,upstream(204,extra,b""),&guard);
        let parsed = parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,502);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-provider-secret"));
        assert!(!parsed.headers.contains_key("x-serverware-policy-hash"));
        let queue = state.audit_queue.lock().unwrap();
        assert!(queue.iter().all(|event| !event.event.to_string().contains("synthetic-provider-secret")));
    }
    for constraint in [json!({"id":"body-field","type":"responseJson","phase":"response",
        "fields":{"safe":{"required":true,"type":"string","equals":"yes"}}}),
        json!({"id":"body-date","type":"responseDateWindow","phase":"response","required":true,
            "dateFields":["created_at"],"formats":["epochMillis"],"maxAgeDays":1})]
    {
        for applies in [false,true] {
            let (base,_,decision,url) = fixture(); let mut snapshot = (*base).clone(); let mut constraint = constraint.clone();
            constraint["operations"] = json!([if applies {"generic.read"} else {"generic.other"}]);
            snapshot.routes[0].constraints.push(constraint); let snapshot = Arc::new(snapshot); let state = test_gate_state(Arc::clone(&snapshot));
            let wire = finalize(&snapshot,&state,&decision,&url,upstream(204,"Server: discard\r\n",b""),&ResponseSecretGuard::default());
            assert_eq!(parse_buffered_response(&wire).unwrap().status,if applies {502} else {204});
        }
    }
}

#[test]
fn response_metadata_v2_keeps_old_envelopes_strict_and_never_reuses_connections() {
    let mut old = envelope(); old.as_object_mut().unwrap().remove("unlistedHeaderPolicy");
    let extra = headers(&[("server",b"synthetic")]);
    assert!(enforce_response_envelope(&old,StatusCode::NO_CONTENT,&extra,Some(0),None).is_err());
    enforce_response_envelope(&envelope(),StatusCode::NO_CONTENT,&extra,Some(0),None).unwrap();
    let mut route = test_snapshot(1).routes[0].clone(); assert!(reuse_idle_upstream_connections(&route,"GET"));
    route.adapter_config["response"] = profile(); assert!(!reuse_idle_upstream_connections(&route,"GET"));
    for malformed in [false,true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut first = accept_bounded(&listener); read_request_head_from(&mut first,None).unwrap();
            let mut wire = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\nServer: synthetic\r\n\r\n".to_vec();
            if malformed { wire.extend_from_slice(b"illegal trailing bytes"); } first.write_all(&wire).unwrap();
            let mut second = accept_bounded(&listener); read_request_head_from(&mut second,None).unwrap();
            let body = b"{\"fresh\":true}";
            second.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).unwrap();
            second.write_all(body).unwrap();
        });
        let client = build_pinned_upstream_client(&UpstreamClientConfig {root_certificates:vec![],native_capture_tls:None},
            "metadata.example.test",address,reuse_idle_upstream_connections(&route,"GET")).unwrap();
        let target = format!("http://metadata.example.test:{}/fixture",address.port());
        match client.get(&target).send() {
            Ok(mut first) => { assert_eq!(first.status(),StatusCode::NO_CONTENT); let mut bytes=Vec::new(); let read=first.read_to_end(&mut bytes); if !malformed {read.unwrap();} }
            Err(_) => assert!(malformed),
        }
        let mut second = client.get(&target).send().unwrap(); assert_eq!(second.status(),StatusCode::OK);
        let mut bytes=Vec::new(); second.read_to_end(&mut bytes).unwrap(); assert_eq!(bytes,b"{\"fresh\":true}"); server.join().unwrap();
    }
}

#[test]
fn response_metadata_v2_all_proofs_refuse_before_inner_decision_lease_or_dispatch() {
    let (base,_,_,_) = fixture(); let mut snapshot=(*base).clone();
    snapshot.routes[0].credential_ref=Some("credential:synthetic".into());
    let snapshot=Arc::new(snapshot);
    let matched=RouteMatch {route:&snapshot.routes[0],params:BTreeMap::new()};
    for kind in [ResponseProofKind::Buffered,ResponseProofKind::Streaming,ResponseProofKind::Observation] {
        assert_eq!(validate_response_proof_route_preflight(&matched,kind),Err("response_metadata_v2_proof_unsupported"));
    }
    let old=test_snapshot(1); let old_match=RouteMatch {route:&old.routes[0],params:BTreeMap::new()};
    assert!(validate_response_proof_route_preflight(&old_match,ResponseProofKind::Buffered).is_ok());
    struct Writer(Vec<u8>);
    impl Write for Writer { fn write(&mut self,bytes:&[u8])->io::Result<usize>{self.0.extend_from_slice(bytes);Ok(bytes.len())} fn flush(&mut self)->io::Result<()>{Ok(())} }
    impl TerminalDeadlineWrite for Writer { fn set_terminal_write_deadline(&mut self,_deadline:Option<Instant>){} }
    for flag in 0..8 {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let mut state=test_gate_state(Arc::clone(&snapshot)); state.credential_lease_url=Some(format!("http://{}/lease",listener.local_addr().unwrap()));
        let mut request=IncomingRequest {method:"GET".into(),target:"https://example.test/resource".into(),headers:BTreeMap::new(),body:vec![],client_ip:None};
        if flag>=5 { request.headers.insert([RESPONSE_PROOF_NONCE_HEADER,STREAM_RESPONSE_PROOF_NONCE_HEADER,RESPONSE_OBSERVATION_NONCE_HEADER][flag-5].to_string(),"synthetic-nonce".into()); }
        let mut authorization=None; let mut upstream=None; let mut observation=ResponseObservationTrace::new(); let mut writer=Writer(vec![]);
        let context=StreamingResponseProofContext {client_nonce:"synthetic".into(),client_nonce_bytes:vec![],tls_exporter:"synthetic".into()};
        let streaming=(flag==2).then_some(StreamingResponseProofRequest {context:&context,expected_client_request_digest:"sha256:synthetic",writer:&mut writer});
        let observation_context=ResponseObservationContext {client_nonce:"synthetic".into(),client_nonce_bytes:vec![],nonce_expires_at_epoch_ms:0,
            tls_exporter:"synthetic".into(),method:"GET".into(),target_digest:String::new(),query_present:false,query_digest:String::new(),headers_digest:String::new(),header_count:0};
        let v2=ResponseObservationV2Execution {context:&observation_context,route:ResponseObservationRouteConfig {version:ResponseObservationRouteVersion::V2,
            lifecycle_timeout:Duration::from_secs(1),publication_target_id:None,publication_target_policy_sha256:None},connection_identity_sha256:String::new()};
        let result=forward_absolute_request_inner_with_prepared(&state,&snapshot,request,None,None,None,Some("agent:test"),None,
            (flag==0).then_some(&mut authorization),(flag==1).then_some(&mut upstream),None,streaming,
            (flag==4).then_some(&v2),(flag==3).then_some(&mut observation),false);
        let ForwardResult::Buffered(wire)=result else {panic!("proof must refuse locally")};
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,422);
        assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],"response_metadata_v2_proof_unsupported");
        assert!(authorization.is_none() && upstream.is_none() && writer.0.is_empty());
        assert_eq!(observation.policy_decision_state,"not-evaluated");
        assert!(state.credential_leases.lock().unwrap().is_empty()); assert!(state.credential_generations.lock().unwrap().is_empty());
        assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed),0); assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed),0);
        assert!(state.audit_queue.lock().unwrap().is_empty());
        assert!(matches!(listener.accept(),Err(error) if error.kind()==io::ErrorKind::WouldBlock));
    }
}

#[test]
fn response_metadata_v2_headerless_shadow_terminal_accounting_source_contract() {
    // Source invariant only: no native generation, durable ledger or active
    // dispatch receipt is fabricated. Real finalizer output controls above do
    // not claim an executed native shadow lifecycle.
    let core = include_str!("policy_core.rs");
    let begin = core.split_once("pub(crate) fn begin_unavailable(").unwrap().1
        .split_once("pub(crate) fn record_unavailable(").unwrap().0;
    assert!(begin.contains("generation_is_current_for(snapshot)"));
    assert!(begin.contains("capture: ShadowResponseCapture::Unavailable"));
    assert!(!begin.contains("HeaderMap") && !begin.contains("headers.clone()"));
    let exact = core.split_once("fn try_finish_exact<F>(").unwrap().1
        .split_once("pub(crate) fn finish_parsed_unavailable(").unwrap().0;
    let refusal = exact.find("unavailable response capture cannot authorize exact comparison").unwrap();
    assert!(exact.contains("let ShadowResponseCapture::Parsed { status, headers } = &self.capture else"));
    assert!(refusal < exact.find("let response_facts = json!").unwrap());
    assert!(refusal < exact.find("self.hook.inner.sender.try_send(work)").unwrap());
    let terminal = core.split_once("pub(crate) fn finish_parsed_unavailable(").unwrap().1
        .split_once("pub(crate) fn finish_streaming_unavailable(").unwrap().0;
    assert!(terminal.contains(".finalize_post_dispatch_response_observed("));
    assert!(terminal.contains("PolicyShadowTerminalReason::PostDispatchFinalizationFailed"));
    assert!(terminal.contains(".record_unavailable_detail(reason, Some(returned_response))"));
    assert!(terminal.contains("self.hook.inner.ledger.mark_hard_unready()"));
    assert!(terminal.contains("self.completed = true"));
    let main = include_str!("main.rs");
    let finalize = main.split_once("fn finalize_upstream_response(").unwrap().1
        .split_once("fn finalize_shadow_local_response(").unwrap().0;
    let start = finalize.split_once("if let Some(observation) = response_observation.as_deref_mut()").unwrap().0;
    assert!(start.find("response_metadata::prepare(").unwrap() < start.find("hook.begin_unavailable(snapshot)").unwrap());
    assert!(start.contains("Some(hook) => match if metadata_v2"));
    let rejected = start.split_once("if let Some(payload) = metadata_v2_error").unwrap().1;
    assert!(rejected.find("finish_shadow_parsed_response_unavailable(").unwrap()
        < rejected.find("return ForwardResult::buffered(blocked)").unwrap());
    assert!(rejected.contains("&blocked"));
    let released = finalize.split_once("let released = parse_buffered_response(&response)").unwrap().1;
    assert!(released.contains("finish_shadow_parsed_response_unavailable("));
    assert!(released.contains("RawTransportCaptureUnavailableAfterRelease"));
    assert!(released.contains("RawTransportCaptureUnavailableAfterBlock"));
}
