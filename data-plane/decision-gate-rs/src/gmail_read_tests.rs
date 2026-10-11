//! Deterministic contract controls and bounded loopback finalizer fixtures only.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

fn envelope() -> Value {
    json!({"id":"gmail-read-response","type":"responseEnvelope","phase":"response",
        "statusCodes":STATUSES,"bodyPresence":"required","contentTypes":["application/json"],
        "unlistedHeaderPolicy":"discardUnselectedV1","allowedResponseHeaderNames":[],"responseHeaderRules":[]})
}

fn config() -> Value {
    json!({"credentialBinding":{"credentialType":"oauth2","provider":"google",
        "subjects":["synthetic-account"],"clientIds":["synthetic-client"],
        "requiredScopes":["https://www.googleapis.com/auth/gmail.readonly"]},
        "request":{"allowedHeaders":HEADERS,"allowedQueryKeys":QUERY_KEYS,
            "allowedMediaTypes":[],"maxBodyBytes":0,"valueRules":[]},
        "agePolicy":{"mode":"unrestricted"},"response":response_profile(false)})
}

fn route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into(); route.adapter_config = config();
    route.host = "gmail.googleapis.com".into(); route.methods = HashSet::from(["GET".into()]);
    route.paths = vec![compile_template(LIST_PATH).unwrap(), compile_template(GET_PATH).unwrap()];
    route.credential_ref = Some("credential:gmail-test".into());
    route.constraints = vec![envelope()]; route.jit = json!({}); route
}

fn request(target: &str) -> DecisionRequest {
    serde_json::from_value(json!({"method":"GET","url":target,
        "headers":{"accept":"application/json","accept-encoding":"identity"}})).unwrap()
}

fn inspected(path: &str, status: u16, body: &[u8], guard: &ResponseSecretGuard) -> Result<SensitiveResponseBytes, Value> {
    let status = StatusCode::from_u16(status).unwrap();
    inspect_response(&Url::parse(&format!("https://gmail.googleapis.com{path}")).unwrap(),
        status, Some("application/json; charset=UTF-8"), &response_profile(!status.is_success()),
        body.to_vec().into(), guard)
}

fn policy() -> Value {
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":"credential:gmail-test",
        "match":{"scheme":"https","host":"gmail.googleapis.com","port":443,"methods":["GET"],"paths":[LIST_PATH,GET_PATH]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope()]});
    let mut policy = policy_with_route(wire.clone());
    policy["routes"] = json!([wire]);
    policy["credentials"] = json!([{"id":"credential:gmail-test","credentialType":"oauth2",
        "provider":"google","providerSubject":"synthetic-account","oauthClientId":"synthetic-client",
        "scopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"],
        "injection":{"type":"bearer","header":"Authorization","field":"access_token"}}]);
    policy
}

#[test]
fn gmail_read_contract_is_closed_bound_and_legacy_independent() {
    validate_policy_capabilities(&policy()).unwrap();
    validate_route(&route()).unwrap();
    let schema: Value = serde_json::from_str(include_str!("../../../schemas/adapters/gmail.read.v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&config()));
    for patch in [json!({"mode":"maxAgeDays","maxAgeDays":30}), Value::Null, json!({"mode":"unrestricted","maxAgeDays":3650})] {
        let mut changed=config(); changed["agePolicy"]=patch;
        assert!(!validator.is_valid(&changed)); assert!(validate_config(&changed,&[envelope()]).is_err());
    }
    for mode in ["json", "bufferedJsonOrEmpty204V2", "stream"] {
        let mut changed=config(); changed["response"]["mode"]=json!(mode);
        assert!(validate_config(&changed,&[envelope()]).is_err());
    }
    assert!(buffered_response::validate_envelope_pairing("gmail.v1",Some(MODE),&[envelope()]).is_err());
    assert!(buffered_response::validate_envelope_pairing("generic.rest",Some(MODE),&[envelope()]).is_err());
    for pointer in ["/credentials/0/providerSubject","/credentials/0/oauthClientId","/credentials/0/injection/field"] {
        let mut changed=policy(); *changed.pointer_mut(pointer).unwrap()=json!("wrong");
        assert!(validate_policy_capabilities(&changed).is_err(),"{pointer}");
    }
    for field in ["jit","responseObservation"] {
        let mut changed=policy(); changed["routes"][0][field]=json!({});
        assert!(validate_policy_capabilities(&changed).is_err());
    }
}

#[test]
fn gmail_read_normalizes_list_pagination_and_known_ids_without_age_rewrite() {
    let route=route();
    for (path,operation) in [
        (format!("{LIST_PATH}?labelIds=INBOX&maxResults=20&q=from%3Aalice"),"gmail.messages.list"),
        (format!("{LIST_PATH}?pageToken=opaque%3Dcursor"),"gmail.messages.list"),
        (format!("{LIST_PATH}/known_id-2?format=full"),"gmail.message.get"),
        (format!("{LIST_PATH}/send?format=metadata&metadataHeaders=Subject"),"gmail.message.get"),
    ] {
        let target=format!("https://gmail.googleapis.com{path}"); let req=request(&target); let url=Url::parse(&target).unwrap();
        let matched=RouteMatch {route:&route,params:route.paths.iter().find_map(|path| path.matches(url.path())).unwrap()};
        let (normalized,rewrite)=validate_adapter(&req,&req.headers,&url,&matched).unwrap();
        assert_eq!(rewrite,json!({})); assert_eq!(normalized["operation"],operation); assert_eq!(normalized["gmailUser"],"me");
        assert!(req.gmail_proofs.is_empty());
    }
}

#[test]
fn gmail_read_request_admission_refuses_method_account_path_body_and_encoding() {
    let route=route();
    for target in [
        "https://gmail.googleapis.com/gmail/v1/users/other/messages",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/id/attachments/a",
        "https://gmail.googleapis.com/gmail/v1/users/me/threads",
        "https://other.example/gmail/v1/users/me/messages",
    ] {
        let req=request(target); assert!(validate_provider_request_admission(&req,&Url::parse(target).unwrap(),&route).is_err());
    }
    let target=format!("https://gmail.googleapis.com{LIST_PATH}"); let url=Url::parse(&target).unwrap();
    for variant in 0..4 {
        let mut req=request(&target);
        match variant {0=>req.method="POST".into(),1=>req.body="{}".into(),2=>{req.headers.insert("accept-encoding".into(),"gzip".into());},_=>{req.headers.insert("x-goog-user-project".into(),"billing".into());}}
        assert!(validate_provider_request_admission(&req,&url,&route).is_err());
    }
    let mut changed=route.clone(); changed.paths=vec![compile_template("/gmail/**").unwrap()];
    assert!(validate_route(&changed).is_err());
}

#[test]
fn gmail_read_query_bounds_and_existing_canonical_client_limit_are_explicit() {
    let route=route();
    for suffix in ["?maxResults=0","?maxResults=501","?maxResults=01","?includeSpamTrash=true","?fields=id","?format=raw","?q=a&q=b"] {
        let target=format!("https://gmail.googleapis.com{LIST_PATH}{suffix}"); let req=request(&target);
        assert!(normalize_request(&req,&req.headers,&Url::parse(&target).unwrap(),&route).is_err());
    }
    for size in [2048,2049] {
        let target=format!("https://gmail.googleapis.com{LIST_PATH}?q={}","x".repeat(size)); let req=request(&target);
        assert_eq!(normalize_request(&req,&req.headers,&Url::parse(&target).unwrap(),&route).is_ok(),size==2048);
    }
    // Retained pre-query rows keep this restriction; only the signed new mode opts in.
    assert!(validate_raw_absolute_target(&format!("https://gmail.googleapis.com{LIST_PATH}?q=a&maxResults=1")).is_err());
    assert!(validate_raw_absolute_target(&format!("https://gmail.googleapis.com{LIST_PATH}?labelIds=A&labelIds=B")).is_err());
    assert!(validate_raw_absolute_target(&format!("https://gmail.googleapis.com{LIST_PATH}?q=a+b")).is_err());
}

#[test]
fn gmail_read_preserves_complete_json_pagination_and_numeric_spelling() {
    let raw=br#" { "messages":[{"id":"abc","threadId":"thread_1"}], "nextPageToken":"opaque\u003Dcursor", "resultSizeEstimate":2, "other":18446744073709551617, "n":1e2 } "#;
    let released=inspected(LIST_PATH,200,raw,&ResponseSecretGuard::default()).unwrap();
    assert_eq!(&*released,raw);
    let raw=br#"{"id":"known_1","payload":{"body":{"data":"untouched"}},"unlisted":{"x":true}}"#;
    let released=inspected(&format!("{LIST_PATH}/known_1"),200,raw,&ResponseSecretGuard::default()).unwrap();
    assert_eq!(&*released,raw);
    let error=br#" {"error":{"code":403,"message":"synthetic"},"extra":true} "#;
    assert_eq!(&*inspected(LIST_PATH,403,error,&ResponseSecretGuard::default()).unwrap(),error);
}

#[test]
fn gmail_read_response_semantics_and_bounds_fail_closed() {
    for body in [br#"[]"#.as_slice(),br#"{"messages":null}"#,br#"{"messages":[{"id":"a"},{"id":"a"}]}"#,
        br#"{"messages":[{"id":"a/b"}]}"#,br#"{"nextPageToken":"\n"}"#,br#"{"resultSizeEstimate":-1}"#,
        br#"{"messages":[],"messages":[]}"#,br#"{"n":NaN}"#] {
        assert!(inspected(LIST_PATH,200,body,&ResponseSecretGuard::default()).is_err());
    }
    assert!(inspected(&format!("{LIST_PATH}?maxResults=1"),200,br#"{"messages":[{"id":"a"},{"id":"b"}]}"#,&ResponseSecretGuard::default()).is_err());
    assert!(inspected(&format!("{LIST_PATH}/wanted"),200,br#"{"id":"different"}"#,&ResponseSecretGuard::default()).is_err());
    assert!(inspected(LIST_PATH,400,b"[]",&ResponseSecretGuard::default()).is_err());
    for status in [201,204,206,302,418] { assert!(inspected(LIST_PATH,status,b"{}",&ResponseSecretGuard::default()).is_err()); }
    let large=format!("{{\"text\":\"{}\"}}","x".repeat(ERROR_BYTES as usize));
    assert_eq!(inspected(LIST_PATH,400,large.as_bytes(),&ResponseSecretGuard::default()).err().unwrap()["error"],"response_body_too_large");
}

#[test]
fn gmail_read_scans_raw_decoded_and_discarded_disclosure_material() {
    let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for body in [br#"{"secret":"synthetic-secret"}"#.as_slice(),br#"{"secret":"\u0073ynthetic-secret"}"#] {
        assert_eq!(inspected(LIST_PATH,200,body,&guard).err().unwrap()["error"],"response_credential_reflection");
    }
    let mut headers=HeaderMap::new(); headers.insert("content-type",HeaderValue::from_static("application/json"));
    headers.insert("x-unselected",HeaderValue::from_static("synthetic-secret"));
    assert_eq!(response_metadata::prepare(&headers,&[envelope()],&guard).err().unwrap()["error"],"response_credential_reflection");
    headers.insert("x-unselected",HeaderValue::from_static("ordinary-provider-metadata"));
    let selected=response_metadata::prepare(&headers,&[envelope()],&guard).unwrap();
    assert!(!selected.contains_key("x-unselected")); assert!(selected.contains_key("content-type"));
}

fn fixture() -> (Arc<Snapshot>,GateState,Value,Url) {
    let mut snapshot=(*test_snapshot(1)).clone(); snapshot.routes=vec![route()];
    let snapshot=Arc::new(snapshot); let state=test_gate_state(Arc::clone(&snapshot));
    let decision=json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":"gmail.messages.list","gmailUser":"me"},"canonical_request":{"request":{
            "method":"GET","scheme":"https","authority":"gmail.googleapis.com","path":LIST_PATH}}});
    (snapshot,state,decision,Url::parse(&format!("https://gmail.googleapis.com{LIST_PATH}")).unwrap())
}

fn upstream(status:u16,extra:&str,body:&[u8]) -> reqwest::blocking::Response {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap();
    let mut wire=format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).into_bytes(); wire.extend_from_slice(body);
    let server=thread::spawn(move || {
        let deadline=Instant::now()+Duration::from_secs(4);
        let mut stream=loop { match listener.accept() {
            Ok((stream,_))=>break stream,
            Err(error) if error.kind()==io::ErrorKind::WouldBlock && Instant::now()<deadline=>thread::sleep(Duration::from_millis(2)),
            Err(error)=>panic!("bounded local response fixture: {error}"),
        }};
        stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        read_request_head_from(&mut stream,None).unwrap(); stream.write_all(&wire).unwrap();
    });
    let response=Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap().get(format!("http://{address}/fixture")).send().unwrap();
    server.join().unwrap(); response
}

fn finalized(snapshot:&Arc<Snapshot>,state:&GateState,decision:&Value,url:&Url,response:reqwest::blocking::Response,guard:&ResponseSecretGuard) -> SensitiveResponseBytes {
    match finalize_upstream_response(state,snapshot,decision,"GET",url,response,guard,None,None,None,None,None,None,None,None,None,false) {
        ForwardResult::Buffered(wire)=>wire,ForwardResult::Streamed=>panic!("Gmail read must buffer"),
    }
}

#[test]
fn gmail_read_real_finalizer_releases_json_and_discards_only_bounded_metadata() {
    let (snapshot,state,decision,url)=fixture();
    for (status,raw) in [(200,br#" {"messages":[{"id":"a"}],"nextPageToken":"cursor"} "#.as_slice()),(403,br#"{"error":{"code":403},"detail":"kept"}"#)] {
        let response=upstream(status,"Content-Type: application/json\r\nServer: synthetic\r\n",raw);
        let wire=finalized(&snapshot,&state,&decision,&url,response,&ResponseSecretGuard::default());
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,status); assert_eq!(parsed.body,raw);
        assert!(!String::from_utf8_lossy(&wire).contains("Server: synthetic"));
    }
}

#[test]
fn gmail_read_json_media_parameters_real_finalizer_preserves_success_and_error_bytes() {
    for (status, body) in [(200, br#" {"messages":[{"id":"a"}],"nextPageToken":"cursor"} "#.as_slice()),
        (403, br#" {"error":{"code":403},"detail":"kept"} "#),
        (500, br#" {"error":{"code":500},"detail":"kept"} "#)]
    {
        for media in ["application/json; charset=utf-8", "Application/JSON; Charset=\"UTF-8\"",
            "application/json; profile=fixture; charset=utf-8"]
        {
            let (snapshot, state, decision, url) = fixture();
            let response = upstream(status, &format!("Content-Type: {media}\r\nServer: synthetic\r\n"), body);
            let wire = finalized(&snapshot, &state, &decision, &url, response, &ResponseSecretGuard::default());
            let parsed = parse_buffered_response(&wire).unwrap();
            assert_eq!(parsed.status, status, "{media}");
            assert_eq!(parsed.body, body);
            assert!(parsed.headers.contains_key("x-serverware-policy-hash"));
            assert!(!parsed.headers.contains_key("server"));
        }
    }
}

#[test]
fn gmail_read_json_media_parameters_real_finalizer_refuses_ambiguity() {
    for status in [200, 403, 500] {
        for extra in ["", "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Type: application/json; charset\r\n",
            "Content-Type: application/json; charset=\r\n",
            "Content-Type: application/json; charset=\"utf-8\r\n",
            "Content-Type: application/json; charset=utf-8; CHARSET=utf-8\r\n",
            "Content-Type: application/json; charset=utf-8\r\nContent-Type: application/json; charset=utf-8\r\n"]
        {
            let (snapshot, state, decision, url) = fixture();
            let wire = finalized(&snapshot, &state, &decision, &url,
                upstream(status, extra, b"{}"), &ResponseSecretGuard::default());
            let parsed = parse_buffered_response(&wire).unwrap();
            assert_eq!(parsed.status, 502, "{extra}");
            assert!(!parsed.headers.contains_key("x-serverware-policy-hash"));
        }
    }
}

#[test]
fn gmail_read_json_media_parameters_require_the_full_validated_route() {
    let mut fields = HeaderMap::new();
    fields.insert("content-type", HeaderValue::from_static("application/json; charset=utf-8"));
    validate_response_envelopes(&route(), StatusCode::OK, &fields, Some(2), None).unwrap();
    for variant in 0..5 {
        let mut invalid = route();
        match variant {
            0 => invalid.host = "other.example".into(),
            1 => invalid.adapter_config["response"]["mode"] = json!("json"),
            2 => invalid.adapter_config["agePolicy"] = json!({"mode":"unrestricted", "extra":true}),
            3 => invalid.constraints[0]["contentTypePolicy"] = json!(MODE),
            _ => invalid.paths = vec![compile_template("/gmail/**").unwrap()],
        }
        assert_eq!(validate_response_envelopes(&invalid, StatusCode::OK, &fields, Some(2), None)
            .unwrap_err()["error"], "response_envelope_policy_invalid");
    }
    let mut generic = test_snapshot(1).routes[0].clone();
    generic.constraints[0]["contentTypePolicy"] = json!(MODE);
    assert!(validate_route_response_release_mode(&generic).is_err());
    assert!(validate_response_envelopes(&generic, StatusCode::OK, &fields, Some(2), None).is_err());
}

#[test]
fn gmail_read_real_finalizer_retains_framing_reflection_and_revocation_guards() {
    let (snapshot,state,decision,url)=fixture(); let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for headers in ["Content-Type: application/json\r\nX-Discarded: synthetic-secret\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: application/json\r\nSet-Cookie: forbidden=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n"] {
        let wire=finalized(&snapshot,&state,&decision,&url,upstream(200,headers,b"{}"),&guard);
        assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
    }
    *state.snapshot.write().unwrap()=test_snapshot(2);
    let wire=finalized(&snapshot,&state,&decision,&url,upstream(200,"Content-Type: application/json\r\n",b"{}"),&guard);
    let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,502);
    assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],"response_snapshot_revoked");
}

#[test]
fn gmail_read_proofs_refuse_before_lease_or_dispatch_and_connections_do_not_reuse() {
    let (snapshot,state,_,url)=fixture();
    let matched=RouteMatch{route:&snapshot.routes[0],params:BTreeMap::new()};
    for kind in [ResponseProofKind::Buffered,ResponseProofKind::Streaming,ResponseProofKind::Observation] {
        assert_eq!(validate_response_proof_route_preflight(&matched,kind),Err("response_metadata_v2_proof_unsupported"));
    }
    assert!(!reuse_idle_upstream_connections(&snapshot.routes[0],"GET"));
    for nonce in [RESPONSE_PROOF_NONCE_HEADER,STREAM_RESPONSE_PROOF_NONCE_HEADER,RESPONSE_OBSERVATION_NONCE_HEADER] {
        let request=IncomingRequest{method:"GET".into(),target:url.to_string(),headers:BTreeMap::from([(nonce.into(),"synthetic-nonce".into())]),body:vec![],client_ip:None};
        let result=forward_absolute_request_inner_with_prepared(&state,&snapshot,request,None,None,None,Some("agent:test"),None,None,None,None,None,None,None,false);
        let ForwardResult::Buffered(wire)=result else {panic!("proof must refuse locally")};
        assert_eq!(parse_buffered_response(&wire).unwrap().status,422);
        assert!(state.credential_leases.lock().unwrap().is_empty()); assert!(state.audit_queue.lock().unwrap().is_empty());
    }
}

fn ordered_route() -> Route {
    let mut route = route();
    route.adapter_config["request"]["queryMode"] = json!(request_query_compat::MODE);
    route.adapter_config["request"]["allowedHeaders"] = json!(ORDERED_HEADERS);
    route.adapter_config["request"]["discardHeaders"] = json!(ORDERED_DISCARD);
    route.discard_headers = vec!["accept-encoding".into()];
    route
}

fn ordered_snapshot() -> Arc<Snapshot> {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes = vec![ordered_route()];
    Arc::new(snapshot)
}

fn ordered_material(snapshot: &Snapshot, target: &str) -> (DecisionRequest, Url, Value, Value) {
    let route = &snapshot.routes[0];
    let mut req = request(target);
    req.headers = discard_declared_request_headers(&req.headers, &route.discard_headers).unwrap();
    let (_, url) = parse_target_for_route(snapshot, "GET", target, None, &req.headers, Some("agent:test")).unwrap();
    let (operation, rewrite) = normalize_request(&req, &req.headers, &url, route).unwrap();
    let canonical = canonical_request(&req, &req.headers, &url, &snapshot.principals[0], route, 7, &snapshot.hash, &operation);
    let decision = json!({"allowed":true,"principal_id":"agent:test","route_id":route.id,
        "policy_hash":snapshot.hash,"credential_ref":route.credential_ref,"credential_version":7,
        "discard_headers":route.discard_headers,"canonical_request":canonical,
        "request_digest":canonical_request_digest_profile(&canonical,ReleaseProfile::Legacy),
        "operation_digest":operation_digest(&canonical),"operation":operation,"rewrite":rewrite});
    (req, url, canonical, decision)
}

#[test]
fn gmail_read_ordered_contract_is_explicit_and_keeps_prequery_rows_unchanged() {
    let ordered = ordered_route();
    validate_route(&ordered).unwrap();
    let mut signed = policy(); signed["routes"][0]["adapter"]["config"] = ordered.adapter_config.clone();
    validate_policy_capabilities(&signed).unwrap();
    let schema: Value = serde_json::from_str(include_str!("../../../schemas/adapters/gmail.read.v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&ordered.adapter_config));
    for variant in 0..6 {
        let mut changed = ordered.clone();
        match variant {
            0 => { changed.adapter_config["request"].as_object_mut().unwrap().remove("discardHeaders"); },
            1 => changed.adapter_config["request"]["discardHeaders"] = json!([]),
            2 => changed.adapter_config["request"]["discardHeaders"] = json!(["user-agent"]),
            3 => changed.adapter_config["request"]["allowedHeaders"] = json!(HEADERS),
            4 => changed.adapter_config["request"]["queryMode"] = json!("unknown"),
            _ => changed.adapter_config["request"]["queryMode"] = Value::Null,
        }
        assert!(validate_route(&changed).is_err());
        assert!(!validator.is_valid(&changed.adapter_config));
    }
    let mut drifted = ordered.clone(); drifted.discard_headers.clear();
    assert!(validate_route(&drifted).is_err());
    let old = route(); validate_route(&old).unwrap();
    let req = request(&format!("https://gmail.googleapis.com{LIST_PATH}?q=a"));
    let canonical = canonical_request(&req,&req.headers,&Url::parse(&req.url).unwrap(),
        &test_snapshot(1).principals[0],&old,7,"sha256:test",&json!({"operation":"gmail.messages.list","gmailUser":"me"}));
    assert_eq!(canonical["v"],1);
    assert!(!canonical["request"].as_object().unwrap().contains_key("query_wire"));
    assert!(!canonical["request"].as_object().unwrap().contains_key("discard_headers"));
    canonical_request_discard_headers(&canonical,&[]).unwrap();
}

#[test]
fn gmail_read_ordered_real_intake_and_connect_preserve_form_wire() {
    let snapshot = ordered_snapshot();
    for suffix in ["?q=from:alice+subject:a%2Bb&labelIds=INBOX&labelIds=STARRED&maxResults=20",
        "?pageToken=opaque==&q=has:attachment", "?q&&", "?", ""] {
        let target = format!("https://gmail.googleapis.com{LIST_PATH}{suffix}");
        let wire = format!("GET {target} HTTP/1.1\r\nHost: gmail.googleapis.com\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n\r\n");
        let head = read_request_head_with_ordered_query_from(&mut std::io::Cursor::new(wire.as_bytes()),None,true).unwrap();
        assert_eq!(head.target,target);
        let (_, url) = parse_target_for_route(&snapshot,&head.method,&head.target,None,&head.headers,Some("agent:test")).unwrap();
        assert_eq!(url.query(), target.split_once('?').map(|(_,raw)|raw));
        for inner in [format!("{LIST_PATH}{suffix}"),target.clone()] {
            let absolute = connect_inner_target_with_parser(&inner,"gmail.googleapis.com",443,|target|
                parse_target_for_route(&snapshot,"GET",target,None,&head.headers,Some("agent:test"))).unwrap();
            assert_eq!(absolute,target);
        }
    }
    let target = format!("https://gmail.googleapis.com{LIST_PATH}/id?metadataHeaders=Subject&format=metadata&metadataHeaders=From");
    let (_,url)=parse_ordered_target("GET",&target).unwrap();
    let mut req=request(&target); req.headers.clear();
    normalize_request(&req,&req.headers,&url,&snapshot.routes[0]).unwrap();
    for target in [format!("https://gmail.googleapis.com{LIST_PATH}?q=a+b"),
        format!("https://gmail.googleapis.com{LIST_PATH}?labelIds=A&labelIds=B")] {
        let wire=format!("GET {target} HTTP/1.1\r\nHost: gmail.googleapis.com\r\n\r\n");
        assert!(read_request_head_from(&mut std::io::Cursor::new(wire.as_bytes()),None).is_err());
    }
}

#[test]
fn gmail_read_ordered_route_identity_and_legacy_never_backtrack() {
    let snapshot=ordered_snapshot(); let target=format!("https://gmail.googleapis.com{LIST_PATH}?q=a+b");
    assert!(parse_target_for_route(&snapshot,"GET",&target,None,&BTreeMap::new(),Some("wrong-principal")).is_err());
    assert!(parse_target_for_route(&snapshot,"POST",&target,None,&BTreeMap::new(),Some("agent:test")).is_err());
    for target in ["https://other.example/gmail/v1/users/me/messages?q=a+b",
        "https://gmail.googleapis.com/gmail/v1/users/other/messages?q=a+b",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/id/attachments/a?q=a+b",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=%GG"] {
        assert!(parse_target_for_route(&snapshot,"GET",target,None,&BTreeMap::new(),Some("agent:test")).is_err());
    }
    let mut old=(*snapshot).clone(); old.routes=vec![route()];
    assert!(!allows_ordered_intake(&old,None));
    assert!(parse_target_for_route(&old,"GET",&target,None,&BTreeMap::new(),Some("agent:test")).is_err());
    let mut ambiguous=(*snapshot).clone(); let mut competing=route(); competing.id="route:legacy".into();
    ambiguous.routes.push(competing);
    assert!(parse_target_for_route(&ambiguous,"GET",&target,None,&BTreeMap::new(),Some("agent:test")).is_err());
    assert!(connect_inner_target_with_parser(&target,"other.example",443,|value|parse_ordered_target("GET",value)).is_err());
}

#[test]
fn gmail_read_ordered_default_client_headers_are_bounded_then_discarded() {
    let route=ordered_route(); let target=format!("https://gmail.googleapis.com{LIST_PATH}?q=hello+world");
    let url=Url::parse(&target).unwrap(); let mut req=request(&target);
    req.headers=BTreeMap::from([("Accept".into(),"*/*".into()),("User-Agent".into(),"python-requests/2.32.3".into()),
        ("Accept-Encoding".into(),"gzip, deflate, br".into()),("Connection".into(),"keep-alive".into())]);
    let original=req.headers.clone();
    req.headers=discard_declared_request_headers(&req.headers,&route.discard_headers).unwrap();
    validate_provider_request_admission(&req,&url,&route).unwrap();
    let forwarded=canonical_forwarded_request_headers(&req.headers,&url,Some(0),&json!({"type":"bearer","header":"Authorization","field":"access_token"})).unwrap();
    assert!(!forwarded.contains_key("accept-encoding")); assert!(!forwarded.contains_key("connection"));
    assert_eq!(original["Accept-Encoding"],"gzip, deflate, br");
    let mut ambiguous=original.clone(); ambiguous.insert("accept-encoding".into(),"identity".into());
    assert!(discard_declared_request_headers(&ambiguous,&route.discard_headers).is_err());
    let mut invalid=original; invalid.insert("Accept-Encoding".into(),"gzip\r\ninjected: x".into());
    assert!(discard_declared_request_headers(&invalid,&route.discard_headers).is_err());
    let mut old=request(&target); old.headers.insert("accept-encoding".into(),"gzip".into());
    assert!(validate_provider_request_admission(&old,&url,&super::tests::route()).is_err());
}

#[test]
fn gmail_read_ordered_canonical_v3_binds_wire_pairs_and_discard_without_equivalence() {
    let snapshot=ordered_snapshot(); let mut digests=HashSet::new();
    for suffix in ["", "?", "?q=a+b", "?q=a%20b", "?q=a%2Bb", "?q=a%2bb", "?q=a%20b&&"] {
        let target=format!("https://gmail.googleapis.com{LIST_PATH}{suffix}");
        let (_,url,canonical,decision)=ordered_material(&snapshot,&target);
        assert_eq!(canonical["v"],3); assert_eq!(canonical["request"]["query_mode"],"orderedFormV1");
        assert_eq!(canonical["request"]["query_wire"],json!(url.query()));
        assert_eq!(canonical["request"]["query"],json!(query_pairs(&url)));
        assert_eq!(canonical["request"]["discard_headers"],json!(["accept-encoding"]));
        assert!(digests.insert(operation_digest(&canonical)));
        assert!(canonical_request_discard_headers(&canonical,&snapshot.routes[0].discard_headers).is_err());
        assert_eq!(allowed_decision_discard_headers(&snapshot,&decision).unwrap(),vec!["accept-encoding"]);
        for profile in [ReleaseProfile::PolicyAware,ReleaseProfile::Native] {
            assert!(allowed_decision_discard_headers_profile(&snapshot,&decision,profile).is_err());
        }
    }
}

#[test]
fn gmail_read_ordered_dispatch_preserves_exact_url_and_rejects_forged_commitments() {
    let snapshot=ordered_snapshot();
    for raw in ["q=a+b&labelIds=INBOX&labelIds=STARRED", "pageToken=x==&q=a:/@?;b", "q&&", ""] {
        let target=format!("https://gmail.googleapis.com{LIST_PATH}?{raw}");
        let (req,url,canonical,decision)=ordered_material(&snapshot,&target);
        let mut preserved=url.clone(); apply_route_rewrite(&snapshot.routes[0],&mut preserved,&json!({})).unwrap();
        assert_eq!(preserved.as_str(),target);
        assert_eq!(provider_url_for_decision(&snapshot,&decision,"GET",&url).unwrap().as_str(),target);
        assert!(provider_url_bound_to_decision(&decision,"GET",&url).is_err());
        assert!(apply_route_rewrite(&snapshot.routes[0],&mut preserved,&json!({"query":{}})).is_err());
        // Build only: this control performs no DNS or provider I/O.
        let client=Client::builder().no_proxy().build().unwrap();
        let mut built=client.get(url.clone()).headers(req.headers.iter().map(|(name,value)|
            (HeaderName::from_bytes(name.as_bytes()).unwrap(),HeaderValue::from_str(value).unwrap())).collect()).build().unwrap();
        assert_eq!(built.url().as_str(),target); assert!(!built.headers().contains_key("accept-encoding"));
        validate_built_request(&canonical,&snapshot.routes[0],&url,&built).unwrap();
        built.headers_mut().insert("accept-encoding",HeaderValue::from_static("gzip"));
        assert!(validate_built_request(&canonical,&snapshot.routes[0],&url,&built).is_err());
        for field in ["query_wire","query","query_mode","discard_headers"] {
            let mut tampered=canonical.clone(); tampered["request"][field]=Value::Null;
            assert!(validate_canonical_url(&tampered,&snapshot.routes[0],"GET",&url).is_err(),"{field}");
        }
        let mut changed=url.clone(); changed.set_query(Some("q=different"));
        assert!(validate_canonical_url(&canonical,&snapshot.routes[0],"GET",&changed).is_err());
        let mut downgrade=canonical; downgrade["v"]=json!(2);
        assert!(super::canonical_discard_headers(&downgrade,&snapshot.routes[0]).is_err());
    }
}

#[test]
fn gmail_read_ordered_unsupported_consumers_refuse_before_generation_or_lease() {
    let snapshot=ordered_snapshot(); let mut state=test_gate_state(Arc::clone(&snapshot));
    let target=format!("https://gmail.googleapis.com{LIST_PATH}?labelIds=INBOX&labelIds=STARRED&q=a+b");
    state.atomic_release_authorization_enabled=true;
    let result=decide_internal(&state,&snapshot,request(&target),Some("agent:test"));
    assert_eq!(result["payload"]["error"],"ordered_query_release_profile_unsupported");
    state.atomic_release_authorization_enabled=false;
    for nonce in [RESPONSE_PROOF_NONCE_HEADER,STREAM_RESPONSE_PROOF_NONCE_HEADER,RESPONSE_OBSERVATION_NONCE_HEADER] {
        let mut req=request(&target); req.headers.insert(nonce.into(),"synthetic".into());
        let result=decide_internal(&state,&snapshot,req,Some("agent:test"));
        assert_eq!(result["payload"]["error"],"response_metadata_v2_proof_unsupported");
    }
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.audit_queue.lock().unwrap().is_empty());
}

#[test]
fn gmail_read_ordered_shadow_and_final_dispatch_source_contract_only() {
    // These are hook-presence controls, not native shadow/dispatch runtime proof.
    let source=include_str!("policy_core.rs");
    let evaluation=source.split("fn evaluate_policy_plan_request(").nth(1).unwrap().split("fn ").next().unwrap();
    assert!(evaluation.contains("provider_query::parse_target_for_route(compiled"));
    assert!(evaluation.contains("provider_query::apply_route_rewrite(route"));
    let prerequisite=source.split("pub(crate) fn reserve_credential_prerequisites(").nth(1).unwrap().split("pub(crate) fn ").next().unwrap();
    assert!(prerequisite.contains("provider_query::parse_target_for_route(snapshot, &facts.method, &facts.url"));
    assert!(prerequisite.contains("Some(&principal.id)"));
    let source=include_str!("main.rs");
    let forward=source.split("fn forward_absolute_request_inner_with_prepared").nth(1).unwrap().split("fn ").next().unwrap();
    assert!(forward.contains("provider_query::provider_url_for_decision"));
    assert!(forward.contains("provider_query::validate_built_request"));
    // The new dispatch shim delegates every non-GitHub path to this unchanged module.
    let shim=include_str!("provider_query.rs");
    assert!(shim.contains("crate::gmail_read::provider_url_for_decision"));
    assert!(shim.contains("crate::gmail_read::validate_built_request"));
}
