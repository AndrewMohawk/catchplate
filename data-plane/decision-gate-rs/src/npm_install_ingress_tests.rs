//! Actual bounded HTTP parsing, request ownership and built-request controls.
//! In-memory streams and synthetic compiled policy/token fixtures only: these
//! tests do not perform TLS, DNS, provider I/O, credential acquisition or native admission.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot, test_upstream_client};
use flate2::{write::GzEncoder, Compression};
use std::io::{Cursor, Write};

const PRINCIPAL: &str = "agent:test";
const CREDENTIAL: &str = "credential:npm-install";
const URL: &str = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
const JSON_BODY: &[u8] = br#"{"fixture":["1.0.0"]}"#;

fn config(mode: &str) -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":["synthetic-npm"],"secretClass":"bearerToken"},"packages":["fixture"],
        "mode":mode,"request":npm_install::request_config(mode).unwrap(),
        "response":npm_install::response_profile(mode,false).unwrap()})
}

fn install_snapshot(mode: &str) -> Arc<Snapshot> {
    let mut value = (*test_snapshot(1)).clone();
    let route = &mut value.routes[0];
    route.adapter_type = npm_install::ADAPTER.into(); route.adapter_config = config(mode);
    route.host = npm_install::HOST.into();
    route.methods = HashSet::from([if mode == "audit" {"POST".into()} else {"GET".into()}]);
    route.paths = npm_install::route_paths(mode).unwrap().into_iter()
        .map(|path| compile_template(path).unwrap()).collect();
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":npm_install::PLACEHOLDER}));
    route.discard_headers = npm_install::DISCARD.iter().map(|value| value.to_string()).collect();
    route.constraints = vec![npm_install::envelope(mode,"install-response").unwrap()];
    route.jit = json!({});
    value.credentials.insert(CREDENTIAL.into(), Credential {provider:"operator-demo".into(),
        provider_subject:Some("synthetic-npm".into()), injection:json!({"type":"bearer",
            "header":"Authorization","__serverwareCredentialType":"static"})});
    Arc::new(value)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap(); encoder.finish().unwrap()
}

fn wire(target: &str, body: &[u8], extra: &str) -> (Vec<u8>, usize) {
    let head = format!("POST {target} HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: {}\r\nAccept: application/json\r\nNpm-Command: install\r\n{extra}\r\n", body.len(), npm_install::PLACEHOLDER);
    let length = head.len(); let mut bytes = head.into_bytes(); bytes.extend_from_slice(body);
    (bytes,length)
}

fn parsed(snapshot: &Arc<Snapshot>, bytes: &[u8]) -> IncomingRequest {
    let (raw,_) = wire(URL,bytes,""); let mut reader = Cursor::new(raw);
    let head = read_request_head_with_intake_from(&mut reader,Some("127.0.0.1".into()),false,
        npm_install_audit_intake(snapshot,PRINCIPAL)).unwrap();
    assert_eq!(admit_npm_install_encoding_head(snapshot,Some(PRINCIPAL),&head),Ok(true));
    let limit = buffered_route_body_limit(snapshot,&head,Some(PRINCIPAL));
    assert_eq!(limit,65_536);
    read_request_body_from_head(&mut reader,head,limit).unwrap()
}

fn reviewed() -> (Arc<Snapshot>,IncomingRequest,DecisionRequest) {
    let snapshot = install_snapshot("audit"); let input = parsed(&snapshot,&gzip(JSON_BODY));
    let request = reviewed_buffered_decision_request(&snapshot,&input,Some(PRINCIPAL),None).unwrap();
    (snapshot,input,request)
}

fn canonical(snapshot: &Snapshot, request: &DecisionRequest) -> Value {
    let mut admitted = request.clone(); let route = &snapshot.routes[0];
    credential_header_replacement::remove_for_route(snapshot,route,&snapshot.principals[0],&mut admitted.headers).unwrap();
    admitted.headers = discard_declared_request_headers(&admitted.headers,&route.discard_headers).unwrap();
    let url = Url::parse(URL).unwrap();
    validate_provider_request_admission(&admitted,&url,route).unwrap();
    let headers = canonical_admitted_request_headers(&admitted,&url,
        decision_request_body_length(&admitted).unwrap(),&snapshot.credentials[CREDENTIAL].injection).unwrap();
    let matched = snapshot.match_route(PRINCIPAL,"POST",&url).unwrap();
    let (operation,rewrite) = validate_adapter(&admitted,&headers,&url,&matched).unwrap();
    assert_eq!(rewrite,json!({}));
    assert_eq!(operation,json!({"operation":"npm.install.audit.read","packages":["fixture"],
        "packageVersions":{"fixture":["1.0.0"]}}));
    canonical_request(&admitted,&headers,&url,&snapshot.principals[0],route,7,&snapshot.hash,&operation)
}

#[test]
fn npm_install_default_and_management_intake_remain_identity_only() {
    let snapshot = install_snapshot("audit"); let body = gzip(JSON_BODY); let (raw,_) = wire(URL,&body,"");
    assert!(read_request_head_from(&mut Cursor::new(raw.clone()),None).is_err());
    assert!(read_request_head_with_ordered_query_from(&mut Cursor::new(raw),None,true).is_err());
    let input = parsed(&snapshot,&body);
    assert!(reviewed_buffered_decision_request(&snapshot,&input,None,None).is_err());
    let forged:DecisionRequest = serde_json::from_value(json!({"method":"POST","url":URL,
        "headers":input.headers,"body":std::str::from_utf8(JSON_BODY).unwrap(),
        "bodySha256":body_sha_bytes(&body),"npm_install_audit_body":{"wire":body},
        "forwarded_body_length":body.len(),"forwarded_body_utf8_valid":false})).unwrap();
    assert!(forged.npm_install_audit_body.is_none());
    assert!(admitted_request_content_encoding(&forged).is_err());
    let state = test_gate_state(Arc::clone(&snapshot));
    assert_eq!(decide(&state,forged)["error"],"request_content_encoding_denied");
    let owner = reviewed_buffered_decision_request(&snapshot,&input,Some(PRINCIPAL),None).unwrap();
    assert_eq!(decide(&state,owner)["error"],"request_content_encoding_denied");
}

#[test]
fn npm_install_exact_route_admission_precedes_any_body_read() {
    let snapshot = install_snapshot("audit"); let bytes = gzip(JSON_BODY);
    for target in [URL,"https://registry.npmjs.org/fixture","https://registry.npmjs.org/-/npm/v1/security/audits/quick",
        "https://other.example/-/npm/v1/security/advisories/bulk"] {
        let (raw,head_bytes) = wire(target,&bytes,""); let mut reader = Cursor::new(raw);
        let head = read_request_head_with_intake_from(&mut reader,None,false,true).unwrap();
        assert_eq!(reader.position(),head_bytes as u64); assert!(head.prefetched_body.is_empty());
        assert_eq!(admit_npm_install_encoding_head(&snapshot,Some(PRINCIPAL),&head).is_ok(),target==URL);
        assert!(admit_npm_install_encoding_head(&snapshot,None,&head).is_err());
        assert!(admit_npm_install_encoding_head(&snapshot,Some("agent:other"),&head).is_err());
        assert_eq!(reader.position(),head_bytes as u64);
    }
    for mode in ["metadata","tarball"] { assert!(!npm_install_audit_intake(&install_snapshot(mode),PRINCIPAL)); }
}

#[test]
fn npm_install_current_connect_identity_and_changed_route_refuse_before_body() {
    let mut current = (*install_snapshot("audit")).clone();
    current.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256:sha256_prefixed(b"synthetic-connect-token"), source_cidrs:vec![],
        expires_at_ms:Some(2_000), basic_transport:None,
    });
    let auth = ConnectAuthentication::capture_at(&current,PRINCIPAL,None,
        &BTreeMap::from([("proxy-authorization".into(),"Bearer synthetic-connect-token".into())]),1_000).unwrap();
    let (raw,head_bytes) = wire(URL,&gzip(JSON_BODY),""); let mut reader = Cursor::new(raw);
    let head = read_request_head_with_intake_from(&mut reader,None,false,true).unwrap();
    assert!(auth.revalidate_at(&current,1_999).is_ok());
    assert!(auth.revalidate_at(&current,2_000).is_err());
    current.routes[0].principals = vec!["agent:other".into()];
    assert!(admit_npm_install_encoding_head(&current,Some(PRINCIPAL),&head).is_err());
    current.principals.clear(); assert!(auth.revalidate_at(&current,1_999).is_err());
    assert_eq!(reader.position(),head_bytes as u64);
}

#[test]
fn npm_install_gzip_framing_is_closed_and_bounded_before_decode() {
    let snapshot = install_snapshot("audit"); let bytes = gzip(JSON_BODY);
    for extra in ["Content-Encoding: gzip\r\n","Transfer-Encoding: chunked\r\n",
        "Connection: content-encoding\r\n"] {
        let (raw,_) = wire(URL,&bytes,extra);
        assert!(read_request_head_with_intake_from(&mut Cursor::new(raw),None,false,true).is_err());
    }
    let (raw,_) = wire(URL,&bytes,"");
    let base = read_request_head_with_intake_from(&mut Cursor::new(raw),None,false,true).unwrap();
    for (field,value) in [("content-encoding","GZip"),("content-encoding","gzip, identity"),
        ("content-type","text/plain"),("content-length","065"),("content-length","65537")] {
        let mut head = RequestHead {method:base.method.clone(),target:base.target.clone(),http_version:"HTTP/1.1".into(),
            headers:base.headers.clone(),raw_headers_digest:None,raw_header_count:0,
            content_length:base.content_length,has_content_length:true,prefetched_body:vec![],client_ip:None};
        head.headers.insert(field.into(),value.into());
        assert!(admit_npm_install_encoding_head(&snapshot,Some(PRINCIPAL),&head).is_err());
    }
    for bytes in [JSON_BODY.to_vec(),gzip(b"{\"fixture\":[\"1.0.0\"],\"fixture\":[\"2.0.0\"]}"),
        gzip(b"{\"unselected\":[\"1.0.0\"]}"),[gzip(JSON_BODY),b"tail".to_vec()].concat()] {
        let input = parsed(&snapshot,&bytes);
        assert!(reviewed_buffered_decision_request(&snapshot,&input,Some(PRINCIPAL),None).is_err());
    }
}

#[test]
fn npm_install_canonical_uses_original_compressed_bytes_and_headers() {
    let (snapshot,input,request) = reviewed(); let canonical = canonical(&snapshot,&request);
    assert_eq!(request.body.as_bytes(),JSON_BODY);
    assert_eq!(request.forwarded_body_utf8_valid,Some(false));
    assert_eq!(request.npm_install_audit_body.as_ref().unwrap().wire(),input.body);
    assert_eq!(canonical["v"],2);
    assert_eq!(canonical["request"]["body_sha256"],body_sha_bytes(&input.body));
    assert_ne!(canonical["request"]["body_sha256"],body_sha_bytes(JSON_BODY));
    assert_eq!(canonical["request"]["headers"]["content-encoding"],"gzip");
    assert_eq!(canonical["request"]["headers"]["content-length"],input.body.len().to_string());
    assert!(canonical["request"]["headers"].get("authorization").is_none());
    validate_buffered_body_binding(&json!({"canonical_request":canonical}),&input.body).unwrap();
    let ordinary = canonical_forwarded_request_headers(&request.headers,&Url::parse(URL).unwrap(),
        Some(input.body.len() as u64),&json!({"type":"bearer"})).unwrap();
    assert!(!ordinary.contains_key("content-encoding"));
}

#[test]
fn npm_install_retention_preserves_owner_and_refuses_forged_or_rebound_originals() {
    let (snapshot,input,request) = reviewed();
    let retained = policy_core::npm_install_retained_request_for_test(&request,Some(PRINCIPAL),&input.body).unwrap();
    assert_eq!(canonical(&snapshot,&retained),canonical(&snapshot,&request));
    assert_eq!(retained.body,request.body);
    assert_eq!(retained.npm_install_audit_body.as_ref().unwrap().wire(),input.body);
    assert!(policy_core::npm_install_retained_request_for_test(&request,None,&input.body).is_err());
    assert!(policy_core::npm_install_retained_request_for_test(&request,Some(PRINCIPAL),JSON_BODY).is_err());
    for case in 0..5 {
        let mut changed = request.clone();
        match case {
            0 => changed.npm_install_audit_body = None,
            1 => changed.body = "{}".into(),
            2 => changed.body_sha256 = Some(body_sha_bytes(JSON_BODY)),
            3 => changed.forwarded_body_utf8_valid = Some(true),
            _ => changed.headers.insert("content-encoding".into(),"identity".into()).map(|_|()).unwrap(),
        }
        assert!(policy_core::npm_install_retained_request_for_test(&changed,Some(PRINCIPAL),&input.body).is_err());
    }
}

#[test]
fn npm_install_actual_built_body_validation_refuses_changed_wire_or_encoding() {
    let (snapshot,input,request) = reviewed();
    let decision = json!({"canonical_request":canonical(&snapshot,&request)});
    let owner = request.npm_install_audit_body.as_ref().unwrap();
    let client = test_upstream_client();
    let headers = filtered_reviewed_forward_headers(&request.headers,&json!({"type":"bearer"}),
        &snapshot.routes[0].discard_headers,Some(owner)).unwrap();
    assert_eq!(headers["content-encoding"],"gzip");
    assert_eq!(headers["content-length"],input.body.len().to_string());
    let built = client.post(URL).headers(headers).body(input.body.clone()).build().unwrap();
    validate_npm_install_built_audit(owner,&snapshot.routes[0],&decision,&built).unwrap();
    assert_eq!(built.body().unwrap().as_bytes().unwrap(),input.body);
    for (encoding,body) in [(Some("identity"),input.body.clone()),(None,input.body.clone()),
        (Some("gzip"),JSON_BODY.to_vec()),(Some("gzip"),gzip(b"{\"fixture\":[\"2.0.0\"]}"))] {
        let mut builder = client.post(URL).header("content-length",body.len()).body(body);
        if let Some(value) = encoding { builder = builder.header("content-encoding",value); }
        assert!(validate_npm_install_built_audit(owner,&snapshot.routes[0],&decision,&builder.build().unwrap()).is_err());
    }
    let mut rebound = decision.clone(); rebound["canonical_request"]["request"]["headers"]["content-encoding"] = json!("identity");
    assert!(validate_npm_install_built_audit(owner,&snapshot.routes[0],&rebound,&built).is_err());
    assert!(validate_npm_install_built_audit(owner,&install_snapshot("metadata").routes[0],&decision,&built).is_err());
}

#[test]
fn npm_install_startup_profiles_are_closed_and_all_three_modes_are_joined() {
    for mode in ["metadata","tarball","audit"] {
        let snapshot = install_snapshot(mode); let route = &snapshot.routes[0];
        npm_install::validate_route(route).unwrap(); validate_route_response_release_mode(route).unwrap();
        assert!(response_metadata::uses_mode(route_response_mode(route).unwrap()));
        let wire = json!({"id":"route:test","principals":[PRINCIPAL],"credentialRef":CREDENTIAL,
            "credentialHeader":{"mode":"replaceExact","expectedValue":npm_install::PLACEHOLDER},
            "match":{"scheme":"https","host":npm_install::HOST,"port":443,
                "methods":[if mode=="audit" {"POST"} else {"GET"}],"paths":npm_install::route_paths(mode).unwrap()},
            "adapter":{"type":npm_install::ADAPTER,"config":config(mode)},"constraints":route.constraints});
        let mut policy = policy_with_route(wire.clone()); policy["routes"] = json!([wire]);
        policy["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
            "providerSubject":"synthetic-npm","injection":{"type":"bearer","header":"Authorization"}}]);
        validate_policy_capabilities(&policy).unwrap();
        let mut crossed = route.clone(); crossed.adapter_type = "generic.rest".into();
        assert!(validate_route_response_release_mode(&crossed).is_err());
    }
    let embedded = closed_embedded_policy_schema().unwrap();
    assert!(embedded["$defs"].get("adapter_npm_install_v1__root").is_some());
    assert_eq!(npm_install::gate_capability(),json!({"schema":"serverware.operatorNpmInstallGate/v1",
        "adapter":"npm.install.v1","modes":["metadata","tarball","audit"]}));
}

#[test]
fn npm_install_connect_source_wiring_keeps_identity_before_body_and_dns() {
    // Source-only placement control complements the actual parser/owner tests;
    // it does not claim a real TLS tunnel or installed policy signature.
    let source = include_str!("main.rs");
    let connect = source.split("let request_snapshot = current_snapshot(&state);").nth(1).unwrap();
    let identity = connect.find("connect_authentication.revalidate(&request_snapshot)").unwrap();
    let route = connect.find("admit_npm_install_encoding_head(").unwrap();
    let body = connect.find("read_request_body_from_head(").unwrap();
    assert!(identity < route && route < body);
    let prepare = source.split("fn prepare_upstream_for_forward_body(").nth(1).unwrap()
        .split("fn prepare_upstream_for_buffered_forward(").next().unwrap();
    assert!(prepare.find("npm_install::AuditBody::from_wire").unwrap() < prepare.find("prepare_upstream(state").unwrap());
    let send = source.split("fn forward_absolute_request_inner_with_prepared").nth(1).unwrap();
    assert!(send.contains("validate_npm_install_built_audit(owner, route, &decision, built)?"));
}
