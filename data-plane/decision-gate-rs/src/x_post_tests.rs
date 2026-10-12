//! Actual admission, preparation and bounded loopback finalizer components.
//! Signed identity fixtures are synthetic: no OAuth consent, quota store,
//! native authority, production dispatch or real X acceptance is claimed.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const CREDENTIAL: &str = "credential:x-post-test";
const TARGET: &str = "https://api.x.com/2/tweets";
fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../scripts/fixtures/x_post_v1.json")).unwrap()
}
fn config() -> Value {
    json!({"credentialBinding":vectors()["credentialBinding"],"request":request_config(),"response":response_profile(false)})
}
fn raw_credential() -> Value {
    json!({"id":CREDENTIAL,"credentialType":"oauth2","provider":"x","providerSubject":"fixture-x-account",
        "oauthClientId":"fixture-x-client","scopes":SCOPES,
        "injection":{"type":"bearer","header":"Authorization","field":"access_token"}})
}
fn credential(raw:&Value) -> Credential {
    Credential {provider:raw["provider"].as_str().unwrap().into(),
        provider_subject:Some(raw["providerSubject"].as_str().unwrap().into()),
        injection:credential_injection_with_signed_identity(&raw["injection"],raw.as_object().unwrap()).unwrap()}
}
fn route() -> Route {
    let mut value=test_snapshot(1).routes[0].clone();
    value.adapter_type=ADAPTER.into(); value.adapter_config=config(); value.host=HOST.into();
    value.methods=HashSet::from(["POST".into()]); value.paths=vec![compile_template(PATH).unwrap()];
    value.credential_ref=Some(CREDENTIAL.into()); value.credential_header=Some(vectors()["replacement"].clone());
    value.discard_headers=DISCARD.iter().map(|v| v.to_string()).collect();
    value.constraints=vec![envelope("x-post-response")]; value.jit=json!({}); value
}
fn snapshot() -> Arc<Snapshot> {
    let mut value=(*test_snapshot(1)).clone(); value.routes=vec![route()];
    value.credentials.insert(CREDENTIAL.into(),credential(&raw_credential())); Arc::new(value)
}
fn policy() -> Value {
    let wire=json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":vectors()["replacement"],
        "match":{"scheme":"https","host":HOST,"port":443,"methods":["POST"],"paths":[PATH]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope("x-post-response")]});
    let mut value=policy_with_route(wire.clone()); value["routes"]=json!([wire]);
    value["credentials"]=json!([raw_credential()]); value
}
fn request() -> DecisionRequest {
    serde_json::from_value(json!({"method":"POST","url":TARGET,
        "headers":{"authorization":PLACEHOLDER,"content-type":"application/json","accept":"application/json",
            "user-agent":"synthetic-x-post/1","accept-encoding":"gzip"},"body":" {\"text\":\"hello\\nline\"} "})).unwrap()
}
fn vector_request(case:&Value) -> DecisionRequest {
    let mut req=request(); req.method=case["method"].as_str().unwrap().into(); req.url=case["url"].as_str().unwrap().into();
    req.body=case["body"].as_str().unwrap().into(); req.headers.clear(); req.headers.insert("authorization".into(),PLACEHOLDER.into());
    for pair in case["headers"].as_array().unwrap() {
        assert!(req.headers.insert(pair[0].as_str().unwrap().into(),pair[1].as_str().unwrap().into()).is_none());
    }
    req
}
fn admitted(mut req:DecisionRequest,snapshot:&Snapshot)->Result<(Value,Value),String> {
    let route=&snapshot.routes[0]; let (_,url)=parse_validated_absolute_target(&req.url).map_err(|_|"target")?;
    credential_header_replacement::remove_for_route(snapshot,route,&snapshot.principals[0],&mut req.headers).map_err(|_|"replacement")?;
    req.headers=discard_declared_request_headers(&req.headers,&route.discard_headers).map_err(|_|"discard")?;
    validate_provider_request_admission(&req,&url,route).map_err(|_|"admission")?;
    let headers=canonical_forwarded_request_headers(&req.headers,&url,decision_request_body_length(&req).map_err(|_|"framing")?,
        &snapshot.credentials[CREDENTIAL].injection).map_err(|_|"headers")?;
    let matched=RouteMatch {route,params:route.paths[0].matches_canonical(url.path()).ok_or("path")?};
    let (operation,rewrite)=validate_adapter(&req,&headers,&url,&matched).map_err(|_|"adapter")?;
    assert_eq!(rewrite,json!({}));
    let canonical=canonical_request(&req,&headers,&url,&snapshot.principals[0],route,7,&snapshot.hash,&operation);
    Ok((operation,canonical))
}

#[test]
fn x_post_shared_vectors_and_original_bytes() {
    let fixture=vectors(); let held=snapshot();
    assert_eq!(fixture["request"],request_config()); assert_eq!(fixture["response"],response_profile(false));
    assert_eq!(fixture["quota"],quota(50));
    for case in fixture["requests"].as_array().unwrap() {
        let result=admitted(vector_request(case),&held);
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok((operation,canonical))=result {
            assert_eq!(operation,fixture["operation"]);
            validate_buffered_body_binding(&json!({"canonical_request":canonical}),case["body"].as_str().unwrap().as_bytes()).unwrap();
            assert_eq!(canonical["v"],2); assert_eq!(canonical["request"]["query"],json!([]));
            assert!(!canonical.to_string().contains(PLACEHOLDER));
        }
    }
    for case in fixture["responses"].as_array().unwrap() {
        let status=StatusCode::from_u16(case["status"].as_u64().unwrap() as u16).unwrap();
        let raw=case["body"].as_str().unwrap().as_bytes();
        let result=inspect_response(&Url::parse(TARGET).unwrap(),status,case["content_type"].as_str(),
            &response_profile(status!=StatusCode::CREATED),raw.to_vec().into(),&ResponseSecretGuard::default());
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok(body)=result { assert_eq!(&*body,raw); }
    }
    let original=request(); let (_,canonical)=admitted(original.clone(),&held).unwrap();
    let mut changed=original; changed.body=changed.body.trim().into();
    assert_ne!(canonical,admitted(changed,&held).unwrap().1);
}

#[test]
fn x_post_closed_policy_schema_and_oauth_identity() {
    validate_policy_capabilities(&policy()).unwrap(); validate_route(&route()).unwrap();
    validate_route_response_release_mode(&route()).unwrap();
    for version in ["serverware.policy/v1",policy_route_authority::BUNDLE] {
        let mut raw=policy(); raw["apiVersion"]=json!(version); raw["kind"]=json!("PolicyBundle");
        raw["metadata"]=json!({"id":"x-post-test","sequence":1,"rollbackEpoch":1});
        if version==policy_route_authority::BUNDLE {
            let pin=format!("sha256:{}","0".repeat(64));
            raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
                "mappingSha256":pin,"routeAuthorityRootSha256":pin,"operationAuthorityRootSha256":pin});
        }
        validate_policy_schema(&raw).unwrap();
    }
    for (pointer,value) in [
        ("/credentials/0/provider",json!("operator-demo")),("/credentials/0/providerSubject",json!("other-account")),
        ("/credentials/0/oauthClientId",json!("other-client")),("/credentials/0/scopes",json!(["tweet.read","users.read"])),
        ("/credentials/0/injection/header",json!("X-Token")),("/credentials/0/injection/field",json!("refresh_token")),
        ("/routes/0/match/methods",json!(["GET","POST"])),("/routes/0/match/paths",json!(["/2/{name}"])),
        ("/routes/0/adapter/config/credentialBinding/subjects",json!(["fixture-x-account","other"])),
        ("/routes/0/adapter/config/credentialBinding/requiredScopes",json!(["tweet.read","tweet.write","users.read"])),
        ("/routes/0/adapter/config/response/mode",json!(x_app_read::MODE)),
    ] { let mut changed=policy(); *changed.pointer_mut(pointer).unwrap()=value;
        assert!(validate_policy_capabilities(&changed).is_err(),"{pointer}"); }
    for field in ["extra","prefix"] {
        let mut changed=policy(); changed["credentials"][0]["injection"][field]=json!("bad");
        assert!(validate_policy_capabilities(&changed).is_err());
        assert!(validate_credential(&credential(&changed["credentials"][0])).is_err());
    }
    for field in ["jit","responseObservation"] { let mut changed=policy(); changed["routes"][0][field]=json!({});
        assert!(validate_policy_capabilities(&changed).is_err()); }
    let mut superset=policy(); superset["credentials"][0]["scopes"].as_array_mut().unwrap().push(json!("bookmark.read"));
    validate_policy_capabilities(&superset).unwrap();
    for adapter in ["x.v2",x_app_read::ADAPTER,"generic.rest"] {
        assert!(buffered_response::validate_envelope_pairing(adapter,Some(MODE),&[envelope("x")]).is_err());
    }
}

#[test]
fn x_post_runtime_metadata_uses_existing_verified_oauth_guard() {
    let held=snapshot(); let scope=CredentialLeaseScope::new("agent:test","route:test",CREDENTIAL);
    let metadata=BTreeMap::from([
        ("provider_id".into(),json!("x")),("provider_subject".into(),json!("fixture-x-account")),
        ("oauth_client_id".into(),json!("fixture-x-client")),("scopes".into(),json!(SCOPES)),
        ("oauth".into(),json!(true)),("provider_identity_verified".into(),json!(true)),
        ("auth_type".into(),json!("bearer")),("header_name".into(),json!("Authorization")),
    ]);
    validate_runtime_credential_binding(&held,&scope,&metadata).unwrap();
    for (key,value) in [("oauth",json!(false)),("provider_identity_verified",json!(false)),
        ("provider_subject",json!("other")),("oauth_client_id",json!("other")),("app_id",json!("contradiction")),
        ("provider",json!("google")),("account",json!("contradiction")),("scope",json!("tweet.read")),
        ("scopes",json!(["tweet.read","tweet.write","users.read"]))] {
        let mut changed=metadata.clone(); changed.insert(key.into(),value);
        assert!(validate_runtime_credential_binding(&held,&scope,&changed).is_err(),"{key}");
    }
}

#[test]
fn x_post_account_quota_keys_and_whole_policy_conflicts() {
    let mut raw=policy(); raw["routes"][0]["constraints"].as_array_mut().unwrap().push(quota(50));
    validate_policy_capabilities(&raw).unwrap();
    let mut second=raw["routes"][0].clone(); second["id"]=json!("route:other"); second["credentialRef"]=json!("credential:other");
    second["adapter"]["config"]["credentialBinding"]["clientIds"]=json!(["other-client"]);
    let mut second_credential=raw_credential(); second_credential["id"]=json!("credential:other"); second_credential["oauthClientId"]=json!("other-client");
    raw["credentials"].as_array_mut().unwrap().push(second_credential.clone()); raw["routes"].as_array_mut().unwrap().push(second);
    validate_policy_capabilities(&raw).unwrap();
    for constraints in [json!([envelope("second")]),json!([envelope("second"),quota(51)])] {
        let mut changed=raw.clone(); changed["routes"][1]["constraints"]=constraints;
        assert!(validate_policy_capabilities(&changed).unwrap_err().contains("same account-day quota"));
    }
    let mut a=route(); a.constraints.push(quota(50)); let mut b=a.clone(); b.id="other-route".into();
    b.credential_ref=Some("credential:other".into()); let mut left=json!({"operation":OPERATION}); let mut right=left.clone();
    bind_provider_account_scope(&a,Some(&credential(&raw_credential())),&mut left).unwrap();
    bind_provider_account_scope(&b,Some(&credential(&second_credential)),&mut right).unwrap();
    let first=rate_limit_key(&quota(50),&a,"first-app",Some(CREDENTIAL),1,&left);
    assert_eq!(first,rate_limit_key(&quota(50),&b,"other-app",Some("credential:other"),900,&right));
    second_credential["providerSubject"]=json!("different-account");
    bind_provider_account_scope(&b,Some(&credential(&second_credential)),&mut right).unwrap();
    assert_ne!(first,rate_limit_key(&quota(50),&b,"other-app",Some("credential:other"),900,&right));
    // The actual mixed-policy guard uses compiled template semantics; principal
    // separation must never bypass an account ceiling. No legacy policy changes
    // are inferred when the new quota is absent.
    let credentials=HashMap::from([(CREDENTIAL.into(),credential(&raw_credential()))]);
    let limited=raw["routes"][0].clone();
    for path in ["/2/tweets","/2/{name}","/2/*","/**"] {
        let generic=json!({"principals":["different-app"],"credentialRef":CREDENTIAL,"adapter":{"type":"generic.rest"},
            "match":{"scheme":"https","host":HOST,"port":443,"methods":["POST"],"paths":[path]}});
        assert!(validate_policy_routes(&[limited.clone(),generic.clone()],&credentials).is_err());
        assert!(validate_policy_routes(&[policy()["routes"][0].clone(),generic.clone()],&credentials).is_ok());
        assert!(validate_policy_routes(&[generic],&credentials).is_ok());
    }
    let legacy=json!({"credentialRef":CREDENTIAL,"adapter":{"type":"x.v2","config":{"mode":"controlledWrite"}}});
    assert!(validate_policy_routes(&[limited,legacy.clone()],&credentials).is_err());
    assert!(validate_policy_routes(&[legacy],&credentials).is_ok());
    let mut generic=crate::tests::generic_policy_route("json",json!(1024));
    generic["id"]=json!("generic:overlap"); generic["credentialRef"]=json!(CREDENTIAL);
    generic["match"]["host"]=json!(HOST); generic["match"]["paths"]=json!(["/2/{name}"]);
    generic["adapter"]["config"]["request"]["allowedHeaders"]=json!(["content-type"]);
    generic["adapter"]["config"]["request"]["allowedMediaTypes"]=json!(["application/json"]);
    generic["adapter"]["config"]["request"]["allowedFields"]=json!(["text"]);
    generic["constraints"]=json!([{"id":"generic:text","type":"jsonBody",
        "allowedFields":["text"],"requiredFields":["text"],"fields":{"text":{"type":"string"}}}]);
    let mut generic_policy=policy_with_route(generic);
    generic_policy["credentials"]=json!([raw_credential()]);
    generic_policy["routes"][0]["adapter"]["config"]["credentialBinding"]=config()["credentialBinding"].clone();
    validate_policy_capabilities(&generic_policy).unwrap();
    generic_policy["routes"].as_array_mut().unwrap().push(raw["routes"][0].clone());
    assert!(validate_policy_capabilities(&generic_policy).unwrap_err().contains("overlapping legacy or generic write route"));
}

#[test]
fn x_post_signed_v2_authority_is_write() {
    let pin=|value:&Value| sha256_prefixed(policy_route_authority::canonical(value).unwrap().as_bytes());
    let mut raw=policy(); raw["apiVersion"]=json!(policy_route_authority::BUNDLE);
    let operations=json!([{"operationName":OPERATION,"operation":"write","requestAuthorityClass":"write"}]);
    let profile=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","routeSha256":sha256_prefixed(b"route:test"),
        "signedRouteSha256":pin(&raw["routes"][0]),"adapterType":ADAPTER,"operations":operations,
        "signedPrincipalsSha256":pin(&raw["principals"]),"signedCredentialsSha256":pin(&raw["credentials"]),
        "signedDefaultsSha256":pin(&raw["defaults"]),"principalSha256s":[sha256_prefixed(b"agent:test")]});
    let profile_pin=pin(&profile); let profiles=json!([{"routeId":"route:test","compiledSemanticProfileSha256":profile_pin,"profile":profile}]);
    let entries=json!([{"routeSha256":profile["routeSha256"],"compiledSemanticProfileSha256":profile_pin,
        "operationName":OPERATION,"operation":"write","requestAuthorityClass":"write"}]);
    raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
        "mappingSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthority/v1","profiles":profiles})),
        "routeAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles})),
        "operationAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))});
    let held=snapshot(); let compiled=policy_route_authority::admit(&raw,&held.routes).unwrap().unwrap();
    assert!(compiled.binding(&held.principals[0],&held.routes[0],&json!({"operation":OPERATION})).is_ok());
    raw["routeAuthority"]["genericOperations"]=json!([{"routeId":"route:test","operationName":OPERATION,"operation":"read"}]);
    assert!(policy_route_authority::admit(&raw,&held.routes).is_err());
}

struct InertResolver(AtomicU64);
impl UpstreamResolver for InertResolver {
    fn resolve(&self,host:&str,port:u16)->Result<Vec<SocketAddr>,String> {
        assert_eq!((host,port),(HOST,443)); self.0.fetch_add(1,Ordering::Relaxed); Ok(vec!["127.0.0.1:443".parse().unwrap()])
    }
}
#[test]
fn x_post_real_preparation_requires_complete_body_before_resolution_and_denials_before_lease_quota() {
    let held=snapshot(); let mut state=test_gate_state(held.clone());
    let resolver=Arc::new(InertResolver(AtomicU64::new(0))); state.upstream_resolver=resolver.clone();
    let req=request(); let url=Url::parse(TARGET).unwrap();
    let incoming=IncomingRequest{method:"POST".into(),target:TARGET.into(),headers:req.headers.clone(),body:req.body.as_bytes().to_vec(),client_ip:None};
    let head=RequestHead{method:"POST".into(),target:TARGET.into(),http_version:"HTTP/1.1".into(),headers:req.headers.clone(),
        raw_headers_digest:None,raw_header_count:0,content_length:incoming.body.len(),has_content_length:true,
        prefetched_body:incoming.body.clone(),client_ip:None};
    assert!(prepare_upstream_for_forward(&state,&held,&head,&url,Some("agent:test")).unwrap().is_none());
    assert!(prepare_upstream_for_forward_body(&state,&held,&head,&url,Some("agent:test"),Some(&incoming.body[..2])).unwrap().is_none());
    for case in vectors()["requests"].as_array().unwrap().iter().filter(|case|case["allowed"]==false) {
        assert_eq!(decide_internal(&state,&held,vector_request(case),Some("agent:test"))["allowed"],false,"{}",case["id"]);
    }
    for body in [b"{}".as_slice(),b"[]",br#"{"text":"a","text":"b"}"#] {
        let changed=IncomingRequest{method:"POST".into(),target:TARGET.into(),headers:req.headers.clone(),body:body.to_vec(),client_ip:None};
        assert!(prepare_upstream_for_buffered_forward(&state,&held,&changed,&url,Some("agent:test")).unwrap().is_none());
    }
    let mut wrong=request(); wrong.headers.insert("authorization".into(),"Bearer other".into());
    assert_eq!(decide_internal(&state,&held,wrong,Some("agent:test"))["allowed"],false);
    assert_eq!(resolver.0.load(Ordering::Relaxed),0);
    assert!(prepare_upstream_for_buffered_forward(&state,&held,&incoming,&url,Some("agent:test")).unwrap().is_some());
    assert_eq!(resolver.0.load(Ordering::Relaxed),1); assert_eq!(buffered_route_body_limit(&held,&head,Some("agent:test")),REQUEST_BYTES);
    assert!(state.credential_leases.lock().unwrap().is_empty()); assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed),0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed),0);
}

#[test]
fn x_post_body_caps_and_raw_decoded_response_reflection() {
    let held=snapshot(); let mut req=request(); req.body=json!({"text":"é".repeat(TEXT_BYTES/2)}).to_string();
    assert!(admitted(req.clone(),&held).is_ok()); req.body=json!({"text":"é".repeat(TEXT_BYTES/2+1)}).to_string();
    assert!(admitted(req,&held).is_err());
    let mut req=request(); req.body.push_str(&" ".repeat(REQUEST_BYTES as usize-req.body.len()));
    assert!(admitted(req.clone(),&held).is_ok()); req.body.push(' '); assert!(admitted(req,&held).is_err());
    let url=Url::parse(TARGET).unwrap(); let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for raw in [br#"{"token":"synthetic-secret"}"#.as_slice(),br#"{"token":"synthetic\u002dsecret"}"#] {
        assert_eq!(inspect_response(&url,StatusCode::CREATED,Some("application/json"),&response_profile(false),raw.to_vec().into(),&guard)
            .err().unwrap()["error"],"response_credential_reflection");
    }
    for (status,limit) in [(StatusCode::CREATED,SUCCESS_BYTES),(StatusCode::TOO_MANY_REQUESTS,ERROR_BYTES)] {
        let mut body=b"{}".to_vec(); body.resize(limit as usize,b' ');
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status!=StatusCode::CREATED),body.clone().into(),&guard).is_ok());
        body.push(b' '); assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status!=StatusCode::CREATED),body.into(),&guard).is_err());
    }
}

fn decision(held:&Snapshot)->Value {
    let (operation,canonical)=admitted(request(),held).unwrap();
    json!({"allowed":true,"action":"allow","adapter":ADAPTER,"principal_id":"agent:test","route_id":"route:test",
        "policy_hash":held.hash,"snapshot_epoch":held.epoch,"operation":operation,"canonical_request":canonical,
        "request_digest":canonical_request_digest_profile(&canonical,ReleaseProfile::Legacy),
        "operation_digest":operation_digest_profile(&canonical,ReleaseProfile::Legacy)})
}
fn upstream(status:u16,extra:&str,body:&[u8])->reqwest::blocking::Response {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap();
    let mut wire=format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).into_bytes(); wire.extend_from_slice(body);
    let worker=thread::spawn(move || {
        let deadline=Instant::now()+Duration::from_secs(4);
        let mut stream=loop {match listener.accept(){Ok((stream,_))=>break stream,
            Err(e) if e.kind()==io::ErrorKind::WouldBlock && Instant::now()<deadline=>thread::sleep(Duration::from_millis(2)),
            Err(e)=>panic!("bounded local receiver: {e}")}};
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap(); stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        read_request_head_from(&mut stream,None).unwrap(); stream.write_all(&wire).unwrap();
    });
    let response=Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .post(format!("http://{address}/fixture")).send().unwrap(); worker.join().unwrap(); response
}
fn finalized(held:&Arc<Snapshot>,state:&GateState,decision:&Value,response:reqwest::blocking::Response,guard:&ResponseSecretGuard)->SensitiveResponseBytes {
    match finalize_upstream_response(state,held,decision,"POST",&Url::parse(TARGET).unwrap(),response,guard,
        None,None,None,None,None,None,None,None,None,false) {
        ForwardResult::Buffered(wire)=>wire,ForwardResult::Streamed=>panic!("X post must buffer")
    }
}
#[test]
fn x_post_real_finalizer_preserves_whole_created_and_error_objects() {
    let held=snapshot(); let state=test_gate_state(held.clone()); let decision=decision(&held);
    for (status,body) in [(201,br#" {"data":{"id":"123","text":"hello"},"extra":1e0} "#.as_slice()),
        (402,br#"{"title":"credits required"}"#),(429,br#"{"error":"rate limit"}"#)] {
        let wire=finalized(&held,&state,&decision,upstream(status,"Content-Type: application/json; charset=utf-8\r\nServer: fixture\r\n",body),&ResponseSecretGuard::default());
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,status); assert_eq!(parsed.body,body);
        assert!(!parsed.headers.contains_key("server"));
    }
}
#[test]
fn x_post_real_finalizer_blocks_unsafe_replies_as_unknown_without_retry() {
    let held=snapshot(); let state=test_gate_state(held.clone()); let decision=decision(&held);
    let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for (status,headers,body) in [
        (200,"Content-Type: application/json\r\n",b"{}".as_slice()),
        (201,"Content-Type: application/json\r\nContent-Encoding: gzip\r\n",b"{}"),
        (201,"Content-Type: application/json\r\nContent-Type: application/json\r\n",b"{}"),
        (201,"Content-Type: application/json\r\n",br#"{"token":"synthetic\u002dsecret"}"#),
        (201,"Content-Type: application/json\r\nX-Discard: synthetic-secret\r\n",b"{}"),
        (201,"Content-Type: application/json\r\n",b"[]"),
    ] {
        let wire=finalized(&held,&state,&decision,upstream(status,headers,body),&guard);
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,409);
        let value:Value=serde_json::from_slice(&parsed.body).unwrap();
        assert_eq!(value["providerOutcome"],"unknown"); assert_eq!(value["retryProviderRequest"],false);
        assert_eq!(value["providerOperationMayHaveCommitted"],true);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-secret"));
    }
}
