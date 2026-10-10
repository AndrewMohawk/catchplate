//! Shared protocol vectors and inert preparation / bounded loopback finalizers.
//! These synthetic fixtures do not contact X or assert provider entitlement.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const CREDENTIAL: &str = "credential:x-test";
const NAME: &str = "fixture_user";
const TARGET: &str = "https://api.x.com/2/users/by/username/fixture_user";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../scripts/fixtures/x_app_read_v1.json")).unwrap()
}

fn config() -> Value {
    let fixture = vectors();
    json!({"credentialBinding":fixture["credentialBinding"],"username":NAME,
        "request":request_config(),"response":response_profile(false)})
}

fn route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into(); route.adapter_config = config(); route.host = HOST.into();
    route.methods = HashSet::from(["GET".into()]); route.paths = vec![compile_template(&path(NAME)).unwrap()];
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = DISCARD.iter().map(|name| name.to_string()).collect();
    route.constraints = vec![envelope("x-read-response")]; route.jit = json!({});
    route
}

fn snapshot() -> Arc<Snapshot> {
    let mut value = (*test_snapshot(1)).clone(); value.routes = vec![route()];
    value.credentials.insert(CREDENTIAL.into(), Credential {provider:"operator-demo".into(),
        provider_subject:Some("synthetic-x-subject".into()),
        injection:json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"})});
    Arc::new(value)
}

fn policy() -> Value {
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":HOST,"port":443,"methods":["GET"],"paths":[path(NAME)]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope("x-read-response")]});
    let mut value = policy_with_route(wire.clone()); value["routes"] = json!([wire]);
    value["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
        "providerSubject":"synthetic-x-subject","injection":{"type":"bearer","header":"Authorization"}}]);
    value
}

fn request() -> DecisionRequest {
    serde_json::from_value(json!({"method":"GET","url":TARGET,
        "headers":{"authorization":PLACEHOLDER,"accept":"application/json","content-type":"application/json",
            "user-agent":"synthetic-x-sdk/1","accept-encoding":"gzip,deflate"}})).unwrap()
}

fn admitted(mut req: DecisionRequest, snapshot: &Snapshot) -> Result<(Value, Value), String> {
    let route = &snapshot.routes[0];
    let (_, url) = parse_validated_absolute_target(&req.url).map_err(|_| "target")?;
    credential_header_replacement::remove_for_route(snapshot,route,&snapshot.principals[0],&mut req.headers)
        .map_err(|_| "replacement")?;
    req.headers = discard_declared_request_headers(&req.headers,&route.discard_headers).map_err(|_| "discard")?;
    validate_provider_request_admission(&req,&url,route).map_err(|_| "admission")?;
    let headers = canonical_forwarded_request_headers(&req.headers,&url,
        decision_request_body_length(&req).map_err(|_| "framing")?,&snapshot.credentials[CREDENTIAL].injection)
        .map_err(|_| "canonical headers")?;
    let matched = RouteMatch {route,params:route.paths[0].matches_canonical(url.path()).ok_or("path")?};
    let (operation,rewrite) = validate_adapter(&req,&headers,&url,&matched).map_err(|_| "adapter")?;
    assert_eq!(rewrite,json!({}));
    let canonical = canonical_request(&req,&headers,&url,&snapshot.principals[0],route,7,&snapshot.hash,&operation);
    Ok((operation,canonical))
}

#[test]
fn x_app_read_shared_request_response_vectors_and_profile_parity() {
    let fixture = vectors(); let snapshot = snapshot();
    assert_eq!(fixture["request"],request_config()); assert_eq!(fixture["response"],response_profile(false));
    assert_eq!(fixture["adapter"],ADAPTER); assert_eq!(fixture["replacement"],route().credential_header.unwrap());
    for case in fixture["requests"].as_array().unwrap() {
        let mut req = request(); req.method=case["method"].as_str().unwrap().into();
        req.url=case["url"].as_str().unwrap().into(); req.body=case["body"].as_str().unwrap().into();
        req.headers.clear(); req.headers.insert("authorization".into(),PLACEHOLDER.into());
        for pair in case["headers"].as_array().unwrap() {
            assert!(req.headers.insert(pair[0].as_str().unwrap().into(),pair[1].as_str().unwrap().into()).is_none());
        }
        let result=admitted(req,&snapshot);
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok((operation,_))=result { assert_eq!(operation,fixture["operation"]); }
    }
    let url=Url::parse(TARGET).unwrap();
    for case in fixture["responses"].as_array().unwrap() {
        let status=StatusCode::from_u16(case["status"].as_u64().unwrap() as u16).unwrap();
        let raw=case["body"].as_str().unwrap().as_bytes();
        let result=inspect_response(&url,status,case["content_type"].as_str(),
            &response_profile(status.is_client_error()||status.is_server_error()),raw.to_vec().into(),&ResponseSecretGuard::default());
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok(body)=result { assert_eq!(&*body,raw); }
    }
}

#[test]
fn x_app_read_closed_contract_and_startup_v1_v2_schema_compile() {
    validate_policy_capabilities(&policy()).unwrap(); validate_route(&route()).unwrap();
    validate_route_response_release_mode(&route()).unwrap();
    let embedded=closed_embedded_policy_schema().unwrap();
    assert_eq!(embedded["$defs"]["adapter_x_app_read_v1__root"]["properties"]["username"]["$ref"],
        "#/$defs/adapter_x_app_read_v1__username");
    for version in ["serverware.policy/v1",policy_route_authority::BUNDLE] {
        let mut raw=policy(); raw["apiVersion"]=json!(version); raw["kind"]=json!("PolicyBundle");
        raw["metadata"]=json!({"id":"x-read-startup","sequence":1,"rollbackEpoch":1});
        if version==policy_route_authority::BUNDLE {
            let pin=format!("sha256:{}","0".repeat(64));
            raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
                "mappingSha256":pin,"routeAuthorityRootSha256":pin,"operationAuthorityRootSha256":pin});
        }
        validate_policy_schema(&raw).expect("actual startup compiler must resolve the new schema");
        for name in ["", "Fixture", "has-dot", "sixteen_chars___", "a/b", "é"] {
            let mut changed=raw.clone(); changed["routes"][0]["adapter"]["config"]["username"]=json!(name);
            assert!(validate_policy_schema(&changed).is_err(),"{name}");
        }
        let mut changed=raw; changed["routes"][0]["adapter"]["config"]["extra"]=json!(true);
        assert!(validate_policy_schema(&changed).is_err());
    }
    for (pointer,value) in [
        ("/routes/0/match/host",json!("api.twitter.com")),("/routes/0/match/port",json!(444)),
        ("/routes/0/match/methods",json!(["GET","HEAD"])),("/routes/0/match/paths",json!(["/2/users/by/username/{username}"])),
        ("/routes/0/credentialHeader/expectedValue",json!("Bearer different")),
        ("/routes/0/adapter/config/request/maxBodyBytes",json!(1)),
        ("/routes/0/adapter/config/request/allowedMediaTypes",json!([])),
        ("/routes/0/adapter/config/request/allowedQueryKeys",json!(["user.fields"])),
        ("/routes/0/adapter/config/response/mode",json!("json")),
        ("/routes/0/adapter/config/response/error/maxBodyBytes",json!(65537)),
        ("/credentials/0/provider",json!("x")),("/credentials/0/providerSubject",json!("other")),
        ("/credentials/0/injection/type",json!("header")),("/credentials/0/injection/header",json!("X-Token")),
        ("/routes/0/constraints/0/contentTypePolicy",json!("npmJsonUtf8V1")),
        ("/routes/0/constraints/0/statusCodes",json!([200,201])),
    ] { let mut changed=policy(); *changed.pointer_mut(pointer).unwrap()=value;
        assert!(validate_policy_capabilities(&changed).is_err(),"{pointer}"); }
    for field in ["jit","responseObservation"] { let mut changed=policy(); changed["routes"][0][field]=json!({});
        assert!(validate_policy_capabilities(&changed).is_err()); }
    for field in ["prefix","field"] { let mut changed=policy(); changed["credentials"][0]["injection"][field]=json!("token");
        assert!(validate_policy_capabilities(&changed).is_err()); }
}

#[test]
fn x_app_read_signed_v2_authority_is_exact_read() {
    let pin=|value:&Value| sha256_prefixed(policy_route_authority::canonical(value).unwrap().as_bytes());
    let mut raw=policy(); raw["apiVersion"]=json!(policy_route_authority::BUNDLE);
    let operations=json!([{"operationName":OPERATION,"operation":"read","requestAuthorityClass":"read"}]);
    let profile=json!({"apiVersion":"serverware.compiledRouteAuthority/v1",
        "routeSha256":sha256_prefixed(b"route:test"),"signedRouteSha256":pin(&raw["routes"][0]),
        "adapterType":ADAPTER,"operations":operations,"signedPrincipalsSha256":pin(&raw["principals"]),
        "signedCredentialsSha256":pin(&raw["credentials"]),"signedDefaultsSha256":pin(&raw["defaults"]),
        "principalSha256s":[sha256_prefixed(b"agent:test")]});
    let profile_pin=pin(&profile);
    let profiles=json!([{"routeId":"route:test","compiledSemanticProfileSha256":profile_pin,"profile":profile}]);
    let entries=json!([{"routeSha256":profile["routeSha256"],"compiledSemanticProfileSha256":profile_pin,
        "operationName":OPERATION,"operation":"read","requestAuthorityClass":"read"}]);
    raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
        "mappingSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthority/v1","profiles":profiles})),
        "routeAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles})),
        "operationAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))});
    let snapshot=snapshot(); let compiled=policy_route_authority::admit(&raw,&snapshot.routes).unwrap().unwrap();
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&vectors()["operation"]).is_ok());
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&json!({"operation":"tweets.write"})).is_err());
    let mut changed=raw.clone(); changed["routeAuthority"]["genericOperations"]=json!([
        {"routeId":"route:test","operationName":OPERATION,"operation":"write"}]);
    assert!(policy_route_authority::admit(&changed,&snapshot.routes).is_err());
    raw["routes"][0]["adapter"]["config"]["username"]=json!("other");
    assert!(policy_route_authority::admit(&raw,&snapshot.routes).is_err());
}

#[test]
fn x_app_read_denials_precede_generation_lease_and_quota() {
    let snapshot=snapshot(); let state=test_gate_state(Arc::clone(&snapshot));
    for case in vectors()["requests"].as_array().unwrap().iter().filter(|case|case["allowed"]==false) {
        let mut req=request(); req.method=case["method"].as_str().unwrap().into(); req.url=case["url"].as_str().unwrap().into();
        req.body=case["body"].as_str().unwrap().into(); req.headers.clear(); req.headers.insert("authorization".into(),PLACEHOLDER.into());
        for pair in case["headers"].as_array().unwrap() { req.headers.insert(pair[0].as_str().unwrap().into(),pair[1].as_str().unwrap().into()); }
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false,"{}",case["id"]);
    }
    for (name,value) in [("authorization","Bearer wrong".into()),("user-agent","bad\r\nvalue".into()),
        ("user-agent","x".repeat(MAX_CANONICAL_REQUEST_HEADER_VALUE_BYTES+1)),("x-extra","forbidden".into())] {
        let mut req=request(); req.headers.insert(name.into(),value);
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false);
    }
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed),0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed),0);
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
}

struct InertResolver(AtomicU64);
impl UpstreamResolver for InertResolver {
    fn resolve(&self,host:&str,port:u16)->Result<Vec<SocketAddr>,String> {
        assert_eq!((host,port),(HOST,443)); self.0.fetch_add(1,Ordering::Relaxed);
        Ok(vec!["127.0.0.1:443".parse().unwrap()])
    }
}

#[test]
fn x_app_read_actual_buffered_and_head_preparation_allow_optional_json_only_without_body() {
    let mut held=(*snapshot()).clone();
    held.routes[0].resolved_address_policy=ResolvedAddressPolicy::ExplicitCidrs(vec!["127.0.0.1/32".parse().unwrap()]);
    let snapshot=Arc::new(held); let mut state=test_gate_state(Arc::clone(&snapshot));
    let resolver=Arc::new(InertResolver(AtomicU64::new(0))); state.upstream_resolver=resolver.clone();
    let req=request(); let url=Url::parse(TARGET).unwrap();
    let mut incoming=IncomingRequest {method:"GET".into(),target:TARGET.into(),headers:req.headers.clone(),body:vec![],client_ip:None};
    for media in [None,Some("application/json"),Some("APPLICATION/JSON; charset=UTF-8")] {
        incoming.headers.remove("content-type");
        if let Some(media)=media { incoming.headers.insert("content-type".into(),media.into()); }
        assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&incoming,&url,Some("agent:test")).unwrap().is_some());
        let mut head=RequestHead {method:"GET".into(),target:TARGET.into(),http_version:"HTTP/1.1".into(),
            headers:incoming.headers.clone(),raw_headers_digest:None,raw_header_count:0,content_length:0,
            has_content_length:false,prefetched_body:vec![],client_ip:None};
        assert!(prepare_upstream_for_forward(&state,&snapshot,&head,&url,Some("agent:test")).unwrap().is_some());
        head.content_length=1;
        assert!(prepare_upstream_for_forward(&state,&snapshot,&head,&url,Some("agent:test")).unwrap().is_none());
    }
    assert_eq!(resolver.0.load(Ordering::Relaxed),6);
    for variant in 0..5 {
        let mut changed=IncomingRequest {method:"GET".into(),target:TARGET.into(),headers:req.headers.clone(),body:vec![],client_ip:None};
        match variant {
            0=>changed.body=b"{}".to_vec(),
            1=>{changed.headers.insert("content-type".into(),"text/plain".into());},
            2=>{changed.headers.insert("Content-Type".into(),"application/json".into());},
            3=>{changed.headers.insert("content-type".into(),"application/json; charset=latin-1".into());},
            _=>{changed.headers.insert("authorization".into(),"Bearer wrong".into());},
        }
        assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&changed,&url,Some("agent:test")).unwrap().is_none());
    }
    assert_eq!(resolver.0.load(Ordering::Relaxed),6);
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert_eq!(buffered_route_body_limit(&snapshot,&RequestHead {method:"GET".into(),target:TARGET.into(),
        http_version:"HTTP/1.1".into(),headers:req.headers.clone(),raw_headers_digest:None,raw_header_count:0,
        content_length:0,has_content_length:false,prefetched_body:vec![],client_ip:None},Some("agent:test")),0);
}

#[test]
fn x_app_read_strict_json_bounds_and_raw_decoded_reflection() {
    let url=Url::parse(TARGET).unwrap(); let mut guard=ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-secret");
    for raw in [br#"{"token":"synthetic-secret"}"#.as_slice(),br#"{"token":"synthetic\u002dsecret"}"#] {
        assert_eq!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),
            raw.to_vec().into(),&guard).err().unwrap()["error"],"response_credential_reflection");
    }
    for (status,limit) in [(StatusCode::OK,SUCCESS_BYTES),(StatusCode::BAD_REQUEST,ERROR_BYTES)] {
        let mut raw=b"{\"x\":\"".to_vec(); raw.extend(std::iter::repeat(b'a').take(limit as usize-8)); raw.extend_from_slice(b"\"}");
        assert_eq!(raw.len(),limit as usize);
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status!=StatusCode::OK),
            raw.clone().into(),&guard).is_ok());
        raw.push(b' ');
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status!=StatusCode::OK),raw.into(),&guard).is_err());
    }
    for status in STATUSES {
        let status=StatusCode::from_u16(*status).unwrap();
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status!=StatusCode::OK),
            b"{}".to_vec().into(),&guard).is_ok());
    }
}

fn fixture() -> (Arc<Snapshot>,GateState,Value,Url) {
    let snapshot=snapshot(); let state=test_gate_state(Arc::clone(&snapshot));
    let decision=json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic-request","operation_digest":"sha256:synthetic-operation",
        "operation":{"operation":OPERATION,"username":NAME},"canonical_request":{"request":{
            "method":"GET","scheme":"https","authority":HOST,"path":path(NAME)}}});
    (snapshot,state,decision,Url::parse(TARGET).unwrap())
}

fn upstream(status:u16,extra:&str,body:&[u8])->reqwest::blocking::Response {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap();
    let mut wire=format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).into_bytes();
    wire.extend_from_slice(body);
    let server=thread::spawn(move || {
        let deadline=Instant::now()+Duration::from_secs(4);
        let mut stream=loop { match listener.accept() {
            Ok((stream,_))=>break stream,
            Err(error) if error.kind()==io::ErrorKind::WouldBlock && Instant::now()<deadline=>thread::sleep(Duration::from_millis(2)),
            Err(error)=>panic!("bounded local response fixture: {error}"),
        }};
        stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        read_request_head_from(&mut stream,None).unwrap(); stream.write_all(&wire).unwrap();
    });
    let response=Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .get(format!("http://{address}/fixture")).send().unwrap(); server.join().unwrap(); response
}

fn finalized(snapshot:&Arc<Snapshot>,state:&GateState,decision:&Value,url:&Url,
    response:reqwest::blocking::Response,guard:&ResponseSecretGuard)->SensitiveResponseBytes {
    match finalize_upstream_response(state,snapshot,decision,"GET",url,response,guard,None,None,None,None,None,None,
        None,None,None,false) { ForwardResult::Buffered(wire)=>wire,ForwardResult::Streamed=>panic!("X read must buffer") }
}

#[test]
fn x_app_read_real_finalizer_preserves_whole_objects_and_discards_metadata() {
    let (snapshot,state,decision,url)=fixture();
    for (status,body) in [(200,br#" {"errors":[{"title":"Not found"}],"number":1e0} "#.as_slice()),
        (200,br#"{"data":{"username":"different"},"future":true}"#),(429,br#"{"title":"rate limit"}"#)] {
        let wire=finalized(&snapshot,&state,&decision,&url,upstream(status,
            "Content-Type: application/json; charset=utf-8\r\nServer: synthetic\r\nX-Cache: ordinary\r\n",body),&ResponseSecretGuard::default());
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,status); assert_eq!(parsed.body,body);
        assert_eq!(parsed.headers.get("content-type").map(SensitiveString::as_str),Some("application/json"));
        assert!(!parsed.headers.contains_key("server")); assert!(!parsed.headers.contains_key("x-cache"));
    }
}

#[test]
fn x_app_read_real_finalizer_keeps_metadata_media_status_and_snapshot_guards() {
    let (snapshot,state,decision,url)=fixture(); let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for header in ["Content-Type: application/json\r\nX-Discarded: synthetic-secret\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n", "Content-Type: application/json\r\nSet-Cookie: x=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n", "Content-Type: application/problem+json\r\n"] {
        let wire=finalized(&snapshot,&state,&decision,&url,upstream(200,header,b"{}"),&guard);
        assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-secret"));
    }
    for (status,body) in [(201,b"{}".as_slice()),(204,b""),(302,b"{}"),(200,b"[]"),(404,b"not JSON")] {
        let wire=finalized(&snapshot,&state,&decision,&url,upstream(status,"Content-Type: application/json\r\n",body),&guard);
        assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
    }
    *state.snapshot.write().unwrap()=test_snapshot(2);
    let wire=finalized(&snapshot,&state,&decision,&url,upstream(200,"Content-Type: application/json\r\n",b"{}"),&guard);
    let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,502);
    assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],"response_snapshot_revoked");
}

#[test]
fn x_app_read_has_no_legacy_mode_or_proof_shortcut() {
    for adapter in ["generic.rest","x.v2","gmail.read.v1","npm.registry","npm.metadata.v1","npm.publish.v1"] {
        assert!(buffered_response::validate_envelope_pairing(adapter,Some(MODE),&[envelope("x")]).is_err());
        let mut changed=route(); changed.adapter_type=adapter.into();
        assert!(validate_route_response_release_mode(&changed).is_err());
    }
    for mode in ["json","bufferedJsonOrEmpty204V2",npm_metadata::MODE] {
        assert!(buffered_response::validate_envelope_pairing(ADAPTER,Some(mode),&[envelope("x")]).is_err());
    }
    // The existing unmarked generic no-body fixture still refuses JSON media.
    let generic=test_snapshot(1).routes[0].clone();
    assert!(validate_generic_request_media_admission(generic.adapter_config["request"].as_object().unwrap(),
        &BTreeMap::from([("content-type".into(),"application/json".into())]),"none",0).is_err());
    let (snapshot,_,_,_)=fixture(); let matched=RouteMatch{route:&snapshot.routes[0],params:BTreeMap::new()};
    for kind in [ResponseProofKind::Buffered,ResponseProofKind::Streaming,ResponseProofKind::Observation] {
        assert_eq!(validate_response_proof_route_preflight(&matched,kind),Err("response_metadata_v2_proof_unsupported"));
    }
    assert!(!reuse_idle_upstream_connections(&snapshot.routes[0],"GET"));
}

#[test]
fn x_app_read_canonical_discard_replacement_and_original_empty_body_binding() {
    let snapshot=snapshot(); let (_,canonical)=admitted(request(),&snapshot).unwrap();
    assert_eq!(canonical["v"],2);
    assert_eq!(canonical["request"]["discard_headers"],json!(DISCARD));
    assert_eq!(canonical["operation"],vectors()["operation"]);
    assert!(!canonical.to_string().contains(PLACEHOLDER));
    let mut changed=request(); changed.headers.insert("accept-encoding".into(),"br".into());
    assert_eq!(canonical_request_digest_profile(&canonical,ReleaseProfile::Legacy),
        canonical_request_digest_profile(&admitted(changed,&snapshot).unwrap().1,ReleaseProfile::Legacy));
    let decision=json!({"canonical_request":canonical});
    validate_buffered_body_binding(&decision,b"").unwrap();
    assert!(validate_buffered_body_binding(&decision,b"{}").is_err());
    let mut req=request(); req.headers.remove("authorization");
    assert!(admitted(req,&snapshot).is_err());
    let req=request(); let url=Url::parse(TARGET).unwrap();
    let matched=RouteMatch{route:&snapshot.routes[0],params:BTreeMap::from([("username".into(),NAME.into())])};
    assert!(normalize_request(&req,&url,&matched).is_err());
}

#[test]
fn x_app_read_health_marker_is_exact_compiled_support_not_provider_readiness() {
    let expected=json!({"schema":"serverware.operatorXAppReadGate/v1","adapter":"x.app_read.v1","operation":"x.username.read"});
    assert_eq!(gate_capability(),expected);
    // The real health producer advertises support even when no X rule exists.
    let snapshot=test_snapshot(1); let state=test_gate_state(Arc::clone(&snapshot));
    let wire=health_response(&state); let parsed=parse_buffered_response(&wire).unwrap();
    let body:Value=serde_json::from_slice(&parsed.body).unwrap();
    assert_eq!(body["operator_x_app_read"],expected);
    assert_eq!(body["policy_hash"],snapshot.hash);
    assert_eq!(body["routes"],1);
}
