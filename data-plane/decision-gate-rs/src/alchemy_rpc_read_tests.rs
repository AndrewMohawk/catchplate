//! Shared strict JSON vectors, inert admission and bounded local finalizers.
//! No Alchemy contact, provider entitlement or live installation is asserted.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const CREDENTIAL: &str = "credential:alchemy-test";
const SUBJECT: &str = "synthetic-alchemy-subject";
const CHAIN: &str = "eth-mainnet";
const TARGET: &str = "https://eth-mainnet.g.alchemy.com/v2";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../scripts/fixtures/alchemy_rpc_read_v1.json")).unwrap()
}

fn config() -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":[SUBJECT],"secretClass":"bearerToken"},"chain":CHAIN,
        "request":request_config(),"response":response_profile(false)})
}

fn route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into(); route.adapter_config = config(); route.host = host(CHAIN).unwrap().into();
    route.methods = HashSet::from(["POST".into()]); route.paths = vec![compile_template(PATH).unwrap()];
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = DISCARD.iter().map(|name| name.to_string()).collect();
    route.constraints = vec![envelope("alchemy-read-response")]; route.jit = json!({});
    route
}

fn snapshot() -> Arc<Snapshot> {
    let mut value = (*test_snapshot(1)).clone(); value.routes = vec![route()];
    value.credentials.insert(CREDENTIAL.into(), Credential {provider:"operator-demo".into(),
        provider_subject:Some(SUBJECT.into()),
        injection:json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"})});
    Arc::new(value)
}

fn policy() -> Value {
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":host(CHAIN).unwrap(),"port":443,"methods":["POST"],"paths":[PATH]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope("alchemy-read-response")]});
    let mut value = policy_with_route(wire.clone()); value["routes"] = json!([wire]);
    value["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
        "providerSubject":SUBJECT,"injection":{"type":"bearer","header":"Authorization"}}]);
    value
}

fn operation(id: Value) -> Value {
    json!({"operation":OPERATION,"chain":CHAIN,"method":"eth_chainId","requestId":id})
}

fn request() -> DecisionRequest {
    serde_json::from_value(json!({"method":"POST","url":TARGET,
        "headers":{"authorization":PLACEHOLDER,"accept":"application/json","content-type":"application/json",
            "user-agent":"synthetic-alchemy-sdk/1","accept-encoding":"gzip,deflate"},
        "body":" {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]} "})).unwrap()
}

fn vector_request(case: &Value) -> DecisionRequest {
    let mut req = request(); req.method = case["method"].as_str().unwrap().into();
    req.url = case["url"].as_str().unwrap().into(); req.body = case["body"].as_str().unwrap().into();
    req.headers.clear(); req.headers.insert("authorization".into(), PLACEHOLDER.into());
    for pair in case["headers"].as_array().unwrap() {
        assert!(req.headers.insert(pair[0].as_str().unwrap().into(), pair[1].as_str().unwrap().into()).is_none());
    }
    req
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
fn alchemy_rpc_read_shared_request_response_vectors() {
    let fixture = vectors(); let snapshot = snapshot();
    assert_eq!(fixture["adapter"],ADAPTER); assert_eq!(fixture["request"],request_config());
    assert_eq!(fixture["response"],response_profile(false));
    assert_eq!(fixture["credentialBinding"],config()["credentialBinding"]);
    assert_eq!(fixture["operation"],operation(json!(1)));
    assert_eq!(fixture["replacement"],route().credential_header.unwrap());
    for case in fixture["requests"].as_array().unwrap() {
        let result = admitted(vector_request(case),&snapshot);
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok((operation,_)) = result { assert_eq!(operation,case["operation"],"{}",case["id"]); }
    }
    let url = Url::parse(TARGET).unwrap();
    for case in fixture["responses"].as_array().unwrap() {
        let status = StatusCode::from_u16(case["status"].as_u64().unwrap() as u16).unwrap();
        let raw = case["body"].as_str().unwrap().as_bytes();
        let result = inspect_response(&url,status,case["content_type"].as_str(),
            &response_profile(status != StatusCode::OK),&operation(case["request_id"].clone()),
            raw.to_vec().into(),&ResponseSecretGuard::default());
        assert_eq!(result.is_ok(),case["allowed"].as_bool().unwrap(),"{}",case["id"]);
        if let Ok(body) = result { assert_eq!(&*body,raw); }
    }
}

#[test]
fn alchemy_rpc_read_closed_policy_and_actual_startup_schemas() {
    validate_policy_capabilities(&policy()).unwrap(); validate_route(&route()).unwrap();
    validate_route_response_release_mode(&route()).unwrap();
    let embedded = closed_embedded_policy_schema().unwrap();
    assert_eq!(embedded["$defs"]["adapter_alchemy_rpc_read_v1__root"]["properties"]["chain"]["$ref"],
        "#/$defs/adapter_alchemy_rpc_read_v1__chain");
    for version in ["serverware.policy/v1",policy_route_authority::BUNDLE] {
        let mut raw = policy(); raw["apiVersion"] = json!(version); raw["kind"] = json!("PolicyBundle");
        raw["metadata"] = json!({"id":"alchemy-read-startup","sequence":1,"rollbackEpoch":1});
        if version == policy_route_authority::BUNDLE {
            let pin = format!("sha256:{}","0".repeat(64));
            raw["routeAuthority"] = json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
                "mappingSha256":pin,"routeAuthorityRootSha256":pin,"operationAuthorityRootSha256":pin});
        }
        validate_policy_schema(&raw).expect("actual startup schema must resolve Alchemy");
        for chain in ["", "ETH-mainnet", "eth-goerli", "eth-mainnet.g.alchemy.com"] {
            let mut changed = raw.clone(); changed["routes"][0]["adapter"]["config"]["chain"] = json!(chain);
            assert!(validate_policy_schema(&changed).is_err(),"{chain}");
        }
    }
    for (pointer,value) in [
        ("/routes/0/match/host",json!("eth-sepolia.g.alchemy.com")),("/routes/0/match/port",json!(444)),
        ("/routes/0/match/methods",json!(["POST","GET"])),("/routes/0/match/paths",json!(["/v2/{key}"])),
        ("/routes/0/credentialHeader/expectedValue",json!("Bearer different")),
        ("/routes/0/adapter/config/request/maxBodyBytes",json!(65537)),
        ("/routes/0/adapter/config/request/maxBodyBytes",json!(65536.0)),
        ("/routes/0/adapter/config/request/allowedHeaders",json!(["authorization"])),
        ("/routes/0/adapter/config/response/mode",json!("json")),
        ("/routes/0/adapter/config/response/maxBodyBytes",json!(65536.0)),
        ("/routes/0/adapter/config/response/error/maxBodyBytes",json!(65537)),
        ("/routes/0/adapter/config/response/error/maxBodyBytes",json!(65536.0)),
        ("/credentials/0/provider",json!("alchemy")),("/credentials/0/providerSubject",json!("other")),
        ("/credentials/0/injection/type",json!("header")),("/credentials/0/injection/header",json!("X-Key")),
        ("/routes/0/constraints/0/contentTypePolicy",json!("xAppReadJsonUtf8V1")),
        ("/routes/0/constraints/0/statusCodes",json!([200,201])),
    ] { let mut changed = policy(); *changed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_policy_capabilities(&changed).is_err(),"{pointer}"); }
    for field in ["jit","responseObservation"] { let mut changed = policy(); changed["routes"][0][field] = json!({});
        assert!(validate_policy_capabilities(&changed).is_err()); }
    let mut changed = policy(); changed["routes"][0]["adapter"]["config"]["extra"] = json!(true);
    assert!(validate_policy_capabilities(&changed).is_err());
}

#[test]
fn alchemy_rpc_read_both_exact_chains_and_methods_only() {
    for chain in ["eth-mainnet","eth-sepolia"] {
        let mut held = (*snapshot()).clone(); held.routes[0].adapter_config["chain"] = json!(chain);
        held.routes[0].host = host(chain).unwrap().into();
        for method in ["eth_chainId","eth_blockNumber"] {
            let mut req = request(); req.url = format!("https://{}/v2",host(chain).unwrap());
            req.body = json!({"jsonrpc":"2.0","id":"typed-id","method":method,"params":[]}).to_string();
            assert_eq!(admitted(req,&held).unwrap().0,
                json!({"operation":OPERATION,"chain":chain,"method":method,"requestId":"typed-id"}));
        }
    }
    for id in [json!(null),json!(true),json!(-1),json!(1.0),json!(9_007_199_254_740_992_u64),json!(""),
        json!("a".repeat(65)),json!("é"),json!("\n")] { assert!(!request_id(&id),"{id}"); }
    for id in [json!(0),json!(9_007_199_254_740_991_u64),json!(" "),json!("a".repeat(64))] {
        assert!(request_id(&id),"{id}");
    }
}

#[test]
fn alchemy_rpc_read_signed_v2_authority_is_read_despite_post() {
    let pin = |value:&Value| sha256_prefixed(policy_route_authority::canonical(value).unwrap().as_bytes());
    let mut raw = policy(); raw["apiVersion"] = json!(policy_route_authority::BUNDLE);
    let operations = json!([{"operationName":OPERATION,"operation":"read","requestAuthorityClass":"read"}]);
    let profile = json!({"apiVersion":"serverware.compiledRouteAuthority/v1",
        "routeSha256":sha256_prefixed(b"route:test"),"signedRouteSha256":pin(&raw["routes"][0]),
        "adapterType":ADAPTER,"operations":operations,"signedPrincipalsSha256":pin(&raw["principals"]),
        "signedCredentialsSha256":pin(&raw["credentials"]),"signedDefaultsSha256":pin(&raw["defaults"]),
        "principalSha256s":[sha256_prefixed(b"agent:test")]});
    let profile_pin = pin(&profile);
    let profiles = json!([{"routeId":"route:test","compiledSemanticProfileSha256":profile_pin,"profile":profile}]);
    let entries = json!([{"routeSha256":profile["routeSha256"],"compiledSemanticProfileSha256":profile_pin,
        "operationName":OPERATION,"operation":"read","requestAuthorityClass":"read"}]);
    raw["routeAuthority"] = json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
        "mappingSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthority/v1","profiles":profiles})),
        "routeAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles})),
        "operationAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))});
    let snapshot = snapshot(); let compiled = policy_route_authority::admit(&raw,&snapshot.routes).unwrap().unwrap();
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&operation(json!(1))).is_ok());
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&json!({"operation":"alchemy.transaction.write"})).is_err());
    raw["routeAuthority"]["genericOperations"] = json!([{"routeId":"route:test","operationName":OPERATION,"operation":"write"}]);
    assert!(policy_route_authority::admit(&raw,&snapshot.routes).is_err());
}

#[test]
fn alchemy_rpc_read_denials_precede_credential_generation_and_quota() {
    let snapshot = snapshot(); let state = test_gate_state(Arc::clone(&snapshot));
    for case in vectors()["requests"].as_array().unwrap().iter().filter(|case|case["allowed"] == false) {
        assert_eq!(decide_internal(&state,&snapshot,vector_request(case),Some("agent:test"))["allowed"],false,"{}",case["id"]);
    }
    for (name,value) in [("authorization","Bearer wrong".into()),("user-agent","bad\r\nvalue".into()),
        ("user-agent","x".repeat(MAX_CANONICAL_REQUEST_HEADER_VALUE_BYTES+1)),("x-extra","forbidden".into())] {
        let mut req = request(); req.headers.insert(name.into(),value);
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false);
    }
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
    assert!(state.credential_lease_activity.lock().unwrap().is_empty());
    assert!(state.credential_lease_flights.lock().unwrap().is_empty());
    assert!(state.constraint_rate_counters.lock().unwrap().is_empty());
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed),0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed),0);
}

struct InertResolver(AtomicU64);
impl UpstreamResolver for InertResolver {
    fn resolve(&self,selected:&str,port:u16)->Result<Vec<SocketAddr>,String> {
        assert_eq!((selected,port),(host(CHAIN).unwrap(),443)); self.0.fetch_add(1,Ordering::Relaxed);
        Ok(vec!["127.0.0.1:443".parse().unwrap()])
    }
}

#[test]
fn alchemy_rpc_read_head_refuses_and_complete_body_precedes_preparation() {
    let mut held = (*snapshot()).clone();
    held.routes[0].resolved_address_policy = ResolvedAddressPolicy::ExplicitCidrs(vec!["127.0.0.1/32".parse().unwrap()]);
    let snapshot = Arc::new(held); let mut state = test_gate_state(Arc::clone(&snapshot));
    let resolver = Arc::new(InertResolver(AtomicU64::new(0))); state.upstream_resolver = resolver.clone();
    let req = request(); let url = Url::parse(TARGET).unwrap();
    let incoming = IncomingRequest {method:"POST".into(),target:TARGET.into(),headers:req.headers.clone(),
        body:req.body.as_bytes().to_vec(),client_ip:None};
    let head = RequestHead {method:"POST".into(),target:TARGET.into(),http_version:"HTTP/1.1".into(),
        headers:req.headers.clone(),raw_headers_digest:None,raw_header_count:0,content_length:incoming.body.len(),
        has_content_length:true,prefetched_body:incoming.body.clone(),client_ip:None};
    assert!(prepare_upstream_for_forward(&state,&snapshot,&head,&url,Some("agent:test")).unwrap().is_none());
    assert!(prepare_upstream_for_forward_body(&state,&snapshot,&head,&url,Some("agent:test"),
        Some(&incoming.body[..incoming.body.len()-1])).unwrap().is_none());
    assert_eq!(resolver.0.load(Ordering::Relaxed),0);
    for body in [b"".as_slice(),b"[]",b"{}",br#"{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[]}"#] {
        let mut changed = IncomingRequest {body:body.to_vec(),method:"POST".into(),target:TARGET.into(),
            headers:req.headers.clone(),client_ip:None};
        assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&changed,&url,Some("agent:test")).unwrap().is_none());
        changed.headers.remove("content-type");
        assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&changed,&url,Some("agent:test")).unwrap().is_none());
    }
    assert_eq!(resolver.0.load(Ordering::Relaxed),0);
    assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&incoming,&url,Some("agent:test")).unwrap().is_some());
    assert_eq!(resolver.0.load(Ordering::Relaxed),1);
    assert_eq!(buffered_route_body_limit(&snapshot,&head,Some("agent:test")),REQUEST_BYTES);
    assert!(state.credential_leases.lock().unwrap().is_empty());
}

#[test]
fn alchemy_rpc_read_canonical_original_body_and_typed_id_binding() {
    let snapshot = snapshot(); let req = request(); let original = req.body.as_bytes().to_vec();
    let (op,canonical) = admitted(req,&snapshot).unwrap();
    assert_eq!(op,operation(json!(1))); assert_eq!(canonical["v"],2);
    assert_eq!(canonical["request"]["query"],json!([]));
    assert!(canonical["request"].get("query_wire").is_none());
    assert!(canonical["request"].get("query_mode").is_none());
    assert_eq!(canonical["request"]["discard_headers"],json!(DISCARD));
    assert!(!canonical.to_string().contains(PLACEHOLDER));
    validate_buffered_body_binding(&json!({"canonical_request":canonical}),&original).unwrap();
    assert!(validate_buffered_body_binding(&json!({"canonical_request":canonical}),b"{}").is_err());
    let mut changed = request(); changed.body = changed.body.trim().into();
    let (same_op,changed_canonical) = admitted(changed,&snapshot).unwrap();
    assert_eq!(op,same_op); assert_ne!(canonical,changed_canonical);
    let mut changed = request(); changed.body = changed.body.replace("\"id\":1","\"id\":\"1\"");
    assert_ne!(admitted(changed,&snapshot).unwrap().0,op);
    let mut changed = request(); changed.headers.insert("accept-encoding".into(),"br".into());
    assert_eq!(admitted(changed,&snapshot).unwrap().1,canonical);
}

#[test]
fn alchemy_rpc_read_exact_body_limits_and_reflection() {
    let snapshot = snapshot(); let mut req = request();
    req.body.push_str(&" ".repeat(REQUEST_BYTES as usize-req.body.len()));
    assert!(admitted(req.clone(),&snapshot).is_ok()); req.body.push(' ');
    assert!(admitted(req,&snapshot).is_err());
    let url = Url::parse(TARGET).unwrap(); let mut guard = ResponseSecretGuard::default();
    guard.add_text_encodings("synthetic-secret");
    for raw in [br#"{"jsonrpc":"2.0","id":1,"result":"synthetic-secret"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"result":"synthetic\u002dsecret"}"#] {
        assert_eq!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),
            &operation(json!(1)),raw.to_vec().into(),&guard).err().unwrap()["error"],"response_credential_reflection");
    }
    for (status,raw) in [(StatusCode::OK,br#"{"jsonrpc":"2.0","id":1,"result":null}"#.as_slice()),
        (StatusCode::TOO_MANY_REQUESTS,b"{}".as_slice())] {
        let mut body = raw.to_vec(); body.resize(RESPONSE_BYTES as usize,b' ');
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status != StatusCode::OK),
            &operation(json!(1)),body.clone().into(),&guard).is_ok());
        body.push(b' ');
        assert!(inspect_response(&url,status,Some("application/json"),&response_profile(status != StatusCode::OK),
            &operation(json!(1)),body.into(),&guard).is_err());
    }
}

fn upstream(status:u16,extra:&str,body:&[u8])->reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut wire = format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).into_bytes();
    wire.extend_from_slice(body);
    let server = thread::spawn(move || {
        let deadline = Instant::now()+Duration::from_secs(4);
        let mut stream = loop { match listener.accept() {
            Ok((stream,_))=>break stream,
            Err(error) if error.kind()==io::ErrorKind::WouldBlock && Instant::now()<deadline=>thread::sleep(Duration::from_millis(2)),
            Err(error)=>panic!("bounded local response fixture: {error}"),
        }};
        stream.set_nonblocking(false).unwrap(); stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        read_request_head_from(&mut stream,None).unwrap(); stream.write_all(&wire).unwrap();
    });
    let response = Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .post(format!("http://{address}/fixture")).send().unwrap(); server.join().unwrap(); response
}

fn decision(snapshot:&Snapshot) -> Value {
    // Finalizer-only synthetic allow context, with the actual adapter's whole
    // canonical request/operation and digests (not credential acquisition).
    let (operation, canonical) = admitted(request(), snapshot).unwrap();
    json!({"action":"allow","allowed":true,"adapter":ADAPTER,
        "principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,
        "request_digest":canonical_request_digest_profile(&canonical,ReleaseProfile::Legacy),
        "operation_digest":operation_digest_profile(&canonical,ReleaseProfile::Legacy),
        "operation":operation,"canonical_request":canonical})
}

fn finalized(snapshot:&Arc<Snapshot>,state:&GateState,decision:&Value,response:reqwest::blocking::Response,
    guard:&ResponseSecretGuard)->SensitiveResponseBytes {
    match finalize_upstream_response(state,snapshot,decision,"POST",&Url::parse(TARGET).unwrap(),response,guard,
        None,None,None,None,None,None,None,None,None,false) {
        ForwardResult::Buffered(wire)=>wire,ForwardResult::Streamed=>panic!("Alchemy read must buffer")
    }
}

#[test]
fn alchemy_rpc_read_actual_finalizer_preserves_results_and_rpc_errors() {
    let snapshot = snapshot(); let state = test_gate_state(Arc::clone(&snapshot)); let decision = decision(&snapshot);
    for (status,body) in [(200,br#" {"jsonrpc":"2.0","id":1,"result":"0x1","future":1e0} "#.as_slice()),
        (200,br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"fixture","data":[1]}}"#),
        (429,br#"{"message":"rate limit"}"#)] {
        let wire = finalized(&snapshot,&state,&decision,upstream(status,
            "Content-Type: application/json; charset=utf-8\r\nServer: synthetic\r\nX-Cache: ordinary\r\n",body),&ResponseSecretGuard::default());
        let parsed = parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,status); assert_eq!(parsed.body,body);
        assert!(!parsed.headers.contains_key("server")); assert!(!parsed.headers.contains_key("x-cache"));
    }
}

#[test]
fn alchemy_rpc_read_actual_finalizer_keeps_binding_metadata_and_snapshot_guards() {
    let snapshot = snapshot(); let state = test_gate_state(Arc::clone(&snapshot)); let decision = decision(&snapshot);
    let mut guard = ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    let valid = br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#;
    for header in ["Content-Type: application/json\r\nX-Discarded: synthetic-secret\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n", "Content-Type: application/json\r\nSet-Cookie: x=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n", "Content-Type: application/problem+json\r\n"] {
        let wire = finalized(&snapshot,&state,&decision,upstream(200,header,valid),&guard);
        assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-secret"));
    }
    for (status,body) in [(201,valid.as_slice()),(204,b""),(302,b"{}"),(200,b"[]"),(404,b"not JSON"),
        (200,br#"{"jsonrpc":"2.0","id":"1","result":"0x1"}"#),
        (200,br#"{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}"#)] {
        let wire = finalized(&snapshot,&state,&decision,upstream(status,"Content-Type: application/json\r\n",body),&guard);
        assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
    }
    *state.snapshot.write().unwrap() = test_snapshot(2);
    let wire = finalized(&snapshot,&state,&decision,upstream(200,"Content-Type: application/json\r\n",valid),&guard);
    let parsed = parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,502);
    assert_eq!(serde_json::from_slice::<Value>(&parsed.body).unwrap()["error"],"response_snapshot_revoked");
}

#[test]
fn alchemy_rpc_read_no_legacy_mode_or_proof_shortcut() {
    for adapter in ["generic.rest","x.v2","x.app_read.v1","gmail.read.v1","npm.registry","npm.metadata.v1","npm.publish.v1"] {
        assert!(buffered_response::validate_envelope_pairing(adapter,Some(MODE),&[envelope("alchemy")]).is_err());
        let mut changed = route(); changed.adapter_type = adapter.into();
        assert!(validate_route_response_release_mode(&changed).is_err());
    }
    for mode in ["json","bufferedJsonOrEmpty204V2",x_app_read::MODE] {
        assert!(buffered_response::validate_envelope_pairing(ADAPTER,Some(mode),&[envelope("alchemy")]).is_err());
    }
    let snapshot = snapshot(); let matched = RouteMatch {route:&snapshot.routes[0],params:BTreeMap::new()};
    for kind in [ResponseProofKind::Buffered,ResponseProofKind::Streaming,ResponseProofKind::Observation] {
        assert_eq!(validate_response_proof_route_preflight(&matched,kind),Err("response_metadata_v2_proof_unsupported"));
    }
    assert!(!reuse_idle_upstream_connections(&snapshot.routes[0],"POST"));
}

#[test]
fn alchemy_rpc_read_health_is_compiled_support_not_provider_readiness() {
    let expected = json!({"schema":"serverware.operatorAlchemyRpcReadGate/v1","adapter":ADAPTER,"operation":OPERATION});
    assert_eq!(gate_capability(),expected);
    let snapshot = test_snapshot(1); let state = test_gate_state(Arc::clone(&snapshot));
    let wire = health_response(&state); let parsed = parse_buffered_response(&wire).unwrap();
    let body:Value = serde_json::from_slice(&parsed.body).unwrap();
    assert_eq!(body["operator_alchemy_rpc_read"],expected);
    assert_eq!(body["policy_hash"],snapshot.hash); assert_eq!(body["routes"],1);
}
