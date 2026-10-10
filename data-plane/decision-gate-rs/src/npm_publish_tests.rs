//! Synthetic byte fixtures, inert resolver, and bounded loopback finalizers.
//! No real registry, package archive extraction, or provider credentials.
use super::*;
use crate::tests::{policy_with_route, test_gate_state, test_snapshot,
    test_custody_response_proof_signer, test_upstream_client};
use crate::*;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

const CREDENTIAL: &str = "credential:npm-test";
const BASE: &str = "https://registry.npmjs.org";

fn config(package: &str) -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":["synthetic-npm"],"secretClass":"bearerToken"},"package":package,"tag":"latest",
        "request":request_config(),"response":response_profile(false)})
}

fn route(package: &str) -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into(); route.adapter_config = config(package); route.host = HOST.into();
    route.methods = HashSet::from(["PUT".into()]); route.paths = vec![compile_template(PATH).unwrap()];
    route.credential_ref = Some(CREDENTIAL.into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = DISCARD.iter().map(|v| v.to_string()).collect();
    route.constraints = vec![envelope("npm-publish-response")]; route.jit = json!({});
    route
}

fn snapshot(package: &str) -> Arc<Snapshot> {
    let mut snapshot = (*test_snapshot(1)).clone();
    snapshot.routes = vec![route(package)];
    snapshot.credentials.insert(CREDENTIAL.into(), Credential { provider:"operator-demo".into(),
        provider_subject:Some("synthetic-npm".into()),
        injection:json!({"type":"bearer","header":"Authorization","__serverwareCredentialType":"static"}) });
    Arc::new(snapshot)
}

fn policy() -> Value {
    let wire = json!({"id":"route:test","principals":["agent:test"],"credentialRef":CREDENTIAL,
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":HOST,"port":443,"methods":["PUT"],"paths":[PATH]},
        "adapter":{"type":ADAPTER,"config":config("fixture")},"constraints":[envelope("npm-publish-response")]});
    let mut policy = policy_with_route(wire.clone()); policy["routes"] = json!([wire]);
    policy["credentials"] = json!([{"id":CREDENTIAL,"credentialType":"static","provider":"operator-demo",
        "providerSubject":"synthetic-npm","secretClass":"bearerToken","injection":{"type":"bearer","header":"Authorization"}}]);
    policy
}

fn payload(package: &str, version: &str, bytes: &[u8]) -> Value {
    let name = format!("{package}-{version}.tgz");
    json!({"_id":package,"name":package,"description":"synthetic inert fixture","access":null,
        "dist-tags":{"latest":version},"versions":{version:{"name":package,"version":version,
            "_id":format!("{package}@{version}"),"_nodeVersion":"25.5.0","_npmVersion":"11.8.0",
            "future":{"preserved":true},"dist":{"integrity":format!("sha512-{}",STANDARD.encode(Sha512::digest(bytes))),
                "shasum":hex::encode(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY,bytes).as_ref()),
                "tarball":format!("http://{HOST}/{package}/-/{name}")}}},
        "_attachments":{name:{"content_type":"application/octet-stream","data":STANDARD.encode(bytes),"length":bytes.len()}}})
}

fn request(package: &str) -> DecisionRequest {
    serde_json::from_value(json!({"method":"PUT","url":format!("{BASE}/{}",package.replace('/',"%2f")),
        "headers":{"authorization":PLACEHOLDER,"accept":"*/*","content-type":"application/json",
            "user-agent":"npm/11.8.0 node/v25.5.0","npm-command":"publish","npm-auth-type":"web",
            "npm-in-ci":"false","accept-encoding":"gzip,deflate","npm-session":"synthetic-session"},
        "body":payload(package,"1.2.3",b"inert bytes, not an executable archive").to_string()})).unwrap()
}

fn admitted(mut req: DecisionRequest, snapshot: &Snapshot) -> (DecisionRequest, Url, Value, Value) {
    let route = &snapshot.routes[0]; let (_, url) = parse_validated_absolute_target(&req.url).unwrap();
    credential_header_replacement::remove_for_route(snapshot,route,&snapshot.principals[0],&mut req.headers).unwrap();
    req.headers = discard_declared_request_headers(&req.headers,&route.discard_headers).unwrap();
    validate_provider_request_admission(&req,&url,route).unwrap();
    let headers = canonical_forwarded_request_headers(&req.headers,&url,decision_request_body_length(&req).unwrap(),
        &snapshot.credentials[CREDENTIAL].injection).unwrap();
    let matched = RouteMatch { route, params:route.paths[0].matches_canonical(url.path()).unwrap() };
    let (operation,rewrite) = validate_adapter(&req,&headers,&url,&matched).unwrap(); assert_eq!(rewrite,json!({}));
    let canonical = canonical_request(&req,&headers,&url,&snapshot.principals[0],route,7,&snapshot.hash,&operation);
    (req,url,operation,canonical)
}

#[test]
fn npm_publish_closed_contract_and_actual_startup_schema_compile() {
    validate_policy_capabilities(&policy()).unwrap(); validate_route(&route("fixture")).unwrap();
    validate_route_response_release_mode(&route("fixture")).unwrap();
    let schema:Value=serde_json::from_str(include_str!("../../../schemas/adapters/npm.publish.v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&config("fixture")));
    let embedded=closed_embedded_policy_schema().unwrap();
    assert!(embedded["$defs"].get("adapter_npm_publish_v1__root").is_some());
    for version in ["serverware.policy/v1",policy_route_authority::BUNDLE] {
        let mut raw=policy(); raw["apiVersion"]=json!(version); raw["kind"]=json!("PolicyBundle");
        raw["metadata"]=json!({"id":"npm-publish-startup","sequence":1,"rollbackEpoch":1});
        if version==policy_route_authority::BUNDLE {
            let pin=format!("sha256:{}","0".repeat(64));
            raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
                "mappingSha256":pin,"routeAuthorityRootSha256":pin,"operationAuthorityRootSha256":pin});
        }
        validate_policy_schema(&raw).expect("actual startup embedded validator must compile");
        let mut invalid=raw.clone(); invalid["routes"][0]["adapter"]["config"]["unknown"]=json!(true);
        assert!(validate_policy_schema(&invalid).is_err());
        for (pointer,value) in [
            ("/routes/0/match/methods",json!(["GET","PUT"])),("/routes/0/match/host",json!("other.example")),
            ("/routes/0/match/port",json!(444)),("/routes/0/match/paths",json!(["/**"])),
            ("/routes/0/credentialHeader/expectedValue",json!("Bearer other")),
            ("/routes/0/adapter/config/package",json!("Fixture")),("/routes/0/adapter/config/tag",json!("*")),
            ("/routes/0/adapter/config/request/maxBodyBytes",json!(REQUEST_BYTES+1)),
            ("/routes/0/adapter/config/response/error/maxBodyBytes",json!(65537)),
            ("/credentials/0/provider",json!("npm")),("/credentials/0/providerSubject",json!("other")),
            ("/routes/0/constraints/0/statusCodes",json!([200,201])),
        ] { let mut changed=policy(); *changed.pointer_mut(pointer).unwrap()=value;
            assert!(validate_policy_capabilities(&changed).is_err(),"{pointer}"); }
    }
    for field in ["jit","responseObservation"] { let mut changed=policy(); changed["routes"][0][field]=json!({});
        assert!(validate_policy_capabilities(&changed).is_err()); }
    for adapter in ["generic.rest","npm.registry","npm.metadata.v1"] {
        assert!(buffered_response::validate_envelope_pairing(adapter,Some(MODE),&[envelope("npm")]).is_err()); }
}

#[test]
fn npm_publish_signed_v2_authority_is_publish_with_write_request_authority() {
    let pin=|value:&Value| sha256_prefixed(policy_route_authority::canonical(value).unwrap().as_bytes());
    let mut raw=policy(); raw["apiVersion"]=json!(policy_route_authority::BUNDLE);
    let operations=json!([{"operationName":"npm.publish","operation":"publish","requestAuthorityClass":"write"}]);
    let profile=json!({"apiVersion":"serverware.compiledRouteAuthority/v1",
        "routeSha256":sha256_prefixed(b"route:test"),"signedRouteSha256":pin(&raw["routes"][0]),
        "adapterType":ADAPTER,"operations":operations,"signedPrincipalsSha256":pin(&raw["principals"]),
        "signedCredentialsSha256":pin(&raw["credentials"]),"signedDefaultsSha256":pin(&raw["defaults"]),
        "principalSha256s":[sha256_prefixed(b"agent:test")]});
    let profile_pin=pin(&profile);
    let profiles=json!([{"routeId":"route:test","compiledSemanticProfileSha256":profile_pin,"profile":profile}]);
    let entries=json!([{"routeSha256":profile["routeSha256"],"compiledSemanticProfileSha256":profile_pin,
        "operationName":"npm.publish","operation":"publish","requestAuthorityClass":"write"}]);
    raw["routeAuthority"]=json!({"apiVersion":"serverware.compiledRouteAuthority/v1","genericOperations":[],
        "mappingSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthority/v1","profiles":profiles})),
        "routeAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles})),
        "operationAuthorityRootSha256":pin(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))});
    let snapshot=snapshot("fixture");
    let compiled=policy_route_authority::admit(&raw,&snapshot.routes).unwrap().unwrap();
    let operation=admitted(request("fixture"),&snapshot).2;
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&operation).is_ok());
    assert!(compiled.binding(&snapshot.principals[0],&snapshot.routes[0],&json!({"operation":"npm.metadata.read"})).is_err());
    raw["routeAuthority"]["genericOperations"]=json!([{"routeId":"route:test","operationName":"npm.publish","operation":"read"}]);
    assert!(policy_route_authority::admit(&raw,&snapshot.routes).is_err());
}

#[test]
fn npm_publish_stock_scoped_unscoped_bytes_hashes_and_canonical_v2() {
    for package in ["fixture","@fixture/pkg"] {
        let snapshot=snapshot(package); let original=request(package); let original_body=original.body.clone();
        let (req,url,operation,canonical)=admitted(original,&snapshot);
        assert_eq!(req.body,original_body); assert_eq!(operation["packageName"],package);
        assert_eq!(operation["packageVersion"],"1.2.3"); assert_eq!(operation["tag"],"latest");
        assert_eq!(operation["attachmentName"],format!("{package}-1.2.3.tgz"));
        assert_eq!(operation["attachmentBytes"],b"inert bytes, not an executable archive".len().to_string());
        assert_eq!(operation.as_object().unwrap().len(),8);
        assert_eq!(canonical["v"],2); assert_eq!(canonical["request"]["discard_headers"],json!(DISCARD));
        assert_eq!(canonical["request"]["body_sha256"],sha256_prefixed(original_body.as_bytes()));
        assert!(!req.headers.contains_key("authorization"));
        for header in DISCARD { assert!(!req.headers.contains_key(*header)); }
        let matched=RouteMatch { route:&snapshot.routes[0],params:BTreeMap::from([("wrong".into(),"fixture".into())]) };
        assert!(normalize_request(&req,&url,&matched).is_err());
        for access in [Value::Null,json!("public"),json!("restricted")] {
            let mut req=request(package); let mut body=payload(package,"1.0.0-beta.1+build.01",b"x");
            body["access"]=access; body.as_object_mut().unwrap().remove("description"); req.body=body.to_string();
            admitted(req,&snapshot);
        }
    }
    for value in ["0.0.0","1.2.3","1.2.3-beta.0","1.2.3-1x.01x+001"] { assert!(version(value)); }
    for value in ["v1.2.3","01.2.3","1.2","1.2.3-01","1.2.3-","1.2.3+","1.2.3+a+b","1.2.3 "] { assert!(!version(value),"{value}"); }
    for value in ["latest","next-1","a.b_c"] { assert!(tag(value)); }
    for value in ["Latest","*","1next","-next",""] { assert!(!tag(value)); }
}

#[test]
fn npm_publish_payload_mutations_and_media_fail_before_credential_preparation() {
    let snapshot=snapshot("fixture"); let state=test_gate_state(Arc::clone(&snapshot));
    let base=payload("fixture","1.2.3",b"x");
    let fields=[("/_id",json!("other")),("/name",json!("other")),("/access",json!(true)),
        ("/description",json!(null)),("/dist-tags",json!({"next":"1.2.3"})),
        ("/versions/1.2.3/name",json!("other")),("/versions/1.2.3/version",json!("2.0.0")),
        ("/versions/1.2.3/_id",json!("fixture@2.0.0")),
        ("/versions/1.2.3/dist/shasum",json!("0".repeat(40))),
        ("/versions/1.2.3/dist/integrity",json!("sha512-wrong")),
        ("/versions/1.2.3/dist/tarball",json!("https://registry.npmjs.org/fixture/-/fixture-1.2.3.tgz")),
        ("/_attachments/fixture-1.2.3.tgz/data",json!("eB==")),
        ("/_attachments/fixture-1.2.3.tgz/length",json!(true)),
        ("/_attachments/fixture-1.2.3.tgz/length",json!(2)),
        ("/_attachments/fixture-1.2.3.tgz/content_type",json!("application/gzip"))];
    for (pointer,value) in fields { let mut body=base.clone(); *body.pointer_mut(pointer).unwrap()=value;
        let mut req=request("fixture"); req.body=body.to_string();
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false,"{pointer}"); }
    for pointer in ["/extra","/versions/2.0.0","/_attachments/provenance.sigstore","/versions/1.2.3/dist/extra"] {
        let mut body=base.clone(); let (parent,key)=pointer.rsplit_once('/').unwrap();
        body.pointer_mut(parent).unwrap().as_object_mut().unwrap().insert(key.into(),json!({}));
        let mut req=request("fixture"); req.body=body.to_string();
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false,"{pointer}"); }
    for media in ["application/json;charset=latin1","application/json;foo=bar","application/vnd.npm.install-v1+json"] {
        let mut req=request("fixture"); req.headers.insert("content-type".into(),media.into());
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false); }
    for (method,path) in [("GET","/fixture"),("PUT","/other"),("PUT","/fixture?tag=latest"),
        ("PUT","/fixture/-/fixture.tgz"),("PUT","/@fixture%2Fpkg"),("PUT","/-/whoami")] {
        let mut req=request("fixture"); req.method=method.into(); req.url=format!("{BASE}{path}");
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false); }
    for body in ["{}","{\"name\":1,\"name\":2}","{\"x\":-0}","{\"x\":NaN}","[]"] {
        let mut req=request("fixture"); req.body=body.into();
        assert_eq!(decide_internal(&state,&snapshot,req,Some("agent:test"))["allowed"],false); }
    assert_eq!(state.credential_lease_refresh_success.load(Ordering::Relaxed),0);
    assert_eq!(state.credential_lease_refresh_failed.load(Ordering::Relaxed),0);
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.credential_generations.lock().unwrap().is_empty());
}

#[test]
fn npm_publish_manifest_budget_and_preallocation_attachment_bounds() {
    for number in ["0","-0.0","1e2","1e-20","18446744073709551617","1.7976931348623157e308"] {
        assert_eq!(manifest_budget(&strict_json_value_from_str(number).unwrap()),320); }
    for (value,expected) in [(json!(null),4),(json!(true),4),(json!(false),5),
        (json!("é"),4),(json!("\n\"\\"),8),(json!([]),2),(json!({}),2),
        (json!([1,true,null]),332),(json!({"x":1}),326)] { assert_eq!(manifest_budget(&value),expected); }
    let mut body=payload("fixture","1.2.3",b"x");
    body["versions"]["1.2.3"]["padding"]=json!("");
    let empty=manifest_budget(&body["versions"]["1.2.3"]);
    body["versions"]["1.2.3"]["padding"]=json!("a".repeat(MANIFEST_BYTES-empty));
    let mut req=request("fixture"); req.body=body.to_string();
    payload_operation(&req,"fixture","latest").unwrap();
    body["versions"]["1.2.3"]["padding"]=json!("a".repeat(MANIFEST_BYTES-empty+1));
    req.body=body.to_string(); assert!(payload_operation(&req,"fixture","latest").is_err());
    let mut body=payload("fixture","1.2.3",b"x");
    body["_attachments"]["fixture-1.2.3.tgz"]["data"]=json!("A".repeat(TARBALL_BYTES.div_ceil(3)*4));
    body["_attachments"]["fixture-1.2.3.tgz"]["length"]=json!(TARBALL_BYTES);
    req.body=body.to_string(); assert!(payload_operation(&req,"fixture","latest").is_err(),"unpadded decoded length exceeds8MiB before decoder");
    req.body=" ".repeat(REQUEST_BYTES as usize+1); assert!(payload_operation(&req,"fixture","latest").is_err());
    let mut deep=json!(null); for _ in 0..65 { deep=json!([deep]); } assert!(!bounded_document(&deep));
}

struct InertResolver(AtomicU64);
impl UpstreamResolver for InertResolver {
    fn resolve(&self,host:&str,port:u16)->Result<Vec<SocketAddr>,String> {
        assert_eq!((host,port),(HOST,443)); self.0.fetch_add(1,Ordering::Relaxed);
        Ok(vec!["127.0.0.1:443".parse().unwrap()])
    }
}

#[test]
fn npm_publish_buffered_preparation_validates_actual_body_before_resolution() {
    let mut held=(*snapshot("fixture")).clone();
    held.routes[0].resolved_address_policy=ResolvedAddressPolicy::ExplicitCidrs(vec!["127.0.0.1/32".parse().unwrap()]);
    let snapshot=Arc::new(held); let mut state=test_gate_state(Arc::clone(&snapshot));
    let resolver=Arc::new(InertResolver(AtomicU64::new(0))); state.upstream_resolver=resolver.clone();
    let req=request("fixture"); let url=Url::parse(&req.url).unwrap();
    let mut incoming=IncomingRequest {method:req.method.clone(),target:req.url.clone(),headers:req.headers.clone(),
        body:req.body.as_bytes().to_vec(),client_ip:None};
    let prepared=prepare_upstream_for_buffered_forward(&state,&snapshot,&incoming,&url,Some("agent:test")).unwrap().unwrap();
    assert_eq!(prepared.route_id,snapshot.routes[0].id); assert_eq!(resolver.0.load(Ordering::Relaxed),1);
    incoming.body=b"{}".to_vec();
    assert!(prepare_upstream_for_buffered_forward(&state,&snapshot,&incoming,&url,Some("agent:test")).unwrap().is_none());
    assert_eq!(resolver.0.load(Ordering::Relaxed),1);
    let head=RequestHead {method:"PUT".into(),target:url.to_string(),http_version:"HTTP/1.1".into(),
        headers:incoming.headers.clone(),raw_headers_digest:None,raw_header_count:0,
        content_length:req.body.len(),has_content_length:true,prefetched_body:Vec::new(),client_ip:None};
    assert!(prepare_upstream_for_forward(&state,&snapshot,&head,&url,Some("agent:test")).unwrap().is_none());
    assert_eq!(resolver.0.load(Ordering::Relaxed),1);
    assert!(state.credential_leases.lock().unwrap().is_empty());
}

fn window() -> Value { json!({"id":"npm-hours","type":"requestTimeWindow","phase":"request",
    "timezone":"UTC","dailyWindows":[{"start":"12:00","end":"12:15"}]}) }

#[test]
fn npm_publish_window_is_optional_exact_and_carries_exclusive_send_deadline() {
    let mut route=route("fixture"); route.constraints.push(window()); validate_route(&route).unwrap();
    let inside=parse_rfc3339_ms("2026-07-27T12:14:59.900Z").unwrap();
    let end=parse_rfc3339_ms("2026-07-27T12:15:00Z").unwrap();
    enforce_request_time_window_at_ms(&window(),inside).unwrap();
    assert!(enforce_request_time_window_at_ms(&window(),end).is_err());
    assert_eq!(request_policy_deadline_epoch_ms(&route,inside as u64).unwrap(),Some(end as u64));
    let deadlines=upstream_send_deadlines(Some(end as u64),None);
    assert_eq!(upstream_send_deadline_timeout_at(deadlines,inside as u128),Ok(Some(Duration::from_millis(100))));
    assert_eq!(upstream_send_deadline_timeout_at(deadlines,end as u128),Err("upstream_send_authority_expired"));
    for (start,end) in [("12:00","12:00"),("23:00","01:00"),("00:00","24:00"),("+1:00","12:00")] {
        let mut changed=window(); changed["dailyWindows"]=json!([{"start":start,"end":end}]);
        assert!(validate_config(&config("fixture"),&[envelope("response"),changed]).is_err()); }
    for (key,value) in [("timezone",json!("America/New_York")),("weekdays",json!(["mon"])),("notAfter",json!("2026-12-01T00:00:00Z"))] {
        let mut changed=window(); changed[key]=value;
        assert!(validate_config(&config("fixture"),&[envelope("response"),changed]).is_err()); }
}

#[test]
fn npm_publish_delayed_final_sender_rechecks_policy_deadline_before_connect() {
    let snapshot=snapshot("fixture"); let mut state=test_gate_state(Arc::clone(&snapshot));
    state.response_proof_signer=test_custody_response_proof_signer(sha256_prefixed(b"synthetic-response-spki"));
    let state=Arc::new(state);
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else {panic!("custody fixture");};
    let transition=signer.health.begin_health_transition();
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap();
    // The previous test binds this field to the exact route window. Here only
    // the policy deadline expires while the actual sender waits at its barrier.
    let deadline=u64::try_from(now_epoch_ms()).unwrap()+100;
    let worker_state=Arc::clone(&state); let worker_snapshot=Arc::clone(&snapshot);
    let worker=thread::spawn(move || send_upstream_request_with_current_lease(&worker_state,&worker_snapshot,None,
        test_upstream_client().put(format!("http://{address}/fixture")).body("synthetic"),
        UpstreamSendDeadlines {policy_expires_at_epoch_ms:Some(deadline),..UpstreamSendDeadlines::default()},true));
    let bound=Instant::now()+Duration::from_secs(2);
    while signer.health.dispatch_coordination.lock().unwrap().waiting_dispatches!=1 && Instant::now()<bound {
        thread::sleep(Duration::from_millis(1)); }
    let waiting=signer.health.dispatch_coordination.lock().unwrap().waiting_dispatches;
    while now_epoch_ms()<u128::from(deadline) && Instant::now()<bound {thread::sleep(Duration::from_millis(1));}
    drop(transition);
    let error=worker.join().unwrap().expect_err("policy deadline must prevent delayed send");
    assert_eq!(waiting,1);
    assert!(matches!(error,UpstreamSendError::CredentialAuthority("upstream_send_authority_expired")));
    assert_eq!(listener.accept().expect_err("no target connection").kind(),io::ErrorKind::WouldBlock);
}

#[test]
fn npm_publish_response_preserves_strict_object_bytes_and_scans_reflection() {
    let url=Url::parse(&format!("{BASE}/fixture")).unwrap(); let guard=ResponseSecretGuard::default();
    for status in STATUSES { let status=StatusCode::from_u16(*status).unwrap();
        let body=br#" {"ok":true,"id":"fixture","future":1e2} "#;
        assert_eq!(&*inspect_response(&url,status,Some("application/json; charset=utf-8"),
            &response_profile(!status.is_success()),body.to_vec().into(),&guard).unwrap(),body); }
    for body in [b"[]".as_slice(),b"",br#"{"x":-0}"#,br#"{"x":NaN}"#,br#"{"x":1,"x":2}"#,br#"{}{}"#] {
        assert!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),body.to_vec().into(),&guard).is_err()); }
    for status in [202,204,206,302,418] { assert!(inspect_response(&url,StatusCode::from_u16(status).unwrap(),Some("application/json"),
        &response_profile(status>=400),b"{}".to_vec().into(),&guard).is_err()); }
    for media in ["application/vnd.npm.install-v1+json","text/json","application/json; charset=latin1","application/json;foo=bar"] {
        assert!(!is_json_content_type(media)); }
    let body=format!("{{\"x\":\"{}\"}}","a".repeat(RESPONSE_BYTES as usize-8)); assert_eq!(body.len(),RESPONSE_BYTES as usize);
    assert!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),body.as_bytes().to_vec().into(),&guard).is_ok());
    assert!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),format!("{body} ").into_bytes().into(),&guard).is_err());
    let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    for body in [br#"{"x":"synthetic-secret"}"#.as_slice(),br#"{"x":"\u0073ynthetic-secret"}"#] {
        assert_eq!(inspect_response(&url,StatusCode::OK,Some("application/json"),&response_profile(false),body.to_vec().into(),&guard).err().unwrap()["error"],"response_credential_reflection"); }
}

#[test]
fn npm_publish_dispatch_barrier_cannot_rearm_expired_window_or_contact_target() {
    let snapshot=snapshot("fixture"); let state=test_gate_state(Arc::clone(&snapshot));
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap(); let deadline=u64::try_from(now_epoch_ms()).unwrap()+100;
    let mut reached=false;
    let result=send_upstream_request_with_current_lease_finalized(&state,&snapshot,None,
        test_upstream_client().put(format!("http://{address}/fixture")).body("synthetic"),
        UpstreamSendDeadlines {policy_expires_at_epoch_ms:Some(deadline),..UpstreamSendDeadlines::default()},false,
        |_| { reached=true; let bound=Instant::now()+Duration::from_secs(2);
            while now_epoch_ms()<u128::from(deadline) && Instant::now()<bound {thread::sleep(Duration::from_millis(1));}
            Ok(None) });
    assert!(reached,"the deadline must still be live at the initial send check");
    assert!(matches!(result,Err(UpstreamSendError::CredentialAuthority("upstream_send_authority_expired"))));
    assert_eq!(listener.accept().expect_err("expired after barrier: no target connection").kind(),io::ErrorKind::WouldBlock);
}

fn upstream(status:u16,headers:&str,body:&[u8])->reqwest::blocking::Response {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let address=listener.local_addr().unwrap();
    let mut wire=format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",body.len()).into_bytes();
    wire.extend_from_slice(body);
    let server=thread::spawn(move || {
        let bound=Instant::now()+Duration::from_secs(4);
        let mut stream=loop {match listener.accept() {Ok((stream,_))=>break stream,
            Err(e) if e.kind()==io::ErrorKind::WouldBlock && Instant::now()<bound=>thread::sleep(Duration::from_millis(2)),
            Err(_)=>panic!("bounded synthetic response accept failed")}};
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        read_request_head_from(&mut stream,None).unwrap(); stream.write_all(&wire).unwrap();
    });
    let result=Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap()
        .get(format!("http://{address}/fixture")).send().unwrap(); server.join().unwrap(); result
}

#[test]
fn npm_publish_real_finalizer_keeps_whole_json_and_blocks_metadata_encoding_reflection() {
    let snapshot=snapshot("fixture"); let state=test_gate_state(Arc::clone(&snapshot));
    let url=Url::parse(&format!("{BASE}/fixture")).unwrap();
    let decision=json!({"principal_id":"agent:test","route_id":"route:test","policy_hash":snapshot.hash,
        "snapshot_epoch":snapshot.epoch,"request_digest":"sha256:synthetic","operation_digest":"sha256:synthetic",
        "operation":{"operation":"npm.publish","packageName":"fixture"},
        "canonical_request":{"request":{"method":"PUT","scheme":"https","authority":HOST,"path":"/fixture"}}});
    let mut guard=ResponseSecretGuard::default(); guard.add_text_encodings("synthetic-secret");
    let finalize=|status,headers,body:&[u8]| match finalize_upstream_response(&state,&snapshot,&decision,"PUT",&url,
        upstream(status,headers,body),&guard,None,None,None,None,None,None,None,None,None,false) {
            ForwardResult::Buffered(wire)=>wire,ForwardResult::Streamed=>panic!("publish must buffer")};
    for status in [200,201,409] { let body=br#" {"ok":true,"dynamic":{"kept":1e2}} "#;
        let wire=finalize(status,"Content-Type: application/json; charset=utf-8\r\nServer: synthetic\r\nX-Future: discarded\r\n",body);
        let parsed=parse_buffered_response(&wire).unwrap(); assert_eq!(parsed.status,status); assert_eq!(parsed.body,body);
        assert!(!parsed.headers.contains_key("server")); assert!(!parsed.headers.contains_key("x-future")); }
    for headers in ["Content-Type: application/json\r\nX-Discarded: synthetic-secret\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: application/json\r\nSet-Cookie: forbidden=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n",
        "Content-Type: application/vnd.npm.install-v1+json\r\n"] {
        let wire=finalize(201,headers,b"{}"); assert_eq!(parse_buffered_response(&wire).unwrap().status,502);
        assert!(!String::from_utf8_lossy(&wire).contains("synthetic-secret")); }
}
