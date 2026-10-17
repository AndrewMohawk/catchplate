//! In-memory HTTP intake plus actual token/preflight and runtime-policy guards.
//! Compiled policy/Profile inputs are synthetic. No socket, TLS handshake,
//! provider request, signed-policy installation or native admission is claimed.
use super::*;
use crate::tests::{test_gate_state, test_snapshot};
use crate::npm_install_connect_encoding as encoding;
use std::io::Cursor;

const PRINCIPAL: &str = "agent:test";
const APP: &str = "a1111111-1111-4111-8111-111111111111";
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTHORITY: &str = "registry.npmjs.org:443";

fn snapshot() -> Arc<Snapshot> {
    let mut value = (*test_snapshot(1)).clone();
    value.policy_id = "catchplate-operator-demo".into();
    value.principals[0].proxy_authorization = parse_proxy_authorization(Some(&json!({
        "scheme":"Bearer", "tokenId":APP, "tokenSha256":sha256_prefixed(TOKEN.as_bytes()),
        "expiresAtEpochMs":now_epoch_ms()+60_000, "basicTransport":{"username":APP}
    })), PRINCIPAL).unwrap();
    let route = &mut value.routes[0];
    route.scheme = "https".into(); route.host = npm_install::HOST.into(); route.port = 443;
    route.resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    route.methods = HashSet::from(["POST".into()]);
    route.paths = npm_install::route_paths("audit").unwrap().into_iter()
        .map(|path| compile_template(path).unwrap()).collect();
    route.adapter_type = npm_install::ADAPTER.into();
    route.adapter_config = json!({"credentialBinding":{"credentialType":"static", "provider":"operator-demo",
        "subjects":["synthetic-npm"], "secretClass":"bearerToken"}, "packages":["fixture"], "mode":"audit",
        "request":npm_install::request_config("audit").unwrap(),
        "response":npm_install::response_profile("audit",false).unwrap()});
    route.credential_ref = Some("credential:npm-install".into());
    route.credential_header = Some(json!({"mode":"replaceExact", "expectedValue":npm_install::PLACEHOLDER}));
    route.discard_headers = npm_install::DISCARD.iter().map(|value| value.to_string()).collect();
    route.constraints = vec![npm_install::envelope("audit","install-response").unwrap()];
    route.jit = json!({});
    value.credentials.insert("credential:npm-install".into(), Credential {
        provider:"operator-demo".into(), provider_subject:Some("synthetic-npm".into()),
        injection:json!({"type":"bearer", "header":"Authorization", "__catchplateCredentialType":"static"}),
    });
    npm_install::validate_route(route).unwrap();
    Arc::new(value)
}

fn state(snapshot: &Arc<Snapshot>) -> GateState {
    let mut state = test_gate_state(Arc::clone(snapshot));
    state.policy_shadow = ShadowRuntime::new_operator_demo(operator_demo::test_publish_dispatch_profile(snapshot));
    state.proxy_ingress_attestation.mode = operator_demo::INGRESS_MODE;
    state
}

fn authorization(basic: bool) -> String {
    if basic { format!("Basic {}", general_purpose::STANDARD.encode(format!("{APP}:{TOKEN}"))) }
    else { format!("Bearer {TOKEN}") }
}

fn wire(basic: bool, length: &str, extra: &str) -> Vec<u8> {
    format!("CONNECT {AUTHORITY} HTTP/1.1\r\nHost: {AUTHORITY}\r\nProxy-Authorization: {}\r\nContent-Encoding: gzip\r\n{length}{extra}\r\n",
        authorization(basic)).into_bytes()
}

fn parse(raw: Vec<u8>, enabled: bool) -> Result<IncomingRequest, String> {
    let mut reader = Cursor::new(raw);
    let head = read_operator_outer_request_head_from(&mut reader,Some("127.0.0.1".into()),false,enabled)?;
    read_request_body_from_head(&mut reader,head,0)
}

fn authenticated(snapshot: &Arc<Snapshot>, request: &IncomingRequest) -> ConnectAuthentication {
    let decision = connect_preflight(snapshot,request.client_ip.as_deref(),&request.target,&request.headers,None);
    assert_eq!(decision["allowed"],true);
    assert_eq!(decision["principal_id"],PRINCIPAL);
    ConnectAuthentication::capture_with_mtls(snapshot,PRINCIPAL,request.client_ip.as_deref(),&request.headers,None).unwrap()
}

#[test]
fn npm_install_connect_bodyless_gzip_requires_actual_token_and_audit_grant() {
    let snapshot = snapshot(); let state = state(&snapshot);
    assert!(encoding::allows_intake(&state,&snapshot,false));
    for basic in [false,true] {
        for length in ["","Content-Length: 0\r\n"] {
            let request = parse(wire(basic,length,""),true).unwrap();
            assert!(request.body.is_empty());
            assert_eq!(request.headers["content-encoding"],"gzip");
            let authentication = authenticated(&snapshot,&request);
            encoding::require_authenticated(&state,&snapshot,&request,&authentication).unwrap();
            // Admission neither strips the reviewed outer header nor turns it
            // into an owned compressed inner request body.
            assert_eq!(request.headers["content-encoding"],"gzip");
            assert!(request.body.is_empty());
        }
    }
}

#[test]
fn npm_install_connect_provisional_syntax_refuses_aliases_bodies_and_ambiguity() {
    let ordinary = String::from_utf8(wire(true,"","")).unwrap();
    for (before,after) in [("CONNECT ","POST "), (AUTHORITY,"registry.npmjs.org:0443"),
        (AUTHORITY,"registry.npmjs.org:444"), (AUTHORITY,"Registry.npmjs.org:443"),
        (AUTHORITY,"other.example:443"), ("Content-Encoding: gzip","Content-Encoding: GZip"),
        ("Content-Encoding: gzip","Content-Encoding: gzip, identity"),
        ("Host: registry.npmjs.org:443","Host: registry.npmjs.org"),
        ("Host: registry.npmjs.org:443","Host: other.example:443")] {
        assert!(parse(ordinary.replacen(before,after,1).into_bytes(),true).is_err(),"{before} -> {after}");
    }
    for extra in ["Content-Length: 1\r\n", "Content-Length: 00\r\n", "Content-Length: +0\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n", "Content-Encoding: gzip\r\n",
        "Host: registry.npmjs.org:443\r\n", "Transfer-Encoding: chunked\r\n",
        "Connection: content-encoding\r\n", "Connection: host\r\n", "Connection: proxy-authorization\r\n"] {
        assert!(parse(wire(true,"",extra),true).is_err(),"{extra}");
    }
    for tail in [b"x".as_slice(),b"GET /fixture HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n"] {
        let mut raw = wire(true,"Content-Length: 0\r\n",""); raw.extend_from_slice(tail);
        assert!(parse(raw,true).is_err());
    }
    let headers = BTreeMap::from([("host".into(),AUTHORITY.into()),("content-encoding".into(),"gzip".into())]);
    assert!(encoding::permits_head("CONNECT",AUTHORITY,&headers,0,false,&[]));
    assert!(!encoding::permits_head("CONNECT",AUTHORITY,&headers,0,false,b"prefetched"));
    assert!(!encoding::permits_head("CONNECT",AUTHORITY,&headers,1,false,&[]));
}

#[test]
fn npm_install_connect_default_management_and_inner_parsers_keep_old_policy() {
    let raw = wire(true,"","");
    assert!(read_request_head_from(&mut Cursor::new(raw.clone()),None).is_err());
    assert!(read_request_head_with_ordered_query_from(&mut Cursor::new(raw.clone()),None,true).is_err());
    assert!(read_request_head_with_intake_from(&mut Cursor::new(raw.clone()),None,false,false).is_err());
    assert!(parse(raw.clone(),false).is_err());
    let identity = String::from_utf8(raw.clone()).unwrap().replace("Content-Encoding: gzip","Content-Encoding: identity");
    assert!(read_request_head_from(&mut Cursor::new(identity.into_bytes()),None).is_ok());
    let inner = b"POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\nabc";
    // Enabling the outer-only exception cannot admit a gzip POST.
    assert!(parse(inner.to_vec(),true).is_err());
    let mut reader = Cursor::new(inner);
    let head = read_request_head_with_intake_from(&mut reader,None,false,true).unwrap();
    assert_eq!(head.method,"POST"); assert!(head.prefetched_body.is_empty());
    assert_eq!(reader.position() as usize,inner.len()-3);
    let snapshot = snapshot(); let state = state(&snapshot);
    assert!(!encoding::allows_intake(&state,&snapshot,true));
}

#[test]
fn npm_install_connect_missing_wrong_expired_and_revoked_authentication_refuse() {
    let snapshot = snapshot(); let state = state(&snapshot);
    let good = parse(wire(true,"",""),true).unwrap();
    let authentication = authenticated(&snapshot,&good);
    for replacement in [None,Some("Bearer invalid-token"),Some("Basic invalid-encoding")] {
        let mut request = parse(wire(true,"",""),true).unwrap();
        if let Some(value) = replacement { request.headers.insert("proxy-authorization".into(),value.into()); }
        else { request.headers.remove("proxy-authorization"); }
        assert_eq!(connect_preflight(&snapshot,request.client_ip.as_deref(),&request.target,&request.headers,None)["allowed"],false);
        assert!(ConnectAuthentication::capture_with_mtls(&snapshot,PRINCIPAL,request.client_ip.as_deref(),&request.headers,None).is_err());
    }
    for expired in [false,true] {
        let mut changed = (*snapshot).clone();
        if expired {
            match changed.principals[0].proxy_authorization.as_mut().unwrap() {
                ProxyAuthorizationPolicy::BearerToken {expires_at_ms,..} => *expires_at_ms=Some(now_epoch_ms()-1),
                _ => unreachable!(),
            }
        } else { changed.principals.clear(); }
        let changed = Arc::new(changed);
        assert_eq!(connect_preflight(&changed,good.client_ip.as_deref(),&good.target,&good.headers,None)["allowed"],false);
        assert!(authentication.revalidate(&changed).is_err());
        assert!(encoding::require_authenticated(&state,&changed,&good,&authentication).is_err());
    }
    for anonymous in [false,true] {
        let mut changed=(*snapshot).clone();
        let mut request=parse(wire(false,"",""),true).unwrap();
        if anonymous {
            changed.principals[0].proxy_authorization=None;
            changed.routes[0].principals=vec!["*".into()];
            request.headers.remove("proxy-authorization");
        } else if let Some(ProxyAuthorizationPolicy::BearerToken {expires_at_ms,..}) =
            changed.principals[0].proxy_authorization.as_mut() {
            *expires_at_ms=None;
            // Basic transport already requires a finite expiry, even when
            // this request presents Bearer. Preserve that earlier refusal.
            let invalid_basic=Arc::new(changed.clone());
            assert_eq!(connect_preflight(&invalid_basic,request.client_ip.as_deref(),
                &request.target,&request.headers,None)["allowed"],false);
            assert!(ConnectAuthentication::capture_with_mtls(&invalid_basic,PRINCIPAL,
                request.client_ip.as_deref(),&request.headers,None).is_err());
            if let Some(ProxyAuthorizationPolicy::BearerToken {basic_transport,..}) =
                changed.principals[0].proxy_authorization.as_mut() {
                *basic_transport=None;
            }
        }
        // Deliberately weakened current compiled input, not valid operator
        // Profile admission: preserve the original owner while testing that
        // legacy preflight alone cannot admit anonymous/nonfinite gzip intake.
        let changed=Arc::new(changed);
        *state.snapshot.write().unwrap()=Arc::clone(&changed);
        assert!(snapshot_is_active(&state,&changed));
        assert_eq!(connect_preflight(&changed,request.client_ip.as_deref(),&request.target,&request.headers,None)["allowed"],true);
        let captured=ConnectAuthentication::capture_with_mtls(&changed,PRINCIPAL,
            request.client_ip.as_deref(),&request.headers,None).unwrap();
        captured.revalidate(&changed).unwrap();
        assert!(encoding::require_authenticated(&state,&changed,&request,&captured).is_err());
    }
}

#[test]
fn npm_install_connect_other_grants_and_other_principals_do_not_admit_gzip() {
    for change in 0..5 {
        let original = snapshot(); let mut altered = (*original).clone();
        match change {
            0 => altered.routes[0].principals=vec!["agent:other".into()],
            1 => altered.routes[0].adapter_config["mode"]=json!("metadata"),
            2 => altered.routes[0].adapter_type="generic.rest".into(),
            3 => altered.routes[0].adapter_config["request"]["maxBodyBytes"]=json!(1),
            _ => altered.routes.clear(),
        }
        let changed = Arc::new(altered);
        let state = state(&changed); let request = parse(wire(true,"",""),true).unwrap();
        assert!(snapshot_is_active(&state,&changed));
        assert_eq!(connect_preflight(&changed,request.client_ip.as_deref(),&request.target,&request.headers,None)["allowed"],
            !matches!(change,0|4));
        let authentication = ConnectAuthentication::capture_with_mtls(&changed,PRINCIPAL,
            request.client_ip.as_deref(),&request.headers,None).unwrap();
        assert!(encoding::require_authenticated(&state,&changed,&request,&authentication).is_err(),"case {change}");
    }
    // A real token for another principal can receive host-level CONNECT
    // admission from a different grant without acquiring the audit exception.
    let mut altered = (*snapshot()).clone();
    let mut second = altered.principals[0].clone(); second.id="agent:other".into();
    if let Some(ProxyAuthorizationPolicy::BearerToken {token_sha256,..}) = &mut second.proxy_authorization {
        *token_sha256=sha256_prefixed(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    }
    altered.principals.push(second);
    let mut separate = altered.routes[0].clone(); separate.id="route:other".into();
    separate.principals=vec!["agent:other".into()]; separate.adapter_type="generic.rest".into();
    altered.routes.push(separate);
    let changed=Arc::new(altered); let state=state(&changed);
    let mut request=parse(wire(false,"",""),true).unwrap();
    request.headers.insert("proxy-authorization".into(),"Bearer bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
    let decision=connect_preflight(&changed,request.client_ip.as_deref(),&request.target,&request.headers,None);
    assert_eq!(decision["allowed"],true); assert_eq!(decision["principal_id"],"agent:other");
    let authentication=ConnectAuthentication::capture_with_mtls(&changed,"agent:other",request.client_ip.as_deref(),&request.headers,None).unwrap();
    assert!(encoding::require_authenticated(&state,&changed,&request,&authentication).is_err());
}

#[test]
fn npm_install_connect_nonoperator_native_and_atomic_profiles_remain_excluded() {
    let snapshot = snapshot(); let request = parse(wire(true,"",""),true).unwrap();
    let authentication = authenticated(&snapshot,&request);
    for mode in 0..5 {
        let mut candidate=state(&snapshot);
        match mode {
            0 => candidate.is_production=true,
            1 => candidate.policy_shadow=ShadowRuntime::new_inactive_for_forwarding_tests(),
            2 => candidate.native_policy_bytes=Some(vec![0u8].into()),
            3 => candidate.atomic_release_authorization_enabled=true,
            _ => candidate.proxy_ingress_attestation.mode="native-mtls-v1",
        }
        assert!(!encoding::allows_intake(&candidate,&snapshot,false),"mode {mode}");
        assert!(encoding::require_authenticated(&candidate,&snapshot,&request,&authentication).is_err(),"mode {mode}");
    }
}

#[test]
fn npm_install_connect_source_join_stays_after_authentication_before_tls_200() {
    // Placement only; component tests above do not claim that TLS was started.
    let source=include_str!("main.rs");
    let connect=source.split("fn handle_connect_request(").nth(1).unwrap()
        .split("fn handle_connection(").next().unwrap();
    let preflight=connect.find("connect_preflight(").unwrap();
    let capture=connect.find("ConnectAuthentication::capture_with_mtls(").unwrap();
    let admit=connect.find("npm_install_connect_encoding::require_authenticated(").unwrap();
    let tls=connect.find("mitm_server_config(").unwrap();
    assert!(preflight<capture && capture<admit && admit<tls);
    let outer=source.split("fn handle_gate_connection(").nth(1).unwrap();
    assert!(outer.contains("let npm_connect_gzip = matches!(&proxy_ingress, ProxyIngressConfig::OperatorDemoTlsEdge)\n        && npm_install_connect_encoding::allows_intake("));
    assert!(outer.contains("npm_install_connect_encoding::allows_intake("));
    assert!(outer.contains("read_operator_outer_request_head_from("));
}
