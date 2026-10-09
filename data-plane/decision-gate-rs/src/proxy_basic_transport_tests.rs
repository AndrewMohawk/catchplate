//! Synthetic, source-authored controls; no provider, process admission or live proxy proof.
use super::{BasicTransport, MAX_EXPIRY, REFUSED};
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use crate::{ConnectAuthentication, ConnectAuthenticationError, ConnectProxyAuthorizationBinding,
    DecisionRequest, ProxyAuthorizationPolicy};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::Arc;

const USER: &str = "a1111111-1111-4111-8111-111111111111";
const OTHER: &str = "b1111111-1111-4111-8111-111111111111";
fn token() -> String { "a".repeat(43) }
fn wire(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}
fn config() -> Value {
    json!({"scheme":"Bearer", "tokenId":USER, "tokenSha256":crate::sha256_prefixed(token().as_bytes()),
        "expiresAtEpochMs":2000, "basicTransport":{"username":USER}})
}
fn parse(value: &Value) -> ProxyAuthorizationPolicy {
    crate::parse_proxy_authorization(Some(value), "agent:test").unwrap().unwrap()
}
fn transport() -> BasicTransport {
    BasicTransport::from_policy(config().as_object().unwrap()).unwrap().unwrap()
}
fn snapshot() -> crate::Snapshot {
    let mut value = (*test_snapshot(1)).clone();
    value.policy_id = "serverware-operator-demo".into();
    value.principals[0].proxy_authorization = Some(parse(&config()));
    value
}

#[test]
fn basic_transport_policy_is_closed_exact_and_finitely_expiring() {
    for expiry in [1u64, MAX_EXPIRY as u64] {
        let mut value = config();
        value["expiresAtEpochMs"] = json!(expiry);
        assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_ok());
    }
    for invalid in [Value::Null, json!({}), json!({"username":USER,"extra":true}),
        json!({"username":7}), json!({"username":USER.to_uppercase()}),
        json!({"username":OTHER}), json!({"username":format!(" {USER}")})] {
        let mut value = config(); value["basicTransport"] = invalid;
        assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
    }
    for invalid in [Value::Null, json!(0), json!(-1), json!(true), json!(1.5), json!(MAX_EXPIRY as u64 + 1)] {
        let mut value = config(); value["expiresAtEpochMs"] = invalid;
        assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
    }
    for key in ["tokenId", "expiresAtEpochMs", "scheme"] {
        let mut value = config(); value.as_object_mut().unwrap().remove(key);
        assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
    }
    let mut value = config(); value["scheme"] = json!("bearer");
    assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
    value = config(); value["tokenSha256"] = json!(format!("sha256:{}", "z".repeat(64)));
    assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
    // The absent option keeps the old grammar, including its optional expiry/token ID.
    value = config(); value.as_object_mut().unwrap().remove("basicTransport");
    value.as_object_mut().unwrap().remove("expiresAtEpochMs");
    value["tokenId"] = json!("legacy-token-name");
    assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_ok());
}

#[test]
fn basic_transport_wire_is_fixed_length_canonical_and_secret_free() {
    let parser = transport();
    let valid = wire(USER, &token());
    assert_eq!(valid.len(), 114);
    let digest = crate::sha256_prefixed(token().as_bytes());
    assert_eq!(parser.token_sha256(&valid), Some(digest.clone()));
    assert_eq!(parser.token_sha256(&valid.replacen("Basic", "bAsIc", 1)), Some(digest));
    let mut bad_pad_bits = valid.clone().into_bytes();
    assert_eq!(bad_pad_bits[112], b'E'); // Final two decoded bytes are "aa": YWE=.
    bad_pad_bits[112] = b'F';
    for invalid in [format!(" {valid}"), format!("{valid} "), format!("{valid}\r"),
        valid.replacen("Basic ", "Basic  ", 1), valid.replacen("Basic ", "Basic\t", 1),
        valid.replacen("Basic", "Other", 1), valid.trim_end_matches('=').to_owned(),
        format!("{valid}="), String::from_utf8(bad_pad_bits).unwrap(),
        format!("Basic {}", "_".repeat(108)), wire(OTHER, &token()),
        wire(USER, &"a".repeat(42)), wire(USER, &"a".repeat(44)),
        wire(USER, &format!("{}:", "a".repeat(42))),
        wire(USER, &format!("{}\n", "a".repeat(42))),
        format!("Basic {}", STANDARD.encode(format!("{USER};{}", token())))] {
        assert!(parser.token_sha256(&invalid).is_none());
    }
    // Inner token is the agreed opaque 43-character alphabet, not another decoder.
    for last in ['_', '-', 'Z'] {
        let password = format!("{}{last}", "a".repeat(42));
        assert_eq!(parser.token_sha256(&wire(USER, &password)), Some(crate::sha256_prefixed(password.as_bytes())));
    }
}

#[test]
fn basic_transport_matching_keeps_token_source_and_expiry_guards() {
    let mut value = config(); value["sourceCidrs"] = json!(["127.0.0.1/32"]);
    let policy = parse(&value);
    let valid = wire(USER, &token());
    assert!(policy.matches_at(Some("127.0.0.1"), Some(&valid), 1999));
    assert!(policy.matches_at(Some("127.0.0.1"), Some(&format!("Bearer {}", token())), 1999));
    for ip in [None, Some("127.0.0.2"), Some("not-an-ip")] {
        assert!(!policy.matches_at(ip, Some(&valid), 1000));
    }
    for header in [None, Some(wire(OTHER, &token())), Some(wire(USER, &"b".repeat(43)))] {
        assert!(!policy.matches_at(Some("127.0.0.1"), header.as_deref(), 1000));
    }
    for now in [2000, 2001] { assert!(!policy.matches_at(Some("127.0.0.1"), Some(&valid), now)); }
    let mut corrupted = policy.clone();
    if let ProxyAuthorizationPolicy::BearerToken { expires_at_ms, .. } = &mut corrupted { *expires_at_ms = None; }
    assert!(!corrupted.matches_at(Some("127.0.0.1"), Some(&valid), 1000));
    value.as_object_mut().unwrap().remove("basicTransport");
    let legacy = parse(&value);
    assert!(!legacy.matches_at(Some("127.0.0.1"), Some(&valid), 1000));
    assert!(legacy.matches_at(Some("127.0.0.1"), Some(&format!(" Bearer {} ", token())), 1000));
}

#[test]
fn basic_transport_connect_capture_revalidates_expiry_revocation_and_identity() {
    let original = snapshot();
    let headers = BTreeMap::from([("Proxy-Authorization".into(), wire(USER, &token()))]);
    let captured = ConnectAuthentication::capture_at(&original, "agent:test", None, &headers, 1000).unwrap();
    assert_eq!(captured.proxy_authorization_binding, Some(ConnectProxyAuthorizationBinding::BasicTransportTokenSha256 {
        username:USER.into(), token_sha256:crate::sha256_prefixed(token().as_bytes()),
    }));
    let retained = format!("{:?}", captured.proxy_authorization_binding);
    assert!(!retained.contains(&token()));
    assert!(!retained.contains(headers.get("Proxy-Authorization").unwrap()));
    assert!(captured.revalidate_at(&original, 1999).is_ok());
    assert_eq!(captured.revalidate_at(&original, 2000).err(), Some(ConnectAuthenticationError::SelectorRejected));
    let mut policy_only = original.clone(); policy_only.epoch += 1; policy_only.hash = crate::sha256_prefixed(b"changed-routes");
    assert!(captured.revalidate_at(&policy_only, 1000).is_ok());
    for mutation in 0..3 {
        let mut changed = original.clone(); let mut value = config();
        match mutation {
            0 => { value.as_object_mut().unwrap().remove("basicTransport"); },
            1 => { value["tokenId"] = json!(OTHER); value["basicTransport"]["username"] = json!(OTHER); },
            _ => { value["tokenSha256"] = json!(crate::sha256_prefixed(b"changed-token")); },
        }
        changed.principals[0].proxy_authorization = Some(parse(&value));
        assert_eq!(captured.revalidate_at(&changed, 1000).err(), Some(ConnectAuthenticationError::IdentityPolicyChanged));
    }
    let mut revoked = original.clone(); revoked.principals.clear();
    assert_eq!(captured.revalidate_at(&revoked, 1000).err(), Some(ConnectAuthenticationError::PrincipalRevoked));
    let wrong = BTreeMap::from([("proxy-authorization".into(), wire(USER, &"b".repeat(43)))]);
    assert_eq!(ConnectAuthentication::capture_at(&original, "agent:test", None, &wrong, 1000).err(),
        Some(ConnectAuthenticationError::SelectorRejected));
    let bearer = BTreeMap::from([("proxy-authorization".into(), format!("Bearer {}", token()))]);
    let bearer = ConnectAuthentication::capture_at(&original, "agent:test", None, &bearer, 1000).unwrap();
    assert_ne!(captured.binding_sha256(), bearer.binding_sha256());
}

#[test]
fn basic_transport_absence_preserves_both_legacy_digest_bytes() {
    let mut value = config(); value.as_object_mut().unwrap().remove("basicTransport");
    let mut principal = snapshot().principals.remove(0);
    principal.proxy_authorization = Some(parse(&value));
    let expected_auth = json!({"type":"bearerToken", "tokenSha256":value["tokenSha256"],
        "sourceCidrs":[], "expiresAtEpochMs":"2000"});
    let identity = crate::digest_json_ensure_ascii(&json!({"principalId":"agent:test", "sourceCidrs":[],
        "mtls":null, "requiredHeaders":{}, "proxyAuthorization":expected_auth}));
    assert_eq!(principal.identity_policy_digest(), identity);
    let behavior = crate::sha256_prefixed(crate::canonical_json(&json!({
        "principals":[{"id":"agent:test", "sourceCidrs":[], "mtls":null, "requiredHeaders":{},
            "proxyAuthorization":{"type":"bearer-token", "tokenSha256":value["tokenSha256"],
                "sourceCidrs":[], "expiresAtMs":"2000"}}], "credentials":[], "routes":[]
    })).as_bytes());
    assert_eq!(crate::compiled_snapshot_behavior_sha256(&[principal.clone()], &HashMap::new(), &[]), behavior);
    principal.proxy_authorization = Some(parse(&config()));
    assert_ne!(principal.identity_policy_digest(), identity);
    assert_ne!(crate::compiled_snapshot_behavior_sha256(&[principal], &HashMap::new(), &[]), behavior);
}

#[test]
fn basic_transport_schema_and_capability_admission_are_operator_v1_only() {
    let mut raw = policy_with_route(generic_policy_route("none", json!(1024)));
    raw["apiVersion"] = json!("serverware.policy/v1"); raw["kind"] = json!("PolicyBundle");
    raw["metadata"] = json!({"id":"serverware-operator-demo", "sequence":1, "rollbackEpoch":1});
    raw["principals"][0]["proxyAuthorization"] = config();
    assert!(crate::validate_policy_schema(&raw).is_ok());
    assert!(crate::validate_policy_capabilities(&raw).is_ok());
    for mutation in 0..4 {
        let mut changed = raw.clone();
        match mutation {
            0 => changed["apiVersion"] = json!("serverware.policy/v2"),
            1 => changed["metadata"]["id"] = json!("other-policy"),
            2 => changed["principals"][0]["proxyAuthorization"]["basicTransport"] = Value::Null,
            _ => changed["principals"][0]["proxyAuthorization"]["basicTransport"]["extra"] = json!(true),
        }
        assert!(crate::validate_policy_schema(&changed).is_err());
        assert!(crate::validate_policy_capabilities(&changed).is_err());
    }
    raw["principals"][0]["proxyAuthorization"].as_object_mut().unwrap().remove("basicTransport");
    raw["metadata"]["id"] = json!("other-policy");
    assert!(crate::validate_policy_schema(&raw).is_ok());
    assert!(crate::validate_policy_capabilities(&raw).is_ok());
}

#[test]
fn basic_transport_nonoperator_decision_refuses_before_credential_work() {
    let original = Arc::new(snapshot());
    let state = test_gate_state(original.clone());
    assert_eq!(super::require_runtime(&state, &original), Err(REFUSED));
    assert_eq!(super::require_scope(&original, false), Err(REFUSED));
    let mut other_id = (*original).clone(); other_id.policy_id = "other-policy".into();
    assert_eq!(super::require_scope(&other_id, true), Err(REFUSED));
    let request: DecisionRequest = serde_json::from_value(json!({"method":"GET",
        "url":"https://example.test/resource", "headers":{"proxy-authorization":wire(USER, &token())}})).unwrap();
    let result = crate::decide_internal(&state, &original, request, Some("agent:test"));
    assert_eq!(result["status_code"], 403);
    assert_eq!(result["payload"]["error"], REFUSED);
    assert!(result.get("request_digest").is_none());
    assert!(state.credential_leases.lock().unwrap().is_empty());
    assert!(state.audit_queue.lock().unwrap().is_empty());
    // No new option means no new profile restriction, even for ordinary development fixtures.
    assert!(super::require_runtime(&state, &test_snapshot(1)).is_ok());
}

#[test]
fn basic_transport_http_intake_keeps_ambiguity_and_upstream_stripping_guards() {
    let value = wire(USER, &token());
    let raw = format!("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization:\t{value} \t\r\n\r\n");
    let head = crate::read_request_head_from(&mut Cursor::new(raw.as_bytes()), None).unwrap();
    assert_eq!(head.headers.get("proxy-authorization"), Some(&value));
    assert!(transport().token_sha256(head.headers.get("proxy-authorization").unwrap()).is_some());
    let duplicate = format!("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: {value}\r\nproxy-authorization: {value}\r\n\r\n");
    assert!(crate::read_request_head_from(&mut Cursor::new(duplicate.as_bytes()), None).is_err());
    let headers = BTreeMap::from([("proxy-authorization".into(), value),
        ("accept".into(), "application/json".into()), ("authorization".into(), "Bearer PROVIDER_PLACEHOLDER".into())]);
    let forwarded = crate::client_forward_header_material(&headers, &json!({"type":"bearer"})).unwrap();
    assert_eq!(forwarded, BTreeMap::from([("accept".into(), "application/json".into())]));
}
