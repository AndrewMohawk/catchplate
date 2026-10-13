//! Actual parser/matcher/CONNECT controls with a synthetic explicit clock.
//! No transport, signing authority, deployment or client handoff is claimed.
use super::*;
use crate::{ConnectAuthentication, ConnectAuthenticationError, Snapshot};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeMap;

const USER: &str = "12345678-1234-4234-9234-123456789abc";
const ENROLLMENT: &str = "22345678-1234-4234-9234-123456789abc";
const OTHER: &str = "32345678-1234-4234-9234-123456789abc";

fn token(new: bool) -> String { if new { "b".repeat(43) } else { "a".repeat(43) } }
fn hash(new: bool) -> String { crate::sha256_prefixed(token(new).as_bytes()) }

fn config(basic: bool, renewed: bool) -> Value {
    let mut value = json!({"scheme":"Bearer", "tokenId":USER, "tokenSha256":hash(renewed),
        "sourceCidrs":["127.0.0.1/32"], "expiresAtEpochMs":if renewed { 8000 } else { 6000 },
        "managedRenewal":{"schema":SCHEMA, "enrollmentId":ENROLLMENT,
            "enrollmentExpiresAtEpochMs":10000, "rotatedAtEpochMs":if renewed { 1000 } else { 500 }}});
    if basic { value["basicTransport"] = json!({"username":USER}); }
    if renewed { value["managedRenewal"]["previousToken"] = json!({"tokenSha256":hash(false),
        "originalExpiresAtEpochMs":6000, "expiresAtEpochMs":2000}); }
    value
}

fn snapshot(value: &Value) -> Snapshot {
    let mut snapshot = (*crate::tests::test_snapshot(1)).clone();
    snapshot.policy_id = "serverware-operator-demo".into();
    let principal = &mut snapshot.principals[0];
    principal.source_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    principal.required_headers = BTreeMap::from([("x-agent-class".into(), "build".into())]);
    principal.proxy_authorization = crate::parse_proxy_authorization(Some(value), "agent:test").unwrap();
    snapshot
}

fn headers(basic: bool, new: bool) -> BTreeMap<String, String> {
    let wire = if basic { format!("Basic {}", STANDARD.encode(format!("{USER}:{}", token(new)))) }
        else { format!("Bearer {}", token(new)) };
    BTreeMap::from([("proxy-authorization".into(), wire), ("x-agent-class".into(), "build".into())])
}

fn capture(snapshot: &Snapshot, basic: bool, new: bool, now: u128) -> ConnectAuthentication {
    ConnectAuthentication::capture_at(snapshot, "agent:test", Some("127.0.0.1"), &headers(basic, new), now).unwrap()
}

#[test]
fn current_and_previous_match_both_transports_until_exact_cutoff() {
    for basic in [false, true] {
        let held = snapshot(&config(basic, true));
        let principal = &held.principals[0];
        for wire_basic in [false, basic] {
            for new in [false, true] {
                assert!(principal.matches_at(Some("127.0.0.1"), &headers(wire_basic, new), None, 1999));
                assert!(!principal.matches_at(Some("127.0.0.2"), &headers(wire_basic, new), None, 1999));
            }
            assert!(!principal.matches_at(Some("127.0.0.1"), &headers(wire_basic, false), None, 2000));
            assert!(principal.matches_at(Some("127.0.0.1"), &headers(wire_basic, true), None, 2000));
            assert!(!principal.matches_at(Some("127.0.0.1"), &headers(wire_basic, true), None, 8000));
        }
        let mut value = config(basic, true);
        value["expiresAtEpochMs"] = json!(1500);
        let held = snapshot(&value);
        assert!(held.principals[0].matches_at(Some("127.0.0.1"), &headers(basic, false), None, 1999));
        assert!(!held.principals[0].matches_at(Some("127.0.0.1"), &headers(basic, true), None, 1500));
    }
}

#[test]
fn old_connect_survives_renewal_only_with_its_own_verifier_and_deadline() {
    for basic in [false, true] {
        let before = snapshot(&config(basic, false));
        let held = capture(&before, basic, false, 900);
        let after = snapshot(&config(basic, true));
        assert_ne!(before.principals[0].identity_policy_digest(), after.principals[0].identity_policy_digest());
        assert_ne!(crate::compiled_snapshot_behavior_sha256(&before.principals, &before.credentials, &before.routes),
            crate::compiled_snapshot_behavior_sha256(&after.principals, &after.credentials, &after.routes));
        let binding = held.binding_sha256();
        assert!(held.revalidate_at(&after, 1999).is_ok());
        assert_eq!(held.binding_sha256(), binding);
        assert_eq!(held.revalidate_at(&after, 2000).err(), Some(ConnectAuthenticationError::SelectorRejected));
        let old_reconnect = capture(&after, basic, false, 1500);
        assert!(old_reconnect.revalidate_at(&after, 1999).is_ok());
        assert!(old_reconnect.revalidate_at(&after, 2000).is_err());
        let new = capture(&after, basic, true, 1500);
        assert_ne!(new.proxy_authorization_binding, held.proxy_authorization_binding);
        assert!(new.revalidate_at(&after, 7999).is_ok());
        assert!(new.revalidate_at(&after, 8000).is_err());
    }
}

#[test]
fn previous_pruning_keeps_new_connect_but_never_rebinds_old_connect() {
    for basic in [false, true] {
        let before = snapshot(&config(basic, false));
        let old = capture(&before, basic, false, 900);
        let after = snapshot(&config(basic, true));
        let new = capture(&after, basic, true, 1500);
        let mut value = config(basic, true);
        value["managedRenewal"].as_object_mut().unwrap().remove("previousToken");
        let pruned = snapshot(&value);
        assert!(new.revalidate_at(&pruned, 2500).is_ok());
        assert_eq!(old.revalidate_at(&pruned, 1500).err(), Some(ConnectAuthenticationError::SelectorRejected));
    }
}

#[test]
fn captured_original_expiry_cannot_be_extended_by_later_policy() {
    let before = snapshot(&config(false, false));
    let held = capture(&before, false, false, 900);
    let mut value = config(false, false);
    value["expiresAtEpochMs"] = json!(9000);
    let changed = snapshot(&value);
    assert!(held.revalidate_at(&changed, 5999).is_ok());
    assert_eq!(held.revalidate_at(&changed, 6000).err(), Some(ConnectAuthenticationError::SelectorRejected));
}

#[test]
fn cancellation_replacement_rotation_and_selectors_invalidate_connect() {
    let before = snapshot(&config(true, false));
    let held = capture(&before, true, false, 900);
    for case in 0..8 {
        let mut value = config(true, true);
        match case {
            0 => { value.as_object_mut().unwrap().remove("managedRenewal"); },
            1 => value["managedRenewal"]["enrollmentId"] = json!(OTHER),
            2 => value["managedRenewal"]["enrollmentExpiresAtEpochMs"] = json!(11000),
            3 => { value["tokenId"] = json!(OTHER); value["basicTransport"]["username"] = json!(OTHER); },
            4 => { value.as_object_mut().unwrap().remove("basicTransport"); },
            5 => value["sourceCidrs"] = json!(["127.0.0.0/8"]),
            _ => (),
        }
        let mut changed = snapshot(&value);
        if case == 6 { changed.principals[0].required_headers.insert("x-agent-class".into(), "release".into()); }
        if case == 7 { changed.principals[0].source_cidrs = vec!["127.0.0.1/32".parse().unwrap()]; }
        assert_eq!(held.revalidate_at(&changed, 1500).err(), Some(ConnectAuthenticationError::IdentityPolicyChanged), "case {case}");
    }
    let mut revoked = before.clone(); revoked.principals.clear();
    assert_eq!(held.revalidate_at(&revoked, 1500).err(), Some(ConnectAuthenticationError::PrincipalRevoked));
}

#[test]
fn managed_parser_rejects_nonfinite_unknown_and_malformed_fields() {
    let valid = config(false, true);
    let mut invalid = Vec::new();
    for raw in [Value::Null, json!(false), json!([]), json!({}), json!({"schema":SCHEMA})] {
        let mut value = valid.clone(); value["managedRenewal"] = raw; invalid.push(value);
    }
    for field in ["enrollmentExpiresAtEpochMs", "rotatedAtEpochMs"] {
        for raw in [Value::Null, json!(true), json!(0), json!(-1), json!(1000.0), json!(9_007_199_254_740_992u64)] {
            let mut value = valid.clone(); value["managedRenewal"][field] = raw; invalid.push(value);
        }
    }
    for field in ["originalExpiresAtEpochMs", "expiresAtEpochMs"] {
        for raw in [Value::Null, json!(true), json!(0), json!(-1), json!(1500.0), json!(9_007_199_254_740_992u64)] {
            let mut value = valid.clone(); value["managedRenewal"]["previousToken"][field] = raw; invalid.push(value);
        }
    }
    for (path, raw) in [
        ("/managedRenewal/schema", json!("serverware.proxyTokenRenewal/v2")),
        ("/managedRenewal/enrollmentId", json!("not-a-uuid")),
        ("/managedRenewal/previousToken", Value::Null),
        ("/managedRenewal/previousToken/tokenSha256", json!(hash(true))),
        ("/managedRenewal/previousToken/originalExpiresAtEpochMs", json!(10001)),
        ("/managedRenewal/previousToken/expiresAtEpochMs", json!(1000)),
        ("/managedRenewal/previousToken/expiresAtEpochMs", json!(6001)),
        ("/tokenId", json!("wrong")), ("/expiresAtEpochMs", Value::Null),
        ("/expiresAtEpochMs", json!(1000)), ("/expiresAtEpochMs", json!(10001)),
    ] { let mut value = valid.clone(); *value.pointer_mut(path).unwrap() = raw; invalid.push(value); }
    let mut extra = valid.clone(); extra["managedRenewal"]["unexpected"] = json!(true); invalid.push(extra);
    let mut extra = valid.clone(); extra["managedRenewal"]["previousToken"]["unexpected"] = json!(true); invalid.push(extra);
    for (index, value) in invalid.iter().enumerate() {
        assert!(crate::parse_proxy_authorization(Some(value), "agent:test").is_err(), "case {index}");
    }
}

#[test]
fn overlap_is_five_minutes_maximum_without_current_expiry_coupling() {
    let mut value = config(false, true);
    value["managedRenewal"]["enrollmentExpiresAtEpochMs"] = json!(1_000_000);
    value["managedRenewal"]["previousToken"]["originalExpiresAtEpochMs"] = json!(500_000);
    value["managedRenewal"]["previousToken"]["expiresAtEpochMs"] = json!(301_000);
    assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_ok());
    value["managedRenewal"]["previousToken"]["expiresAtEpochMs"] = json!(301_001);
    assert!(crate::parse_proxy_authorization(Some(&value), "agent:test").is_err());
}

#[test]
fn enrollment_of_expired_manual_token_does_not_revive_it() {
    let mut value = config(false, false);
    value["expiresAtEpochMs"] = json!(100);
    let held = snapshot(&value);
    assert!(!held.principals[0].matches_at(Some("127.0.0.1"), &headers(false, false), None, 900));
    assert!(ConnectAuthentication::capture_at(&held, "agent:test", Some("127.0.0.1"),
        &headers(false, false), 900).is_err());
}

#[test]
fn bearer_only_option_requires_both_signed_operator_profile_and_runtime() {
    let config = config(false, true);
    let mut raw = json!({"apiVersion":"serverware.policy/v1", "metadata":{"id":"serverware-operator-demo"},
        "principals":[{"proxyAuthorization":config}]});
    assert!(validate_raw_policy(&raw).is_ok());
    raw["apiVersion"] = json!("serverware.policy/v2");
    assert!(validate_raw_policy(&raw).is_err());
    raw["apiVersion"] = json!("serverware.policy/v1"); raw["metadata"]["id"] = json!("native");
    assert!(validate_raw_policy(&raw).is_err());
    let mut held = snapshot(&config);
    assert!(require_scope(&held, true).is_ok());
    assert!(require_scope(&held, false).is_err());
    held.principals[0].required_headers.clear();
    held.routes[0].host = "registry.npmjs.org".into();
    held.routes[0].resolved_address_policy = crate::ResolvedAddressPolicy::PublicOnly;
    let profile = crate::operator_demo::test_publish_dispatch_profile(&held);
    let mut state = crate::tests::test_gate_state(std::sync::Arc::new(held.clone()));
    assert!(require_runtime(&state, &held).is_err());
    state.policy_shadow = crate::ShadowRuntime::new_operator_demo(profile);
    state.proxy_ingress_attestation.mode = crate::operator_demo::INGRESS_MODE.into();
    assert!(require_runtime(&state, &held).is_ok());
    state.is_production = true;
    assert!(require_runtime(&state, &held).is_err());
    state.is_production = false;
    state.atomic_release_authorization_enabled = true;
    assert!(require_runtime(&state, &held).is_err());
    state.atomic_release_authorization_enabled = false;
    state.proxy_ingress_attestation.mode = "development-raw".into();
    assert!(require_runtime(&state, &held).is_err());
}
