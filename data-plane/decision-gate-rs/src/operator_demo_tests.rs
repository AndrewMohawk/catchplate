//! Offline, synthetic fixtures only. No provider traffic or process environment mutation.
// The child controls exercise validated Profile admission, not the fixed-path
// deployment Selection::admit or live startup marker provisioning.
#[path = "operator_audit_publication_integration_tests.rs"]
mod publication_integration;
#[path = "operator_google_reconciliation_tests.rs"]
mod google_reconciliation;

use super::*;
use crate::tests::{generic_policy_route, policy_with_route, test_gate_state, test_snapshot};
use crate::{
    canonical_json, load_snapshot, now_epoch_ms, refresh_policy_snapshot,
    response_proof_signing_material, sha256_prefixed, signature_payload, DecisionRequest,
    PolicyTrustRootSource, ShadowIngressKind, ShadowRuntime,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN: &str = "synthetic-client-token-never-a-provider-secret";

fn snapshot(sequence: u64) -> Snapshot {
    let mut snapshot = (*test_snapshot(sequence)).clone();
    snapshot.policy_id = "serverware-operator-demo".to_owned();
    snapshot.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256: sha256_prefixed(TOKEN.as_bytes()),
        source_cidrs: vec![],
        expires_at_ms: Some(10_000),
        basic_transport: None,
    });
    snapshot.routes[0].host = "api.example.com".to_owned();
    snapshot.routes[0].resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    snapshot
}

fn profile(snapshot: &Snapshot, deployment: Deployment) -> Profile {
    let profile = Profile {
        deployment: Arc::new(deployment),
        google: None,
        active: Arc::new(RwLock::new(ApprovedPolicy {
            high_water: policy_high_water_for(snapshot),
            targets: BTreeSet::new(),
        })),
    };
    let approved = profile
        .validate_snapshot(snapshot)
        .expect("admitted synthetic policy");
    *profile.active.write().unwrap() = approved;
    profile
}

fn public_deployment() -> Deployment {
    Deployment::parse(r#"["https://api.example.com"]"#, None).unwrap()
}

#[test]
fn operator_demo_basic_transport_requires_validated_operator_runtime() {
    let mut candidate = snapshot(1);
    let username = "a1111111-1111-4111-8111-111111111111";
    let config = json!({"scheme":"Bearer", "tokenId":username,
        "tokenSha256":sha256_prefixed("a".repeat(43).as_bytes()),
        "expiresAtEpochMs":10_000, "basicTransport":{"username":username}});
    candidate.principals[0].proxy_authorization =
        crate::parse_proxy_authorization(Some(&config), "agent:test").unwrap();
    let profile = profile(&candidate, public_deployment());
    let candidate = Arc::new(candidate);
    let mut state = test_gate_state(candidate.clone());
    assert!(crate::proxy_basic_transport::require_runtime(&state, &candidate).is_err());
    state.policy_shadow = ShadowRuntime::new_operator_demo(profile);
    state.proxy_ingress_attestation.mode = INGRESS_MODE.into();
    assert!(crate::proxy_basic_transport::require_runtime(&state, &candidate).is_ok());
    state.is_production = true;
    assert!(crate::proxy_basic_transport::require_runtime(&state, &candidate).is_err());
    state.is_production = false;
    state.atomic_release_authorization_enabled = true;
    assert!(crate::proxy_basic_transport::require_runtime(&state, &candidate).is_err());
    state.atomic_release_authorization_enabled = false;
    state.proxy_ingress_attestation.mode = "development-raw".into();
    assert!(crate::proxy_basic_transport::require_runtime(&state, &candidate).is_err());
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = env::temp_dir().join(format!(
            "serverware-operator-demo-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove task test scratch");
    }
}

#[test]
fn operator_demo_selection_refuses_native_production_and_synthetic_aliases() {
    assert!(!selected(None, None, None, None, false, false).unwrap());
    assert!(selected(Some("1"), Some("dev"), Some("0"), Some("0"), false, false).unwrap());
    for (flag, channel, production, synthetic, native, forbidden) in [
        ("yes", "dev", None, None, false, false),
        ("1", "production", None, None, false, false),
        ("1", "dev", Some("1"), None, false, false),
        ("1", "dev", None, Some("1"), false, false),
        ("1", "dev", None, None, true, false),
        ("1", "dev", None, None, false, true),
    ] {
        assert!(selected(
            Some(flag),
            Some(channel),
            production,
            synthetic,
            native,
            forbidden
        )
        .is_err());
    }
}

#[test]
fn operator_demo_deployment_origins_and_fixture_ips_are_narrow_and_immutable() {
    assert_eq!(
        Target::parse("https://api.example.com:443/").unwrap(),
        Target::parse("https://api.example.com").unwrap()
    );
    for origin in [
        "http://api.example.com",
        "https://api.example.com:444",
        "https://127.0.0.1",
        "https://[::1]",
        "https://api.example.com/path",
        "https://a@api.example.com",
        "https://api.example.com?x=1",
        "https://api.example.com#x",
        "https://localhost",
        "https://api.local",
        "https://api.test",
        "https://*.example.com",
        "https://api.example.com.",
        "https://-bad.example.com",
        "https://demo-upstream",
    ] {
        assert!(Target::parse(origin).is_err(), "accepted {origin}");
    }
    assert!(Deployment::parse("[]", None).is_err());
    assert!(Deployment::parse(
        r#"["https://api.example.com","https://api.example.com:443"]"#,
        None
    )
    .is_err());
    let fixture = r#"["https://demo-upstream:8443"]"#;
    assert!(Deployment::parse(fixture, Some(r#"["172.16.249.18/32"]"#)).is_ok());
    assert!(Deployment::parse(fixture, Some(r#"["127.0.0.1/32"]"#)).is_ok());
    for cidrs in [
        "[]",
        r#"["172.16.249.0/24"]"#,
        r#"["169.254.169.254/32"]"#,
        r#"["8.8.8.8/32"]"#,
        r#"["127.0.0.1/32","127.0.0.2/32"]"#,
    ] {
        assert!(Deployment::parse(fixture, Some(cidrs)).is_err());
    }
    assert!(Deployment::parse(
        r#"["https://api.example.com"]"#,
        Some(r#"["127.0.0.1/32"]"#)
    )
    .is_err());
}

#[test]
fn operator_demo_marker_is_distinct_private_regular_and_single_link() {
    let scratch = Scratch::new();
    let marker = scratch.0.join(".serverware-operator-demo.json");
    fs::write(&marker, MARKER).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    validate_marker(&scratch.0).unwrap();
    fs::hard_link(&marker, scratch.0.join("other")).unwrap();
    assert!(validate_marker(&scratch.0).is_err());
    fs::remove_file(scratch.0.join("other")).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(validate_marker(&scratch.0).is_err());
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &marker,
        b"{\"schema\": \"serverware.developmentSandbox/v1\", \"syntheticOnly\": true}\n",
    )
    .unwrap();
    assert!(validate_marker(&scratch.0).is_err());
    fs::write(&marker, MARKER).unwrap();
    fs::rename(&marker, scratch.0.join("real")).unwrap();
    symlink("real", &marker).unwrap();
    assert!(validate_marker(&scratch.0).is_err());
}

#[test]
fn operator_demo_every_principal_requires_hashed_bearer_and_expiry() {
    let original = snapshot(1);
    let profile = profile(&original, public_deployment());
    for invalid in [
        None,
        Some(ProxyAuthorizationPolicy::LegacyExact(
            "Bearer raw-secret".into(),
        )),
        Some(ProxyAuthorizationPolicy::BearerToken {
            token_sha256: sha256_prefixed(b"token"),
            source_cidrs: vec![],
            expires_at_ms: None,
            basic_transport: None,
        }),
        Some(ProxyAuthorizationPolicy::BearerToken {
            token_sha256: "sha256:not-a-digest".into(),
            source_cidrs: vec![],
            expires_at_ms: Some(500),
            basic_transport: None,
        }),
    ] {
        let mut candidate = original.clone();
        let mut extra = candidate.principals[0].clone();
        extra.id = "agent:unexpected-fallback".into();
        extra.proxy_authorization = invalid;
        candidate.principals.push(extra);
        assert!(profile.validate_snapshot(&candidate).is_err());
    }
    let mut candidate = original.clone();
    candidate.principals[0]
        .required_headers
        .insert("x-identity".into(), "trusted".into());
    assert!(profile.validate_snapshot(&candidate).is_err());
}

#[test]
fn operator_demo_bearer_authentication_denies_missing_wrong_and_expired_tokens() {
    let snapshot = snapshot(1);
    let principal = &snapshot.principals[0];
    assert!(authenticated_principal(principal));
    let good = BTreeMap::from([("proxy-authorization".into(), format!("Bearer {TOKEN}"))]);
    let bad = BTreeMap::from([("proxy-authorization".into(), "Bearer different".into())]);
    assert!(principal.matches_at(None, &good, None, 9_999));
    assert!(!principal.matches_at(None, &good, None, 10_000));
    assert!(!principal.matches_at(None, &good, None, 10_001));
    assert!(!principal.matches_at(None, &bad, None, 9_999));
    assert!(!principal.matches_at(None, &BTreeMap::new(), None, 9_999));
    // Keeping an expired principal in a later policy is safe: it remains denied
    // and does not prevent an unrelated connection from being edited/deleted.
    profile(&snapshot, public_deployment())
        .validate_snapshot(&snapshot)
        .unwrap();
}

#[test]
fn operator_demo_effects_bind_policy_exact_target_and_dispatch_request() {
    let snapshot = snapshot(1);
    let profile = profile(&snapshot, public_deployment());
    let commitment = sha256_prefixed(b"synthetic final request");
    let permit = profile.effect(&snapshot, "route:test").unwrap();
    assert!(permit
        .bind_dispatch(
            &snapshot.hash,
            "https",
            "other.example.com",
            443,
            &commitment
        )
        .is_err());
    assert!(profile
        .effect_for_target(&snapshot.hash, "http", "api.example.com", 80)
        .is_err());
    assert!(profile
        .effect_for_target(
            &sha256_prefixed(b"other policy"),
            "https",
            "api.example.com",
            443
        )
        .is_err());
    let permit = profile
        .effect(&snapshot, "route:test")
        .unwrap()
        .bind_dispatch(&snapshot.hash, "https", "api.example.com", 443, &commitment)
        .unwrap();
    permit.validate(&snapshot.hash, &commitment).unwrap();
    assert!(permit
        .validate(&snapshot.hash, &sha256_prefixed(b"changed request"))
        .is_err());
}

#[test]
fn operator_demo_routes_cannot_expand_public_or_fixture_address_authority() {
    let original = snapshot(1);
    let public = profile(&original, public_deployment());
    let mut candidate = original.clone();
    candidate.routes[0].resolved_address_policy =
        ResolvedAddressPolicy::ExplicitCidrs(vec!["127.0.0.1/32".parse().unwrap()]);
    assert!(public.validate_snapshot(&candidate).is_err());
    candidate.routes[0].host = "demo-upstream".into();
    candidate.routes[0].port = 8443;
    let fixture = profile(
        &candidate,
        Deployment::parse(
            r#"["https://demo-upstream:8443"]"#,
            Some(r#"["127.0.0.1/32"]"#),
        )
        .unwrap(),
    );
    candidate.routes[0].resolved_address_policy =
        ResolvedAddressPolicy::ExplicitCidrs(vec!["127.0.0.2/32".parse().unwrap()]);
    assert!(fixture.validate_snapshot(&candidate).is_err());
    candidate.routes[0].resolved_address_policy = ResolvedAddressPolicy::PublicOnly;
    assert!(fixture.validate_snapshot(&candidate).is_err());
}

#[test]
fn operator_demo_monotonic_reload_revokes_old_effects_and_readiness() {
    let old = snapshot(1);
    let profile = profile(&old, public_deployment());
    let old_effect = profile.effect(&old, "route:test").unwrap();
    let next = snapshot(2);
    let prepared = profile.prepare_reload(&old, &next).unwrap();
    profile.commit_reload(prepared).unwrap();
    assert!(profile.matches(&next.hash));
    assert!(!profile.matches(&old.hash));
    assert!(old_effect.validate(&old.hash).is_err());
    assert!(profile.prepare_reload(&next, &old).is_err());
    let mut stale_sequence = snapshot(3);
    stale_sequence.policy_sequence = 2;
    assert!(profile.prepare_reload(&next, &stale_sequence).is_err());
    let mut changed_id = snapshot(3);
    changed_id.policy_id = "serverware-demo".into();
    assert!(profile.prepare_reload(&next, &changed_id).is_err());
    let runtime = ShadowRuntime::new_operator_demo(profile);
    assert!(runtime.serving_ready(&next));
    assert!(!runtime.serving_ready(&old));
    assert_eq!(runtime.status()["mode"], "operator-demo");
    assert_eq!(runtime.status()["production_custody_bound"], false);
}

fn signed_policy(key: &SigningKey, key_id: &str, sequence: u64, deny_all: bool) -> Value {
    let mut route = generic_policy_route("none", json!(1024));
    route["match"]["host"] = json!("api.example.com");
    let mut policy = policy_with_route(route);
    policy["principals"] = json!([{"id":"agent:test", "proxyAuthorization":{
        "scheme":"Bearer", "tokenId":"synthetic", "tokenSha256":sha256_prefixed(TOKEN.as_bytes()),
        "expiresAtEpochMs":now_epoch_ms() as u64 + 86_400_000,
    }}]);
    if deny_all {
        // The shared policy schema requires at least one route. An expired,
        // unrecoverable client principal makes this sentinel deny all traffic.
        policy["principals"][0]["proxyAuthorization"]["expiresAtEpochMs"] = json!(1);
        policy["routes"][0]["match"]["methods"] = json!(["GET"]);
        policy["routes"][0]["match"]["paths"] =
            json!(["/__serverware_operator_demo_unconfigured__"]);
    }
    policy["apiVersion"] = json!("serverware.policy/v1");
    policy["kind"] = json!("PolicyBundle");
    policy["metadata"] = json!({"id":"serverware-operator-demo", "sequence":sequence,
        "rollbackEpoch":1, "signingKeyId":key_id});
    let signature = key.sign(canonical_json(&signature_payload(&policy)).as_bytes());
    policy["metadata"]["signature"] = json!(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ));
    policy
}

#[test]
fn operator_demo_signed_reload_changes_ready_hash_without_restarting_or_losing_highwater() {
    let scratch = Scratch::new();
    let path = scratch.0.join("policy.json");
    let trust_path = scratch.0.join("trust.pem");
    let high_water_path = scratch.0.join("high-water.json");
    let (key, pem, key_id) = response_proof_signing_material().unwrap();
    fs::write(&trust_path, pem).unwrap();
    let trust = PolicyTrustRootSource::File(trust_path.to_string_lossy().into_owned());
    let initial = signed_policy(&key, &key_id, 1, true);
    fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();
    let old =
        Arc::new(load_snapshot(path.to_str().unwrap(), &trust, "sha256:test-binary").unwrap());
    let mut state = test_gate_state(Arc::clone(&old));
    state.policy_path = path.to_string_lossy().into_owned();
    state.policy_trust_root_source = trust;
    state.policy_high_water_path = Some(high_water_path.clone());
    state.policy_shadow = ShadowRuntime::new_operator_demo(profile(&old, public_deployment()));
    let publication_lock = scratch.0.join(crate::operator_audit_publication::LOCK_NAME);
    fs::write(&publication_lock, []).unwrap();
    fs::set_permissions(&publication_lock, fs::Permissions::from_mode(0o600)).unwrap();
    state.operator_audit_publication = Some(Arc::new(
        crate::operator_audit_publication::Owner::open(&path).unwrap()));
    assert!(state.policy_shadow.serving_ready(&old));
    let bootstrap_headers =
        BTreeMap::from([("proxy-authorization".into(), format!("Bearer {TOKEN}"))]);
    assert!(!old.principals[0].matches_at(None, &bootstrap_headers, None, now_epoch_ms()));
    let next = signed_policy(&key, &key_id, 2, false);
    fs::write(&path, serde_json::to_vec(&next).unwrap()).unwrap();
    assert!(refresh_policy_snapshot(&state, true).unwrap());
    let active = current_snapshot(&state);
    assert_ne!(old.hash, active.hash);
    assert!(state.policy_shadow.serving_ready(&active));
    assert!(!state.policy_shadow.serving_ready(&old));
    let request: DecisionRequest = serde_json::from_value(
        json!({"method":"POST", "url":"https://api.example.com/resource", "headers":{}}),
    )
    .unwrap();
    assert!(!state
        .policy_shadow
        .capture(
            &active,
            &request,
            None,
            ShadowIngressKind::ForwardedHttp,
            now_epoch_ms(),
            None
        )
        .must_fail_closed());
    assert!(state
        .policy_shadow
        .capture(
            &old,
            &request,
            None,
            ShadowIngressKind::ForwardedHttp,
            now_epoch_ms(),
            None
        )
        .must_fail_closed());
    let high_water: Value = serde_json::from_slice(&fs::read(&high_water_path).unwrap()).unwrap();
    assert_eq!(high_water["sequence"], 2);
    fs::write(&path, serde_json::to_vec(&initial).unwrap()).unwrap();
    assert!(refresh_policy_snapshot(&state, true).is_err());
    assert_eq!(current_snapshot(&state).hash, active.hash);
    let mut tampered = next;
    tampered["metadata"]["sequence"] = json!(3);
    fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(refresh_policy_snapshot(&state, true).is_err());
    assert_eq!(current_snapshot(&state).hash, active.hash);
    assert!(state.policy_shadow.serving_ready(&active));
}

#[test]
fn operator_demo_source_keeps_reload_guard_native_paths_and_post_send_validation() {
    let main = include_str!("main.rs");
    let reload = main
        .split("fn refresh_policy_snapshot(")
        .nth(1)
        .unwrap()
        .split("fn policy_worker(")
        .next()
        .unwrap();
    assert!(
        reload.find("begin_mutation()").unwrap() < reload.find("prepare_operator_reload").unwrap()
    );
    assert!(
        reload.find("validate_policy_high_water").unwrap()
            < reload.find("commit_operator_reload").unwrap()
    );
    let send = main
        .split("fn send_upstream_request_with_current_lease_and_timeout_validated_and_finalized")
        .nth(1)
        .unwrap()
        .split("fn earliest_credential_lease_expiry_epoch_ms")
        .next()
        .unwrap();
    let after_send = send.split("client.execute(request)").nth(1).unwrap();
    assert!(after_send.contains("else if let Some(permit) = operator_dispatch_permit"));
    assert!(after_send.contains("permit.commit_provider_send(effect_state"));
    let synthetic = include_str!("development_sandbox.rs");
    assert!(synthetic.contains("serverware.developmentSandbox/v1"));
    assert!(synthetic.contains("(\"https\", \"demo-upstream\", 8443)"));
    assert!(!synthetic.contains("operator_demo"));
}
