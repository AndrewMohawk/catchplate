//! Real signed loopback metadata/lease/ACK and actual forwarding decision.
//! The synthetic control plane has no SQLite counter or provider; these tests
//! do not claim durable quota/SDK acceptance or mint a successful send permit.
use super::*;
use crate::operator_x_quota::Request as QuotaRequest;

fn first_decision(fixture: &Fixture) -> (QuotaRequest, Value) {
    assert!(fixture.state.credential_generations.lock().unwrap().is_empty());
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    let mut owner = QuotaRequest::new(Instant::now() + Duration::from_secs(5));
    let input = serde_json::from_value(json!({"method":"POST", "url":"https://api.x.com/2/tweets",
        "headers":{"proxy-authorization":format!("Bearer {TOKEN}"),
            "authorization":x_post::PLACEHOLDER,"content-type":"application/json"},
        "body":"{\"text\":\"synthetic release test\"}"})).unwrap();
    let (decision, release) = decide_internal_for_forward_with_shadow(&fixture.state,
        &fixture.snapshot, input, Some("agent:test"), None, None, Some(&mut owner));
    assert!(release.is_none());
    assert_eq!(decision["allowed"], true, "metadata-only first decision: {decision}");
    assert_eq!(decision["credential_version"], 7);
    assert_eq!(decision["canonical_request"]["v"], 2);
    assert_eq!(decision["operation"]["operation"], "tweets.write");
    assert_eq!(decision["injection"]["secret_available"], false);
    assert_eq!(decision["policy_effect_results"]["credential_secret_available"], false);
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    let metadata = peek_cached_credential_lease_info(&fixture.state, &fixture.snapshot, &fixture.scope).unwrap();
    assert_eq!(metadata.version, 7);
    assert!(!metadata.secret_available);
    assert_eq!(metadata.metadata, fixture.authority.metadata());
    (owner, decision)
}

fn private_lease(fixture: &Fixture, receiver: &Receiver, owner: &mut QuotaRequest, decision: &Value) -> SecretLease {
    // Queue only the receiver's bounded response permission. The request still
    // verifies the signed ACK before receiving the wrapped lease. This fixture
    // exercises the ACK protocol, not a durable database receiver.
    receiver.release.send(()).unwrap();
    let lease = owner.prepare_release_if_admitted(&fixture.state, &fixture.snapshot, decision,
        "POST", &Url::parse("https://api.x.com/2/tweets").unwrap(), false).unwrap().unwrap();
    assert_eq!(lease.version, 7);
    assert_eq!(lease.metadata, fixture.authority.metadata());
    assert_eq!(lease.secret.as_str(), SECRET);
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    lease
}

fn transcript(receiver: Receiver, decision: &Value) {
    let start = receiver.entered.recv_timeout(WAIT).unwrap();
    let calls = receiver.finish();
    assert_eq!(calls.iter().map(|(kind,_)| kind.as_str()).collect::<Vec<_>>(),
        ["generationMetadata", "attestation", "audit", "dispatchSecret"]);
    assert_eq!(calls[0].1["apiVersion"], "serverware.credentialLeaseRequest/v3");
    assert_eq!(calls[2].1, start);
    let events = start["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["eventType"], "data_plane.credential.release_started");
    for name in ["request_digest", "operation_digest", "attempt_id"] {
        assert_eq!(events[0]["event"][name], decision[name]);
    }
    assert_eq!(calls[3].1["apiVersion"], "serverware.operatorXQuotaCredentialLeaseRequest/v1");
    assert_eq!(calls[3].1["operatorXQuota"]["canonicalRequest"], decision["canonical_request"]);
    assert!(!serde_json::to_string(&start).unwrap().contains("synthetic-google-release-secret"));
}

#[test]
fn managed_quota_first_request_metadata_then_private_lease_projects_availability() {
    let fixture = Fixture::for_provider_with_quota(60_000, true, true);
    let receiver = Receiver::start(&fixture, "ok");
    let (mut owner, original) = first_decision(&fixture);
    let lease = private_lease(&fixture, &receiver, &mut owner, &original);
    let plan = &original["injection"]["plan"];
    assert!(active_credential_injection_binding(&fixture.snapshot, &original, plan, &lease).is_err());
    let mut decision = original.clone();
    owner.record_acquired_secret(&fixture.state, &fixture.snapshot, &mut decision, &lease).unwrap();
    let mut expected = original.clone();
    expected["injection"]["secret_available"] = json!(true);
    expected["policy_effect_results"]["credential_secret_available"] = json!(true);
    assert_eq!(decision, expected, "exactly two observations change; no canonical authority changes");
    assert!(active_credential_injection_binding(&fixture.snapshot, &decision, plan, &lease).is_ok());
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    assert!(!peek_cached_credential_lease_info(&fixture.state, &fixture.snapshot, &fixture.scope).unwrap().secret_available);
    // Secret availability cannot substitute for the still-missing one-use
    // durable claim. No provider transport is constructed or executed here.
    assert!(owner.acquire_send(&fixture.state, &fixture.snapshot, &credential_lease_release_binding(&lease)).is_err());
    let retained = decision.clone();
    assert!(owner.record_acquired_secret(&fixture.state, &fixture.snapshot, &mut decision, &lease).is_err());
    assert_eq!(decision, retained);
    transcript(receiver, &original);
}

#[test]
fn managed_quota_invalid_private_lease_or_currentness_never_projects_availability() {
    let fixture = Fixture::for_provider_with_quota(60_000, true, true);
    let receiver = Receiver::start(&fixture, "ok");
    let (mut owner, original) = first_decision(&fixture);
    let lease = private_lease(&fixture, &receiver, &mut owner, &original);
    for mode in ["missing-owner", "secret", "version", "metadata", "scope", "plan", "canonical", "digest", "attempt"] {
        let mut invalid = lease.clone();
        let mut decision = original.clone();
        match mode {
            "secret" => invalid.secret = Zeroizing::new("{\"access_token\":\"other\"}".into()),
            "version" => invalid.version += 1,
            "metadata" => invalid.metadata_sha256 = sha256_prefixed(b"other metadata"),
            "scope" => invalid.scope = CredentialLeaseScope::new("other", "route:test", "x-account"),
            "plan" => decision["injection"]["plan"]["field"] = json!("refresh_token"),
            "canonical" => decision["canonical_request"]["credential_version"] = json!("8"),
            "digest" => decision["request_digest"] = json!(sha256_prefixed(b"other request")),
            "attempt" => decision["attempt_id"] = json!(sha256_prefixed(b"other attempt")),
            _ => {},
        }
        let before = decision.clone();
        let absent = QuotaRequest::new(Instant::now() + WAIT);
        let selected = if mode == "missing-owner" { &absent } else { &owner };
        assert!(selected.record_acquired_secret(&fixture.state, &fixture.snapshot, &mut decision, &invalid).is_err(), "{mode}");
        assert_eq!(decision, before, "failed {mode} must not mutate the decision");
    }
    let original_generation = fixture.state.credential_generations.lock().unwrap()[&fixture.scope].clone();
    for mode in ["missing", "wall-expired", "monotonic-expired", "generation-changed", "inactive-snapshot"] {
        {
            let mut cache = fixture.state.credential_generations.lock().unwrap();
            match mode {
                "missing" => { cache.remove(&fixture.scope); },
                "wall-expired" => cache.get_mut(&fixture.scope).unwrap().expires_at_epoch_ms = now_epoch_ms(),
                "monotonic-expired" => cache.get_mut(&fixture.scope).unwrap().expires_at_monotonic = Instant::now(),
                "generation-changed" => cache.get_mut(&fixture.scope).unwrap().version += 1,
                _ => *fixture.state.snapshot.write().unwrap() = Arc::new((*fixture.snapshot).clone()),
            }
        }
        let mut decision = original.clone();
        assert!(owner.record_acquired_secret(&fixture.state, &fixture.snapshot, &mut decision, &lease).is_err(), "{mode}");
        assert_eq!(decision, original);
        fixture.state.credential_generations.lock().unwrap().insert(fixture.scope.clone(), original_generation.clone());
        *fixture.state.snapshot.write().unwrap() = Arc::clone(&fixture.snapshot);
    }
    assert!(fixture.state.credential_leases.lock().unwrap().is_empty());
    transcript(receiver, &original);
}
