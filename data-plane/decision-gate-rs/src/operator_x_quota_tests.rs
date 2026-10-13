//! Component controls for real DTO validators, built reqwest bytes and terminal
//! owner transitions. No fabricated signed ACK or native authority is accepted;
//! complete HTTP/SQLite/SDK acceptance is a separate joined fixture.
use super::*;

fn sha(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn wire() -> Value {
    let now = now_epoch_ms();
    let expiry = (now + 4000).min((now / DAY_MS + 1) * DAY_MS) as u64;
    json!({"apiVersion":REQUEST,"purpose":"dispatchSecret","principalId":"application-a","routeId":"route-a",
        "credentialId":"account-a","expectedCredentialVersion":7,"expectedMetadataSha256":sha('1'),
        "recipientPublicKey":general_purpose::URL_SAFE_NO_PAD.encode([1u8;32]),
        "recipientKeyId":sha('2'),"recipientNonce":general_purpose::URL_SAFE_NO_PAD.encode([2u8;32]),
        "policyHash":sha('3'),"dataPlaneBinaryDigest":sha('4'),"maxTtlSeconds":5,
        "operatorXQuota":{"canonicalRequest":{"fixture":"no plaintext post text"},"requestDigest":sha('5'),
            "operationDigest":sha('6'),"attemptNonce":sha('7'),"expiresAtEpochMs":expiry}})
}
fn reservation(wire: &Value) -> Reservation {
    Reservation {
        schema: RESERVATION.into(),
        reservation_id: "11111111-1111-4111-8111-111111111111".into(),
        bucket_key: sha('8'),
        utc_day: (now_epoch_ms() / DAY_MS) as u64,
        expires_at_epoch_ms: wire["operatorXQuota"]["expiresAtEpochMs"].as_u64().unwrap(),
        binding_digest: digest_json_ensure_ascii(&binding(wire)),
    }
}
fn lease() -> SecretLease {
    SecretLease {
        profile: ReleaseProfile::Legacy,
        scope: CredentialLeaseScope::new("application-a", "route-a", "account-a"),
        version: 7,
        secret: Zeroizing::new(
            r#"{"access_token":"synthetic-access-canary","refresh_token":"must-not-inject"}"#
                .into(),
        ),
        metadata: BTreeMap::new(),
        metadata_sha256: sha('1'),
        policy_hash: sha('3'),
        request_authority: None,
        release_authorization: None,
        expires_at_epoch_ms: now_epoch_ms() + 4000,
        expires_at_monotonic: Instant::now() + Duration::from_secs(4),
    }
}
fn injection() -> Value {
    json!({"type":"bearer","header":"Authorization","field":"access_token"})
}
fn built(body: &[u8]) -> reqwest::blocking::Request {
    reqwest::blocking::Client::new()
        .post("https://api.x.com/2/tweets")
        .header("Authorization", "Bearer synthetic-access-canary")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body.to_vec())
        .build()
        .unwrap()
}

#[test]
fn operator_x_quota_profile_flag_and_no_implicit_capability() {
    assert!(!selected(None).unwrap());
    assert!(!selected(Some("0")).unwrap());
    assert!(selected(Some("1")).unwrap());
    for flag in ["", "true", "01", " 1", "1 "] {
        assert!(selected(Some(flag)).is_err());
    }
    let snapshot = crate::tests::test_snapshot(1);
    let mut state = crate::tests::test_gate_state(snapshot);
    assert!(!ordinary(&state));
    assert!(capability(&state).is_null());
    state.operator_x_quota_enabled = true;
    // A flag on a generic/native-unadmitted runtime creates no authority.
    assert!(!ordinary(&state));
    assert!(capability(&state).is_null());
    state.is_production = true;
    assert!(!ordinary(&state));
}

#[test]
fn operator_x_quota_original_twelve_field_binding_is_exact() {
    let raw = wire();
    let original = binding(&raw);
    assert_eq!(
        original,
        json!({"principal_id":"application-a","route_id":"route-a","credential_id":"account-a",
        "credential_version":7,"credential_metadata_digest":sha('1'),"policy_hash":sha('3'),"request_digest":sha('5'),
        "operation_digest":sha('6'),"attempt_nonce":sha('7'),
        "recipient_digest":digest_json_ensure_ascii(&json!({"recipientKeyId":sha('2'),"recipientNonce":general_purpose::URL_SAFE_NO_PAD.encode([2u8;32])})),
        "request_binding_digest":digest_json_ensure_ascii(&raw),"expires_at_epoch_ms":raw["operatorXQuota"]["expiresAtEpochMs"]})
    );
    for key in [
        "principalId",
        "routeId",
        "credentialId",
        "policyHash",
        "expectedCredentialVersion",
        "expectedMetadataSha256",
        "recipientKeyId",
        "recipientNonce",
        "dataPlaneBinaryDigest",
    ] {
        let mut changed = raw.clone();
        changed[key] = json!("different");
        assert_ne!(binding(&changed), original, "{key}");
    }
    for key in [
        "canonicalRequest",
        "requestDigest",
        "operationDigest",
        "attemptNonce",
        "expiresAtEpochMs",
    ] {
        let mut changed = raw.clone();
        changed["operatorXQuota"][key] = Value::Null;
        assert_ne!(binding(&changed), original, "{key}");
    }
}

#[test]
fn operator_x_quota_reservation_is_closed_and_request_bound() {
    let raw = wire();
    let value = reservation(&raw);
    assert!(reservation_matches(&value, &raw));
    let base = serde_json::to_value(&value).unwrap();
    for key in ["schema", "reservation_id", "bucket_key", "binding_digest"] {
        let mut changed = base.clone();
        changed[key] = json!("other");
        assert!(!reservation_matches(
            &serde_json::from_value(changed).unwrap(),
            &raw
        ));
    }
    for key in ["utc_day", "expires_at_epoch_ms"] {
        let mut changed = base.clone();
        changed[key] = json!(0);
        assert!(!reservation_matches(
            &serde_json::from_value(changed).unwrap(),
            &raw
        ));
    }
    let mut extra = base.clone();
    extra["authority"] = json!(true);
    assert!(serde_json::from_value::<Reservation>(extra).is_err());
    let mut boolean = base;
    boolean["utc_day"] = json!(true);
    assert!(serde_json::from_value::<Reservation>(boolean).is_err());
}

#[test]
fn operator_x_quota_claim_cannot_cross_day_expiry_or_binding() {
    let raw = wire();
    let reserved = reservation(&raw);
    let now = now_epoch_ms();
    let mut value = serde_json::to_value(&reserved).unwrap();
    value["schema"] = json!(CLAIM);
    value["claimed_at_epoch_ms"] = json!(now as u64);
    let claim: Claim = serde_json::from_value(value.clone()).unwrap();
    assert!(claim_matches(&claim, &reserved, now));
    assert!(!claim_matches(
        &claim,
        &reserved,
        u128::from(reserved.expires_at_epoch_ms)
    ));
    assert!(!claim_matches(
        &claim,
        &reserved,
        (u128::from(reserved.utc_day) + 1) * DAY_MS
    ));
    assert!(!claim_matches(&claim, &reserved, now - 1));
    for key in ["schema", "reservation_id", "bucket_key", "binding_digest"] {
        let mut changed = value.clone();
        changed[key] = json!("other");
        assert!(!claim_matches(
            &serde_json::from_value(changed).unwrap(),
            &reserved,
            now
        ));
    }
    for key in ["utc_day", "expires_at_epoch_ms", "claimed_at_epoch_ms"] {
        let mut changed = value.clone();
        changed[key] = json!(u64::MAX);
        assert!(!claim_matches(
            &serde_json::from_value(changed).unwrap(),
            &reserved,
            now
        ));
    }
    value["nativeProof"] = json!(true);
    assert!(serde_json::from_value::<Claim>(value).is_err());
}

#[test]
fn operator_x_quota_built_request_uses_oauth_field_and_all_canonical_bytes() {
    let body = br#"{"text":"synthetic"}"#;
    let lease = lease();
    let request = built(body);
    let mut raw = wire();
    raw["operatorXQuota"]["canonicalRequest"] = json!({"request":{"body_sha256":sha256_prefixed(body),
        "headers":{"host":"api.x.com","content-length":body.len().to_string(),"content-type":"application/json","accept":"application/json"}}});
    validate_built(&raw, &lease, &injection(), &request).unwrap();
    for (header, value) in [
        ("accept", "text/plain"),
        ("content-type", "text/plain"),
        ("host", "elsewhere"),
        ("content-length", "999"),
        ("authorization", "Bearer must-not-inject"),
        ("x-added", "value"),
        ("transfer-encoding", "chunked"),
    ] {
        let mut changed = built(body);
        changed.headers_mut().insert(
            HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        assert!(
            validate_built(&raw, &lease, &injection(), &changed).is_err(),
            "{header}"
        );
    }
    let mut changed = built(body);
    changed
        .headers_mut()
        .append("accept", HeaderValue::from_static("application/json"));
    assert!(validate_built(&raw, &lease, &injection(), &changed).is_err());
    assert!(validate_built(&raw, &lease, &injection(), &built(br#"{"text":"other"}"#)).is_err());
    let mut changed = built(body);
    *changed.url_mut() = Url::parse("https://api.x.com/2/tweets?other=1").unwrap();
    assert!(validate_built(&raw, &lease, &injection(), &changed).is_err());
}

#[test]
fn operator_x_quota_claim_nonce_is_fresh_canonical_32_bytes() {
    let first = http_nonce().unwrap();
    let second = http_nonce().unwrap();
    assert_ne!(first, second);
    for nonce in [first, second] {
        assert_eq!(nonce.len(), 43);
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(&nonce).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(general_purpose::URL_SAFE_NO_PAD.encode(bytes), nonce);
        assert!(!nonce.starts_with("sha256:"));
    }
}

#[test]
fn operator_x_quota_terminal_claim_cannot_restart_or_extend_owner() {
    let snapshot = crate::tests::test_snapshot(1);
    let state = crate::tests::test_gate_state(Arc::clone(&snapshot));
    let original = Instant::now() + Duration::from_secs(1);
    let mut owner = Request::new(original);
    let lease = lease();
    let binding = credential_lease_release_binding(&lease);
    let request = built(b"{}");
    // Actual first failure occurs before any HTTP because no admitted pin exists.
    assert!(owner.claim(&state, &snapshot, &binding, &request).is_err());
    assert!(owner.claim_started);
    assert!(owner.claim(&state, &snapshot, &binding, &request).is_err());
    assert!(owner.permit.is_none());
    assert!(owner.deadline <= original);
    assert!(owner
        .consume_before_execute(&state, &snapshot, &binding, &request)
        .is_err());
    assert!(!owner.still_releasable(&state, &snapshot, &binding));
}

#[test]
fn operator_x_quota_actual_send_join_claims_outside_guards_and_consumes_at_execute() {
    let source = include_str!("main.rs");
    let body = source
        .split("fn send_upstream_request_with_quota_owner<F, G>(")
        .nth(1)
        .unwrap()
        .split("fn earliest_credential_lease_expiry_epoch_ms")
        .next()
        .unwrap();
    assert!(body.find("owner.claim(").unwrap() < body.find("owner.acquire_send(").unwrap());
    assert!(
        body.find("owner.consume_before_execute(").unwrap()
            < body.find("client.execute(request)").unwrap()
    );
    assert!(
        body.find("upstream_send_deadline_timeout(deadlines)")
            .unwrap()
            < body.find("owner.consume_before_execute(").unwrap()
    );
    assert!(body.contains("acquire_upstream_send_authority(state, snapshot, binding)"));
    let wrapper=source.split("fn send_upstream_request_with_current_lease_and_timeout_validated_and_finalized<F, G>(").nth(1).unwrap()
        .split("fn send_upstream_request_with_quota_owner").next().unwrap();
    assert!(wrapper.contains("require_response_proof, None, validate_request"));
}
