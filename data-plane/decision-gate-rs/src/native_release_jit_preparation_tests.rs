//! Component projections from the actual Python no-lifespan ASGI producer.
//! The exporting test independently checks the raw 27-field facade arguments,
//! both derived requests and the real synthetic Ed25519 HTTP response. This
//! fixture carries no signing key, native owner, Prepared pair or authority.
//! Historical producer-manifest wire fixture: not current-contract admission.
//! Route metadata is synthetic, not a claim of compiled-policy admission.
use super::*;

const FIXTURE: &str = include_str!("../../../scripts/fixtures/native_release_jit_preparation.json");

pub(super) struct Fixture {
    pub(super) request: Value,
    pub(super) route: Route,
    pub(super) actor: String,
    pub(super) durable: ReleaseAuthorizationDurablePolicyBinding,
    pub(super) body: Vec<u8>,
}

impl Fixture {
    pub(super) fn load() -> Self {
        let value: Value = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(value["schema"], "serverware.nativeReleaseJitPreparationFixture/v1");
        let row = &value["route"];
        let request = value["request"].clone();
        let durable = ReleaseAuthorizationDurablePolicyBinding {
            actor_id: request["durablePolicy"]["actorId"].as_str().unwrap().to_owned(),
            claim_digest: request["durablePolicy"]["claimDigest"].as_str().unwrap().to_owned(),
            claims: request["durablePolicy"]["claims"].as_array().unwrap().clone(),
        };
        let strings = |name: &str| row[name].as_array().unwrap().iter()
            .map(|item| item.as_str().unwrap().to_owned()).collect::<Vec<_>>();
        let route = Route {
            id: row["id"].as_str().unwrap().to_owned(), principals: strings("principals"),
            scheme: row["scheme"].as_str().unwrap().to_owned(),
            host: row["host"].as_str().unwrap().to_owned(), port: row["port"].as_u64().unwrap() as u16,
            resolved_address_policy: ResolvedAddressPolicy::PublicOnly,
            methods: strings("methods").into_iter().collect(),
            // Path matching is not invoked by this pure projection. The actual
            // production Request retains/rechecks its already selected route.
            paths: Vec::new(), credential_ref: row["credentialRef"].as_str().map(str::to_owned),
            credential_header: None, adapter_type: row["adapterType"].as_str().unwrap().to_owned(),
            adapter_config: row["adapterConfig"].clone(), discard_headers: Vec::new(),
            constraints: row["constraints"].as_array().unwrap().clone(), jit: row["jit"].clone(),
            response_observation: None,
        };
        Self { request, route, actor: value["actorId"].as_str().unwrap().to_owned(), durable,
            body: value["responseBody"].as_str().unwrap().as_bytes().to_vec() }
    }

    pub(super) fn claims(&self) -> Claims<'_> {
        Claims { actor: &self.actor, attempt_id: self.request["attemptId"].as_str().unwrap(),
            principal_id: self.request["principalId"].as_str().unwrap(), route: &self.route,
            credential_ref: self.request["credentialRef"].as_str(),
            credential_version: self.request["credentialVersion"].as_u64().unwrap(),
            policy_hash: self.request["policyHash"].as_str().unwrap(),
            request_digest: self.request["requestDigest"].as_str().unwrap(),
            operation_digest: self.request["operationDigest"].as_str().unwrap(),
            operation: &self.request["operationContext"], canonical: &self.request["canonicalRequest"],
            method: self.request["canonicalRequest"]["request"]["method"].as_str().unwrap(),
            durable: &self.durable }
    }
}

fn encoded(value: &impl Serialize) -> Vec<u8> {
    native_response_profile::canonical_ascii_bytes(value).unwrap()
}

#[test]
fn python_asgi_originals_match_actual_payload_and_pure_claims_only() {
    let f = Fixture::load();
    let claims = f.claims();
    let wire = decode_wire(&f.body).unwrap();
    validate_claims(&wire, &claims).unwrap();
    assert_eq!(canonical_request_digest_profile(claims.canonical, ReleaseProfile::Native), claims.request_digest);
    assert_eq!(operation_digest_profile(claims.canonical, ReleaseProfile::Native), claims.operation_digest);
    let mut payload = release_authorization_reserve_payload(claims.attempt_id, claims.principal_id,
        claims.route, claims.credential_ref, claims.credential_version, claims.policy_hash,
        claims.request_digest, claims.operation_digest, claims.operation, claims.canonical, Some(claims.durable));
    payload["apiVersion"] = json!(ReleaseProfile::Native.request_version(ReleaseOperation::Prepare, true).unwrap());
    assert_eq!(encoded(&payload), encoded(&f.request));
    assert_eq!(encoded(&wire), f.body);
    let parent = object(&wire.parent_request).unwrap();
    assert_eq!(field(&parent, "operation").unwrap().get(), "\"release.reserve\"");
    let child = object(&wire.child_request).unwrap();
    assert_eq!(field(&child, "operation").unwrap().get(), "\"jit.request\"");
    assert_ne!(field(&parent, "requestDigest").unwrap().get(),
        field(&child, "requestDigest").unwrap().get());
    let runtime = object(&wire.runtime_input).unwrap();
    let private = object(field(&runtime, "privateDocuments").unwrap().get()).unwrap();
    let url: String = serde_json::from_str(field(&private, "url").unwrap().get()).unwrap();
    assert_eq!(url, "https://synthetic.invalid/resource?label=caf%C3%A9&token=redacted");
    assert!(!url.contains("synthetic-private-query"));
    // Result<(), String> can only correlate bytes, never return Prepared/Owner.
    let correlated: Result<(), String> = serverware_decision_gate::native_secret_broker_v1::
        validate_release_jit_review_originals(wire.runtime_input.as_bytes(),
            wire.parent_request.as_bytes(), wire.child_request.as_bytes());
    assert!(correlated.is_ok());
}

#[test]
fn actual_request_scope_and_durable_claim_substitutions_are_refused() {
    let original = Fixture::load();
    let wire = decode_wire(&original.body).unwrap();
    for name in ["attemptId", "principalId", "policyHash", "requestDigest", "operationDigest", "credentialRef"] {
        let mut changed = Fixture::load();
        changed.request[name] = json!(if name == "principalId" { "agent:other" } else { "sha256:other" });
        assert!(validate_claims(&wire, &changed.claims()).is_err(), "{name}");
    }
    let mut changed = Fixture::load();
    changed.request["credentialVersion"] = json!(8);
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.actor.push_str("-other");
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.durable.claims[0]["max_units"] = json!(11);
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.request["operationContext"]["label"] = json!("changed");
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.request["canonicalRequest"]["request"]["body_sha256"] = json!(sha256_prefixed(b"other"));
    assert!(validate_claims(&wire, &changed.claims()).is_err());
}

#[test]
fn closed_canonical_wire_rejects_aliases_duplicates_nesting_and_oversize() {
    let f = Fixture::load();
    let mut value: Value = serde_json::from_slice(&f.body).unwrap();
    value["extra"] = json!(true);
    assert!(decode_wire(&encoded(&value)).is_err());
    value.as_object_mut().unwrap().remove("extra");
    value.as_object_mut().unwrap().remove("childRequest");
    assert!(decode_wire(&encoded(&value)).is_err());
    value = serde_json::from_slice(&f.body).unwrap();
    value["parentRequest"] = serde_json::from_str(value["parentRequest"].as_str().unwrap()).unwrap();
    assert!(decode_wire(&encoded(&value)).is_err());
    let duplicate = [b"{\"apiVersion\":\"duplicate\",".as_slice(), &f.body[1..]].concat();
    assert!(decode_wire(&duplicate).is_err());
    assert!(decode_wire(&[b" ".as_slice(), &f.body].concat()).is_err());
    assert!(decode_wire(&serde_json::to_vec_pretty(&decode_wire(&f.body).unwrap()).unwrap()).is_err());
    assert!(decode_wire(&vec![b' '; MAX_RESPONSE_BYTES as usize + 1]).is_err());
    assert!(decode_wire(b"\xff").is_err());
    for version in ["serverware.nativeReleasePreparation/v1", "serverware.nativeReleaseJitPreparation/v2"] {
        let mut wire = decode_wire(&f.body).unwrap(); wire.api_version = version.into();
        assert!(validate_claims(&wire, &f.claims()).is_err());
    }
}

#[test]
fn text_graph_numbers_are_not_decoded_or_recanonicalized_as_parent_values() {
    let f = Fixture::load();
    let numbers = r#"{"values":[1e-05,1e+20,18446744073709551633,-18446744073709551633,-0.0]}"#;
    let mut wire = decode_wire(&f.body).unwrap();
    // Transport representation proof only: these substituted graphs are NOT
    // claimed valid originals and the pure claim verifier must reject them.
    wire.parent_request = Zeroizing::new(numbers.to_owned());
    let roundtrip = decode_wire(&encoded(&wire)).unwrap();
    assert_eq!(roundtrip.parent_request.as_bytes(), numbers.as_bytes());
    assert!(validate_claims(&roundtrip, &f.claims()).is_err());
    let lossy: Value = serde_json::from_str(numbers).unwrap();
    assert_ne!(serde_json::to_vec(&lossy).unwrap(), numbers.as_bytes());
    assert_eq!(roundtrip.runtime_input.as_bytes(), wire.runtime_input.as_bytes());
    assert_eq!(roundtrip.child_request.as_bytes(), wire.child_request.as_bytes());
}

#[test]
fn original_graph_substitutions_and_parent_child_domain_swaps_are_refused() {
    let f = Fixture::load();
    for selected in ["runtime", "parent", "child"] {
        let mut wire = decode_wire(&f.body).unwrap();
        let text = match selected { "runtime" => &mut wire.runtime_input,
            "parent" => &mut wire.parent_request, _ => &mut wire.child_request };
        let old = text.to_string();
        *text = Zeroizing::new(old.replacen("agent:synthetic", "agent:substitute", 1));
        assert_ne!(text.as_str(), old);
        assert!(validate_claims(&wire, &f.claims()).is_err(), "{selected}");
    }
    let mut wire = decode_wire(&f.body).unwrap();
    std::mem::swap(&mut wire.parent_request, &mut wire.child_request);
    assert!(validate_claims(&wire, &f.claims()).is_err());
    let mut wire = decode_wire(&f.body).unwrap();
    let old = wire.parent_request.to_string();
    wire.parent_request = Zeroizing::new(old.replacen("release.reserve", "jit.request", 1));
    assert_ne!(wire.parent_request.as_str(), old);
    assert!(validate_claims(&wire, &f.claims()).is_err());
}

#[test]
fn current_route_policy_limits_and_shared_quota_are_independent_required_joins() {
    let original = Fixture::load();
    let wire = decode_wire(&original.body).unwrap();
    for (pointer, replacement) in [("/approvers/quorum", json!(1)),
        ("/approvers/users", json!(["oidc:other"])),
        ("/approvers/authn/allowedAuthenticatorClasses", json!(["hardware"])),
        ("/approvers/authn/requireHardwareAttestation", json!(false)),
        ("/approvers/authn/maxAssertionAgeSeconds", json!(31)),
        ("/pendingTtlSeconds", json!(301)), ("/ttlSeconds", json!(31)), ("/maxUses", json!(2))] {
        let mut changed = Fixture::load();
        let pieces: Vec<_> = pointer.trim_start_matches('/').split('/').collect();
        let mut target = &mut changed.route.jit;
        for piece in &pieces[..pieces.len()-1] { target = &mut target[*piece]; }
        target[*pieces.last().unwrap()] = replacement;
        assert!(validate_claims(&wire, &changed.claims()).is_err(), "{pointer}");
    }
    let mut changed = Fixture::load();
    changed.route.jit["approvers"].as_object_mut().unwrap().remove("quorum");
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.route.constraints[0]["max"] = json!(11);
    assert!(validate_claims(&wire, &changed.claims()).is_err());
    changed = Fixture::load(); changed.route.id.push_str("-other");
    assert!(validate_claims(&wire, &changed.claims()).is_err());
}

#[test]
fn python_review_and_set_spelling_match_without_normalizing_private_originals() {
    assert_eq!(quote_plus("a *~+/\u{e9}\n"), "a+%2A~%2B%2F%C3%A9%0A");
    assert_eq!(sorted_strings(&json!(["b", "a", "b"])).unwrap(), json!(["a", "b"]));
    assert_eq!(marshaled_set(&json!(["a", "\u{e9}"])).unwrap(),
        json!({"$authorityType":"set", "items":["\u{e9}", "a"]}));
    let mut f = Fixture::load();
    f.request["canonicalRequest"]["request"]["query"] = json!([
        ["password_hint", "private-a"], ["AUTH", "private-b"], ["safe", "a *~"]]);
    let (url, display) = review_display(&f.claims()).unwrap();
    assert_eq!(url, "https://synthetic.invalid/resource?password_hint=redacted&AUTH=redacted&safe=a+%2A~");
    assert_eq!(display.as_object().unwrap().len(), 5);
    assert!(!encoded(&display).windows(7).any(|window| window == b"private"));
    assert!(display.get("operation").is_none());
}

#[test]
fn lifetime_and_reachable_terminal_boundary_do_not_grant_native_authority() {
    assert!(custody_deadline_remaining(Instant::now(), "native compound preparation").is_err());
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(custody_deadline_remaining(deadline, "native compound preparation").unwrap() <= Duration::from_secs(1));
    assert_eq!(release_authorization_operation_path("native-jit-prepare").unwrap(), PATH);
    assert!(release_authorization_operation_path("native-jit-prepare?alias").is_err());
    // Explicit source-order control only; this does not fabricate a live native
    // CONNECT owner or claim HTTP/native admission coverage from unit data.
    let source = include_str!("main.rs");
    let caller = source.split("fn request_release_authorization_with_connect").nth(1).unwrap();
    let branch = caller.find("return native_release_jit_preparation::prepare_and_submit(").unwrap();
    let old_prepare = caller.find("Some(prepare_release_policy(").unwrap();
    assert!(branch < old_prepare);
    assert!(caller[branch..old_prepare].contains("}, shadow_finalization);"));
    let consumer = include_str!("native_release_jit_preparation.rs");
    let terminal = consumer.split("pub(super) fn prepare_and_submit").nth(1).unwrap();
    assert!(terminal.contains("submission::submit(retained, evidence, original_boottime_deadline, shadow)"));
    let freeze = terminal.find("native_jit_review::freeze_deadline(").unwrap();
    let http = terminal.find("post_release_authorization_http_on_deadline(").unwrap();
    let prepare = terminal.find("native_jit_review::prepare(").unwrap();
    assert!(freeze < http && http < prepare);
    assert!(terminal[prepare..].contains("retained.check()?;"));
    assert!(!consumer.contains("prepare_release_jit_review("));
    assert!(!consumer.contains("configure_jit_review("));
}
