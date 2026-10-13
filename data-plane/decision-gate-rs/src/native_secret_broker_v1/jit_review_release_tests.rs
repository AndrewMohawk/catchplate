//! Independent literal release/JIT request vectors and pure correlation controls.
//! The ciphertext below is synthetic length-correct data, NOT a cryptographic
//! receipt. Nothing here constructs PreparedReleasePair, a retained owner,
//! native admission, a signer, a database writer, or provider authority.
use super::*;
use serde_json::value::RawValue;

const MANIFEST: &str = "sha256:9fa8ca9ea0aa5c37e94ca5344eb1b4b62ae7f46c06843907a5bd3fb0baf4f9e2";
const PARENT_ORIGINAL: &str = "sha256:befb9c29e1e9d770ed834444468a9d785723b0db9aee84bca19ff831422a67ff";
const CHILD_ORIGINAL: &str = "sha256:cdbdeb4e8c8ef15eea1e394d500bdbf211357fb3271f53bb9bc4cd887f9a92b3";
const PARENT_DIGEST: &str = "sha256:baf90ca55fb61c292108404b2470d8dbb9da75825de7bbdfb40312a35085e50a";
const PARENT_OPERATION: &str = "sha256:bad401085c38d2ea27ce1d9fd839eaa98eb86d8f8bfcd08d50731472b7025e70";
const CHILD_DIGEST: &str = "sha256:34e9dcac76e77e6c7421ca10f444632e53d399aa16538e9534b08b8a6e95ac2f";
const CHILD_OPERATION: &str = "sha256:138181e8a5ae9640d7653987671ca9c7f6f7675454e1c38b42f56363b17a33fb";
const WALL: u64 = 100_000_000_000;
const BOOT: u64 = 10_000_000_000;
const BROKER: u64 = 100_000_000_000;
type RawMap = BTreeMap<String, Vec<u8>>;

// Separate test oracle: never uses release/originals joining, V9 derivation or
// production framing. Only integer/string fixture leaves use the ASCII codec.
fn encoded(value: &Value) -> Vec<u8> { canonical_ascii_bytes(value).unwrap() }
fn raw_map(value: &Value) -> RawMap {
    value.as_object().unwrap().iter().map(|(k, v)| (k.clone(), encoded(v))).collect()
}
fn assemble(values: &RawMap) -> Vec<u8> {
    let mut bytes = vec![b'{'];
    for (index, (key, value)) in values.iter().enumerate() {
        if index > 0 { bytes.push(b','); }
        bytes.extend(encoded(&json!(key))); bytes.push(b':'); bytes.extend(value);
    }
    bytes.push(b'}'); bytes
}
fn split(raw: &[u8]) -> RawMap {
    let fields: BTreeMap<String, &RawValue> = serde_json::from_slice(raw).unwrap();
    fields.into_iter().map(|(k, v)| (k, v.get().as_bytes().to_vec())).collect()
}
fn replace(raw: &[u8], field: &str, value: &[u8]) -> Vec<u8> {
    let mut values = split(raw); assert!(values.contains_key(field));
    values.insert(field.into(), value.to_vec()); assemble(&values)
}
fn oracle_framed(domain: &str, values: &[&[u8]]) -> String {
    let mut bytes = domain.as_bytes().to_vec(); bytes.push(0);
    for value in values { bytes.extend((value.len() as u64).to_be_bytes()); bytes.extend(*value); }
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn request(operation: &str, public: &RawMap) -> Vec<u8> {
    let (handler, adapter) = match operation {
        "release.reserve" => ("reserve_release_authorization_v2",
            "serverware.policyAuthorityPlanningAdapter/reserve_release_authorization_v2/v1"),
        "jit.request" => ("ensure_jit_approval_request",
            "serverware.policyAuthorityPlanningAdapter/ensure_jit_approval_request/v1"),
        _ => panic!("unknown test operation"),
    };
    let mut intent = raw_map(&json!({"schema":"serverware.policyAuthorityBusinessIntent/v2",
        "operation":operation, "planningAdapterId":adapter}));
    intent.insert("arguments".into(), assemble(public));
    let mut arguments = public.clone(); arguments.insert("businessIntent".into(), assemble(&intent));
    let mut auth = raw_map(&json!({"schema":"serverware.policyAuthorityV9Authorization/v1",
        "operation":operation, "handler":handler, "operationManifestDigest":MANIFEST}));
    auth.insert("arguments".into(), assemble(&arguments));
    let digest = oracle_framed("serverware.policyAuthorityV9Request/v1", &[&assemble(&auth)]);
    let id = oracle_framed("serverware.policyAuthorityOperation/v2", &[operation.as_bytes(), digest.as_bytes()]);
    auth.insert("schema".into(), encoded(&json!("serverware.policyAuthorityV9Request/v1")));
    auth.insert("requestDigest".into(), encoded(&json!(digest)));
    auth.insert("operationId".into(), encoded(&json!(id))); assemble(&auth)
}

struct Fixture {
    config: Value, runtime: Vec<u8>, parent: Vec<u8>, child: Vec<u8>, command: Vec<u8>, response: Value,
}
fn fixture(changes: &[(&str, &[u8])]) -> Fixture {
    // Exact source_values/native_raw_arguments oracle in the Python private
    // release suite. The six literal digest assertions below detect drift.
    let child_original = json!({
        "route_id":"route:synthetic", "method":"PUT", "principal_id":"agent:synthetic",
        "credential_id":"credential:synthetic", "credential_version":7,
        "policy_hash":format!("sha256:{}", "1".repeat(64)),
        "request_digest":format!("sha256:{}", "2".repeat(64)),
        "operation_digest":format!("sha256:{}", "3".repeat(64)),
        "pending_ttl_seconds":300, "grant_ttl_seconds":30, "grant_max_uses":1,
        "required_approver_roles":{"$authorityType":"set","items":["approver"]},
        "allowed_approver_ids":{"$authorityType":"set","items":["oidc:alpha","oidc:beta"]},
        "require_approver_webauthn":true, "approval_threshold":2,
        "approver_credential_policy":{"allowedCredentialRecordIds":[],
            "allowedAuthenticatorClasses":["hardware","yubikey"], "allowedAaguids":[],
            "requireAttestationTrusted":true, "requiredTrustBundleDigest":null,
            "minimumTrustBundleSequence":null, "rpId":"synthetic.invalid",
            "origins":["https://synthetic.invalid"], "requireUserPresence":true,
            "requireUserVerification":true, "counterPolicy":"strict-or-zero", "maxAssertionAgeSeconds":30},
        "url":"https://synthetic.invalid/private-release-url-721/caf\u{e9}",
        "canonical_request":{"private":"private-release-document-853", "literal":{
            "$authorityType":"bytes", "base64Url":"literal-review-JSON-not-a-type-tag"}},
        "redacted_display":{"label":"private-release-display-964", "unicode":"caf\u{e9}"}});
    let mut child_public = child_original.as_object().unwrap().clone();
    let mut documents = serde_json::Map::new();
    for field in ["url", "canonical_request", "redacted_display"] {
        documents.insert(field.into(), child_public.remove(field).unwrap());
    }
    let documents = Value::Object(documents);
    child_public.insert("schema".into(), json!("serverware.jitRequestCommitments/v2"));
    child_public.insert("original_arguments_digest".into(), json!(sha(&encoded(&child_original))));
    child_public.insert("url_commitment".into(), json!(sha(documents["url"].as_str().unwrap().as_bytes())));
    child_public.insert("canonical_request_digest".into(), json!(sha(&encoded(&documents["canonical_request"]))));
    child_public.insert("redacted_display_digest".into(), json!(sha(&encoded(&documents["redacted_display"]))));
    let child_public = Value::Object(child_public);
    let mut nested = serde_json::Map::new();
    for field in ["method", "url", "canonical_request", "redacted_display", "pending_ttl_seconds",
        "grant_ttl_seconds", "grant_max_uses"] { nested.insert(field.into(), child_original[field].clone()); }
    let pin = format!("sha256:{}", "8".repeat(64));
    let mut parent_original = raw_map(&json!({"attempt_id":pin, "flow_id":pin,
        "operation_context":{"public":"unchanged"}, "shared_quotas":[], "require_jit_grant":true,
        "reservation_ttl_seconds":5, "durable_policy_binding":{"fixture":"public claim, not admitted policy"},
        "jit_approval_request":nested, "now_epoch_ms":null, "actor_id":"oidc:synthetic-actor",
        "authority_policy_hash":null, "authority_route_id":null, "native_profile":true,
        "policy_aware_profile":false,
        "expected_approver_policy_sha256":"sha256:ca91d87c21f8706949a6b06c3d7c3dcdd6120dac6b2f5caa788e25b9155fc454"}));
    for field in ["route_id", "principal_id", "credential_id", "credential_version", "policy_hash",
        "request_digest", "operation_digest", "required_approver_roles", "allowed_approver_ids",
        "require_approver_webauthn", "approval_threshold", "approver_credential_policy"] {
        parent_original.insert(field.into(), encoded(&child_original[field]));
    }
    for (field, value) in changes {
        assert!(parent_original.contains_key(*field)); parent_original.insert((*field).into(), value.to_vec());
    }
    let mut parent_public = parent_original.clone();
    parent_public.insert("schema".into(), encoded(&json!("serverware.releaseReserveCommitments/v1")));
    parent_public.insert("original_arguments_digest".into(), encoded(&json!(sha(&assemble(&parent_original)))));
    parent_public.insert("jit_approval_request".into(), encoded(&child_public));
    let child = request("jit.request", &raw_map(&child_public));
    let parent = request("release.reserve", &parent_public);
    let mut envelope = raw_map(&json!({"schema":"serverware.policyAuthorityPrivateReleaseWriterInput/v1",
        "handler":"reserve_release_authorization_v2", "operationManifestDigest":MANIFEST,
        "privateDocuments":documents}));
    envelope.insert("arguments".into(), assemble(&parent_public));
    let runtime = assemble(&envelope);
    let mut identity = serde_json::Map::new();
    for field in IDENTITY { identity.insert((*field).into(), json!(sha(field.as_bytes()))); }
    let boot = [b'b'; 32];
    let mut holder = b"serverware/credential-currentness-holder/v1\0".to_vec();
    holder.extend(boot); holder.extend(hex::decode(identity["keyId"].as_str().unwrap().strip_prefix("sha256:").unwrap()).unwrap());
    identity.insert("bootId".into(), json!(URL_SAFE_NO_PAD.encode(boot)));
    identity.insert("holderId".into(), json!(sha(&holder)));
    identity.insert("policyHash".into(), child_original["policy_hash"].clone());
    let config = json!({"apiVersion":"serverware.nativeJitReviewConfiguration/v1",
        "sourceContractDigest":MANIFEST, "controlPlaneConfigurationDigest":sha(b"synthetic configuration"),
        "deploymentId":"synthetic-offline", "instanceId":"spiffe://synthetic.invalid/native",
        "secretKekId":"attested-memory-kek:0123456789abcdef01234567", "attemptCapacity":16, "identity":identity});
    let mut command = raw_map(&json!({"apiVersion":"serverware.nativeJitReviewChannel/v1",
        "phase":"seal-release-pair", "challenge":URL_SAFE_NO_PAD.encode([b'c';32]),
        "issuedAtEpochNs":WALL, "sealExpiresAtEpochNs":WALL+20_000_000_000u64,
        "documentExpiresAtEpochNs":WALL+120_000_000_000u64, "deadlineBoottimeNs":BOOT+25_000_000_000u64}));
    command.insert("runtimeInput".into(), runtime.clone()); command.insert("parentRequest".into(), parent.clone());
    command.insert("publicRequest".into(), child.clone());
    let command = assemble(&command);
    let child_value: Value = serde_json::from_slice(&child).unwrap();
    let parent_fields = split(&parent);
    let parent_digest: Value = serde_json::from_slice(&parent_fields["requestDigest"]).unwrap();
    let parent_operation: Value = serde_json::from_slice(&parent_fields["operationId"]).unwrap();
    let scope = json!({"schema":"serverware.nativeJitReviewScope/v2", "publicRequest":child_value,
        "parentRequestSha256":sha(&parent), "sourceContractDigest":MANIFEST,
        "controlPlaneConfigurationDigest":config["controlPlaneConfigurationDigest"],
        "ownerScopeDigest":sha(&encoded(&config)), "issuedAtEpochNs":WALL,
        "sealExpiresAtEpochNs":WALL+20_000_000_000u64, "documentExpiresAtEpochNs":WALL+120_000_000_000u64});
    let canonical_payload = encoded(&json!({"schema":"serverware.jitCanonicalReviewPayload/v1",
        "url":documents["url"], "canonical_request":documents["canonical_request"]}));
    let display = encoded(&documents["redacted_display"]);
    let mut items = Vec::new();
    for (plaintext, kind, purpose) in [(&canonical_payload, "approval-secret-json/v1", "jit-canonical-request"),
        (&display, "approval-review-json/v1", "jit-redacted-display")] {
        items.push(json!({"opaqueId":opaque_id(child_value["requestDigest"].as_str().unwrap(), purpose).unwrap(),
            "valueKind":kind, "plaintextSha256":sha(plaintext), "plaintextBytes":plaintext.len(),
            "wrappedKeyNonce":URL_SAFE.encode([0u8;12]), "wrappedKey":URL_SAFE.encode([0u8;48]),
            "ciphertextNonce":URL_SAFE.encode([0u8;12]), "ciphertext":URL_SAFE.encode(vec![0u8;plaintext.len()+16])}));
    }
    let pair = json!({"schema":"serverware.nativeJitReviewPair/v2", "scope":scope,
        "keyId":config["secretKekId"], "items":items});
    let mut bindings = config["identity"].as_object().unwrap().clone();
    for field in ["sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "secretKekId"] {
        bindings.insert(field.into(), config[field].clone());
    }
    for (field, value) in [
        ("ownerScopeDigest", scope["ownerScopeDigest"].clone()),
        ("requestDigest", child_value["requestDigest"].clone()), ("operationId", child_value["operationId"].clone()),
        ("publicRequestSha256", json!(sha(&child))), ("pairSha256", json!(sha(&encoded(&pair)))),
        ("parentRequestSha256", json!(sha(&parent))), ("parentRequestDigest", parent_digest),
        ("parentOperationId", parent_operation), ("challenge", json!(URL_SAFE_NO_PAD.encode([b'c';32]))),
        ("issuedAtEpochNs", json!(WALL)), ("expiresAtEpochNs", scope["sealExpiresAtEpochNs"].clone()),
        ("documentExpiresAtEpochNs", scope["documentExpiresAtEpochNs"].clone())] { bindings.insert(field.into(), value); }
    let response = json!({"apiVersion":"serverware.nativeJitReviewChannel/v1", "phase":"prepared-release-pair",
        "operation":"release.reserve", "pair":pair, "statementBindings":bindings});
    Fixture { config, runtime, parent, child, command, response }
}
fn check(f: &Fixture, command: &[u8], response: &Value) -> Result<(), String> {
    release::validate_release_exchange(&f.config, command, response, WALL, BOOT, BROKER)
}
fn refresh_pair_digest(response: &mut Value) {
    response["statementBindings"]["pairSha256"] = json!(sha(&encoded(&response["pair"])));
}

#[test]
fn release_literal_parent_and_child_vectors_match_without_constructing_prepared() {
    let f = fixture(&[]);
    let original = release::read(&f.runtime, &f.parent, &f.child).unwrap();
    let runtime: Value = serde_json::from_slice(&f.runtime).unwrap();
    assert_eq!(runtime["arguments"]["original_arguments_digest"], PARENT_ORIGINAL);
    assert_eq!(runtime["arguments"]["jit_approval_request"]["original_arguments_digest"], CHILD_ORIGINAL);
    assert_eq!(original.parent.request_digest, PARENT_DIGEST);
    assert_eq!(original.parent.operation_id, PARENT_OPERATION);
    assert_eq!(original.parent.sha256, sha(&f.parent));
    assert_eq!(original.child.request["requestDigest"], CHILD_DIGEST);
    assert_eq!(original.child.request["operationId"], CHILD_OPERATION);
    assert_ne!(original.parent.request_digest, CHILD_DIGEST);
    assert!(check(&f, &f.command, &f.response).is_ok());
}

#[test]
fn release_parent_only_changes_bind_parent_while_entire_child_and_item_ids_stay_stable() {
    let base = fixture(&[]);
    for (field, value) in [("operation_context", br#"{"public":"changed"}"#.as_slice()),
        ("shared_quotas", br#"[{"public":"unadmitted quota claim"}]"#),
        ("durable_policy_binding", br#"{"public":"unadmitted policy claim"}"#),
        ("reservation_ttl_seconds", b"6"), ("now_epoch_ms", b"0"), ("actor_id", br#""oidc:other""#)] {
        let changed = fixture(&[(field, value)]);
        assert_eq!(base.child, changed.child, "{field}");
        assert_ne!(base.parent, changed.parent, "{field}");
        for key in ["parentRequestSha256", "parentRequestDigest", "parentOperationId"] {
            assert_ne!(base.response["statementBindings"][key], changed.response["statementBindings"][key]);
        }
        for index in 0..2 { assert_eq!(base.response["pair"]["items"][index]["opaqueId"],
            changed.response["pair"]["items"][index]["opaqueId"]); }
        assert!(check(&changed, &changed.command, &changed.response).is_ok(), "{field}");
        assert!(check(&base, &changed.command, &base.response).is_err(), "{field}");
        assert!(check(&base, &base.command, &changed.response).is_err(), "{field}");
    }
}

#[test]
fn release_public_parent_numbers_retain_exact_original_bytes_in_all_three_json_roots() {
    let numbers = br#"{"numbers":[1e-05,1e+20,18446744073709551633,-18446744073709551633,-0.0,true,null]}"#;
    let quotas = [b"[".as_slice(), numbers, b"]"].concat();
    for (field, value) in [("operation_context", numbers.as_slice()),
        ("durable_policy_binding", numbers.as_slice()), ("shared_quotas", quotas.as_slice())] {
        let f = fixture(&[(field, value)]);
        let before = (f.runtime.clone(), f.parent.clone(), f.child.clone(), f.command.clone());
        let original = release::read(&f.runtime, &f.parent, &f.child).unwrap();
        assert_eq!(original.parent.sha256, sha(&f.parent));
        assert_eq!(original.child.request["requestDigest"], CHILD_DIGEST);
        assert!(check(&f, &f.command, &f.response).is_ok(), "{field}");
        assert_eq!(before, (f.runtime.clone(), f.parent.clone(), f.child.clone(), f.command.clone()));
        let modified = String::from_utf8(f.command.clone()).unwrap().replacen("1e-05", "1e-06", 1).into_bytes();
        assert_ne!(modified, f.command);
        assert!(check(&f, &modified, &f.response).is_err());
        let lossy: Value = serde_json::from_slice(&f.command).unwrap();
        let rewritten = encoded(&lossy);
        assert_ne!(rewritten, f.command);
        assert!(check(&f, &rewritten, &f.response).is_err());
    }
}

#[test]
fn release_parent_child_request_and_private_original_substitutions_fail_closed() {
    let f = fixture(&[]);
    for (field, value) in [("operation", json!("jit.request")), ("handler", json!("ensure_jit_approval_request")),
        ("schema", json!("serverware.policyAuthorityV9Authorization/v1")),
        ("operationManifestDigest", json!(sha(b"other manifest"))),
        ("requestDigest", json!(CHILD_DIGEST)), ("operationId", json!(CHILD_OPERATION))] {
        let parent = replace(&f.parent, field, &encoded(&value));
        assert!(release::read(&f.runtime, &parent, &f.child).is_err(), "{field}");
    }
    let parent_fields = split(&f.parent);
    let mut args = split(&parent_fields["arguments"]);
    args.insert("actor_id".into(), encoded(&json!("oidc:uncommitted")));
    let parent = replace(&f.parent, "arguments", &assemble(&args));
    assert!(release::read(&f.runtime, &parent, &f.child).is_err());
    let command = String::from_utf8(f.command.clone()).unwrap();
    for (old, new) in [("private-release-url-721", "private-release-url-722"),
        ("private-release-document-853", "private-release-document-854"),
        ("private-release-display-964", "private-release-display-965")] {
        let changed = command.replacen(old, new, 1); assert_ne!(changed, command);
        assert!(check(&f, changed.as_bytes(), &f.response).is_err());
    }
    assert!(release::read(&f.runtime, &f.child, &f.parent).is_err());
}

#[test]
fn release_recomputed_parent_does_not_bypass_native_grammar_or_inherited_child_joins() {
    // The oracle recomputes original_arguments_digest, both copies of business
    // arguments, the V9 digest and operation ID. Refusal must therefore come
    // from the grammar/join, not an accidentally stale outer commitment.
    for (field, value) in [("principal_id", br#""agent:another""#.as_slice()),
        ("route_id", br#""route:another""#), ("credential_id", br#""credential:another""#),
        ("credential_version", b"8"), ("approval_threshold", b"1"),
        ("require_approver_webauthn", b"false"), ("native_profile", b"false"),
        ("policy_aware_profile", b"true"), ("require_jit_grant", b"false"),
        ("actor_id", br#""""#), ("flow_id", br#""different-flow""#),
        ("reservation_ttl_seconds", b"0"), ("reservation_ttl_seconds", b"301"),
        ("reservation_ttl_seconds", b"true"), ("now_epoch_ms", b"-1"),
        ("now_epoch_ms", b"9223372036854775808"), ("operation_context", b"[]"),
        ("durable_policy_binding", b"[]"), ("shared_quotas", b"{}"),
        ("shared_quotas", b"[false]"), ("authority_route_id", br#""route:synthetic""#)] {
        let f = fixture(&[(field, value)]);
        let error = release::read(&f.runtime, &f.parent, &f.child).err()
            .unwrap_or_else(|| panic!("recomputed invalid parent accepted: {field}"));
        for private in ["private-release-url-721", "private-release-document-853", "private-release-display-964"] {
            assert!(!error.contains(private));
        }
        assert!(check(&f, &f.command, &f.response).is_err(), "{field}");
    }
    let too_many = format!("[{}]", ["{}"; 13].join(","));
    let f = fixture(&[("shared_quotas", too_many.as_bytes())]);
    assert!(release::read(&f.runtime, &f.parent, &f.child).is_err());
    let oversized_context = format!("{{\"x\":\"{}\"}}", "x".repeat(64 * 1024));
    let f = fixture(&[("operation_context", oversized_context.as_bytes())]);
    assert!(release::read(&f.runtime, &f.parent, &f.child).is_err());
    let alternate_attempt = encoded(&json!(format!("sha256:{}", "9".repeat(64))));
    let policy = encoded(&json!(format!("sha256:{}", "1".repeat(64))));
    for changes in [vec![("attempt_id", alternate_attempt.as_slice()), ("flow_id", alternate_attempt.as_slice())],
        vec![("authority_policy_hash", policy.as_slice()), ("authority_route_id", br#""route:synthetic""#.as_slice())]] {
        let f = fixture(&changes);
        let read = release::read(&f.runtime, &f.parent, &f.child).unwrap();
        assert_ne!(read.parent.request_digest, PARENT_DIGEST);
        assert_eq!(read.child.request["requestDigest"], CHILD_DIGEST);
        assert!(check(&f, &f.command, &f.response).is_ok());
    }
}

#[test]
fn release_command_response_scope_and_binding_field_sets_are_closed_and_profile_specific() {
    let f = fixture(&[]);
    let command_fields = split(&f.command);
    assert_eq!(command_fields.len(), 10);
    for field in command_fields.keys() {
        let mut changed = command_fields.clone(); changed.remove(field);
        assert!(check(&f, &assemble(&changed), &f.response).is_err(), "missing command {field}");
    }
    let mut extra = command_fields.clone(); extra.insert("verified".into(), b"true".to_vec());
    assert!(check(&f, &assemble(&extra), &f.response).is_err());
    for (field, value) in [("phase", "seal-pair"), ("apiVersion", "serverware.nativeJitReviewChannel/v2")] {
        assert!(check(&f, &replace(&f.command, field, &encoded(&json!(value))), &f.response).is_err());
    }
    for path in [vec![], vec!["pair"], vec!["pair", "scope"], vec!["statementBindings"]] {
        let mut value = &f.response;
        for field in &path { value = &value[*field]; }
        let fields: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        for field in fields.iter().map(String::as_str).chain(std::iter::once("extra")) {
            let mut changed = f.response.clone(); let mut object = &mut changed;
            for part in &path { object = &mut object[*part]; }
            if field == "extra" { object.as_object_mut().unwrap().insert(field.into(), json!(true)); }
            else { object.as_object_mut().unwrap().remove(field); }
            assert!(check(&f, &f.command, &changed).is_err(), "path {path:?} field {field}");
        }
    }
    for (field, value) in [("phase", "prepared"), ("operation", "jit.request")] {
        let mut changed = f.response.clone(); changed[field] = json!(value);
        assert!(check(&f, &f.command, &changed).is_err());
    }
    for (path, schema) in [("pair", "serverware.nativeJitReviewPair/v1"),
        ("scope", "serverware.nativeJitReviewScope/v1")] {
        let mut changed = f.response.clone();
        if path == "pair" { changed["pair"]["schema"] = json!(schema); }
        else { changed["pair"]["scope"]["schema"] = json!(schema); }
        refresh_pair_digest(&mut changed);
        assert!(check(&f, &f.command, &changed).is_err());
    }
}

#[test]
fn release_every_parent_binding_and_scope_hash_is_checked_even_with_refreshed_pair_hash() {
    let f = fixture(&[]);
    assert_eq!(f.response["statementBindings"].as_object().unwrap().len(), 27);
    for field in ["parentRequestSha256", "parentRequestDigest", "parentOperationId"] {
        let mut changed = f.response.clone(); changed["statementBindings"][field] = json!(sha(b"other parent"));
        assert!(check(&f, &f.command, &changed).is_err(), "{field}");
    }
    let mut changed = f.response.clone();
    changed["pair"]["scope"]["parentRequestSha256"] = json!(sha(b"other parent"));
    changed["statementBindings"]["parentRequestSha256"] = changed["pair"]["scope"]["parentRequestSha256"].clone();
    refresh_pair_digest(&mut changed);
    assert!(check(&f, &f.command, &changed).is_err());
    for field in BINDINGS {
        let mut changed = f.response.clone(); changed["statementBindings"][*field] = json!("changed");
        assert!(check(&f, &f.command, &changed).is_err(), "{field}");
    }
}

#[test]
fn release_expiry_clipping_keeps_original_wall_and_boottime_bounds() {
    let f = fixture(&[]);
    let seal = WALL + 20_000_000_000;
    assert!(release::validate_release_exchange(&f.config, &f.command, &f.response, seal, BOOT, BROKER).is_err());
    assert!(release::validate_release_exchange(&f.config, &f.command, &f.response,
        WALL, BOOT + 25_000_000_000, BROKER).is_err());
    assert!(release::validate_release_exchange(&f.config, &f.command, &f.response,
        WALL - 1, BOOT, BROKER).is_err());
    assert!(release::validate_release_exchange(&f.config, &f.command, &f.response,
        WALL, BOOT, BOOT + 24_000_000_000).is_err());
    let mut clipped = f.response.clone();
    clipped["pair"]["scope"]["sealExpiresAtEpochNs"] = json!(WALL + 3_000_000_000);
    clipped["pair"]["scope"]["documentExpiresAtEpochNs"] = json!(WALL + 10_000_000_000);
    clipped["statementBindings"]["expiresAtEpochNs"] = clipped["pair"]["scope"]["sealExpiresAtEpochNs"].clone();
    clipped["statementBindings"]["documentExpiresAtEpochNs"] = clipped["pair"]["scope"]["documentExpiresAtEpochNs"].clone();
    refresh_pair_digest(&mut clipped);
    assert!(check(&f, &f.command, &clipped).is_ok());
    for (field, binding, value) in [("sealExpiresAtEpochNs", "expiresAtEpochNs", seal + 1),
        ("documentExpiresAtEpochNs", "documentExpiresAtEpochNs", WALL + 120_000_000_001)] {
        let mut changed = f.response.clone(); changed["pair"]["scope"][field] = json!(value);
        changed["statementBindings"][binding] = json!(value); refresh_pair_digest(&mut changed);
        assert!(check(&f, &f.command, &changed).is_err(), "{field}");
    }
}

#[test]
fn release_total_command_limit_duplicate_structure_and_nonfinite_numbers_refuse() {
    let f = fixture(&[]);
    assert!(f.command.len() < MAX_COMMAND);
    let mut oversized = f.command.clone(); oversized.resize(MAX_COMMAND + 1, b' ');
    assert!(check(&f, &oversized, &f.response).is_err());
    // Every component is individually below 512 KiB, while their actual
    // duplicated parent/business-intent command exceeds the total limit.
    let public_claim = format!("{{\"padding\":\"{}\"}}", "x".repeat(180 * 1024));
    let large = fixture(&[("durable_policy_binding", public_claim.as_bytes())]);
    assert!(large.runtime.len() < MAX_COMMAND && large.parent.len() < MAX_COMMAND && large.child.len() < MAX_COMMAND);
    assert!(large.command.len() > MAX_COMMAND);
    assert!(check(&large, &large.command, &large.response).is_err());
    let command = String::from_utf8(f.command.clone()).unwrap();
    let duplicate = command.replacen("\"phase\":", "\"phase\":\"seal-release-pair\",\"phase\":", 1);
    assert_ne!(duplicate, command); assert!(check(&f, duplicate.as_bytes(), &f.response).is_err());
    for invalid in [br#"{"n":NaN}"#.as_slice(), br#"{"n":1e999}"#, br#"{"n": 1}"#,
        br#"{"z":1,"a":2}"#, br#"{"n":1,"n":2}"#] {
        let args = split(&f.runtime);
        let changed_args = replace(&args["arguments"], "operation_context", invalid);
        let runtime = replace(&f.runtime, "arguments", &changed_args);
        let command = replace(&f.command, "runtimeInput", &runtime);
        assert!(check(&f, &command, &f.response).is_err());
    }
}
