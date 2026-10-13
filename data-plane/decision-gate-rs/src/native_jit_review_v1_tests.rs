//! Actual local signature/grammar controls, not NSM/startup/broker admission.
//! No test manufactures Owner, PreparedReleasePair or SignedReleasePair.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

fn pin(byte: char) -> String { format!("sha256:{}", byte.to_string().repeat(64)) }
fn config() -> (Value, SigningKey) {
    let signing = SigningKey::from_bytes(&[41; 32]);
    let der = signing.verifying_key().to_public_key_der().unwrap();
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der.as_bytes()));
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap().pem();
    let target = json!({"controlPlaneResponseSigningKeyId":pin('a'),"releaseRecordSha256":pin('b'),
        "policyHash":pin('c'),"expectedBinaryDigest":pin('d'),"expectedPcrs":{
            "PCR0":format!("sha384:{}", "1".repeat(96)),"PCR1":format!("sha384:{}", "2".repeat(96)),
            "PCR2":format!("sha384:{}", "3".repeat(96))},"expectedEif":format!("sha384:{}", "1".repeat(96)),
        "maxAgeSeconds":60,"futureSkewSeconds":2,"instanceId":"spiffe://synthetic.test/gate",
        "secretKekId":format!("attested-memory-kek:{}", "4".repeat(24))});
    (json!({"apiVersion":"serverware.nativeJitReviewConfiguration/v2","controlPlaneConfigurationDigest":pin('e'),
        "instanceId":target["instanceId"],"secretKekId":target["secretKekId"],"nativeJitReviewCustodyPolicy":{
            "schema":"serverware.nativeJitReviewCustodyAuthorityPolicy/v1","sourceContractDigest":pin('f'),
            "reservationTtlSeconds":15,"operationMaxSeconds":10,"attemptCapacity":4,"deploymentId":"synthetic-jit",
            "assignmentAuthorizer":{"publicKeyPem":pem,"publicKeyPemSha256":sha(pem.as_bytes()),
                "publicKeySpkiSha256":sha(der.as_bytes())},"target":target,"trustRoots":{
                "apiVersion":"serverware.nativeJitReviewNativeTrustRoots/v1","awsNitroRootCertificatesPem":[ca],
                "awsNitroCrlsDerBase64url":[],"nitroCertificateProfile":{
                    "profileId":"aws-nitro-attestation-pki-native-v1","allowedLeafExtendedKeyUsageOids":[]}}}}), signing)
}
fn parsed(value: &Value) -> Configuration { serde_json::from_value(value.clone()).unwrap() }
fn signed(config: &Value, key: &SigningKey) -> Value {
    let p = &config["nativeJitReviewCustodyPolicy"];
    let mut item = p["target"].clone(); let boot = URL_SAFE_NO_PAD.encode([9u8; 32]); let key_id = pin('9');
    item["bootId"] = json!(boot); item["keyId"] = json!(key_id);
    item["holderId"] = json!(current::holder_id(&boot, &key_id).unwrap());
    for field in ["configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"] { item[field] = json!(pin('8')); }
    item["expectedModuleId"] = json!("synthetic-module");
    let payload = json!({"schema":"serverware.nativeJitReviewAssignment/v1","sourceContractDigest":p["sourceContractDigest"],
        "controlPlaneConfigurationDigest":config["controlPlaneConfigurationDigest"],"deploymentId":p["deploymentId"],
        "assignment":item,"issuedAtEpochNs":100,"expiresAtEpochNs":1_000_000_100u64});
    let mut result = json!({"schema":"serverware.signedNativeJitReviewAssignment/v1","payload":payload,"signature":""});
    resign(&mut result, key); result
}
fn resign(value: &mut Value, key: &SigningKey) {
    let raw = canonical_ascii_bytes(&value["payload"]).unwrap();
    let mut hash = Sha256::new(); hash.update(b"serverware.signedNativeJitReviewAssignment/v1\0");
    hash.update((raw.len() as u64).to_be_bytes()); hash.update(&raw);
    let signature = key.sign(format!("sha256:{}", hex::encode(hash.finalize())).as_bytes());
    value["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
}
fn verify(c: &Value, s: &Value, now: u64) -> bool {
    assignment::signed_original(&parsed(c), &canonical_ascii_bytes(s).unwrap(), now).is_ok()
}

#[test]
fn cold_configuration_is_closed_distinct_and_not_admission() {
    let (c, _) = config(); parsed(&c).validate().unwrap();
    let mut extra = c.clone(); extra["admitted"] = json!(true);
    assert!(serde_json::from_value::<Configuration>(extra).is_err());
    for version in ["serverware.nativeJitReviewConfiguration/v1", "serverware.nativeStaticCredentialConfiguration/v1"] {
        let mut bad = c.clone(); bad["apiVersion"] = json!(version); assert!(parsed(&bad).validate().is_err());
    }
    let broker = serde_json::to_value(parsed(&c).broker().unwrap()).unwrap();
    assert_eq!(broker.as_object().unwrap().len(), 7);
    assert_eq!(broker["attemptCapacity"], 4);
    assert_eq!(broker["sourceContractDigest"], c["nativeJitReviewCustodyPolicy"]["sourceContractDigest"]);
}

#[test]
fn cold_policy_bounds_keys_target_and_trust_do_not_alias() {
    let (c, _) = config();
    for (path, value) in [("reservationTtlSeconds", 0), ("reservationTtlSeconds", 301),
        ("operationMaxSeconds", 31), ("attemptCapacity", 0), ("attemptCapacity", 17)] {
        let mut bad = c.clone(); bad["nativeJitReviewCustodyPolicy"][path] = json!(value);
        assert!(parsed(&bad).validate().is_err(), "{path}");
    }
    let mut bad = c.clone(); bad["instanceId"] = json!("spiffe://synthetic.test/has space");
    bad["nativeJitReviewCustodyPolicy"]["target"]["instanceId"] = bad["instanceId"].clone();
    assert!(parsed(&bad).validate().is_err());
    let mut bad = c.clone(); bad["nativeJitReviewCustodyPolicy"]["assignmentAuthorizer"]["publicKeyPemSha256"] = json!(pin('1'));
    assert!(parsed(&bad).validate().is_err());
    let mut bad = c.clone(); bad["nativeJitReviewCustodyPolicy"]["trustRoots"]["apiVersion"] = json!("serverware.staticCredentialNativeTrustRoots/v1");
    assert!(parsed(&bad).validate().is_err());
}

#[test]
fn genuine_local_assignment_signature_checks_without_creating_owner() {
    let (c, key) = config(); let s = signed(&c, &key);
    assert!(verify(&c, &s, 101));
    let mut bad = s.clone(); bad["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
    assert!(!verify(&c, &bad, 101));
    let wrong = SigningKey::from_bytes(&[42; 32]); assert!(!verify(&c, &signed(&c, &wrong), 101));
    let mut bad = s.clone(); bad["payload"]["assignment"]["expectedModuleId"] = json!("different-module");
    assert!(!verify(&c, &bad, 101));
}

#[test]
fn assignment_source_config_target_interval_and_envelope_are_exact() {
    let (c, key) = config(); let s = signed(&c, &key);
    for field in ["sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId"] {
        let mut bad = s.clone(); bad["payload"][field] = json!(if field == "deploymentId" { "different-deployment".to_owned() } else { pin('7') });
        resign(&mut bad, &key); assert!(!verify(&c, &bad, 101));
    }
    for (field, value) in [("instanceId", "spiffe://different.test/gate".to_owned()),
        ("secretKekId", format!("attested-memory-kek:{}", "7".repeat(24))),
        ("expectedBinaryDigest", pin('7')), ("holderId", pin('7'))] {
        let mut bad = s.clone(); bad["payload"]["assignment"][field] = json!(value);
        resign(&mut bad, &key); assert!(!verify(&c, &bad, 101));
    }
    let mut bad = s.clone(); bad["payload"]["expiresAtEpochNs"] = json!(86_400_000_000_101u64);
    resign(&mut bad, &key); assert!(!verify(&c, &bad, 101));
    assert!(!verify(&c, &s, 99)); assert!(!verify(&c, &s, 1_000_000_100));
    let mut bad = s.clone(); bad["schema"] = json!("serverware.signedStaticCredentialAssignment/v1"); assert!(!verify(&c, &bad, 101));
    let mut bad = s.clone(); bad["signatureBase64Url"] = bad["signature"].clone(); assert!(!verify(&c, &bad, 101));
    let mut raw = canonical_ascii_bytes(&s).unwrap(); raw.push(b' ');
    assert!(assignment::signed_original(&parsed(&c), &raw, 101).is_err());
    assert!(assignment::signed_original(&parsed(&c), &vec![b' '; MAX_ASSIGNMENT + 1], 101).is_err());
}

#[test]
fn actual_python_originals_require_independent_manifest_and_reservation_ttl() {
    let fixture: Value = serde_json::from_str(include_str!("../../../scripts/fixtures/native_release_jit_preparation.json")).unwrap();
    let response: Value = serde_json::from_str(fixture["responseBody"].as_str().unwrap()).unwrap();
    let runtime = response["runtimeInput"].as_str().unwrap().as_bytes();
    let parent = response["parentRequest"].as_str().unwrap().as_bytes();
    let child = response["childRequest"].as_str().unwrap().as_bytes();
    let raw: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_slice(parent).unwrap();
    let args: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_str(raw["arguments"].get()).unwrap();
    let (mut c, _) = config();
    c["nativeJitReviewCustodyPolicy"]["sourceContractDigest"] = serde_json::from_str(raw["operationManifestDigest"].get()).unwrap();
    c["nativeJitReviewCustodyPolicy"]["reservationTtlSeconds"] = serde_json::from_str(args["reservation_ttl_seconds"].get()).unwrap();
    assert!(parsed(&c).originals(runtime, parent, child).is_ok());
    let mut bad = c.clone(); bad["nativeJitReviewCustodyPolicy"]["sourceContractDigest"] = json!(pin('2'));
    assert!(parsed(&bad).originals(runtime, parent, child).is_err());
    let mut bad = c.clone(); bad["nativeJitReviewCustodyPolicy"]["reservationTtlSeconds"] = json!(299);
    assert!(parsed(&bad).originals(runtime, parent, child).is_err());
}

#[test]
fn private_owner_and_signing_path_remain_request_bound_and_terminal() {
    // Explicit source wiring assertion only, not native or custody acceptance.
    let source = include_str!("native_jit_review_custody.rs");
    assert!(source.find("admitted.prepare(").unwrap() < source.find("owner.sign(").unwrap());
    assert!(source.find("owner.sign(").unwrap() < source.find("owner.quote_fresh(").unwrap());
    assert!(source.contains("broker.check_release_jit_review_prepared(identity, &prepared)"));
    assert!(source.contains("admitted.poison(); broker.poison_jit_review();"));
    assert!(source.contains("owner.verify_identity(identity, original)"));
    assert!(!source.contains("owner.verify_identity(identity, deadline)"));
    let consumer = include_str!("native_release_jit_preparation.rs");
    let actual = consumer.split("pub(super) fn prepare_and_refuse(").nth(1).unwrap();
    assert!(actual.contains("let _retained = (retained, evidence);\n    Err(UNAVAILABLE.to_owned())"));
}
