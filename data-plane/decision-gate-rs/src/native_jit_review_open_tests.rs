//! Pure private-state, real local signature and grammar tests only. Synthetic
//! Attempt records are not privileged owners. No Owner, Accepted, native TLS,
//! enclave identity, broker response or committed authority is manufactured.
use super::*;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

const AUTHORIZATION: &str = "serverware.nativeJitReviewOpeningAuthorization/v1";
const ACK: &str = "serverware.nativeJitReviewOpeningCommitAcknowledgment/v1";

fn pin(label: &str) -> String { sha(label.as_bytes()) }
fn literal(value: &Value) -> String {
    String::from_utf8(canonical_ascii_bytes(value).unwrap()).unwrap()
}
fn purpose_key(key: &SigningKey) -> Value {
    let public = key.verifying_key();
    json!({"keyId":sha(public.to_public_key_der().unwrap().as_bytes()),
        "publicKeyBase64Url":URL_SAFE_NO_PAD.encode(public.as_bytes())})
}
fn authorities() -> (Value, SigningKey, SigningKey) {
    let grant = SigningKey::from_bytes(&[51; 32]);
    let commit = SigningKey::from_bytes(&[52; 32]);
    (json!({"authorizerKey":purpose_key(&grant),"commitOwnerKey":purpose_key(&commit)}), grant, commit)
}
fn envelope(payload: &Value, key: &SigningKey, domain: &str) -> String {
    let mut preimage = domain.as_bytes().to_vec(); preimage.push(0);
    preimage.extend(canonical_ascii_bytes(payload).unwrap());
    literal(&json!({"schema":payload["schema"].as_str().unwrap()
        .replacen("serverware.native","serverware.signedNative",1),
        "payload":payload,"signatureBase64Url":URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes())}))
}
fn private_attempt() -> Attempt {
    Attempt { marker: Arc::new(()), nonce: Zeroizing::new("synthetic-cookie".into()), expires: 1_000, deadline: 2_000,
        phase: Phase::Prepared { view: Zeroizing::new(b"synthetic-private-view".to_vec()),
            statement: json!({"synthetic":true}), proof_sha: Some(pin("preparation")) } }
}
fn binding_fixture() -> (Value, String, Value, Value, Vec<u8>) {
    let view = br#"{"display":"synthetic immutable review"}"#.to_vec();
    // These exact historical bytes deliberately exceed serde_json Number's
    // integer width and preserve decimal spelling; no re-encoding is allowed.
    let parent = r#"{"fraction":1.2500,"large":184467440737095516160001}"#;
    let child = format!(r#"{{"arguments":{{"redacted_display_digest":"{}","fraction":1.2500,"large":184467440737095516160001}}}}"#, sha(&view));
    let pair = literal(&json!({"items":[{"plaintextSha256":pin("unused first item")},
        {"plaintextSha256":sha(&view)}]}));
    let input = json!({"reviewId":"review-1","parentOriginal":parent,"childOriginal":child,
        "pairOriginal":pair,"proofOriginal":"synthetic-seal-proof-original"});
    let challenge = json!({"schema":CHALLENGE_SCHEMA,"reviewId":"review-1","approvalRequestId":"approval-1",
        "sourceContractDigest":SOURCE_CONTRACT_DIGEST,"controlPlaneConfigurationDigest":pin("configuration"),
        "openingAssignmentSha256":pin("assignment"),"ownerScopeDigest":pin("owner"),
        "browserNonceCommitment":pin("nonce"),"recipientPublicKey":URL_SAFE_NO_PAD.encode([7u8;32]),
        "issuedAtEpochNs":100,"expiresAtEpochNs":1_000});
    // This literal is an opaque signed-challenge stand-in for the pure hash
    // join only. It is never passed off as an authenticated native challenge.
    let original = literal(&json!({"syntheticChallenge":challenge}));
    let scope = json!({"reviewId":challenge["reviewId"],"approvalRequestId":challenge["approvalRequestId"],
        "reviewerId":"reviewer-1","sessionId":"session-1","credentialRecordId":"credential-1",
        "challengeSha256":sha(original.as_bytes()),"parentOriginalSha256":sha(parent.as_bytes()),
        "childOriginalSha256":sha(child.as_bytes()),"pairSha256":sha(pair.as_bytes()),
        "sealProofSha256":sha(input["proofOriginal"].as_str().unwrap().as_bytes()),
        "sealedSourceContractDigest":pin("historical source"),"sourceContractDigest":SOURCE_CONTRACT_DIGEST,
        "controlPlaneConfigurationDigest":challenge["controlPlaneConfigurationDigest"],
        "openingAssignmentSha256":challenge["openingAssignmentSha256"],"ownerScopeDigest":challenge["ownerScopeDigest"],
        "browserNonceCommitment":challenge["browserNonceCommitment"],"recipientPublicKey":challenge["recipientPublicKey"],
        "documentExpiresAtEpochNs":1_000,"approvalExpiresAtEpochNs":1_000,
        "sessionExpiresAtEpochNs":1_000,"assignmentExpiresAtEpochNs":1_000});
    let grant = json!({"schema":AUTHORIZATION,"operation":"jit.review-open.authorize",
        "requestDigest":pin("request"),"scope":scope,"currentRootVectorDigest":pin("root vector"),
        "currentRootHeadDigest":pin("root head"),"currentRootSequence":0,
        "issuedAtEpochNs":110,"expiresAtEpochNs":900});
    (challenge, original, input, grant, view)
}
fn acknowledgment(grant: &Value, authorization: &str, view: &[u8]) -> (Value, Value, String) {
    let proof_sha = pin("preparation-original");
    let prepared = json!({"schema":PREPARATION_SCHEMA,"authorizationSha256":sha(authorization.as_bytes()),
        "scope":grant["scope"],"reviewDigest":sha(view),"preparedAtEpochNs":125,"expiresAtEpochNs":900});
    let ack = json!({"schema":ACK,"operation":"jit.review-open.receipt.issue","requestDigest":pin("commit request"),
        "authorizationSha256":prepared["authorizationSha256"],"preparationSha256":proof_sha,"scope":grant["scope"],
        "reviewDigest":sha(view),"receiptId":"receipt-1","receiptExpiresAtEpochNs":850,
        "commitMarkerSha256":pin("commit marker"),"completionReceiptSha256":pin("completion"),
        "afterRootVectorDigest":pin("after vector"),"committedAtEpochNs":130,"expiresAtEpochNs":800});
    (ack, prepared, proof_sha)
}
fn cold_configuration() -> Value {
    let (keys, _, _) = authorities();
    let assignment = SigningKey::from_bytes(&[53;32]);
    let der = assignment.verifying_key().to_public_key_der().unwrap();
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der.as_bytes()));
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap().pem();
    let target = json!({"controlPlaneResponseSigningKeyId":pin("control plane"),"releaseRecordSha256":pin("release"),
        "policyHash":pin("policy"),"expectedBinaryDigest":pin("binary"),"expectedPcrs":{
            "PCR0":format!("sha384:{}","1".repeat(96)),"PCR1":format!("sha384:{}","2".repeat(96)),
            "PCR2":format!("sha384:{}","3".repeat(96))},"expectedEif":format!("sha384:{}","1".repeat(96)),
        "maxAgeSeconds":60,"futureSkewSeconds":2,"instanceId":"spiffe://synthetic.test/gate",
        "secretKekId":format!("attested-memory-kek:{}","4".repeat(24))});
    json!({"apiVersion":"serverware.nativeJitReviewOpeningStartup/v1","controlPlaneConfigurationDigest":pin("configuration"),
        "instanceId":target["instanceId"],"secretKekId":target["secretKekId"],"browserVsockPort":9203,
        "nativeJitReviewOpeningPolicy":{"schema":"serverware.nativeJitReviewOpeningPolicy/v1",
            "sourceContractDigest":SOURCE_CONTRACT_DIGEST,"deploymentId":"synthetic-opening",
            "operationMaxSeconds":10,"attemptCapacity":4,"target":target,
            "authorizerKey":keys["authorizerKey"],"commitOwnerKey":keys["commitOwnerKey"],
            "assignmentAuthorizer":{"publicKeyPem":pem,"publicKeyPemSha256":sha(pem.as_bytes()),
                "publicKeySpkiSha256":sha(der.as_bytes())},
            "nativeOrigin":"https://native.synthetic.test","portalOrigin":"https://portal.synthetic.test",
            "trustRoots":{"apiVersion":"serverware.nativeJitReviewOpeningNativeTrustRoots/v1",
                "awsNitroRootCertificatesPem":[ca],"awsNitroCrlsDerBase64url":[],
                "nitroCertificateProfile":{"profileId":"aws-nitro-attestation-pki-native-v1",
                    "allowedLeafExtendedKeyUsageOids":[]}}}})
}
fn valid_configuration(value: &Value) -> bool {
    serde_json::from_value::<Configuration>(value.clone()).is_ok_and(|config| config.validate().is_ok())
}

#[test]
fn pure_attempt_consumes_private_view_once_and_never_rearms_on_authentication() {
    let mut item = private_attempt();
    let Phase::Prepared { view, proof_sha: Some(proof), .. } = item.consume() else { panic!("expected prepared"); };
    assert_eq!(&view[..], b"synthetic-private-view"); assert_eq!(proof, pin("preparation"));
    assert!(matches!(&item.phase, Phase::Spent));
    // A valid cookie does not itself restore a consumed phase.
    assert!(item.authenticate(&item.marker, "synthetic-cookie", 999, 1_999).is_ok());
    assert!(matches!(item.consume(), Phase::Spent));
    assert!(matches!(item.consume(), Phase::Spent));
}

#[test]
fn pure_attempt_owner_cookie_and_both_original_expiry_boundaries_are_required() {
    let item = private_attempt();
    let same_owner = Arc::clone(&item.marker); let different_owner = Arc::new(());
    assert!(item.authenticate(&same_owner, "synthetic-cookie", 999, 1_999).is_ok());
    assert!(item.authenticate(&different_owner, "synthetic-cookie", 999, 1_999).is_err());
    for cookie in ["", "synthetic-cookif", "synthetic-cookie-longer"] {
        assert!(item.authenticate(&same_owner, cookie, 999, 1_999).is_err());
    }
    for (wall, boot) in [(1_000,1_999),(999,2_000),(1_001,2_001)] {
        assert!(item.authenticate(&same_owner, "synthetic-cookie", wall, boot).is_err());
    }
    assert!(matches!(&item.phase, Phase::Prepared { .. }));
}

#[test]
fn local_grant_signature_is_exact_key_domain_purpose_and_original() {
    let (policy, grant_key, commit_key) = authorities();
    let (_, _, _, grant, _) = binding_fixture();
    let signed = envelope(&grant, &grant_key, AUTHORIZATION);
    assert_eq!(wire::authority(&signed, &policy, false, 120).unwrap(), grant);
    assert!(wire::authority(&signed, &policy, true, 120).is_err());
    for (key, domain) in [(&commit_key,AUTHORIZATION),(&grant_key,ACK),
        (&grant_key,"serverware.nativeStaticCredentialAuthorization/v1")] {
        assert!(wire::authority(&envelope(&grant,key,domain), &policy, false, 120).is_err());
    }
    let mut tampered: Value = serde_json::from_str(&signed).unwrap();
    tampered["payload"]["requestDigest"] = json!(pin("tampered request"));
    assert!(wire::authority(&literal(&tampered), &policy, false, 120).is_err());
    let mut extra: Value = serde_json::from_str(&signed).unwrap(); extra["admitted"] = json!(true);
    assert!(wire::authority(&literal(&extra), &policy, false, 120).is_err());
    assert!(wire::authority(&(signed.clone()+" "), &policy, false, 120).is_err());
    assert!(wire::authority(&format!("{{\"schema\":\"duplicate\",{}", &signed[1..]), &policy, false, 120).is_err());
}

#[test]
fn local_authority_closed_scope_integer_and_time_controls_are_resigned() {
    let (policy, key, _) = authorities(); let (_, _, _, grant, _) = binding_fixture();
    for now in [109,900,901] {
        assert!(wire::authority(&envelope(&grant,&key,AUTHORIZATION), &policy, false, now).is_err());
    }
    for name in grant["scope"].as_object().unwrap().keys() {
        let mut bad = grant.clone(); bad["scope"].as_object_mut().unwrap().remove(name);
        assert!(wire::authority(&envelope(&bad,&key,AUTHORIZATION), &policy, false, 120).is_err(), "{name}");
    }
    for (field,value) in [("issuedAtEpochNs",json!(0)),("expiresAtEpochNs",json!(true)),
        ("currentRootSequence",json!(-1)),("currentRootSequence",json!(u64::MAX)),
        ("operation",json!("jit.review-open.receipt.issue")),("extra",json!(null))] {
        let mut bad = grant.clone(); bad[field] = value;
        assert!(wire::authority(&envelope(&bad,&key,AUTHORIZATION), &policy, false, 120).is_err(), "{field}");
    }
    for name in ["documentExpiresAtEpochNs","approvalExpiresAtEpochNs","sessionExpiresAtEpochNs","assignmentExpiresAtEpochNs"] {
        let mut bad = grant.clone(); bad["scope"][name] = json!(899);
        assert!(wire::authority(&envelope(&bad,&key,AUTHORIZATION), &policy, false, 120).is_err(), "{name}");
    }
    let mut long = grant.clone(); long["expiresAtEpochNs"] = json!(30_000_000_111u64);
    for name in ["documentExpiresAtEpochNs","approvalExpiresAtEpochNs","sessionExpiresAtEpochNs","assignmentExpiresAtEpochNs"] {
        long["scope"][name] = json!(40_000_000_000u64);
    }
    assert!(wire::authority(&envelope(&long,&key,AUTHORIZATION), &policy, false, 120).is_err());
}

#[test]
fn pure_grant_join_binds_challenge_all_four_literal_originals_and_expiry() {
    let (challenge, original, input, grant, _) = binding_fixture();
    assert!(wire::grant_join(&grant,&challenge,&original,&input,1_000).is_ok());
    for name in ["reviewId","approvalRequestId","sourceContractDigest","controlPlaneConfigurationDigest",
        "openingAssignmentSha256","ownerScopeDigest","browserNonceCommitment","recipientPublicKey"] {
        let mut bad = challenge.clone(); bad[name] = json!("different");
        assert!(wire::grant_join(&grant,&bad,&original,&input,1_000).is_err(), "{name}");
    }
    for name in ["parentOriginal","childOriginal","pairOriginal","proofOriginal"] {
        let mut bad = input.clone(); bad[name] = json!(format!("{} ", input[name].as_str().unwrap()));
        assert!(wire::grant_join(&grant,&challenge,&original,&bad,1_000).is_err(), "{name}");
    }
    assert!(wire::grant_join(&grant,&challenge,&(original.clone()+" "),&input,1_000).is_err());
    assert!(wire::grant_join(&grant,&challenge,&original,&input,1_001).is_err());
    for (name,value) in [("issuedAtEpochNs",111),("expiresAtEpochNs",899)] {
        let mut bad = challenge.clone(); bad[name] = json!(value);
        assert!(wire::grant_join(&grant,&bad,&original,&input,1_000).is_err());
    }
}

#[test]
fn local_commit_ack_requires_distinct_signature_and_exact_preparation_binding() {
    let (policy, grant_key, commit_key) = authorities(); let (_, _, _, grant, view) = binding_fixture();
    let authorization = envelope(&grant,&grant_key,AUTHORIZATION);
    let (ack, prepared, proof_sha) = acknowledgment(&grant,&authorization,&view);
    let signed = envelope(&ack,&commit_key,ACK);
    assert_eq!(wire::authority(&signed,&policy,true,140).unwrap(),ack);
    assert!(wire::ack_join(&ack,&prepared,&proof_sha).is_ok());
    assert!(wire::authority(&signed,&policy,false,140).is_err());
    assert!(wire::authority(&envelope(&ack,&grant_key,ACK),&policy,true,140).is_err());
    assert!(wire::authority(&envelope(&ack,&commit_key,AUTHORIZATION),&policy,true,140).is_err());
    for name in ["authorizationSha256","preparationSha256","reviewDigest"] {
        let mut bad = ack.clone(); bad[name] = json!(pin("wrong binding"));
        let verified = wire::authority(&envelope(&bad,&commit_key,ACK),&policy,true,140).unwrap();
        assert!(wire::ack_join(&verified,&prepared,&proof_sha).is_err(), "{name}");
    }
    let mut bad = ack.clone(); bad["scope"]["reviewerId"] = json!("another-reviewer");
    let verified = wire::authority(&envelope(&bad,&commit_key,ACK),&policy,true,140).unwrap();
    assert!(wire::ack_join(&verified,&prepared,&proof_sha).is_err());
    for (name,value) in [("committedAtEpochNs",124),("expiresAtEpochNs",901)] {
        let mut bad = ack.clone(); bad[name] = json!(value);
        assert!(wire::ack_join(&bad,&prepared,&proof_sha).is_err());
    }
    let mut bad = ack.clone(); bad["receiptExpiresAtEpochNs"] = json!(799);
    assert!(wire::authority(&envelope(&bad,&commit_key,ACK),&policy,true,140).is_err());
    for value in ["", "receipt with spaces", "receipt\t", "receipt\u{7f}"] {
        let mut bad = ack.clone(); bad["receiptId"] = json!(value);
        assert!(wire::authority(&envelope(&bad,&commit_key,ACK),&policy,true,140).is_err());
    }
    assert!(wire::authority(&signed,&policy,true,800).is_err());
}

#[test]
fn pure_display_digest_projection_preserves_floats_and_large_literal_numbers() {
    let (challenge, original, input, grant, view) = binding_fixture(); let before = input.clone();
    assert!(wire::review_digest_join(&input,&view).is_ok());
    assert!(wire::grant_join(&grant,&challenge,&original,&input,1_000).is_ok());
    assert_eq!(input,before);
    for name in ["parentOriginal","childOriginal"] {
        assert!(input[name].as_str().unwrap().contains("1.2500"));
        assert!(input[name].as_str().unwrap().contains("184467440737095516160001"));
        let mut bad = input.clone(); bad[name] = json!(input[name].as_str().unwrap().replace("1.2500","1.25"));
        assert!(wire::grant_join(&grant,&challenge,&original,&bad,1_000).is_err());
    }
    assert!(wire::review_digest_join(&input,b"changed private view").is_err());
    for name in ["childOriginal","pairOriginal"] {
        let mut bad = input.clone(); bad[name] = json!(input[name].as_str().unwrap().replace(&sha(&view),&pin("different display")));
        assert!(wire::review_digest_join(&bad,&view).is_err());
        bad[name] = json!("{}"); assert!(wire::review_digest_join(&bad,&view).is_err());
    }
    let mut bad = input.clone(); bad["pairOriginal"] = json!("{\"items\":[]}");
    assert!(wire::review_digest_join(&bad,&view).is_err());
}

#[test]
fn cold_opening_schema_and_current_manifest_are_closed_and_not_sealing() {
    let good = cold_configuration(); assert!(valid_configuration(&good));
    let config: Configuration = serde_json::from_value(good.clone()).unwrap();
    assert_eq!(config.browser_vsock_port(),9203); assert_eq!(config.deployment_id(),"synthetic-opening");
    for version in ["serverware.nativeJitReviewConfiguration/v2","serverware.nativeStaticCredentialConfiguration/v1"] {
        let mut bad = good.clone(); bad["apiVersion"] = json!(version); assert!(!valid_configuration(&bad));
    }
    for value in [json!("serverware.nativeJitReviewCustodyAuthorityPolicy/v1"),json!(null)] {
        let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["schema"] = value;
        assert!(!valid_configuration(&bad));
    }
    for value in [json!(pin("old manifest")),json!(format!("sha256:{}","0".repeat(64))),json!(null)] {
        let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["sourceContractDigest"] = value;
        assert!(!valid_configuration(&bad));
    }
    let mut bad = good.clone(); bad["admitted"] = json!(true); assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["grant"] = json!(true);
    assert!(!valid_configuration(&bad));
    for name in good["nativeJitReviewOpeningPolicy"].as_object().unwrap().keys() {
        let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"].as_object_mut().unwrap().remove(name);
        assert!(!valid_configuration(&bad), "{name}");
    }
}

#[test]
fn cold_policy_rejects_bad_bounds_key_aliases_targets_trust_and_origins() {
    let good = cold_configuration(); assert!(valid_configuration(&good));
    for (name,value) in [("operationMaxSeconds",json!(0)),("operationMaxSeconds",json!(31)),
        ("attemptCapacity",json!(0)),("attemptCapacity",json!(17)),("attemptCapacity",json!(true)),
        ("nativeOrigin",json!("http://native.synthetic.test")),("nativeOrigin",json!("https://portal.synthetic.test"))] {
        let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"][name] = value;
        assert!(!valid_configuration(&bad), "{name}");
    }
    for port in [0,1023,u32::MAX] {
        let mut bad = good.clone(); bad["browserVsockPort"] = json!(port); assert!(!valid_configuration(&bad));
    }
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["commitOwnerKey"] =
        good["nativeJitReviewOpeningPolicy"]["authorizerKey"].clone(); assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["authorizerKey"]["keyId"] = json!(pin("wrong SPKI"));
    assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["assignmentAuthorizer"]["publicKeyPemSha256"] = json!(pin("wrong PEM"));
    assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["target"]["expectedEif"] = json!(format!("sha384:{}","9".repeat(96)));
    assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["instanceId"] = json!("spiffe://another.test/gate"); assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["trustRoots"]["apiVersion"] = json!("serverware.nativeJitReviewNativeTrustRoots/v1");
    assert!(!valid_configuration(&bad));
    let mut bad = good.clone(); bad["nativeJitReviewOpeningPolicy"]["trustRoots"]["awsNitroRootCertificatesPem"] = json!([]);
    assert!(!valid_configuration(&bad));
}

#[test]
fn source_only_disclosure_order_spends_before_ack_and_private_output() {
    // Source-order guard only: this neither opens TLS nor exercises a native
    // owner. Connected acceptance must separately prove actual custody.
    let source = include_str!("native_jit_review_open_v1.rs");
    let disclose = source.split("pub(crate) fn plan_disclosure(").nth(1).unwrap();
    let spend = disclose.find("item.consume()").unwrap();
    let ack = disclose.find("wire::authority(").unwrap();
    let binding = disclose.find("wire::ack_join(").unwrap();
    let output = disclose.find("request.respond(").unwrap();
    assert!(spend < ack && ack < binding && binding < output);
    assert!(!disclose[..output].contains("item.phase ="));
    let prepare = source.split("pub(crate) fn plan_preparation(").nth(1).unwrap()
        .split("pub(crate) fn prepare(").next().unwrap();
    assert!(prepare.find("item.consume()").unwrap() < prepare.find("wire::authority(").unwrap());
    assert!(prepare.find("attempt_capacity(self.preparations").unwrap() < prepare.find("item.consume()").unwrap());
    assert!(prepare.find("request.check()").unwrap() < prepare.find("self.preparations += 1").unwrap());
    let challenge = source.split("pub(crate) fn begin_challenge(").nth(1).unwrap()
        .split("pub(crate) fn finish_challenge(").next().unwrap();
    assert!(challenge.find("request.narrow_deadline(deadline)").unwrap()
        < challenge.find("self.attempts.insert(").unwrap());
    let custody = include_str!("native_jit_review_open_custody.rs");
    let handle = custody.split("pub fn handle_native_jit_review_open(").nth(1).unwrap();
    let compact: String = handle.split_whitespace().collect();
    assert!(!compact.contains("self.verify_native_identity(identity,deadline)"));
    assert!(compact.contains("letoriginal=identity.deadline().min(owner.deadline())"));
    assert!(compact.contains("owner.verify_identity(identity,original)"));
    assert!(compact.contains("admitted.check(broker,identity,owner_deadline)"));
    assert!(compact.contains("RequestOutcome::local(admitted.plan_preparation(request))"));
    assert!(compact.contains("RequestOutcome::local(admitted.plan_disclosure(request))"));
    assert!(!compact.contains("RequestOutcome::local(admitted.prepare("));
    assert!(!compact.contains("RequestOutcome::local(self.sign_review_open_statement("));
}

#[test]
fn local_refusal_preserves_other_attempt_and_shared_liveness() {
    // Synthetic private state only, not a fabricated native Owner/Accepted.
    let service=ServiceFence::default();
    let mut healthy=private_attempt();
    let owner=Arc::clone(&healthy.marker);
    assert!(matches!(RequestOutcome::local(healthy.authenticate(&owner,"wrong-cookie",100,100)),RequestOutcome::Refused));
    assert!(matches!(RequestOutcome::local(attempt_capacity(16,16)),RequestOutcome::Refused));
    assert!(attempt_capacity(15,16).is_ok());
    let (policy,_,_)=authorities();
    assert!(matches!(RequestOutcome::local(wire::authority("not-json",&policy,false,140)),RequestOutcome::Refused));
    service.check().unwrap();
    healthy.authenticate(&owner,"synthetic-cookie",100,100).unwrap();
    assert!(matches!(healthy.consume(),Phase::Prepared{..}));
    service.check().unwrap();
}

#[test]
fn claimed_refusal_and_uncertain_socket_output_never_rearm() {
    let service=ServiceFence::default();
    let mut claimed=private_attempt();
    let owner=Arc::clone(&claimed.marker);
    claimed.authenticate(&owner,"synthetic-cookie",100,100).unwrap();
    let Phase::Prepared{view,..}=claimed.consume() else { panic!("private fixture phase"); };
    let (policy,grant_key,_)=authorities();
    let (_,_,_,grant,bytes)=binding_fixture();
    let authorization=envelope(&grant,&grant_key,AUTHORIZATION);
    let (ack,_,_)=acknowledgment(&grant,&authorization,&bytes);
    // A real locally signed but wrong-purpose-key ACK is refused after claim.
    let wrong=envelope(&ack,&grant_key,ACK);
    assert!(matches!(RequestOutcome::local(wire::authority(&wrong,&policy,true,140)),RequestOutcome::Refused));
    drop(view);
    assert!(matches!(claimed.consume(),Phase::Spent));
    assert!(matches!(RequestOutcome::local(Err::<(),String>("uncertain socket write".into())),RequestOutcome::Refused));
    assert!(matches!(claimed.consume(),Phase::Spent));
    service.check().unwrap();
}

#[test]
fn fatal_shared_custody_fence_cannot_resume_after_local_refusal() {
    let mut service=ServiceFence::default();
    service.check().unwrap();
    service.poison();
    assert!(service.check().is_err());
    assert!(matches!(RequestOutcome::local(Err::<(),String>("local refusal".into())),RequestOutcome::Refused));
    assert!(service.check().is_err());
    service.poison();
    assert!(service.check().is_err());
}
