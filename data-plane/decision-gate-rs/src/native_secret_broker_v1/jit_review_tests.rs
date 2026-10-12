//! Recorded actual FD3/Python crypto originals; pure correlation tests only.
//! These tests never construct Prepared, a process/identity or native authority.
use super::*;

fn fixture() -> Vec<Value> {
    let path = std::env::var_os("SERVERWARE_TEST_JIT_RUST_FIXTURE")
        .expect("the actual Python FD3 fixture is required; this test never skips");
    let file = std::fs::File::open(path).expect("read actual FD3 fixture");
    assert!(file.metadata().expect("fixture metadata").len() <= 128 * 1024);
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut bytes).expect("bounded fixture read");
    assert!(bytes.len() <= 128 * 1024);
    if bytes.last() == Some(&b'\n') { bytes.pop(); }
    let value = document(&bytes, 128 * 1024).expect("canonical actual FD3 fixture");
    fields(&value, &["schema", "boundary", "cases"]).unwrap();
    assert!(value["schema"] == "serverware.nativeJitRustContractFixture/v1"
        && value["boundary"] == "synthetic-local-process-no-native-admission");
    let cases = value["cases"].as_array().expect("two fixture cases");
    assert!(cases.len() == 2 && cases[0]["name"] == "ordinary" && cases[1]["name"] == "clipped");
    for case in cases {
        fields(case, &["name", "configurationOriginal", "commandOriginal", "responseOriginal",
            "validationNowEpochNs", "validationBoottimeNs", "brokerDeadlineBoottimeNs"]).unwrap();
    }
    cases.clone()
}
fn parsed(case: &Value) -> (Value, &str, Value) {
    (document(text(&case["configurationOriginal"]).unwrap().as_bytes(), MAX_COMMAND).unwrap(),
        text(&case["commandOriginal"]).unwrap(),
        document(text(&case["responseOriginal"]).unwrap().as_bytes(), MAX_FRAME).unwrap())
}
fn check(case: &Value, config: &Value, command: &str, response: &Value) -> Result<(), String> {
    validate_exchange(config, command.as_bytes(), response, integer(&case["validationNowEpochNs"] )?,
        integer(&case["validationBoottimeNs"] )?, integer(&case["brokerDeadlineBoottimeNs"] )?)
}

#[test]
fn actual_python_fd3_originals_correlate_without_minting_prepared() {
    for case in fixture() {
        let (config, command, response) = parsed(&case);
        assert!(check(&case, &config, command, &response).is_ok());
        for exact in ["1e-05", "1e+20", "18446744073709551633", "-18446744073709551633"] {
            assert!(command.contains(exact), "actual numeric spelling must be present");
        }
        let (original, _) = originals::command_inputs(command.as_bytes()).unwrap();
        assert!(original.plaintexts[0].0 != original.request["arguments"]["canonical_request_digest"]);
        if case["name"] == "clipped" {
            let (_, control) = originals::command_inputs(command.as_bytes()).unwrap();
            assert!(integer(&response["pair"]["scope"]["sealExpiresAtEpochNs"]).unwrap()
                < integer(&control["sealExpiresAtEpochNs"]).unwrap());
            assert!(integer(&response["pair"]["scope"]["documentExpiresAtEpochNs"]).unwrap()
                < integer(&control["documentExpiresAtEpochNs"]).unwrap());
        }
    }
}

#[test]
fn private_numbers_are_never_round_tripped_and_boolean_null_structure_is_valid() {
    for raw in [b"{\"a\":true,\"b\":[false,null,{\"n\":18446744073709551633}]}".as_slice(),
        b"{\"float\":1e-05,\"negative\":-18446744073709551633,\"zero\":-0.0}"] {
        assert!(originals::structure(raw, 0, &mut 0).is_ok());
    }
    for case in fixture() {
        let (config, command, response) = parsed(&case);
        let changed = command.replacen("1e-05", "1e-06", 1);
        assert!(changed != command && check(&case, &config, &changed, &response).is_err());
        let lossy: Value = serde_json::from_str(command).unwrap();
        let rewritten = String::from_utf8(canonical_ascii_bytes(&lossy).unwrap()).unwrap();
        assert!(rewritten != command && check(&case, &config, &rewritten, &response).is_err());
    }
}

#[test]
fn private_duplicate_nonfinite_noncanonical_and_structure_bounds_refuse() {
    for raw in [b"{\"a\":1,\"a\":2}".as_slice(), b"{\"b\":1,\"a\":2}", b"{\"a\": 1}",
        b"{\"a\":NaN}", b"{\"a\":1e999}", b"{\"a\":\"\\u0061\"}", b"{\"a\":1}\n"] {
        assert!(originals::structure(raw, 0, &mut 0).is_err());
    }
    assert!(originals::structure(b"null", 33, &mut 0).is_err());
    assert!(originals::structure(b"null", 0, &mut 131072).is_err());
    for case in fixture() {
        let (config, command, response) = parsed(&case);
        let duplicated = command.replacen("\"numbers\":[", "\"numbers\":[],\"numbers\":[", 1);
        assert!(duplicated != command && check(&case, &config, &duplicated, &response).is_err());
    }
}

#[test]
fn every_retained_identity_and_configuration_join_is_checked() {
    let case = fixture().remove(0);
    let (config, command, response) = parsed(&case);
    for field in IDENTITY {
        let mut changed = response.clone(); changed["statementBindings"][*field] = json!("changed");
        assert!(check(&case, &config, command, &changed).is_err());
    }
    for field in ["sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest", "deploymentId",
        "instanceId", "requestDigest", "operationId", "publicRequestSha256", "pairSha256", "secretKekId", "challenge"] {
        let mut changed = response.clone(); changed["statementBindings"][field] = json!("changed");
        assert!(check(&case, &config, command, &changed).is_err());
    }
    let mut different_config = config.clone(); different_config["controlPlaneConfigurationDigest"] = json!(sha(b"other CP config"));
    assert!(check(&case, &different_config, command, &response).is_err());
    let mut extra = response.clone(); extra["verified"] = json!(true);
    assert!(check(&case, &config, command, &extra).is_err());
}

#[test]
fn pair_domains_ids_plaintext_wrapper_and_padding_are_exact() {
    let case = fixture().remove(0);
    let (config, command, response) = parsed(&case);
    for field in ["opaqueId", "valueKind", "plaintextSha256", "plaintextBytes", "wrappedKeyNonce",
        "wrappedKey", "ciphertextNonce", "ciphertext"] {
        let mut changed = response.clone(); changed["pair"]["items"][0][field] = json!("changed");
        assert!(check(&case, &config, command, &changed).is_err());
    }
    let mut reversed = response.clone(); reversed["pair"]["items"].as_array_mut().unwrap().swap(0, 1);
    assert!(check(&case, &config, command, &reversed).is_err());
    let unpadded = json!(URL_SAFE_NO_PAD.encode([1u8; 17]));
    assert!(padded(&unpadded, 17).is_err());
    assert!(padded(&json!(URL_SAFE.encode([1u8; 17])), 17).is_ok());
    assert!(padded(&json!(URL_SAFE.encode([1u8; 16])), 17).is_err());
}

#[test]
fn expiry_original_deadline_and_cross_case_refuse() {
    let cases = fixture();
    for case in &cases {
        let (config, command, response) = parsed(case);
        let expires = integer(&response["statementBindings"]["expiresAtEpochNs"]).unwrap();
        assert!(validate_exchange(&config, command.as_bytes(), &response, expires,
            integer(&case["validationBoottimeNs"]).unwrap(), integer(&case["brokerDeadlineBoottimeNs"]).unwrap()).is_err());
        assert!(validate_exchange(&config, command.as_bytes(), &response, integer(&case["validationNowEpochNs"]).unwrap(),
            integer(&case["brokerDeadlineBoottimeNs"]).unwrap(), integer(&case["brokerDeadlineBoottimeNs"]).unwrap()).is_err());
        let mut extended = response.clone(); extended["pair"]["scope"]["sealExpiresAtEpochNs"] = json!(i64::MAX);
        assert!(check(case, &config, command, &extended).is_err());
    }
    let (config, command, _) = parsed(&cases[0]);
    let (_, _, other_response) = parsed(&cases[1]);
    assert!(check(&cases[0], &config, command, &other_response).is_err());
}

#[test]
fn frozen_wall_cannot_extend_the_original_monotonic_seal() {
    let (wall, boot, expires) = (100_000_000_000, 10_000_000_000, 104_000_000_000);
    let deadline = seal_deadline(wall, boot, expires, boot + 12_000_000_000, boot + 20_000_000_000).unwrap();
    assert_eq!(deadline, boot + 4_000_000_000);
    assert!(seal_live(wall, expires, deadline, wall, deadline - 1).is_ok());
    assert!(seal_live(wall, expires, deadline, wall, deadline).is_err());
    assert!(seal_live(wall, expires, deadline, wall, deadline + 1).is_err());
    assert!(seal_live(wall, expires, deadline, expires, boot).is_err());
    // Forward wall movement may tighten the independent parent limit. This
    // does not pretend to recover the unexported child BOOTTIME sample.
    let tightened = seal_deadline(wall + 3_000_000_000, boot + 1_000_000_000,
        expires, deadline, boot + 20_000_000_000).unwrap();
    assert_eq!(tightened, boot + 2_000_000_000);
    assert!(seal_live(wall, expires, tightened, wall + 3_000_000_000, tightened).is_err());
    let later_stalled = seal_deadline(wall + 3_000_000_000, boot + 1_500_000_000,
        expires, tightened, boot + 20_000_000_000).unwrap();
    assert_eq!(later_stalled, tightened); // It cannot rearm to 2.5 seconds.
}

#[test]
fn child_clips_only_narrow_same_initial_clock_pair_and_do_not_change_broker_lifetime() {
    let (wall, boot, broker) = (100_000_000_000, 10_000_000_000, 30_000_000_000);
    let original = seal_deadline(wall, boot, wall + 20_000_000_000, boot + 12_000_000_000, broker).unwrap();
    assert_eq!(original, boot + 12_000_000_000);
    let clipped = seal_deadline(wall, boot, wall + 3_000_000_000, original, broker).unwrap();
    assert_eq!(clipped, boot + 3_000_000_000);
    assert!(clipped < original && original < broker);
    // A later distinct request can still use the original broker interval;
    // neither this leaf nor production modifies that global deadline.
    let next = seal_deadline(wall + 5_000_000_000, boot + 5_000_000_000,
        wall + 9_000_000_000, broker, broker).unwrap();
    assert_eq!(next, boot + 9_000_000_000);
    let ceiling = seal_deadline(wall, boot, wall + 100_000_000_000, boot + 120_000_000_000,
        boot + 120_000_000_000).unwrap();
    assert_eq!(ceiling, boot + 30_000_000_000);
}

#[test]
fn seal_clock_overflow_expired_and_inconsistent_originals_refuse() {
    for args in [(0, 1, 2, 20, 20), (5, 0, 6, 20, 20), (5, 1, 5, 20, 20),
        (5, 1, 4, 20, 20), (5, 10, 6, 10, 20), (5, 1, 6, 21, 20),
        (5, u64::MAX - 1, 8, u64::MAX, u64::MAX),
        (5, u64::MAX - 10, 6, u64::MAX, u64::MAX),
        (i64::MAX as u64, 1, i64::MAX as u64 + 1, 20, 20)] {
        assert!(seal_deadline(args.0, args.1, args.2, args.3, args.4).is_err());
    }
}
