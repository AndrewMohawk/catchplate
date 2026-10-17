//! Independently selected legacy or native-principal statement families plus a
//! genuine same-key role-4 quote. Nested semantics remain the proof client's job.

use super::{b64, config::{Expectations, TrustRoots}, decode_b64, digest, digest_text,
    ensure, exact, fixed_b64, fresh, json, nitro, now_seconds, parse_digest, pem_der, text, uint};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use catchplate_decision_gate::native_response_profile_v1 as response_profile;
use sha2::{Digest, Sha256};

const COMMON: &[&str] = &[
    "apiVersion", "issued_at_unix", "client_nonce", "principal_id", "route_id",
    "request_digest", "operation_digest", "runtime_manifest_digest", "data_plane_binary_digest",
    "release_digest", "server_instance", "tls_channel_binding",
];
const AUTHORIZED: &[&str] = &[
    "client_request_digest", "release_authority", "control_plane_authorization_receipt",
    "upstream_response", "policy_digest",
];
const BUFFERED: &str = "catchplate.proxyResponseStatement/v2";
const STREAMING: &str = "catchplate.streamingResponseStatement/v1";
const OBSERVATION: &str = "catchplate.responseObservationStatement/v1";
const BOOT_DOMAIN: &[u8] = b"catchplate/native-proof-custody-boot/v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"catchplate/native-response-attestation-challenge/v1\0";
const BINDING_DOMAIN: &[u8] = b"catchplate/enclave-runtime-key-binding/v1\0";
const ED25519_SPKI_PREFIX: &[u8] = &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

pub(super) fn verify(raw: &[u8], expected: &Expectations, roots: &TrustRoots) -> Result<Value, String> {
    let envelope = json::parse(raw, 512 * 1024)?;
    exact(&envelope, &[
        "apiVersion", "kind", "server_statement", "server_statement_sha256", "server_signature", "native_attestation",
    ])?;
    let envelope_version = if expected.native_principal_profile { response_profile::NATIVE_ENVELOPE }
        else { "catchplate.nativeResponseRuntimeProof/v1" };
    ensure(text(&envelope, "apiVersion")? == envelope_version
        && text(&envelope, "kind")? == "CatchplateNativeResponseRuntimeProof", "native envelope version/kind differs")?;
    let statement = envelope.get("server_statement").ok_or("native statement is missing")?;
    let version = text(statement, "apiVersion")?;
    let mut fields = COMMON.to_vec();
    match (expected.native_principal_profile, version) {
        (false, BUFFERED) | (true, response_profile::NATIVE_BUFFERED) => {
            fields.extend_from_slice(AUTHORIZED); fields.push("response");
        }
        (false, STREAMING) | (true, response_profile::NATIVE_STREAMING) => {
            fields.extend_from_slice(AUTHORIZED);
            fields.extend_from_slice(&["authorization_binding_validation", "control_plane_authorization_receipt_sha256", "released_response"]);
        }
        (false, OBSERVATION) | (true, response_profile::NATIVE_OBSERVATION) => fields.extend_from_slice(&[
            "observation_id", "request", "policy", "credential", "authorization", "response_path",
            "upstream_attempt", "upstream_observation", "emitted_response", "observation_authority",
        ]),
        _ => return Err("native statement family is unsupported".to_owned()),
    }
    exact(statement, &fields)?;
    if expected.native_principal_profile {
        ensure(response_profile::valid_principal(text(statement, "principal_id")?),
            "native statement principal is outside its selected profile")?;
    }
    let buffered = version == if expected.native_principal_profile { response_profile::NATIVE_BUFFERED } else { BUFFERED };
    let observation = version == if expected.native_principal_profile { response_profile::NATIVE_OBSERVATION } else { OBSERVATION };
    // serde_json's map is sorted in the locked closure. Strings retain the same
    // valid UTF-8 scalars signed by custody; there is no ASCII re-encoding.
    let statement_bytes = serde_json::to_vec(statement).map_err(|_| "encode native statement")?;
    ensure(!statement_bytes.is_empty() && statement_bytes.len() <= 256 * 1024,
        "native statement exceeds its bound")?;
    let statement_digest = digest(&statement_bytes);
    ensure(parse_digest::<32>(text(&envelope, "server_statement_sha256")?, "sha256:", true)? == statement_digest,
        "native statement digest differs")?;
    let nonce = decode_b64(text(statement, "client_nonce")?, 64)?;
    ensure(nonce.len() >= 32 && (buffered || nonce.len() == 32)
        && nonce == expected.nonce, "native statement nonce differs from independent expectations")?;
    let policy = if observation {
        let value = statement.get("policy").ok_or("native observation policy is missing")?;
        exact(value, &["digest", "snapshot_epoch", "decision_state", "completion_state"])?;
        text(value, "digest")?
    } else { text(statement, "policy_digest")? };
    ensure(parse_digest::<32>(policy, "sha256:", true)? == expected.policy
        && parse_digest::<32>(text(statement, "data_plane_binary_digest")?, "sha256:", true)? == expected.binary,
        "native statement policy/binary differs from independent expectations")?;
    let now = now_seconds()?;
    let statement_issued = uint(statement, "issued_at_unix")?;
    fresh(statement_issued, now, expected)?;

    let signed = envelope.get("server_signature").ok_or("native signature is missing")?;
    exact(signed, &["algorithm", "key_id", "public_key_pem", "signature"])?;
    ensure(text(signed, "algorithm")? == "Ed25519"
        && parse_digest::<32>(text(signed, "key_id")?, "sha256:", true)? == expected.key_id,
        "native signature algorithm/key differs")?;
    let spki = pem_der(text(signed, "public_key_pem")?, "PUBLIC KEY", 4096)?;
    ensure(spki.len() == ED25519_SPKI_PREFIX.len() + 32 && spki.starts_with(ED25519_SPKI_PREFIX)
        && digest(&spki) == expected.key_id, "native Ed25519 SPKI differs from independent expectations")?;
    let raw_key: [u8; 32] = spki[ED25519_SPKI_PREFIX.len()..].try_into().map_err(|_| "native proof key size differs")?;
    ensure(raw_key != [0; 32], "native proof key is zero")?;
    let key = VerifyingKey::from_bytes(&raw_key).map_err(|_| "native proof key is invalid")?;
    let signature: [u8; 64] = fixed_b64(text(signed, "signature")?.strip_prefix("ed25519:")
        .ok_or("native signature prefix differs")?)?;
    key.verify_strict(&statement_bytes, &Signature::from_bytes(&signature))
        .map_err(|_| "native statement signature is invalid")?;
    let mut challenge = Sha256::new();
    challenge.update(CHALLENGE_DOMAIN);
    challenge.update([nonce.len() as u8]);
    challenge.update(&nonce);
    challenge.update(statement_digest);
    challenge.update(signature);
    let challenge: [u8; 32] = challenge.finalize().into();

    let attestation = envelope.get("native_attestation").ok_or("native attestation is missing")?;
    exact(attestation, &["apiVersion", "attestationDocumentB64", "responseProofPublicKey"])?;
    ensure(text(attestation, "apiVersion")? == "catchplate.nativeResponseProofKeyEvidence/v1"
        && fixed_b64::<32>(text(attestation, "responseProofPublicKey")?)? == raw_key,
        "native role-4 evidence key/version differs")?;
    let document = decode_b64(text(attestation, "attestationDocumentB64")?, 12 * 1024)?;
    let mut binding = Sha256::new();
    binding.update(BOOT_DOMAIN);
    binding.update(expected.boot);
    binding.update(expected.key_id);
    binding.update(expected.control_plane_key_id);
    let binding: [u8; 32] = binding.finalize().into();
    ensure(binding != [0; 32], "native boot binding is zero")?;
    let mut user_data = BINDING_DOMAIN.to_vec();
    user_data.push(4);
    for commitment in [&expected.release_record, &expected.policy, &expected.configuration,
        &expected.ca_certificate, &expected.ca_spki, &digest(&raw_key), &binding] {
        user_data.extend_from_slice(commitment);
    }
    let issued = nitro::verify(&document, expected, roots, &raw_key, &user_data, &challenge, now)?;
    let finished = now_seconds()?;
    ensure(finished >= now, "native verifier clock moved backwards")?;
    fresh(statement_issued, finished, expected)?;
    fresh(issued, finished, expected)?;
    Ok(json!({
        "apiVersion": if expected.native_principal_profile { response_profile::NATIVE_VERDICT }
            else { "catchplate.nativeResponseAttestationVerification/v1" },
        "ok": true, "debug": false, "resultScope": "local-signature-and-native-quote-only", "okForAction": false,
        "statementApiVersion": version, "serverStatementSha256": digest_text(&statement_digest),
        "signatureSha256": digest_text(&digest(&signature)), "clientNonce": b64(&expected.nonce),
        "quoteChallenge": b64(&challenge), "bootId": b64(&expected.boot), "keyId": digest_text(&expected.key_id),
        "controlPlaneResponseSigningKeyId": digest_text(&expected.control_plane_key_id),
        "policyHash": digest_text(&expected.policy), "dataPlaneBinaryDigest": digest_text(&expected.binary),
        "requestBindingSha256": digest_text(&binding), "attestationDocumentSha256": digest_text(&digest(&document)),
        "issuedAtUnix": issued, "statementIssuedAtUnix": statement_issued,
    }))
}
