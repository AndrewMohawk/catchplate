//! Compound release originals, not native caller admission or writer evidence.
//! Parent numeric spellings stay borrowed RawValue bytes throughout derivation.
//! The actual child additionally validates Python's canonical finite numbers,
//! the complete private release grammar and its current contract manifest.
use super::*;
use serde_json::value::RawValue;

const PARENT_ARGUMENTS: &[&str] = &["attempt_id", "flow_id", "principal_id", "route_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest", "operation_context",
    "shared_quotas", "require_jit_grant", "reservation_ttl_seconds", "durable_policy_binding",
    "jit_approval_request", "now_epoch_ms", "actor_id", "authority_policy_hash", "authority_route_id",
    "required_approver_roles", "allowed_approver_ids", "require_approver_webauthn", "approval_threshold",
    "approver_credential_policy", "native_profile", "policy_aware_profile", "expected_approver_policy_sha256",
    "schema", "original_arguments_digest", "businessIntent"];
const INHERITED: &[&str] = &["principal_id", "route_id", "credential_id", "credential_version",
    "policy_hash", "request_digest", "operation_digest", "required_approver_roles", "allowed_approver_ids",
    "require_approver_webauthn", "approval_threshold", "approver_credential_policy"];

pub(super) struct ParentBindings {
    pub(super) sha256: String,
    pub(super) request_digest: String,
    pub(super) operation_id: String,
}
pub(super) struct ReleaseOriginals {
    pub(super) child: originals::Originals,
    pub(super) parent: ParentBindings,
}

fn string(value: &RawValue) -> Result<String, String> {
    serde_json::from_str(value.get()).map_err(|_| "JIT release text differs".to_owned())
}
fn exact(value: &RawValue, expected: &str) -> Result<(), String> {
    ensure(value.get().as_bytes() == canonical_ascii_bytes(&expected)?, "JIT release purpose differs")
}
fn raw_join<'a>(values: &'a BTreeMap<String, &'a RawValue>, omit: &[&str])
    -> Result<Zeroizing<Vec<u8>>, String> {
    originals::join(&values.iter().filter(|(name, _)| !omit.contains(&name.as_str()))
        .map(|(name, value)| (name.as_str(), value.get().as_bytes())).collect())
}

// This rechecks the pure graph derivation and originals, not current policy,
// credentials, selected rows, proofs, authentication or custody permission.
pub(super) fn read(runtime: &[u8], parent: &[u8], child: &[u8]) -> Result<ReleaseOriginals, String> {
    for raw in [runtime, parent, child] {
        ensure(!raw.is_empty() && raw.len() <= MAX_COMMAND, "JIT release originals exceed bound")?;
        originals::structure(raw, 0, &mut 0)?;
    }
    let envelope = originals::object(runtime)?;
    originals::keys(&envelope, &["schema", "handler", "operationManifestDigest", "arguments", "privateDocuments"])?;
    exact(envelope["schema"], "serverware.policyAuthorityPrivateReleaseWriterInput/v1")?;
    exact(envelope["handler"], "reserve_release_authorization_v2")?;
    let request = originals::object(parent)?;
    originals::keys(&request, &["schema", "operation", "operationId", "requestDigest", "handler",
        "operationManifestDigest", "arguments"])?;
    exact(request["schema"], "serverware.policyAuthorityV9Request/v1")?;
    exact(request["operation"], "release.reserve")?;
    exact(request["handler"], "reserve_release_authorization_v2")?;
    ensure(request["operationManifestDigest"].get() == envelope["operationManifestDigest"].get(),
        "JIT release manifest differs")?;
    let arguments = originals::object(request["arguments"].get().as_bytes())?;
    originals::keys(&arguments, PARENT_ARGUMENTS)?;
    exact(arguments["schema"], "serverware.releaseReserveCommitments/v1")?;
    let unsigned = raw_join(&arguments, &["businessIntent"])?;
    ensure(unsigned.as_slice() == envelope["arguments"].get().as_bytes(), "JIT release public/private arguments differ")?;
    let intent = originals::object(arguments["businessIntent"].get().as_bytes())?;
    originals::keys(&intent, &["schema", "operation", "planningAdapterId", "arguments"])?;
    exact(intent["schema"], "serverware.policyAuthorityBusinessIntent/v2")?;
    exact(intent["operation"], "release.reserve")?;
    exact(intent["planningAdapterId"], "serverware.policyAuthorityPlanningAdapter/reserve_release_authorization_v2/v1")?;
    ensure(intent["arguments"].get().as_bytes() == unsigned.as_slice(), "JIT release business intent differs")?;
    ensure(arguments["native_profile"].get() == "true" && arguments["policy_aware_profile"].get() == "false"
        && arguments["require_jit_grant"].get() == "true", "JIT compound native profile differs")?;

    // Derive the standalone private-v2 envelope without parsing any parent
    // context/quotas or private documents through serde_json::Value.
    let child_runtime = originals::join(&BTreeMap::from([
        ("schema", b"\"serverware.policyAuthorityPrivateJitWriterInput/v2\"".as_slice()),
        ("handler", b"\"ensure_jit_approval_request\"".as_slice()),
        ("operationManifestDigest", envelope["operationManifestDigest"].get().as_bytes()),
        ("arguments", arguments["jit_approval_request"].get().as_bytes()),
        ("privateDocuments", envelope["privateDocuments"].get().as_bytes()),
    ]))?;
    let child = originals::read(&child_runtime, child)?;
    ensure(child.request["arguments"]["businessIntent"]["planningAdapterId"]
        == "serverware.policyAuthorityPlanningAdapter/ensure_jit_approval_request/v1",
        "JIT compound child intent differs")?;
    let nested = originals::object(arguments["jit_approval_request"].get().as_bytes())?;
    for name in INHERITED {
        ensure(arguments[*name].get() == nested.get(*name).ok_or("JIT inherited field absent")?.get(),
            "JIT release child inherited field differs")?;
    }
    // Every untyped facade field is retained; only the seven original nested
    // child fields are reconstructed from their exact public/private owners.
    let private = originals::object(envelope["privateDocuments"].get().as_bytes())?;
    let mut nested_raw = BTreeMap::new();
    for name in ["method", "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"] {
        nested_raw.insert(name, nested.get(name).ok_or("JIT nested field absent")?.get().as_bytes());
    }
    nested_raw.extend(private.iter().map(|(name, value)| (name.as_str(), value.get().as_bytes())));
    let nested_raw = originals::join(&nested_raw)?;
    let mut reconstructed: BTreeMap<&str, &[u8]> = arguments.iter()
        .filter(|(name, _)| !["schema", "original_arguments_digest", "businessIntent"].contains(&name.as_str()))
        .map(|(name, value)| (name.as_str(), value.get().as_bytes())).collect();
    reconstructed.insert("jit_approval_request", &nested_raw);
    let reconstructed = originals::join(&reconstructed)?;
    ensure(string(arguments["original_arguments_digest"])? == sha(&reconstructed), "JIT release original commitment differs")?;
    parent_grammar(&arguments)?;

    let authorization = originals::join(&BTreeMap::from([
        ("schema", b"\"serverware.policyAuthorityV9Authorization/v1\"".as_slice()),
        ("operation", request["operation"].get().as_bytes()),
        ("handler", request["handler"].get().as_bytes()),
        ("operationManifestDigest", request["operationManifestDigest"].get().as_bytes()),
        ("arguments", request["arguments"].get().as_bytes()),
    ]))?;
    let request_digest = framed("serverware.policyAuthorityV9Request/v1", &[&authorization]);
    let operation_id = framed("serverware.policyAuthorityOperation/v2", &[b"release.reserve", request_digest.as_bytes()]);
    ensure(string(request["requestDigest"])? == request_digest && string(request["operationId"])? == operation_id,
        "JIT release public commitment differs")?;
    Ok(ReleaseOriginals { child, parent: ParentBindings { sha256: sha(parent), request_digest, operation_id } })
}

fn parent_grammar(arguments: &BTreeMap<String, &RawValue>) -> Result<(), String> {
    for name in ["attempt_id", "policy_hash", "request_digest", "operation_digest", "expected_approver_policy_sha256"] {
        digest(&string(arguments[name])?)?;
    }
    ensure(arguments["flow_id"].get() == arguments["attempt_id"].get()
        && !string(arguments["actor_id"])?.is_empty(), "JIT release flow or actor differs")?;
    let ttl: u64 = serde_json::from_str(arguments["reservation_ttl_seconds"].get()).map_err(|_| "JIT release TTL differs")?;
    ensure((1..=300).contains(&ttl), "JIT release TTL bound")?;
    if arguments["now_epoch_ms"].get() != "null" {
        let now: u64 = serde_json::from_str(arguments["now_epoch_ms"].get()).map_err(|_| "JIT release original time differs")?;
        ensure(now <= i64::MAX as u64, "JIT release original time bound")?;
    }
    originals::object(arguments["operation_context"].get().as_bytes())?;
    ensure(arguments["operation_context"].get().len() <= 64 * 1024, "JIT release operation context bound")?;
    originals::object(arguments["durable_policy_binding"].get().as_bytes())?;
    let quotas: Vec<&RawValue> = serde_json::from_str(arguments["shared_quotas"].get()).map_err(|_| "JIT release quota list differs")?;
    ensure(quotas.len() <= 12, "JIT release quota count bound")?;
    for quota in quotas { originals::object(quota.get().as_bytes())?; }
    ensure((arguments["authority_policy_hash"].get() == "null" && arguments["authority_route_id"].get() == "null")
        || (arguments["authority_policy_hash"].get() == arguments["policy_hash"].get()
            && arguments["authority_route_id"].get() == arguments["route_id"].get()),
        "JIT release authority aliases differ")
}

pub(super) fn command_inputs(raw: &[u8]) -> Result<(ReleaseOriginals, Value), String> {
    ensure(raw.len() <= MAX_COMMAND, "JIT compound command bound")?;
    originals::structure(raw, 0, &mut 0)?;
    let values = originals::object(raw)?;
    originals::keys(&values, &["apiVersion", "phase", "runtimeInput", "publicRequest", "parentRequest",
        "issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs", "deadlineBoottimeNs", "challenge"])?;
    let original = read(values["runtimeInput"].get().as_bytes(), values["parentRequest"].get().as_bytes(),
        values["publicRequest"].get().as_bytes())?;
    let controls = values.iter().filter(|(key, _)| !["runtimeInput", "publicRequest", "parentRequest"].contains(&key.as_str()))
        .map(|(key, value)| Ok((key.clone(), document(value.get().as_bytes(), MAX_COMMAND)?)))
        .collect::<Result<serde_json::Map<String, Value>, String>>()?;
    Ok((original, Value::Object(controls)))
}

pub(super) fn validate_release_exchange(config: &Value, command: &[u8], response: &Value,
    now_wall: u64, now_boot: u64, broker_deadline: u64) -> Result<(), String> {
    let (original, controls) = command_inputs(command)?;
    validate_correlations(config, &original.child, &controls, Some(&original.parent), response,
        now_wall, now_boot, broker_deadline)
}
