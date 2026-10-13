//! Actual retained broker exchange for JIT storage, NOT caller admission.
//!
//! No public RPC or open/release operation is added here. The separate v26
//! native_jit_review_v1 owner admits its own cold configuration/assignment and
//! custody signer; this primitive alone grants none of that authority. `Prepared` records only
//! successful material preparation by this same retained process/identity; it
//! is unsigned and cannot be deserialized or constructed from supplied replies.
use super::*;
use base64::engine::general_purpose::URL_SAFE;
use std::collections::BTreeSet;

#[path = "jit_review_originals.rs"]
mod originals;
#[path = "jit_review_release.rs"]
mod release;
#[cfg(test)]
#[path = "jit_review_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "jit_review_release_tests.rs"]
mod release_tests;

const CHANNEL: &str = "serverware.nativeJitReviewChannel/v1";
const CONFIG: &str = "serverware.nativeJitReviewConfiguration/v1";
const MAX_COMMAND: usize = 512 * 1024;
const MAX_PLAINTEXT: usize = 256 * 1024;
const IDENTITY: &[&str] = &["holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest"];
const NATIVE_SCOPE: &[&str] = &["releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256"];
const BINDINGS: &[&str] = &["sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest",
    "deploymentId", "instanceId", "requestDigest", "operationId", "publicRequestSha256", "pairSha256",
    "secretKekId", "challenge", "issuedAtEpochNs", "expiresAtEpochNs", "documentExpiresAtEpochNs",
    "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "releaseRecordSha256", "policyHash",
    "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest"];

/// Pure bounded original-byte/graph correlation only. This cannot configure or
/// use a broker, create PreparedReleasePair, authenticate a caller, pin a source
/// contract, or authorize signing/retention. Parent numbers stay RawValue bytes;
/// the measured Python owner remains the complete canonical-number validator.
pub fn validate_release_jit_review_originals(runtime: &[u8], parent: &[u8], child: &[u8])
    -> Result<(), String> {
    release::read(runtime, parent, child).map(|_| ())
}

pub(crate) fn assignment_document(raw: &[u8]) -> Result<Value, String> { document(raw, 64 * 1024) }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Configuration {
    api_version: String, source_contract_digest: String, control_plane_configuration_digest: String,
    deployment_id: String, instance_id: String, secret_kek_id: String, attempt_capacity: u64,
}

impl Configuration {
    fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == CONFIG && (1..=16).contains(&self.attempt_capacity), "JIT cold profile differs")?;
        digest(&self.source_contract_digest)?; digest(&self.control_plane_configuration_digest)?;
        ensure(!self.deployment_id.is_empty() && self.deployment_id.len() <= 128
            && self.deployment_id.as_bytes()[0].is_ascii_alphanumeric()
            && self.deployment_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
            "JIT deployment scope differs")?;
        ensure(self.instance_id.starts_with("spiffe://") && self.instance_id.len() <= 4096
            && self.instance_id.chars().all(|c| c > ' ' && c != '\u{7f}'), "JIT instance scope differs")?;
        ensure(self.secret_kek_id.len() == 44 && self.secret_kek_id.starts_with("attested-memory-kek:")
            && self.secret_kek_id[20..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "JIT KEK spelling differs")
    }
}

pub(super) struct Configured {
    wire: Value, marker: Arc<()>, broker_deadline: u64, last_wall: u64, last_boot: u64,
    spent: BTreeSet<String>,
}

/// Plain request bounds, not a verified request or permission to seal.
pub(crate) struct SealWindow {
    pub issued_at_epoch_ns: u64, pub seal_expires_at_epoch_ns: u64,
    pub document_expires_at_epoch_ns: u64, pub challenge: String,
}

/// Only the actual exchange method below constructs this private-field value.
/// Its ciphertext/unsigned bindings are not native evidence or writer custody.
/// Its independent parent seal cap does not transfer the child's private
/// BOOTTIME sample or continue that completed child operation.
pub(crate) struct Prepared {
    pair: Value, bindings: Value, marker: Arc<()>, broker_deadline: u64, deadline: u64,
}
impl Prepared {
    pub(crate) fn pair(&self) -> &Value { &self.pair }
    pub(crate) fn statement_bindings(&self) -> &Value { &self.bindings }
}

/// Distinct compound storage preparation. Not a signature, caller admission,
/// approval, writer capability or permission to open either private document.
pub(crate) struct PreparedReleasePair { prepared: Prepared }
impl PreparedReleasePair {
    pub(crate) fn pair(&self) -> &Value { self.prepared.pair() }
    pub(crate) fn statement_bindings(&self) -> &Value { self.prepared.statement_bindings() }
}

fn text(value: &Value) -> Result<&str, String> { value.as_str().ok_or_else(|| "JIT text field differs".to_owned()) }
fn integer(value: &Value) -> Result<u64, String> {
    value.as_u64().filter(|n| *n > 0 && *n <= i64::MAX as u64).ok_or_else(|| "JIT integer bound differs".to_owned())
}
fn wall() -> Result<u64, String> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos()).ok()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64).ok_or_else(|| "JIT wall clock unavailable".to_owned())
}
// Freeze from one initial clock pair, with BOOTTIME sampled BEFORE wall time.
// Subsequent wall samples must never renew this independent monotonic cap.
// Further observations may only narrow a previously frozen cap. This is not
// reconstruction or transfer of the child's independently sampled deadline.
fn seal_deadline(initial_wall: u64, initial_boot: u64, seal_expires: u64,
    caller_deadline: u64, broker_deadline: u64) -> Result<u64, String> {
    ensure(initial_wall > 0 && initial_wall <= i64::MAX as u64 && initial_boot > 0
        && seal_expires > initial_wall && seal_expires <= i64::MAX as u64
        && caller_deadline <= broker_deadline, "JIT original seal clock bounds differ")?;
    let remaining = seal_expires.checked_sub(initial_wall).ok_or("JIT seal interval underflow")?;
    let seal_bound = initial_boot.checked_add(remaining).ok_or("JIT seal clock overflow")?;
    let maximum_bound = initial_boot.checked_add(30_000_000_000).ok_or("JIT seal ceiling overflow")?;
    let result = caller_deadline.min(broker_deadline).min(seal_bound).min(maximum_bound);
    ensure(initial_boot < result, "JIT original seal clock expired")?;
    Ok(result)
}
fn seal_live(issued: u64, expires: u64, deadline: u64, observed_wall: u64, observed_boot: u64)
    -> Result<(), String> {
    ensure(issued <= observed_wall && observed_wall < expires && observed_boot < deadline,
        "JIT prepared original wall or monotonic seal interval expired")
}
fn framed(domain: &str, frames: &[&[u8]]) -> String {
    let mut hash = Sha256::new(); hash.update(domain.as_bytes()); hash.update([0]);
    for frame in frames { hash.update((frame.len() as u64).to_be_bytes()); hash.update(frame); }
    format!("sha256:{}", hex::encode(hash.finalize()))
}
fn opaque_id(request: &str, purpose: &str) -> Result<String, String> {
    let hash = Sha256::digest(canonical_ascii_bytes(&json!({"schema":"serverware.policyAuthorityDeterministicIdentity/v1",
        "operation":"jit.request", "requestDigest":request, "purpose":purpose}))?);
    let mut bytes = [0u8; 16]; bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 15) | 0x50; bytes[8] = (bytes[8] & 63) | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}
fn padded(value: &Value, length: usize) -> Result<(), String> {
    let value = text(value)?;
    ensure(value.len() == length.div_ceil(3) * 4, "JIT ciphertext encoding bound")?;
    let raw = URL_SAFE.decode(value).map_err(|_| "JIT ciphertext encoding differs")?;
    ensure(raw.len() == length && URL_SAFE.encode(raw) == value, "JIT ciphertext is not canonical padded base64url")
}

fn configuration_wire(value: &Value) -> Result<(), String> {
    fields(value, &["apiVersion", "sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId",
        "instanceId", "secretKekId", "attemptCapacity", "identity"])?;
    let mut cold = value.as_object().ok_or("JIT configuration object")?.clone(); cold.remove("identity");
    let config: Configuration = serde_json::from_value(Value::Object(cold)).map_err(|_| "JIT configuration grammar")?;
    config.validate()?;
    let identity = &value["identity"]; fields(identity, IDENTITY)?;
    for field in IDENTITY.iter().filter(|field| **field != "bootId") { digest(text(&identity[*field])?)?; }
    ensure(identity["holderId"] == crate::native_currentness_v1::holder_id(text(&identity["bootId"])?, text(&identity["keyId"])?)?,
        "JIT holder binding differs")
}

fn request_scope(config: &Value, request: &Value) -> Result<(), String> {
    ensure(request["operationManifestDigest"] == config["sourceContractDigest"]
        && request["arguments"]["policy_hash"] == config["identity"]["policyHash"], "JIT cold request scope differs")
}

/// Pure correlation only, also used by recorded synthetic fixture controls.
/// It cannot create Prepared or authenticate a child, caller, key or clock.
fn validate_exchange(config: &Value, command: &[u8], response: &Value,
    now_wall: u64, now_boot: u64, broker_deadline: u64) -> Result<(), String> {
    let (original, control) = originals::command_inputs(command)?;
    validate_correlations(config, &original, &control, None, response, now_wall, now_boot, broker_deadline)
}

// Shared child/plaintext/owner joins. The optional parent comes only from the
// separate raw-original reconstruction, never from response-supplied claims.
fn validate_correlations(config: &Value, original: &originals::Originals, control: &Value,
    parent: Option<&release::ParentBindings>, response: &Value,
    now_wall: u64, now_boot: u64, broker_deadline: u64) -> Result<(), String> {
    configuration_wire(config)?;
    request_scope(config, &original.request)?;
    let (phase, response_phase, operation, pair_schema, scope_schema) = if parent.is_some() {
        ("seal-release-pair", "prepared-release-pair", "release.reserve",
            "serverware.nativeJitReviewPair/v2", "serverware.nativeJitReviewScope/v2")
    } else {
        ("seal-pair", "prepared", "jit.request",
            "serverware.nativeJitReviewPair/v1", "serverware.nativeJitReviewScope/v1")
    };
    ensure(control["apiVersion"] == CHANNEL && control["phase"] == phase, "JIT command purpose differs")?;
    crate::native_currentness_v1::bytes32(text(&control["challenge"])?)?;
    let issued = integer(&control["issuedAtEpochNs"])?;
    let requested_seal = integer(&control["sealExpiresAtEpochNs"])?;
    let requested_document = integer(&control["documentExpiresAtEpochNs"])?;
    let deadline = control["deadlineBoottimeNs"].as_u64().filter(|n| *n > 0).ok_or("JIT command deadline")?;
    let ttl = integer(&original.request["arguments"]["pending_ttl_seconds"])?;
    ensure(ttl <= 3600 && issued <= now_wall && now_wall < requested_seal && issued < requested_seal
        && requested_seal - issued <= 30_000_000_000 && requested_seal <= requested_document
        && requested_document <= issued.checked_add(ttl * 1_000_000_000).ok_or("JIT expiry overflow")?
        && now_boot < deadline && deadline <= broker_deadline, "JIT original interval differs")?;
    fields(response, &["apiVersion", "phase", "operation", "pair", "statementBindings"])?;
    ensure(response["apiVersion"] == CHANNEL && response["phase"] == response_phase && response["operation"] == operation,
        "JIT helper response purpose differs")?;
    let pair = &response["pair"]; fields(pair, &["schema", "scope", "keyId", "items"])?;
    ensure(pair["schema"] == pair_schema && pair["keyId"] == config["secretKekId"], "JIT pair profile differs")?;
    let scope = &pair["scope"];
    let mut scope_fields = vec!["schema", "publicRequest", "sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest",
        "issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs"];
    if parent.is_some() { scope_fields.push("parentRequestSha256"); }
    fields(scope, &scope_fields)?;
    let scope_digest = sha(&canonical_ascii_bytes(config)?);
    ensure(scope["schema"] == scope_schema && scope["publicRequest"] == original.request
        && scope["sourceContractDigest"] == config["sourceContractDigest"]
        && scope["controlPlaneConfigurationDigest"] == config["controlPlaneConfigurationDigest"]
        && scope["ownerScopeDigest"] == scope_digest && scope["issuedAtEpochNs"] == issued, "JIT pair scope differs")?;
    let seal = integer(&scope["sealExpiresAtEpochNs"])?;
    let document_expiry = integer(&scope["documentExpiresAtEpochNs"])?;
    // Child may only shorten requested wall limits. The retained independent
    // BOOTTIME bound remains mandatory; no wall-to-boot clock offset is invented.
    ensure(now_wall < seal && issued < seal && seal <= requested_seal && seal <= document_expiry
        && document_expiry <= requested_document, "JIT child extended or expired its original window")?;
    let items = pair["items"].as_array().filter(|items| items.len() == 2).ok_or("JIT pair item count")?;
    for (index, (kind, purpose)) in [("approval-secret-json/v1", "jit-canonical-request"),
        ("approval-review-json/v1", "jit-redacted-display")].iter().enumerate() {
        let item = &items[index];
        fields(item, &["opaqueId", "valueKind", "plaintextSha256", "plaintextBytes", "wrappedKeyNonce", "wrappedKey",
            "ciphertextNonce", "ciphertext"])?;
        let (expected_sha, length) = &original.plaintexts[index];
        ensure(*length > 0 && *length <= MAX_PLAINTEXT && item["plaintextSha256"] == *expected_sha
            && item["plaintextBytes"].as_u64() == Some(*length as u64) && item["valueKind"] == *kind
            && item["opaqueId"] == opaque_id(text(&original.request["requestDigest"])?, purpose)?, "JIT item original/domain differs")?;
        padded(&item["wrappedKeyNonce"], 12)?; padded(&item["wrappedKey"], 48)?;
        padded(&item["ciphertextNonce"], 12)?; padded(&item["ciphertext"], length + 16)?;
    }
    let bindings = &response["statementBindings"];
    let mut binding_fields = BINDINGS.to_vec();
    if let Some(parent) = parent {
        binding_fields.extend(["parentRequestSha256", "parentRequestDigest", "parentOperationId"]);
        ensure(scope["parentRequestSha256"] == parent.sha256
            && bindings["parentRequestSha256"] == parent.sha256
            && bindings["parentRequestDigest"] == parent.request_digest
            && bindings["parentOperationId"] == parent.operation_id, "JIT prepared parent correlation differs")?;
    }
    fields(bindings, &binding_fields)?;
    for field in IDENTITY { ensure(bindings[*field] == config["identity"][*field], "JIT native identity binding differs")?; }
    for field in ["sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "secretKekId"] {
        ensure(bindings[field] == config[field], "JIT configured binding differs")?;
    }
    ensure(bindings["ownerScopeDigest"] == scope_digest && bindings["requestDigest"] == original.request["requestDigest"]
        && bindings["operationId"] == original.request["operationId"]
        && bindings["publicRequestSha256"] == sha(&canonical_ascii_bytes(&original.request)?)
        && bindings["pairSha256"] == sha(&canonical_ascii_bytes(pair)?) && bindings["challenge"] == control["challenge"]
        && bindings["issuedAtEpochNs"] == issued && bindings["expiresAtEpochNs"] == seal
        && bindings["documentExpiresAtEpochNs"] == document_expiry, "JIT prepared correlation differs")
}

impl Owner {
    pub(crate) fn jit_review_marker(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        deadline: u64) -> Result<Arc<()>, String> {
        self.check_jit_identity(identity, deadline).map(|(_, marker, _, _)| marker)
    }
    pub(crate) fn poison_jit_review(&mut self) { self.poisoned = true; self.process.terminate(); }
    pub(crate) fn configure_jit_review(&mut self, config: Configuration, identity: &mut EnclaveRuntimeIdentityV1,
        boot: &str, key: &str, cp_key: &str, binary: &str, deadline: u64) -> Result<(), String> {
        let result = (|| {
            self.check(deadline)?; config.validate()?;
            let service = self.service_token_scope.as_ref().ok_or("JIT configuration requires completed service custody")?;
            ensure(self.jit_configuration.is_none() && !self.credential_phase_started
                && config.secret_kek_id == self.secret_kek_id && config.instance_id == service.instance_id
                && binary == service.binary_digest && identity.deadline() == self.deadline,
                "JIT cold configuration is not the original broker/service scope")?;
            identity.require_serving_privileges(self.serving.as_ref().ok_or("JIT serving owner absent")?, deadline)?;
            let mut scope = identity.refresh_scope(deadline)?;
            ensure(scope["policyHash"] == service.policy_hash
                && Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca, "JIT actual native identity differs")?;
            let object = scope.as_object_mut().ok_or("JIT native scope object")?;
            object.insert("holderId".to_owned(), json!(crate::native_currentness_v1::holder_id(boot, key)?));
            for (name, value) in [("bootId", boot), ("keyId", key), ("controlPlaneResponseSigningKeyId", cp_key),
                ("expectedBinaryDigest", binary)] { object.insert(name.to_owned(), json!(value)); }
            let mut wire = serde_json::to_value(config).map_err(|_| "JIT configuration encoding")?;
            wire["identity"] = scope; configuration_wire(&wire)?;
            let raw = canonical_ascii_bytes(&json!({"apiVersion":CHANNEL, "phase":"configure", "configuration":wire}))?;
            let response = document(&self.process.exchange(&raw, deadline)?, 4096)?;
            fields(&response, &["apiVersion", "phase"])?;
            ensure(response["apiVersion"] == CHANNEL && response["phase"] == "configured", "JIT child configuration failed")?;
            self.check(deadline)?;
            identity.verify_live(deadline)?;
            self.jit_configuration = Some(Configured { wire, marker: Arc::new(()), broker_deadline: self.deadline,
                last_wall: wall()?, last_boot: now()?, spent: BTreeSet::new() });
            Ok(())
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    fn check_jit_identity(&mut self, identity: &mut EnclaveRuntimeIdentityV1, deadline: u64)
        -> Result<(Value, Arc<()>, u64, u64), String> {
        self.check(deadline)?;
        let held = self.jit_configuration.as_ref().ok_or("JIT broker is not configured")?;
        ensure(held.broker_deadline == self.deadline && identity.deadline() == self.deadline
            && deadline <= self.deadline, "JIT original owner deadline differs")?;
        identity.require_serving_privileges(self.serving.as_ref().ok_or("JIT serving owner absent")?, deadline)?;
        let scope = identity.refresh_scope(deadline)?;
        for field in NATIVE_SCOPE { ensure(scope[*field] == held.wire["identity"][*field], "JIT retained native scope changed")?; }
        ensure(Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca
            && held.wire["secretKekId"] == self.secret_kek_id, "JIT retained CA/KEK changed")?;
        let boot = now()?; let wall = wall()?; let final_boot = now()?;
        ensure(wall >= held.last_wall && boot >= held.last_boot && final_boot >= boot && final_boot < deadline,
            "JIT original clocks expired or rolled back")?;
        let held = self.jit_configuration.as_mut().ok_or("JIT configuration disappeared")?;
        held.last_wall = wall; held.last_boot = final_boot;
        Ok((held.wire.clone(), Arc::clone(&held.marker), wall, boot))
    }

    /// Internal storage primitive only. Inputs are claims, not caller authority;
    /// no public route or signer can turn this result into admitted evidence.
    pub(crate) fn prepare_jit_review(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        runtime_original: &[u8], public_original: &[u8], window: SealWindow, deadline: u64) -> Result<Prepared, String> {
        self.prepare_jit_pair(identity, runtime_original, public_original, None, window, deadline)
    }

    pub(crate) fn prepare_release_jit_review(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        runtime_original: &[u8], parent_original: &[u8], public_original: &[u8],
        window: SealWindow, deadline: u64) -> Result<PreparedReleasePair, String> {
        self.prepare_jit_pair(identity, runtime_original, public_original, Some(parent_original), window, deadline)
            .map(|prepared| PreparedReleasePair { prepared })
    }

    fn prepare_jit_pair(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        runtime_original: &[u8], public_original: &[u8], parent_original: Option<&[u8]>,
        window: SealWindow, deadline: u64) -> Result<Prepared, String> {
        let result = (|| {
            let (config, marker, before_wall, before_boot) = self.check_jit_identity(identity, deadline)?;
            let original = if let Some(parent) = parent_original {
                release::read(runtime_original, parent, public_original)?.child
            } else { originals::read(runtime_original, public_original)? };
            request_scope(&config, &original.request)?;
            crate::native_currentness_v1::bytes32(&window.challenge)?;
            let request_digest = text(&original.request["requestDigest"])?.to_owned();
            let attempt_deadline = seal_deadline(before_wall, before_boot, window.seal_expires_at_epoch_ns,
                deadline, self.deadline)?;
            let phase = if parent_original.is_some() { "seal-release-pair" } else { "seal-pair" };
            let control = json!({"apiVersion":CHANNEL, "phase":phase, "challenge":window.challenge,
                "issuedAtEpochNs":window.issued_at_epoch_ns, "sealExpiresAtEpochNs":window.seal_expires_at_epoch_ns,
                "documentExpiresAtEpochNs":window.document_expires_at_epoch_ns, "deadlineBoottimeNs":attempt_deadline});
            let controls = control.as_object().ok_or("JIT control object")?.iter()
                .map(|(name, value)| Ok((name.clone(), canonical_ascii_bytes(value)?)))
                .collect::<Result<BTreeMap<String, Vec<u8>>, String>>()?;
            let mut fields: BTreeMap<&str, &[u8]> = controls.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
            fields.insert("runtimeInput", runtime_original); fields.insert("publicRequest", public_original);
            if let Some(parent) = parent_original { fields.insert("parentRequest", parent); }
            let command = originals::join(&fields)?;
            ensure(command.len() <= MAX_COMMAND && window.issued_at_epoch_ns <= before_wall
                && before_wall < window.seal_expires_at_epoch_ns && before_boot < attempt_deadline, "JIT command bound or interval differs")?;
            let held = self.jit_configuration.as_mut().ok_or("JIT configuration absent")?;
            ensure(held.spent.len() < integer(&config["attemptCapacity"])? as usize
                && held.spent.insert(request_digest), "JIT preparation attempt already spent or capacity exhausted")?;
            // Fence precedes the first byte. Only this actual retained exchange
            // can lead to Prepared; no supplied reply can call its constructor.
            let response = document(&self.process.exchange(&command, attempt_deadline)?, MAX_FRAME)?;
            let (_, same_marker, after_wall, after_boot) = self.check_jit_identity(identity, attempt_deadline)?;
            ensure(Arc::ptr_eq(&marker, &same_marker), "JIT preparation owner changed")?;
            if parent_original.is_some() {
                release::validate_release_exchange(&config, &command, &response, after_wall, after_boot, self.deadline)?;
            } else { validate_exchange(&config, &command, &response, after_wall, after_boot, self.deadline)?; }
            let expires = integer(&response["statementBindings"]["expiresAtEpochNs"])?;
            let prepared_deadline = seal_deadline(before_wall, before_boot, expires, attempt_deadline, self.deadline)?;
            // Optional one-way tightening, never renewal. The helper has
            // completed its operation; no exact child BOOTTIME is exported.
            let prepared_deadline = seal_deadline(after_wall, after_boot, expires, prepared_deadline, self.deadline)?;
            let (_, final_marker, final_wall, final_boot) = self.check_jit_identity(identity, prepared_deadline)?;
            ensure(Arc::ptr_eq(&marker, &final_marker), "JIT preparation owner changed during final validation")?;
            seal_live(window.issued_at_epoch_ns, expires, prepared_deadline, final_wall, final_boot)?;
            Ok(Prepared { pair: response["pair"].clone(), bindings: response["statementBindings"].clone(),
                marker, broker_deadline: self.deadline, deadline: prepared_deadline })
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    /// A future consumer must retain this same owner, not just copy ciphertext.
    /// This check still grants no signature, approval or plaintext-open right.
    pub(crate) fn check_jit_review_prepared(&mut self, identity: &mut EnclaveRuntimeIdentityV1, prepared: &Prepared)
        -> Result<(), String> {
        let result = (|| {
            let (_, marker, wall, boot) = self.check_jit_identity(identity, prepared.deadline)?;
            ensure(Arc::ptr_eq(&marker, &prepared.marker) && prepared.broker_deadline == self.deadline
                && prepared.bindings["pairSha256"] == sha(&canonical_ascii_bytes(&prepared.pair)?), "JIT prepared owner or original interval changed")?;
            seal_live(integer(&prepared.bindings["issuedAtEpochNs"] )?, integer(&prepared.bindings["expiresAtEpochNs"] )?,
                prepared.deadline, wall, boot)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    pub(crate) fn check_release_jit_review_prepared(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        prepared: &PreparedReleasePair) -> Result<(), String> {
        self.check_jit_review_prepared(identity, &prepared.prepared)
    }
}
