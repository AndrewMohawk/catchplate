//! Native measured holder: registration, local irreversible drain, and polling.
//! No database or network operation is introduced into the upstream send path.
//! Polling failure blocks locally; it never fabricates a remote acknowledgement.

use super::*;
use serverware_decision_gate::native_currentness_v1 as wire;
use std::collections::BTreeMap;

const PATH: &str = "/api/data-plane/credential-currentness";
const MAX_HOLDERS: usize = 64;
const MAX_REPLY: usize = 128 * 1024;

pub(super) struct LocalHolder {
    configuration: Option<wire::Configuration>,
    entries: Mutex<BTreeMap<(String, u64), Entry>>,
}

struct Entry {
    registration: Option<String>,
    blocked: bool,
    acknowledgement_attempted: bool,
}

// Constructors remain private to the measured gate's actual state transitions.
pub(super) struct PreparedEvidence { statement: wire::Statement }
impl PreparedEvidence {
    pub(super) fn statement(&self) -> &wire::Statement { &self.statement }
}
pub(super) struct PreparedLease<'a> {
    holder: String,
    epoch: u64,
    registration: String,
    request: &'a Value,
}
impl PreparedLease<'_> {
    pub(super) fn parts(&self) -> (&str, u64, &str, &Value) {
        (&self.holder, self.epoch, &self.registration, self.request)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Root {
    api_version: String, credential_id: String, credential_version: u64, epoch: u64,
    status: String, root_sha256: String, barrier_id: Option<String>,
    predecessor_barrier_sha256: Option<String>, origin_request_digest: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Holder {
    holder_id: String, boot_id: String, key_id: String, epoch: u64,
    registration_sha256: String, acknowledgement_sha256: Option<String>, status: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrozenHolder {
    holder_id: String, boot_id: String, key_id: String,
    control_plane_response_signing_key_id: String, registration_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BarrierOriginal {
    api_version: String, barrier_id: String, credential_id: String, credential_version: u64,
    epoch: u64, holders: Vec<FrozenHolder>, issued_at_epoch_ns: u64, expires_at_epoch_ns: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Barrier { original: BarrierOriginal, sha256: String, status: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Currentness { root: Root, challenge: Option<Value>, holder: Option<Holder>, barrier: Option<Barrier> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultWire {
    ok: bool, operation: String, request_digest: String, audit_event_digest: String,
    idempotent_replay: bool, currentness: Currentness,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation { api_version: String, currentness: Currentness }

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("credential currentness original/owner differs".to_owned()) }
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    native_response_profile::canonical_ascii_bytes(value)
}
fn response_value(bytes: &[u8]) -> Result<Value, String> {
    // HTTP responses need not use custody frame ordering. Reject duplicate
    // members before materializing them; never compare dump/request bytes.
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    StrictJsonValidateSeed.deserialize(&mut parser).map_err(|_| "currentness response JSON is invalid")?;
    parser.end().map_err(|_| "currentness response has trailing data")?;
    serde_json::from_slice(bytes).map_err(|_| "currentness response JSON is invalid".to_owned())
}
fn current_shape(value: &Value) -> Result<(), String> {
    let current = value.as_object().ok_or("currentness projection absent")?;
    require(current.len() == 4 && ["root", "challenge", "holder", "barrier"].iter().all(|key| current.contains_key(*key)))?;
    require(current["root"].as_object().is_some_and(|root| root.len() == 9
        && root.contains_key("barrierId") && root.contains_key("predecessorBarrierSha256")))?;
    if !current["holder"].is_null() {
        require(current["holder"].as_object().is_some_and(|holder| holder.len() == 7 && holder.contains_key("acknowledgementSha256")))?;
    }
    if !current["barrier"].is_null() {
        require(current["barrier"].as_object().is_some_and(|barrier| barrier.len() == 3
            && barrier.get("original").and_then(Value::as_object).is_some_and(|original| original.len() == 8)))?;
    }
    Ok(())
}
fn epoch_ns() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "currentness clock before epoch")?
        .as_nanos().try_into().map_err(|_| "currentness clock overflow".to_owned())
}
fn signer(state: &GateState) -> Result<&CustodyResponseProofSigner, String> {
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err("currentness requires its measured native gate".to_owned());
    };
    signer.transport.require_native()?;
    native_runtime_live(state)?;
    Ok(signer)
}
fn holder_id(state: &GateState) -> Result<String, String> {
    let signer = signer(state)?;
    wire::holder_id(&signer.boot_id, &signer.key_id)
}
fn operation_deadline(state: &GateState, original: Option<Instant>) -> Result<Instant, String> {
    let bound = Instant::now().checked_add(native_service_remaining(state)?
        .ok_or("currentness native lifetime absent")?.min(Duration::from_secs(30)))
        .ok_or("currentness deadline overflow")?;
    let deadline = original.map_or(bound, |original| original.min(bound));
    custody_deadline_remaining(deadline, "credential currentness")?;
    Ok(deadline)
}

impl LocalHolder {
    pub(super) fn new(configuration: Option<wire::Configuration>) -> Self {
        Self { configuration, entries: Mutex::new(BTreeMap::new()) }
    }
    pub(super) fn enabled(&self) -> bool { self.configuration.is_some() }
    pub(super) fn require_send(&self, id: &str, version: u64) -> Result<(), String> {
        if !self.enabled() { return Ok(()); }
        let entries = self.entries.lock().map_err(|_| "currentness registry poisoned")?;
        require(entries.get(&(id.to_owned(), version))
            .is_some_and(|entry| !entry.blocked && entry.registration.is_some()))
    }
    fn block(&self, id: &str, version: u64) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(&(id.to_owned(), version)) { entry.blocked = true; }
        }
    }
}

fn post(state: &GateState, snapshot: &Arc<Snapshot>, id: &str, version: u64,
    phase: &str, arguments: Value, deadline: Instant) -> Result<Currentness, String> {
    custody_deadline_remaining(deadline, "currentness request")?;
    signer(state)?;
    require(snapshot_is_active(state, snapshot) && policy_trust_is_fresh(state))?;
    let mut url = Url::parse(state.credential_lease_url.as_deref().ok_or("currentness lease URL absent")?)
        .map_err(|_| "currentness lease URL invalid")?;
    url.set_path(PATH);
    url.set_query(None);
    url.set_fragment(None);
    let mut nonce = [0u8; 32];
    ring_rand::SystemRandom::new().fill(&mut nonce).map_err(|_| "currentness response nonce unavailable")?;
    let nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let body = json!({"apiVersion":"serverware.credentialCurrentnessRequest/v1",
        "credentialId":id, "credentialVersion":version,
        "request":{"phase":phase,"arguments":arguments}});
    let timeout = custody_deadline_remaining(deadline, "currentness request")?.min(Duration::from_secs(3));
    let mut response = state.credential_lease_client.post(url.as_str())
        .header("X-Serverware-Data-Plane-Token", state.credential_lease_token.as_deref().ok_or("currentness token absent")?)
        .header("X-Serverware-Response-Nonce", &nonce).timeout(timeout).json(&body).send()
        .map_err(|_| "currentness request outcome is unknown")?;
    let status = response.status();
    let bytes = read_bounded_control_plane_response_body(&mut response, MAX_REPLY, "currentness response")?;
    verify_credential_lease_response(snapshot, url.as_str(), &nonce, status, response.headers(), &bytes)?;
    custody_deadline_remaining(deadline, "currentness response")?;
    require(status.is_success() && snapshot_is_active(state, snapshot) && policy_trust_is_fresh(state))?;
    let value = response_value(&bytes)?;
    current_shape(value.get("currentness").ok_or("currentness result projection absent")?)?;
    let current = if phase == "poll" {
        let reply: Observation = serde_json::from_value(value).map_err(|_| "currentness observation shape differs")?;
        require(reply.api_version == "serverware.credentialCurrentnessObservation/v1")?;
        reply.currentness
    } else {
        let reply: ResultWire = serde_json::from_value(value).map_err(|_| "currentness result shape differs")?;
        require(reply.ok && !reply.idempotent_replay
            && reply.operation == format!("credential.currentness.{phase}")
            && wire::digest(&reply.request_digest) && wire::digest(&reply.audit_event_digest))?;
        reply.currentness
    };
    require(current.root.api_version == "serverware.credentialCurrentnessRoot/v1"
        && current.root.credential_id == id && current.root.credential_version == version
        && current.root.epoch == version && wire::digest(&current.root.root_sha256)
        && wire::digest(&current.root.origin_request_digest)
        && current.root.predecessor_barrier_sha256.as_deref().map_or(true, wire::digest))?;
    Ok(current)
}

fn challenge(state: &GateState, snapshot: &Arc<Snapshot>, id: &str, version: u64,
    barrier: Option<&Barrier>, deadline: Instant) -> Result<PreparedEvidence, String> {
    let signer = signer(state)?;
    let configuration = state.credential_currentness.configuration.as_ref().ok_or("currentness profile absent")?;
    configuration.validate()?;
    let issued = epoch_ns()?;
    let remaining = custody_deadline_remaining(deadline, "currentness challenge")?;
    let expires = issued.checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| "currentness window overflow")?)
        .ok_or("currentness epoch overflow")?;
    let mut nonce = [0u8; 32];
    let mut uuid = [0u8; 16];
    let rng = ring_rand::SystemRandom::new();
    rng.fill(&mut nonce).map_err(|_| "currentness challenge unavailable")?;
    rng.fill(&mut uuid).map_err(|_| "currentness challenge ID unavailable")?;
    uuid[6] = (uuid[6] & 15) | 64; uuid[8] = (uuid[8] & 63) | 128;
    let hex = hex::encode(uuid);
    let challenge_id = format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]);
    let statement = wire::Statement {
        api_version: wire::SCHEMA.to_owned(), phase: if barrier.is_some() { "ack" } else { "register" }.to_owned(),
        holder_id: holder_id(state)?, boot_id: signer.boot_id.clone(), key_id: signer.key_id.clone(),
        control_plane_response_signing_key_id: signer.control_plane_response_signing_key_id.clone(),
        deployment_id: configuration.deployment_id.clone(), credential_id: id.to_owned(), credential_version: version,
        epoch: version, challenge_id, challenge: general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        barrier_id: barrier.map(|value| value.original.barrier_id.clone()),
        barrier_sha256: barrier.map(|value| value.sha256.clone()), policy_hash: snapshot.hash.clone(),
        data_plane_binary_sha256: state.binary_digest.clone(), issued_at_epoch_ns: issued,
        expires_at_epoch_ns: barrier.map_or(expires, |value| expires.min(value.original.expires_at_epoch_ns)),
    };
    statement.validate(epoch_ns()?)?;
    let request = json!({"phase":statement.phase,"holderId":statement.holder_id,
        "challengeId":statement.challenge_id,"challenge":statement.challenge,
        "barrierId":statement.barrier_id,"barrierSha256":statement.barrier_sha256,
        "issuedAtEpochNs":statement.issued_at_epoch_ns,"expiresAtEpochNs":statement.expires_at_epoch_ns});
    let reply = post(state, snapshot, id, version, "challenge", request.clone(), deadline)?;
    require(reply.challenge.as_ref() == Some(&request))?;
    Ok(PreparedEvidence { statement })
}

fn evidence(state: &GateState, prepared: &PreparedEvidence, deadline: Instant) -> Result<Value, String> {
    let signer = signer(state)?;
    custody_deadline_remaining(deadline, "currentness proof")?;
    let mut authority = state.mitm_authority.as_ref().ok_or("currentness identity absent")?
        .lock().map_err(|_| "currentness identity poisoned")?;
    let MitmAuthority::Native(identity) = &mut *authority else { return Err("currentness identity is not native".to_owned()); };
    let native_deadline = identity.deadline();
    let value = signer.transport.currentness_evidence(identity, prepared, native_deadline)?;
    custody_deadline_remaining(deadline, "currentness proof completion")?;
    require(canonical(&value)?.len() <= 32 * 1024)?;
    Ok(value)
}

fn ensure_registered(state: &GateState, snapshot: &Arc<Snapshot>, id: &str, version: u64,
    deadline: Instant) -> Result<(), String> {
    let key = (id.to_owned(), version);
    {
        let mut entries = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?;
        if let Some(entry) = entries.get(&key) { return require(!entry.blocked && entry.registration.is_some()); }
        require(entries.len() < MAX_HOLDERS)?;
        // A failed/uncertain registration is never retried in this holder boot.
        entries.insert(key.clone(), Entry { registration: None, blocked: false, acknowledgement_attempted: false });
    }
    let attempt = (|| {
        let prepared = challenge(state, snapshot, id, version, None, deadline)?;
        let original = evidence(state, &prepared, deadline)?;
        let digest = sha256_prefixed(&canonical(&original)?);
        let reply = post(state, snapshot, id, version, "register", json!({"evidence":original}), deadline)?;
        let holder = reply.holder.ok_or("registered holder result absent")?;
        require(reply.root.status == "open" && reply.root.barrier_id.is_none() && reply.barrier.is_none()
            && holder.holder_id == prepared.statement.holder_id && holder.boot_id == prepared.statement.boot_id
            && holder.key_id == prepared.statement.key_id && holder.epoch == version
            && holder.status == "registered" && holder.registration_sha256 == digest
            && holder.acknowledgement_sha256.is_none())?;
        let mut entries = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?;
        let entry = entries.get_mut(&key).ok_or("currentness registration disappeared")?;
        require(!entry.blocked && entry.registration.is_none())?;
        entry.registration = Some(digest);
        Ok(())
    })();
    if attempt.is_err() { state.credential_currentness.block(id, version); }
    attempt
}

/// Called after the existing native recipient quote has bound the original
/// inner request. Metadata does not register or confer secret release rights.
pub(super) fn wrap_request(state: &GateState, snapshot: &Arc<Snapshot>, scope: &CredentialLeaseScope,
    purpose: CredentialLeasePurpose, version: Option<u64>, inner: Value, original_deadline: Option<Instant>)
    -> Result<(Value, Option<Value>), String> {
    if !state.credential_currentness.enabled() { return Ok((inner, None)); }
    let deadline = operation_deadline(state, original_deadline)?;
    let currentness = if purpose == CredentialLeasePurpose::GenerationMetadata { Value::Null } else {
        let version = version.ok_or("currentness dispatch version absent")?;
        ensure_registered(state, snapshot, &scope.credential_id, version, deadline)?;
        let entries = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?;
        let entry = entries.get(&(scope.credential_id.clone(), version)).ok_or("currentness holder absent")?;
        require(!entry.blocked)?;
        let prepared = PreparedLease { holder: holder_id(state)?, epoch: version,
            registration: entry.registration.clone().ok_or("currentness registration absent")?, request: &inner };
        let signature = signer(state)?.transport.currentness_lease(&prepared)?;
        custody_deadline_remaining(deadline, "currentness recipient binding")?;
        json!({"holderId":prepared.holder,"epoch":version,"registrationSha256":prepared.registration,"signature":signature})
    };
    Ok((json!({"apiVersion":"serverware.nativeCurrentCredentialLeaseRequest/v1",
        "currentness":currentness,"leaseRequest":inner}), Some(currentness)))
}

pub(super) fn unwrap_response(state: &GateState, purpose: CredentialLeasePurpose, expected: &Option<Value>,
    body: &[u8]) -> Result<(Vec<u8>, Option<u64>), String> {
    if !state.credential_currentness.enabled() { require(expected.is_none())?; return Ok((body.to_vec(), None)); }
    let value = response_value(body)?;
    let object = value.as_object().ok_or("currentness envelope is not an object")?;
    require(object.len() == 3 && object.get("apiVersion").and_then(Value::as_str)
        == Some("serverware.nativeCurrentCredentialLeaseEnvelope/v1") && object.contains_key("envelope"))?;
    let currentness = object.get("currentness").ok_or("currentness envelope pin absent")?;
    let version = if purpose == CredentialLeasePurpose::GenerationMetadata {
        require(expected.as_ref() == Some(&Value::Null))?;
        let fields = currentness.as_object().ok_or("currentness metadata context absent")?;
        let version = fields.get("credentialVersion").and_then(Value::as_u64).ok_or("currentness metadata version absent")?;
        require(fields.len() == 3 && version > 0 && version <= i64::MAX as u64
            && fields.get("epoch").and_then(Value::as_u64) == Some(version)
            && fields.get("rootSha256").and_then(Value::as_str).is_some_and(wire::digest))?;
        Some(version)
    } else { require(expected.as_ref() == Some(currentness))?; None };
    Ok((canonical(&object["envelope"])?, version))
}

pub(super) fn poll_once(state: &GateState) -> Result<(), String> {
    if !state.credential_currentness.enabled() { return Ok(()); }
    let keys: Vec<_> = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?
        .iter().filter(|(_, entry)| entry.registration.is_some() && !entry.acknowledgement_attempted)
        .map(|(key, _)| key.clone()).collect();
    for (id, version) in keys {
        let attempt = poll_holder(state, &id, version);
        if attempt.is_err() { state.credential_currentness.block(&id, version); }
        // Poll reads may recur; register/ack mutations are each one-shot. A
        // blocked holder never resumes sends even if a later poll succeeds.
    }
    Ok(())
}

fn poll_holder(state: &GateState, id: &str, version: u64) -> Result<(), String> {
    let snapshot = current_snapshot(state);
    let deadline = operation_deadline(state, None)?;
    let local_id = holder_id(state)?;
    let reply = post(state, &snapshot, id, version, "poll", json!({"holderId":local_id}), deadline)?;
    let registration = {
        let entries = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?;
        entries.get(&(id.to_owned(), version)).and_then(|entry| entry.registration.clone()).ok_or("holder not registered")?
    };
    let observed = reply.holder.ok_or("currentness holder disappeared")?;
    require(observed.holder_id == local_id && observed.epoch == version && observed.registration_sha256 == registration)?;
    if reply.root.status == "open" {
        return require(reply.root.barrier_id.is_none() && reply.barrier.is_none() && observed.status == "registered");
    }
    state.credential_currentness.block(id, version);
    let barrier = reply.barrier.ok_or("currentness frozen barrier absent")?;
    let original = &barrier.original;
    require(reply.root.status == "quiescing" && barrier.status == "quiescing"
        && original.api_version == "serverware.credentialCurrentnessBarrier/v1"
        && original.credential_id == id && original.credential_version == version && original.epoch == version
        && reply.root.barrier_id.as_deref() == Some(original.barrier_id.as_str())
        && wire::uuid(&original.barrier_id) && original.holders.len() <= MAX_HOLDERS
        && original.holders.windows(2).all(|pair| pair[0].holder_id < pair[1].holder_id)
        && sha256_prefixed(&canonical(original)?) == barrier.sha256
        && original.issued_at_epoch_ns <= epoch_ns()? && epoch_ns()? < original.expires_at_epoch_ns)?;
    let signer = signer(state)?;
    require(original.holders.iter().filter(|holder| holder.holder_id == local_id
        && holder.registration_sha256 == registration && holder.boot_id == signer.boot_id
        && holder.key_id == signer.key_id
        && holder.control_plane_response_signing_key_id == signer.control_plane_response_signing_key_id).count() == 1)?;
    let remaining = original.expires_at_epoch_ns.checked_sub(epoch_ns()?).ok_or("barrier expired")?;
    let deadline = deadline.min(Instant::now().checked_add(Duration::from_nanos(remaining)).ok_or("barrier deadline overflow")?);
    // Prevent future sends first; this actual mutation then waits every permit
    // already dispatched and purges every principal/route scope for the epoch.
    let _drained = state.upstream_dispatch_authority.begin_mutation_on_deadline(deadline)?;
    state.credential_leases.lock().map_err(|_| "lease cache poisoned")?
        .retain(|_, lease| !(lease.scope.credential_id == id && lease.version == version));
    state.credential_generations.lock().map_err(|_| "generation cache poisoned")?
        .retain(|scope, generation| !(scope.credential_id == id && generation.version == version));
    {
        let mut entries = state.credential_currentness.entries.lock().map_err(|_| "currentness registry poisoned")?;
        let entry = entries.get_mut(&(id.to_owned(), version)).ok_or("currentness holder disappeared")?;
        require(entry.blocked && !entry.acknowledgement_attempted)?;
        entry.acknowledgement_attempted = true;
    }
    let prepared = challenge(state, &snapshot, id, version, Some(&barrier), deadline)?;
    let original = evidence(state, &prepared, deadline)?;
    let digest = sha256_prefixed(&canonical(&original)?);
    let reply = post(state, &snapshot, id, version, "ack", json!({"evidence":original}), deadline)?;
    let holder = reply.holder.ok_or("acknowledged holder result absent")?;
    require(holder.holder_id == local_id && holder.status == "acked" && holder.epoch == version
        && holder.registration_sha256 == registration && holder.acknowledgement_sha256.as_deref() == Some(digest.as_str()))
}
