//! Cleanup owns permit issuance and one-use consumption, not the business
//! outcome. Only an independently signed native completion can request either.
//! No reply escapes before the exact exchange is synced and read back.
use super::*;
use super::active_effect_values::{self as effect, Barrier, Cleanup, Completion};
use super::common::DurableAppendJournal;
use super::ledger_spool_values::{invalid, sha};
use super::spool_head_values::require;
use super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as ResultBody, ProductionArtifactKindV4 as Kind,
    SignedProductionArtifactMaterialV4 as Material, SignedProductionServiceTransitionV4 as Transition};
use crate::policy_shadow::{hash_domain_frames, AuthorityRole as Role};
use std::os::unix::fs::{FileExt, MetadataExt};

pub(super) const RUNTIME: &str = "serverware.policyCustodyServiceRuntimeConfig/v8";
pub(super) const API: &str = "serverware.nativeActiveEffectCleanupCommand/v1";
pub(super) const GRANT_FD: &str = "active-effect-cleanup-grant";
pub(super) const DIRECTORY: &str = "active-effect-cleanup-journal";
const DOMAIN: &[u8] = b"serverware.nativeActiveEffectCleanupGrant.signature/v1";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection { pub(super) grant_fd_name: String }

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) api_version: String,
    pub(super) purpose: String,
    pub(super) guest: guest::GuestClosureBinding,
    pub(super) runtime_configuration_sha256: Sha256Digest,
    pub(super) authority_history_manifest_sha256: Sha256Digest,
    pub(super) head_grant_original: String,
    pub(super) durable_authority_epoch: AuthorityEpochRefV3,
    pub(super) durable_public_key_base64url: String,
    pub(super) initial_transition_head_sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Grant { pub(super) payload: Payload, pub(super) signature_base64url: String }

fn key(raw: &str) -> Result<VerifyingKey, ServiceError> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    require(bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == raw)?;
    VerifyingKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}
fn signature(raw: &str) -> Result<Signature, ServiceError> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    require(bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == raw)?;
    Signature::from_slice(&bytes).map_err(|_| invalid())
}
impl Grant {
    pub(super) fn verify(&self, history: &RuntimeAuthorityHistory)
        -> Result<(spool_head::Grant, VerifyingKey), ServiceError> {
        let p = &self.payload;
        require(p.api_version == "serverware.nativeActiveEffectCleanupGrant/v1"
            && p.purpose == "native-active-effect-cleanup"
            && p.guest.service_role == "cleanup-authorization-consumer"
            && p.runtime_configuration_sha256 == p.guest.runtime_configuration_sha256
            && &p.authority_history_manifest_sha256 == history.manifest_sha256()
            && p.head_grant_original.is_ascii() && !p.head_grant_original.is_empty()
            && p.head_grant_original.len() <= 65536
            && p.initial_transition_head_sha256 != Sha256Digest::compute(&[]))?;
        history.root_authority_key().verify_strict(
            &super::super::protocol::domain_separated_signature_preimage(DOMAIN, &encode_canonical_frame(p)?)?,
            &signature(&self.signature_base64url)?).map_err(|_| invalid())?;

        // The cleanup root independently authorizes this WHOLE original. It
        // does not pretend to be the DRS history/root or verify that history
        // with the cleanup history. Actual allocations require the pinned DRS
        // epoch/key and the digest of these exact head-grant bytes below.
        let head: spool_head::Grant = decode_canonical_frame(p.head_grant_original.as_bytes())?;
        let h = &head.payload;
        let effects = h.effects.as_ref().ok_or_else(invalid)?;
        let completed = h.completion.as_ref().ok_or_else(invalid)?;
        let own = history.current_epoch().map_err(|_| invalid())?;
        let durable = key(&p.durable_public_key_base64url)?;
        require(head.effects_selected() && head.completion_selected()
            && h.purpose == "native-shared-spool-head"
            && h.guest.service_role == "durable-recovery-store"
            && h.runtime_configuration_sha256 == h.guest.runtime_configuration_sha256
            && h.guest.uid != p.guest.uid
            && h.guest.boot_id_base64url == p.guest.boot_id_base64url
            && h.guest.time_namespace_device == p.guest.time_namespace_device
            && h.guest.time_namespace_inode == p.guest.time_namespace_inode
            && h.scope.issued_at_boottime_nanos > 0
            && h.scope.issued_at_boottime_nanos < h.scope.expires_at_boottime_nanos
            && h.scope.issued_at_boottime_nanos >= p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && h.scope.expires_at_boottime_nanos <= p.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && h.scope.issued_at_boottime_nanos >= h.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && h.scope.expires_at_boottime_nanos <= h.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && h.proof_scope_original.is_ascii() && !h.proof_scope_original.is_empty() && h.proof_scope_original.len() <= 16384
            && Sha256Digest::compute(h.proof_scope_original.as_bytes()) == h.scope.proof_scope_sha256
            && h.initial_transition_head_sha256 != Sha256Digest::compute(&[])
            && h.ingress.role == Role::CustodyIngressAdmission && h.ledger.role == Role::CustodyLedgerAppend
            && h.retrieval.role == Role::CustodyRetrievalResponse && completed.terminal.role == Role::CustodyTerminalAppend
            && (1..=32).contains(&completed.regular_append_capacity)
            && effects.dispatch_barrier.role == Role::CustodyDispatchBarrier
            && effects.active_effect_barrier.role == Role::CustodyActiveEffectBarrier
            && effects.active_effect_commit.role == Role::CustodyActiveEffectCommit
            && effects.cleanup_authority_epoch == own.epoch_reference()
            && effects.cleanup_key()? == *own.service_signing_key()
            && effects.cleanup_initial_transition_head_sha256 == p.initial_transition_head_sha256
            && p.durable_authority_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore)
            && verifying_key_spki_sha256(&durable).map_err(|_| invalid())? == p.durable_authority_epoch.service_signing_key_spki_sha256)?;
        let keys = [h.ingress.material()?, h.ledger.material()?, h.retrieval.material()?,
            h.origin_verifier.material()?, completed.terminal.material()?, effects.dispatch_barrier.material()?,
            effects.active_effect_barrier.material()?, effects.active_effect_commit.material()?, durable];
        require(keys.iter().enumerate().all(|(index, candidate)| keys[..index].iter().all(|prior| prior != candidate)
            && candidate != history.root_authority_key() && candidate != own.service_signing_key()))?;
        Ok((head, durable))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Command { pub(super) api_version: String, pub(super) completion: Completion }
impl Command {
    fn request(&self) -> &Dispatch { &self.completion.prepared.core.request }
    pub(super) fn deadline(&self) -> Result<u64, ServiceError> {
        require(self.api_version == API && effect::selected(self.request()))?;
        self.request().validate().map_err(|_| invalid())?;
        Ok(self.request().binding().operation_deadline_boottime_nanos)
    }
}
pub(super) fn is_command(raw: &[u8]) -> Result<bool, ServiceError> {
    let value: serde_json::Value = decode_canonical_frame(raw)?;
    Ok(value.get("apiVersion").and_then(|v| v.as_str()) == Some(API))
}

/// Fields and construction stay private to this gate. The real cleanup key
/// owner accepts this capability, never arbitrary payload/result bytes.
pub(super) struct Input {
    command: Command, epoch: AuthorityEpochRefV3, predecessor: Sha256Digest,
    nonce: Sha256Digest, completed: u64,
}
impl Input {
    pub(super) fn sign(&self, signing: &SigningKey) -> Result<Cleanup, ServiceError> {
        let completion = &self.command.completion;
        let result = if matches!(self.command.request(), Dispatch::AppendActiveEffectBarrier { .. }) {
            let (reference, exact_signed_artifact) = Material::sign_for_service(Kind::ActiveEffectPermit,
                HistoricalServiceRoleV3::CleanupAuthorizationConsumer, self.epoch.clone(), self.command.request().binding(),
                completion.prepared.core.trusted_time_checkpoint_sha256.clone(), self.nonce.clone(),
                completion.artifact.clone(), signing).map_err(|_| invalid())?;
            ResultBody::SealedArtifact { reference, exact_signed_artifact }
        } else { ResultBody::Artifact(completion.artifact.clone()) };
        let transition = Transition::sign(HistoricalServiceRoleV3::CleanupAuthorizationConsumer,
            self.epoch.clone(), self.command.request().binding(), self.predecessor.clone(),
            sha(&result)?, self.completed, signing).map_err(|_| invalid())?;
        Ok(Cleanup { result, transition })
    }
}
pub(super) trait Owner: generation_service::Owner {
    fn sign_active_effect_cleanup(&self, input: &Input) -> Result<Cleanup, ServiceError>;
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record { command: Command, grant_sha256: Sha256Digest, owner_state_sha256: Sha256Digest }
struct Append { key: Sha256Digest, request: Vec<u8>, response: Vec<u8> }
pub(super) struct Gate {
    grant: Grant, head_grant: spool_head::Grant, grant_raw: Vec<u8>, grant_file: std::fs::File,
    history: RuntimeAuthorityHistory, durable_key: VerifyingKey, bootstrap: Bootstrap,
    worker: BoundedServiceWorker<Append, Vec<u8>>, records: Vec<(Record, Cleanup)>,
    barriers: BTreeMap<Sha256Digest, Barrier>, consumed: BTreeSet<Sha256Digest>,
    head: Sha256Digest, bytes: usize, poisoned: bool,
}
impl Gate {
    pub(super) fn open<T>(loaded: &LoadedConfig<T>, runtime: &RuntimeConfigHeaderV3, bootstrap: &Bootstrap,
        activation: &mut BTreeMap<String, OwnedFd>) -> Result<Option<Self>, ServiceRunnerError> {
        let Some(selection) = &runtime.spool_cleanup else { return Ok(None); };
        require(runtime.api_version == RUNTIME && runtime.generation_admission.is_some()
            && runtime.dispatch_admission.is_none() && runtime.spool_head.is_none() && runtime.spool_current.is_none()
            && selection.grant_fd_name == GRANT_FD)?;
        bootstrap.check()?;
        let association = bootstrap.generation_association()?;
        let grant_file = std::fs::File::from(take_activation_fd(activation, GRANT_FD)?);
        let grant_raw = read_grant(&grant_file)?;
        let grant: Grant = decode_canonical_frame(&grant_raw)?;
        let history = runtime.load_authority_history(&loaded.credentials, TrustedHostServiceRoleV3::CleanupAuthorizationConsumer)?;
        let (head_grant, durable_key) = grant.verify(&history)?;
        require(grant.payload.guest == association.binding() && grant.payload.runtime_configuration_sha256 == loaded.exact_sha256
            && grant_file.metadata()?.uid() == grant.payload.guest.uid && grant_file.metadata()?.gid() == grant.payload.guest.gid)?;
        let directory = take_activation_fd(activation, DIRECTORY)?;
        validate_directory_capability(directory.as_fd(), DIRECTORY, runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal = DurableAppendJournal::from_directory_without_orphan_repair(directory,
            TrustedHostServiceRoleV3::CleanupAuthorizationConsumer, 4 * 1024 * 1024)?;
        let chain = journal.verified_complete_chain(MAX_RECORDS, MAX_BYTES)?;
        let mut recovered = Vec::new();
        for value in chain.records {
            let record: Record = decode_canonical_frame(&value.exact_request_bytes)?;
            require(value.idempotency_sha256 == sha(&record.command)?)?;
            recovered.push((record, decode_canonical_frame::<Cleanup>(&value.exact_response_bytes)?));
        }
        let worker = BoundedServiceWorker::start("custody-effect-cleanup", runtime.maximum_durability_worker_nanos,
            move |input: Append, fence: &BoundedDurabilityFence| {
                fence.require_open()?;
                let saved = journal.append_exact_exchange(input.key, &input.request, &input.response)?;
                fence.require_open()?;
                require(saved.exact_response_bytes() == input.response.as_slice())?;
                Ok(input.response)
            })?;
        let head = grant.payload.initial_transition_head_sha256.clone();
        let mut gate = Self { grant, head_grant, grant_raw, grant_file, history, durable_key, bootstrap: bootstrap.clone(),
            worker, records: Vec::new(), barriers: BTreeMap::new(), consumed: BTreeSet::new(), head, bytes: 0, poisoned: false };
        gate.check()?;
        for (record, reply) in recovered { gate.apply(record, reply)?; }
        Ok(Some(gate))
    }
    fn check(&self) -> Result<(), ServiceError> {
        let metadata = self.grant_file.metadata()?;
        require(!self.poisoned && read_grant(&self.grant_file)? == self.grant_raw
            && metadata.uid() == self.grant.payload.guest.uid && metadata.gid() == self.grant.payload.guest.gid)?;
        self.bootstrap.check().map_err(|_| invalid())?;
        self.grant.verify(&self.history)?;
        let now = boottime_now_nanos().map_err(|_| invalid())?;
        let scope = &self.head_grant.payload.scope;
        require(scope.issued_at_boottime_nanos <= now && now < scope.expires_at_boottime_nanos)
    }
    fn validate(&self, command: &Command) -> Result<Sha256Digest, ServiceError> {
        command.deadline()?;
        command.completion.verify(&self.head_grant)?;
        let core = &command.completion.prepared.core;
        let allocation = &core.allocation;
        let p = &allocation.payload;
        let binding = command.request().binding();
        allocation.validate(command.request(), &self.head_grant.payload.scope)?;
        require(p.service_grant_sha256 == Sha256Digest::compute(self.grant.payload.head_grant_original.as_bytes())
            && p.authority_epoch == self.grant.payload.durable_authority_epoch
            && core.proof_scope_sha256 == self.head_grant.payload.scope.proof_scope_sha256)?;
        self.durable_key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(
            effect::ALLOCATION_DOMAIN, &encode_canonical_frame(p)?)?, &signature(&allocation.signature_base64url)?)
            .map_err(|_| invalid())?;
        for (record, _) in &self.records {
            require(!super::completed_operation::relation(record.command.request().binding(), binding).map_err(|_| invalid())?)?;
        }
        let effect_id = p.preparation.effect_id_sha256().clone();
        match command.request() {
            Dispatch::AppendActiveEffectBarrier { .. } => require(!self.barriers.contains_key(&effect_id) && !self.consumed.contains(&effect_id))?,
            Dispatch::CommitActiveEffect { .. } | Dispatch::ReconcileActiveEffect { .. } => {
                let retained = self.barriers.get(&effect_id).ok_or_else(invalid)?;
                require(!self.consumed.contains(&effect_id) && p.barrier.as_ref() == Some(retained))?;
            },
            _ => return Err(invalid()),
        }
        Ok(effect_id)
    }
    fn apply(&mut self, record: Record, reply: Cleanup) -> Result<(), ServiceError> {
        require(record.grant_sha256 == Sha256Digest::compute(&self.grant_raw)
            && record.owner_state_sha256 != Sha256Digest::compute(&[]))?;
        let effect_id = self.validate(&record.command)?;
        reply.verify(&record.command.completion, &self.head_grant)?;
        require(reply.transition.predecessor_head_sha256 == self.head
            && record.command.completion.completed_at_boottime_nanos <= reply.transition.completed_at_boottime_nanos)?;
        let size = encode_canonical_frame(&(&record, &reply))?.len();
        let bytes = self.bytes.checked_add(size).ok_or_else(invalid)?;
        require(bytes <= MAX_BYTES && self.records.len() < MAX_RECORDS)?;
        if matches!(record.command.request(), Dispatch::AppendActiveEffectBarrier { .. }) {
            let barrier = Barrier { request: record.command.request().clone(), result: reply.result.clone() };
            barrier.wire()?;
            self.barriers.insert(effect_id, barrier);
        } else { self.consumed.insert(effect_id); }
        self.head = reply.transition.resulting_head_sha256.clone();
        self.bytes = bytes;
        self.records.push((record, reply));
        Ok(())
    }
    pub(super) fn handle(&mut self, raw: &[u8], owner: &impl Owner) -> Result<Option<Vec<u8>>, ServiceError> {
        if !is_command(raw)? { return Ok(None); }
        self.check()?;
        let command: Command = decode_canonical_frame(raw)?;
        let deadline = command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_| invalid())?;
        require(boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
        for (record, reply) in &self.records {
            if super::completed_operation::relation(record.command.request().binding(), command.request().binding()).map_err(|_| invalid())? {
                require(record.command == command && record.owner_state_sha256 == owner.generation_state(deadline)?)?;
                return Ok(Some(encode_canonical_frame(reply)?));
            }
        }
        self.validate(&command)?;
        let now = boottime_now_nanos().map_err(|_| invalid())?;
        require(command.completion.completed_at_boottime_nanos <= now && now < deadline && self.records.len() < MAX_RECORDS)?;
        let owner_state = owner.generation_state(deadline)?;
        let nonce = hash_domain_frames(b"serverware.nativeActiveEffectCleanupSlot/v1",
            &[&self.grant_raw, &encode_canonical_frame(&command)?, self.head.as_str().as_bytes()]);
        let reply = owner.sign_active_effect_cleanup(&Input { command: command.clone(),
            epoch: self.history.current_epoch().map_err(|_| invalid())?.epoch_reference(),
            predecessor: self.head.clone(), nonce, completed: boottime_now_nanos().map_err(|_| invalid())? })?;
        reply.verify(&command.completion, &self.head_grant)?;
        let record = Record { command, grant_sha256: Sha256Digest::compute(&self.grant_raw), owner_state_sha256: owner_state };
        let request = encode_canonical_frame(&record)?;
        let response = encode_canonical_frame(&reply)?;
        require(request.len() <= MAX_SERVICE_FRAME_BYTES && response.len() <= 4 * 1024 * 1024
            && self.bytes.checked_add(request.len() + response.len() + 4096).is_some_and(|size| size <= MAX_BYTES))?;
        // Any uncertain write/state change permanently fences this live owner.
        // A restarted owner refuses orphaned journal state; it cannot infer an
        // outcome from a deadline, missing reply or an uploaded barrier.
        self.poisoned = true;
        let persisted = self.worker.execute(Append { key: sha(&record.command)?, request, response: response.clone() }, deadline)
            .map_err(|_| invalid())?;
        require(persisted == response && record.owner_state_sha256 == owner.generation_state(deadline)?
            && boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
        self.apply(record, reply)?;
        self.poisoned = false;
        self.check()?;
        Ok(Some(response))
    }
}
fn read_grant(file: &std::fs::File) -> Result<Vec<u8>, ServiceError> {
    let metadata = file.metadata()?;
    require(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == 15 && metadata.is_file()
        && metadata.nlink() == 0 && metadata.mode() & 0o7777 == 0o600 && metadata.len() > 0 && metadata.len() <= 131072)?;
    let mut raw = vec![0; metadata.len() as usize];
    let mut offset = 0;
    while offset < raw.len() {
        let count = file.read_at(&mut raw[offset..], offset as u64)?;
        require(count > 0)?;
        offset += count;
    }
    Ok(raw)
}
