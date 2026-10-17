//! One commissioned cold state, real durable DRS genesis, and independent CSA mirror.
//! A signature is never released before its exact original has been headed and
//! read back. Partial attempts remain closed; no absent-file recovery is state.
use super::*;
use super::common::DurableAppendJournal;
use super::ledger_spool_values::sha;
use super::publication_genesis::{self as fixed, require, invalid, Scope, InitialState, GenesisEvidence, Completion, Witness};
use super::spool_head_values::RoleKey;
use super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use crate::policy_shadow::AuthorityRole;
use std::os::unix::fs::{FileExt, MetadataExt};

pub(super) const RUNTIME: &str = "catchplate.policyCustodyServiceRuntimeConfig/v11";
pub(super) const API: &str = "catchplate.nativePublicationGenesisCommand/v1";
pub(super) const GRANT_FD: &str = "publication-genesis-grant";
pub(super) const DIRECTORY: &str = "publication-genesis-journal";
pub(super) const MAX_GRANT: usize = 256 * 1024;
const DOMAIN: &[u8] = b"catchplate.nativePublicationGenesisGrant.signature/v1";
const MAX_RECORD: usize = 2 * 1024 * 1024;
const MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Selection { pub(super) grant_fd_name: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) api_version: String, pub(super) purpose: String, pub(super) service_role: TrustedHostServiceRoleV3,
    pub(super) guest: guest::GuestClosureBinding, pub(super) runtime_configuration_sha256: Sha256Digest,
    pub(super) authority_history_manifest_sha256: Sha256Digest, pub(super) scope: Scope,
    pub(super) native: RoleKey, pub(super) retrieval: RoleKey, pub(super) initial_transition_head_sha256: Sha256Digest,
    pub(super) durable_authority_epoch: AuthorityEpochRefV3, pub(super) durable_public_key_base64url: String,
    pub(super) current_authority_epoch: AuthorityEpochRefV3, pub(super) current_public_key_base64url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Grant { pub(super) payload: Payload, pub(super) signature_base64url: String }
impl Grant {
    pub(super) fn verify(&self, history: &RuntimeAuthorityHistory) -> Result<(VerifyingKey, VerifyingKey), ServiceError> {
        let p = &self.payload; p.scope.guest(&p.guest)?;
        require(p.api_version == "catchplate.nativePublicationGenesisGrant/v1" && p.purpose == "native-cold-publication-genesis"
            && matches!(p.service_role, TrustedHostServiceRoleV3::DurableRecoveryStore | TrustedHostServiceRoleV3::CurrentSignatureAuthority)
            && p.guest.service_role == (if p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore { "durable-recovery-store" } else { "current-signature-authority" })
            && p.guest.uid > 0 && p.guest.gid > 0 && p.runtime_configuration_sha256 == p.guest.runtime_configuration_sha256
            && &p.authority_history_manifest_sha256 == history.manifest_sha256()
            && p.native.role == AuthorityRole::CustodyPublicationReconciliation && p.retrieval.role == AuthorityRole::CustodyRetrievalResponse
            && p.initial_transition_head_sha256 != Sha256Digest::compute(&[])
            && p.durable_authority_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore)
            && p.current_authority_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::CurrentSignatureAuthority))?;
        verify_signature(history.root_authority_key(), DOMAIN, &encode_canonical_frame(p)?, &self.signature_base64url)?;
        let durable = epoch_key(&p.durable_authority_epoch, &p.durable_public_key_base64url)?;
        let current = epoch_key(&p.current_authority_epoch, &p.current_public_key_base64url)?;
        let native = p.native.material()?; let retrieval = p.retrieval.material()?;
        let keys = [&durable, &current, &native, &retrieval];
        require(keys.iter().all(|key| *key != history.root_authority_key())
            && keys.iter().enumerate().all(|(i, key)| keys.iter().skip(i + 1).all(|other| key != other)))?;
        let own = history.current_epoch().map_err(|_| invalid())?;
        let (epoch, key) = if p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore {
            (&p.durable_authority_epoch, &durable)
        } else { (&p.current_authority_epoch, &current) };
        require(&own.epoch_reference() == epoch && own.service_signing_key() == key)?;
        Ok((durable, current))
    }
}
pub(super) fn epoch_key(epoch: &AuthorityEpochRefV3, raw: &str) -> Result<VerifyingKey, ServiceError> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    require(bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == raw)?;
    let key = VerifyingKey::from_bytes(&<[u8;32]>::try_from(bytes.as_slice()).map_err(|_| invalid())?).map_err(|_| invalid())?;
    require(verifying_key_spki_sha256(&key).map_err(|_| invalid())? == epoch.service_signing_key_spki_sha256)?; Ok(key)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="operation", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Action { Initialize, Finalize { completion: Completion }, Mirror { completion: Completion, durable: Witness } }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Command { pub(super) api_version: String, pub(super) scope: Scope, pub(super) action: Action }
impl Command {
    pub(super) fn deadline(&self) -> Result<u64, ServiceError> {
        require(self.api_version == API)?; self.scope.validate()?; Ok(self.scope.expires_at_boottime_nanos)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="publicationGenesisResult", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Reply { Genesis(GenesisEvidence), Finalized(Witness), Mirrored(Witness) }
pub(super) fn is_command(raw: &[u8]) -> Result<bool, ServiceError> {
    let value: serde_json::Value = decode_canonical_frame(raw)?;
    Ok(value.get("apiVersion").and_then(|v| v.as_str()) == Some(API))
}
pub(super) fn response_deadline(raw: &[u8], deadline: u64) -> Result<(), ServiceError> {
    let reply: Reply = decode_canonical_frame(raw)?;
    require(match reply { Reply::Genesis(value) => value.scope.expires_at_boottime_nanos == deadline
        && value.observed_at_boottime_nanos < deadline,
        Reply::Finalized(value) | Reply::Mirrored(value) => value.completed_at_boottime_nanos < deadline })
}

// The owner receives no caller-constructible signing input. Gate creates this
// only after the seed append/readback or after full final-original validation.
pub(super) struct SigningInput { kind: SigningKind }
enum SigningKind {
    Genesis { scope: Scope, grant: Sha256Digest, epoch: AuthorityEpochRefV3, now: u64 },
    Witness { scope: Scope, completion: Completion, predecessor: Sha256Digest, grant: Sha256Digest,
        epoch: AuthorityEpochRefV3, now: u64, mirrored: bool },
}
impl SigningInput {
    pub(super) fn sign(&self, key: &SigningKey) -> Result<Reply, ServiceError> {
        match &self.kind {
            SigningKind::Genesis { scope, grant, epoch, now } => Ok(Reply::Genesis(GenesisEvidence::sign(scope.clone(), grant.clone(), epoch.clone(), *now, key)?)),
            SigningKind::Witness { scope, completion, predecessor, grant, epoch, now, mirrored } => {
                let value = Witness::sign(scope, completion, predecessor.clone(), grant.clone(), epoch.clone(), *now, key)?;
                Ok(if *mirrored { Reply::Mirrored(value) } else { Reply::Finalized(value) })
            },
        }
    }
    pub(super) fn is_durable(&self) -> bool { !matches!(&self.kind, SigningKind::Witness { mirrored: true, .. }) }
}
pub(super) trait Owner: generation_service::Owner {
    fn sign_publication_genesis(&self, input: &SigningInput) -> Result<Reply, ServiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="stage", content="body", rename_all="kebab-case", deny_unknown_fields)]
enum Persisted { Seed(String), Released(Reply) }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Record { command: Command, grant_sha256: Sha256Digest, owner_state_sha256: Sha256Digest,
    predecessor_head_sha256: Sha256Digest, sequence: u64 }
struct Append { key: Sha256Digest, request: Vec<u8>, response: Vec<u8> }
pub(super) struct Gate {
    grant: Grant, grant_raw: Vec<u8>, grant_file: std::fs::File, history: RuntimeAuthorityHistory,
    durable_key: VerifyingKey, current_key: VerifyingKey, bootstrap: Bootstrap,
    worker: BoundedServiceWorker<Append, Vec<u8>>, records: Vec<(Record, Persisted)>,
    head: Sha256Digest, bytes: usize, poisoned: bool,
}
impl Gate {
    pub(super) fn open<T>(loaded: &LoadedConfig<T>, runtime: &RuntimeConfigHeaderV3, bootstrap: &Bootstrap,
        activation: &mut BTreeMap<String, OwnedFd>, role: TrustedHostServiceRoleV3) -> Result<Option<Self>, ServiceRunnerError> {
        let Some(selection) = &runtime.publication_genesis_admission else { return Ok(None); };
        require(runtime.api_version == RUNTIME && selection.grant_fd_name == GRANT_FD
            && matches!(role, TrustedHostServiceRoleV3::DurableRecoveryStore | TrustedHostServiceRoleV3::CurrentSignatureAuthority))?;
        bootstrap.check()?;
        let association = bootstrap.generation_association()?;
        let history = runtime.load_authority_history(&loaded.credentials, role)?;
        let grant_file = std::fs::File::from(take_activation_fd(activation, GRANT_FD)?);
        let grant_raw = read_grant(&grant_file)?; let grant: Grant = decode_canonical_frame(&grant_raw)?;
        let (durable_key, current_key) = grant.verify(&history)?;
        let history_raw = runtime.authority_history_original(&loaded.credentials)?;
        super::initial_history::require_genesis_guest(&history_raw, runtime, role, &grant.payload.guest)?;
        super::initial_history::require_genesis_window(&history_raw, runtime, role,
            grant.payload.scope.issued_at_boottime_nanos, grant.payload.scope.expires_at_boottime_nanos)?;
        require(grant.payload.service_role == role && grant.payload.guest == association.binding()
            && grant.payload.runtime_configuration_sha256 == loaded.exact_sha256
            && grant_file.metadata()?.uid() == grant.payload.guest.uid && grant_file.metadata()?.gid() == grant.payload.guest.gid)?;
        let directory = take_activation_fd(activation, DIRECTORY)?;
        validate_directory_capability(directory.as_fd(), DIRECTORY, runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal = DurableAppendJournal::from_directory_without_orphan_repair(directory, role, MAX_RECORD)?;
        let chain = journal.verified_complete_chain(3, MAX_BYTES)?;
        let mut recovered = Vec::new();
        for value in chain.records {
            let record: Record = decode_canonical_frame(&value.exact_request_bytes)?;
            require(value.idempotency_sha256 == sha(&(record.sequence, &record.command))?)?;
            recovered.push((record, decode_canonical_frame::<Persisted>(&value.exact_response_bytes)?));
        }
        let worker = BoundedServiceWorker::start("custody-publication-genesis", runtime.maximum_durability_worker_nanos,
            move |input: Append, fence: &BoundedDurabilityFence| {
                fence.require_open()?;
                let stored = journal.append_exact_exchange(input.key, &input.request, &input.response)?;
                fence.require_open()?; require(stored.exact_response_bytes() == input.response.as_slice())?;
                Ok(input.response)
            })?;
        let head = grant.payload.initial_transition_head_sha256.clone();
        let mut value = Self { grant, grant_raw, grant_file, history, durable_key, current_key, bootstrap: bootstrap.clone(),
            worker, records: Vec::new(), head, bytes: 4096, poisoned: false };
        value.check()?;
        for (record, response) in recovered { value.apply(record, response)?; }
        // An interrupted seed is not a completed initialization or permission
        // to make a second decision after process restart.
        require(value.records.is_empty() || matches!(value.records.last(), Some((_, Persisted::Released(_)))))?;
        Ok(Some(value))
    }
    fn check(&self) -> Result<(), ServiceError> {
        require(!self.poisoned)?; self.check_originals()
    }
    fn check_originals(&self) -> Result<(), ServiceError> {
        require(read_grant(&self.grant_file)? == self.grant_raw)?;
        self.bootstrap.check().map_err(|_| invalid())?;
        self.grant.payload.scope.live(boottime_now_nanos().map_err(|_| invalid())?)
    }
    fn completion(&self, value: &Completion) -> Result<(), ServiceError> {
        let p = &self.grant.payload;
        value.verify(&p.scope, &p.native, &p.retrieval, &p.durable_authority_epoch, &self.durable_key)
    }
    fn validate_command(&self, command: &Command) -> Result<(), ServiceError> {
        command.deadline()?; let p = &self.grant.payload;
        require(command.scope == p.scope)?;
        match &command.action {
            Action::Initialize => require(p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore),
            Action::Finalize { completion } => {
                require(p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore)?; self.completion(completion)?;
                require(matches!(self.records.get(1), Some((_, Persisted::Released(Reply::Genesis(value))))
                    if value == &completion.prepared.core.genesis))
            },
            Action::Mirror { completion, durable } => {
                require(p.service_role == TrustedHostServiceRoleV3::CurrentSignatureAuthority)?; self.completion(completion)?;
                durable.verify(&p.scope, completion, &sha(&completion.prepared.core.genesis)?, &p.durable_authority_epoch, &self.durable_key)
            },
        }
    }
    fn validate_record(&self, record: &Record, response: &Persisted) -> Result<(), ServiceError> {
        self.validate_command(&record.command)?;
        let p = &self.grant.payload; let own_sha = Sha256Digest::compute(&self.grant_raw);
        require(record.grant_sha256 == own_sha && record.owner_state_sha256 != Sha256Digest::compute(&[])
            && record.predecessor_head_sha256 == self.head && record.sequence == self.records.len() as u64 + 1
            && self.records.first().is_none_or(|(prior, _)| prior.owner_state_sha256 == record.owner_state_sha256))?;
        match response {
            Persisted::Seed(raw) => require(self.records.is_empty() && raw == &InitialState::original(&p.scope)?
                && matches!(record.command.action, Action::Initialize | Action::Mirror { .. })),
            Persisted::Released(Reply::Genesis(value)) => {
                require(self.records.len() == 1 && matches!(record.command.action, Action::Initialize)
                    && matches!(self.records.first(), Some((prior, Persisted::Seed(_))) if prior.command == record.command
                        && prior.owner_state_sha256 == record.owner_state_sha256)
                    && value.grant_sha256 == own_sha)?;
                value.verify(&p.scope, &p.durable_authority_epoch, &self.durable_key)
            },
            Persisted::Released(Reply::Finalized(value)) => {
                let Action::Finalize { completion } = &record.command.action else { return Err(invalid()); };
                require(self.records.len() == 2 && value.grant_sha256 == own_sha)?;
                value.verify(&p.scope, completion, &sha(&completion.prepared.core.genesis)?, &p.durable_authority_epoch, &self.durable_key)
            },
            Persisted::Released(Reply::Mirrored(value)) => {
                let Action::Mirror { completion, durable } = &record.command.action else { return Err(invalid()); };
                require(self.records.len() == 1 && value.grant_sha256 == own_sha
                    && matches!(self.records.first(), Some((prior, Persisted::Seed(_))) if prior.command == record.command
                        && prior.owner_state_sha256 == record.owner_state_sha256)
                    && value.completed_at_boottime_nanos >= durable.completed_at_boottime_nanos)?;
                value.verify(&p.scope, completion, &sha(durable)?, &p.current_authority_epoch, &self.current_key)
            },
        }
    }
    fn apply(&mut self, record: Record, response: Persisted) -> Result<(), ServiceError> {
        self.validate_record(&record, &response)?;
        let bytes = budget(encode_canonical_frame(&record)?.len(), encode_canonical_frame(&response)?.len())?;
        require(self.records.len() < 3 && self.bytes.checked_add(bytes).is_some_and(|n| n <= MAX_BYTES))?;
        self.head = sha(&(&record, &response))?; self.bytes += bytes; self.records.push((record, response)); Ok(())
    }
    fn append(&mut self, command: &Command, owner_state: &Sha256Digest, response: Persisted, owner: &impl Owner) -> Result<(), ServiceError> {
        self.check_originals()?;
        let deadline = command.deadline()?;
        let record = Record { command: command.clone(), grant_sha256: Sha256Digest::compute(&self.grant_raw),
            owner_state_sha256: owner_state.clone(), predecessor_head_sha256: self.head.clone(), sequence: self.records.len() as u64 + 1 };
        self.validate_record(&record, &response)?;
        let request = encode_canonical_frame(&record)?; let raw = encode_canonical_frame(&response)?;
        require(self.bytes.checked_add(budget(request.len(), raw.len())?).is_some_and(|n| n <= MAX_BYTES))?;
        let persisted = self.worker.execute(Append { key: sha(&(record.sequence, command))?, request, response: raw.clone() }, deadline).map_err(|_| invalid())?;
        require(persisted == raw && owner.generation_state(deadline)? == *owner_state
            && boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
        self.check_originals()?;
        self.apply(record, response)
    }
    pub(super) fn handle(&mut self, raw: &[u8], owner: &impl Owner) -> Result<Option<Vec<u8>>, ServiceError> {
        if !is_command(raw)? { return Ok(None); }
        self.check()?; require(raw.len() <= MAX_RECORD)?;
        let command: Command = decode_canonical_frame(raw)?; let deadline = command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_| invalid())?;
        self.validate_command(&command)?;
        let owner_state = owner.generation_state(deadline)?;
        for (record, response) in &self.records {
            if record.command == command {
                require(record.owner_state_sha256 == owner_state)?;
                if let Persisted::Released(reply) = response {
                    self.check()?; return Ok(Some(encode_canonical_frame(reply)?));
                }
            } else if std::mem::discriminant(&record.command.action) == std::mem::discriminant(&command.action) {
                return Err(invalid());
            }
        }
        let is_initialize = matches!(command.action, Action::Initialize);
        let is_mirror = matches!(command.action, Action::Mirror { .. });
        require(if is_initialize || is_mirror { self.records.is_empty() } else { self.records.len() == 2 })?;
        self.poisoned = true;
        if is_initialize || is_mirror {
            self.append(&command, &owner_state, Persisted::Seed(InitialState::original(&command.scope)?), owner)?;
        }
        let p = &self.grant.payload; let now = boottime_now_nanos().map_err(|_| invalid())?; p.scope.live(now)?;
        let own_grant = Sha256Digest::compute(&self.grant_raw);
        let kind = match &command.action {
            Action::Initialize => SigningKind::Genesis { scope: p.scope.clone(), grant: own_grant, epoch: p.durable_authority_epoch.clone(), now },
            Action::Finalize { completion } => SigningKind::Witness { scope: p.scope.clone(), completion: completion.clone(),
                predecessor: sha(&completion.prepared.core.genesis)?, grant: own_grant, epoch: p.durable_authority_epoch.clone(), now, mirrored: false },
            Action::Mirror { completion, durable } => SigningKind::Witness { scope: p.scope.clone(), completion: completion.clone(),
                predecessor: sha(durable)?, grant: own_grant, epoch: p.current_authority_epoch.clone(), now, mirrored: true },
        };
        self.check_originals()?;
        let reply = owner.sign_publication_genesis(&SigningInput { kind })?;
        self.append(&command, &owner_state, Persisted::Released(reply.clone()), owner)?;
        self.poisoned = false; self.check()?;
        Ok(Some(encode_canonical_frame(&reply)?))
    }
}
fn budget(request: usize, response: usize) -> Result<usize, ServiceError> {
    let decoded = request.checked_add(response).ok_or_else(invalid)?;
    require(request > 0 && response > 0 && decoded <= MAX_RECORD)?;
    decoded.checked_mul(3).and_then(|n| n.checked_add(4096)).ok_or_else(invalid)
}
fn verify_signature(key: &VerifyingKey, domain: &[u8], raw: &[u8], signature: &str) -> Result<(), ServiceError> {
    let bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    require(bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == signature)?;
    key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(domain, raw)?,
        &Signature::from_slice(&bytes).map_err(|_| invalid())?).map_err(|_| invalid())
}
fn read_grant(file: &std::fs::File) -> Result<Vec<u8>, ServiceError> {
    let m = file.metadata()?;
    require(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == 15 && m.is_file() && m.nlink() == 0
        && m.mode() & 0o7777 == 0o600 && m.len() > 0 && m.len() <= MAX_GRANT as u64)?;
    let mut raw = vec![0; m.len() as usize]; let mut offset = 0;
    while offset < raw.len() { let n = file.read_at(&mut raw[offset..], offset as u64)?; require(n > 0)?; offset += n; }
    Ok(raw)
}
