//! Separately admitted durable policy-publication state and independent mirror.
//! An empty journal means the signed baseline, never an invented genesis.
//! Only a definite exact append/readback releases a completion witness.
use super::*;
use super::common::DurableAppendJournal;
use super::ledger_spool_values::sha;
use super::publication::{Admission, Candidate, Proposal, Snapshot};
use super::publication_state::{State, invalid, require};
use super::spool_head_values::RoleKey;
use super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as ResultBody, SignedProductionServiceTransitionV4 as Transition,
    SignedProductionArtifactMaterialV4 as Material, ProductionArtifactKindV4 as Kind};
use std::os::unix::fs::{FileExt, MetadataExt};
use crate::policy_shadow::AuthorityRole;

pub(super) const RUNTIME: &str = "serverware.policyCustodyServiceRuntimeConfig/v10";
pub(super) const API: &str = "serverware.nativePublicationServiceCommand/v1";
pub(super) const GRANT_FD: &str = "publication-grant";
pub(super) const DIRECTORY: &str = "publication-journal";
pub(super) const MAX_GRANT: usize = 256 * 1024;
const DOMAIN: &[u8] = b"serverware.nativePublicationServiceGrant.signature/v1";
const MAX_RECORDS: usize = 128;
const MAX_RECORD: usize = 4 * 1024 * 1024;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Selection { pub(super) grant_fd_name: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) api_version: String,
    pub(super) purpose: String,
    pub(super) service_role: TrustedHostServiceRoleV3,
    pub(super) guest: guest::GuestClosureBinding,
    pub(super) runtime_configuration_sha256: Sha256Digest,
    pub(super) authority_history_manifest_sha256: Sha256Digest,
    pub(super) admission: Admission,
    pub(super) native: RoleKey,
    pub(super) retrieval: RoleKey,
    pub(super) initial_transition_head_sha256: Sha256Digest,
    pub(super) initial_durable_transition_head_sha256: Sha256Digest,
    pub(super) durable_authority_epoch: AuthorityEpochRefV3,
    pub(super) durable_public_key_base64url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Grant { pub(super) payload: Payload, pub(super) signature_base64url: String }

impl Grant {
    pub(super) fn verify(&self, history: &RuntimeAuthorityHistory) -> Result<VerifyingKey, ServiceError> {
        let p = &self.payload;
        require(p.api_version == "serverware.nativePublicationServiceGrant/v1"
            && p.purpose == "native-policy-publication-state"
            && matches!(p.service_role, TrustedHostServiceRoleV3::DurableRecoveryStore | TrustedHostServiceRoleV3::CurrentSignatureAuthority)
            && p.guest.service_role == match p.service_role {
                TrustedHostServiceRoleV3::DurableRecoveryStore => "durable-recovery-store", _ => "current-signature-authority" }
            && p.runtime_configuration_sha256 == p.guest.runtime_configuration_sha256
            && &p.authority_history_manifest_sha256 == history.manifest_sha256()
            && p.initial_transition_head_sha256 != Sha256Digest::compute(&[])
            && p.initial_durable_transition_head_sha256 != Sha256Digest::compute(&[])
            && p.durable_authority_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore)
            && p.admission.scope.issued_at_boottime_nanos >= p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && p.admission.scope.expires_at_boottime_nanos <= p.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && p.retrieval.role == AuthorityRole::CustodyRetrievalResponse)?;
        p.admission.validate(&p.native)?;
        verify_key_signature(history.root_authority_key(), DOMAIN, &encode_canonical_frame(p)?, &self.signature_base64url)?;
        let raw = URL_SAFE_NO_PAD.decode(&p.durable_public_key_base64url).map_err(|_| invalid())?;
        require(raw.len() == 32 && URL_SAFE_NO_PAD.encode(&raw) == p.durable_public_key_base64url)?;
        let durable = VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_| invalid())?).map_err(|_| invalid())?;
        require(verifying_key_spki_sha256(&durable)? == p.durable_authority_epoch.service_signing_key_spki_sha256)?;
        let native = p.native.material()?;
        let retrieval = p.retrieval.material()?;
        let current = history.current_epoch().map_err(|_| invalid())?;
        require(native != retrieval && native != durable && retrieval != durable
            && [&native, &retrieval, &durable].iter().all(|key| *key != history.root_authority_key())
            && native != *current.service_signing_key() && retrieval != *current.service_signing_key())?;
        if p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore {
            require(p.durable_authority_epoch == current.epoch_reference() && durable == *current.service_signing_key()
                && p.initial_transition_head_sha256 == p.initial_durable_transition_head_sha256)?;
        } else { require(durable != *current.service_signing_key())?; }
        Ok(durable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="operation", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Action {
    Snapshot { request: Dispatch },
    Commit { proposal: Proposal },
    Mirror { proposal: Proposal, durable: Witness },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Command { pub(super) api_version: String, pub(super) action: Action }
impl Command {
    pub(super) fn request(&self) -> &Dispatch { match &self.action {
        Action::Snapshot { request } => request,
        Action::Commit { proposal } | Action::Mirror { proposal, .. } => &proposal.prepared.core.request,
    } }
    pub(super) fn deadline(&self) -> Result<u64, ServiceError> {
        require(self.api_version == API)?;
        self.request().validate().map_err(|_| invalid())?;
        Ok(self.request().binding().operation_deadline_boottime_nanos)
    }
    fn proposal(&self) -> Result<&Proposal, ServiceError> { match &self.action {
        Action::Commit { proposal } | Action::Mirror { proposal, .. } => Ok(proposal), _ => Err(invalid()),
    } }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Witness { pub(super) result: ResultBody, pub(super) transition: Transition }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="publicationResult", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Reply { Snapshot(Snapshot), Witness(Witness) }
pub(super) fn is_command(raw: &[u8]) -> Result<bool, ServiceError> {
    let value: serde_json::Value = decode_canonical_frame(raw)?;
    Ok(value.get("apiVersion").and_then(|v| v.as_str()) == Some(API))
}
pub(super) fn response_deadline(raw: &[u8], deadline: u64) -> Result<(), ServiceError> {
    let reply: Reply = decode_canonical_frame(raw)?;
    require(match reply {
        Reply::Snapshot(v) => v.request.binding().operation_deadline_boottime_nanos == deadline
            && v.observed_at_boottime_nanos < deadline,
        Reply::Witness(v) => v.transition.completed_at_boottime_nanos < deadline,
    })
}

/// Only the admitted gate constructs these inputs; actual owners never expose
/// a general-purpose signature method to a caller or to public DTOs.
pub(super) struct SnapshotInput { request: Dispatch, native: Sha256Digest, state: State, epoch: AuthorityEpochRefV3, now: u64 }
impl SnapshotInput {
    pub(super) fn sign(&self, key: &SigningKey) -> Result<Snapshot, ServiceError> {
        Snapshot::sign(self.request.clone(), self.native.clone(), self.state.current_receipt_original.clone(),
            self.state.pending_prepared_original.clone(), self.epoch.clone(), self.now, key)
    }
}
pub(super) struct WitnessInput {
    proposal: Proposal, role: HistoricalServiceRoleV3, epoch: AuthorityEpochRefV3,
    predecessor: Sha256Digest, completed: u64, durable_result: Option<ResultBody>,
}
impl WitnessInput {
    pub(super) fn sign(&self, key: &SigningKey) -> Result<Witness, ServiceError> {
        let core = &self.proposal.prepared.core;
        let result = if let Some(result) = &self.durable_result { result.clone() } else {
            match &core.candidate {
                Candidate::ExistingReceipt | Candidate::Commit { .. } => {
                    let artifact = self.proposal.artifact.clone().ok_or_else(invalid)?;
                    let (reference, exact_signed_artifact) = Material::sign_for_service(Kind::PublicationReconciliationReceipt,
                        self.role, self.epoch.clone(), core.request.binding(), core.trust_checkpoint_sha256.clone(),
                        sha(&self.proposal)?, artifact, key).map_err(|_| invalid())?;
                    ResultBody::SealedArtifact { reference, exact_signed_artifact }
                },
                Candidate::Prepared(_) => ResultBody::Artifact(self.proposal.artifact.clone().ok_or_else(invalid)?),
                Candidate::Abort => ResultBody::Aborted { abort_evidence_sha256: core.identity()? },
            }
        };
        self.proposal.require_result(&result)?;
        let transition = Transition::sign(self.role, self.epoch.clone(), core.request.binding(), self.predecessor.clone(),
            sha(&result)?, self.completed, key).map_err(|_| invalid())?;
        Ok(Witness { result, transition })
    }
}
pub(super) trait Owner: generation_service::Owner {
    fn sign_publication_snapshot(&self, input: &SnapshotInput) -> Result<Snapshot, ServiceError>;
    fn sign_publication_witness(&self, input: &WitnessInput) -> Result<Witness, ServiceError>;
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Record { command: Command, grant_sha256: Sha256Digest, owner_state_sha256: Sha256Digest }
struct Append { key: Sha256Digest, request: Vec<u8>, response: Vec<u8> }
pub(super) struct Gate {
    grant: Grant, grant_raw: Vec<u8>, grant_file: std::fs::File, history: RuntimeAuthorityHistory,
    durable_key: VerifyingKey, bootstrap: Bootstrap, worker: BoundedServiceWorker<Append, Vec<u8>>,
    records: Vec<(Record, Witness)>, state: State, head: Sha256Digest, durable_head: Sha256Digest,
    bytes: usize, poisoned: bool,
}
impl Gate {
    pub(super) fn open<T>(loaded: &LoadedConfig<T>, runtime: &RuntimeConfigHeaderV3, bootstrap: &Bootstrap,
        activation: &mut BTreeMap<String, OwnedFd>, role: TrustedHostServiceRoleV3) -> Result<Option<Self>, ServiceRunnerError> {
        let Some(selection) = &runtime.publication_admission else { return Ok(None); };
        require(runtime.api_version == RUNTIME && selection.grant_fd_name == GRANT_FD
            && matches!(role, TrustedHostServiceRoleV3::DurableRecoveryStore | TrustedHostServiceRoleV3::CurrentSignatureAuthority))?;
        bootstrap.check()?;
        let association = bootstrap.generation_association()?;
        let history = runtime.load_authority_history(&loaded.credentials, role)?;
        let grant_file = std::fs::File::from(take_activation_fd(activation, GRANT_FD)?);
        let grant_raw = read_grant(&grant_file)?;
        let grant: Grant = decode_canonical_frame(&grant_raw)?;
        let durable_key = grant.verify(&history)?;
        require(grant.payload.service_role == role && grant.payload.guest == association.binding()
            && grant.payload.runtime_configuration_sha256 == loaded.exact_sha256
            && grant_file.metadata()?.uid() == grant.payload.guest.uid && grant_file.metadata()?.gid() == grant.payload.guest.gid)?;
        let directory = take_activation_fd(activation, DIRECTORY)?;
        validate_directory_capability(directory.as_fd(), DIRECTORY, runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal = DurableAppendJournal::from_directory_without_orphan_repair(directory, role, MAX_RECORD)?;
        let chain = journal.verified_complete_chain(MAX_RECORDS, MAX_BYTES)?;
        let mut recovered = Vec::new();
        for value in chain.records {
            let record: Record = decode_canonical_frame(&value.exact_request_bytes)?;
            require(value.idempotency_sha256 == sha(&record.command)?)?;
            let Reply::Witness(witness) = decode_canonical_frame(&value.exact_response_bytes)? else { return Err(invalid().into()); };
            recovered.push((record, witness));
        }
        let worker = BoundedServiceWorker::start("custody-publication-durability", runtime.maximum_durability_worker_nanos,
            move |input: Append, fence: &BoundedDurabilityFence| {
                fence.require_open()?;
                let record = journal.append_exact_exchange(input.key, &input.request, &input.response)?;
                fence.require_open()?;
                require(record.exact_response_bytes() == input.response.as_slice())?;
                Ok(input.response)
            })?;
        let state = State::admitted(&grant.payload.admission.prior_receipt_original)?;
        let head = grant.payload.initial_transition_head_sha256.clone();
        let durable_head = grant.payload.initial_durable_transition_head_sha256.clone();
        let mut value = Self { grant, grant_raw, grant_file, history, durable_key, bootstrap: bootstrap.clone(),
            worker, records: Vec::new(), state, head, durable_head, bytes: 4096, poisoned: false };
        value.check()?;
        for (record, witness) in recovered { value.apply(record, witness)?; }
        Ok(Some(value))
    }
    fn check(&self) -> Result<(), ServiceError> {
        require(!self.poisoned && read_grant(&self.grant_file)? == self.grant_raw)?;
        self.bootstrap.check().map_err(|_| invalid())?;
        let now = boottime_now_nanos().map_err(|_| invalid())?;
        let scope = &self.grant.payload.admission.scope;
        require(scope.issued_at_boottime_nanos <= now && now < scope.expires_at_boottime_nanos)
    }
    fn verify_durable_signature(&self, epoch: &AuthorityEpochRefV3, domain: &[u8], payload: &[u8], signature: &str)
        -> Result<(), &'static str> {
        if epoch != &self.grant.payload.durable_authority_epoch { return Err("publication durable epoch differs"); }
        verify_key_signature(&self.durable_key, domain, payload, signature).map_err(|_| "publication durable signature differs")
    }
    fn verify_result(&self, proposal: &Proposal, result: &ResultBody) -> Result<(), ServiceError> {
        proposal.require_result(result)?;
        if let ResultBody::SealedArtifact { reference, exact_signed_artifact } = result {
            let core = &proposal.prepared.core;
            require(exact_signed_artifact.authority_epoch == self.grant.payload.durable_authority_epoch
                && exact_signed_artifact.trust_checkpoint_sha256 == core.trust_checkpoint_sha256
                && exact_signed_artifact.custody_slot_nonce_sha256 == sha(proposal)?)?;
            exact_signed_artifact.validate_with_history(reference, core.request.binding(), Kind::PublicationReconciliationReceipt,
                HistoricalServiceRoleV3::DurableRecoveryStore,
                |epoch, domain, payload, signature| self.verify_durable_signature(epoch, domain, payload, signature))
                .map_err(|_| invalid())?;
        }
        Ok(())
    }
    fn validate(&self, command: &Command) -> Result<State, ServiceError> {
        command.deadline()?;
        let proposal = command.proposal()?;
        let p = &self.grant.payload;
        proposal.verify_with_key(&p.admission, &p.native, &p.retrieval, &p.durable_authority_epoch, &self.durable_key)?;
        for (record, _) in &self.records {
            require(!completed_operation::relation(record.command.request().binding(), command.request().binding()).map_err(|_| invalid())?)?;
        }
        // A reference is accepted only if this actual journal previously
        // released that exact DRS recovery seal for the still-current receipt.
        if let Dispatch::PrepareGenerationPublication { recovered, .. } = command.request() {
            require(self.records.iter().any(|(record, witness)| {
                matches!(record.command.request(), Dispatch::RecoverCurrentState { .. })
                    && matches!(&witness.result, ResultBody::SealedArtifact { reference, exact_signed_artifact }
                        if reference == recovered && exact_signed_artifact.artifact.exact_bytes().ok().as_deref()
                            == Some(self.state.current_receipt_original.as_bytes()))
            }))?;
        }
        match &command.action {
            Action::Commit { .. } => require(p.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore)?,
            Action::Mirror { durable, .. } => {
                require(p.service_role == TrustedHostServiceRoleV3::CurrentSignatureAuthority
                    && durable.transition.service_role == HistoricalServiceRoleV3::DurableRecoveryStore
                    && durable.transition.predecessor_head_sha256 == self.durable_head
                    && durable.transition.completed_at_boottime_nanos >= proposal.completed_at_boottime_nanos)?;
                self.verify_result(proposal, &durable.result)?;
                durable.transition.validate_with_history(command.request().binding(), &sha(&durable.result)?,
                    |epoch, domain, payload, signature| self.verify_durable_signature(epoch, domain, payload, signature))
                    .map_err(|_| invalid())?;
            },
            Action::Snapshot { .. } => return Err(invalid()),
        }
        self.state.next(proposal)
    }
    fn verify_witness(&self, record: &Record, witness: &Witness) -> Result<State, ServiceError> {
        require(record.grant_sha256 == Sha256Digest::compute(&self.grant_raw)
            && record.owner_state_sha256 != Sha256Digest::compute(&[]))?;
        let next = self.validate(&record.command)?;
        let proposal = record.command.proposal()?;
        self.verify_result(proposal, &witness.result)?;
        let transition = &witness.transition;
        require(transition.service_role == historical_service_role(self.grant.payload.service_role)
            && transition.authority_epoch == self.history.current_epoch().map_err(|_| invalid())?.epoch_reference()
            && transition.predecessor_head_sha256 == self.head
            && transition.completed_at_boottime_nanos >= proposal.completed_at_boottime_nanos)?;
        if let Action::Mirror { durable, .. } = &record.command.action {
            require(witness.result == durable.result && transition.completed_at_boottime_nanos >= durable.transition.completed_at_boottime_nanos)?;
        }
        transition.validate_with_history(record.command.request().binding(), &sha(&witness.result)?,
            |epoch, domain, payload, signature| self.history.verify_service_signature(epoch, domain, payload, signature)
                .map_err(|_| "publication service signature differs")).map_err(|_| invalid())?;
        Ok(next)
    }
    fn apply(&mut self, record: Record, witness: Witness) -> Result<(), ServiceError> {
        let next = self.verify_witness(&record, &witness)?;
        let transition = &witness.transition;
        let request_len = encode_canonical_frame(&record)?.len();
        let response_len = encode_canonical_frame(&Reply::Witness(witness.clone()))?.len();
        let bytes = record_budget(request_len, response_len)?;
        let total = self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        require(total <= MAX_BYTES && self.records.len() < MAX_RECORDS)?;
        self.durable_head = match &record.command.action {
            Action::Mirror { durable, .. } => durable.transition.resulting_head_sha256.clone(),
            _ => transition.resulting_head_sha256.clone(),
        };
        self.head = transition.resulting_head_sha256.clone();
        self.state = next;
        self.bytes = total;
        self.records.push((record, witness));
        Ok(())
    }
    pub(super) fn handle(&mut self, raw: &[u8], owner: &impl Owner) -> Result<Option<Vec<u8>>, ServiceError> {
        if !is_command(raw)? { return Ok(None); }
        self.check()?;
        require(raw.len() <= MAX_RECORD)?;
        let command: Command = decode_canonical_frame(raw)?;
        let deadline = command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_| invalid())?;
        self.grant.payload.admission.request(command.request())?;
        require(boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
        for (record, witness) in &self.records {
            if completed_operation::relation(record.command.request().binding(), command.request().binding()).map_err(|_| invalid())? {
                require(record.owner_state_sha256 == owner.generation_state(deadline)?)?;
                if let Action::Snapshot { request } = &command.action {
                    require(self.grant.payload.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore && request == record.command.request())?;
                    return Ok(Some(encode_canonical_frame(&Reply::Snapshot(record.command.proposal()?.prepared.core.snapshot.clone()))?));
                }
                require(record.command == command)?;
                return Ok(Some(encode_canonical_frame(&Reply::Witness(witness.clone()))?));
            }
        }
        let owner_state = owner.generation_state(deadline)?;
        if let Action::Snapshot { request } = &command.action {
            require(self.grant.payload.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore)?;
            let snapshot = owner.sign_publication_snapshot(&SnapshotInput { request: request.clone(), native: self.grant.payload.native.grant_sha256.clone(),
                state: self.state.clone(), epoch: self.grant.payload.durable_authority_epoch.clone(), now: boottime_now_nanos().map_err(|_| invalid())? })?;
            snapshot.verify_with_key(&self.grant.payload.durable_authority_epoch, &self.durable_key)?;
            self.state.require_snapshot(&snapshot)?;
            let response = encode_canonical_frame(&Reply::Snapshot(snapshot))?;
            require(response.len() <= MAX_RECORD && owner_state == owner.generation_state(deadline)?
                && boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
            return Ok(Some(response));
        }
        self.validate(&command)?;
        require(self.records.len() < MAX_RECORDS)?;
        self.poisoned = true;
        let proposal = command.proposal()?;
        let completed = boottime_now_nanos().map_err(|_| invalid())?;
        require(proposal.completed_at_boottime_nanos <= completed && completed < deadline)?;
        let durable_result = match &command.action { Action::Mirror { durable, .. } => Some(durable.result.clone()), _ => None };
        let witness = owner.sign_publication_witness(&WitnessInput { proposal: proposal.clone(),
            role: historical_service_role(self.grant.payload.service_role), epoch: self.history.current_epoch().map_err(|_| invalid())?.epoch_reference(),
            predecessor: self.head.clone(), completed, durable_result })?;
        let record = Record { command, grant_sha256: Sha256Digest::compute(&self.grant_raw), owner_state_sha256: owner_state };
        self.verify_witness(&record, &witness)?;
        let request = encode_canonical_frame(&record)?;
        let response = encode_canonical_frame(&Reply::Witness(witness.clone()))?;
        require(self.bytes.checked_add(record_budget(request.len(), response.len())?).is_some_and(|v| v <= MAX_BYTES))?;
        let persisted = self.worker.execute(Append { key: sha(&record.command)?, request, response: response.clone() }, deadline).map_err(|_| invalid())?;
        require(persisted == response && record.owner_state_sha256 == owner.generation_state(deadline)?
            && boottime_now_nanos().map_err(|_| invalid())? < deadline)?;
        self.apply(record, witness)?;
        self.poisoned = false;
        self.check()?;
        Ok(Some(response))
    }
}

fn record_budget(request: usize, response: usize) -> Result<usize, ServiceError> {
    let decoded = request.checked_add(response).ok_or_else(invalid)?;
    require(request > 0 && response > 0 && decoded <= MAX_RECORD)?;
    // Recovery retains encoded journal bytes and both decoded originals. This
    // upper bound includes base64 expansion, metadata, and the bounded head.
    decoded.checked_mul(3).and_then(|v| v.checked_add(4096)).ok_or_else(invalid)
}

fn verify_key_signature(key: &VerifyingKey, domain: &[u8], payload: &[u8], signature: &str) -> Result<(), ServiceError> {
    let raw = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    require(raw.len() == 64 && URL_SAFE_NO_PAD.encode(&raw) == signature)?;
    key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(domain, payload)?,
        &Signature::from_slice(&raw).map_err(|_| invalid())?).map_err(|_| invalid())
}
fn read_grant(file: &std::fs::File) -> Result<Vec<u8>, ServiceError> {
    let metadata = file.metadata()?;
    require(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == 15 && metadata.is_file()
        && metadata.nlink() == 0 && metadata.mode() & 0o7777 == 0o600 && metadata.len() > 0 && metadata.len() <= MAX_GRANT as u64)?;
    let mut raw = vec![0; metadata.len() as usize];
    let mut offset = 0;
    while offset < raw.len() { let n = file.read_at(&mut raw[offset..], offset as u64)?; require(n > 0)?; offset += n; }
    Ok(raw)
}
