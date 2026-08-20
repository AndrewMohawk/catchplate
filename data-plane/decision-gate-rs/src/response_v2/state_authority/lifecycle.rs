use super::contract::{Digest, Identifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptState {
    Absent,
    Reserved,
    Authorized,
    Staged,
    Dispatching,
    OutcomeUnknown,
    Observed,
    TerminalFailed,
    ReleasePrepared,
    Finalized,
    Published,
    Archived,
}

impl AttemptState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "ABSENT",
            Self::Reserved => "RESERVED",
            Self::Authorized => "AUTHORIZED",
            Self::Staged => "STAGED",
            Self::Dispatching => "DISPATCHING",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Self::Observed => "OBSERVED",
            Self::TerminalFailed => "TERMINAL_FAILED",
            Self::ReleasePrepared => "RELEASE_PREPARED",
            Self::Finalized => "FINALIZED",
            Self::Published => "PUBLISHED",
            Self::Archived => "ARCHIVED",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::TerminalFailed | Self::Archived)
    }

    pub const fn allows_transition(self, successor: Self) -> bool {
        matches!(
            (self, successor),
            (Self::Absent, Self::Reserved)
                | (Self::Reserved, Self::Authorized)
                | (Self::Authorized, Self::Staged)
                | (Self::Staged, Self::Dispatching)
                | (Self::Dispatching, Self::Observed)
                | (Self::Dispatching, Self::OutcomeUnknown)
                | (Self::OutcomeUnknown, Self::Observed)
                | (Self::Observed, Self::ReleasePrepared)
                | (Self::ReleasePrepared, Self::Finalized)
                | (Self::Finalized, Self::Published)
                | (Self::Published, Self::Archived)
                | (Self::Reserved, Self::TerminalFailed)
                | (Self::Authorized, Self::TerminalFailed)
                | (Self::Staged, Self::TerminalFailed)
                | (Self::Dispatching, Self::TerminalFailed)
                | (Self::OutcomeUnknown, Self::TerminalFailed)
                | (Self::Observed, Self::TerminalFailed)
                | (Self::ReleasePrepared, Self::TerminalFailed)
                | (Self::Finalized, Self::TerminalFailed)
                | (Self::Published, Self::TerminalFailed)
        )
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum OperationKind {
    #[serde(rename = "responseV2.generation.install/v1")]
    GenerationInstall,
    #[serde(rename = "responseV2.generation.reconcile/v1")]
    GenerationReconcile,
    #[serde(rename = "responseV2.generation.ready/v1")]
    GenerationReady,
    #[serde(rename = "responseV2.attempt.reserve/v1")]
    AttemptReserve,
    #[serde(rename = "responseV2.attempt.authorize/v1")]
    AttemptAuthorize,
    #[serde(rename = "responseV2.object.commitRaw/v1")]
    ObjectCommitRaw,
    #[serde(rename = "responseV2.object.inspectImmutableRaw/v1")]
    ObjectInspectImmutableRaw,
    #[serde(rename = "responseV2.attempt.stage/v1")]
    AttemptStage,
    #[serde(rename = "responseV2.dispatch.begin/v1")]
    DispatchBegin,
    #[serde(rename = "responseV2.dispatch.recordOutcome/v1")]
    DispatchRecordOutcome,
    #[serde(rename = "responseV2.attempt.terminalize/v1")]
    AttemptTerminalize,
    #[serde(rename = "responseV2.attempt.finalize/v1")]
    AttemptFinalize,
    #[serde(rename = "responseV2.attempt.publish/v1")]
    AttemptPublish,
    #[serde(rename = "responseV2.release.consumeAndRetrieveExact/v1")]
    ReleaseConsumeAndRetrieveExact,
    #[serde(rename = "responseV2.release.resolveReplay/v1")]
    ReleaseResolveReplay,
    #[serde(rename = "responseV2.attempt.settle/v1")]
    AttemptSettle,
    #[serde(rename = "responseV2.attempt.archive/v1")]
    AttemptArchive,
    #[serde(rename = "responseV2.fence.revoke/v1")]
    FenceRevoke,
    #[serde(rename = "responseV2.fence.observeQuiescence/v1")]
    FenceObserveQuiescence,
    #[serde(rename = "responseV2.evidence.append/v1")]
    EvidenceAppend,
    #[serde(rename = "responseV2.publisher.enqueue/v1")]
    PublisherEnqueue,
    #[serde(rename = "responseV2.publisher.acknowledge/v1")]
    PublisherAcknowledge,
    #[serde(rename = "responseV2.transparency.checkpoint/v1")]
    TransparencyCheckpoint,
    #[serde(rename = "responseV2.trustedTime.advance/v1")]
    TrustedTimeAdvance,
    #[serde(rename = "responseV2.reconciliation.transition/v1")]
    ReconciliationTransition,
    #[serde(
        rename = "responseV2.reconciliation.terminalizeExpiredAttempt/v1"
    )]
    ReconciliationTerminalizeExpiredAttempt,
    #[serde(rename = "responseV2.state.query/v1")]
    StateQuery,
}

impl OperationKind {
    pub const fn is_generation_scoped(self) -> bool {
        matches!(
            self,
            Self::GenerationInstall
                | Self::GenerationReconcile
                | Self::GenerationReady
                | Self::StateQuery
        )
    }

    pub const fn permits_attempt_state(self, state: AttemptState) -> bool {
        match self {
            Self::GenerationInstall
            | Self::GenerationReconcile
            | Self::GenerationReady
            | Self::StateQuery => false,
            Self::AttemptReserve => matches!(state, AttemptState::Absent),
            Self::AttemptAuthorize => matches!(state, AttemptState::Reserved),
            Self::ObjectCommitRaw => matches!(
                state,
                AttemptState::Authorized
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
            ),
            Self::ObjectInspectImmutableRaw => matches!(
                state,
                AttemptState::Observed
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
            Self::AttemptStage => matches!(state, AttemptState::Authorized),
            Self::DispatchBegin => matches!(state, AttemptState::Staged),
            Self::DispatchRecordOutcome => matches!(
                state,
                AttemptState::Dispatching | AttemptState::OutcomeUnknown
            ),
            Self::AttemptTerminalize => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
            Self::AttemptFinalize => {
                matches!(state, AttemptState::ReleasePrepared)
            }
            Self::AttemptPublish => matches!(state, AttemptState::Finalized),
            Self::ReleaseConsumeAndRetrieveExact => {
                matches!(
                    state,
                    AttemptState::Observed
                        | AttemptState::Finalized
                        | AttemptState::Published
                )
            }
            Self::ReleaseResolveReplay => !matches!(state, AttemptState::Absent),
            Self::AttemptSettle => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
            Self::AttemptArchive => matches!(state, AttemptState::Published),
            Self::FenceRevoke => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
                    | AttemptState::TerminalFailed
            ),
            Self::FenceObserveQuiescence => {
                matches!(state, AttemptState::TerminalFailed)
            }
            Self::EvidenceAppend => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
            Self::PublisherEnqueue => matches!(
                state,
                AttemptState::Finalized | AttemptState::Published
            ),
            Self::PublisherAcknowledge => {
                matches!(state, AttemptState::Published)
            }
            Self::TransparencyCheckpoint => {
                matches!(state, AttemptState::Published)
            }
            Self::TrustedTimeAdvance => {
                matches!(state, AttemptState::Reserved)
            }
            Self::ReconciliationTransition => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
            Self::ReconciliationTerminalizeExpiredAttempt => matches!(
                state,
                AttemptState::Reserved
                    | AttemptState::Authorized
                    | AttemptState::Staged
                    | AttemptState::Dispatching
                    | AttemptState::OutcomeUnknown
                    | AttemptState::Observed
                    | AttemptState::ReleasePrepared
                    | AttemptState::Finalized
                    | AttemptState::Published
            ),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GenerationInstall => {
                "responseV2.generation.install/v1"
            }
            Self::GenerationReconcile => {
                "responseV2.generation.reconcile/v1"
            }
            Self::GenerationReady => "responseV2.generation.ready/v1",
            Self::AttemptReserve => "responseV2.attempt.reserve/v1",
            Self::AttemptAuthorize => {
                "responseV2.attempt.authorize/v1"
            }
            Self::ObjectCommitRaw => "responseV2.object.commitRaw/v1",
            Self::ObjectInspectImmutableRaw => {
                "responseV2.object.inspectImmutableRaw/v1"
            }
            Self::AttemptStage => "responseV2.attempt.stage/v1",
            Self::DispatchBegin => "responseV2.dispatch.begin/v1",
            Self::DispatchRecordOutcome => {
                "responseV2.dispatch.recordOutcome/v1"
            }
            Self::AttemptTerminalize => {
                "responseV2.attempt.terminalize/v1"
            }
            Self::AttemptFinalize => {
                "responseV2.attempt.finalize/v1"
            }
            Self::AttemptPublish => "responseV2.attempt.publish/v1",
            Self::ReleaseConsumeAndRetrieveExact => {
                "responseV2.release.consumeAndRetrieveExact/v1"
            }
            Self::ReleaseResolveReplay => {
                "responseV2.release.resolveReplay/v1"
            }
            Self::AttemptSettle => "responseV2.attempt.settle/v1",
            Self::AttemptArchive => "responseV2.attempt.archive/v1",
            Self::FenceRevoke => "responseV2.fence.revoke/v1",
            Self::FenceObserveQuiescence => {
                "responseV2.fence.observeQuiescence/v1"
            }
            Self::EvidenceAppend => "responseV2.evidence.append/v1",
            Self::PublisherEnqueue => {
                "responseV2.publisher.enqueue/v1"
            }
            Self::PublisherAcknowledge => {
                "responseV2.publisher.acknowledge/v1"
            }
            Self::TransparencyCheckpoint => {
                "responseV2.transparency.checkpoint/v1"
            }
            Self::TrustedTimeAdvance => {
                "responseV2.trustedTime.advance/v1"
            }
            Self::ReconciliationTransition => {
                "responseV2.reconciliation.transition/v1"
            }
            Self::ReconciliationTerminalizeExpiredAttempt => {
                "responseV2.reconciliation.terminalizeExpiredAttempt/v1"
            }
            Self::StateQuery => "responseV2.state.query/v1",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStatus {
    Prepared,
    Committed,
    Failed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FenceState {
    Active,
    Revoked,
    Quiescent,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetEffectState {
    Dispatching,
    OutcomeUnknown,
    Observed,
    ReconciledFailure,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationState {
    Pending,
    Running,
    Blocked,
    Complete,
    Failed,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationDomain {
    ProviderGenerations,
    RoleIdentities,
    Attempts,
    Operations,
    Fences,
    #[serde(rename = "REPLAY_LEDGERS")]
    ReplayLedger,
    #[serde(rename = "RELEASE_LEDGERS")]
    Releases,
    CredentialUses,
    TargetEffects,
    PolicyDecisions,
    Evidence,
    Finalizations,
    ImmutableObjects,
    ImmutableInspections,
    TerminalSettlements,
    Archives,
    PublisherOutbox,
    TransparencyLeaves,
    TransparencyCheckpoints,
    TrustedTimeHighwater,
}

impl ReconciliationDomain {
    pub const ALL: [Self; 20] = [
        Self::ProviderGenerations,
        Self::RoleIdentities,
        Self::Attempts,
        Self::Operations,
        Self::Fences,
        Self::ReplayLedger,
        Self::Releases,
        Self::CredentialUses,
        Self::TargetEffects,
        Self::PolicyDecisions,
        Self::Evidence,
        Self::Finalizations,
        Self::ImmutableObjects,
        Self::ImmutableInspections,
        Self::TerminalSettlements,
        Self::Archives,
        Self::PublisherOutbox,
        Self::TransparencyLeaves,
        Self::TransparencyCheckpoints,
        Self::TrustedTimeHighwater,
    ];
    pub const REQUIRED: [Self; 20] = Self::ALL;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderGenerations => "PROVIDER_GENERATIONS",
            Self::RoleIdentities => "ROLE_IDENTITIES",
            Self::Attempts => "ATTEMPTS",
            Self::Operations => "OPERATIONS",
            Self::Fences => "FENCES",
            Self::ReplayLedger => "REPLAY_LEDGERS",
            Self::Releases => "RELEASE_LEDGERS",
            Self::CredentialUses => "CREDENTIAL_USES",
            Self::TargetEffects => "TARGET_EFFECTS",
            Self::PolicyDecisions => "POLICY_DECISIONS",
            Self::Evidence => "EVIDENCE",
            Self::Finalizations => "FINALIZATIONS",
            Self::ImmutableObjects => "IMMUTABLE_OBJECTS",
            Self::ImmutableInspections => "IMMUTABLE_INSPECTIONS",
            Self::TerminalSettlements => "TERMINAL_SETTLEMENTS",
            Self::Archives => "ARCHIVES",
            Self::PublisherOutbox => "PUBLISHER_OUTBOX",
            Self::TransparencyLeaves => "TRANSPARENCY_LEAVES",
            Self::TransparencyCheckpoints => "TRANSPARENCY_CHECKPOINTS",
            Self::TrustedTimeHighwater => "TRUSTED_TIME_HIGHWATER",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutboxState {
    Pending,
    Delivering,
    Delivered,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableRecordKind {
    ProviderGeneration,
    RoleIdentity,
    Attempt,
    Operation,
    Fence,
    ReplayLedger,
    ReleaseLedger,
    CredentialUse,
    TargetEffect,
    PolicyDecision,
    Evidence,
    ImmutableInspection,
    Finalization,
    ImmutableObject,
    Archive,
    PublisherOutbox,
    TransparencyLeaf,
    TransparencyCheckpoint,
    TrustedTimeHighwater,
    ReconciliationJob,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptRecord {
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub revision: u64,
    pub state: AttemptState,
    pub fence_token: Identifier,
    pub stable_resume_id: Identifier,
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub deadline_clock: String,
    pub deadline_boot_id: Identifier,
    pub deadline_boot_millis: u64,
    pub request_sha256: Digest,
    pub created_at_epoch_millis: u64,
    pub updated_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationRecord {
    pub generation_id: Identifier,
    pub operation_id: Identifier,
    pub request_id: Identifier,
    pub attempt_id: Option<Identifier>,
    pub operation: OperationKind,
    pub exact_request_sha256: Digest,
    pub expected_revision: Option<u64>,
    pub expected_state: Option<AttemptState>,
    pub fence_token: Option<Identifier>,
    pub status: OperationStatus,
    pub canonical_signed_result_sha256: Option<Digest>,
    pub canonical_signed_result_base64url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FenceRecord {
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub fence_token: Identifier,
    pub allocation_sequence: u64,
    pub state: FenceState,
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub revoked_revision: Option<u64>,
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
    pub observation_evidence_sha256: Option<Digest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayLedgerRecord {
    pub generation_id: Identifier,
    pub replay_id: Identifier,
    pub operation_id: Identifier,
    pub exact_request_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationLedgerRecord {
    pub generation_id: Identifier,
    pub release_authorization_id: Identifier,
    pub attempt_id: Identifier,
    pub finalization_id: Identifier,
    pub exact_release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
    pub preauthorization_artifact_sha256: Digest,
    pub signed_state_mutation_receipt_sha256: Digest,
    pub release_preparation_receipt_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
    pub prepared_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseRetrievalLedgerRecord {
    pub generation_id: Identifier,
    pub retrieval_id: Identifier,
    pub release_authorization_id: Identifier,
    pub attempt_id: Identifier,
    pub finalization_id: Identifier,
    pub exact_replay_key_sha256: Digest,
    pub prepared_canonical_result_sha256: Digest,
    pub release_preparation_receipt_sha256: Digest,
    pub final_envelope_sha256: Digest,
    pub final_envelope_verification_sha256: Digest,
    pub release_object_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
    pub retrieved_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StableResumeRecord {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub stable_resume_id: Identifier,
    pub revision: u64,
    pub state: AttemptState,
    pub fence_token: Identifier,
    pub last_operation_id: Identifier,
    pub last_canonical_result_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "phase",
    content = "record",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ReleaseReplayRecord {
    Prepare(ReleasePreparationReplayRecord),
    Retrieve(ReleaseRetrievalReplayRecord),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationReplayRecord {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub release_authorization_id: Identifier,
    pub finalization_id: Identifier,
    pub exact_release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
    pub preauthorization_artifact_sha256: Digest,
    pub signed_state_mutation_receipt_sha256: Digest,
    pub release_preparation_receipt_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
    pub canonical_signed_result_base64url: String,
    pub prepared_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseRetrievalReplayRecord {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub release_authorization_id: Identifier,
    pub finalization_id: Identifier,
    pub exact_replay_key_sha256: Digest,
    pub prepared_canonical_result_sha256: Digest,
    pub release_preparation_receipt_sha256: Digest,
    pub final_envelope_sha256: Digest,
    pub final_envelope_verification_sha256: Digest,
    pub release_object_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
    pub canonical_signed_result_base64url: String,
    pub retrieved_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialUseRecord {
    pub generation_id: Identifier,
    pub credential_use_id: Identifier,
    pub attempt_id: Identifier,
    pub credential_binding_sha256: Digest,
    pub transport_authorization_sha256: Digest,
    pub target_effect_id: Identifier,
    pub state: TargetEffectState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetEffectRecord {
    pub generation_id: Identifier,
    pub target_effect_id: Identifier,
    pub attempt_id: Identifier,
    pub idempotency_key_sha256: Digest,
    pub state: TargetEffectState,
    pub request_object_sha256: Digest,
    pub response_object_sha256: Option<Digest>,
    pub transport_evidence_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDecisionRecord {
    pub generation_id: Identifier,
    pub policy_decision_id: Identifier,
    pub attempt_id: Identifier,
    pub policy_generation_sha256: Digest,
    pub raw_response_object_sha256: Option<Digest>,
    pub released_projection_sha256: Option<Digest>,
    pub verifier_evidence_sha256: Digest,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRecord {
    pub generation_id: Identifier,
    pub evidence_id: Identifier,
    pub attempt_id: Identifier,
    pub evidence_type: Identifier,
    pub producing_role_id: Identifier,
    pub canonical_artifact_sha256: Digest,
    pub object_sha256: Option<Digest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableInspectionRecord {
    pub generation_id: Identifier,
    pub inspection_operation_id: Identifier,
    pub attempt_id: Identifier,
    pub object_id: Identifier,
    pub object_sha256: Digest,
    pub object_length: u64,
    pub inspection_purpose_sha256: Digest,
    pub canonical_signed_result_sha256: Digest,
    pub canonical_signed_result_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizationRecord {
    pub generation_id: Identifier,
    pub finalization_id: Identifier,
    pub attempt_id: Identifier,
    pub attempt_revision: u64,
    pub fence_token: Identifier,
    pub canonical_final_envelope_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub transition_chain_sha256: Digest,
    pub evidence_root_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableObjectRecord {
    pub generation_id: Identifier,
    pub object_id: Identifier,
    pub attempt_id: Identifier,
    pub object_kind: Identifier,
    pub content_sha256: Digest,
    pub content_length: u64,
    pub media_type: String,
    pub storage_locator: String,
    pub immutable_storage_receipt_sha256: Digest,
    pub committed_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchiveRecord {
    pub generation_id: Identifier,
    pub archive_id: Identifier,
    pub attempt_id: Identifier,
    pub finalization_id: Identifier,
    pub canonical_archive_sha256: Digest,
    pub object_ids: Vec<Identifier>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublisherOutboxRecord {
    pub generation_id: Identifier,
    pub outbox_id: Identifier,
    pub attempt_id: Identifier,
    pub publication_id: Identifier,
    pub finalization_id: Identifier,
    pub payload_object_sha256: Digest,
    pub state: OutboxState,
    pub delivery_attempt: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencyLeafRecord {
    pub generation_id: Identifier,
    pub leaf_sequence: u64,
    pub leaf_sha256: Digest,
    pub predecessor_leaf_sha256: Option<Digest>,
    pub canonical_artifact_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransparencyCheckpointRecord {
    pub generation_id: Identifier,
    pub checkpoint_id: Identifier,
    pub tree_size: u64,
    pub root_sha256: Digest,
    pub predecessor_checkpoint_sha256: Option<Digest>,
    pub signed_checkpoint_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedTimeHighwaterRecord {
    pub generation_id: Identifier,
    pub clock_id: Identifier,
    pub epoch_millis: u64,
    pub sequence: u64,
    pub source_evidence_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciliationJobRecord {
    pub generation_id: Identifier,
    pub reconciliation_job_id: Identifier,
    pub attempt_id: Option<Identifier>,
    pub domain: ReconciliationDomain,
    pub state: ReconciliationState,
    pub authoritative_cursor: u64,
    pub blocker_code: Option<Identifier>,
    pub result_sha256: Option<Digest>,
}
