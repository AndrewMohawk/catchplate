use serde::{Deserialize, Serialize};

use crate::response_observation_v2_api::V2MonotonicDeadlineV1;

use super::super::protocol::LifecycleTransitionV1;

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum StateCollectionV1 {
    ProviderGenerations,
    RoleIdentities,
    Attempts,
    Operations,
    Fences,
    ReplayLedger,
    ReleaseLedger,
    CredentialUses,
    TargetEffects,
    PolicyDecisions,
    Evidence,
    Finalizations,
    Objects,
    Archives,
    PublisherOutbox,
    TransparencyLeaves,
    TransparencyCheckpoints,
    TrustedTimeHighWater,
    ReconciliationJobs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityMutationV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub collection: StateCollectionV1,
    pub entity_key: String,
    pub expected_revision: u64,
    pub expected_state: String,
    pub expected_state_sha256: String,
    pub fencing_token: u64,
    pub transition: LifecycleTransitionV1,
    pub mutation_sha256: String,
    pub canonical_mutation: serde_json::Value,
    pub deadline: V2MonotonicDeadlineV1,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum AuthorityResultKindV1 {
    Applied,
    AlreadyApplied,
    Conflict,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityResultV1 {
    pub kind: AuthorityResultKindV1,
    pub operation_id: String,
    pub idempotency_key: String,
    pub stable_resume_id: String,
    pub authority_sequence: u64,
    pub collection: StateCollectionV1,
    pub entity_key: String,
    pub authoritative_revision: u64,
    pub authoritative_state: String,
    pub authoritative_state_sha256: String,
    pub fencing_token: u64,
    pub canonical_result_sha256: String,
    pub canonical_result: AuthorityPayloadV1,
    pub committed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "resultType",
    content = "result",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub(crate) enum AuthorityPayloadV1 {
    MutationCommitted {
        transition: LifecycleTransitionV1,
        terminal_record_sha256: String,
    },
    FenceAllocated {
        fencing_token: u64,
        owner_sha256: String,
    },
    FenceRevoked {
        fencing_token: u64,
        revocation_record_sha256: String,
    },
    QuiescenceObserved {
        fencing_token: u64,
        fence_revoked: bool,
        owner_pidfd_exit_observed: bool,
        owner_cgroup_empty_observed: bool,
        owner_observation_sha256: String,
        quiescent: bool,
    },
    ReleaseConsumed {
        authorization_id: String,
        exact_replay_key_sha256: String,
        release_receipt_sha256: String,
        released_object_sha256: String,
    },
    ReplayResolved {
        idempotency_key: String,
        original_result_sha256: String,
    },
    ReconciliationComplete {
        reconciliation_high_water: u64,
        reconciliation_state_sha256: String,
    },
    Query {
        present: bool,
        record_sha256: Option<String>,
        record: Option<serde_json::Value>,
    },
    Conflict {
        expected_revision: u64,
        observed_revision: u64,
        observed_state: String,
        observed_state_sha256: String,
    },
    OutcomeUnknown {
        operation_id: String,
        reconciliation_job_id: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FenceAllocationV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub owner_service_id: String,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_sha256: String,
    pub expected_previous_token: u64,
    pub deadline: V2MonotonicDeadlineV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FenceRevocationV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub generation_id: String,
    pub generation: u64,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub expected_owner_sha256: String,
    pub revocation_reason: String,
    pub deadline: V2MonotonicDeadlineV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnerObservationV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub generation_id: String,
    pub generation: u64,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub fence_revoked: bool,
    pub owner_pidfd_exit_observed: bool,
    pub owner_cgroup_empty_observed: bool,
    pub owner_observation_sha256: String,
    pub observed_at_boottime_ns: u64,
    pub deadline: V2MonotonicDeadlineV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "command",
    content = "parameters",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub(crate) enum StateAuthorityCommandV1 {
    Mutate(AuthorityMutationV1),
    Query {
        generation_id: String,
        generation: u64,
        collection: StateCollectionV1,
        entity_key: String,
        deadline: V2MonotonicDeadlineV1,
    },
    AllocateFence(FenceAllocationV1),
    RevokeFence(FenceRevocationV1),
    ObserveQuiescence(OwnerObservationV1),
    ResolveReplay {
        generation_id: String,
        generation: u64,
        idempotency_key: String,
        request_sha256: String,
        deadline: V2MonotonicDeadlineV1,
    },
    Reconcile {
        generation_id: String,
        generation: u64,
        reconciliation_cursor: u64,
        deadline: V2MonotonicDeadlineV1,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateAuthorityResponseV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub command_sha256: String,
    pub result: AuthorityResultV1,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl StateAuthorityResponseV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}
