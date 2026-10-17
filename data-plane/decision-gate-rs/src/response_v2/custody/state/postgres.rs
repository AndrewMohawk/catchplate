use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::StateCollectionV1;
use crate::response_observation_v2::custody::V2RuntimeError;

pub(crate) const POSTGRES_AUTHORITY_CONTRACT_API_VERSION: &str =
    "catchplate.responseObservationV2PostgresAuthority/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PostgresAuthorityContractV1 {
    pub api_version: String,
    pub cluster_id: String,
    pub database_id: String,
    pub schema_generation: u64,
    pub migration_manifest_sha256: String,
    pub operation_registry_sha256: String,
    pub serializable_transactions_required: bool,
    pub synchronous_commit_required: bool,
    pub exact_retry_results_required: bool,
    pub canonical_signed_retry_bytes_required: bool,
    pub canonical_lock_order_required: bool,
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    pub bounded_worker_count: u32,
    pub owned_collections: Vec<StateCollectionV1>,
}

pub(crate) fn validate_postgres_authority_contract(
    contract: &PostgresAuthorityContractV1,
) -> Result<(), V2RuntimeError> {
    let collections = contract
        .owned_collections
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let expected = [
        StateCollectionV1::ProviderGenerations,
        StateCollectionV1::RoleIdentities,
        StateCollectionV1::Attempts,
        StateCollectionV1::Operations,
        StateCollectionV1::Fences,
        StateCollectionV1::ReplayLedger,
        StateCollectionV1::ReleaseLedger,
        StateCollectionV1::CredentialUses,
        StateCollectionV1::TargetEffects,
        StateCollectionV1::PolicyDecisions,
        StateCollectionV1::Evidence,
        StateCollectionV1::Finalizations,
        StateCollectionV1::Objects,
        StateCollectionV1::Archives,
        StateCollectionV1::PublisherOutbox,
        StateCollectionV1::TransparencyLeaves,
        StateCollectionV1::TransparencyCheckpoints,
        StateCollectionV1::TrustedTimeHighWater,
        StateCollectionV1::ReconciliationJobs,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if contract.api_version
            != POSTGRES_AUTHORITY_CONTRACT_API_VERSION
        || contract.cluster_id.is_empty()
        || contract.database_id.is_empty()
        || contract.schema_generation == 0
        || !is_sha256(&contract.migration_manifest_sha256)
        || !is_sha256(&contract.operation_registry_sha256)
        || !contract.serializable_transactions_required
        || !contract.synchronous_commit_required
        || !contract.exact_retry_results_required
        || !contract.canonical_signed_retry_bytes_required
        || !contract.canonical_lock_order_required
        || contract.statement_timeout_ms == 0
        || contract.statement_timeout_ms > 30_000
        || contract.lock_timeout_ms == 0
        || contract.lock_timeout_ms
            > contract.statement_timeout_ms
        || contract.bounded_worker_count == 0
        || contract.bounded_worker_count > 64
        || collections.len() != contract.owned_collections.len()
        || collections != expected
    {
        return Err(V2RuntimeError::new(
            "postgres_state_authority_contract_invalid",
            "PostgreSQL state authority must own the complete durable state set under SERIALIZABLE, synchronous, bounded, canonical-lock-order, exact-retry semantics",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
