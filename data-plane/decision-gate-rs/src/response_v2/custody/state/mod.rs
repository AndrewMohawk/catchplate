mod client;
mod model;
mod postgres;
mod postgres_adapter;

use sha2::Digest as _;

pub(crate) use client::StateAuthorityClient;
pub(crate) use model::{
    AuthorityMutationV1, AuthorityPayloadV1, AuthorityResultV1,
    AuthorityResultKindV1,
    FenceAllocationV1, FenceRevocationV1, OwnerObservationV1,
    StateAuthorityCommandV1,
    StateAuthorityResponseV1, StateCollectionV1,
};
pub(crate) use postgres::{
    validate_postgres_authority_contract, PostgresAuthorityContractV1,
};
pub(crate) use postgres_adapter::{
    LedgerObjectStore, PostgresUdsBackend,
};

pub(crate) fn validate_authority_result(
    command: &StateAuthorityCommandV1,
    result: &AuthorityResultV1,
) -> Result<(), super::V2RuntimeError> {
    use AuthorityPayloadV1::*;
    use AuthorityResultKindV1::*;
    let canonical =
        crate::canonical_json_bytes(&result.canonical_result)
            .map_err(|_| {
                super::V2RuntimeError::new(
                    "state_authority_result_invalid",
                    "authority result payload cannot be canonicalized",
                )
            })?;
    let canonical_command =
        crate::canonical_json_bytes(command).map_err(|_| {
            super::V2RuntimeError::new(
                "state_authority_command_invalid",
                "authority command cannot be canonicalized for its stable resume identifier",
            )
        })?;
    let expected_resume_id = {
        let mut hasher = sha2::Sha256::new();
        for value in [
            b"serverware.response-v2/stable-resume/v1".as_slice(),
            canonical_command.as_slice(),
            result.operation_id.as_bytes(),
            result.idempotency_key.as_bytes(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        format!("sha256:{:x}", hasher.finalize())
    };
    if result.operation_id.is_empty()
        || result.idempotency_key.is_empty()
        || !is_sha256(&result.stable_resume_id)
        || result.stable_resume_id != expected_resume_id
        || result.authority_sequence == 0
        || result.authoritative_revision == 0
        || result.authoritative_state.is_empty()
        || result.canonical_result_sha256
            != format!(
                "sha256:{:x}",
                sha2::Sha256::digest(canonical)
            )
        || result.committed_at_epoch_ms == 0
    {
        return Err(super::V2RuntimeError::new(
            "state_authority_result_invalid",
            "authority result lacks a canonical durable terminal binding",
        ));
    }
    let valid_terminal = match (&result.kind, &result.canonical_result) {
        (Applied | AlreadyApplied, MutationCommitted { .. }) => {
            matches!(command, StateAuthorityCommandV1::Mutate(_))
        }
        (
            Applied | AlreadyApplied,
            FenceAllocated {
                fencing_token,
                owner_sha256,
            },
        ) => match command {
            StateAuthorityCommandV1::AllocateFence(request) => {
                *fencing_token == result.fencing_token
                    && result.fencing_token
                        > request.expected_previous_token
                    && is_sha256(owner_sha256)
            }
            _ => false,
        },
        (
            Applied | AlreadyApplied,
            FenceRevoked {
                fencing_token,
                revocation_record_sha256,
            },
        ) => match command {
            StateAuthorityCommandV1::RevokeFence(request) => {
                *fencing_token == result.fencing_token
                    && *fencing_token == request.fencing_token
                    && is_sha256(revocation_record_sha256)
            }
            _ => false,
        },
        (
            Applied | AlreadyApplied,
            QuiescenceObserved {
                fencing_token,
                fence_revoked,
                owner_pidfd_exit_observed,
                owner_cgroup_empty_observed,
                owner_observation_sha256,
                quiescent,
                ..
            },
        ) => match command {
            StateAuthorityCommandV1::ObserveQuiescence(request) => {
                *fencing_token == result.fencing_token
                    && *fencing_token == request.fencing_token
                    && *fence_revoked == request.fence_revoked
                    && *owner_pidfd_exit_observed
                        == request.owner_pidfd_exit_observed
                    && *owner_cgroup_empty_observed
                        == request.owner_cgroup_empty_observed
                    && owner_observation_sha256
                        == &request.owner_observation_sha256
                    && *quiescent
                        == (*fence_revoked
                            && *owner_pidfd_exit_observed
                            && *owner_cgroup_empty_observed)
            }
            _ => false,
        },
        (
            Applied | AlreadyApplied,
            ReplayResolved {
                idempotency_key,
                ..
            },
        ) => match command {
            StateAuthorityCommandV1::ResolveReplay {
                idempotency_key: expected,
                ..
            } => idempotency_key == expected,
            _ => false,
        },
        (
            Applied | AlreadyApplied,
            ReconciliationComplete { .. },
        ) => matches!(
            command,
            StateAuthorityCommandV1::Reconcile { .. }
        ),
        (Applied | AlreadyApplied, Query { .. }) => {
            matches!(command, StateAuthorityCommandV1::Query { .. })
        }
        (
            AuthorityResultKindV1::Conflict,
            AuthorityPayloadV1::Conflict { .. },
        ) => true,
        (
            AuthorityResultKindV1::OutcomeUnknown,
            AuthorityPayloadV1::OutcomeUnknown { .. },
        ) => true,
        _ => false,
    };
    if !valid_terminal {
        return Err(super::V2RuntimeError::new(
            "state_authority_result_class_mismatch",
            "authority result terminal class does not match the exact command",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
