use super::common::ServiceRuntime;
use super::common::provider_authority_scope;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use sha2::Digest as _;

use super::super::attestation::{
    RoleSigningKey, STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN,
    STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN,
    SETTLEMENT_EVIDENCE_CONTEXT_SIGNATURE_DOMAIN,
};
use super::super::protocol::{
    ordered_authority_proof_seed_artifacts_root_sha256,
    AttemptStateQueryRequestV1, PersistedAuthorityProofMaterialV1,
    ServiceOperationV1, SignedAttemptStateObservationV1,
    SignedReplaySourceObservationV1,
    SettlementEvidenceContextRequestV1,
    SignedSettlementEvidenceContextV1,
    SignedStateMutationReceiptV1,
    ATTEMPT_STATE_OBSERVATION_API_VERSION,
    STATE_MUTATION_RECEIPT_API_VERSION,
    SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION,
};
use super::super::state::{
    LedgerObjectStore, PostgresUdsBackend,
};
use super::super::{
    CustodyServiceRole, RootOwnedResponseObservationV2Config,
    V2RuntimeError,
};
use super::super::super::state_authority::{
    AuthorityResultSigner, AuthoritySignerIdentity, BootClock, BootDeadline,
    CgroupObserver, CgroupOwner, Digest,
    ExactSignedResultBytes, GenerationRpcRequestFrame, Identifier,
    ImmutableObjectStore, PgValue, PostgresBackend,
    ReconciliationDomain, ServiceRole,
    StateAuthority, StateAuthorityConfiguration,
};

const QUERY_ATTEMPT_OBSERVATION_SQL: &str = "
SELECT attempt.revision, attempt.state, attempt.fence_token, attempt.stable_resume_id,
       attempt.owner_process_id, attempt.owner_pid, attempt.owner_start_time_ticks,
       attempt.owner_cgroup_id, attempt.deadline_boot_id, attempt.deadline_boot_millis,
       fence.allocation_sequence
FROM response_v2_state_authority.attempts AS attempt
JOIN response_v2_state_authority.fences AS fence
  ON fence.generation_id=attempt.generation_id AND fence.attempt_id=attempt.attempt_id
 AND fence.fence_token=attempt.fence_token
WHERE attempt.generation_id = $1 AND attempt.attempt_id = $2
FOR SHARE OF attempt,fence";
const QUERY_ATTEMPT_OBJECTS_SQL: &str = "
SELECT object.generation_id, object.object_id, object.object_kind, object.content_sha256,
       object.content_length, object.media_type, object.storage_locator,
       object.immutable_storage_receipt_sha256
FROM response_v2_state_authority.immutable_objects AS object
WHERE object.generation_id = $1 AND (object.attempt_id = $2 OR EXISTS (
    SELECT 1 FROM response_v2_state_authority.evidence AS evidence
    WHERE evidence.generation_id = object.generation_id AND evidence.attempt_id = $2
      AND evidence.evidence_type = 'ARTIFACT_COMMIT'
      AND evidence.object_sha256 = object.content_sha256
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,generationId}' = object.generation_id
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,attemptId}' = evidence.attempt_id
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,artifactId}' = evidence.evidence_id
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifactType}' = 'ARTIFACT_COMMIT'
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifact,objectId}' = object.object_id
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifact,objectKind}' = object.object_kind
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifact,contentSha256}' = object.content_sha256
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifact,contentLength}' = object.content_length::text
      AND convert_from(evidence.canonical_artifact,'UTF8')::jsonb #>> '{body,payload,artifact,immutableStorageReceiptSha256}' = object.immutable_storage_receipt_sha256
))
ORDER BY object.object_id
FOR SHARE OF object";
const QUERY_CREDENTIAL_USE_ID_SQL: &str = "
SELECT credential_use_id
FROM response_v2_state_authority.credential_uses
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE";
const QUERY_TARGET_EFFECT_ID_SQL: &str = "
SELECT target_effect_id
FROM response_v2_state_authority.target_effects
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE";
const QUERY_POLICY_DECISION_ID_SQL: &str = "
SELECT policy_decision_id
FROM response_v2_state_authority.policy_decisions
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE";
const QUERY_ATTEMPT_EVIDENCE_SQL: &str = "
SELECT canonical_artifact
FROM response_v2_state_authority.evidence
WHERE generation_id = $1 AND attempt_id = $2
ORDER BY evidence_id
FOR SHARE";
const QUERY_INSPECTION_ARTIFACTS_SQL: &str = "
SELECT signed_inspection_artifact, canonical_signed_result_sha256
FROM response_v2_state_authority.immutable_inspections
WHERE generation_id = $1 AND attempt_id = $2
ORDER BY inspection_id
FOR SHARE";
const QUERY_REPLAY_SOURCE_SQL: &str = "
SELECT replay.replay_id, replay.operation_id,
       replay.exact_request_sha256,
       replay.canonical_signed_result,
       replay.canonical_signed_result_sha256,
       operation.attempt_id
FROM response_v2_state_authority.replay_ledger AS replay
JOIN response_v2_state_authority.operations AS operation
  ON operation.generation_id = replay.generation_id
 AND operation.operation_id = replay.operation_id
WHERE replay.generation_id = $1 AND replay.replay_id = $2
FOR SHARE";
const QUERY_SETTLEMENT_FENCE_SQL: &str = "
SELECT state
FROM response_v2_state_authority.fences
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE";
const QUERY_SETTLEMENT_TARGET_SQL: &str = "
SELECT target_effect_id, state, response_object_sha256
FROM response_v2_state_authority.target_effects
WHERE generation_id = $1 AND attempt_id = $2
FOR SHARE";

pub(super) struct StateExecution {
    pub receipt: SignedStateMutationReceiptV1,
    pub response_data_result: Option<
        super::super::super::state_authority::rpc::
            ResponseDataStateResult,
    >,
    pub exact_raw: Option<Vec<u8>>,
    pub exact_descriptor: Option<
        crate::response_observation_v2_api::ExactByteObjectDescriptor,
    >,
}

pub(super) fn retrieve_observed_raw_object(
    config: &RootOwnedResponseObservationV2Config,
    proof: &PersistedAuthorityProofMaterialV1,
    deadline_boottime_ns: u64,
) -> Result<Vec<u8>, V2RuntimeError> {
    let state =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let ledger = config
        .custody_topology()
        .process(CustodyServiceRole::ImmutableArtifactLedger)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_ledger_missing",
                "signed topology omits immutable-artifact-ledger",
            )
        })?;
    let backend = postgres_backend(config, &state)?;
    let instant =
        backend.current_boot_instant().map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock,
        boot_id: instant.boot_id,
        deadline_boot_millis: deadline_boottime_ns / 1_000_000,
    };
    let store = LedgerObjectStore::new(
        ledger.process_state_object_root(),
        ledger.uid,
        ledger.gid,
    )
    .map_err(authority_error)?;
    store
        .retrieve_exact(
            &proof.raw_response_object.generation_id,
            &proof.raw_response_object.object_id,
            &proof.raw_response_storage_locator,
            &proof.raw_response_immutable_storage_receipt_sha256,
            &proof.raw_response_object.content_sha256,
            proof.raw_response_object.content_length,
            &deadline,
        )
        .map_err(authority_error)
}

pub(super) fn query_replay_source_postgres(
    config: &RootOwnedResponseObservationV2Config,
    request_id: &str,
    operation_id: &str,
    source_replay_id: &str,
    observation: &SignedAttemptStateObservationV1,
    deadline_boottime_ns: u64,
    signing_key: &RoleSigningKey,
) -> Result<SignedReplaySourceObservationV1, V2RuntimeError> {
    if signing_key.logical_role() != "linearizable-store"
        || observation.generation_id
            != config.custody_topology().generation_id
    {
        return Err(V2RuntimeError::new(
            "replay_source_query_signer_invalid",
            "replay source query requires the installed linearizable-store observation",
        ));
    }
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend = postgres_backend(config, &scoped)?;
    let instant =
        backend.current_boot_instant().map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock,
        boot_id: instant.boot_id,
        deadline_boot_millis: deadline_boottime_ns / 1_000_000,
    };
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_error)?;
    let row = transaction
        .query_optional(
            QUERY_REPLAY_SOURCE_SQL,
            &[
                PgValue::Text(scoped.generation_id.clone()),
                PgValue::Text(source_replay_id.to_owned()),
            ],
        )
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "replay_source_missing",
                "state authority has no exact durable replay source",
            )
        })?;
    let canonical = row
        .require_bytes("canonical_signed_result")
        .map_err(authority_error)?;
    let canonical_sha256 = row
        .require_text("canonical_signed_result_sha256")
        .map_err(authority_error)?;
    if format!("sha256:{:x}", sha2::Sha256::digest(&canonical))
            != canonical_sha256
        || row.require_text("attempt_id").map_err(authority_error)?
            != observation.attempt_id
    {
        return Err(V2RuntimeError::new(
            "replay_source_binding_mismatch",
            "durable replay source digest or attempt does not match the signed observation",
        ));
    }
    transaction.commit(&deadline).map_err(authority_error)?;
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::StateAuthority,
        signing_key,
        ServiceOperationV1::ReplayResolve,
        operation_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut signed = SignedReplaySourceObservationV1 {
        api_version:
            "serverware.responseV2ReplaySourceObservation/v1"
                .to_owned(),
        generation_id: scoped.generation_id,
        generation: scoped.generation,
        request_id: request_id.to_owned(),
        operation_id: operation_id.to_owned(),
        source_replay_id:
            row.require_text("replay_id").map_err(authority_error)?,
        source_operation_id:
            row.require_text("operation_id").map_err(authority_error)?,
        source_attempt_id: observation.attempt_id.clone(),
        source_exact_request_sha256: row
            .require_text("exact_request_sha256")
            .map_err(authority_error)?,
        source_canonical_result_sha256: canonical_sha256,
        source_canonical_result_base64url:
            super::super::super::state_authority::canonical::
                encode_base64url(&canonical),
        authority_scope: scope,
        signer_logical_role: signing_key.logical_role().to_owned(),
        signer_key_id: signing_key.key_id().to_owned(),
        signature: String::new(),
    };
    signed.signature = signing_key.sign(
        super::super::attestation::
            REPLAY_SOURCE_OBSERVATION_SIGNATURE_DOMAIN,
        &signed.without_signature(),
    )?;
    Ok(signed)
}

pub(super) fn query_settlement_evidence_context_postgres(
    config: &RootOwnedResponseObservationV2Config,
    request: &SettlementEvidenceContextRequestV1,
    signing_key: &RoleSigningKey,
) -> Result<SignedSettlementEvidenceContextV1, V2RuntimeError> {
    use super::super::super::state_authority::canonical::{
        canonical_jcs_bytes, sha256_digest,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, FenceState, TargetEffectState,
    };

    let observation = &request.attempt_observation;
    super::super::attestation::verify_attempt_state_observation(
        config.custody_topology(),
        observation,
    )?;
    if signing_key.logical_role() != "linearizable-store"
        || request.api_version
            != SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION
        || request.generation_id
            != config.custody_topology().generation_id
        || request.generation
            != config.custody_topology().generation
        || observation.generation_id != request.generation_id
        || observation.generation != request.generation
        || request.terminal_code.is_empty()
    {
        return Err(V2RuntimeError::new(
            "settlement_evidence_context_request_invalid",
            "settlement context query is not bound to the installed generation, signed attempt, and linearizable-store signer",
        ));
    }
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend = postgres_backend(config, &scoped)?;
    let instant =
        backend.current_boot_instant().map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock.clone(),
        boot_id: instant.boot_id.clone(),
        deadline_boot_millis:
            request.deadline_boottime_ns / 1_000_000,
    };
    deadline.ensure_current(&instant).map_err(authority_error)?;
    let parameters = [
        PgValue::Text(scoped.generation_id.clone()),
        PgValue::Text(observation.attempt_id.clone()),
    ];
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_error)?;
    let fence = transaction
        .query_optional(QUERY_SETTLEMENT_FENCE_SQL, &parameters)
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "settlement_fence_missing",
                "state authority has no fence for the observed attempt",
            )
        })?;
    let fence_state = match fence
        .require_text("state")
        .map_err(authority_error)?
        .as_str()
    {
        "ACTIVE" => FenceState::Active,
        "REVOKED" => FenceState::Revoked,
        "QUIESCENT" => FenceState::Quiescent,
        _ => {
            return Err(V2RuntimeError::new(
                "settlement_fence_state_invalid",
                "state authority returned an unknown fence state",
            ))
        }
    };
    if fence_state != FenceState::Active {
        return Err(V2RuntimeError::new(
            "settlement_fence_not_active",
            "settlement evidence requires the active attempt fence",
        ));
    }
    let target = transaction
        .query_optional(QUERY_SETTLEMENT_TARGET_SQL, &parameters)
        .map_err(authority_error)?;
    let (
        target_effect_id,
        target_effect_state,
        upstream_response_sha256,
    ) = match target {
        Some(row) => {
            let state = match row
                .require_text("state")
                .map_err(authority_error)?
                .as_str()
            {
                "DISPATCHING" => TargetEffectState::Dispatching,
                "OUTCOME_UNKNOWN" => {
                    TargetEffectState::OutcomeUnknown
                }
                "OBSERVED" => TargetEffectState::Observed,
                "RECONCILED_FAILURE" => {
                    TargetEffectState::ReconciledFailure
                }
                _ => {
                    return Err(V2RuntimeError::new(
                        "settlement_target_state_invalid",
                        "state authority returned an unknown target-effect state",
                    ))
                }
            };
            (
                Some(Identifier(
                    row.require_text("target_effect_id")
                        .map_err(authority_error)?,
                )),
                Some(state),
                row.optional_text("response_object_sha256")
                    .map_err(authority_error)?
                    .map(Digest),
            )
        }
        None => (None, None, None),
    };
    let expected_upstream = request
        .expected_upstream_response_sha256
        .clone()
        .map(Digest);
    if expected_upstream != upstream_response_sha256 {
        return Err(V2RuntimeError::new(
            "settlement_upstream_response_mismatch",
            "caller projection differs from the persisted target response",
        ));
    }
    transaction.commit(&deadline).map_err(authority_error)?;
    let observed = backend
        .observe(
            &CgroupOwner {
                process_id:
                    Identifier(observation.owner_process_id.clone()),
                pid: observation.owner_pid,
                process_start_time_ticks:
                    observation.owner_start_time_ticks,
                cgroup_id:
                    Identifier(observation.owner_cgroup_id.clone()),
            },
            &deadline,
        )
        .map_err(authority_error)?;
    if !observed.owner_death_observed
        || !observed.cgroup_empty_observed
        || !observed.cgroup_death_observed
    {
        return Err(V2RuntimeError::new(
            "settlement_cleanup_incomplete",
            "owner process and cgroup are not fully quiescent",
        ));
    }
    let terminal_code = Identifier(request.terminal_code.clone());
    let terminal_detail_sha256 = sha256_digest(
        &canonical_jcs_bytes(&(
            "SETTLE_ATTEMPT",
            Identifier(request.generation_id.clone()),
            Identifier(observation.attempt_id.clone()),
            observation.attempt_revision,
            observation.authoritative_state,
            Identifier(observation.stable_resume_id.clone()),
            Identifier(observation.fencing_token.to_string()),
            fence_state,
            &terminal_code,
            &target_effect_id,
            target_effect_state,
            &upstream_response_sha256,
            (&instant.boot_id, instant.boot_millis),
            (&deadline.boot_id, deadline.deadline_boot_millis),
            (
                Identifier(observation.owner_process_id.clone()),
                observation.owner_pid,
                observation.owner_start_time_ticks,
                Identifier(observation.owner_cgroup_id.clone()),
            ),
            (
                observed.owner_death_observed,
                observed.cgroup_empty_observed,
                observed.cgroup_death_observed,
            ),
        ))
        .map_err(authority_error)?,
    );
    let recovery_required = matches!(
        observation.authoritative_state,
        AttemptState::Dispatching | AttemptState::OutcomeUnknown
    ) || matches!(
        target_effect_state,
        Some(TargetEffectState::ReconciledFailure)
    );
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::StateAuthority,
        signing_key,
        ServiceOperationV1::Reconcile,
        &request.operation_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut context = SignedSettlementEvidenceContextV1 {
        api_version:
            SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION.to_owned(),
        generation_id: request.generation_id.clone(),
        generation: request.generation,
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        attempt_id: observation.attempt_id.clone(),
        attempt_revision: observation.attempt_revision,
        authoritative_state:
            observation.authoritative_state,
        authoritative_state_sha256:
            observation.authoritative_state_sha256.clone(),
        stable_resume_id: observation.stable_resume_id.clone(),
        fencing_token: observation.fencing_token,
        fence_state,
        owner_process_id: observation.owner_process_id.clone(),
        owner_pid: observation.owner_pid,
        owner_start_time_ticks:
            observation.owner_start_time_ticks,
        owner_cgroup_id: observation.owner_cgroup_id.clone(),
        deadline_boot_id: observation.deadline_boot_id.clone(),
        deadline_boot_millis: observation.deadline_boot_millis,
        observed_boot_id: instant.boot_id.0,
        observed_boot_millis: instant.boot_millis,
        cleanup_deadline_boot_id: deadline.boot_id.0,
        cleanup_deadline_boot_millis:
            deadline.deadline_boot_millis,
        owner_death_observed: observed.owner_death_observed,
        cgroup_empty_observed:
            observed.cgroup_empty_observed,
        cgroup_death_observed:
            observed.cgroup_death_observed,
        target_effect_id:
            target_effect_id.map(|identifier| identifier.0),
        target_effect_state,
        upstream_response_sha256:
            upstream_response_sha256.map(|digest| digest.0),
        terminal_code: terminal_code.0,
        terminal_detail_sha256:
            terminal_detail_sha256.0,
        recovery_required,
        authority_scope: scope,
        signer_logical_role:
            signing_key.logical_role().to_owned(),
        signer_key_id: signing_key.key_id().to_owned(),
        signature: String::new(),
    };
    context.signature = signing_key.sign(
        SETTLEMENT_EVIDENCE_CONTEXT_SIGNATURE_DOMAIN,
        &context.without_signature(),
    )?;
    Ok(context)
}

struct StateResultSigner<'a> {
    key: &'a RoleSigningKey,
    role_id: Identifier,
    key_id: Identifier,
    clock: PostgresUdsBackend,
    secret_key_path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    credentials_directory: Option<PathBuf>,
    guest_delivery: Option<std::sync::Arc<super::super::guest_delivery::Delivery>>,
    identity: AuthoritySignerIdentity,
}

impl AuthorityResultSigner for StateResultSigner<'_> {
    fn role_id(&self) -> &Identifier {
        &self.role_id
    }

    fn key_id(&self) -> &Identifier {
        &self.key_id
    }

    fn identity(&self) -> &AuthoritySignerIdentity {
        &self.identity
    }

    fn sign_digest(
        &self,
        digest: &[u8; 32],
        deadline: &BootDeadline,
    ) -> super::super::super::state_authority::AuthorityResult<Vec<u8>> {
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        if let Some(owner) = &self.guest_delivery {
            owner.require_signer(self.key.logical_role(), self.key.key_id(), &self.secret_key_path)
                .map_err(|error| super::super::super::state_authority::AuthorityError::Authentication {
                    code:"guest_signing_original_changed", reason:error.to_string(),
                })?;
        } else { validate_signing_credential(
            &self.secret_key_path,
            self.expected_uid,
            self.expected_gid,
            self.credentials_directory.as_deref(),
        )?; }
        let signature = self.key.sign_digest_bytes(digest);
        if let Some(owner) = &self.guest_delivery {
            owner.check().map_err(|error| super::super::super::state_authority::AuthorityError::Authentication {
                code:"guest_signing_original_changed", reason:error.to_string(),
            })?;
        }
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        Ok(signature)
    }
}

type TrustedHostStateAuthority<'a> = StateAuthority<
    PostgresUdsBackend,
    StateResultSigner<'a>,
    super::ledger_exact_read::Store<'a>,
    PostgresUdsBackend,
    PostgresUdsBackend,
>;

pub(crate) fn run(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    ServiceRuntime::prepare(
        config,
        CustodyServiceRole::StateAuthority,
    )?
    .run()
}

pub(super) fn execute_postgres(
    config: &RootOwnedResponseObservationV2Config,
    frame: &super::super::super::state_authority::rpc::RpcRequestFrame,
    request_id: &str,
    operation_id: &str,
    attempt_id: &str,
    stable_resume_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
    signing_key: &RoleSigningKey,
) -> Result<StateExecution, V2RuntimeError> {
    execute_profile_postgres(config, frame, request_id, operation_id, attempt_id,
        stable_resume_id, attempt_revision, fencing_token, signing_key, false)
}

pub(super) fn execute_profile_postgres(
    config: &RootOwnedResponseObservationV2Config,
    frame: &super::super::super::state_authority::rpc::RpcRequestFrame,
    request_id: &str,
    operation_id: &str,
    attempt_id: &str,
    stable_resume_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
    signing_key: &RoleSigningKey,
    sequence_profile: bool,
) -> Result<StateExecution, V2RuntimeError> {
    let reserve = frame.request.operation
        == super::super::super::state_authority::lifecycle::OperationKind::AttemptReserve;
    if reserve && (!sequence_profile || fencing_token != 0 || attempt_revision != 0) {
        return Err(V2RuntimeError::new("sequence_reserve_profile_required",
            "Reserve requires the explicit fresh sequence profile and unallocated zero wrapper"));
    }
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    if sequence_profile && scoped.process.max_frame_bytes
        != super::super::super::state_authority::postgres::sequence_originals::REQUIRED_CUSTODY_FRAME_BYTES {
        return Err(V2RuntimeError::new("sequence_profile_transport_bound",
            "new sequence execution requires the independently configured 256 KiB custody bound"));
    }
    if signing_key.logical_role() != "linearizable-store" {
        return Err(V2RuntimeError::new(
            "state_authority_engine_signer_invalid",
            "PostgreSQL authority engine requires the linearizable-store subkey",
        ));
    }
    let ledger = config
        .custody_topology()
        .process(CustodyServiceRole::ImmutableArtifactLedger)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_ledger_missing",
                "signed topology omits immutable-artifact-ledger",
            )
        })?;
    let timeout = std::time::Duration::from_millis(
        scoped.process.request_timeout_ms,
    );
    let authority = trusted_host_authority(
        config,
        signing_key,
        ledger,
        timeout,
        None,
    )?;
    let exact = if sequence_profile {
        authority.execute_sequence_mutation(frame)
    } else {
        authority.execute_mutation(frame)
    }.map_err(authority_error)?;
    let signed:
        super::super::super::state_authority::rpc::SignedOperationResult =
        serde_json::from_slice(&exact.canonical_bytes).map_err(|_| {
            V2RuntimeError::new(
                "state_authority_result_invalid",
                "PostgreSQL authority returned a non-DTO signed result",
            )
        })?;
    let body = &signed.body;
    let allocated_fence = body.fence_token.0.parse::<u64>().map_err(|_| {
        V2RuntimeError::new("state_authority_fence_profile_invalid",
            "custody receipt requires an actual canonical sequence fence, never a hash conversion")
    })?;
    super::super::super::state_authority::postgres::sequence_originals::canonical_fence(
        &body.fence_token.0, allocated_fence).map_err(authority_error)?;
    let expected_fence_token =
        frame.request.fence.fence_token.as_ref();
    if body.generation_id.0 != scoped.generation_id
        || body.request_id.0 != request_id
        || body.operation_id.0 != operation_id
        || body.attempt_id.0 != attempt_id
        || body.stable_resume_id.0 != stable_resume_id
        || body.authoritative_revision == 0
        || body.authoritative_revision < attempt_revision
        || (!reserve && allocated_fence != fencing_token)
        || expected_fence_token
            .is_some_and(|token| token != &body.fence_token)
    {
        return Err(V2RuntimeError::new(
            "state_authority_result_binding_mismatch",
            "PostgreSQL authority result does not bind the exact request, operation, attempt, resume ID, revision, and fence",
        ));
    }
    let disposition = match body.disposition {
        super::super::super::state_authority::rpc::
            ResultDisposition::Applied => "APPLIED",
        super::super::super::state_authority::rpc::
            ResultDisposition::OutcomeUnknown => "OUTCOME_UNKNOWN",
        super::super::super::state_authority::rpc::
            ResultDisposition::Conflict => "CONFLICT",
        super::super::super::state_authority::rpc::
            ResultDisposition::Rejected => "REJECTED",
    };
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::StateAuthority,
        signing_key,
        ServiceOperationV1::StateCas,
        operation_id,
        attempt_id,
        body.authoritative_revision,
        allocated_fence,
    )?;
    let mut receipt = SignedStateMutationReceiptV1 {
        api_version: STATE_MUTATION_RECEIPT_API_VERSION.to_owned(),
        generation_id: scoped.generation_id,
        generation: scoped.generation,
        operation: ServiceOperationV1::StateCas,
        request_id: request_id.to_owned(),
        operation_id: operation_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        stable_resume_id: stable_resume_id.to_owned(),
        authority_scope: scope,
        exact_request_sha256: body.exact_request_sha256.0.clone(),
        exact_result_sha256: exact.canonical_sha256.0,
        disposition: disposition.to_owned(),
        authoritative_revision: body.authoritative_revision,
        authoritative_state:
            body.authoritative_state.as_str().to_owned(),
        fencing_token: allocated_fence,
        signer_logical_role: signing_key.logical_role().to_owned(),
        signer_key_id: signing_key.key_id().to_owned(),
        signature: String::new(),
    };
    receipt.signature = signing_key.sign(
        STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN,
        &receipt.without_signature(),
    )?;
    let exact_raw = body
        .retrieved_immutable_raw
        .as_ref()
        .map(|raw| {
            super::super::super::state_authority::canonical::
                decode_base64url(
                    "operationResult.retrievedImmutableRaw.rawContentBase64url",
                    &raw.raw_content_base64url,
                )
                .map_err(authority_error)
        })
        .transpose()?;
    let exact_descriptor = body
        .retrieved_immutable_raw
        .as_ref()
        .map(|raw| {
            crate::response_observation_v2_api::
                ExactByteObjectDescriptor {
                object_id: raw.reference.object_id.0.clone(),
                media_type:
                    crate::response_observation_v2_api::
                        ExactObjectMediaType::Http11Response,
                fd_index: 0,
                byte_length: raw.reference.content_length,
                sha256: raw.reference.content_sha256.0.clone(),
                required_seals:
                    crate::response_observation_v2_api::
                        MemfdSealProfile::ImmutableV1,
            }
        });
    let response_data_result = body.response_data_result.clone();
    Ok(StateExecution {
        receipt,
        response_data_result,
        exact_raw,
        exact_descriptor,
    })
}

fn trusted_query_authority<'a>(
    config: &RootOwnedResponseObservationV2Config,
    signing_key: &'a RoleSigningKey,
) -> Result<TrustedHostStateAuthority<'a>, V2RuntimeError> {
    let scoped = config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let ledger = config.custody_topology().process(CustodyServiceRole::ImmutableArtifactLedger)
        .ok_or_else(|| V2RuntimeError::new("state_authority_ledger_missing", "signed topology omits immutable ledger"))?;
    trusted_host_authority(config, signing_key, ledger,
        std::time::Duration::from_millis(scoped.process.request_timeout_ms), None)
}

pub(super) fn query_staged_original_postgres(
    config: &RootOwnedResponseObservationV2Config,
    request: &super::super::protocol::StagedOriginalQueryV1,
    signing_key: &RoleSigningKey,
) -> Result<super::super::protocol::SignedStagedOriginalV1, V2RuntimeError> {
    use super::super::protocol::{SignedStagedOriginalV1, STAGED_ORIGINAL_API_VERSION,
        STAGED_ORIGINAL_QUERY_API_VERSION};
    let scoped = config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    if request.api_version != STAGED_ORIGINAL_QUERY_API_VERSION
        || request.generation_id != scoped.generation_id || request.generation != scoped.generation
        || signing_key.logical_role() != "linearizable-store"
        || request.expected_revision == 0 || request.expected_fencing_token == 0
        || scoped.process.max_frame_bytes
            != super::super::super::state_authority::postgres::sequence_originals::REQUIRED_CUSTODY_FRAME_BYTES {
        return Err(V2RuntimeError::new("staged_original_query_invalid", "wrong exact query profile/generation/signer/head"));
    }
    Identifier(request.request_id.clone()).validate("stagedOriginal.requestId",128).map_err(authority_error)?;
    Identifier(request.operation_id.clone()).validate("stagedOriginal.operationId",128).map_err(authority_error)?;
    Digest(request.expected_stable_resume_id.clone()).validate("stagedOriginal.stableResumeId").map_err(authority_error)?;
    if let Some(digest)=&request.expected_dispatch_request_sha256 {
        Digest(digest.clone()).validate("stagedOriginal.dispatchRequestSha256").map_err(authority_error)?;
    }
    let backend = postgres_backend(config, &scoped)?;
    let now = backend.current_boot_instant().map_err(authority_error)?;
    let deadline = BootDeadline { clock: now.clock, boot_id: now.boot_id,
        deadline_boot_millis: request.deadline_boottime_ns / 1_000_000 };
    let body = trusted_query_authority(config, signing_key)?.query_staged_original(
        &Identifier(request.attempt_id.clone()), &request.expected_stable_resume_id,
        request.expected_revision, request.expected_fencing_token, request.expected_state,
        request.expected_dispatch_request_sha256.as_deref(), &deadline).map_err(authority_error)?;
    let authority_scope = provider_authority_scope(config.custody_topology(),
        CustodyServiceRole::StateAuthority, signing_key, ServiceOperationV1::StateCas,
        &request.operation_id, &body.attempt_id, body.revision, body.fencing_token)?;
    let mut signed = SignedStagedOriginalV1 { api_version: STAGED_ORIGINAL_API_VERSION.into(),
        generation_id: scoped.generation_id, generation: scoped.generation,
        request_id: request.request_id.clone(), operation_id: request.operation_id.clone(), body,
        authority_scope, signer_logical_role: signing_key.logical_role().into(),
        signer_key_id: signing_key.key_id().into(), signature: String::new() };
    signed.signature = signing_key.sign(super::super::attestation::STAGED_ORIGINAL_SIGNATURE_DOMAIN,
        &signed.without_signature())?;
    super::super::attestation::verify_staged_original(config.custody_topology(), &signed)?;
    Ok(signed)
}

pub(super) fn query_attempt_observation_postgres(
    config: &RootOwnedResponseObservationV2Config,
    request: &AttemptStateQueryRequestV1,
    signing_key: &RoleSigningKey,
) -> Result<SignedAttemptStateObservationV1, V2RuntimeError> {
    use super::super::super::state_authority::lifecycle::AttemptState;
    use super::super::super::state_authority::rpc::{
        AuthorityArtifactType, RawObjectReference,
        SignedAuthorityArtifact,
    };

    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    if signing_key.logical_role() != "linearizable-store"
        || request.api_version
            != ATTEMPT_STATE_OBSERVATION_API_VERSION
        || request.generation_id != scoped.generation_id
        || request.generation != scoped.generation
        || request.attempt_id.is_empty()
        || request.expected_stable_resume_id.is_empty()
    {
        return Err(V2RuntimeError::new(
            "attempt_state_query_invalid",
            "attempt-state query is not bound to the installed generation and linearizable-store signer",
        ));
    }
    let backend = postgres_backend(config, &scoped)?;
    let instant =
        backend.current_boot_instant().map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock,
        boot_id: instant.boot_id,
        deadline_boot_millis:
            request.deadline_boottime_ns / 1_000_000,
    };
    let parameters = [
        PgValue::Text(scoped.generation_id.clone()),
        PgValue::Text(request.attempt_id.clone()),
    ];
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_error)?;
    trusted_query_authority(config, signing_key)?
        .require_sequence_database(transaction.as_mut()).map_err(authority_error)?;
    let attempt = transaction
        .query_optional(QUERY_ATTEMPT_OBSERVATION_SQL, &parameters)
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "attempt_state_query_missing",
                "state authority has no such installed-generation attempt",
            )
        })?;
    let revision =
        attempt.require_u64("revision").map_err(authority_error)?;
    let state_text =
        attempt.require_text("state").map_err(authority_error)?;
    let authoritative_state = match state_text.as_str() {
        "RESERVED" => AttemptState::Reserved,
        "AUTHORIZED" => AttemptState::Authorized,
        "STAGED" => AttemptState::Staged,
        "DISPATCHING" => AttemptState::Dispatching,
        "OUTCOME_UNKNOWN" => AttemptState::OutcomeUnknown,
        "OBSERVED" => AttemptState::Observed,
        "TERMINAL_FAILED" => AttemptState::TerminalFailed,
        "FINALIZED" => AttemptState::Finalized,
        "PUBLISHED" => AttemptState::Published,
        "RELEASE_PREPARED" => AttemptState::ReleasePrepared,
        "ARCHIVED" => AttemptState::Archived,
        _ => {
            return Err(V2RuntimeError::new(
                "attempt_state_query_state_unknown",
                "state authority returned an unknown lifecycle state",
            ))
        }
    };
    let stable_resume_id = attempt
        .require_text("stable_resume_id")
        .map_err(authority_error)?;
    let fencing_token = super::super::super::state_authority::postgres::sequence_originals::canonical_fence(
        &attempt.require_text("fence_token").map_err(authority_error)?,
        attempt.require_u64("allocation_sequence").map_err(authority_error)?,
    ).map_err(authority_error)?;
    if stable_resume_id != request.expected_stable_resume_id {
        return Err(V2RuntimeError::new(
            "attempt_state_query_resume_mismatch",
            "state-derived stable resume ID differs from the requested attempt binding",
        ));
    }
    let proof_material = if request.include_proof_material {
        let raw_object_id =
            request.raw_response_object_id.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "attempt_state_query_raw_object_missing",
                    "proof-material query requires the persisted raw-response object ID",
                )
            })?;
        let rows = transaction
            .query_many(QUERY_ATTEMPT_OBJECTS_SQL, &parameters)
            .map_err(authority_error)?;
        let mut raw_response_object = None;
        let mut staged_request_object = None;
        let mut raw_receipt = None;
        let mut raw_storage_locator = None;
        for row in rows {
            let object = RawObjectReference {
                generation_id: Identifier(
                    row.require_text("generation_id")
                        .map_err(authority_error)?,
                ),
                object_id: Identifier(
                    row.require_text("object_id")
                        .map_err(authority_error)?,
                ),
                object_kind: Identifier(
                    row.require_text("object_kind")
                        .map_err(authority_error)?,
                ),
                content_sha256: Digest(
                    row.require_text("content_sha256")
                        .map_err(authority_error)?,
                ),
                content_length: row
                    .require_u64("content_length")
                    .map_err(authority_error)?,
                media_type: row
                    .require_text("media_type")
                    .map_err(authority_error)?,
            };
            if &object.object_id.0 == raw_object_id {
                raw_receipt = Some(Digest(
                    row.require_text(
                        "immutable_storage_receipt_sha256",
                    )
                    .map_err(authority_error)?,
                ));
                raw_storage_locator = Some(
                    row.require_text("storage_locator")
                        .map_err(authority_error)?,
                );
                raw_response_object = Some(object);
            } else if staged_request_object.replace(object).is_some() {
                return Err(V2RuntimeError::new(
                    "attempt_state_query_staged_object_ambiguous",
                    "attempt has more than one non-response immutable object",
                ));
            }
        }
        let credential_use_id = query_single_identifier(
            transaction.as_mut(),
            QUERY_CREDENTIAL_USE_ID_SQL,
            &parameters,
            "credential_use_id",
        )?;
        let target_effect_id = query_single_identifier(
            transaction.as_mut(),
            QUERY_TARGET_EFFECT_ID_SQL,
            &parameters,
            "target_effect_id",
        )?;
        let policy_decision_id = query_single_identifier(
            transaction.as_mut(),
            QUERY_POLICY_DECISION_ID_SQL,
            &parameters,
            "policy_decision_id",
        )?;
        let mut artifacts = std::collections::BTreeMap::new();
        for row in transaction
            .query_many(QUERY_ATTEMPT_EVIDENCE_SQL, &parameters)
            .map_err(authority_error)?
        {
            collect_seed_artifact(
                config,
                &mut artifacts,
                &row.require_bytes("canonical_artifact")
                    .map_err(authority_error)?,
            )?;
        }
        let mut inspection_result_sha256 = None;
        for row in transaction
            .query_many(QUERY_INSPECTION_ARTIFACTS_SQL, &parameters)
            .map_err(authority_error)?
        {
            collect_seed_artifact(
                config,
                &mut artifacts,
                &row.require_bytes("signed_inspection_artifact")
                    .map_err(authority_error)?,
            )?;
            let result_sha256 = Digest(
                row.require_text("canonical_signed_result_sha256")
                    .map_err(authority_error)?,
            );
            if inspection_result_sha256
                .replace(result_sha256)
                .is_some()
            {
                return Err(V2RuntimeError::new(
                    "attempt_state_query_inspection_result_ambiguous",
                    "attempt has more than one persisted immutable-inspection result",
                ));
            }
        }
        let ordered_classes = [
            AuthorityArtifactType::CredentialUse,
            AuthorityArtifactType::TargetEffect,
            AuthorityArtifactType::PolicyProof,
            AuthorityArtifactType::TransitionAuthorization,
            AuthorityArtifactType::ImmutableInspection,
            AuthorityArtifactType::Attestation,
            AuthorityArtifactType::ArtifactCommit,
            AuthorityArtifactType::TrustedTime,
            AuthorityArtifactType::TransparencyCheckpoint,
        ];
        let authority_artifacts = ordered_classes
            .into_iter()
            .map(|class| {
                artifacts.remove(&class).ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_artifact_missing",
                        format!(
                            "attempt lacks persisted {} authority evidence",
                            class.as_str(),
                        ),
                    )
                })
            })
            .collect::<Result<Vec<SignedAuthorityArtifact>, _>>()?;
        let root =
            ordered_authority_proof_seed_artifacts_root_sha256(
                &authority_artifacts,
            )?;
        Some(PersistedAuthorityProofMaterialV1 {
            staged_request_object:
                staged_request_object.ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_staged_object_missing",
                        "attempt lacks one unambiguous staged request object",
                    )
                })?,
            raw_response_object:
                raw_response_object.ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_raw_object_missing",
                        "attempt lacks the requested raw response object",
                    )
                })?,
            raw_response_immutable_storage_receipt_sha256:
                raw_receipt.ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_raw_receipt_missing",
                        "raw response lacks its immutable storage receipt",
                    )
                })?,
            raw_response_storage_locator:
                raw_storage_locator.ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_raw_locator_missing",
                        "raw response lacks its immutable CAS locator",
                    )
                })?,
            inspection_canonical_result_sha256:
                inspection_result_sha256.ok_or_else(|| {
                    V2RuntimeError::new(
                        "attempt_state_query_inspection_result_missing",
                        "attempt lacks its persisted immutable-inspection result digest",
                    )
                })?,
            credential_use_id,
            target_effect_id,
            policy_decision_id,
            authority_artifacts,
            authority_artifacts_root_sha256: root,
        })
    } else {
        None
    };
    transaction.commit(&deadline).map_err(authority_error)?;
    let state_sha256 = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(
            crate::canonical_json_bytes(&serde_json::json!({
                "attemptId": request.attempt_id,
                "revision": revision,
                "state": state_text,
                "stableResumeId": stable_resume_id,
                "fencingToken": fencing_token,
            }))
            .map_err(|_| {
                V2RuntimeError::new(
                    "attempt_state_query_digest_invalid",
                    "state observation cannot be canonicalized",
                )
            })?,
        ),
    );
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::StateAuthority,
        signing_key,
        ServiceOperationV1::StateCas,
        &request.operation_id,
        &request.attempt_id,
        revision,
        fencing_token,
    )?;
    let mut observation = SignedAttemptStateObservationV1 {
        api_version: ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
        generation_id: scoped.generation_id,
        generation: scoped.generation,
        operation: ServiceOperationV1::StateCas,
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        attempt_id: request.attempt_id.clone(),
        attempt_revision: revision,
        authoritative_state,
        authoritative_state_sha256: state_sha256,
        stable_resume_id,
        fencing_token,
        owner_process_id: attempt
            .require_text("owner_process_id")
            .map_err(authority_error)?,
        owner_pid: attempt
            .require_u32("owner_pid")
            .map_err(authority_error)?,
        owner_start_time_ticks: attempt
            .require_u64("owner_start_time_ticks")
            .map_err(authority_error)?,
        owner_cgroup_id: attempt
            .require_text("owner_cgroup_id")
            .map_err(authority_error)?,
        deadline_boot_id: attempt
            .require_text("deadline_boot_id")
            .map_err(authority_error)?,
        deadline_boot_millis: attempt
            .require_u64("deadline_boot_millis")
            .map_err(authority_error)?,
        proof_material,
        observation_sha256: String::new(),
        authority_scope: scope,
        signer_logical_role: signing_key.logical_role().to_owned(),
        signer_key_id: signing_key.key_id().to_owned(),
        signature: String::new(),
    };
    observation.observation_sha256 = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(
            crate::canonical_json_bytes(
                &observation
                    .without_observation_digest_and_signature(),
            )
            .map_err(|_| {
                V2RuntimeError::new(
                    "attempt_state_query_digest_invalid",
                    "state observation cannot be canonicalized",
                )
            })?,
        ),
    );
    observation.signature = signing_key.sign(
        STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN,
        &observation.without_signature(),
    )?;
    Ok(observation)
}

fn query_single_identifier(
    transaction: &mut dyn super::super::super::state_authority::
        PostgresTransaction,
    sql: &'static str,
    parameters: &[PgValue],
    column: &'static str,
) -> Result<Identifier, V2RuntimeError> {
    transaction
        .query_optional(sql, parameters)
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "attempt_state_query_binding_missing",
                format!("attempt lacks persisted {column}"),
            )
        })?
        .require_text(column)
        .map(Identifier)
        .map_err(authority_error)
}

fn collect_seed_artifact(
    config: &RootOwnedResponseObservationV2Config,
    artifacts: &mut std::collections::BTreeMap<
        super::super::super::state_authority::rpc::AuthorityArtifactType,
        super::super::super::state_authority::rpc::SignedAuthorityArtifact,
    >,
    canonical: &[u8],
) -> Result<(), V2RuntimeError> {
    use super::super::super::state_authority::rpc::{
        AuthorityArtifactType, SignedAuthorityArtifact,
    };

    let artifact: SignedAuthorityArtifact =
        crate::decode_canonical_json(canonical).map_err(|_| {
            V2RuntimeError::new(
                "attempt_state_query_artifact_invalid",
                "persisted authority evidence is not one canonical closed signed artifact",
            )
        })?;
    artifact.validate_contract().map_err(|error| {
        V2RuntimeError::new(
            "attempt_state_query_artifact_contract_invalid",
            error.to_string(),
        )
    })?;
    if let super::super::super::state_authority::rpc::
        NestedAuthorityPayload::TransparencyCheckpoint(transparency) =
        &artifact.body.payload
    {
        let verification_epoch_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                V2RuntimeError::new(
                    "attempt_state_query_transparency_clock_invalid",
                    "system clock predates the Unix epoch",
                )
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                V2RuntimeError::new(
                    "attempt_state_query_transparency_clock_invalid",
                    "system epoch milliseconds overflow u64",
                )
            })?;
        config.verify_release_transparency_artifact(
            transparency,
            artifact.body.issued_at_epoch_millis,
            verification_epoch_ms,
        )?;
    }
    let class = artifact.body.artifact_class;
    if !matches!(
        class,
        AuthorityArtifactType::CredentialUse
            | AuthorityArtifactType::TargetEffect
            | AuthorityArtifactType::PolicyProof
            | AuthorityArtifactType::TransitionAuthorization
            | AuthorityArtifactType::ImmutableInspection
            | AuthorityArtifactType::Attestation
            | AuthorityArtifactType::ArtifactCommit
            | AuthorityArtifactType::TrustedTime
            | AuthorityArtifactType::TransparencyCheckpoint
    ) {
        return Ok(());
    }
    if artifacts.insert(class, artifact).is_some() {
        return Err(V2RuntimeError::new(
            "attempt_state_query_artifact_ambiguous",
            format!(
                "attempt has more than one persisted {} artifact",
                class.as_str(),
            ),
        ));
    }
    Ok(())
}

pub(crate) fn execute_generation_postgres(
    config: &RootOwnedResponseObservationV2Config,
    frame: &GenerationRpcRequestFrame,
    signing_key: &RoleSigningKey,
    signing_credential_path: &Path,
) -> Result<ExactSignedResultBytes, V2RuntimeError> {
    if signing_key.logical_role() != "linearizable-store" {
        return Err(V2RuntimeError::new(
            "state_authority_engine_signer_invalid",
            "generation operations require the linearizable-store subkey",
        ));
    }
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let ledger = config
        .custody_topology()
        .process(CustodyServiceRole::ImmutableArtifactLedger)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_ledger_missing",
                "signed topology omits immutable-artifact-ledger",
            )
        })?;
    let timeout = std::time::Duration::from_millis(
        scoped.process.request_timeout_ms,
    );
    trusted_host_authority(
        config,
        signing_key,
        ledger,
        timeout,
        Some(signing_credential_path),
    )?
    .execute_generation_operation(frame)
    .map_err(generation_authority_error)
}

pub(crate) fn generation_reconciliation_cursor_postgres(
    config: &RootOwnedResponseObservationV2Config,
    domain: ReconciliationDomain,
) -> Result<u64, V2RuntimeError> {
    use super::super::super::state_authority::postgres::statements;

    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend = postgres_backend(config, &scoped)?;
    let instant = backend
        .current_boot_instant()
        .map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock,
        boot_id: instant.boot_id,
        deadline_boot_millis: instant
            .boot_millis
            .checked_add(scoped.process.request_timeout_ms)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_cursor_deadline_overflow",
                    "generation cursor read deadline overflowed",
                )
            })?,
    };
    let deadline = bounded_generation_read_deadline(config, deadline)?;
    let statement = match domain {
        ReconciliationDomain::ProviderGenerations => {
            statements::PROVIDER_GENERATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::RoleIdentities => {
            statements::ROLE_IDENTITIES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Operations => {
            statements::OPERATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Attempts => {
            statements::ATTEMPTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ReplayLedger => {
            statements::REPLAY_LEDGER_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TerminalSettlements => {
            statements::TERMINAL_SETTLEMENTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TargetEffects => {
            statements::TARGET_EFFECTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Fences => {
            statements::FENCES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Releases => {
            statements::RELEASES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::CredentialUses => {
            statements::CREDENTIAL_USES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::PolicyDecisions => {
            statements::POLICY_DECISIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Evidence => {
            statements::EVIDENCE_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ImmutableInspections => {
            statements::INSPECTIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Finalizations => {
            statements::FINALIZATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ImmutableObjects => {
            statements::IMMUTABLE_OBJECTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Archives => {
            statements::ARCHIVES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::PublisherOutbox => {
            statements::PUBLISHER_OUTBOX_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TransparencyLeaves => {
            statements::TRANSPARENCY_LEAVES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TransparencyCheckpoints => {
            statements::TRANSPARENCY_CHECKPOINTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TrustedTimeHighwater => {
            statements::TRUSTED_TIME_RECONCILIATION_CURSOR_SQL
        }
    };
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_error)?;
    let cursor = transaction
        .query_optional(
            statement,
            &[PgValue::Text(scoped.generation_id.clone())],
        )
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_reconciliation_cursor_missing",
                format!(
                    "{} returned no authoritative cursor",
                    domain.as_str()
                ),
            )
        })?
        .require_u64("authoritative_cursor")
        .map_err(authority_error)?;
    transaction.commit(&deadline).map_err(authority_error)?;
    Ok(cursor)
}

pub(crate) fn generation_reconciliation_checkpoint_postgres(
    config: &RootOwnedResponseObservationV2Config,
    domain: ReconciliationDomain,
) -> Result<u64, V2RuntimeError> {
    use super::super::super::state_authority::postgres::statements;

    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend = postgres_backend(config, &scoped)?;
    let instant = backend
        .current_boot_instant()
        .map_err(authority_error)?;
    let deadline = BootDeadline {
        clock: instant.clock,
        boot_id: instant.boot_id,
        deadline_boot_millis: instant
            .boot_millis
            .checked_add(scoped.process.request_timeout_ms)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_checkpoint_deadline_overflow",
                    "generation checkpoint read deadline overflowed",
                )
            })?,
    };
    let deadline = bounded_generation_read_deadline(config, deadline)?;
    let mut transaction = backend
        .begin_serializable(&deadline)
        .map_err(authority_error)?;
    let row = transaction
        .query_optional(
            statements::GENERATION_RECONCILIATION_CHECKPOINT_SQL,
            &[
                PgValue::Text(scoped.generation_id.clone()),
                PgValue::Text(domain.as_str().to_owned()),
            ],
        )
        .map_err(authority_error)?
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_reconciliation_checkpoint_missing",
                format!(
                    "{} has no durable reconciliation checkpoint",
                    domain.as_str()
                ),
            )
        })?;
    if row
        .require_text("state")
        .map_err(authority_error)?
        != "COMPLETE"
    {
        return Err(V2RuntimeError::new(
            "generation_reconciliation_checkpoint_incomplete",
            format!(
                "{} does not have a completed durable reconciliation checkpoint",
                domain.as_str()
            ),
        ));
    }
    let cursor = row
        .require_u64("authoritative_cursor")
        .map_err(authority_error)?;
    transaction.commit(&deadline).map_err(authority_error)?;
    Ok(cursor)
}

fn bounded_generation_read_deadline(
    config: &RootOwnedResponseObservationV2Config,
    mut deadline: BootDeadline,
) -> Result<BootDeadline, V2RuntimeError> {
    if config.guest_delivery.is_some() {
        let ns = deadline.deadline_boot_millis.checked_mul(1_000_000).ok_or_else(|| {
            V2RuntimeError::new("guest_backend_deadline", "backend BOOTTIME deadline overflow")
        })?;
        deadline.deadline_boot_millis = super::super::guest_delivery::bound_deadline_ns(config, ns)? / 1_000_000;
    }
    Ok(deadline)
}

fn trusted_host_authority<'a>(
    config: &RootOwnedResponseObservationV2Config,
    signing_key: &'a RoleSigningKey,
    ledger: &super::super::config::CustodyProcessBindingV1,
    timeout: std::time::Duration,
    signing_credential_path: Option<&Path>,
) -> Result<TrustedHostStateAuthority<'a>, V2RuntimeError> {
    super::super::guest_delivery::check(config)?;
    let scoped =
        config.scoped_service_config(CustodyServiceRole::StateAuthority)?;
    let backend = postgres_backend_with_timeout(
        config,
        &scoped,
        timeout,
    )?;
    let descriptor = scoped
        .process
        .role_keys
        .iter()
        .find(|descriptor| {
            descriptor.logical_role == signing_key.logical_role()
                && descriptor.key_id == signing_key.key_id()
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_signing_descriptor_missing",
                "linearizable-store key is absent from the signed process binding",
            )
        })?;
    let secret_key_path = signing_credential_path
        .unwrap_or(&descriptor.secret_key_path)
        .to_path_buf();
    let credentials_directory = if config.guest_delivery.is_some() { None } else {
        systemd_credentials_directory(&secret_key_path)?
    };
    let pinned_generation_sha256 = if let Some(owner) = &config.guest_delivery {
        owner.require_signer(signing_key.logical_role(), signing_key.key_id(), &secret_key_path)?;
        Digest(owner.generation_sha256()?.to_owned())
    } else { std::env::var(
        "SERVERWARE_RESPONSE_V2_PROVIDER_GENERATION_SHA256",
    )
    .map(Digest)
    .map_err(|_| {
        V2RuntimeError::new(
            "state_authority_generation_pin_missing",
            "SERVERWARE_RESPONSE_V2_PROVIDER_GENERATION_SHA256 is required",
        )
    })? };
    pinned_generation_sha256
        .validate("configuration.pinnedGenerationSha256")
        .map_err(authority_error)?;
    let result_signer = StateResultSigner {
        key: signing_key,
        role_id: Identifier(scoped.process.service_id.clone()),
        key_id: Identifier(signing_key.key_id().to_owned()),
        clock: backend.clone(),
        secret_key_path,
        expected_uid: scoped.process.uid,
        expected_gid: scoped.process.gid,
        credentials_directory,
        guest_delivery:config.guest_delivery.clone(),
        identity: AuthoritySignerIdentity {
            role_id: Identifier(scoped.process.service_id.clone()),
            process_id: Identifier(scoped.process.service_id.clone()),
            service_role: ServiceRole::StateAuthority,
            logical_role: Identifier(signing_key.logical_role().to_owned()),
            key_id: Identifier(signing_key.key_id().to_owned()),
            key_material_sha256: Digest(
                descriptor.public_key_sha256.clone(),
            ),
            executable_sha256: Digest(
                scoped.process.executable_sha256.clone(),
            ),
            configuration_sha256: Digest(
                scoped.process.configuration_sha256.clone(),
            ),
            allowed_operations:
                super::super::super::state_authority::services::
                    service_contract(ServiceRole::StateAuthority)
                    .operations
                    .to_vec(),
        },
    };
    let object_store = super::ledger_exact_read::Store::new(config, signing_key, ledger)?;
    let local_role_id = result_signer.identity.role_id.clone();
    let request_timeout_ms = super::super::guest_delivery::bounded_timeout_ms(config, scoped.process.request_timeout_ms)?;
    StateAuthority::new(
        backend.clone(),
        result_signer,
        object_store,
        backend.clone(),
        backend,
        StateAuthorityConfiguration {
            api_version:
                super::super::super::state_authority::contract::
                    STATE_AUTHORITY_API_VERSION
                    .to_owned(),
            schema_version:
                super::super::super::state_authority::contract::
                    STATE_AUTHORITY_SCHEMA_VERSION
                    .to_owned(),
            generation_id: Identifier(scoped.generation_id),
            pinned_generation_sha256,
            local_role_id,
            statement_timeout_millis:
                request_timeout_ms,
            lock_timeout_millis:
                request_timeout_ms.min(5_000),
            idle_transaction_timeout_millis:
                request_timeout_ms,
            cleanup_timeout_millis:
                request_timeout_ms,
            maximum_result_bytes: 64 * 1024 * 1024,
        },
    )
    .map_err(authority_error)
}

fn postgres_backend(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &super::super::config::ScopedCustodyServiceConfig,
) -> Result<PostgresUdsBackend, V2RuntimeError> {
    postgres_backend_with_timeout(
        config,
        scoped,
        std::time::Duration::from_millis(
            scoped.process.request_timeout_ms,
        ),
    )
}

fn postgres_backend_with_timeout(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &super::super::config::ScopedCustodyServiceConfig,
    timeout: std::time::Duration,
) -> Result<PostgresUdsBackend, V2RuntimeError> {
    let timeout = if config.guest_delivery.is_some() { std::time::Duration::from_millis(
        super::super::guest_delivery::bounded_timeout_ms(config,
            u64::try_from(timeout.as_millis()).map_err(|_| V2RuntimeError::new("guest_backend_timeout", "backend timeout overflow"))?)?)
    } else { timeout };
    let backend_socket_path = scoped
        .process
        .backend_socket_path
        .as_deref()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_backend_socket_missing",
                "signed state-authority process omits backendSocketPath",
            )
        })?;
    let cgroup_root = if config.guest_delivery.is_some() {
        PathBuf::from("/sys/fs/cgroup")
    } else { std::env::var_os(
        "SERVERWARE_RESPONSE_V2_CGROUP_ROOT",
    )
    .map(PathBuf::from)
    .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup")) };
    PostgresUdsBackend::from_signed_backend_socket(
        backend_socket_path,
        &scoped.process.service_id,
        timeout,
    )
    .and_then(|backend| backend.with_cgroup_root(cgroup_root))
    .map_err(authority_error)
}

fn systemd_credentials_directory(
    secret_key_path: &Path,
) -> Result<Option<PathBuf>, V2RuntimeError> {
    let Some(directory) =
        std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
    else {
        return Ok(None);
    };
    if !directory.is_absolute()
        || secret_key_path.parent() != Some(directory.as_path())
        || secret_key_path.file_name().is_none()
    {
        return Err(V2RuntimeError::new(
            "state_authority_systemd_credential_binding_invalid",
            "signed secretKeyPath must be one direct child of CREDENTIALS_DIRECTORY",
        ));
    }
    Ok(Some(directory))
}

fn validate_signing_credential(
    secret_key_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    credentials_directory: Option<&Path>,
) -> super::super::super::state_authority::AuthorityResult<()> {
    if credentials_directory
        .is_some_and(|directory| {
            secret_key_path.parent() != Some(directory)
        })
    {
        return Err(
            super::super::super::state_authority::AuthorityError::
                Authentication {
                    code: "systemd_credential_path_changed",
                    reason: "signing key left CREDENTIALS_DIRECTORY"
                        .to_owned(),
                },
        );
    }
    let metadata = fs::symlink_metadata(secret_key_path).map_err(
        |error| {
            super::super::super::state_authority::AuthorityError::
                Authentication {
                    code: "signing_credential_unavailable",
                    reason: error.to_string(),
                }
        },
    )?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != 0o400
        || metadata.nlink() != 1
    {
        return Err(
            super::super::super::state_authority::AuthorityError::
                Authentication {
                    code: "signing_credential_identity_changed",
                    reason: "signing credential no longer has its signed owner, mode, and single-link identity"
                        .to_owned(),
                },
        );
    }
    Ok(())
}

fn authority_error(
    error: super::super::super::state_authority::AuthorityError,
) -> V2RuntimeError {
    V2RuntimeError::new(
        "state_authority_engine_failed",
        error.to_string(),
    )
}

fn generation_authority_error(
    error: super::super::super::state_authority::AuthorityError,
) -> V2RuntimeError {
    use super::super::super::state_authority::AuthorityError;

    match &error {
        AuthorityError::NotReady { blockers }
            if blockers.len() == 1
                && blockers[0] == "provider_generation_missing" =>
        {
            V2RuntimeError::new(
                "state_authority_generation_not_installed",
                error.to_string(),
            )
        }
        AuthorityError::Conflict { code, .. }
            if *code == "generation_already_installed" =>
        {
            V2RuntimeError::new(
                "state_authority_generation_already_installed",
                error.to_string(),
            )
        }
        _ => authority_error(error),
    }
}
