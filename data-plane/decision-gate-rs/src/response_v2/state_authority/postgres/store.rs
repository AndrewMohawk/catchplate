use super::statements;
#[path = "staged_originals.rs"]
mod staged_originals;
#[path = "native_staging_journal.rs"]
mod native_staging_journal;
pub(crate) use native_staging_journal::{NativeStagingClaim,NativeStagingClaimResult};
#[path = "native_staging_predecessor.rs"]
mod native_staging_predecessor;
pub use staged_originals::{CommittedRequestOriginalV1, StagedAttemptOriginalV1};
use super::super::canonical::{
    canonical_jcs_bytes, decode_base64url, encode_base64url, sha256_digest,
};
use super::super::contract::{
    AuthorityError, AuthorityResult, BootClock, BootDeadline, BootInstant,
    CgroupObserver, CgroupOwner, Digest, Identifier,
    StateAuthorityConfiguration,
    STATE_AUTHORITY_API_VERSION,
    STATE_AUTHORITY_GENERATION_RESULT_KIND,
    STATE_AUTHORITY_RESULT_KIND, STATE_AUTHORITY_SCHEMA_VERSION,
};
use super::super::lifecycle::{
    AttemptState, FenceState, OperationKind, ReconciliationDomain,
    ReconciliationState, TargetEffectState,
};
use super::super::rpc::{
    derive_generation_readiness_scope,
    sign_authority_artifact, sign_generation_operation_result,
    sign_operation_result, sign_release_preparation_mutation_receipt,
    verify_authority_artifact, verify_generation_request_frame,
    verify_release_preparation_mutation_receipt, verify_request_frame,
    verify_signed_checkpoint, verify_signed_operation_result,
    AcknowledgePublicationMutation, AdvanceTrustedTimeMutation,
    AppendEvidenceMutation, ArchiveMutation, AuthorityResultSigner,
    BeginDispatchMutation, CommitRawObjectMutation,
    ConsumeReleaseAndRetrieveExactMutation, EnqueuePublicationMutation,
    FinalizeMutation, GenerationReadyMutation, ImmutableInspectionArtifact,
    ImmutableInspectionResult, ImmutableRawObject,
    GenerationMutationPayload, GenerationOperationResultBody,
    GenerationReconcileMutation, GenerationRpcRequestFrame,
    InspectImmutableRawMutation, MutationPayload, NestedAuthorityPayload,
    ObserveQuiescenceMutation, OperationResultBody,
    PrepareReleaseConsumptionMutation,
    PublishCheckpointMutation, PublishMutation, RawObjectReference,
    RecordDispatchOutcomeMutation, ReconciliationMutation,
    ReleasePreparationDurableResult, ReleasePreparationMutationReceiptBody,
    ReleasePreparationReceiptArtifact, ReleasePreparationResult,
    ReleaseRetrievalResult, ReplayResolutionResult, ReserveMutation,
    ResolveReplayMutation, ResponseDataStateResult,
    RetrievePreparedReleaseMutation,
    ResultDisposition, RevokeFenceMutation, RpcRequest, RpcRequestFrame,
    SettleAttemptMutation, SettlementResult, SignedAuthorityArtifact,
    SignedOperationResult, StageMutation,
    TerminalizeExpiredAttemptMutation, TerminalizeMutation,
};
use super::super::services::{
    artifact_contract_allows, service_contract,
    validate_service_operation_matrix,
};
use super::super::topology::{
    GenerationStatus, ProviderGeneration, RoleIdentity, ServiceRole,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_RAW_OBJECT_BYTES: usize = 34_603_008;

#[derive(Debug, Clone, PartialEq)]
pub enum PgValue {
    Null,
    Text(String),
    I64(i64),
    U64(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Json(Value),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PgRow {
    pub columns: BTreeMap<String, PgValue>,
}

impl PgRow {
    pub fn require_text(
        &self,
        column: &'static str,
    ) -> AuthorityResult<String> {
        match self.columns.get(column) {
            Some(PgValue::Text(value)) => Ok(value.clone()),
            value => Err(row_type_error(column, "text", value)),
        }
    }

    pub fn optional_text(
        &self,
        column: &'static str,
    ) -> AuthorityResult<Option<String>> {
        match self.columns.get(column) {
            Some(PgValue::Text(value)) => Ok(Some(value.clone())),
            Some(PgValue::Null) | None => Ok(None),
            value => Err(row_type_error(column, "nullable text", value)),
        }
    }

    pub fn require_u64(
        &self,
        column: &'static str,
    ) -> AuthorityResult<u64> {
        match self.columns.get(column) {
            Some(PgValue::U64(value)) => Ok(*value),
            Some(PgValue::I64(value)) if *value >= 0 => Ok(*value as u64),
            value => Err(row_type_error(column, "nonnegative integer", value)),
        }
    }

    pub fn require_u32(
        &self,
        column: &'static str,
    ) -> AuthorityResult<u32> {
        self.require_u64(column)?
            .try_into()
            .map_err(|_| AuthorityError::Backend {
                code: "row_value_out_of_range",
                reason: format!("{column} is not a u32"),
            })
    }

    pub fn require_bool(
        &self,
        column: &'static str,
    ) -> AuthorityResult<bool> {
        match self.columns.get(column) {
            Some(PgValue::Bool(value)) => Ok(*value),
            value => Err(row_type_error(column, "boolean", value)),
        }
    }

    pub fn require_bytes(
        &self,
        column: &'static str,
    ) -> AuthorityResult<Vec<u8>> {
        match self.columns.get(column) {
            Some(PgValue::Bytes(value)) => Ok(value.clone()),
            value => Err(row_type_error(column, "bytes", value)),
        }
    }

    pub fn optional_bytes(
        &self,
        column: &'static str,
    ) -> AuthorityResult<Option<Vec<u8>>> {
        match self.columns.get(column) {
            Some(PgValue::Bytes(value)) => Ok(Some(value.clone())),
            Some(PgValue::Null) | None => Ok(None),
            value => Err(row_type_error(column, "nullable bytes", value)),
        }
    }

    pub fn require_json(
        &self,
        column: &'static str,
    ) -> AuthorityResult<Value> {
        match self.columns.get(column) {
            Some(PgValue::Json(value)) => Ok(value.clone()),
            value => Err(row_type_error(column, "JSON", value)),
        }
    }
}

fn row_type_error(
    column: &'static str,
    expected: &'static str,
    actual: Option<&PgValue>,
) -> AuthorityError {
    AuthorityError::Backend {
        code: "unexpected_postgres_row",
        reason: format!(
            "column {column} expected {expected}, received {actual:?}"
        ),
    }
}

/// Adapter for one PostgreSQL `SERIALIZABLE` transaction.
///
/// Implementations must rollback on drop unless `commit` succeeded. They must
/// not retry statements or the transaction internally; serialization failures
/// are returned to the caller and retried only with the exact request frame.
pub trait PostgresTransaction {
    fn execute(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<u64>;

    fn query_optional(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<Option<PgRow>>;

    fn query_many(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<Vec<PgRow>>;

    fn commit(
        self: Box<Self>,
        deadline: &BootDeadline,
    ) -> AuthorityResult<()>;
}

pub trait PostgresBackend: Send + Sync {
    fn begin_serializable(
        &self,
        deadline: &BootDeadline,
    ) -> AuthorityResult<Box<dyn PostgresTransaction + '_>>;
}

/// Read-only access to bytes already committed by ImmutableArtifactLedger.
///
/// Implementations must authenticate the CAS receipt and return exactly the
/// content identified by the supplied digest and length. They must not fetch
/// upstream content, follow redirects, or mutate the object.
pub trait ImmutableObjectStore: Send + Sync {
    fn retrieve_exact(
        &self,
        generation_id: &Identifier,
        object_id: &Identifier,
        storage_locator: &str,
        immutable_storage_receipt_sha256: &Digest,
        expected_content_sha256: &Digest,
        expected_content_length: u64,
        deadline: &BootDeadline,
    ) -> AuthorityResult<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSignedResultBytes {
    pub canonical_bytes: Vec<u8>,
    pub canonical_sha256: Digest,
}

#[derive(Debug, Clone)]
struct LockedAttempt {
    revision: u64,
    state: AttemptState,
    fence_token: Identifier,
    stable_resume_id: Identifier,
    owner_process_id: Identifier,
    owner_pid: u32,
    owner_start_time_ticks: u64,
    owner_cgroup_id: Identifier,
    deadline_boot_id: Identifier,
    deadline_boot_millis: u64,
}

#[derive(Debug, Clone)]
struct LockedFence {
    fence_token: Identifier,
    state: FenceState,
    owner_process_id: Identifier,
    owner_pid: u32,
    owner_start_time_ticks: u64,
    owner_cgroup_id: Identifier,
}

#[derive(Debug)]
struct AppliedMutation {
    revision: u64,
    state: AttemptState,
    fence_token: Identifier,
    stable_resume_id: Identifier,
    disposition: ResultDisposition,
    conflict_code: Option<Identifier>,
    artifact_ids: Vec<Identifier>,
    deferred_inspection: Option<DeferredInspection>,
    deferred_release: Option<DeferredRelease>,
    retrieved_immutable_raw: Option<ImmutableRawObject>,
    response_data_result: Option<ResponseDataStateResult>,
}

#[derive(Debug)]
struct DeferredInspection {
    inspection_id: Identifier,
    object_reference: RawObjectReference,
    immutable_storage_receipt_sha256: Digest,
    inspection_purpose_sha256: Digest,
    inspected_at: BootInstant,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
}

#[derive(Debug)]
struct LockedInspection {
    inspection_id: Identifier,
    inspection_operation_id: Identifier,
    attempt_id: Identifier,
    object_id: Identifier,
    object_sha256: Digest,
    object_length: u64,
    inspection_purpose_sha256: Digest,
    inspection_artifact_sha256: Digest,
    canonical_signed_result_sha256: Digest,
}

#[derive(Debug, Clone)]
struct LockedReleasePreparation {
    authorization_id: Identifier,
    finalization_id: Identifier,
    exact_release_request_sha256: Digest,
    inspection_result_sha256: Digest,
    release_object_sha256: Digest,
    client_binding_sha256: Digest,
    one_use_nonce_sha256: Digest,
    canonical_signed_result_sha256: Digest,
    preparation: ReleasePreparationResult,
}

#[derive(Debug)]
struct DeferredRelease {
    authorization_id: Identifier,
    finalization_id: Identifier,
    exact_release_request_sha256: Digest,
    inspection_result_sha256: Digest,
    release_object_sha256: Digest,
    client_binding_sha256: Digest,
    exact_replay_key_sha256: Digest,
    one_use_nonce_sha256: Digest,
    preauthorization_artifact_id: Identifier,
    preauthorization_artifact_sha256: Digest,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableTransitionRootEntry {
    operation_id: Identifier,
    operation: String,
    exact_request_sha256: Digest,
    expected_revision: u64,
    expected_state: String,
    fence_token: Identifier,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableEvidenceRootEntry {
    evidence_id: Identifier,
    evidence_type: Identifier,
    producing_role_id: Identifier,
    canonical_artifact_sha256: Digest,
    object_sha256: Option<Digest>,
}

pub struct StateAuthority<B, S, O, C, G> {
    backend: B,
    signer: S,
    immutable_object_store: O,
    boot_clock: C,
    cgroup_observer: G,
    configuration: StateAuthorityConfiguration,
}

impl<B, S, O, C, G> StateAuthority<B, S, O, C, G>
where
    B: PostgresBackend,
    S: AuthorityResultSigner,
    O: ImmutableObjectStore,
    C: BootClock,
    G: CgroupObserver,
{
    pub fn new(
        backend: B,
        signer: S,
        immutable_object_store: O,
        boot_clock: C,
        cgroup_observer: G,
        configuration: StateAuthorityConfiguration,
    ) -> AuthorityResult<Self> {
        configuration.validate()?;
        if signer.role_id() != &configuration.local_role_id {
            return Err(AuthorityError::InvalidContract {
                field: "configuration.localRoleId",
                reason: "result signer role does not match local role"
                    .to_owned(),
            });
        }
        Ok(Self {
            backend,
            signer,
            immutable_object_store,
            boot_clock,
            cgroup_observer,
            configuration,
        })
    }

    pub fn execute_mutation(
        &self,
        frame: &RpcRequestFrame,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        self.execute_mutation_profile(frame, false, None)
    }

    /// Additive custody profile; reject a legacy database before any mutation.
    pub fn execute_sequence_mutation(
        &self,
        frame: &RpcRequestFrame,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        self.execute_mutation_profile(frame, true, None)
    }

    fn execute_mutation_profile(
        &self,
        frame: &RpcRequestFrame,
        require_sequence_originals: bool,
        native_stage: Option<&native_staging_predecessor::StageCompanion<'_>>,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        frame.request.validate()?;
        if frame.request.generation_id
            != self.configuration.generation_id
        {
            return Err(AuthorityError::InvalidContract {
                field: "request.generationId",
                reason: "request does not target the configured generation"
                    .to_owned(),
            });
        }
        self.assert_deadline(&frame.request.deadline)?;
        let exact_request_bytes = canonical_jcs_bytes(frame)?;
        let exact_request_sha256 = sha256_digest(&exact_request_bytes);

        let mut transaction = self
            .backend
            .begin_serializable(&frame.request.deadline)?;
        self.configure_transaction(transaction.as_mut())?;
        let (generation, generation_status) =
            self.lock_generation(transaction.as_mut())?;
        if require_sequence_originals
            && !super::sequence_originals::profile(&generation.migration_sha256)?.retains_originals()
        {
            return Err(super::sequence_originals::refused(
                "sequence custody execution requires the independently pinned fresh database profile",
            ));
        }
        let retains_original = super::sequence_originals::profile(&generation.migration_sha256)?.retains_originals()
            && matches!(frame.request.operation, OperationKind::AttemptReserve
                | OperationKind::AttemptStage | OperationKind::DispatchBegin);
        if retains_original && exact_request_bytes.len() > super::sequence_originals::MAX_ORIGINAL_BYTES {
            return Err(super::sequence_originals::refused("request original exceeds the explicit custody return bound"));
        }
        self.enforce_generation_status(
            generation_status,
            frame.request.operation,
        )?;

        let caller_identity =
            self.lock_role(transaction.as_mut(), &frame.request)?;
        let canonical_caller = generation
            .topology
            .roles
            .iter()
            .find(|identity| identity.role_id == caller_identity.role_id)
            .ok_or_else(|| AuthorityError::Authentication {
                code: "caller_role_absent_from_signed_generation",
                reason: "database role is not in the signed generation"
                    .to_owned(),
            })?;
        if canonical_caller != &caller_identity {
            return Err(AuthorityError::Backend {
                code: "role_identity_generation_mismatch",
                reason: "database role identity differs from the signed generation"
                    .to_owned(),
            });
        }
        let local_authority =
            generation.role(ServiceRole::StateAuthority)?;
        if local_authority.role_id != self.configuration.local_role_id
            || local_authority.key_id.as_ref()
                != Some(self.signer.key_id())
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "state_authority_signer_not_generation_bound".to_owned(),
                ],
            });
        }
        verify_request_frame(frame, &generation, &caller_identity)?;
        let service = service_contract(caller_identity.role);
        if !service.operations.contains(&frame.request.operation) {
            return Err(AuthorityError::Authentication {
                code: "service_contract_operation_denied",
                reason: format!(
                    "{} cannot call {}",
                    caller_identity.role.as_str(),
                    frame.request.operation.as_str()
                ),
            });
        }

        let locked_attempt =
            self.lock_attempt(transaction.as_mut(), &frame.request)?;
        if let Some(existing) = self.lock_operation(
            transaction.as_mut(),
            &frame.request,
        )? {
            return self.return_existing_operation(
                transaction,
                existing,
                &exact_request_sha256,
                &frame.request.deadline,
            );
        }
        if let MutationPayload::ConsumeReleaseAndRetrieveExact(release) =
            &frame.request.payload
        {
            if let ConsumeReleaseAndRetrieveExactMutation::Prepare(
                preparation,
            ) = release
            {
                let replay_trusted_epoch_millis = self.lock_trusted_time(
                    transaction.as_mut(),
                    &generation,
                    frame.request.operation,
                )?;
                let (finalization_id, one_use_nonce_sha256) =
                    self.verify_release_preparation_artifacts(
                        &generation,
                        &frame.request,
                        preparation,
                        replay_trusted_epoch_millis,
                    )?;
                if let Some(existing) = self.lock_release_replay(
                    transaction.as_mut(),
                    &generation,
                    &frame.request,
                    preparation,
                    &finalization_id,
                    &one_use_nonce_sha256,
                )? {
                    self.assert_deadline(&frame.request.deadline)?;
                    transaction.commit(&frame.request.deadline)?;
                    return Ok(existing);
                }
            }
        }

        if frame.request.operation == OperationKind::AttemptReserve {
            if locked_attempt.is_some() {
                return Err(AuthorityError::Conflict {
                    code: "attempt_already_exists_without_replay_record",
                    authoritative_state: locked_attempt
                        .as_ref()
                        .map(|attempt| attempt.state.as_str().to_owned()),
                });
            }
        } else {
            self.validate_attempt_expectation(
                locked_attempt.as_ref(),
                &frame.request,
            )?;
        }

        if let Err(error) = self.insert_prepared_operation(
            transaction.as_mut(),
            &frame.request,
            &exact_request_sha256,
        ) {
            drop(transaction);
            return self.handle_operation_failure(
                frame,
                &exact_request_sha256,
                error,
            );
        }

        let locked_fence = if frame.request.operation
            == OperationKind::AttemptReserve
        {
            None
        } else {
            let attempt = locked_attempt.as_ref().ok_or_else(|| {
                AuthorityError::Conflict {
                    code: "attempt_missing",
                    authoritative_state: None,
                }
            })?;
            match self.lock_and_validate_fence(
                transaction.as_mut(),
                &frame.request,
                attempt,
            ) {
                Ok(fence) => Some(fence),
                Err(error @ AuthorityError::Conflict { .. }) => {
                    return Err(error)
                }
                Err(error) => {
                    drop(transaction);
                    return self.handle_operation_failure(
                        frame,
                        &exact_request_sha256,
                        error,
                    );
                }
            }
        };

        let trusted_epoch_millis = match self.lock_trusted_time(
            transaction.as_mut(),
            &generation,
            frame.request.operation,
        ) {
            Ok(value) => value,
            Err(error) => {
                drop(transaction);
                return self.handle_operation_failure(
                    frame,
                    &exact_request_sha256,
                    error,
                );
            }
        };
        if let Err(error) = transaction.execute(
            statements::CREATE_MUTATION_SAVEPOINT_SQL,
            &[],
        ) {
            drop(transaction);
            return self.handle_operation_failure(
                frame,
                &exact_request_sha256,
                error,
            );
        }
        let applied_result = self.apply_mutation(
            transaction.as_mut(),
            &generation,
            &frame.request,
            locked_attempt.as_ref(),
            locked_fence.as_ref(),
            trusted_epoch_millis,
            native_stage,
        );
        let applied = match applied_result {
            Ok(applied) => {
                if let Err(error) = self.retain_attempt_request_original(
                    transaction.as_mut(), &generation, frame, &exact_request_sha256, &applied,
                ) {
                    drop(transaction);
                    return self.handle_operation_failure(frame, &exact_request_sha256, error);
                }
                if let Err(error) = transaction.execute(
                    statements::RELEASE_MUTATION_SAVEPOINT_SQL,
                    &[],
                ) {
                    drop(transaction);
                    return self.handle_operation_failure(
                        frame,
                        &exact_request_sha256,
                        error,
                    );
                }
                applied
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.execute(
                    statements::ROLLBACK_MUTATION_SAVEPOINT_SQL,
                    &[],
                ) {
                    drop(transaction);
                    return self.handle_operation_failure(
                        frame,
                        &exact_request_sha256,
                        rollback_error,
                    );
                }
                if Self::requires_exact_phase_rollback(
                    frame.request.operation,
                ) {
                    drop(transaction);
                    return Err(error);
                }
                match (locked_attempt.as_ref(), locked_fence.as_ref()) {
                    (Some(attempt), Some(fence)) => {
                        match self.recover_post_reservation_error(
                            transaction.as_mut(),
                            &frame.request,
                            attempt,
                            fence,
                            error,
                        ) {
                            Ok(applied) => applied,
                            Err(error) => {
                                drop(transaction);
                                return self
                                    .handle_operation_failure(
                                        frame,
                                        &exact_request_sha256,
                                        error,
                                    );
                            }
                        }
                    }
                    _ => return Err(error),
                }
            }
        };
        match self.finish_mutation(
            transaction,
            frame,
            &exact_request_sha256,
            applied,
            &frame.request.deadline,
            retains_original,
        ) {
            Ok(result) => Ok(result),
            Err(error) => self.handle_operation_failure(
                frame,
                &exact_request_sha256,
                error,
            ),
        }
    }

    fn finish_mutation(
        &self,
        mut transaction: Box<dyn PostgresTransaction + '_>,
        frame: &RpcRequestFrame,
        exact_request_sha256: &Digest,
        mut applied: AppliedMutation,
        completion_deadline: &BootDeadline,
        retains_original: bool,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        let immutable_inspection = applied
            .deferred_inspection
            .as_ref()
            .map(|inspection| {
                self.build_immutable_inspection_result(
                    &frame.request,
                    applied.revision,
                    &applied.fence_token,
                    inspection,
                    completion_deadline,
                )
            })
            .transpose()?;
        if let Some(release) = applied.deferred_release.as_ref() {
            let preparation = self.build_release_preparation_result(
                &frame.request,
                exact_request_sha256,
                applied.revision,
                applied.state,
                &applied.fence_token,
                &applied.stable_resume_id,
                release,
                completion_deadline,
            )?;
            applied.artifact_ids.push(
                preparation
                    .release_preparation_receipt
                    .body
                    .artifact_id
                    .clone(),
            );
            applied.response_data_result = Some(
                ResponseDataStateResult::ReleasePreparation(preparation),
            );
        }
        let result_body = OperationResultBody {
            api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
            kind: STATE_AUTHORITY_RESULT_KIND.to_owned(),
            schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
            generation_id: frame.request.generation_id.clone(),
            request_id: frame.request.request_id.clone(),
            operation_id: frame.request.operation_id.clone(),
            exact_request_sha256: exact_request_sha256.clone(),
            operation: frame.request.operation,
            attempt_id: frame.request.attempt_id.clone(),
            disposition: applied.disposition,
            authoritative_revision: applied.revision,
            authoritative_state: applied.state,
            fence_token: applied.fence_token.clone(),
            stable_resume_id: applied.stable_resume_id.clone(),
            result_artifact_ids: applied.artifact_ids,
            conflict_code: applied.conflict_code,
            immutable_inspection,
            retrieved_immutable_raw: applied.retrieved_immutable_raw,
            response_data_result: applied.response_data_result,
        };
        let (signed_result, exact_result_bytes) =
            sign_operation_result(
                &self.signer,
                result_body,
                completion_deadline,
            )?;
        if exact_result_bytes.len()
            > self.configuration.maximum_result_bytes as usize
            || (retains_original && exact_result_bytes.len() > super::sequence_originals::MAX_ORIGINAL_BYTES)
        {
            return Err(AuthorityError::InvalidContract {
                field: "operationResult",
                reason: "signed result exceeds configured limit".to_owned(),
            });
        }
        let exact_result_sha256 = sha256_digest(&exact_result_bytes);

        if let Some(inspection) = &signed_result.body.immutable_inspection {
            self.persist_inspection_result(
                transaction.as_mut(),
                &frame.request,
                inspection,
                &exact_result_bytes,
                &exact_result_sha256,
            )?;
        }
        if let Some(release) = applied.deferred_release {
            self.persist_release_result(
                transaction.as_mut(),
                &frame.request,
                &release,
                &exact_result_bytes,
                &exact_result_sha256,
            )?;
        }
        self.append_transparency_leaf(
            transaction.as_mut(),
            &frame.request.generation_id,
            &exact_result_bytes,
            &exact_result_sha256,
        )?;
        let signature_json =
            serde_json::to_value(&signed_result.authentication).map_err(
                |error| AuthorityError::Serialization {
                    reason: error.to_string(),
                },
            )?;
        let operation_status = if matches!(
            applied.disposition,
            ResultDisposition::Conflict | ResultDisposition::Rejected
        ) {
            "FAILED"
        } else {
            "COMMITTED"
        };
        let committed = transaction.execute(
            statements::COMMIT_OPERATION_SQL,
            &[
                text(&frame.request.generation_id),
                text(&frame.request.operation_id),
                PgValue::Text(operation_status.to_owned()),
                PgValue::Bytes(exact_result_bytes.clone()),
                text_digest(&exact_result_sha256),
                PgValue::Json(signature_json),
            ],
        )?;
        if committed != 1 {
            return Err(AuthorityError::Backend {
                code: "operation_terminalization_failed",
                reason:
                    "prepared operation was not terminalized exactly once"
                        .to_owned(),
            });
        }
        let replay_inserted = transaction.execute(
            statements::INSERT_REPLAY_RESULT_SQL,
            &[
                text(&frame.request.generation_id),
                text(&frame.request.request_id),
                text(&frame.request.operation_id),
                text_digest(exact_request_sha256),
                PgValue::Bytes(exact_result_bytes.clone()),
                text_digest(&exact_result_sha256),
            ],
        )?;
        if replay_inserted != 1 {
            return Err(AuthorityError::Backend {
                code: "replay_result_persist_failed",
                reason: "terminal result was not persisted exactly once"
                    .to_owned(),
            });
        }
        completion_deadline.ensure_current(
            &self.boot_clock.current_boot_instant()?,
        )?;
        transaction.commit(completion_deadline)?;
        Ok(ExactSignedResultBytes {
            canonical_bytes: exact_result_bytes,
            canonical_sha256: exact_result_sha256,
        })
    }

    const fn requires_exact_phase_rollback(
        operation: OperationKind,
    ) -> bool {
        matches!(
            operation,
            OperationKind::ReleaseConsumeAndRetrieveExact
                | OperationKind::ReleaseResolveReplay
                | OperationKind::AttemptSettle
        )
    }

    fn handle_operation_failure(
        &self,
        frame: &RpcRequestFrame,
        exact_request_sha256: &Digest,
        error: AuthorityError,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        if Self::requires_exact_phase_rollback(frame.request.operation) {
            Err(error)
        } else {
            self.settle_post_reservation_failure(
                frame,
                exact_request_sha256,
                error,
            )
        }
    }

    fn settle_post_reservation_failure(
        &self,
        frame: &RpcRequestFrame,
        exact_request_sha256: &Digest,
        original_error: AuthorityError,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        let cleanup_instant =
            self.boot_clock.current_boot_instant()?;
        let cleanup_deadline_boot_millis = cleanup_instant
            .boot_millis
            .checked_add(self.configuration.cleanup_timeout_millis)
            .ok_or_else(|| AuthorityError::Backend {
                code: "cleanup_deadline_overflow",
                reason: original_error.to_string(),
            })?;
        let cleanup_deadline = BootDeadline {
            clock: "CLOCK_BOOTTIME".to_owned(),
            boot_id: cleanup_instant.boot_id,
            deadline_boot_millis: cleanup_deadline_boot_millis,
        };
        cleanup_deadline.validate()?;

        let settlement = (|| {
            let mut transaction = self
                .backend
                .begin_serializable(&cleanup_deadline)?;
            self.configure_transaction(transaction.as_mut())?;
            let _ = self.lock_generation(transaction.as_mut())?;
            if let Some(existing) = self.lock_operation(
                transaction.as_mut(),
                &frame.request,
            )? {
                if existing.require_text("status")? != "PREPARED" {
                    return self.return_existing_operation(
                        transaction,
                        existing,
                        exact_request_sha256,
                        &cleanup_deadline,
                    );
                }
            } else {
                self.insert_prepared_operation(
                    transaction.as_mut(),
                    &frame.request,
                    exact_request_sha256,
                )?;
            }
            let attempt = self
                .lock_attempt(transaction.as_mut(), &frame.request)?
                .ok_or_else(|| AuthorityError::Conflict {
                    code: "post_reservation_attempt_missing",
                    authoritative_state: None,
                })?;
            let fence = self.lock_fence_for_settlement(
                transaction.as_mut(),
                &frame.request.generation_id,
                &frame.request.attempt_id,
                &attempt,
            )?;
            let failure_code = authority_error_code(&original_error);
            let terminal_detail_sha256 =
                sha256_digest(&canonical_jcs_bytes(&(
                    "POST_RESERVATION_SETTLEMENT",
                    &attempt.stable_resume_id,
                    failure_code,
                    &frame.request.operation_id,
                    &cleanup_deadline.boot_id,
                    cleanup_deadline.deadline_boot_millis,
                    &fence.fence_token,
                ))?);
            let (revision, state) = if attempt.state.is_terminal() {
                (attempt.revision, attempt.state)
            } else {
                let row = transaction
                    .query_optional(
                        statements::TERMINALIZE_ATTEMPT_SQL,
                        &[
                            text(&frame.request.generation_id),
                            text(&frame.request.attempt_id),
                            PgValue::U64(attempt.revision),
                            PgValue::Text(
                                attempt.state.as_str().to_owned(),
                            ),
                            text(&fence.fence_token),
                            PgValue::Text(
                                "POST_RESERVATION_SETTLEMENT".to_owned(),
                            ),
                            text_digest(&terminal_detail_sha256),
                        ],
                    )?
                    .ok_or_else(|| AuthorityError::Conflict {
                        code: "post_reservation_terminalize_cas_failed",
                        authoritative_state: Some(
                            attempt.state.as_str().to_owned(),
                        ),
                    })?;
                let revision = row.require_u64("revision")?;
                let revoked = transaction.query_optional(
                    statements::REVOKE_FENCE_SQL,
                    &[
                        text(&frame.request.generation_id),
                        text(&frame.request.attempt_id),
                        PgValue::U64(revision),
                    ],
                )?;
                if revoked.is_none() {
                    return Err(AuthorityError::Conflict {
                        code: "post_reservation_fence_revoke_failed",
                        authoritative_state: Some(
                            fence.fence_token.0,
                        ),
                    });
                }
                (revision, AttemptState::TerminalFailed)
            };
            self.finish_mutation(
                transaction,
                frame,
                exact_request_sha256,
                AppliedMutation {
                    revision,
                    state,
                    fence_token: attempt.fence_token,
                    stable_resume_id: attempt.stable_resume_id,
                    disposition: ResultDisposition::Rejected,
                    conflict_code: Some(Identifier(
                        failure_code.to_owned(),
                    )),
                    artifact_ids: Vec::new(),
                    deferred_inspection: None,
                    deferred_release: None,
                    retrieved_immutable_raw: None,
                    response_data_result: None,
                },
                &cleanup_deadline,
                false,
            )
        })();

        settlement.map_err(|settlement_error| {
            AuthorityError::Backend {
                code: "post_reservation_settlement_failed",
                reason: format!(
                    "original={}; settlement={}",
                    original_error, settlement_error
                ),
            }
        })
    }

    fn lock_fence_for_settlement(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        attempt_id: &Identifier,
        attempt: &LockedAttempt,
    ) -> AuthorityResult<LockedFence> {
        let row = transaction
            .query_optional(
                statements::LOCK_FENCE_SQL,
                &[text(generation_id), text(attempt_id)],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "settlement_fence_missing",
                authoritative_state: None,
            })?;
        let fence = LockedFence {
            fence_token: Identifier(row.require_text("fence_token")?),
            state: parse_fence_state(&row.require_text("state")?)?,
            owner_process_id: Identifier(
                row.require_text("owner_process_id")?,
            ),
            owner_pid: row.require_u32("owner_pid")?,
            owner_start_time_ticks:
                row.require_u64("owner_start_time_ticks")?,
            owner_cgroup_id: Identifier(
                row.require_text("owner_cgroup_id")?,
            ),
        };
        if fence.fence_token != attempt.fence_token
            || fence.owner_process_id != attempt.owner_process_id
            || fence.owner_pid != attempt.owner_pid
            || fence.owner_start_time_ticks
                != attempt.owner_start_time_ticks
            || fence.owner_cgroup_id != attempt.owner_cgroup_id
        {
            return Err(AuthorityError::Backend {
                code: "settlement_fence_attempt_mismatch",
                reason: "settlement fence does not match durable attempt"
                    .to_owned(),
            });
        }
        Ok(fence)
    }

    pub fn execute_generation_operation(
        &self,
        frame: &GenerationRpcRequestFrame,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        frame.request.validate()?;
        if frame.request.generation_id
            != self.configuration.generation_id
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationRequest.generationId",
                reason: "request does not target the configured generation"
                    .to_owned(),
            });
        }
        let request_instant =
            self.boot_clock.current_boot_instant()?;
        frame.request.deadline.ensure_current(&request_instant)?;
        let exact_request_bytes = canonical_jcs_bytes(frame)?;
        let exact_request_sha256 = sha256_digest(&exact_request_bytes);

        match &frame.request.payload {
            GenerationMutationPayload::Install(mutation) => {
                mutation.generation.validate()?;
                validate_service_operation_matrix(
                    &mutation.generation.topology,
                )?;
                if mutation.generation.generation_id
                    != frame.request.generation_id
                {
                    return Err(AuthorityError::InvalidContract {
                        field: "generationInstall.generation.generationId",
                        reason: "installed generation must match the frame"
                            .to_owned(),
                    });
                }
                let canonical_generation =
                    canonical_jcs_bytes(&mutation.generation)?;
                let generation_sha256 =
                    sha256_digest(&canonical_generation);
                // Selection is from the independently pinned original, not a
                // missing-column probe or a caller success/profile flag.
                super::sequence_originals::require_database(
                    transaction.as_mut(), &mutation.generation.migration_sha256,
                )?;
                if generation_sha256
                    != mutation.canonical_generation_sha256
                    || generation_sha256
                        != self.configuration.pinned_generation_sha256
                {
                    return Err(AuthorityError::InvalidContract {
                        field: "generationInstall",
                        reason: "generation or migration digest is not the locally pinned response-v2 source"
                            .to_owned(),
                    });
                }
                let caller = mutation
                    .generation
                    .topology
                    .roles
                    .iter()
                    .find(|role| {
                        role.role_id == frame.request.caller_role_id
                    })
                    .ok_or_else(|| AuthorityError::Authentication {
                        code: "generation_install_caller_unassigned",
                        reason: "install caller is absent from the proposed generation"
                            .to_owned(),
                    })?;
                if caller.role != ServiceRole::StateAuthority {
                    return Err(AuthorityError::Authentication {
                        code: "generation_install_role_denied",
                        reason: "only the proposed state-authority identity may install its pinned generation"
                            .to_owned(),
                    });
                }
                self.verify_local_signer(
                    &mutation.generation,
                )?;
                verify_generation_request_frame(
                    frame,
                    &mutation.generation,
                    caller,
                )?;

                let mut transaction = self
                    .backend
                    .begin_serializable(&frame.request.deadline)?;
                self.configure_transaction(transaction.as_mut())?;
                let existing = transaction.query_optional(
                    statements::LOCK_GENERATION_SQL,
                    &[text(&frame.request.generation_id)],
                )?;
                if let Some(existing_generation) = existing {
                    let (stored, status, stored_sha256) =
                        self.parse_generation_row(existing_generation)?;
                    if stored != mutation.generation
                        || stored_sha256 != generation_sha256
                    {
                        return Err(AuthorityError::Conflict {
                            code: "generation_install_conflict",
                            authoritative_state: Some(stored_sha256.0),
                        });
                    }
                    if let Some(operation) = self.lock_operation_by_id(
                        transaction.as_mut(),
                        &frame.request.generation_id,
                        &frame.request.operation_id,
                    )? {
                        return self.return_existing_operation(
                            transaction,
                            operation,
                            &exact_request_sha256,
                            &frame.request.deadline,
                        );
                    }
                    return Err(AuthorityError::Conflict {
                        code: "generation_already_installed",
                        authoritative_state: Some(format!("{status:?}")),
                    });
                }
                self.insert_generation(
                    transaction.as_mut(),
                    &mutation.generation,
                    &canonical_generation,
                    &generation_sha256,
                )?;
                self.insert_generation_operation(
                    transaction.as_mut(),
                    frame,
                    &exact_request_sha256,
                )?;
                let (completed_domains, blockers) =
                    self.generation_reconciliation_status(
                        transaction.as_mut(),
                        &frame.request.generation_id,
                    )?;
                self.finish_generation_operation(
                    transaction,
                    frame,
                    &exact_request_sha256,
                    GenerationStatus::Reconciling,
                    None,
                    generation_sha256,
                    completed_domains,
                    blockers,
                    Vec::new(),
                )
            }
            GenerationMutationPayload::Reconcile(mutation) => {
                let mut transaction = self
                    .backend
                    .begin_serializable(&frame.request.deadline)?;
                self.configure_transaction(transaction.as_mut())?;
                let (generation, status) =
                    self.lock_generation(transaction.as_mut())?;
                if !matches!(
                    status,
                    GenerationStatus::Reconciling
                        | GenerationStatus::Ready
                ) {
                    return Err(AuthorityError::NotReady {
                        blockers: vec![format!(
                            "generation_status_{status:?}"
                        )],
                    });
                }
                let caller = self.lock_role_identity(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.caller_role_id,
                )?;
                if caller.role != ServiceRole::CleanupWatchdog {
                    return Err(AuthorityError::Authentication {
                        code: "generation_reconcile_role_denied",
                        reason: "only cleanup-watchdog may reconcile generation domains"
                            .to_owned(),
                    });
                }
                self.verify_database_role(&generation, &caller)?;
                self.verify_local_signer(&generation)?;
                verify_generation_request_frame(
                    frame,
                    &generation,
                    &caller,
                )?;
                if let Some(operation) = self.lock_operation_by_id(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.operation_id,
                )? {
                    return self.return_existing_operation(
                        transaction,
                        operation,
                        &exact_request_sha256,
                        &frame.request.deadline,
                    );
                }
                self.insert_generation_operation(
                    transaction.as_mut(),
                    frame,
                    &exact_request_sha256,
                )?;
                self.apply_generation_reconciliation(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    mutation,
                    &request_instant,
                )?;
                let (completed_domains, blockers) =
                    self.generation_reconciliation_status(
                        transaction.as_mut(),
                        &frame.request.generation_id,
                    )?;
                self.finish_generation_operation(
                    transaction,
                    frame,
                    &exact_request_sha256,
                    status,
                    None,
                    self.configuration.pinned_generation_sha256.clone(),
                    completed_domains,
                    blockers,
                    Vec::new(),
                )
            }
            GenerationMutationPayload::MarkReady(mutation) => {
                let mut transaction = self
                    .backend
                    .begin_serializable(&frame.request.deadline)?;
                self.configure_transaction(transaction.as_mut())?;
                let (generation, status) =
                    self.lock_generation(transaction.as_mut())?;
                if status != GenerationStatus::Reconciling {
                    return Err(AuthorityError::Conflict {
                        code: "generation_ready_requires_reconciling",
                        authoritative_state: Some(format!("{status:?}")),
                    });
                }
                let caller = self.lock_role_identity(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.caller_role_id,
                )?;
                if caller.role != ServiceRole::StateAuthority {
                    return Err(AuthorityError::Authentication {
                        code: "generation_ready_role_denied",
                        reason: "only the installed state-authority generation identity may collect readiness signatures and execute the READY CAS"
                            .to_owned(),
                    });
                }
                self.verify_database_role(&generation, &caller)?;
                self.verify_local_signer(&generation)?;
                verify_generation_request_frame(
                    frame,
                    &generation,
                    &caller,
                )?;
                if let Some(operation) = self.lock_operation_by_id(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.operation_id,
                )? {
                    return self.return_existing_operation(
                        transaction,
                        operation,
                        &exact_request_sha256,
                        &frame.request.deadline,
                    );
                }
                self.insert_generation_operation(
                    transaction.as_mut(),
                    frame,
                    &exact_request_sha256,
                )?;
                let readiness_artifact_ids =
                    self.apply_generation_ready(
                        transaction.as_mut(),
                        &generation,
                        frame,
                        mutation,
                    )?;
                let (completed_domains, blockers) =
                    self.generation_reconciliation_status(
                        transaction.as_mut(),
                        &frame.request.generation_id,
                    )?;
                self.finish_generation_operation(
                    transaction,
                    frame,
                    &exact_request_sha256,
                    GenerationStatus::Ready,
                    Some(GenerationStatus::Reconciling),
                    self.configuration.pinned_generation_sha256.clone(),
                    completed_domains,
                    blockers,
                    readiness_artifact_ids,
                )
            }
            GenerationMutationPayload::Query(mutation) => {
                let expected_query_sha256 =
                    sha256_digest(&canonical_jcs_bytes(&(
                        frame.request.generation_id.clone(),
                        "GENERATION_STATUS",
                    ))?);
                if mutation.query_sha256 != expected_query_sha256 {
                    return Err(AuthorityError::InvalidContract {
                        field: "stateQuery.querySha256",
                        reason: "query digest must bind the fixed generation-status projection"
                            .to_owned(),
                    });
                }
                let mut transaction = self
                    .backend
                    .begin_serializable(&frame.request.deadline)?;
                self.configure_transaction(transaction.as_mut())?;
                let (generation, status) =
                    self.lock_generation(transaction.as_mut())?;
                let caller = self.lock_role_identity(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.caller_role_id,
                )?;
                self.verify_database_role(&generation, &caller)?;
                self.verify_local_signer(&generation)?;
                verify_generation_request_frame(
                    frame,
                    &generation,
                    &caller,
                )?;
                if let Some(operation) = self.lock_operation_by_id(
                    transaction.as_mut(),
                    &frame.request.generation_id,
                    &frame.request.operation_id,
                )? {
                    return self.return_existing_operation(
                        transaction,
                        operation,
                        &exact_request_sha256,
                        &frame.request.deadline,
                    );
                }
                self.insert_generation_operation(
                    transaction.as_mut(),
                    frame,
                    &exact_request_sha256,
                )?;
                let (completed_domains, blockers) =
                    self.generation_reconciliation_status(
                        transaction.as_mut(),
                        &frame.request.generation_id,
                    )?;
                self.finish_generation_operation(
                    transaction,
                    frame,
                    &exact_request_sha256,
                    status,
                    None,
                    self.configuration.pinned_generation_sha256.clone(),
                    completed_domains,
                    blockers,
                    Vec::new(),
                )
            }
        }
    }

    fn insert_generation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        canonical_generation: &[u8],
        generation_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let inserted = transaction.execute(
            statements::INSERT_GENERATION_SQL,
            &[
                text(&generation.generation_id),
                generation
                    .predecessor_generation_id
                    .as_ref()
                    .map(text)
                    .unwrap_or(PgValue::Null),
                PgValue::U64(generation.rollback_floor),
                PgValue::Bytes(canonical_generation.to_vec()),
                text_digest(generation_sha256),
                text_digest(&generation.source_commit_sha256),
                text_digest(&generation.source_tree_sha256),
                text_digest(&generation.schema_bundle_sha256),
                text_digest(&generation.migration_sha256),
                PgValue::U64(generation.not_before_epoch_millis),
                PgValue::U64(generation.not_after_epoch_millis),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Backend {
                code: "generation_insert_failed",
                reason: "provider generation was not inserted exactly once"
                    .to_owned(),
            });
        }

        let mut roles = generation.topology.roles.iter().collect::<Vec<_>>();
        roles.sort_by(|left, right| left.role_id.cmp(&right.role_id));
        for role in roles {
            let public_key = role
                .public_key_base64url
                .as_ref()
                .map(|encoded| {
                    decode_base64url(
                        "roleIdentity.publicKeyBase64url",
                        encoded,
                    )
                })
                .transpose()?;
            let enabled_operations =
                serde_json::to_value(&role.enabled_operations).map_err(
                    |error| AuthorityError::Serialization {
                        reason: error.to_string(),
                    },
                )?;
            let role_inserted = transaction.execute(
                statements::INSERT_ROLE_IDENTITY_SQL,
                &[
                    text(&generation.generation_id),
                    text(&role.role_id),
                    PgValue::Text(role.role.as_str().to_owned()),
                    text(&role.process_id),
                    PgValue::U64(role.unix_uid as u64),
                    PgValue::U64(role.unix_gid as u64),
                    role.key_id
                        .as_ref()
                        .map(text)
                        .unwrap_or(PgValue::Null),
                    public_key
                        .map(PgValue::Bytes)
                        .unwrap_or(PgValue::Null),
                    role.public_key_sha256
                        .as_ref()
                        .map(text_digest)
                        .unwrap_or(PgValue::Null),
                    PgValue::Bool(role.authority_artifact_signing),
                    text_digest(&role.executable_sha256),
                    text_digest(&role.configuration_sha256),
                    PgValue::Json(enabled_operations),
                ],
            )?;
            if role_inserted != 1 {
                return Err(AuthorityError::Backend {
                    code: "role_identity_insert_failed",
                    reason: format!(
                        "{} was not inserted exactly once",
                        role.role.as_str()
                    ),
                });
            }
        }
        for domain in ReconciliationDomain::REQUIRED {
            let job_id = reconciliation_job_id(domain);
            let seeded = transaction.execute(
                statements::INSERT_RECONCILIATION_DOMAIN_SQL,
                &[
                    text(&generation.generation_id),
                    text(&job_id),
                    PgValue::Text(domain.as_str().to_owned()),
                ],
            )?;
            if seeded != 1 {
                return Err(AuthorityError::Backend {
                    code: "reconciliation_domain_seed_failed",
                    reason: domain.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    fn insert_generation_operation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        frame: &GenerationRpcRequestFrame,
        exact_request_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let inserted = transaction.execute(
            statements::INSERT_GENERATION_OPERATION_SQL,
            &[
                text(&frame.request.generation_id),
                text(&frame.request.operation_id),
                text(&frame.request.request_id),
                PgValue::Text(frame.request.operation.as_str().to_owned()),
                text(&frame.request.caller_role_id),
                text_digest(exact_request_sha256),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Backend {
                code: "generation_operation_prepare_failed",
                reason: "generation operation was not prepared exactly once"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn apply_generation_reconciliation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        mutation: &GenerationReconcileMutation,
        request_instant: &BootInstant,
    ) -> AuthorityResult<()> {
        mutation
            .reconciliation_job_id
            .validate("generationReconcile.reconciliationJobId", 128)?;
        mutation
            .result_sha256
            .validate("generationReconcile.resultSha256")?;
        if mutation.reconciliation_job_id
            != reconciliation_job_id(mutation.domain)
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationReconcile.reconciliationJobId",
                reason: "job ID must be the fixed ID for its reconciliation domain"
                    .to_owned(),
            });
        }
        if !reconciliation_transition_allowed(
            mutation.predecessor_state,
            mutation.successor_state,
        ) {
            return Err(AuthorityError::InvalidContract {
                field: "generationReconcile.successorState",
                reason: "invalid reconciliation lifecycle transition"
                    .to_owned(),
            });
        }
        let authoritative_cursor = self
            .authoritative_reconciliation_cursor(
                transaction,
                generation_id,
                mutation.domain,
            )?;
        if mutation.authoritative_cursor != authoritative_cursor {
            return Err(AuthorityError::Conflict {
                code: "generation_reconciliation_cursor_mismatch",
                authoritative_state: Some(
                    authoritative_cursor.to_string(),
                ),
            });
        }
        if mutation.successor_state == ReconciliationState::Complete
            && matches!(
                mutation.domain,
                ReconciliationDomain::Operations
                    | ReconciliationDomain::Attempts
            )
        {
            self.ensure_expired_attempts_settled(
                transaction,
                generation_id,
                request_instant,
            )?;
        }
        let expected_result_sha256 =
            sha256_digest(&canonical_jcs_bytes(&(
                generation_id,
                &mutation.reconciliation_job_id,
                mutation.domain,
                mutation.predecessor_state,
                mutation.successor_state,
                mutation.authoritative_cursor,
                &mutation.blocker_code,
            ))?);
        if mutation.result_sha256 != expected_result_sha256 {
            return Err(AuthorityError::InvalidContract {
                field: "generationReconcile.resultSha256",
                reason: "result digest does not bind the exact reconciliation transition"
                    .to_owned(),
            });
        }
        if mutation.successor_state == ReconciliationState::Complete
            && mutation.blocker_code.is_some()
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationReconcile.blockerCode",
                reason: "a completed domain cannot retain a blocker"
                    .to_owned(),
            });
        }

        let existing = transaction
            .query_optional(
                statements::LOCK_RECONCILIATION_DOMAIN_SQL,
                &[
                    text(generation_id),
                    PgValue::Text(mutation.domain.as_str().to_owned()),
                ],
            )?
            .ok_or_else(|| AuthorityError::NotReady {
                blockers: vec![format!(
                    "missing_reconciliation_domain:{}",
                    mutation.domain.as_str()
                )],
            })?;
        let stored_state =
            parse_reconciliation_state(&existing.require_text("state")?)?;
        if stored_state != mutation.predecessor_state
            || existing.require_text("reconciliation_job_id")?
                != mutation.reconciliation_job_id.0
            || existing.require_u64("authoritative_cursor")?
                > mutation.authoritative_cursor
        {
            return Err(AuthorityError::Conflict {
                code: "generation_reconciliation_cas_mismatch",
                authoritative_state: Some(format!(
                    "{stored_state:?}@{}",
                    existing.require_u64("authoritative_cursor")?
                )),
            });
        }
        let updated = transaction.execute(
            statements::UPDATE_GENERATION_RECONCILIATION_SQL,
            &[
                text(generation_id),
                PgValue::Text(mutation.domain.as_str().to_owned()),
                text(&mutation.reconciliation_job_id),
                PgValue::Text(reconciliation_state_text(
                    mutation.predecessor_state,
                )),
                PgValue::Text(reconciliation_state_text(
                    mutation.successor_state,
                )),
                PgValue::U64(mutation.authoritative_cursor),
                mutation
                    .blocker_code
                    .as_ref()
                    .map(text)
                    .unwrap_or(PgValue::Null),
                text_digest(&mutation.result_sha256),
            ],
        )?;
        if updated != 1 {
            return Err(AuthorityError::Conflict {
                code: "generation_reconciliation_update_failed",
                authoritative_state: Some(format!("{stored_state:?}")),
            });
        }
        Ok(())
    }

    fn authoritative_reconciliation_cursor(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        domain: ReconciliationDomain,
    ) -> AuthorityResult<u64> {
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
                statements::
                    TRANSPARENCY_CHECKPOINTS_RECONCILIATION_CURSOR_SQL
            }
            ReconciliationDomain::TrustedTimeHighwater => {
                statements::TRUSTED_TIME_RECONCILIATION_CURSOR_SQL
            }
        };
        transaction
            .query_optional(statement, &[text(generation_id)])?
            .ok_or_else(|| AuthorityError::Backend {
                code: "reconciliation_cursor_missing",
                reason: domain.as_str().to_owned(),
            })?
            .require_u64("authoritative_cursor")
    }

    fn ensure_expired_attempts_settled(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        request_instant: &BootInstant,
    ) -> AuthorityResult<()> {
        let attempts = transaction.query_many(
            statements::LOCK_NONTERMINAL_ATTEMPTS_SQL,
            &[text(generation_id)],
        )?;
        for row in attempts {
            let deadline_boot_id =
                Identifier(row.require_text("deadline_boot_id")?);
            let deadline_boot_millis =
                row.require_u64("deadline_boot_millis")?;
            if deadline_boot_id == request_instant.boot_id
                && request_instant.boot_millis < deadline_boot_millis
            {
                continue;
            }
            return Err(AuthorityError::NotReady {
                blockers: vec![format!(
                    "expired_attempt_requires_signed_cleanup:{}:{}",
                    row.require_text("attempt_id")?,
                    row.require_text("stable_resume_id")?
                )],
            });
        }
        Ok(())
    }

    fn generation_reconciliation_status(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
    ) -> AuthorityResult<(
        Vec<ReconciliationDomain>,
        Vec<Identifier>,
    )> {
        let rows = transaction.query_many(
            statements::GENERATION_RECONCILIATION_STATUS_SQL,
            &[text(generation_id)],
        )?;
        let mut seen = BTreeSet::new();
        let mut completed = Vec::new();
        let mut blockers = Vec::new();
        for row in rows {
            let domain =
                parse_reconciliation_domain(&row.require_text("domain")?)?;
            if !seen.insert(domain) {
                return Err(AuthorityError::Backend {
                    code: "duplicate_reconciliation_domain",
                    reason: domain.as_str().to_owned(),
                });
            }
            let state =
                parse_reconciliation_state(&row.require_text("state")?)?;
            if state == ReconciliationState::Complete {
                completed.push(domain);
            } else {
                blockers.push(Identifier(format!(
                    "reconciliation:{}:{state:?}",
                    domain.as_str()
                )));
            }
        }
        for domain in ReconciliationDomain::REQUIRED {
            if !seen.contains(&domain) {
                blockers.push(Identifier(format!(
                    "reconciliation:{}:MISSING",
                    domain.as_str()
                )));
            }
        }
        completed.sort();
        blockers.sort();
        Ok((completed, blockers))
    }

    fn finish_generation_operation(
        &self,
        mut transaction: Box<dyn PostgresTransaction + '_>,
        frame: &GenerationRpcRequestFrame,
        exact_request_sha256: &Digest,
        generation_status: GenerationStatus,
        predecessor_generation_status: Option<GenerationStatus>,
        generation_sha256: Digest,
        completed_domains: Vec<ReconciliationDomain>,
        blockers: Vec<Identifier>,
        result_artifact_ids: Vec<Identifier>,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        let body = GenerationOperationResultBody {
            api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
            kind: STATE_AUTHORITY_GENERATION_RESULT_KIND.to_owned(),
            schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
            generation_id: frame.request.generation_id.clone(),
            request_id: frame.request.request_id.clone(),
            operation_id: frame.request.operation_id.clone(),
            exact_request_sha256: exact_request_sha256.clone(),
            operation: frame.request.operation,
            disposition: ResultDisposition::Applied,
            predecessor_generation_status,
            generation_status,
            generation_sha256,
            completed_domains,
            blockers,
            result_artifact_ids,
            conflict_code: None,
        };
        let (signed_result, exact_result_bytes) =
            sign_generation_operation_result(
                &self.signer,
                body,
                &frame.request.deadline,
            )?;
        if exact_result_bytes.len()
            > self.configuration.maximum_result_bytes as usize
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationOperationResult",
                reason: "signed result exceeds configured limit".to_owned(),
            });
        }
        let exact_result_sha256 = sha256_digest(&exact_result_bytes);
        self.append_transparency_leaf(
            transaction.as_mut(),
            &frame.request.generation_id,
            &exact_result_bytes,
            &exact_result_sha256,
        )?;
        let signature_json =
            serde_json::to_value(&signed_result.authentication).map_err(
                |error| AuthorityError::Serialization {
                    reason: error.to_string(),
                },
            )?;
        let committed = transaction.execute(
            statements::COMMIT_OPERATION_SQL,
            &[
                text(&frame.request.generation_id),
                text(&frame.request.operation_id),
                PgValue::Text("COMMITTED".to_owned()),
                PgValue::Bytes(exact_result_bytes.clone()),
                text_digest(&exact_result_sha256),
                PgValue::Json(signature_json),
            ],
        )?;
        if committed != 1 {
            return Err(AuthorityError::Backend {
                code: "generation_operation_terminalization_failed",
                reason: "prepared generation operation was not committed exactly once"
                    .to_owned(),
            });
        }
        transaction.execute(
            statements::INSERT_REPLAY_RESULT_SQL,
            &[
                text(&frame.request.generation_id),
                text(&frame.request.request_id),
                text(&frame.request.operation_id),
                text_digest(exact_request_sha256),
                PgValue::Bytes(exact_result_bytes.clone()),
                text_digest(&exact_result_sha256),
            ],
        )?;
        self.assert_deadline(&frame.request.deadline)?;
        transaction.commit(&frame.request.deadline)?;
        Ok(ExactSignedResultBytes {
            canonical_bytes: exact_result_bytes,
            canonical_sha256: exact_result_sha256,
        })
    }

    fn configure_transaction(
        &self,
        transaction: &mut dyn PostgresTransaction,
    ) -> AuthorityResult<()> {
        transaction.query_optional(
            statements::CONFIGURE_TRANSACTION_SQL,
            &[
                PgValue::Text(format!(
                    "{}ms",
                    self.configuration.statement_timeout_millis
                )),
                PgValue::Text(format!(
                    "{}ms",
                    self.configuration.lock_timeout_millis
                )),
                PgValue::Text(format!(
                    "{}ms",
                    self.configuration.idle_transaction_timeout_millis
                )),
            ],
        )?;
        Ok(())
    }

    fn assert_deadline(
        &self,
        deadline: &BootDeadline,
    ) -> AuthorityResult<()> {
        let instant = self.boot_clock.current_boot_instant()?;
        deadline.ensure_current(&instant)
    }

    fn lock_generation(
        &self,
        transaction: &mut dyn PostgresTransaction,
    ) -> AuthorityResult<(ProviderGeneration, GenerationStatus)> {
        let row = transaction
            .query_optional(
                statements::LOCK_GENERATION_SQL,
                &[text(&self.configuration.generation_id)],
            )?
            .ok_or_else(|| AuthorityError::NotReady {
                blockers: vec!["provider_generation_missing".to_owned()],
            })?;
        let (generation, status, generation_sha256) =
            self.parse_generation_row(row)?;
        if generation_sha256
            != self.configuration.pinned_generation_sha256
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "provider_generation_not_locally_pinned".to_owned(),
                ],
            });
        }
        super::sequence_originals::require_database(transaction, &generation.migration_sha256)?;
        Ok((generation, status))
    }

    fn parse_generation_row(
        &self,
        row: PgRow,
    ) -> AuthorityResult<(
        ProviderGeneration,
        GenerationStatus,
        Digest,
    )> {
        let bytes = row.require_bytes("canonical_generation")?;
        let expected_digest =
            Digest(row.require_text("generation_sha256")?);
        if sha256_digest(&bytes) != expected_digest {
            return Err(AuthorityError::Backend {
                code: "generation_digest_mismatch",
                reason:
                    "stored canonical generation failed its pinned digest"
                        .to_owned(),
            });
        }
        let generation: ProviderGeneration =
            serde_json::from_slice(&bytes).map_err(|error| {
                AuthorityError::Serialization {
                    reason: format!(
                        "provider generation could not be decoded: {error}"
                    ),
                }
            })?;
        generation.validate()?;
        validate_service_operation_matrix(&generation.topology)?;
        let status = parse_generation_status(&row.require_text("status")?)?;
        Ok((generation, status, expected_digest))
    }

    fn enforce_generation_status(
        &self,
        status: GenerationStatus,
        operation: OperationKind,
    ) -> AuthorityResult<()> {
        let allowed = match operation {
            OperationKind::ReconciliationTransition
            | OperationKind::ReconciliationTerminalizeExpiredAttempt
            | OperationKind::GenerationReady
            | OperationKind::TrustedTimeAdvance
            | OperationKind::TransparencyCheckpoint => {
                matches!(
                    status,
                    GenerationStatus::Reconciling | GenerationStatus::Ready
                )
            }
            _ => status == GenerationStatus::Ready,
        };
        if !allowed {
            return Err(AuthorityError::NotReady {
                blockers: vec![format!(
                    "generation_status_{status:?}"
                )],
            });
        }
        Ok(())
    }

    fn lock_role(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
    ) -> AuthorityResult<RoleIdentity> {
        self.lock_role_identity(
            transaction,
            &request.generation_id,
            &request.caller_role_id,
        )
    }

    fn lock_role_identity(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        role_id: &Identifier,
    ) -> AuthorityResult<RoleIdentity> {
        let row = transaction
            .query_optional(
                statements::LOCK_ROLE_SQL,
                &[
                    text(generation_id),
                    text(role_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Authentication {
                code: "caller_role_not_assigned",
                reason: "caller role is absent from the generation".to_owned(),
            })?;
        let role = parse_service_role(&row.require_text("role_name")?)?;
        let operation_values = row.require_json("enabled_operations")?;
        let operation_strings: Vec<String> =
            serde_json::from_value(operation_values).map_err(|error| {
                AuthorityError::Serialization {
                    reason: format!(
                        "enabled operations could not be decoded: {error}"
                    ),
                }
            })?;
        let identity = RoleIdentity {
            role_id: Identifier(row.require_text("role_id")?),
            role,
            process_id: Identifier(row.require_text("process_id")?),
            unix_uid: row.require_u32("unix_uid")?,
            unix_gid: row.require_u32("unix_gid")?,
            fault_domain_id: Identifier(
                row.require_text("fault_domain_id")?,
            ),
            key_id: row.optional_text("key_id")?.map(Identifier),
            public_key_base64url: row
                .optional_bytes("public_key")?
                .map(|key| encode_base64url(&key)),
            public_key_sha256: row
                .optional_text("public_key_sha256")?
                .map(Digest),
            signing_algorithm: row
                .optional_text("key_id")?
                .map(|_| "Ed25519".to_owned()),
            authority_artifact_signing: row
                .require_bool("authority_artifact_signing")?,
            executable_sha256: Digest(
                row.require_text("executable_sha256")?,
            ),
            configuration_sha256: Digest(
                row.require_text("configuration_sha256")?,
            ),
            enabled_operations: operation_strings
                .into_iter()
                .map(Identifier)
                .collect(),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn verify_database_role(
        &self,
        generation: &ProviderGeneration,
        identity: &RoleIdentity,
    ) -> AuthorityResult<()> {
        let canonical = generation
            .topology
            .roles
            .iter()
            .find(|candidate| candidate.role_id == identity.role_id)
            .ok_or_else(|| AuthorityError::Authentication {
                code: "caller_role_absent_from_signed_generation",
                reason: "database role is not in the signed generation"
                    .to_owned(),
            })?;
        if canonical != identity {
            return Err(AuthorityError::Backend {
                code: "role_identity_generation_mismatch",
                reason: "database role identity differs from the signed generation"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn verify_local_signer(
        &self,
        generation: &ProviderGeneration,
    ) -> AuthorityResult<()> {
        let local_authority =
            generation.role(ServiceRole::StateAuthority)?;
        if local_authority.role_id != self.configuration.local_role_id
            || local_authority.key_id.as_ref()
                != Some(self.signer.key_id())
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "state_authority_signer_not_generation_bound".to_owned(),
                ],
            });
        }
        Ok(())
    }

    fn lock_attempt(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
    ) -> AuthorityResult<Option<LockedAttempt>> {
        transaction
            .query_optional(
                statements::LOCK_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                ],
            )?
            .map(parse_locked_attempt)
            .transpose()
    }

    fn lock_operation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
    ) -> AuthorityResult<Option<PgRow>> {
        self.lock_operation_by_id(
            transaction,
            &request.generation_id,
            &request.operation_id,
        )
    }

    fn lock_operation_by_id(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        operation_id: &Identifier,
    ) -> AuthorityResult<Option<PgRow>> {
        transaction.query_optional(
            statements::LOCK_OPERATION_SQL,
            &[
                text(generation_id),
                text(operation_id),
            ],
        )
    }

    fn return_existing_operation(
        &self,
        transaction: Box<dyn PostgresTransaction + '_>,
        row: PgRow,
        exact_request_sha256: &Digest,
        deadline: &BootDeadline,
    ) -> AuthorityResult<ExactSignedResultBytes> {
        let stored_request_sha256 =
            Digest(row.require_text("exact_request_sha256")?);
        if &stored_request_sha256 != exact_request_sha256 {
            return Err(AuthorityError::Conflict {
                code: "operation_id_reused_with_different_request",
                authoritative_state: Some(
                    row.require_text("status")?,
                ),
            });
        }
        let status = row.require_text("status")?;
        if status == "PREPARED" {
            return Err(AuthorityError::Conflict {
                code: "operation_requires_reconciliation",
                authoritative_state: Some(status),
            });
        }
        let canonical_bytes = row
            .optional_bytes("canonical_signed_result")?
            .ok_or_else(|| AuthorityError::Backend {
                code: "terminal_operation_missing_result",
                reason: "terminal operation has no exact result bytes"
                    .to_owned(),
            })?;
        let canonical_sha256 = Digest(
            row.optional_text("canonical_signed_result_sha256")?
                .ok_or_else(|| AuthorityError::Backend {
                    code: "terminal_operation_missing_result_digest",
                    reason: "terminal operation has no result digest"
                        .to_owned(),
                })?,
        );
        if sha256_digest(&canonical_bytes) != canonical_sha256 {
            return Err(AuthorityError::Backend {
                code: "stored_result_digest_mismatch",
                reason: "stored exact result failed its digest".to_owned(),
            });
        }
        self.assert_deadline(deadline)?;
        transaction.commit(deadline)?;
        Ok(ExactSignedResultBytes {
            canonical_bytes,
            canonical_sha256,
        })
    }

    fn validate_attempt_expectation(
        &self,
        attempt: Option<&LockedAttempt>,
        request: &RpcRequest,
    ) -> AuthorityResult<()> {
        let attempt = attempt.ok_or_else(|| AuthorityError::Conflict {
            code: "attempt_missing",
            authoritative_state: None,
        })?;
        let expected_fence =
            request.fence.fence_token.as_ref().ok_or_else(|| {
                AuthorityError::InvalidContract {
                    field: "request.fence.fenceToken",
                    reason: "exact fence token is required".to_owned(),
                }
            })?;
        if attempt.revision != request.expected_revision
            || attempt.state != request.expected_state
            || &attempt.fence_token != expected_fence
        {
            return Err(AuthorityError::Conflict {
                code: "attempt_cas_mismatch",
                authoritative_state: Some(format!(
                    "{}@{}:{}",
                    attempt.state.as_str(),
                    attempt.revision,
                    attempt.fence_token
                )),
            });
        }
        Ok(())
    }

    fn lock_and_validate_fence(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        attempt: &LockedAttempt,
    ) -> AuthorityResult<LockedFence> {
        let row = transaction
            .query_optional(
                statements::LOCK_FENCE_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "fence_missing",
                authoritative_state: None,
            })?;
        let fence = LockedFence {
            fence_token: Identifier(row.require_text("fence_token")?),
            state: parse_fence_state(&row.require_text("state")?)?,
            owner_process_id: Identifier(
                row.require_text("owner_process_id")?,
            ),
            owner_pid: row.require_u32("owner_pid")?,
            owner_start_time_ticks: row
                .require_u64("owner_start_time_ticks")?,
            owner_cgroup_id: Identifier(
                row.require_text("owner_cgroup_id")?,
            ),
        };
        if fence.fence_token != attempt.fence_token
            || fence.owner_process_id != attempt.owner_process_id
            || fence.owner_pid != attempt.owner_pid
            || fence.owner_start_time_ticks
                != attempt.owner_start_time_ticks
            || fence.owner_cgroup_id != attempt.owner_cgroup_id
        {
            return Err(AuthorityError::Backend {
                code: "fence_attempt_binding_mismatch",
                reason: "authoritative fence does not match attempt owner"
                    .to_owned(),
            });
        }
        if fence.state != FenceState::Active
            && !matches!(
                request.operation,
                OperationKind::ReleaseResolveReplay
                    | OperationKind::FenceObserveQuiescence
                    | OperationKind::AttemptTerminalize
                    | OperationKind::ReconciliationTransition
                    | OperationKind::ReconciliationTerminalizeExpiredAttempt
            )
        {
            return Err(AuthorityError::Conflict {
                code: "fence_not_active",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        Ok(fence)
    }

    fn lock_trusted_time(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        operation: OperationKind,
    ) -> AuthorityResult<Option<u64>> {
        let row = transaction.query_optional(
            statements::LOCK_MAX_TRUSTED_TIME_SQL,
            &[text(&generation.generation_id)],
        )?;
        let epoch = row
            .as_ref()
            .map(|row| row.require_u64("epoch_millis"))
            .transpose()?;
        if epoch.is_none()
            && operation != OperationKind::TrustedTimeAdvance
            && operation != OperationKind::ReconciliationTransition
            && operation
                != OperationKind::ReconciliationTerminalizeExpiredAttempt
        {
            return Err(AuthorityError::NotReady {
                blockers: vec!["trusted_time_highwater_missing".to_owned()],
            });
        }
        if let Some(epoch) = epoch {
            if epoch < generation.not_before_epoch_millis
                || epoch >= generation.not_after_epoch_millis
            {
                return Err(AuthorityError::NotReady {
                    blockers: vec![
                        "provider_generation_outside_validity".to_owned(),
                    ],
                });
            }
        }
        Ok(epoch)
    }

    fn insert_prepared_operation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        exact_request_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let fence_token = request
            .fence
            .fence_token
            .as_ref()
            .map(|token| token.0.clone())
            .unwrap_or_else(|| "ALLOCATE".to_owned());
        let inserted = transaction.execute(
            statements::INSERT_PREPARED_OPERATION_SQL,
            &[
                text(&request.generation_id),
                text(&request.operation_id),
                text(&request.request_id),
                text(&request.attempt_id),
                PgValue::Text(request.operation.as_str().to_owned()),
                text(&request.caller_role_id),
                text_digest(exact_request_sha256),
                PgValue::U64(request.expected_revision),
                PgValue::Text(request.expected_state.as_str().to_owned()),
                PgValue::Text(fence_token),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Backend {
                code: "operation_prepare_failed",
                reason: "operation was not prepared exactly once".to_owned(),
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_mutation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: Option<&LockedAttempt>,
        fence: Option<&LockedFence>,
        trusted_epoch_millis: Option<u64>,
        native_stage: Option<&native_staging_predecessor::StageCompanion<'_>>,
    ) -> AuthorityResult<AppliedMutation> {
        match &request.payload {
            MutationPayload::Reserve(mutation) => self.apply_reserve(
                transaction,
                generation,
                request,
                mutation,
            ),
            MutationPayload::Authorize(mutation) => {
                let attempt = require_attempt(attempt)?;
                let fence = require_fence(fence)?;
                let mut artifact_ids = Vec::new();
                let mut transition_authorization = None;
                for artifact in &mutation.authorization_artifacts {
                    let role = self.verify_nested(
                        generation,
                        artifact,
                        request.operation,
                        request,
                        trusted_epoch_millis,
                    )?;
                    if role == ServiceRole::PolicyProofVerifier {
                        transition_authorization = Some(artifact);
                    }
                    artifact_ids.push(artifact.body.artifact_id.clone());
                }
                let transition_authorization =
                    transition_authorization.ok_or_else(|| {
                        AuthorityError::Authentication {
                            code: "policy_verifier_artifact_missing",
                            reason: "authorization requires a policy-proof-verifier artifact"
                                .to_owned(),
                        }
                    })?;
                let transition = match &transition_authorization.body.payload {
                    NestedAuthorityPayload::TransitionAuthorization(
                        authorization,
                    )
                        if authorization.passed
                            && authorization.policy_decision_id
                                == mutation.policy_decision_id
                            && authorization.policy_generation_sha256
                                == mutation.policy_generation_sha256
                            && authorization.expected_revision
                                == request.expected_revision
                            && authorization.expected_state
                                == request.expected_state
                            && authorization.successor_revision
                                == request.expected_revision + 1
                            && authorization.successor_state
                                == AttemptState::Authorized =>
                    {
                        authorization
                    }
                    _ => {
                        return Err(AuthorityError::Authentication {
                            code: "transition_authorization_invalid",
                            reason: "authorization requires a passing transition DTO bound to the exact predecessor and successor CAS"
                                .to_owned(),
                        })
                    }
                };
                let policy_digest =
                    sha256_digest(&canonical_jcs_bytes(
                        transition_authorization,
                    )?);
                transaction.execute(
                    statements::INSERT_POLICY_DECISION_SQL,
                    &[
                        text(&request.generation_id),
                        text(&mutation.policy_decision_id),
                        text(&request.attempt_id),
                        text_digest(&mutation.policy_generation_sha256),
                        PgValue::Null,
                        PgValue::Null,
                        text_digest(&policy_digest),
                        PgValue::Bool(transition.passed),
                    ],
                )?;
                self.transition(
                    transaction,
                    request,
                    attempt,
                    fence,
                    AttemptState::Authorized,
                    artifact_ids,
                )
            }
            MutationPayload::CommitRawObject(mutation) => {
                let attempt = require_attempt(attempt)?;
                let fence = require_fence(fence)?;
                self.verify_expected_role_artifact(
                    generation,
                    &mutation.artifact_commit,
                    ServiceRole::ImmutableArtifactLedger,
                    request,
                    trusted_epoch_millis,
                )?;
                match &mutation.artifact_commit.body.payload {
                    NestedAuthorityPayload::ArtifactCommit(commit)
                        if commit.object_id == mutation.object_id
                            && commit.object_kind == mutation.object_kind
                            && commit.content_sha256
                                == mutation.expected_content_sha256
                            && commit.content_length
                                == mutation.expected_content_length
                            && commit.immutable_storage_receipt_sha256
                                == mutation
                                    .immutable_storage_receipt_sha256 => {}
                    _ => {
                        return Err(AuthorityError::Authentication {
                            code: "artifact_commit_payload_mismatch",
                            reason: "artifact ledger receipt does not bind exact raw object identity, kind, digest, and length"
                                .to_owned(),
                        })
                    }
                }
                self.commit_raw_object(
                    transaction,
                    request,
                    mutation,
                )?;
                // The already verified attempt-scoped artifact and object
                // association commit atomically with this state transition.
                // A content-addressed row may predate this attempt; that row
                // alone must never manufacture its ArtifactCommit evidence.
                let canonical = canonical_jcs_bytes(&mutation.artifact_commit)?;
                let digest = sha256_digest(&canonical);
                if transaction.execute(statements::INSERT_EVIDENCE_SQL, &[
                    text(&request.generation_id),
                    text(&mutation.artifact_commit.body.artifact_id),
                    text(&request.attempt_id),
                    PgValue::Text("ARTIFACT_COMMIT".to_owned()),
                    text(&mutation.artifact_commit.body.producing_role_id),
                    PgValue::Bytes(canonical), text_digest(&digest),
                    text_digest(&mutation.expected_content_sha256),
                ])? != 1 {
                    return Err(AuthorityError::Conflict {
                        code:"raw_commit_evidence_conflict",
                        authoritative_state:Some(mutation.artifact_commit.body.artifact_id.0.clone()),
                    });
                }
                self.bump(
                    transaction,
                    request,
                    attempt,
                    fence,
                    vec![
                        mutation.artifact_commit.body.artifact_id.clone(),
                        mutation.object_id.clone(),
                    ],
                    ResultDisposition::Applied,
                )
            }
            MutationPayload::InspectImmutableRaw(mutation) => {
                self.apply_inspect_immutable_raw(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::Stage(mutation) => {
                let attempt = require_attempt(attempt)?;
                let fence = require_fence(fence)?;
                self.require_original_reserve_scope(transaction, generation, request, mutation)?;
                self.ensure_object(
                    transaction,
                    request,
                    &mutation.staged_request_object,
                )?;
                let artifact_ids = if let Some(companion)=native_stage {
                    self.require_native_stage_predecessor(transaction,generation,request,mutation,companion)?
                } else {
                    let mut ids=Vec::new();
                    for artifact in &mutation.transition_artifacts {
                        self.verify_nested(generation,artifact,request.operation,request,trusted_epoch_millis)?;
                        ids.push(artifact.body.artifact_id.clone());
                    }
                    ids
                };
                self.transition(
                    transaction,
                    request,
                    attempt,
                    fence,
                    AttemptState::Staged,
                    artifact_ids,
                )
            }
            MutationPayload::BeginDispatch(mutation) => {
                self.apply_begin_dispatch(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::RecordDispatchOutcome(mutation) => {
                self.apply_dispatch_outcome(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::Terminalize(mutation) => self.apply_terminal(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::Finalize(mutation) => self.apply_finalize(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::Publish(mutation) => self.apply_publish(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::ConsumeReleaseAndRetrieveExact(mutation) => {
                self.apply_release(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::ResolveReplay(mutation) => {
                self.apply_replay_resolution(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                )
            }
            MutationPayload::SettleAttempt(mutation) => self.apply_settlement(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::Archive(mutation) => self.apply_archive(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::RevokeFence(mutation) => self.apply_revoke(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::ObserveQuiescence(mutation) => {
                self.apply_quiescence(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::AppendEvidence(mutation) => {
                self.apply_evidence(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::EnqueuePublication(mutation) => {
                self.apply_enqueue(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::AcknowledgePublication(mutation) => {
                self.apply_acknowledge(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::PublishCheckpoint(mutation) => {
                self.apply_checkpoint(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                )
            }
            MutationPayload::AdvanceTrustedTime(mutation) => {
                self.apply_trusted_time(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
            MutationPayload::Reconcile(mutation) => self.apply_reconcile(
                transaction,
                generation,
                request,
                require_attempt(attempt)?,
                require_fence(fence)?,
                mutation,
                trusted_epoch_millis,
            ),
            MutationPayload::TerminalizeExpiredAttempt(mutation) => {
                self.apply_terminalize_expired_attempt(
                    transaction,
                    generation,
                    request,
                    require_attempt(attempt)?,
                    require_fence(fence)?,
                    mutation,
                    trusted_epoch_millis,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_generation_ready(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        frame: &GenerationRpcRequestFrame,
        mutation: &GenerationReadyMutation,
    ) -> AuthorityResult<Vec<Identifier>> {
        let request = &frame.request;
        mutation
            .reconciliation_checkpoint_sha256
            .validate("generationReady.reconciliationCheckpointSha256")?;
        if mutation.role_readiness_artifacts.len()
            != ServiceRole::ALL.len()
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationReady.roleReadinessArtifacts",
                reason: "exactly seven independently signed role-readiness artifacts are required"
                    .to_owned(),
            });
        }
        let reconciliation_rows = transaction.query_many(
            statements::GENERATION_RECONCILIATION_STATUS_SQL,
            &[text(&request.generation_id)],
        )?;
        let authoritative_checkpoint = sha256_digest(
            &canonical_jcs_bytes(
                &reconciliation_rows
                    .iter()
                    .map(|row| {
                        Ok((
                            row.require_text("domain")?,
                            row.require_text("state")?,
                            row.require_u64("authoritative_cursor")?,
                            row.optional_text("blocker_code")?,
                            row.optional_text("result_sha256")?,
                        ))
                    })
                    .collect::<AuthorityResult<Vec<_>>>()?,
            )?,
        );
        if mutation.reconciliation_checkpoint_sha256
            != authoritative_checkpoint
        {
            return Err(AuthorityError::Conflict {
                code: "generation_readiness_checkpoint_mismatch",
                authoritative_state: Some(authoritative_checkpoint.0),
            });
        }
        let trusted_epoch_millis = self
            .lock_trusted_time(
                transaction,
                generation,
                OperationKind::GenerationReady,
            )?
            .ok_or_else(|| AuthorityError::NotReady {
                blockers: vec![
                    "generation_ready_requires_trusted_time".to_owned(),
                ],
            })?;
        let readiness_scope = derive_generation_readiness_scope(
            generation,
            &authoritative_checkpoint,
        )?;
        let mut artifact_ids = Vec::new();
        let mut artifact_digests = BTreeSet::new();
        for (artifact, expected_role) in mutation
            .role_readiness_artifacts
            .iter()
            .zip(ServiceRole::ALL)
        {
            verify_authority_artifact(
                artifact,
                generation,
                expected_role,
                OperationKind::GenerationReady,
                &request.operation_id,
                &readiness_scope.attempt_id,
                readiness_scope.attempt_revision,
                &readiness_scope.fence_token,
            )?;
            if !artifact_contract_allows(
                expected_role,
                OperationKind::GenerationReady,
                artifact.body.payload.artifact_type(),
            ) || trusted_epoch_millis
                < artifact.body.issued_at_epoch_millis
                || trusted_epoch_millis
                    >= artifact.body.expires_at_epoch_millis
            {
                return Err(AuthorityError::Authentication {
                    code: "generation_readiness_artifact_scope_denied",
                    reason: "readiness artifact is outside its installed role, operation, or trusted-time scope"
                        .to_owned(),
                });
            }
            let readiness = match &artifact.body.payload {
                NestedAuthorityPayload::RoleReadiness(readiness)
                    if readiness.role == expected_role
                        && readiness.role_id
                            == artifact.body.producing_role_id
                        && readiness.reconciled_generation_id
                            == request.generation_id
                        && readiness.reconciliation_checkpoint_sha256
                            == mutation.reconciliation_checkpoint_sha256 =>
                {
                    readiness
                }
                _ => {
                    return Err(AuthorityError::Authentication {
                        code: "role_readiness_payload_mismatch",
                        reason: "role readiness artifact does not bind its role, generation, and reconciliation checkpoint"
                            .to_owned(),
                    })
                }
            };
            let assigned = generation.role(expected_role)?;
            if readiness.process_id != assigned.process_id
                || readiness.key_id.as_ref() != assigned.key_id.as_ref()
            {
                return Err(AuthorityError::Authentication {
                    code: "role_readiness_identity_mismatch",
                    reason: "role readiness process/key differs from generation assignment"
                    .to_owned(),
                });
            }
            let artifact_sha256 =
                sha256_digest(&canonical_jcs_bytes(artifact)?);
            if !artifact_digests.insert(artifact_sha256) {
                return Err(AuthorityError::InvalidContract {
                    field: "generationReady.roleReadinessArtifacts",
                    reason: "readiness artifacts must be canonically distinct"
                        .to_owned(),
                });
            }
            artifact_ids.push(artifact.body.artifact_id.clone());
        }
        let role_readiness_root_sha256 = sha256_digest(
            &canonical_jcs_bytes(&mutation.role_readiness_artifacts)?,
        );
        verify_authority_artifact(
            &mutation.router_topology_attestation,
            generation,
            ServiceRole::CustodyRouter,
            OperationKind::GenerationReady,
            &request.operation_id,
            &readiness_scope.attempt_id,
            readiness_scope.attempt_revision,
            &readiness_scope.fence_token,
        )?;
        let router = generation.role(ServiceRole::CustodyRouter)?;
        if mutation
            .router_topology_attestation
            .body
            .producing_service_role
            != ServiceRole::CustodyRouter
        {
            return Err(AuthorityError::Authentication {
                code: "router_topology_attestation_not_router_signed",
                reason: "topology attestation must be signed directly by the installed custody-router key"
                    .to_owned(),
            });
        }
        let topology_sha256 =
            sha256_digest(&canonical_jcs_bytes(&generation.topology)?);
        match &mutation.router_topology_attestation.body.payload {
            NestedAuthorityPayload::RouterTopologyAttestation(attestation)
                if attestation.router_role_id == router.role_id
                    && attestation.router_process_id == router.process_id
                    && Some(&attestation.router_key_id)
                        == router.key_id.as_ref()
                    && attestation.reconciled_generation_id
                        == request.generation_id
                    && attestation.topology_sha256 == topology_sha256
                    && attestation.readiness_contract_sha256
                        == generation
                            .topology
                            .readiness_contract
                            .contract_sha256
                    && attestation.reconciliation_checkpoint_sha256
                        == authoritative_checkpoint
                    && attestation.role_readiness_root_sha256
                        == role_readiness_root_sha256 => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "router_topology_attestation_mismatch",
                    reason: "router topology attestation does not bind its installed key, topology, readiness contract, seven receipts, and reconciliation checkpoint"
                        .to_owned(),
                })
            }
        }
        if !artifact_contract_allows(
            ServiceRole::CustodyRouter,
            OperationKind::GenerationReady,
            mutation
                .router_topology_attestation
                .body
                .payload
                .artifact_type(),
        ) || trusted_epoch_millis
            < mutation
                .router_topology_attestation
                .body
                .issued_at_epoch_millis
            || trusted_epoch_millis
                >= mutation
                    .router_topology_attestation
                    .body
                    .expires_at_epoch_millis
        {
            return Err(AuthorityError::Authentication {
                code: "router_topology_attestation_scope_denied",
                reason: "router topology attestation is outside its installed operation or trusted-time scope"
                    .to_owned(),
            });
        }
        let router_attestation_sha256 = sha256_digest(
            &canonical_jcs_bytes(&mutation.router_topology_attestation)?,
        );
        if artifact_digests.contains(&router_attestation_sha256) {
            return Err(AuthorityError::InvalidContract {
                field: "generationReady.routerTopologyAttestation",
                reason: "router topology attestation must be distinct from all seven readiness receipts"
                    .to_owned(),
            });
        }
        artifact_ids.push(
            mutation
                .router_topology_attestation
                .body
                .artifact_id
                .clone(),
        );
        let blockers = transaction.query_many(
            statements::READINESS_BLOCKERS_SQL,
            &[
                text(&request.generation_id),
                text(&request.operation_id),
            ],
        )?;
        if !blockers.is_empty() {
            return Err(AuthorityError::NotReady {
                blockers: blockers
                    .iter()
                    .map(|row| row.require_text("code"))
                    .collect::<AuthorityResult<Vec<_>>>()?,
            });
        }
        let ready = transaction.query_optional(
            statements::MARK_GENERATION_READY_SQL,
            &[text(&request.generation_id)],
        )?;
        if ready.is_none() {
            return Err(AuthorityError::Conflict {
                code: "generation_ready_cas_failed",
                authoritative_state: Some("RECONCILING".to_owned()),
            });
        }
        artifact_ids.push(Identifier(
            mutation.reconciliation_checkpoint_sha256.0.clone(),
        ));
        Ok(artifact_ids)
    }

    fn apply_reserve(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        mutation: &ReserveMutation,
    ) -> AuthorityResult<AppliedMutation> {
        mutation
            .stable_resume_id
            .validate("reserve.stableResumeId", 128)?;
        mutation
            .owner_process_id
            .validate("reserve.ownerProcessId", 128)?;
        mutation
            .owner_cgroup_id
            .validate("reserve.ownerCgroupId", 128)?;
        mutation.attempt_deadline.validate()?;
        mutation.request_sha256.validate("reserve.requestSha256")?;
        mutation.route_sha256.validate("reserve.routeSha256")?;
        mutation
            .credential_scope_sha256
            .validate("reserve.credentialScopeSha256")?;
        let allocation = transaction
            .query_optional(statements::ALLOCATE_FENCE_SQL, &[])?
            .ok_or_else(|| AuthorityError::Backend {
                code: "fence_allocation_failed",
                reason: "fence sequence returned no value".to_owned(),
            })?
            .require_u64("allocation_sequence")?;
        let fence_token = match super::sequence_originals::profile(&generation.migration_sha256)? {
            super::sequence_originals::Profile::LegacyV1 => {
                let fence_material = canonical_jcs_bytes(&(request.generation_id.clone(), request.attempt_id.clone(), allocation))?;
                let digest = sha256_digest(&fence_material);
                Identifier(format!("fence:{}", &digest.0["sha256:".len()..]))
            }
            super::sequence_originals::Profile::SequenceOriginalsV2
            | super::sequence_originals::Profile::NativeStagingV3 => {
                super::sequence_originals::canonical_fence(&allocation.to_string(), allocation)?;
                self.assert_deadline(&mutation.attempt_deadline)?;
                if mutation.attempt_deadline.boot_id!=request.deadline.boot_id
                    || mutation.attempt_deadline.clock!=request.deadline.clock
                    || mutation.attempt_deadline.deadline_boot_millis>request.deadline.deadline_boot_millis {
                    return Err(super::sequence_originals::refused("Reserve cannot renew or replace its original deadline"));
                }
                Identifier(allocation.to_string())
            }
        };
        transaction.execute(
            statements::INSERT_ATTEMPT_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                text(&fence_token),
                text(&mutation.stable_resume_id),
                text(&mutation.owner_process_id),
                PgValue::U64(mutation.owner_pid as u64),
                PgValue::U64(mutation.owner_start_time_ticks),
                text(&mutation.owner_cgroup_id),
                text(&mutation.attempt_deadline.boot_id),
                PgValue::U64(
                    mutation.attempt_deadline.deadline_boot_millis,
                ),
                text_digest(&mutation.request_sha256),
                text_digest(&mutation.route_sha256),
                text_digest(&mutation.credential_scope_sha256),
            ],
        )?;
        transaction.execute(
            statements::INSERT_FENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                text(&fence_token),
                PgValue::U64(allocation),
                text(&mutation.owner_process_id),
                PgValue::U64(mutation.owner_pid as u64),
                PgValue::U64(mutation.owner_start_time_ticks),
                text(&mutation.owner_cgroup_id),
            ],
        )?;
        Ok(AppliedMutation {
            revision: 1,
            state: AttemptState::Reserved,
            fence_token,
            stable_resume_id: mutation.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: Vec::new(),
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    fn apply_inspect_immutable_raw(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &InspectImmutableRawMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        mutation
            .inspection_id
            .validate("inspectImmutableRaw.inspectionId", 128)?;
        mutation.inspection_purpose_sha256.validate(
            "inspectImmutableRaw.inspectionPurposeSha256",
        )?;
        mutation.expected_immutable_storage_receipt_sha256.validate(
            "inspectImmutableRaw.expectedImmutableStorageReceiptSha256",
        )?;
        if !mutation.require_no_byte_release {
            return Err(AuthorityError::InvalidContract {
                field: "inspectImmutableRaw.requireNoByteRelease",
                reason: "inspection must not release immutable object bytes"
                    .to_owned(),
            });
        }
        let (immutable_raw, immutable_storage_receipt_sha256) =
            self.load_immutable_raw(
            transaction,
            request,
            &mutation.object,
        )?;
        if immutable_storage_receipt_sha256
            != mutation.expected_immutable_storage_receipt_sha256
        {
            return Err(AuthorityError::Authentication {
                code: "immutable_inspection_storage_receipt_mismatch",
                reason: "inspection request does not bind the committed immutable storage receipt"
                    .to_owned(),
            });
        }
        let inspected_at = self.boot_clock.current_boot_instant()?;
        request.deadline.ensure_current(&inspected_at)?;
        let issued_at_epoch_millis =
            trusted_epoch_millis.ok_or_else(|| AuthorityError::NotReady {
                blockers: vec!["trusted_time_highwater_missing".to_owned()],
            })?;
        let mut applied = self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![mutation.object.object_id.clone()],
            ResultDisposition::Applied,
        )?;
        applied.deferred_inspection = Some(DeferredInspection {
            inspection_id: mutation.inspection_id.clone(),
            object_reference: immutable_raw.reference,
            immutable_storage_receipt_sha256,
            inspection_purpose_sha256: mutation
                .inspection_purpose_sha256
                .clone(),
            inspected_at,
            issued_at_epoch_millis,
            expires_at_epoch_millis: generation.not_after_epoch_millis,
        });
        applied.retrieved_immutable_raw = None;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_begin_dispatch(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &BeginDispatchMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.require_original_stage_selection(transaction,generation,request,mutation)?;
        self.ensure_object(transaction, request, &mutation.request_object)?;
        let transport_digest = self.verify_expected_role_artifact(
            generation,
            &mutation.transport_authorization,
            ServiceRole::CredentialTransport,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.transport_authorization.body.payload {
            NestedAuthorityPayload::CredentialUse(credential)
                if credential.credential_use_id
                    == mutation.credential_use_id
                    && credential.credential_binding_sha256
                        == mutation.credential_binding_sha256
                    && credential.target_effect_id
                        == mutation.target_effect_id => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "credential_transport_authorization_mismatch",
                    reason: "credential transport artifact does not bind credential use, credential, and target effect"
                        .to_owned(),
                })
            }
        }
        transaction.execute(
            statements::INSERT_TARGET_EFFECT_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.target_effect_id),
                text(&request.attempt_id),
                text_digest(&mutation.idempotency_key_sha256),
                text_digest(&mutation.request_object.content_sha256),
                text_digest(&transport_digest),
            ],
        )?;
        transaction.execute(
            statements::INSERT_CREDENTIAL_USE_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.credential_use_id),
                text(&request.attempt_id),
                text_digest(&mutation.credential_binding_sha256),
                text_digest(&transport_digest),
                text(&mutation.target_effect_id),
            ],
        )?;
        self.transition(
            transaction,
            request,
            attempt,
            fence,
            AttemptState::Dispatching,
            vec![
                mutation.transport_authorization.body.artifact_id.clone(),
                mutation.target_effect_id.clone(),
                mutation.credential_use_id.clone(),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_dispatch_outcome(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &RecordDispatchOutcomeMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        if !matches!(
            mutation.outcome,
            TargetEffectState::Observed | TargetEffectState::OutcomeUnknown
        ) {
            return Err(AuthorityError::InvalidContract {
                field: "recordDispatchOutcome.outcome",
                reason: "only OBSERVED or OUTCOME_UNKNOWN is accepted"
                    .to_owned(),
            });
        }
        match (mutation.outcome, &mutation.response_object) {
            (TargetEffectState::Observed, Some(object)) => {
                self.ensure_object(transaction, request, object)?;
            }
            (TargetEffectState::OutcomeUnknown, None) => {}
            _ => {
                return Err(AuthorityError::InvalidContract {
                    field: "recordDispatchOutcome.responseObject",
                    reason: "OBSERVED requires immutable raw response bytes; OUTCOME_UNKNOWN forbids inferred bytes"
                        .to_owned(),
                })
            }
        }
        let transport_digest = self.verify_expected_role_artifact(
            generation,
            &mutation.transport_evidence,
            ServiceRole::CredentialTransport,
            request,
            trusted_epoch_millis,
        )?;
        let effect_evidence = match &mutation.transport_evidence.body.payload {
            NestedAuthorityPayload::TargetEffect(effect)
                if effect.target_effect_id == mutation.target_effect_id
                    && effect.outcome == mutation.outcome
                    && effect.response_object_sha256
                        == mutation
                            .response_object
                            .as_ref()
                            .map(|object| object.content_sha256.clone()) =>
            {
                effect
            }
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "target_effect_evidence_mismatch",
                    reason: "transport evidence does not bind exact effect and outcome"
                        .to_owned(),
                })
            }
        };
        let existing = transaction
            .query_optional(
                statements::LOCK_TARGET_EFFECT_SQL,
                &[
                    text(&request.generation_id),
                    text(&mutation.target_effect_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "target_effect_missing",
                authoritative_state: None,
            })?;
        if existing.require_text("idempotency_key_sha256")?
            != effect_evidence.idempotency_key_sha256.0
            || existing.require_text("request_object_sha256")?
                != effect_evidence.request_object_sha256.0
        {
            return Err(AuthorityError::Authentication {
                code: "target_effect_evidence_binding_mismatch",
                reason: "transport evidence does not bind stored idempotency key and request object"
                    .to_owned(),
            });
        }
        if existing.require_text("state")?
            != match attempt.state {
                AttemptState::Dispatching => "DISPATCHING",
                AttemptState::OutcomeUnknown => "OUTCOME_UNKNOWN",
                _ => {
                    return Err(AuthorityError::Conflict {
                        code: "attempt_not_dispatch_reconcilable",
                        authoritative_state: Some(
                            attempt.state.as_str().to_owned(),
                        ),
                    })
                }
            }
        {
            return Err(AuthorityError::Conflict {
                code: "target_effect_state_mismatch",
                authoritative_state: Some(existing.require_text("state")?),
            });
        }
        transaction.execute(
            statements::UPDATE_TARGET_EFFECT_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.target_effect_id),
                PgValue::Text(target_effect_state_text(mutation.outcome)),
                mutation
                    .response_object
                    .as_ref()
                    .map(|object| text_digest(&object.content_sha256))
                    .unwrap_or(PgValue::Null),
                text_digest(&transport_digest),
                mutation
                    .uncertainty_code
                    .as_ref()
                    .map(text)
                    .unwrap_or(PgValue::Null),
            ],
        )?;
        transaction.execute(
            statements::UPDATE_CREDENTIAL_USE_STATE_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.target_effect_id),
                PgValue::Text(target_effect_state_text(mutation.outcome)),
            ],
        )?;
        let successor = match mutation.outcome {
            TargetEffectState::Observed => AttemptState::Observed,
            TargetEffectState::OutcomeUnknown => {
                AttemptState::OutcomeUnknown
            }
            _ => unreachable!(),
        };
        let mut result = self.transition(
            transaction,
            request,
            attempt,
            fence,
            successor,
            vec![
                mutation.transport_evidence.body.artifact_id.clone(),
                mutation.target_effect_id.clone(),
            ],
        )?;
        if mutation.outcome == TargetEffectState::OutcomeUnknown {
            result.disposition = ResultDisposition::OutcomeUnknown;
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_terminal(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &TerminalizeMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        if mutation.stable_resume_id != attempt.stable_resume_id {
            return Err(AuthorityError::Conflict {
                code: "stable_resume_id_mismatch",
                authoritative_state: Some(
                    attempt.stable_resume_id.0.clone(),
                ),
            });
        }
        let mut artifacts = Vec::new();
        for artifact in &mutation.terminal_artifacts {
            self.verify_nested(
                generation,
                artifact,
                request.operation,
                request,
                trusted_epoch_millis,
            )?;
            artifacts.push(artifact.body.artifact_id.clone());
        }
        let row = transaction
            .query_optional(
                statements::TERMINALIZE_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                    text(&mutation.terminal_code),
                    text_digest(&mutation.terminal_detail_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "terminalize_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        Ok(AppliedMutation {
            revision: row.require_u64("revision")?,
            state: AttemptState::TerminalFailed,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: artifacts,
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_finalize(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &FinalizeMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        mutation.final_envelope.validate()?;
        let body = &mutation.final_envelope.body;
        if body.generation_id != request.generation_id
            || body.attempt_id != request.attempt_id
            || body.attempt_revision != request.expected_revision
            || body.fence_token != fence.fence_token
            || body.stable_resume_id != attempt.stable_resume_id
            || body.finalization_id != mutation.finalization_id
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalize.finalEnvelope.body",
                reason: "final envelope does not bind the exact RELEASE_PREPARED state"
                    .to_owned(),
            });
        }
        let release_preparation_artifact =
            &mutation.final_envelope.authority_artifacts[0];
        self.verify_self_bound_nested(
            generation,
            release_preparation_artifact,
            ServiceRole::StateAuthority,
            trusted_epoch_millis,
        )?;
        let release_preparation_payload =
            match &release_preparation_artifact.body.payload {
                NestedAuthorityPayload::ReleasePreparationReceipt(
                    preparation,
                ) => preparation,
                _ => {
                    return Err(AuthorityError::InvalidContract {
                        field: "finalize.finalEnvelope.authorityArtifacts",
                        reason: "first authority artifact must be the post-CAS release-preparation receipt"
                            .to_owned(),
                    })
                }
            };
        if release_preparation_artifact.body.operation
            != OperationKind::ReleaseConsumeAndRetrieveExact
            || release_preparation_artifact.body.attempt_id
                != request.attempt_id
            || release_preparation_artifact.body.attempt_revision
                != request.expected_revision
            || release_preparation_artifact.body.fence_token
                != fence.fence_token
            || release_preparation_payload.successor_revision
                != request.expected_revision
            || release_preparation_payload.successor_state
                != AttemptState::ReleasePrepared
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_release_preparation_scope_mismatch",
                reason: "finalization requires the exact state-derived RELEASE_PREPARED CAS receipt"
                    .to_owned(),
            });
        }
        let locked_preparation = self.lock_release_preparation(
            transaction,
            generation,
            request,
            &release_preparation_payload.release_authorization_id,
        )?;
        if locked_preparation.finalization_id
            != mutation.finalization_id
            || locked_preparation.inspection_result_sha256
                != release_preparation_payload.inspection_result_sha256
            || locked_preparation.release_object_sha256
                != release_preparation_payload.release_object_sha256
            || locked_preparation
                .preparation
                .release_preparation_receipt
                != *release_preparation_artifact
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_release_preparation_mismatch",
                reason: "finalization does not contain the exact durable PREPARE result and receipt"
                    .to_owned(),
            });
        }
        self.ensure_object(
            transaction,
            request,
            &body.staged_request_object,
        )?;
        self.ensure_object(
            transaction,
            request,
            &body.raw_response_object,
        )?;
        if body.raw_response_object.content_sha256
            != locked_preparation.release_object_sha256
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_release_object_mismatch",
                reason: "final envelope object differs from the prepared release object"
                    .to_owned(),
            });
        }
        let inspection_artifact =
            &mutation.final_envelope.authority_artifacts[5];
        let inspection_artifact_sha256 = sha256_digest(
            &canonical_jcs_bytes(inspection_artifact)?,
        );
        let inspection = self.lock_inspection_artifact(
            transaction,
            &request.generation_id,
            &inspection_artifact_sha256,
        )?;
        let inspection_payload = match &inspection_artifact.body.payload {
            NestedAuthorityPayload::ImmutableInspection(payload) => payload,
            _ => {
                return Err(AuthorityError::InvalidContract {
                    field: "finalize.finalEnvelope.authorityArtifacts",
                    reason: "sixth authority artifact must be the immutable inspection"
                        .to_owned(),
                })
            }
        };
        if inspection.inspection_id != inspection_payload.inspection_id
            || inspection.inspection_operation_id
                != inspection_payload.inspection_operation_id
            || inspection.inspection_artifact_sha256
                != inspection_artifact_sha256
            || inspection.attempt_id != request.attempt_id
            || inspection.object_id != body.raw_response_object.object_id
            || inspection.object_sha256
                != body.raw_response_object.content_sha256
            || inspection.object_length
                != body.raw_response_object.content_length
            || inspection_payload.object_id
                != body.raw_response_object.object_id
            || inspection_payload.content_sha256
                != body.raw_response_object.content_sha256
            || inspection_payload.content_length
                != body.raw_response_object.content_length
            || !inspection_payload.bytes_immutable
            || !inspection_payload.replacement_prohibited
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_inspection_mismatch",
                reason: "finalization must bind the exact signed inspection of its immutable raw response"
                    .to_owned(),
            });
        }
        self.verify_expected_role_artifact(
            generation,
            &mutation.final_envelope_verification,
            ServiceRole::PolicyProofVerifier,
            request,
            trusted_epoch_millis,
        )?;
        let final_verification =
            match &mutation.final_envelope_verification.body.payload {
                NestedAuthorityPayload::FinalEnvelopeVerification(
                    verification,
                )
                    if verification.passed
                        && verification.policy_decision_id
                            == body.policy_decision_id
                        && verification.final_envelope_body_sha256
                            == mutation.final_envelope.body_sha256
                        && verification.raw_response_object_sha256
                            == body.raw_response_object.content_sha256
                        && verification.response_framing_sha256
                            == body
                                .http11_framing
                                .canonical_framing_sha256
                        && verification.released_projection_sha256
                            == body.released_projection_sha256 =>
                {
                    verification
                }
                _ => {
                    return Err(AuthorityError::Authentication {
                        code: "final_envelope_verification_invalid",
                        reason: "finalization requires a passing final-envelope DTO bound to body, raw bytes, framing, and released projection"
                            .to_owned(),
                    })
                }
            };
        if mutation.artifact_ledger_evidence
            != mutation.final_envelope.authority_artifacts[7]
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_object_receipt_not_in_envelope",
                reason: "finalization artifact-ledger evidence must be the exact signed slot-eight artifact commit"
                    .to_owned(),
            });
        }
        match &mutation.artifact_ledger_evidence.body.payload {
            NestedAuthorityPayload::ArtifactCommit(commit)
                if commit.object_id == body.raw_response_object.object_id
                    && commit.object_kind
                        == body.raw_response_object.object_kind
                    && commit.content_sha256
                        == body.raw_response_object.content_sha256
                    && commit.content_length
                        == body.raw_response_object.content_length => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "finalization_object_receipt_mismatch",
                    reason: "artifact ledger evidence does not bind the immutable raw response object"
                        .to_owned(),
                })
            }
        }
        let stored_policy = transaction
            .query_optional(
                statements::LOCK_POLICY_DECISION_SQL,
                &[
                    text(&request.generation_id),
                    text(&body.policy_decision_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "policy_decision_missing",
                authoritative_state: None,
            })?;
        if stored_policy.require_text("policy_generation_sha256")?
            != final_verification.policy_generation_sha256.0
            || !stored_policy.require_bool("passed")?
        {
            return Err(AuthorityError::Conflict {
                code: "policy_decision_binding_mismatch",
                authoritative_state: Some(
                    body.policy_decision_id.0.clone(),
                ),
            });
        }
        let policy_evidence_sha256 =
            sha256_digest(&canonical_jcs_bytes(
                &mutation.final_envelope_verification,
            )?);
        let policy_updated = transaction.execute(
            statements::FINALIZE_POLICY_DECISION_SQL,
            &[
                text(&request.generation_id),
                text(&body.policy_decision_id),
                text_digest(&body.raw_response_object.content_sha256),
                text_digest(&body.released_projection_sha256),
                text_digest(&policy_evidence_sha256),
            ],
        )?;
        if policy_updated != 1 {
            return Err(AuthorityError::Conflict {
                code: "policy_decision_finalize_cas_failed",
                authoritative_state: Some(
                    body.policy_decision_id.0.clone(),
                ),
            });
        }
        let expected_roles = [
            ServiceRole::StateAuthority,
            ServiceRole::CredentialTransport,
            ServiceRole::CredentialTransport,
            ServiceRole::PolicyProofVerifier,
            ServiceRole::PolicyProofVerifier,
            ServiceRole::StateAuthority,
            ServiceRole::ReleaseAttestorPublisher,
            ServiceRole::ImmutableArtifactLedger,
            ServiceRole::StateAuthority,
            ServiceRole::ReleaseAttestorPublisher,
        ];
        for (artifact, expected_role) in mutation
            .final_envelope
            .authority_artifacts
            .iter()
            .zip(expected_roles)
        {
            self.verify_self_bound_nested(
                generation,
                artifact,
                expected_role,
                trusted_epoch_millis,
            )?;
        }
        let mut durable_artifacts = mutation
            .final_envelope
            .authority_artifacts
            .iter()
            .collect::<Vec<_>>();
        durable_artifacts.push(&mutation.final_envelope_verification);
        let (transition_chain_sha256, evidence_root_sha256) =
            self.persist_finalization_evidence_and_roots(
                transaction,
                request,
                &body.raw_response_object,
                &durable_artifacts,
            )?;
        if transition_chain_sha256 != body.transition_chain_sha256
            || evidence_root_sha256 != body.evidence_root_sha256
        {
            return Err(AuthorityError::Authentication {
                code: "finalization_durable_root_mismatch",
                reason: "final envelope transition and evidence roots do not match authoritative durable rows"
                    .to_owned(),
            });
        }
        let canonical = canonical_jcs_bytes(&mutation.final_envelope)?;
        let canonical_sha256 = sha256_digest(&canonical);
        transaction.execute(
            statements::INSERT_FINALIZATION_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.finalization_id),
                text(&request.attempt_id),
                PgValue::U64(request.expected_revision + 1),
                text(&fence.fence_token),
                PgValue::Bytes(canonical),
                text_digest(&canonical_sha256),
                text_digest(
                    &inspection.canonical_signed_result_sha256,
                ),
                text_digest(&body.transition_chain_sha256),
                text_digest(&body.evidence_root_sha256),
            ],
        )?;
        let mut artifact_ids = vec![
            mutation
                .final_envelope_verification
                .body
                .artifact_id
                .clone(),
            mutation.finalization_id.clone(),
        ];
        artifact_ids.extend(
            mutation
                .final_envelope
                .authority_artifacts
                .iter()
                .map(|artifact| artifact.body.artifact_id.clone()),
        );
        self.transition(
            transaction,
            request,
            attempt,
            fence,
            AttemptState::Finalized,
            artifact_ids,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_publish(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &PublishMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.ensure_object(
            transaction,
            request,
            &mutation.payload_object,
        )?;
        self.verify_expected_role_artifact(
            generation,
            &mutation.publisher_authorization,
            ServiceRole::ReleaseAttestorPublisher,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.publisher_authorization.body.payload {
            NestedAuthorityPayload::Publication(publication)
                if publication.publication_id == mutation.publication_id
                    && publication.outbox_id == mutation.outbox_id
                    && publication.finalization_id
                        == mutation.finalization_id
                    && publication.payload_object_sha256
                        == mutation.payload_object.content_sha256
                    && publication.publication_state
                        == super::super::lifecycle::OutboxState::Pending
                    && publication.delivery_receipt_sha256.is_none() => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "publisher_authorization_mismatch",
                    reason: "publisher artifact does not bind pending publication and exact object"
                        .to_owned(),
                })
            }
        }
        self.require_finalization(
            transaction,
            request,
            &mutation.finalization_id,
        )?;
        transaction.execute(
            statements::INSERT_OUTBOX_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.outbox_id),
                text(&request.attempt_id),
                text(&mutation.publication_id),
                text(&mutation.finalization_id),
                text_digest(&mutation.payload_object.content_sha256),
            ],
        )?;
        self.transition(
            transaction,
            request,
            attempt,
            fence,
            AttemptState::Published,
            vec![
                mutation.publisher_authorization.body.artifact_id.clone(),
                mutation.publication_id.clone(),
                mutation.outbox_id.clone(),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_release(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &ConsumeReleaseAndRetrieveExactMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        match mutation {
            ConsumeReleaseAndRetrieveExactMutation::Prepare(preparation) => {
                self.apply_release_preparation(
                    transaction,
                    generation,
                    request,
                    attempt,
                    fence,
                    preparation,
                    trusted_epoch_millis,
                )
            }
            ConsumeReleaseAndRetrieveExactMutation::Retrieve(retrieval) => {
                self.apply_release_retrieval(
                    transaction,
                    generation,
                    request,
                    attempt,
                    fence,
                    retrieval,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_release_preparation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &PrepareReleaseConsumptionMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        if attempt.state != AttemptState::Observed {
            return Err(AuthorityError::Conflict {
                code: "release_preparation_requires_observed_attempt",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            });
        }
        let binding = &mutation.binding;
        self.ensure_object(
            transaction,
            request,
            &binding.release_object,
        )?;
        self.verify_inspection_seed(
            transaction,
            generation,
            request,
            attempt,
            fence,
            mutation,
            trusted_epoch_millis,
        )?;
        let (release_finalization_id, one_use_nonce_sha256) =
            self.verify_release_preparation_artifacts(
                generation,
                request,
                mutation,
                trusted_epoch_millis,
            )?;
        let inspection = self.lock_inspection(
            transaction,
            &request.generation_id,
            &binding.inspection_result_sha256,
        )?;
        if inspection.attempt_id != request.attempt_id
            || inspection.object_id != binding.release_object.object_id
            || inspection.object_sha256
                != binding.release_object.content_sha256
            || inspection.object_length
                != binding.release_object.content_length
        {
            return Err(AuthorityError::Authentication {
                code: "release_preparation_inspection_object_mismatch",
                reason: "release preparation must bind the exact immutable object returned by the signed inspection"
                    .to_owned(),
            });
        }
        let preauthorization_artifact_sha256 = sha256_digest(
            &canonical_jcs_bytes(
                &mutation.release_consumption_preauthorization,
            )?,
        );
        let mut applied = self.transition(
            transaction,
            request,
            attempt,
            fence,
            AttemptState::ReleasePrepared,
            vec![
                mutation.release_authorization.body.artifact_id.clone(),
                mutation
                    .release_consumption_preauthorization
                    .body
                    .artifact_id
                    .clone(),
                binding.release_authorization_id.clone(),
            ],
        )?;
        let issued_at_epoch_millis =
            trusted_epoch_millis.ok_or_else(|| AuthorityError::NotReady {
                blockers: vec![
                    "release_preparation_requires_trusted_time".to_owned(),
                ],
            })?;
        applied.deferred_release = Some(DeferredRelease {
            authorization_id: binding.release_authorization_id.clone(),
            finalization_id: release_finalization_id.clone(),
            exact_release_request_sha256: binding.release_request_sha256.clone(),
            inspection_result_sha256: binding
                .inspection_result_sha256
                .clone(),
            release_object_sha256: binding
                .release_object
                .content_sha256
                .clone(),
            client_binding_sha256: binding.client_binding_sha256.clone(),
            exact_replay_key_sha256: binding
                .exact_replay_key_sha256
                .clone(),
            one_use_nonce_sha256: one_use_nonce_sha256.clone(),
            preauthorization_artifact_id: mutation
                .release_consumption_preauthorization
                .body
                .artifact_id
                .clone(),
            preauthorization_artifact_sha256,
            issued_at_epoch_millis,
            expires_at_epoch_millis: generation.not_after_epoch_millis,
        });
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_release_retrieval(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &RetrievePreparedReleaseMutation,
    ) -> AuthorityResult<AppliedMutation> {
        if !matches!(
            attempt.state,
            AttemptState::Finalized | AttemptState::Published
        ) {
            return Err(AuthorityError::Conflict {
                code: "release_retrieval_requires_finalized_attempt",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            });
        }
        let binding = &mutation.binding;
        self.ensure_object(transaction, request, &binding.release_object)?;
        let prepared = self.lock_release_preparation(
            transaction,
            generation,
            request,
            &binding.release_authorization_id,
        )?;
        self.verify_retrieval_binding(
            generation,
            request,
            binding,
            &mutation.prepared_consumption_receipt,
            &prepared,
        )?;
        let finalization = transaction
            .query_optional(
                statements::LOCK_FINALIZATION_BY_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "release_finalization_missing",
                authoritative_state: None,
            })?;
        if finalization.require_text("finalization_id")?
            != prepared.finalization_id.0
            || finalization.require_text("inspection_result_sha256")?
                != binding.inspection_result_sha256.0
        {
            return Err(AuthorityError::Authentication {
                code: "release_retrieval_finalization_mismatch",
                reason: "retrieval is not bound to the prepared release finalization and inspection"
                    .to_owned(),
            });
        }
        let canonical_final_envelope =
            finalization.require_bytes("canonical_final_envelope")?;
        let canonical_final_envelope_sha256 = Digest(
            finalization.require_text("canonical_final_envelope_sha256")?,
        );
        if sha256_digest(&canonical_final_envelope)
            != canonical_final_envelope_sha256
        {
            return Err(AuthorityError::Backend {
                code: "release_final_envelope_digest_mismatch",
                reason: "stored final envelope failed its exact digest"
                    .to_owned(),
            });
        }
        let final_envelope: super::super::rpc::CanonicalFinalEnvelope =
            serde_json::from_slice(&canonical_final_envelope).map_err(
                |error| AuthorityError::Serialization {
                    reason: format!(
                        "stored final envelope could not be decoded: {error}"
                    ),
                },
            )?;
        final_envelope.validate()?;
        if final_envelope.body.raw_response_object
            != binding.release_object
        {
            return Err(AuthorityError::Authentication {
                code: "release_final_envelope_object_mismatch",
                reason: "final envelope does not bind the exact prepared immutable object reference"
                    .to_owned(),
            });
        }
        let prepared_artifact =
            &prepared.preparation.release_preparation_receipt;
        if final_envelope.authority_artifacts.first()
            != Some(prepared_artifact)
        {
            return Err(AuthorityError::Authentication {
                code: "release_preparation_not_in_final_envelope",
                reason: "final envelope slot 1 is not the exact durable release-preparation receipt"
                    .to_owned(),
            });
        }
        self.verify_self_bound_nested(
            generation,
            &mutation.final_envelope_verification,
            ServiceRole::PolicyProofVerifier,
            None,
        )?;
        let verification =
            match &mutation.final_envelope_verification.body.payload {
                NestedAuthorityPayload::FinalEnvelopeVerification(
                    verification,
                )
                    if verification.passed
                        && verification.final_envelope_body_sha256
                            == final_envelope.body_sha256
                        && verification.raw_response_object_sha256
                            == binding.release_object.content_sha256
                        && verification.response_framing_sha256
                            == final_envelope
                                .body
                                .http11_framing
                                .canonical_framing_sha256
                        && verification.released_projection_sha256
                            == final_envelope
                                .body
                                .released_projection_sha256 =>
                {
                    verification
                }
                _ => {
                    return Err(AuthorityError::Authentication {
                        code: "release_final_envelope_verification_invalid",
                        reason: "retrieval requires the passing final verification bound to the finalized ten-artifact envelope"
                            .to_owned(),
                    })
                }
            };
        if mutation.final_envelope_verification.body.operation
            != OperationKind::AttemptFinalize
            || mutation.final_envelope_verification.body.attempt_id
                != request.attempt_id
            || mutation.final_envelope_verification.body.fence_token
                != fence.fence_token
            || verification.policy_decision_id
                != final_envelope.body.policy_decision_id
        {
            return Err(AuthorityError::Authentication {
                code: "release_final_verification_scope_mismatch",
                reason: "final verification does not carry the installed attempt, fence, operation, and policy scope"
                    .to_owned(),
            });
        }
        let final_verification_sha256 = sha256_digest(
            &canonical_jcs_bytes(&mutation.final_envelope_verification)?,
        );
        self.require_persisted_evidence(
            transaction,
            request,
            &mutation.final_envelope_verification,
            &final_verification_sha256,
        )?;
        let (immutable_raw, _) = self.load_immutable_raw(
            transaction,
            request,
            &binding.release_object,
        )?;
        Ok(AppliedMutation {
            revision: attempt.revision,
            state: attempt.state,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: vec![
                prepared_artifact.body.artifact_id.clone(),
                mutation
                    .final_envelope_verification
                    .body
                    .artifact_id
                    .clone(),
            ],
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: Some(immutable_raw),
            response_data_result: Some(
                ResponseDataStateResult::ReleaseRetrieval(
                    ReleaseRetrievalResult {
                        release_authorization_id: binding
                            .release_authorization_id
                            .clone(),
                        exact_replay_key_sha256: binding
                            .exact_replay_key_sha256
                            .clone(),
                        prepared_canonical_result_sha256: prepared
                            .canonical_signed_result_sha256,
                        signed_state_mutation_receipt_sha256: prepared
                            .preparation
                            .durable_result
                            .signed_state_mutation_receipt_sha256
                            .clone(),
                        release_preparation_receipt_sha256: prepared
                            .preparation
                            .release_preparation_receipt_sha256
                            .clone(),
                        finalization_id: prepared.finalization_id,
                        final_envelope_sha256:
                            canonical_final_envelope_sha256,
                        final_envelope_verification_sha256:
                            final_verification_sha256,
                        release_object_sha256: binding
                            .release_object
                            .content_sha256
                            .clone(),
                    },
                ),
            ),
        })
    }

    fn apply_replay_resolution(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &ResolveReplayMutation,
    ) -> AuthorityResult<AppliedMutation> {
        mutation
            .source_replay_id
            .validate("resolveReplay.sourceReplayId", 128)?;
        mutation
            .source_operation_id
            .validate("resolveReplay.sourceOperationId", 128)?;
        mutation
            .source_exact_request_sha256
            .validate("resolveReplay.sourceExactRequestSha256")?;
        mutation
            .source_canonical_result_sha256
            .validate("resolveReplay.sourceCanonicalResultSha256")?;
        if mutation.stable_resume_id != attempt.stable_resume_id
            || mutation.source_replay_id == request.request_id
        {
            return Err(AuthorityError::InvalidContract {
                field: "resolveReplay",
                reason: "replay must bind the persisted stable-resume ID and a prior replay key"
                    .to_owned(),
            });
        }
        let row = transaction
            .query_optional(
                statements::LOCK_REPLAY_RESULT_SQL,
                &[
                    text(&request.generation_id),
                    text(&mutation.source_replay_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "replay_source_missing",
                authoritative_state: Some(
                    mutation.source_replay_id.0.clone(),
                ),
            })?;
        let source_attempt_id = row.optional_text("attempt_id")?;
        let source_fence_token = row.optional_text("fence_token")?;
        if row.require_text("operation_id")?
            != mutation.source_operation_id.0
            || row.require_text("exact_request_sha256")?
                != mutation.source_exact_request_sha256.0
            || row.require_text("canonical_signed_result_sha256")?
                != mutation.source_canonical_result_sha256.0
            || source_attempt_id.as_deref()
                != Some(request.attempt_id.0.as_str())
            || source_fence_token.as_deref()
                != Some(fence.fence_token.0.as_str())
        {
            return Err(AuthorityError::Authentication {
                code: "replay_source_scope_mismatch",
                reason: "replay source does not match the exact installed attempt, operation, request, result, and fence"
                    .to_owned(),
            });
        }
        let canonical_result =
            row.require_bytes("canonical_signed_result")?;
        if sha256_digest(&canonical_result)
            != mutation.source_canonical_result_sha256
        {
            return Err(AuthorityError::Backend {
                code: "replay_source_result_digest_mismatch",
                reason: "replay source bytes failed their durable digest"
                    .to_owned(),
            });
        }
        let source_result: SignedOperationResult =
            serde_json::from_slice(&canonical_result).map_err(|error| {
                AuthorityError::Serialization {
                    reason: format!(
                        "replay source could not be decoded: {error}"
                    ),
                }
            })?;
        verify_signed_operation_result(&source_result, generation)?;
        if source_result.body.operation
            != OperationKind::ReleaseConsumeAndRetrieveExact
            || !matches!(
                source_result.body.response_data_result,
                Some(ResponseDataStateResult::ReleasePreparation(_))
                    | Some(ResponseDataStateResult::ReleaseRetrieval(_))
            )
        {
            return Err(AuthorityError::Authentication {
                code: "replay_source_not_release_phase_result",
                reason: "resolve replay only returns an exact durable PREPARE or RETRIEVE canonical result"
                    .to_owned(),
            });
        }
        Ok(AppliedMutation {
            revision: attempt.revision,
            state: attempt.state,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: Vec::new(),
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: Some(
                ResponseDataStateResult::ReplayResolution(
                    ReplayResolutionResult {
                        source_replay_id: mutation.source_replay_id.clone(),
                        source_operation_id: mutation
                            .source_operation_id
                            .clone(),
                        source_exact_request_sha256: mutation
                            .source_exact_request_sha256
                            .clone(),
                        source_canonical_result_sha256: mutation
                            .source_canonical_result_sha256
                            .clone(),
                        source_canonical_result_base64url:
                            encode_base64url(&canonical_result),
                    },
                ),
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_settlement(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &SettleAttemptMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        mutation
            .terminal_code
            .validate("settleAttempt.terminalCode", 128)?;
        mutation
            .terminal_detail_sha256
            .validate("settleAttempt.terminalDetailSha256")?;
        mutation.cleanup_deadline.validate()?;
        if mutation.stable_resume_id != attempt.stable_resume_id
            || mutation.cleanup_deadline != request.deadline
            || fence.state != FenceState::Active
        {
            return Err(AuthorityError::Conflict {
                code: "settlement_authority_scope_mismatch",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            });
        }
        let cleanup_instant = self.boot_clock.current_boot_instant()?;
        mutation.cleanup_deadline.ensure_current(&cleanup_instant)?;
        if mutation.observed_boot_id != cleanup_instant.boot_id
            || mutation.observed_boot_millis > cleanup_instant.boot_millis
            || cleanup_instant
                .boot_millis
                .saturating_sub(mutation.observed_boot_millis)
                > self.configuration.cleanup_timeout_millis
        {
            return Err(AuthorityError::Conflict {
                code: "settlement_observation_stale",
                authoritative_state: Some(format!(
                    "{}:{}",
                    cleanup_instant.boot_id,
                    cleanup_instant.boot_millis
                )),
            });
        }
        let observed = self.cgroup_observer.observe(
            &CgroupOwner {
                process_id: attempt.owner_process_id.clone(),
                pid: attempt.owner_pid,
                process_start_time_ticks:
                    attempt.owner_start_time_ticks,
                cgroup_id: attempt.owner_cgroup_id.clone(),
            },
            &mutation.cleanup_deadline,
        )?;
        if !observed.owner_death_observed
            || !observed.cgroup_empty_observed
            || !observed.cgroup_death_observed
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![format!(
                    "settlement_cleanup_incomplete:{}",
                    attempt.stable_resume_id
                )],
            });
        }
        let (target_effect_state, upstream_response_sha256) =
            if let Some(target_effect_id) = &mutation.target_effect_id {
                let target = transaction
                    .query_optional(
                        statements::LOCK_TARGET_EFFECT_SQL,
                        &[
                            text(&request.generation_id),
                            text(target_effect_id),
                        ],
                    )?
                    .ok_or_else(|| AuthorityError::Conflict {
                        code: "settlement_target_effect_missing",
                        authoritative_state: Some(
                            target_effect_id.0.clone(),
                        ),
                    })?;
                if target.require_text("attempt_id")?
                    != request.attempt_id.0
                {
                    return Err(AuthorityError::Authentication {
                        code: "settlement_target_effect_attempt_mismatch",
                        reason: "target effect belongs to a different attempt"
                            .to_owned(),
                    });
                }
                let state = parse_target_effect_state(
                    &target.require_text("state")?,
                )?;
                if !matches!(
                    state,
                    TargetEffectState::Observed
                        | TargetEffectState::ReconciledFailure
                ) {
                    return Err(AuthorityError::NotReady {
                        blockers: vec![format!(
                            "target_effect_not_reconciled:{}:{state:?}",
                            target_effect_id
                        )],
                    });
                }
                let response =
                    target.optional_text("response_object_sha256")?.map(Digest);
                if response != mutation.upstream_response_sha256 {
                    return Err(AuthorityError::Authentication {
                        code: "settlement_target_response_mismatch",
                        reason: "settlement response digest differs from the reconciled target effect"
                            .to_owned(),
                    });
                }
                (Some(state), response)
            } else {
                if mutation.upstream_response_sha256.is_some()
                    || matches!(
                        attempt.state,
                        AttemptState::Dispatching
                            | AttemptState::OutcomeUnknown
                            | AttemptState::Observed
                            | AttemptState::ReleasePrepared
                            | AttemptState::Finalized
                            | AttemptState::Published
                    )
                {
                    return Err(AuthorityError::InvalidContract {
                        field: "settleAttempt.targetEffectId",
                        reason: "post-dispatch settlement requires the exact reconciled target effect"
                            .to_owned(),
                    });
                }
                (None, None)
            };
        let expected_terminal_detail_sha256 =
            sha256_digest(&canonical_jcs_bytes(&(
                "SETTLE_ATTEMPT",
                &request.generation_id,
                &request.attempt_id,
                attempt.revision,
                attempt.state,
                &attempt.stable_resume_id,
                &fence.fence_token,
                fence.state,
                &mutation.terminal_code,
                &mutation.target_effect_id,
                target_effect_state,
                &upstream_response_sha256,
                (
                    &mutation.observed_boot_id,
                    mutation.observed_boot_millis,
                ),
                (
                    &mutation.cleanup_deadline.boot_id,
                    mutation.cleanup_deadline.deadline_boot_millis,
                ),
                (
                    &attempt.owner_process_id,
                    attempt.owner_pid,
                    attempt.owner_start_time_ticks,
                    &attempt.owner_cgroup_id,
                ),
                (
                    observed.owner_death_observed,
                    observed.cgroup_empty_observed,
                    observed.cgroup_death_observed,
                ),
            ))?);
        if mutation.terminal_detail_sha256
            != expected_terminal_detail_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "settleAttempt.terminalDetailSha256",
                reason: "terminal detail must be derived from the persisted attempt, fence, reconciled target effect, deadlines, and live cleanup observation"
                    .to_owned(),
            });
        }
        self.verify_expected_role_artifact(
            generation,
            &mutation.reconciliation_evidence,
            ServiceRole::CleanupWatchdog,
            request,
            trusted_epoch_millis,
        )?;
        let expected_job_id = Identifier(format!(
            "settlement:{}:{}",
            request.attempt_id.0, request.expected_revision
        ));
        match &mutation.reconciliation_evidence.body.payload {
            NestedAuthorityPayload::Reconciliation(reconciliation)
                if reconciliation.reconciliation_job_id
                    == expected_job_id
                    && reconciliation.domain.0
                        == "TERMINAL_SETTLEMENTS"
                    && reconciliation.predecessor_state
                        == ReconciliationState::Pending
                    && reconciliation.successor_state
                        == ReconciliationState::Complete
                    && reconciliation.authoritative_cursor
                        == request.expected_revision
                    && reconciliation.result_sha256
                        == expected_terminal_detail_sha256 => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "settlement_reconciliation_evidence_mismatch",
                    reason: "reconciliation evidence does not bind the exact settlement cursor and result"
                        .to_owned(),
                })
            }
        }
        let recovery_required = matches!(
            attempt.state,
            AttemptState::Dispatching | AttemptState::OutcomeUnknown
        ) || matches!(
            target_effect_state,
            Some(TargetEffectState::ReconciledFailure)
        );
        let recovery_evidence = match (
            recovery_required,
            mutation.recovery_evidence.as_ref(),
        ) {
            (true, Some(evidence)) => {
                self.verify_expected_role_artifact(
                    generation,
                    evidence,
                    ServiceRole::CleanupWatchdog,
                    request,
                    trusted_epoch_millis,
                )?;
                match &evidence.body.payload {
                    NestedAuthorityPayload::Recovery(recovery)
                        if recovery.recovery_action.0
                            == "SETTLE_ATTEMPT"
                            && recovery.stable_resume_id
                                == attempt.stable_resume_id
                            && recovery.predecessor_state == attempt.state
                            && recovery.successor_state
                                == AttemptState::TerminalFailed
                            && recovery.deadline_boot_id
                                == attempt.deadline_boot_id
                            && recovery.deadline_boot_millis
                                == attempt.deadline_boot_millis
                            && recovery.observed_boot_id
                                == mutation.observed_boot_id
                            && recovery.observed_boot_millis
                                == mutation.observed_boot_millis
                            && recovery.cleanup_deadline_boot_id
                                == mutation.cleanup_deadline.boot_id
                            && recovery.cleanup_deadline_boot_millis
                                == mutation
                                    .cleanup_deadline
                                    .deadline_boot_millis
                            && recovery.owner_process_id
                                == attempt.owner_process_id
                            && recovery.owner_pid == attempt.owner_pid
                            && recovery.owner_start_time_ticks
                                == attempt.owner_start_time_ticks
                            && recovery.owner_cgroup_id
                                == attempt.owner_cgroup_id
                            && recovery.owner_death_observed
                                == observed.owner_death_observed
                            && recovery.cgroup_empty_observed
                                == observed.cgroup_empty_observed
                            && recovery.cgroup_death_observed
                                == observed.cgroup_death_observed
                            && recovery.fence_token == fence.fence_token
                            && recovery.predecessor_fence_state
                                == FenceState::Active
                            && recovery.successor_fence_state
                                == FenceState::Revoked => Some(evidence),
                    _ => {
                        return Err(AuthorityError::Authentication {
                            code: "settlement_recovery_evidence_mismatch",
                            reason: "recovery evidence does not bind the exact attempt, owner cleanup, terminal transition, and fence revocation"
                                .to_owned(),
                        })
                    }
                }
            }
            (true, None) => {
                return Err(AuthorityError::InvalidContract {
                    field: "settleAttempt.recoveryEvidence",
                    reason: "ambiguous or reconciled-failure settlement requires signed recovery evidence"
                        .to_owned(),
                })
            }
            (false, Some(_)) => {
                return Err(AuthorityError::InvalidContract {
                    field: "settleAttempt.recoveryEvidence",
                    reason: "recovery evidence is forbidden when no recovery path was required"
                        .to_owned(),
                })
            }
            (false, None) => None,
        };
        let reconciliation_sha256 = self.persist_authority_evidence(
            transaction,
            request,
            "SETTLEMENT_RECONCILIATION",
            &mutation.reconciliation_evidence,
        )?;
        let recovery_sha256 = recovery_evidence
            .map(|evidence| {
                self.persist_authority_evidence(
                    transaction,
                    request,
                    "SETTLEMENT_RECOVERY",
                    evidence,
                )
            })
            .transpose()?;
        let row = transaction
            .query_optional(
                statements::TERMINALIZE_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                    text(&mutation.terminal_code),
                    text_digest(&mutation.terminal_detail_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "settlement_terminalize_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        let revision = row.require_u64("revision")?;
        let revoked = transaction.query_optional(
            statements::REVOKE_FENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                PgValue::U64(revision),
            ],
        )?;
        if revoked.is_none() {
            return Err(AuthorityError::Conflict {
                code: "settlement_fence_revoke_cas_failed",
                authoritative_state: Some(fence.fence_token.0.clone()),
            });
        }
        let recovery_artifact_id =
            recovery_evidence.map(|evidence| evidence.body.artifact_id.clone());
        let mut artifact_ids = vec![
            mutation
                .reconciliation_evidence
                .body
                .artifact_id
                .clone(),
        ];
        if let Some(recovery_artifact_id) = &recovery_artifact_id {
            artifact_ids.push(recovery_artifact_id.clone());
        }
        Ok(AppliedMutation {
            revision,
            state: AttemptState::TerminalFailed,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids,
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: Some(
                ResponseDataStateResult::Settlement(SettlementResult {
                    terminal_code: mutation.terminal_code.clone(),
                    terminal_detail_sha256: mutation
                        .terminal_detail_sha256
                        .clone(),
                    predecessor_revision: attempt.revision,
                    predecessor_state: attempt.state,
                    successor_revision: revision,
                    successor_state: AttemptState::TerminalFailed,
                    target_effect_id: mutation.target_effect_id.clone(),
                    target_effect_state,
                    upstream_response_sha256,
                    reconciliation_artifact_id: mutation
                        .reconciliation_evidence
                        .body
                        .artifact_id
                        .clone(),
                    reconciliation_artifact_sha256:
                        reconciliation_sha256,
                    recovery_artifact_id,
                    recovery_artifact_sha256: recovery_sha256,
                }),
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_archive(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &ArchiveMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        if mutation.object_ids.is_empty() {
            return Err(AuthorityError::InvalidContract {
                field: "archive.objectIds",
                reason: "archive must contain immutable objects".to_owned(),
            });
        }
        let mut canonical_object_ids = mutation.object_ids.clone();
        canonical_object_ids.sort();
        canonical_object_ids.dedup();
        if canonical_object_ids != mutation.object_ids {
            return Err(AuthorityError::InvalidContract {
                field: "archive.objectIds",
                reason: "object IDs must be unique and canonically sorted"
                    .to_owned(),
            });
        }
        self.require_finalization(
            transaction,
            request,
            &mutation.finalization_id,
        )?;
        for object_id in &canonical_object_ids {
            let object = transaction
                .query_optional(
                    statements::LOCK_IMMUTABLE_OBJECT_BY_ID_SQL,
                    &[
                        text(&request.generation_id),
                        text(object_id),
                    ],
                )?
                .ok_or_else(|| AuthorityError::Conflict {
                    code: "archive_object_missing",
                    authoritative_state: Some(object_id.0.clone()),
                })?;
            if object.require_text("attempt_id")?
                != request.attempt_id.0
            {
                return Err(AuthorityError::Conflict {
                    code: "archive_object_attempt_mismatch",
                    authoritative_state: Some(object_id.0.clone()),
                });
            }
        }
        self.verify_expected_role_artifact(
            generation,
            &mutation.archive_evidence,
            ServiceRole::ImmutableArtifactLedger,
            request,
            trusted_epoch_millis,
        )?;
        let object_set_sha256 =
            sha256_digest(&canonical_jcs_bytes(&canonical_object_ids)?);
        match &mutation.archive_evidence.body.payload {
            NestedAuthorityPayload::Archive(archive)
                if archive.archive_id == mutation.archive_id
                    && archive.finalization_id
                        == mutation.finalization_id
                    && archive.canonical_archive_sha256
                        == mutation.canonical_archive_sha256
                    && archive.object_set_sha256 == object_set_sha256 => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "archive_artifact_mismatch",
                    reason: "archive artifact does not bind archive, finalization, canonical digest, and object set"
                        .to_owned(),
                })
            }
        }
        transaction.execute(
            statements::INSERT_ARCHIVE_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.archive_id),
                text(&request.attempt_id),
                text(&mutation.finalization_id),
                text_digest(&mutation.canonical_archive_sha256),
                PgValue::Json(
                    serde_json::to_value(&canonical_object_ids).map_err(
                        |error| AuthorityError::Serialization {
                            reason: error.to_string(),
                        },
                    )?,
                ),
            ],
        )?;
        self.transition(
            transaction,
            request,
            attempt,
            fence,
            AttemptState::Archived,
            vec![
                mutation.archive_evidence.body.artifact_id.clone(),
                mutation.archive_id.clone(),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_revoke(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &RevokeFenceMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.verify_expected_role_artifact(
            generation,
            &mutation.cleanup_authorization,
            ServiceRole::CleanupWatchdog,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.cleanup_authorization.body.payload {
            NestedAuthorityPayload::CleanupObservation(cleanup)
                if cleanup.cleanup_action.0 == "REVOKE_FENCE"
                    && cleanup.owner_process_id
                        == fence.owner_process_id
                    && cleanup.owner_pid == fence.owner_pid
                    && cleanup.owner_start_time_ticks
                        == fence.owner_start_time_ticks
                    && cleanup.owner_cgroup_id == fence.owner_cgroup_id
                    && cleanup.predecessor_fence_state
                        == FenceState::Active => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "fence_revoke_authorization_mismatch",
                    reason: "cleanup authorization does not bind exact owner and active fence"
                        .to_owned(),
                })
            }
        }
        if fence.state != FenceState::Active {
            return Err(AuthorityError::Conflict {
                code: "fence_already_revoked",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        let artifact_ids = vec![
            mutation.cleanup_authorization.body.artifact_id.clone(),
        ];
        let applied = if attempt.state.is_terminal() {
            AppliedMutation {
                revision: attempt.revision,
                state: attempt.state,
                fence_token: fence.fence_token.clone(),
                stable_resume_id: attempt.stable_resume_id.clone(),
                disposition: ResultDisposition::Applied,
                conflict_code: None,
                artifact_ids,
                deferred_inspection: None,
                deferred_release: None,
                retrieved_immutable_raw: None,
                response_data_result: None,
            }
        } else {
            self.bump(
                transaction,
                request,
                attempt,
                fence,
                artifact_ids,
                ResultDisposition::Applied,
            )?
        };
        let row = transaction.query_optional(
            statements::REVOKE_FENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                PgValue::U64(applied.revision),
            ],
        )?;
        if row.is_none() {
            return Err(AuthorityError::Conflict {
                code: "fence_revoke_cas_failed",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_quiescence(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &ObserveQuiescenceMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        let observed = self.cgroup_observer.observe(
            &CgroupOwner {
                process_id: mutation.owner_process_id.clone(),
                pid: mutation.owner_pid,
                process_start_time_ticks: mutation.owner_start_time_ticks,
                cgroup_id: mutation.owner_cgroup_id.clone(),
            },
            &request.deadline,
        )?;
        if observed.owner_death_observed
            != mutation.owner_death_observed
            || observed.cgroup_empty_observed
                != mutation.cgroup_empty_observed
            || observed.cgroup_death_observed
                != mutation.cgroup_death_observed
        {
            return Err(AuthorityError::Conflict {
                code: "cgroup_observation_changed",
                authoritative_state: Some(format!(
                    "ownerDeath={},cgroupEmpty={},cgroupDeath={}",
                    observed.owner_death_observed,
                    observed.cgroup_empty_observed,
                    observed.cgroup_death_observed
                )),
            });
        }
        let evidence_digest = self.verify_expected_role_artifact(
            generation,
            &mutation.cleanup_observation,
            ServiceRole::CleanupWatchdog,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.cleanup_observation.body.payload {
            NestedAuthorityPayload::CleanupObservation(cleanup)
                if cleanup.cleanup_action.0 == "OBSERVE_QUIESCENCE"
                    && cleanup.owner_process_id
                        == mutation.owner_process_id
                    && cleanup.owner_pid == mutation.owner_pid
                    && cleanup.owner_start_time_ticks
                        == mutation.owner_start_time_ticks
                    && cleanup.owner_cgroup_id
                        == mutation.owner_cgroup_id
                    && cleanup.owner_death_observed
                    && cleanup.cgroup_empty_observed
                    && cleanup.cgroup_death_observed
                    && cleanup.predecessor_fence_state
                        == FenceState::Revoked => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "quiescence_observation_payload_mismatch",
                    reason: "cleanup observation does not bind owner death, empty cgroup, and revoked fence"
                        .to_owned(),
                })
            }
        }
        if fence.state != FenceState::Revoked
            || !mutation.owner_death_observed
            || !mutation.cgroup_empty_observed
            || !mutation.cgroup_death_observed
            || mutation.owner_process_id != fence.owner_process_id
            || mutation.owner_pid != fence.owner_pid
            || mutation.owner_start_time_ticks
                != fence.owner_start_time_ticks
            || mutation.owner_cgroup_id != fence.owner_cgroup_id
        {
            return Err(AuthorityError::Conflict {
                code: "quiescence_not_proven",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        let row = transaction.query_optional(
            statements::OBSERVE_FENCE_QUIESCENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                text(&mutation.owner_process_id),
                PgValue::U64(mutation.owner_pid as u64),
                PgValue::U64(mutation.owner_start_time_ticks),
                text(&mutation.owner_cgroup_id),
                text_digest(&evidence_digest),
            ],
        )?;
        if row.is_none() {
            return Err(AuthorityError::Conflict {
                code: "quiescence_cas_failed",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        Ok(AppliedMutation {
            revision: attempt.revision,
            state: attempt.state,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: vec![
                mutation.cleanup_observation.body.artifact_id.clone(),
            ],
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_evidence(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &AppendEvidenceMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        let artifact_operation = match &mutation.evidence.body.payload {
            NestedAuthorityPayload::TransparencyCheckpoint(_) => {
                OperationKind::TransparencyCheckpoint
            }
            _ => request.operation,
        };
        self.verify_nested(
            generation,
            &mutation.evidence,
            artifact_operation,
            request,
            trusted_epoch_millis,
        )?;
        if let Some(object) = &mutation.object {
            self.ensure_object(transaction, request, object)?;
        }
        let canonical = canonical_jcs_bytes(&mutation.evidence)?;
        let digest = sha256_digest(&canonical);
        transaction.execute(
            statements::INSERT_EVIDENCE_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.evidence_id),
                text(&request.attempt_id),
                text(&mutation.evidence_type),
                text(&mutation.evidence.body.producing_role_id),
                PgValue::Bytes(canonical),
                text_digest(&digest),
                mutation
                    .object
                    .as_ref()
                    .map(|object| text_digest(&object.content_sha256))
                    .unwrap_or(PgValue::Null),
            ],
        )?;
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation.evidence.body.artifact_id.clone(),
                mutation.evidence_id.clone(),
            ],
            ResultDisposition::Applied,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_enqueue(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &EnqueuePublicationMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.ensure_object(
            transaction,
            request,
            &mutation.payload_object,
        )?;
        self.verify_expected_role_artifact(
            generation,
            &mutation.publisher_authorization,
            ServiceRole::ReleaseAttestorPublisher,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.publisher_authorization.body.payload {
            NestedAuthorityPayload::Publication(publication)
                if publication.publication_id == mutation.publication_id
                    && publication.outbox_id == mutation.outbox_id
                    && publication.finalization_id
                        == mutation.finalization_id
                    && publication.payload_object_sha256
                        == mutation.payload_object.content_sha256
                    && publication.publication_state
                        == super::super::lifecycle::OutboxState::Pending
                    && publication.delivery_receipt_sha256.is_none() => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "outbox_enqueue_authorization_mismatch",
                    reason: "publisher authorization does not bind pending outbox entry"
                        .to_owned(),
                })
            }
        }
        self.require_finalization(
            transaction,
            request,
            &mutation.finalization_id,
        )?;
        transaction.execute(
            statements::INSERT_OUTBOX_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.outbox_id),
                text(&request.attempt_id),
                text(&mutation.publication_id),
                text(&mutation.finalization_id),
                text_digest(&mutation.payload_object.content_sha256),
            ],
        )?;
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation.publisher_authorization.body.artifact_id.clone(),
                mutation.outbox_id.clone(),
            ],
            ResultDisposition::Applied,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_acknowledge(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &AcknowledgePublicationMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        let receipt_digest = self.verify_expected_role_artifact(
            generation,
            &mutation.publisher_receipt,
            ServiceRole::ReleaseAttestorPublisher,
            request,
            trusted_epoch_millis,
        )?;
        match &mutation.publisher_receipt.body.payload {
            NestedAuthorityPayload::Publication(publication)
                if publication.publication_id == mutation.publication_id
                    && publication.outbox_id == mutation.outbox_id
                    && publication.finalization_id
                        == mutation.finalization_id
                    && publication.publication_state
                        == super::super::lifecycle::OutboxState::Delivered
                    && publication.delivery_receipt_sha256.as_ref()
                        == Some(&mutation.delivered_object_sha256) => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "outbox_delivery_receipt_mismatch",
                    reason: "publisher receipt does not bind delivered publication"
                        .to_owned(),
                })
            }
        }
        self.require_finalization(
            transaction,
            request,
            &mutation.finalization_id,
        )?;
        let outbox = transaction
            .query_optional(
                statements::LOCK_OUTBOX_SQL,
                &[
                    text(&request.generation_id),
                    text(&mutation.outbox_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "outbox_entry_missing",
                authoritative_state: None,
            })?;
        if outbox.require_text("publication_id")?
            != mutation.publication_id.0
            || outbox.require_text("finalization_id")?
                != mutation.finalization_id.0
        {
            return Err(AuthorityError::Conflict {
                code: "outbox_binding_mismatch",
                authoritative_state: Some(mutation.outbox_id.0.clone()),
            });
        }
        let updated = transaction.execute(
            statements::ACKNOWLEDGE_OUTBOX_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.outbox_id),
                text_digest(&receipt_digest),
            ],
        )?;
        if updated != 1 {
            return Err(AuthorityError::Conflict {
                code: "outbox_acknowledgement_conflict",
                authoritative_state: None,
            });
        }
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation.publisher_receipt.body.artifact_id.clone(),
                mutation.publication_id.clone(),
            ],
            ResultDisposition::Applied,
        )
    }

    fn apply_checkpoint(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &PublishCheckpointMutation,
    ) -> AuthorityResult<AppliedMutation> {
        let canonical = verify_signed_checkpoint(
            &mutation.checkpoint,
            generation,
        )?;
        let canonical_signed_checkpoint =
            canonical_jcs_bytes(&mutation.checkpoint)?;
        let checkpoint_sha256 =
            sha256_digest(&canonical_signed_checkpoint);
        let last_leaf = transaction.query_optional(
            statements::LOCK_LAST_TRANSPARENCY_LEAF_SQL,
            &[text(&request.generation_id)],
        )?;
        if mutation.checkpoint.tree_size
            != last_leaf
                .as_ref()
                .map(|row| row.require_u64("leaf_sequence"))
                .transpose()?
                .unwrap_or(0)
        {
            return Err(AuthorityError::Conflict {
                code: "checkpoint_tree_size_mismatch",
                authoritative_state: last_leaf
                    .as_ref()
                    .map(|row| row.require_u64("leaf_sequence"))
                    .transpose()?
                    .map(|value| value.to_string()),
            });
        }
        transaction.execute(
            statements::INSERT_TRANSPARENCY_CHECKPOINT_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.checkpoint.checkpoint_id),
                PgValue::U64(mutation.checkpoint.tree_size),
                text_digest(&mutation.checkpoint.root_sha256),
                mutation
                    .checkpoint
                    .predecessor_checkpoint_sha256
                    .as_ref()
                    .map(text_digest)
                    .unwrap_or(PgValue::Null),
                PgValue::Bytes(canonical_signed_checkpoint),
                text_digest(&checkpoint_sha256),
            ],
        )?;
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation.checkpoint.checkpoint_id.clone(),
                Identifier(sha256_digest(&canonical).0),
            ],
            ResultDisposition::Applied,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_trusted_time(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &AdvanceTrustedTimeMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.verify_expected_role_artifact(
            generation,
            &mutation.trusted_time_evidence,
            ServiceRole::StateAuthority,
            request,
            trusted_epoch_millis.or(Some(
                mutation
                    .trusted_time_evidence
                    .body
                    .issued_at_epoch_millis,
            )),
        )?;
        let previous = transaction.query_optional(
            statements::LOCK_TRUSTED_TIME_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.clock_id),
            ],
        )?;
        let predecessor_sequence = previous
            .as_ref()
            .map(|row| row.require_u64("sequence"))
            .transpose()?
            .unwrap_or(0);
        match &mutation.trusted_time_evidence.body.payload {
            NestedAuthorityPayload::TrustedTime(time)
                if time.clock_id == mutation.clock_id
                    && time.epoch_millis == mutation.epoch_millis
                    && time.sequence == mutation.sequence
                    && time.predecessor_sequence
                        == predecessor_sequence => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "trusted_time_evidence_mismatch",
                    reason: "trusted-time evidence does not bind clock, value, sequence, and predecessor"
                        .to_owned(),
                })
            }
        }
        if let Some(previous) = &previous {
            if mutation.sequence
                != previous.require_u64("sequence")? + 1
                || mutation.epoch_millis
                    < previous.require_u64("epoch_millis")?
            {
                return Err(AuthorityError::Conflict {
                    code: "trusted_time_highwater_regression",
                    authoritative_state: Some(format!(
                        "{}@{}",
                        previous.require_u64("epoch_millis")?,
                        previous.require_u64("sequence")?
                    )),
                });
            }
        } else if mutation.sequence != 1 {
            return Err(AuthorityError::Conflict {
                code: "trusted_time_genesis_sequence_invalid",
                authoritative_state: None,
            });
        }
        let evidence_sha256 = sha256_digest(&canonical_jcs_bytes(
            &mutation.trusted_time_evidence,
        )?);
        let updated = transaction.execute(
            statements::UPSERT_TRUSTED_TIME_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.clock_id),
                PgValue::U64(mutation.epoch_millis),
                PgValue::U64(mutation.sequence),
                text_digest(&evidence_sha256),
            ],
        )?;
        if updated != 1 {
            return Err(AuthorityError::Conflict {
                code: "trusted_time_cas_failed",
                authoritative_state: None,
            });
        }
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation
                    .trusted_time_evidence
                    .body
                    .artifact_id
                    .clone(),
            ],
            ResultDisposition::Applied,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_reconcile(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &ReconciliationMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        self.verify_expected_role_artifact(
            generation,
            &mutation.reconciliation_evidence,
            ServiceRole::CleanupWatchdog,
            request,
            trusted_epoch_millis.or(Some(
                mutation
                    .reconciliation_evidence
                    .body
                    .issued_at_epoch_millis,
            )),
        )?;
        let existing = transaction.query_optional(
            statements::LOCK_RECONCILIATION_JOB_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.reconciliation_job_id),
            ],
        )?;
        if let Some(existing) = &existing {
            let state = parse_reconciliation_state(
                &existing.require_text("state")?,
            )?;
            if state != mutation.expected_reconciliation_state {
                return Err(AuthorityError::Conflict {
                    code: "reconciliation_state_mismatch",
                    authoritative_state: Some(format!("{state:?}")),
                });
            }
        } else if mutation.expected_reconciliation_state
            != ReconciliationState::Pending
        {
            return Err(AuthorityError::Conflict {
                code: "reconciliation_job_missing",
                authoritative_state: None,
            });
        }
        let result_sha256 = sha256_digest(&canonical_jcs_bytes(&(
            mutation.reconciliation_job_id.clone(),
            mutation.domain.clone(),
            mutation.expected_reconciliation_state,
            mutation.successor_reconciliation_state,
            mutation.authoritative_cursor,
            mutation.blocker_code.clone(),
        ))?);
        match &mutation.reconciliation_evidence.body.payload {
            NestedAuthorityPayload::Reconciliation(reconciliation)
                if reconciliation.reconciliation_job_id
                    == mutation.reconciliation_job_id
                    && reconciliation.domain == mutation.domain
                    && reconciliation.predecessor_state
                        == mutation.expected_reconciliation_state
                    && reconciliation.successor_state
                        == mutation.successor_reconciliation_state
                    && reconciliation.authoritative_cursor
                        == mutation.authoritative_cursor
                    && reconciliation.result_sha256 == result_sha256 => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "reconciliation_evidence_mismatch",
                    reason: "reconciliation evidence does not bind the exact state transition and canonical outcome digest"
                        .to_owned(),
                })
            }
        }
        let applied = transaction.execute(
            statements::UPSERT_RECONCILIATION_JOB_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.reconciliation_job_id),
                text(&request.attempt_id),
                text(&mutation.domain),
                PgValue::Text(reconciliation_state_text(
                    mutation.successor_reconciliation_state,
                )),
                PgValue::U64(mutation.authoritative_cursor),
                mutation
                    .blocker_code
                    .as_ref()
                    .map(text)
                    .unwrap_or(PgValue::Null),
                text_digest(&result_sha256),
                PgValue::Text(reconciliation_state_text(
                    mutation.expected_reconciliation_state,
                )),
            ],
        )?;
        if applied != 1 {
            return Err(AuthorityError::Conflict {
                code: "reconciliation_cas_failed",
                authoritative_state: existing
                    .map(|row| row.require_text("state"))
                    .transpose()?,
            });
        }
        self.bump(
            transaction,
            request,
            attempt,
            fence,
            vec![
                mutation
                    .reconciliation_evidence
                    .body
                    .artifact_id
                    .clone(),
                mutation.reconciliation_job_id.clone(),
            ],
            ResultDisposition::Applied,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_terminalize_expired_attempt(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &TerminalizeExpiredAttemptMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<AppliedMutation> {
        mutation.cleanup_deadline.validate()?;
        mutation
            .terminal_detail_sha256
            .validate("terminalizeExpiredAttempt.terminalDetailSha256")?;
        if mutation.cleanup_deadline != request.deadline {
            return Err(AuthorityError::InvalidContract {
                field: "terminalizeExpiredAttempt.cleanupDeadline",
                reason: "cleanup deadline must be the authenticated RPC deadline"
                    .to_owned(),
            });
        }
        let cleanup_instant = self.boot_clock.current_boot_instant()?;
        mutation
            .cleanup_deadline
            .ensure_current(&cleanup_instant)?;
        if mutation.observed_boot_id != cleanup_instant.boot_id
            || mutation.observed_boot_millis
                > cleanup_instant.boot_millis
            || cleanup_instant
                .boot_millis
                .saturating_sub(mutation.observed_boot_millis)
                > self.configuration.cleanup_timeout_millis
        {
            return Err(AuthorityError::Conflict {
                code: "expired_attempt_observation_stale",
                authoritative_state: Some(format!(
                    "{}:{}",
                    cleanup_instant.boot_id,
                    cleanup_instant.boot_millis
                )),
            });
        }
        let observed = self.cgroup_observer.observe(
            &CgroupOwner {
                process_id: attempt.owner_process_id.clone(),
                pid: attempt.owner_pid,
                process_start_time_ticks:
                    attempt.owner_start_time_ticks,
                cgroup_id: attempt.owner_cgroup_id.clone(),
            },
            &mutation.cleanup_deadline,
        )?;
        if !observed.owner_death_observed
            || !observed.cgroup_empty_observed
            || !observed.cgroup_death_observed
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![format!(
                    "expired_attempt_cleanup_incomplete:{}",
                    attempt.stable_resume_id
                )],
            });
        }
        let expected_terminal_detail_sha256 =
            sha256_digest(&canonical_jcs_bytes(&(
                "DEADLINE_EXPIRED",
                &attempt.stable_resume_id,
                (
                    &attempt.deadline_boot_id,
                    attempt.deadline_boot_millis,
                ),
                (
                    &mutation.observed_boot_id,
                    mutation.observed_boot_millis,
                ),
                (
                    &mutation.cleanup_deadline.boot_id,
                    mutation.cleanup_deadline.deadline_boot_millis,
                ),
                (
                    &attempt.owner_process_id,
                    attempt.owner_pid,
                    attempt.owner_start_time_ticks,
                    &attempt.owner_cgroup_id,
                ),
                (
                    observed.owner_death_observed,
                    observed.cgroup_empty_observed,
                    observed.cgroup_death_observed,
                ),
                &fence.fence_token,
            ))?);
        if mutation.terminal_detail_sha256
            != expected_terminal_detail_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "terminalizeExpiredAttempt.terminalDetailSha256",
                reason: "terminal detail must bind resume ID, original and cleanup deadlines, live cgroup quiescence, and fence"
                    .to_owned(),
            });
        }
        self.verify_expected_role_artifact(
            generation,
            &mutation.recovery_evidence,
            ServiceRole::CleanupWatchdog,
            request,
            trusted_epoch_millis.or(Some(
                mutation
                    .recovery_evidence
                    .body
                    .issued_at_epoch_millis,
            )),
        )?;
        let deadline_expired =
            mutation.observed_boot_id != attempt.deadline_boot_id
                || mutation.observed_boot_millis
                    >= attempt.deadline_boot_millis;
        if mutation.stable_resume_id != attempt.stable_resume_id
            || !deadline_expired
            || fence.state != FenceState::Active
        {
            return Err(AuthorityError::Conflict {
                code: "attempt_deadline_not_expired",
                authoritative_state: Some(format!(
                    "{}:{}",
                    attempt.deadline_boot_id, attempt.deadline_boot_millis
                )),
            });
        }
        match &mutation.recovery_evidence.body.payload {
            NestedAuthorityPayload::Recovery(recovery)
                if recovery.recovery_action.0
                    == "TERMINALIZE_DEADLINE_EXPIRED"
                    && recovery.stable_resume_id
                        == attempt.stable_resume_id
                    && recovery.predecessor_state == attempt.state
                    && recovery.successor_state
                        == AttemptState::TerminalFailed
                    && recovery.deadline_boot_id
                        == attempt.deadline_boot_id
                    && recovery.deadline_boot_millis
                        == attempt.deadline_boot_millis
                    && recovery.observed_boot_id
                        == mutation.observed_boot_id
                    && recovery.observed_boot_millis
                        == mutation.observed_boot_millis
                    && recovery.cleanup_deadline_boot_id
                        == mutation.cleanup_deadline.boot_id
                    && recovery.cleanup_deadline_boot_millis
                        == mutation
                            .cleanup_deadline
                            .deadline_boot_millis
                    && recovery.owner_process_id
                        == attempt.owner_process_id
                    && recovery.owner_pid == attempt.owner_pid
                    && recovery.owner_start_time_ticks
                        == attempt.owner_start_time_ticks
                    && recovery.owner_cgroup_id
                        == attempt.owner_cgroup_id
                    && recovery.owner_death_observed
                        == observed.owner_death_observed
                    && recovery.cgroup_empty_observed
                        == observed.cgroup_empty_observed
                    && recovery.cgroup_death_observed
                        == observed.cgroup_death_observed
                    && recovery.fence_token == fence.fence_token
                    && recovery.predecessor_fence_state
                        == FenceState::Active
                    && recovery.successor_fence_state
                        == FenceState::Revoked => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "deadline_recovery_evidence_mismatch",
                    reason: "recovery evidence does not bind the deadline-expired attempt and active-to-revoked fence transition"
                        .to_owned(),
                })
            }
        }
        let row = transaction
            .query_optional(
                statements::TERMINALIZE_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                    PgValue::Text("DEADLINE_EXPIRED".to_owned()),
                    text_digest(&mutation.terminal_detail_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "expired_attempt_terminalize_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        let revision = row.require_u64("revision")?;
        let revoked = transaction.query_optional(
            statements::REVOKE_FENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                PgValue::U64(revision),
            ],
        )?;
        if revoked.is_none() {
            return Err(AuthorityError::Conflict {
                code: "expired_attempt_fence_revoke_cas_failed",
                authoritative_state: Some(format!("{:?}", fence.state)),
            });
        }
        Ok(AppliedMutation {
            revision,
            state: AttemptState::TerminalFailed,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids: vec![
                mutation.recovery_evidence.body.artifact_id.clone(),
            ],
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    fn commit_raw_object(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        mutation: &CommitRawObjectMutation,
    ) -> AuthorityResult<()> {
        if mutation.expected_content_length > MAX_RAW_OBJECT_BYTES as u64 {
            return Err(AuthorityError::InvalidContract {
                field: "commitRawObject.expectedContentLength",
                reason: "committed object exceeds the fixed raw-object limit"
                    .to_owned(),
            });
        }
        if mutation.storage_locator.is_empty()
            || mutation.storage_locator.len() > 1024
        {
            return Err(AuthorityError::InvalidContract {
                field: "commitRawObject.storageLocator",
                reason: "CAS locator must contain 1 to 1024 bytes".to_owned(),
            });
        }
        mutation.immutable_storage_receipt_sha256.validate(
            "commitRawObject.immutableStorageReceiptSha256",
        )?;
        let expected_object_id = Identifier(format!(
            "obj:{}",
            &mutation.expected_content_sha256.0["sha256:".len()..]
        ));
        if mutation.object_id != expected_object_id {
            return Err(AuthorityError::InvalidContract {
                field: "commitRawObject.objectId",
                reason: "object ID must be content-addressed from SHA-256"
                    .to_owned(),
            });
        }
        let inserted = transaction.query_optional(
            statements::INSERT_IMMUTABLE_OBJECT_SQL,
            &[
                text(&request.generation_id),
                text(&mutation.object_id),
                text(&request.attempt_id),
                text(&mutation.object_kind),
                text_digest(&mutation.expected_content_sha256),
                PgValue::U64(mutation.expected_content_length),
                PgValue::Text(mutation.media_type.clone()),
                PgValue::Text(mutation.storage_locator.clone()),
                text_digest(
                    &mutation.immutable_storage_receipt_sha256,
                ),
            ],
        )?;
        if inserted.is_none() {
            let existing = transaction
                .query_optional(
                    statements::LOCK_IMMUTABLE_OBJECT_BY_DIGEST_SQL,
                    &[
                        text(&request.generation_id),
                        text_digest(&mutation.expected_content_sha256),
                    ],
                )?
                .ok_or_else(|| AuthorityError::Backend {
                    code: "immutable_object_conflict_without_row",
                    reason: "object insert conflicted but no object exists"
                        .to_owned(),
                })?;
            if existing.require_text("object_id")?
                != mutation.object_id.0
                || existing.require_text("object_kind")? != mutation.object_kind.0
                || existing.require_text("media_type")? != mutation.media_type
                || existing.require_u64("content_length")?
                    != mutation.expected_content_length
                || existing.require_text("storage_locator")?
                    != mutation.storage_locator
                || existing.require_text(
                    "immutable_storage_receipt_sha256",
                )? != mutation.immutable_storage_receipt_sha256.0
            {
                return Err(AuthorityError::Conflict {
                    code: "immutable_object_identity_conflict",
                    authoritative_state: Some(
                        existing.require_text("object_id")?,
                    ),
                });
            }
        }
        Ok(())
    }

    fn ensure_object(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        object: &RawObjectReference,
    ) -> AuthorityResult<()> {
        if object.generation_id != request.generation_id {
            return Err(AuthorityError::InvalidContract {
                field: "rawObjectReference.generationId",
                reason: "object belongs to a different generation".to_owned(),
            });
        }
        let row = transaction
            .query_optional(
                statements::LOCK_IMMUTABLE_OBJECT_BY_DIGEST_SQL,
                &[
                    text(&request.generation_id),
                    text_digest(&object.content_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "immutable_object_missing",
                authoritative_state: Some(object.content_sha256.0.clone()),
            })?;
        if row.require_text("object_id")? != object.object_id.0
            || row.require_text("object_kind")? != object.object_kind.0
            || row.require_u64("content_length")? != object.content_length
            || row.require_text("media_type")? != object.media_type
        {
            return Err(AuthorityError::Conflict {
                code: "immutable_object_reference_mismatch",
                authoritative_state: Some(
                    row.require_text("object_id")?,
                ),
            });
        }
        Ok(())
    }

    fn persist_finalization_evidence_and_roots(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        raw_response_object: &RawObjectReference,
        artifacts: &[&SignedAuthorityArtifact],
    ) -> AuthorityResult<(Digest, Digest)> {
        for artifact in artifacts {
            let canonical = canonical_jcs_bytes(artifact)?;
            let canonical_sha256 = sha256_digest(&canonical);
            let inserted = transaction.execute(
                statements::INSERT_EVIDENCE_SQL,
                &[
                    text(&request.generation_id),
                    text(&artifact.body.artifact_id),
                    text(&request.attempt_id),
                    PgValue::Text(
                        artifact
                            .body
                            .payload
                            .artifact_type()
                            .as_str()
                            .to_owned(),
                    ),
                    text(&artifact.body.producing_role_id),
                    PgValue::Bytes(canonical.clone()),
                    text_digest(&canonical_sha256),
                    text_digest(&raw_response_object.content_sha256),
                ],
            )?;
            if inserted == 0 {
                let existing = transaction
                    .query_optional(
                        statements::LOCK_EVIDENCE_BY_ID_SQL,
                        &[
                            text(&request.generation_id),
                            text(&artifact.body.artifact_id),
                        ],
                    )?
                    .ok_or_else(|| AuthorityError::Backend {
                        code: "finalization_evidence_conflict_without_row",
                        reason: "evidence insert conflicted without a durable row"
                            .to_owned(),
                    })?;
                if existing.require_text("attempt_id")?
                        != request.attempt_id.0
                    || existing.require_text("evidence_type")?
                        != artifact.body.artifact_class.as_str()
                    || existing.require_text("producing_role_id")?
                        != artifact.body.producing_role_id.0
                    || existing.require_bytes("canonical_artifact")?
                        != canonical
                    || existing.require_text(
                        "canonical_artifact_sha256",
                    )? != canonical_sha256.0
                {
                    return Err(AuthorityError::Conflict {
                        code: "finalization_evidence_insert_conflict",
                        authoritative_state: Some(
                            artifact.body.artifact_id.0.clone(),
                        ),
                    });
                }
            } else if inserted != 1 {
                return Err(AuthorityError::Backend {
                    code: "finalization_evidence_insert_count_invalid",
                    reason: "evidence insert affected an invalid row count"
                        .to_owned(),
                });
            }
        }

        let transition_rows = transaction.query_many(
            statements::ATTEMPT_TRANSITION_ROWS_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
            ],
        )?;
        let mut transitions = Vec::with_capacity(transition_rows.len());
        for row in transition_rows {
            transitions.push(DurableTransitionRootEntry {
                operation_id: Identifier(
                    row.require_text("operation_id")?,
                ),
                operation: row.require_text("operation_name")?,
                exact_request_sha256: Digest(
                    row.require_text("exact_request_sha256")?,
                ),
                expected_revision: row.require_u64("expected_revision")?,
                expected_state: row.require_text("expected_state")?,
                fence_token: Identifier(
                    row.require_text("fence_token")?,
                ),
            });
        }
        if transitions.is_empty() {
            return Err(AuthorityError::Backend {
                code: "finalization_transition_chain_empty",
                reason: "attempt has no durable operations".to_owned(),
            });
        }
        let transition_chain_sha256 =
            sha256_digest(&canonical_jcs_bytes(&transitions)?);

        let evidence_rows = transaction.query_many(
            statements::ATTEMPT_EVIDENCE_ROWS_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
            ],
        )?;
        let mut evidence = Vec::with_capacity(evidence_rows.len());
        for row in evidence_rows {
            evidence.push(DurableEvidenceRootEntry {
                evidence_id: Identifier(
                    row.require_text("evidence_id")?,
                ),
                evidence_type: Identifier(
                    row.require_text("evidence_type")?,
                ),
                producing_role_id: Identifier(
                    row.require_text("producing_role_id")?,
                ),
                canonical_artifact_sha256: Digest(
                    row.require_text("canonical_artifact_sha256")?,
                ),
                object_sha256: row
                    .optional_text("object_sha256")?
                    .map(Digest),
            });
        }
        if evidence.len() < artifacts.len() {
            return Err(AuthorityError::Backend {
                code: "finalization_evidence_root_incomplete",
                reason: "durable evidence rows omit final proof artifacts"
                    .to_owned(),
            });
        }
        let evidence_root_sha256 =
            sha256_digest(&canonical_jcs_bytes(&evidence)?);
        Ok((transition_chain_sha256, evidence_root_sha256))
    }

    fn require_finalization(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        finalization_id: &Identifier,
    ) -> AuthorityResult<()> {
        let row = transaction
            .query_optional(
                statements::LOCK_FINALIZATION_BY_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "finalization_missing",
                authoritative_state: None,
            })?;
        if row.require_text("finalization_id")? != finalization_id.0 {
            return Err(AuthorityError::Conflict {
                code: "finalization_id_mismatch",
                authoritative_state: Some(
                    row.require_text("finalization_id")?,
                ),
            });
        }
        Ok(())
    }

    fn load_immutable_raw(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        object: &RawObjectReference,
    ) -> AuthorityResult<(ImmutableRawObject, Digest)> {
        if object.generation_id != request.generation_id {
            return Err(AuthorityError::InvalidContract {
                field: "rawObjectReference.generationId",
                reason: "object belongs to a different generation".to_owned(),
            });
        }
        let row = transaction
            .query_optional(
                statements::LOCK_IMMUTABLE_OBJECT_WITH_CONTENT_SQL,
                &[
                    text(&request.generation_id),
                    text_digest(&object.content_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "immutable_object_missing",
                authoritative_state: Some(object.content_sha256.0.clone()),
            })?;
        if row.require_text("object_id")? != object.object_id.0
            || row.require_text("object_kind")? != object.object_kind.0
            || row.require_u64("content_length")? != object.content_length
            || row.require_text("media_type")? != object.media_type
        {
            return Err(AuthorityError::Conflict {
                code: "immutable_object_reference_mismatch",
                authoritative_state: Some(row.require_text("object_id")?),
            });
        }
        let storage_locator = row.require_text("storage_locator")?;
        let receipt_sha256 = Digest(
            row.require_text("immutable_storage_receipt_sha256")?,
        );
        let raw = self.immutable_object_store.retrieve_exact(
            &request.generation_id,
            &object.object_id,
            &storage_locator,
            &receipt_sha256,
            &object.content_sha256,
            object.content_length,
            &request.deadline,
        )?;
        Ok((
            ImmutableRawObject::from_committed(object.clone(), &raw)?,
            receipt_sha256,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_inspection_seed(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        mutation: &PrepareReleaseConsumptionMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<()> {
        let seed = &mutation.inspection_seed;
        seed.validate()?;
        let body = &seed.body;
        let binding = &mutation.binding;
        if body.generation_id != request.generation_id
            || body.attempt_id != request.attempt_id
            || body.attempt_revision != attempt.revision
            || body.fence_token != fence.fence_token
            || body.stable_resume_id != attempt.stable_resume_id
            || body.raw_response_object != binding.release_object
            || body.inspection_result_sha256
                != binding.inspection_result_sha256
        {
            return Err(AuthorityError::Authentication {
                code: "release_inspection_seed_scope_mismatch",
                reason: "inspection seed does not bind the installed generation, persisted attempt, exact fence, immutable response, and inspection"
                    .to_owned(),
            });
        }
        let expected_roles = [
            ServiceRole::CredentialTransport,
            ServiceRole::CredentialTransport,
            ServiceRole::PolicyProofVerifier,
            ServiceRole::PolicyProofVerifier,
            ServiceRole::StateAuthority,
            ServiceRole::ReleaseAttestorPublisher,
            ServiceRole::ImmutableArtifactLedger,
            ServiceRole::StateAuthority,
            ServiceRole::ReleaseAttestorPublisher,
        ];
        for (artifact, expected_role) in
            seed.authority_artifacts.iter().zip(expected_roles)
        {
            self.verify_self_bound_nested(
                generation,
                artifact,
                expected_role,
                trusted_epoch_millis,
            )?;
        }
        let inspection_artifact = &seed.authority_artifacts[4];
        let inspection_artifact_sha256 =
            sha256_digest(&canonical_jcs_bytes(inspection_artifact)?);
        let inspection = self.lock_inspection_artifact(
            transaction,
            &request.generation_id,
            &inspection_artifact_sha256,
        )?;
        if inspection.attempt_id != request.attempt_id
            || inspection.canonical_signed_result_sha256
                != binding.inspection_result_sha256
            || inspection.object_id != binding.release_object.object_id
            || inspection.object_sha256
                != binding.release_object.content_sha256
            || inspection.object_length
                != binding.release_object.content_length
        {
            return Err(AuthorityError::Authentication {
                code: "release_inspection_seed_artifact_mismatch",
                reason: "inspection seed does not contain the exact durable immutable inspection result"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn lock_release_preparation(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        release_authorization_id: &Identifier,
    ) -> AuthorityResult<LockedReleasePreparation> {
        let row = transaction
            .query_optional(
                statements::LOCK_RELEASE_LEDGER_SQL,
                &[
                    text(&request.generation_id),
                    text(release_authorization_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "release_preparation_missing",
                authoritative_state: Some(
                    release_authorization_id.0.clone(),
                ),
            })?;
        if row.require_text("attempt_id")? != request.attempt_id.0 {
            return Err(AuthorityError::Authentication {
                code: "release_preparation_attempt_mismatch",
                reason: "release preparation belongs to a different attempt"
                    .to_owned(),
            });
        }
        let canonical_result =
            row.require_bytes("canonical_signed_result")?;
        let canonical_signed_result_sha256 = Digest(
            row.require_text("canonical_signed_result_sha256")?,
        );
        if sha256_digest(&canonical_result)
            != canonical_signed_result_sha256
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_result_digest_mismatch",
                reason: "durable PREPARE result failed its exact digest"
                    .to_owned(),
            });
        }
        let signed_result: SignedOperationResult =
            serde_json::from_slice(&canonical_result).map_err(|error| {
                AuthorityError::Serialization {
                    reason: format!(
                        "durable PREPARE result could not be decoded: {error}"
                    ),
                }
            })?;
        verify_signed_operation_result(&signed_result, generation)?;
        if signed_result.body.generation_id != request.generation_id
            || signed_result.body.attempt_id != request.attempt_id
            || signed_result.body.operation
                != OperationKind::ReleaseConsumeAndRetrieveExact
            || signed_result.body.authoritative_state
                != AttemptState::ReleasePrepared
            || signed_result.body.retrieved_immutable_raw.is_some()
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_result_scope_mismatch",
                reason: "durable PREPARE result has wrong authority scope, state, operation, or contains bytes"
                    .to_owned(),
            });
        }
        let preparation = match signed_result.body.response_data_result {
            Some(ResponseDataStateResult::ReleasePreparation(
                preparation,
            )) => preparation,
            _ => {
                return Err(AuthorityError::Backend {
                    code: "release_preparation_result_missing",
                    reason: "durable PREPARE result lacks its preparation receipt"
                        .to_owned(),
                })
            }
        };
        verify_release_preparation_mutation_receipt(
            &preparation
                .durable_result
                .signed_state_mutation_receipt,
            generation,
        )?;
        let signed_receipt_sha256 = sha256_digest(
            &canonical_jcs_bytes(
                &preparation
                    .durable_result
                    .signed_state_mutation_receipt,
            )?,
        );
        if signed_receipt_sha256
            != preparation
                .durable_result
                .signed_state_mutation_receipt_sha256
            || sha256_digest(&canonical_jcs_bytes(
                &preparation.durable_result,
            )?) != preparation.durable_canonical_result_sha256
            || sha256_digest(&canonical_jcs_bytes(
                &preparation.release_preparation_receipt,
            )?) != preparation.release_preparation_receipt_sha256
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_internal_digest_mismatch",
                reason: "durable PREPARE receipt subrecords failed their canonical digests"
                    .to_owned(),
            });
        }
        self.verify_self_bound_nested(
            generation,
            &preparation.release_preparation_receipt,
            ServiceRole::StateAuthority,
            None,
        )?;
        let nested =
            match &preparation.release_preparation_receipt.body.payload {
                NestedAuthorityPayload::ReleasePreparationReceipt(
                    nested,
                ) => nested,
                _ => {
                    return Err(AuthorityError::Backend {
                        code: "release_preparation_artifact_type_mismatch",
                        reason: "durable PREPARE result has the wrong nested artifact type"
                            .to_owned(),
                    })
                }
            };
        let durable = &preparation.durable_result;
        let receipt = &durable.signed_state_mutation_receipt.body;
        if nested.release_authorization_id
            != durable.release_authorization_id
            || nested.release_request_sha256
                != durable.release_request_sha256
            || nested.inspection_result_sha256
                != durable.inspection_result_sha256
            || nested.release_object_sha256
                != durable.release_object_sha256
            || nested.client_binding_sha256
                != durable.client_binding_sha256
            || nested.exact_replay_key_sha256
                != durable.exact_replay_key_sha256
            || nested.preauthorization_artifact_sha256
                != durable.preauthorization_artifact_sha256
            || nested.signed_state_mutation_receipt_sha256
                != durable.signed_state_mutation_receipt_sha256
            || nested.durable_canonical_result_sha256
                != preparation.durable_canonical_result_sha256
            || nested.one_use_nonce_sha256
                != durable.one_use_nonce_sha256
            || nested.predecessor_revision != receipt.predecessor_revision
            || nested.predecessor_state != receipt.predecessor_state
            || nested.successor_revision != receipt.successor_revision
            || nested.successor_state != receipt.successor_state
            || nested.fence_token != receipt.fence_token
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_receipt_binding_mismatch",
                reason: "release-preparation artifact does not bind its exact signed post-CAS receipt and durable result"
                    .to_owned(),
            });
        }
        if durable.release_authorization_id != *release_authorization_id
            || row.require_text("finalization_id")?
                != durable.finalization_id.0
            || row.require_text("exact_release_request_sha256")?
                != durable.release_request_sha256.0
            || row.require_text("inspection_result_sha256")?
                != durable.inspection_result_sha256.0
            || row.require_text("release_object_sha256")?
                != durable.release_object_sha256.0
            || row.require_text("client_binding_sha256")?
                != durable.client_binding_sha256.0
            || row.require_text("one_use_nonce_sha256")?
                != durable.one_use_nonce_sha256.0
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_ledger_binding_mismatch",
                reason: "release ledger columns differ from the exact signed PREPARE result"
                    .to_owned(),
            });
        }
        Ok(LockedReleasePreparation {
            authorization_id: durable.release_authorization_id.clone(),
            finalization_id: durable.finalization_id.clone(),
            exact_release_request_sha256: durable
                .release_request_sha256
                .clone(),
            inspection_result_sha256: durable
                .inspection_result_sha256
                .clone(),
            release_object_sha256: durable.release_object_sha256.clone(),
            client_binding_sha256: durable.client_binding_sha256.clone(),
            one_use_nonce_sha256: durable.one_use_nonce_sha256.clone(),
            canonical_signed_result_sha256,
            preparation,
        })
    }

    fn verify_retrieval_binding(
        &self,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        binding: &super::super::rpc::ReleasePreparationMutationBinding,
        supplied_receipt:
            &super::super::rpc::SignedReleasePreparationMutationReceipt,
        prepared: &LockedReleasePreparation,
    ) -> AuthorityResult<()> {
        binding
            .exact_replay_key_sha256
            .validate("releaseRetrieval.binding.exactReplayKeySha256")?;
        verify_release_preparation_mutation_receipt(
            supplied_receipt,
            generation,
        )?;
        let durable = &prepared.preparation.durable_result;
        let receipt = &supplied_receipt.body;
        if supplied_receipt != &durable.signed_state_mutation_receipt
            || binding.release_authorization_id
                != prepared.authorization_id
            || binding.release_request_sha256
                != prepared.exact_release_request_sha256
            || binding.inspection_result_sha256
                != prepared.inspection_result_sha256
            || binding.release_object.content_sha256
                != prepared.release_object_sha256
            || binding.client_binding_sha256
                != prepared.client_binding_sha256
            || binding.exact_replay_key_sha256
                != durable.exact_replay_key_sha256
            || receipt.generation_id != request.generation_id
            || receipt.attempt_id != request.attempt_id
            || receipt.fence_token
                != request
                    .fence
                    .fence_token
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| AuthorityError::InvalidContract {
                        field: "request.fence.fenceToken",
                        reason: "retrieval requires the exact persisted fence"
                            .to_owned(),
                    })?
            || receipt.successor_state
                != AttemptState::ReleasePrepared
            || receipt.one_use_nonce_sha256
                != prepared.one_use_nonce_sha256
        {
            return Err(AuthorityError::Authentication {
                code: "release_retrieval_preparation_binding_mismatch",
                reason: "retrieval does not bind the exact durable signed PREPARE receipt, client, replay key, object, and fence"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn require_persisted_evidence(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        artifact: &SignedAuthorityArtifact,
        artifact_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let row = transaction
            .query_optional(
                statements::LOCK_EVIDENCE_BY_ID_SQL,
                &[
                    text(&request.generation_id),
                    text(&artifact.body.artifact_id),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "final_verification_evidence_missing",
                authoritative_state: Some(
                    artifact.body.artifact_id.0.clone(),
                ),
            })?;
        let canonical_artifact = row.require_bytes("canonical_artifact")?;
        if row.require_text("attempt_id")? != request.attempt_id.0
            || row.require_text("evidence_type")?
                != "FINAL_ENVELOPE_VERIFICATION"
            || row.require_text("producing_role_id")?
                != artifact.body.producing_role_id.0
            || Digest(row.require_text("canonical_artifact_sha256")?)
                != *artifact_sha256
            || sha256_digest(&canonical_artifact) != *artifact_sha256
            || canonical_artifact != canonical_jcs_bytes(artifact)?
        {
            return Err(AuthorityError::Authentication {
                code: "final_verification_evidence_mismatch",
                reason: "supplied final verification is not the exact durable finalization evidence"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn persist_authority_evidence(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        evidence_type: &str,
        artifact: &SignedAuthorityArtifact,
    ) -> AuthorityResult<Digest> {
        let canonical_artifact = canonical_jcs_bytes(artifact)?;
        let canonical_artifact_sha256 =
            sha256_digest(&canonical_artifact);
        let inserted = transaction.execute(
            statements::INSERT_EVIDENCE_SQL,
            &[
                text(&request.generation_id),
                text(&artifact.body.artifact_id),
                text(&request.attempt_id),
                PgValue::Text(evidence_type.to_owned()),
                text(&artifact.body.producing_role_id),
                PgValue::Bytes(canonical_artifact),
                text_digest(&canonical_artifact_sha256),
                PgValue::Null,
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Conflict {
                code: "settlement_evidence_insert_conflict",
                authoritative_state: Some(
                    artifact.body.artifact_id.0.clone(),
                ),
            });
        }
        Ok(canonical_artifact_sha256)
    }

    fn verify_release_preparation_artifacts(
        &self,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        mutation: &PrepareReleaseConsumptionMutation,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<(Identifier, Digest)> {
        let binding = &mutation.binding;
        binding
            .exact_replay_key_sha256
            .validate("releasePreparation.binding.exactReplayKeySha256")?;
        mutation.inspection_seed.validate()?;
        let mutation_binding_sha256 =
            sha256_digest(&canonical_jcs_bytes(binding)?);
        let successor_revision =
            request.expected_revision.checked_add(1).ok_or_else(|| {
                AuthorityError::InvalidContract {
                    field: "request.expectedRevision",
                    reason: "release preparation revision overflow".to_owned(),
                }
            })?;
        let inspection_artifact_sha256 = sha256_digest(
            &canonical_jcs_bytes(
                &mutation.inspection_seed.authority_artifacts[4],
            )?,
        );
        self.verify_expected_role_artifact(
            generation,
            &mutation.release_authorization,
            ServiceRole::ReleaseAttestorPublisher,
            request,
            trusted_epoch_millis,
        )?;
        self.verify_expected_role_artifact(
            generation,
            &mutation.release_consumption_preauthorization,
            ServiceRole::ReleaseAttestorPublisher,
            request,
            trusted_epoch_millis,
        )?;
        let release = match &mutation.release_authorization.body.payload {
            NestedAuthorityPayload::ReleaseAuthorization(release)
                if release.release_authorization_id
                    == binding.release_authorization_id
                    && release.release_request_sha256
                        == binding.release_request_sha256
                    && release.inspection_result_sha256
                        == binding.inspection_result_sha256
                    && release.inspection_artifact_sha256
                        == inspection_artifact_sha256
                    && release.inspection_seed_body_sha256
                        == mutation.inspection_seed.body_sha256
                    && release.inspection_seed_root_sha256
                        == mutation
                            .inspection_seed
                            .body
                            .authority_artifacts_root_sha256
                    && release.release_object_sha256
                        == binding.release_object.content_sha256 =>
            {
                release
            }
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "release_authorization_payload_mismatch",
                    reason: "release artifact does not bind authorization, request, and exact object"
                        .to_owned(),
                })
            }
        };
        match &mutation
            .release_consumption_preauthorization
            .body
            .payload
        {
            NestedAuthorityPayload::ReleaseConsumptionPreauthorization(
                consumption,
            )
                if consumption.release_authorization_id
                    == binding.release_authorization_id
                    && consumption.finalization_id
                        == release.finalization_id
                    && consumption.mutation_binding_sha256
                        == mutation_binding_sha256
                    && consumption.release_request_sha256
                        == binding.release_request_sha256
                    && consumption.inspection_result_sha256
                        == binding.inspection_result_sha256
                    && consumption.release_object_sha256
                        == binding.release_object.content_sha256
                    && consumption.client_binding_sha256
                        == binding.client_binding_sha256
                    && consumption.exact_replay_key_sha256
                        == binding.exact_replay_key_sha256
                    && consumption.one_use_nonce_sha256
                        == release.one_use_nonce_sha256
                    && consumption.expected_revision
                        == request.expected_revision
                    && consumption.expected_state
                        == request.expected_state
                    && consumption.successor_revision
                        == successor_revision
                    && consumption.successor_state
                        == AttemptState::ReleasePrepared => {}
            _ => {
                return Err(AuthorityError::Authentication {
                    code: "release_consumption_preauthorization_mismatch",
                    reason: "consumption preauthorization does not bind the inspection seed, mutation binding, authorization, exact request, object, client, replay key, one-use nonce, and exact RELEASE_PREPARED CAS"
                        .to_owned(),
                })
            }
        }
        Ok((
            release.finalization_id.clone(),
            release.one_use_nonce_sha256.clone(),
        ))
    }

    fn verify_nested(
        &self,
        generation: &ProviderGeneration,
        artifact: &SignedAuthorityArtifact,
        operation: OperationKind,
        request: &RpcRequest,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<ServiceRole> {
        let identity = generation
            .topology
            .roles
            .iter()
            .find(|identity| {
                identity.role_id == artifact.body.producing_role_id
            })
            .ok_or_else(|| AuthorityError::Authentication {
                code: "nested_artifact_role_unassigned",
                reason: "artifact role is absent from the generation"
                    .to_owned(),
            })?;
        if !identity.authority_artifact_signing
            || !service_contract(identity.role).can_sign_authority_artifacts
        {
            return Err(AuthorityError::Authentication {
                code: "role_cannot_sign_authority_artifacts",
                reason: format!(
                    "{} has no authority key in this topology",
                    identity.role.as_str()
                ),
            });
        }
        if !artifact_contract_allows(
            identity.role,
            operation,
            artifact.body.payload.artifact_type(),
        ) {
            return Err(AuthorityError::Authentication {
                code: "artifact_role_operation_matrix_denied",
                reason: format!(
                    "{} cannot produce this artifact type for {}",
                    identity.role.as_str(),
                    operation.as_str()
                ),
            });
        }
        if !identity.enabled_operations.contains(&Identifier(
            operation.as_str().to_owned(),
        )) {
            return Err(AuthorityError::Authentication {
                code: "nested_artifact_operation_not_assigned",
                reason: format!(
                    "{} is not assigned {}",
                    identity.role.as_str(),
                    operation.as_str()
                ),
            });
        }
        verify_authority_artifact(
            artifact,
            generation,
            identity.role,
            operation,
            &request.operation_id,
            &request.attempt_id,
            request.expected_revision,
            request
                .fence
                .fence_token
                .as_ref()
                .unwrap_or(&artifact.body.fence_token),
        )?;
        if let Some(now) = trusted_epoch_millis {
            if now < artifact.body.issued_at_epoch_millis
                || now >= artifact.body.expires_at_epoch_millis
            {
                return Err(AuthorityError::Authentication {
                    code: "nested_artifact_not_current",
                    reason: "artifact is not current at trusted time"
                        .to_owned(),
                });
            }
        }
        Ok(identity.role)
    }

    fn verify_self_bound_nested(
        &self,
        generation: &ProviderGeneration,
        artifact: &SignedAuthorityArtifact,
        expected_role: ServiceRole,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<()> {
        verify_authority_artifact(
            artifact,
            generation,
            expected_role,
            artifact.body.operation,
            &artifact.body.operation_id,
            &artifact.body.attempt_id,
            artifact.body.attempt_revision,
            &artifact.body.fence_token,
        )?;
        if let Some(now) = trusted_epoch_millis {
            if now < artifact.body.issued_at_epoch_millis
                || now >= artifact.body.expires_at_epoch_millis
            {
                return Err(AuthorityError::Authentication {
                    code: "nested_artifact_not_current",
                    reason: "artifact is not current at trusted time"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn verify_expected_role_artifact(
        &self,
        generation: &ProviderGeneration,
        artifact: &SignedAuthorityArtifact,
        expected_role: ServiceRole,
        request: &RpcRequest,
        trusted_epoch_millis: Option<u64>,
    ) -> AuthorityResult<Digest> {
        let role = self.verify_nested(
            generation,
            artifact,
            request.operation,
            request,
            trusted_epoch_millis,
        )?;
        if role != expected_role {
            return Err(AuthorityError::Authentication {
                code: "nested_artifact_wrong_role",
                reason: format!(
                    "expected {}, received {}",
                    expected_role.as_str(),
                    role.as_str()
                ),
            });
        }
        Ok(sha256_digest(&canonical_jcs_bytes(artifact)?))
    }

    fn recover_post_reservation_error(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        error: AuthorityError,
    ) -> AuthorityResult<AppliedMutation> {
        if let AuthorityError::Conflict { code, .. } = &error {
            return Ok(AppliedMutation {
                revision: attempt.revision,
                state: attempt.state,
                fence_token: fence.fence_token.clone(),
                stable_resume_id: attempt.stable_resume_id.clone(),
                disposition: ResultDisposition::Conflict,
                conflict_code: Some(Identifier((*code).to_owned())),
                artifact_ids: Vec::new(),
                deferred_inspection: None,
                deferred_release: None,
                retrieved_immutable_raw: None,
                response_data_result: None,
            });
        }
        if attempt.state.is_terminal() {
            return Ok(AppliedMutation {
                revision: attempt.revision,
                state: attempt.state,
                fence_token: fence.fence_token.clone(),
                stable_resume_id: attempt.stable_resume_id.clone(),
                disposition: ResultDisposition::Rejected,
                conflict_code: Some(Identifier(
                    authority_error_code(&error).to_owned(),
                )),
                artifact_ids: Vec::new(),
                deferred_inspection: None,
                deferred_release: None,
                retrieved_immutable_raw: None,
                response_data_result: None,
            });
        }
        let detail_sha256 = sha256_digest(error.to_string().as_bytes());
        let row = transaction
            .query_optional(
                statements::TERMINALIZE_ATTEMPT_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                    PgValue::Text(
                        "POST_RESERVATION_OPERATION_REJECTED".to_owned(),
                    ),
                    text_digest(&detail_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "post_reservation_terminalize_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        let revision = row.require_u64("revision")?;
        let revoked = transaction.query_optional(
            statements::REVOKE_FENCE_SQL,
            &[
                text(&request.generation_id),
                text(&request.attempt_id),
                PgValue::U64(revision),
            ],
        )?;
        if revoked.is_none() {
            return Err(AuthorityError::Conflict {
                code: "post_reservation_fence_revoke_failed",
                authoritative_state: Some(fence.fence_token.0.clone()),
            });
        }
        Ok(AppliedMutation {
            revision,
            state: AttemptState::TerminalFailed,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: attempt.stable_resume_id.clone(),
            disposition: ResultDisposition::Rejected,
            conflict_code: Some(Identifier(
                authority_error_code(&error).to_owned(),
            )),
            artifact_ids: Vec::new(),
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    fn transition(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        successor: AttemptState,
        artifact_ids: Vec<Identifier>,
    ) -> AuthorityResult<AppliedMutation> {
        if !attempt.state.allows_transition(successor) {
            return Err(AuthorityError::Conflict {
                code: "invalid_attempt_transition",
                authoritative_state: Some(format!(
                    "{}->{}",
                    attempt.state.as_str(),
                    successor.as_str()
                )),
            });
        }
        let row = transaction
            .query_optional(
                statements::CAS_ATTEMPT_STATE_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                    PgValue::Text(successor.as_str().to_owned()),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "attempt_transition_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        Ok(AppliedMutation {
            revision: row.require_u64("revision")?,
            state: successor,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: Identifier(
                row.require_text("stable_resume_id")?,
            ),
            disposition: ResultDisposition::Applied,
            conflict_code: None,
            artifact_ids,
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    fn bump(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        attempt: &LockedAttempt,
        fence: &LockedFence,
        artifact_ids: Vec<Identifier>,
        disposition: ResultDisposition,
    ) -> AuthorityResult<AppliedMutation> {
        let row = transaction
            .query_optional(
                statements::CAS_ATTEMPT_BUMP_SQL,
                &[
                    text(&request.generation_id),
                    text(&request.attempt_id),
                    PgValue::U64(request.expected_revision),
                    PgValue::Text(request.expected_state.as_str().to_owned()),
                    text(&fence.fence_token),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "attempt_revision_cas_failed",
                authoritative_state: Some(attempt.state.as_str().to_owned()),
            })?;
        Ok(AppliedMutation {
            revision: row.require_u64("revision")?,
            state: attempt.state,
            fence_token: fence.fence_token.clone(),
            stable_resume_id: Identifier(
                row.require_text("stable_resume_id")?,
            ),
            disposition,
            conflict_code: None,
            artifact_ids,
            deferred_inspection: None,
            deferred_release: None,
            retrieved_immutable_raw: None,
            response_data_result: None,
        })
    }

    fn lock_release_replay(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation: &ProviderGeneration,
        request: &RpcRequest,
        mutation: &PrepareReleaseConsumptionMutation,
        finalization_id: &Identifier,
        one_use_nonce_sha256: &Digest,
    ) -> AuthorityResult<Option<ExactSignedResultBytes>> {
        let binding = &mutation.binding;
        let existing = transaction.query_optional(
            statements::LOCK_RELEASE_LEDGER_SQL,
            &[
                text(&request.generation_id),
                text(&binding.release_authorization_id),
            ],
        )?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.require_text("exact_release_request_sha256")?
            != binding.release_request_sha256.0
            || existing.require_text("finalization_id")?
                != finalization_id.0
            || existing.require_text("inspection_result_sha256")?
                != binding.inspection_result_sha256.0
            || existing.require_text("release_object_sha256")?
                != binding.release_object.content_sha256.0
            || existing.require_text("client_binding_sha256")?
                != binding.client_binding_sha256.0
            || existing.require_text("one_use_nonce_sha256")?
                != one_use_nonce_sha256.0
        {
            return Err(AuthorityError::Conflict {
                code: "release_authorization_reused_with_different_binding",
                authoritative_state: Some(
                    binding.release_authorization_id.0.clone(),
                ),
            });
        }
        let canonical_bytes =
            existing.require_bytes("canonical_signed_result")?;
        let canonical_sha256 = Digest(
            existing.require_text("canonical_signed_result_sha256")?,
        );
        if sha256_digest(&canonical_bytes) != canonical_sha256 {
            return Err(AuthorityError::Backend {
                code: "release_replay_result_digest_mismatch",
                reason: "release replay bytes failed their stored digest"
                    .to_owned(),
            });
        }
        let signed_result: SignedOperationResult =
            serde_json::from_slice(&canonical_bytes).map_err(|error| {
                AuthorityError::Serialization {
                    reason: format!(
                        "release PREPARE replay result could not be decoded: {error}"
                    ),
                }
            })?;
        verify_signed_operation_result(&signed_result, generation)?;
        match signed_result.body.response_data_result {
            Some(ResponseDataStateResult::ReleasePreparation(
                preparation,
            )) if preparation
                .durable_result
                .exact_replay_key_sha256
                == binding.exact_replay_key_sha256 => {}
            _ => {
                return Err(AuthorityError::Conflict {
                    code: "release_replay_key_mismatch",
                    authoritative_state: Some(
                        binding.release_authorization_id.0.clone(),
                    ),
                })
            }
        }
        Ok(Some(ExactSignedResultBytes {
            canonical_bytes,
            canonical_sha256,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_release_preparation_result(
        &self,
        request: &RpcRequest,
        exact_request_sha256: &Digest,
        successor_revision: u64,
        successor_state: AttemptState,
        fence_token: &Identifier,
        stable_resume_id: &Identifier,
        release: &DeferredRelease,
        deadline: &BootDeadline,
    ) -> AuthorityResult<ReleasePreparationResult> {
        if successor_state != AttemptState::ReleasePrepared
            || successor_revision
                != request.expected_revision.checked_add(1).ok_or_else(|| {
                    AuthorityError::InvalidContract {
                        field: "request.expectedRevision",
                        reason: "release preparation revision overflow"
                            .to_owned(),
                    }
                })?
        {
            return Err(AuthorityError::Backend {
                code: "release_preparation_post_cas_state_mismatch",
                reason: "release-preparation receipt can only be signed after the exact RELEASE_PREPARED CAS"
                    .to_owned(),
            });
        }
        let signed_state_mutation_receipt =
            sign_release_preparation_mutation_receipt(
                &self.signer,
                ReleasePreparationMutationReceiptBody {
                    api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
                    kind: "ResponseV2ReleasePreparationMutationReceipt"
                        .to_owned(),
                    schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
                    generation_id: request.generation_id.clone(),
                    request_id: request.request_id.clone(),
                    operation_id: request.operation_id.clone(),
                    exact_request_sha256: exact_request_sha256.clone(),
                    attempt_id: request.attempt_id.clone(),
                    stable_resume_id: stable_resume_id.clone(),
                    release_authorization_id: release
                        .authorization_id
                        .clone(),
                    release_request_sha256: release
                        .exact_release_request_sha256
                        .clone(),
                    inspection_result_sha256: release
                        .inspection_result_sha256
                        .clone(),
                    release_object_sha256: release
                        .release_object_sha256
                        .clone(),
                    client_binding_sha256: release
                        .client_binding_sha256
                        .clone(),
                    exact_replay_key_sha256: release
                        .exact_replay_key_sha256
                        .clone(),
                    preauthorization_artifact_sha256: release
                        .preauthorization_artifact_sha256
                        .clone(),
                    one_use_nonce_sha256: release
                        .one_use_nonce_sha256
                        .clone(),
                    predecessor_revision: request.expected_revision,
                    predecessor_state: request.expected_state,
                    successor_revision,
                    successor_state,
                    fence_token: fence_token.clone(),
                },
                deadline,
            )?;
        let signed_state_mutation_receipt_sha256 = sha256_digest(
            &canonical_jcs_bytes(&signed_state_mutation_receipt)?,
        );
        let durable_result = ReleasePreparationDurableResult {
            release_authorization_id: release.authorization_id.clone(),
            finalization_id: release.finalization_id.clone(),
            release_request_sha256: release
                .exact_release_request_sha256
                .clone(),
            inspection_result_sha256: release
                .inspection_result_sha256
                .clone(),
            release_object_sha256: release.release_object_sha256.clone(),
            client_binding_sha256: release.client_binding_sha256.clone(),
            exact_replay_key_sha256: release
                .exact_replay_key_sha256
                .clone(),
            one_use_nonce_sha256: release.one_use_nonce_sha256.clone(),
            preauthorization_artifact_id: release
                .preauthorization_artifact_id
                .clone(),
            preauthorization_artifact_sha256: release
                .preauthorization_artifact_sha256
                .clone(),
            signed_state_mutation_receipt,
            signed_state_mutation_receipt_sha256:
                signed_state_mutation_receipt_sha256.clone(),
        };
        let durable_canonical_result_sha256 =
            sha256_digest(&canonical_jcs_bytes(&durable_result)?);
        let payload = NestedAuthorityPayload::ReleasePreparationReceipt(
            ReleasePreparationReceiptArtifact {
                release_authorization_id: release.authorization_id.clone(),
                release_request_sha256: release
                    .exact_release_request_sha256
                    .clone(),
                inspection_result_sha256: release
                    .inspection_result_sha256
                    .clone(),
                release_object_sha256: release
                    .release_object_sha256
                    .clone(),
                client_binding_sha256: release
                    .client_binding_sha256
                    .clone(),
                exact_replay_key_sha256: release
                    .exact_replay_key_sha256
                    .clone(),
                preauthorization_artifact_sha256: release
                    .preauthorization_artifact_sha256
                    .clone(),
                signed_state_mutation_receipt_sha256:
                    signed_state_mutation_receipt_sha256.clone(),
                predecessor_revision: request.expected_revision,
                predecessor_state: request.expected_state,
                successor_revision,
                successor_state,
                fence_token: fence_token.clone(),
                one_use_nonce_sha256: release
                    .one_use_nonce_sha256
                    .clone(),
                durable_canonical_result_sha256:
                    durable_canonical_result_sha256.clone(),
            },
        );
        let payload_sha256 =
            sha256_digest(&canonical_jcs_bytes(&payload)?);
        let artifact_id = Identifier(format!(
            "artifact:{}",
            &payload_sha256.0["sha256:".len()..]
        ));
        let release_preparation_receipt = sign_authority_artifact(
            &self.signer,
            &request.generation_id,
            artifact_id,
            request.operation,
            &request.operation_id,
            &request.attempt_id,
            successor_revision,
            fence_token,
            release.issued_at_epoch_millis,
            release.expires_at_epoch_millis,
            payload,
            deadline,
        )?;
        let release_preparation_receipt_sha256 = sha256_digest(
            &canonical_jcs_bytes(&release_preparation_receipt)?,
        );
        Ok(ReleasePreparationResult {
            durable_result,
            durable_canonical_result_sha256,
            release_preparation_receipt,
            release_preparation_receipt_sha256,
        })
    }

    fn build_immutable_inspection_result(
        &self,
        request: &RpcRequest,
        successor_revision: u64,
        fence_token: &Identifier,
        inspection: &DeferredInspection,
        deadline: &BootDeadline,
    ) -> AuthorityResult<ImmutableInspectionResult> {
        let payload = NestedAuthorityPayload::ImmutableInspection(
            ImmutableInspectionArtifact {
                inspection_id: inspection.inspection_id.clone(),
                inspection_operation_id: request.operation_id.clone(),
                object_id: inspection.object_reference.object_id.clone(),
                object_kind: inspection.object_reference.object_kind.clone(),
                content_sha256: inspection
                    .object_reference
                    .content_sha256
                    .clone(),
                content_length: inspection.object_reference.content_length,
                media_type: inspection.object_reference.media_type.clone(),
                immutable_storage_receipt_sha256: inspection
                    .immutable_storage_receipt_sha256
                    .clone(),
                inspection_purpose_sha256: inspection
                    .inspection_purpose_sha256
                    .clone(),
                inspected_at_boot_id: inspection.inspected_at.boot_id.clone(),
                inspected_at_boot_millis: inspection
                    .inspected_at
                    .boot_millis,
                bytes_immutable: true,
                replacement_prohibited: true,
            },
        );
        let payload_sha256 =
            sha256_digest(&canonical_jcs_bytes(&payload)?);
        let artifact_id = Identifier(format!(
            "artifact:{}",
            &payload_sha256.0["sha256:".len()..]
        ));
        let signed_inspection_artifact = sign_authority_artifact(
            &self.signer,
            &request.generation_id,
            artifact_id,
            request.operation,
            &request.operation_id,
            &request.attempt_id,
            successor_revision,
            fence_token,
            inspection.issued_at_epoch_millis,
            inspection.expires_at_epoch_millis,
            payload,
            deadline,
        )?;
        let inspection_artifact_sha256 = sha256_digest(
            &canonical_jcs_bytes(&signed_inspection_artifact)?,
        );
        Ok(ImmutableInspectionResult {
            inspection_id: inspection.inspection_id.clone(),
            inspection_operation_id: request.operation_id.clone(),
            object_reference: inspection.object_reference.clone(),
            immutable_storage_receipt_sha256: inspection
                .immutable_storage_receipt_sha256
                .clone(),
            inspection_purpose_sha256: inspection
                .inspection_purpose_sha256
                .clone(),
            inspected_at_boot_id: inspection.inspected_at.boot_id.clone(),
            inspected_at_boot_millis: inspection.inspected_at.boot_millis,
            signed_inspection_artifact,
            inspection_artifact_sha256,
            bytes_immutable: true,
            replacement_prohibited: true,
        })
    }

    fn persist_inspection_result(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        inspection: &ImmutableInspectionResult,
        canonical_result: &[u8],
        canonical_result_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let canonical_artifact =
            canonical_jcs_bytes(&inspection.signed_inspection_artifact)?;
        if sha256_digest(&canonical_artifact)
            != inspection.inspection_artifact_sha256
        {
            return Err(AuthorityError::Backend {
                code: "immutable_inspection_artifact_digest_mismatch",
                reason: "signed inspection artifact changed before persistence"
                    .to_owned(),
            });
        }
        let inserted = transaction.execute(
            statements::INSERT_IMMUTABLE_INSPECTION_SQL,
            &[
                text(&request.generation_id),
                text(&inspection.inspection_id),
                text(&inspection.inspection_operation_id),
                text(&request.attempt_id),
                PgValue::U64(
                    inspection
                        .signed_inspection_artifact
                        .body
                        .attempt_revision,
                ),
                text(
                    &inspection
                        .signed_inspection_artifact
                        .body
                        .fence_token,
                ),
                text(&inspection.object_reference.object_id),
                text(&inspection.object_reference.object_kind),
                text_digest(&inspection.object_reference.content_sha256),
                PgValue::U64(inspection.object_reference.content_length),
                PgValue::Text(inspection.object_reference.media_type.clone()),
                text_digest(
                    &inspection.immutable_storage_receipt_sha256,
                ),
                text_digest(&inspection.inspection_purpose_sha256),
                text(&inspection.inspected_at_boot_id),
                PgValue::U64(inspection.inspected_at_boot_millis),
                PgValue::Bytes(canonical_artifact),
                text_digest(&inspection.inspection_artifact_sha256),
                PgValue::Bytes(canonical_result.to_vec()),
                text_digest(canonical_result_sha256),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Backend {
                code: "immutable_inspection_persist_failed",
                reason: "signed immutable inspection was not persisted exactly once"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn lock_inspection(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        inspection_result_sha256: &Digest,
    ) -> AuthorityResult<LockedInspection> {
        let row = transaction
            .query_optional(
                statements::LOCK_IMMUTABLE_INSPECTION_SQL,
                &[
                    text(generation_id),
                    text_digest(inspection_result_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "immutable_inspection_missing",
                authoritative_state: Some(
                    inspection_result_sha256.0.clone(),
                ),
            })?;
        let canonical_result =
            row.require_bytes("canonical_signed_result")?;
        let stored_sha256 = Digest(
            row.require_text("canonical_signed_result_sha256")?,
        );
        if &stored_sha256 != inspection_result_sha256
            || sha256_digest(&canonical_result) != stored_sha256
        {
            return Err(AuthorityError::Backend {
                code: "immutable_inspection_digest_mismatch",
                reason: "stored signed inspection bytes failed their exact digest"
                    .to_owned(),
            });
        }
        Ok(LockedInspection {
            inspection_id: Identifier(row.require_text("inspection_id")?),
            inspection_operation_id: Identifier(
                row.require_text("inspection_operation_id")?,
            ),
            attempt_id: Identifier(row.require_text("attempt_id")?),
            object_id: Identifier(row.require_text("object_id")?),
            object_sha256: Digest(row.require_text("object_sha256")?),
            object_length: row.require_u64("object_length")?,
            inspection_purpose_sha256: Digest(
                row.require_text("inspection_purpose_sha256")?,
            ),
            inspection_artifact_sha256: Digest(
                row.require_text("inspection_artifact_sha256")?,
            ),
            canonical_signed_result_sha256: stored_sha256,
        })
    }

    fn lock_inspection_artifact(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        inspection_artifact_sha256: &Digest,
    ) -> AuthorityResult<LockedInspection> {
        let row = transaction
            .query_optional(
                statements::LOCK_IMMUTABLE_INSPECTION_BY_ARTIFACT_SQL,
                &[
                    text(generation_id),
                    text_digest(inspection_artifact_sha256),
                ],
            )?
            .ok_or_else(|| AuthorityError::Conflict {
                code: "immutable_inspection_artifact_missing",
                authoritative_state: Some(
                    inspection_artifact_sha256.0.clone(),
                ),
            })?;
        let canonical_artifact =
            row.require_bytes("signed_inspection_artifact")?;
        let stored_artifact_sha256 =
            Digest(row.require_text("inspection_artifact_sha256")?);
        let canonical_result = row.require_bytes("canonical_signed_result")?;
        let stored_result_sha256 =
            Digest(row.require_text("canonical_signed_result_sha256")?);
        if &stored_artifact_sha256 != inspection_artifact_sha256
            || sha256_digest(&canonical_artifact) != stored_artifact_sha256
            || sha256_digest(&canonical_result) != stored_result_sha256
        {
            return Err(AuthorityError::Backend {
                code: "immutable_inspection_persistence_digest_mismatch",
                reason: "stored inspection artifact or signed state result failed its exact digest"
                    .to_owned(),
            });
        }
        Ok(LockedInspection {
            inspection_id: Identifier(row.require_text("inspection_id")?),
            inspection_operation_id: Identifier(
                row.require_text("inspection_operation_id")?,
            ),
            attempt_id: Identifier(row.require_text("attempt_id")?),
            object_id: Identifier(row.require_text("object_id")?),
            object_sha256: Digest(row.require_text("object_sha256")?),
            object_length: row.require_u64("object_length")?,
            inspection_purpose_sha256: Digest(
                row.require_text("inspection_purpose_sha256")?,
            ),
            inspection_artifact_sha256: stored_artifact_sha256,
            canonical_signed_result_sha256: stored_result_sha256,
        })
    }

    fn persist_release_result(
        &self,
        transaction: &mut dyn PostgresTransaction,
        request: &RpcRequest,
        release: &DeferredRelease,
        canonical_result: &[u8],
        canonical_result_sha256: &Digest,
    ) -> AuthorityResult<()> {
        let inserted = transaction.execute(
            statements::INSERT_RELEASE_LEDGER_SQL,
            &[
                text(&request.generation_id),
                text(&release.authorization_id),
                text(&request.attempt_id),
                text(&release.finalization_id),
                text_digest(&release.exact_release_request_sha256),
                text_digest(&release.inspection_result_sha256),
                text_digest(&release.release_object_sha256),
                text_digest(&release.client_binding_sha256),
                text_digest(&release.one_use_nonce_sha256),
                PgValue::Bytes(canonical_result.to_vec()),
                text_digest(canonical_result_sha256),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Conflict {
                code: "release_authorization_consumption_conflict",
                authoritative_state: Some(
                    release.authorization_id.0.clone(),
                ),
            });
        }
        Ok(())
    }

    fn append_transparency_leaf(
        &self,
        transaction: &mut dyn PostgresTransaction,
        generation_id: &Identifier,
        canonical_artifact: &[u8],
        canonical_artifact_sha256: &Digest,
    ) -> AuthorityResult<u64> {
        let predecessor = transaction.query_optional(
            statements::LOCK_LAST_TRANSPARENCY_LEAF_SQL,
            &[text(generation_id)],
        )?;
        let predecessor_sequence = predecessor
            .as_ref()
            .map(|row| row.require_u64("leaf_sequence"))
            .transpose()?
            .unwrap_or(0);
        let predecessor_sha256 = predecessor
            .as_ref()
            .map(|row| row.require_text("leaf_sha256"))
            .transpose()?
            .map(Digest);
        let leaf_sequence = predecessor_sequence
            .checked_add(1)
            .ok_or_else(|| AuthorityError::Backend {
                code: "transparency_sequence_exhausted",
                reason: "transparency sequence overflow".to_owned(),
            })?;
        let leaf_material = canonical_jcs_bytes(&(
            generation_id,
            leaf_sequence,
            &predecessor_sha256,
            canonical_artifact_sha256,
        ))?;
        let leaf_sha256 = sha256_digest(&leaf_material);
        let inserted = transaction.execute(
            statements::INSERT_TRANSPARENCY_LEAF_SQL,
            &[
                text(generation_id),
                PgValue::U64(leaf_sequence),
                text_digest(&leaf_sha256),
                predecessor_sha256
                    .as_ref()
                    .map(text_digest)
                    .unwrap_or(PgValue::Null),
                text_digest(canonical_artifact_sha256),
                PgValue::Bytes(canonical_artifact.to_vec()),
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Conflict {
                code: "transparency_leaf_append_conflict",
                authoritative_state: Some(
                    predecessor_sequence.to_string(),
                ),
            });
        }
        Ok(leaf_sequence)
    }
}

fn require_attempt(
    attempt: Option<&LockedAttempt>,
) -> AuthorityResult<&LockedAttempt> {
    attempt.ok_or_else(|| AuthorityError::Conflict {
        code: "attempt_missing",
        authoritative_state: None,
    })
}

fn require_fence(
    fence: Option<&LockedFence>,
) -> AuthorityResult<&LockedFence> {
    fence.ok_or_else(|| AuthorityError::Conflict {
        code: "fence_missing",
        authoritative_state: None,
    })
}

fn parse_locked_attempt(row: PgRow) -> AuthorityResult<LockedAttempt> {
    Ok(LockedAttempt {
        revision: row.require_u64("revision")?,
        state: parse_attempt_state(&row.require_text("state")?)?,
        fence_token: Identifier(row.require_text("fence_token")?),
        stable_resume_id: Identifier(
            row.require_text("stable_resume_id")?,
        ),
        owner_process_id: Identifier(
            row.require_text("owner_process_id")?,
        ),
        owner_pid: row.require_u32("owner_pid")?,
        owner_start_time_ticks: row
            .require_u64("owner_start_time_ticks")?,
        owner_cgroup_id: Identifier(
            row.require_text("owner_cgroup_id")?,
        ),
        deadline_boot_id: Identifier(
            row.require_text("deadline_boot_id")?,
        ),
        deadline_boot_millis: row.require_u64("deadline_boot_millis")?,
    })
}

fn parse_attempt_state(value: &str) -> AuthorityResult<AttemptState> {
    match value {
        "RESERVED" => Ok(AttemptState::Reserved),
        "AUTHORIZED" => Ok(AttemptState::Authorized),
        "STAGED" => Ok(AttemptState::Staged),
        "DISPATCHING" => Ok(AttemptState::Dispatching),
        "OUTCOME_UNKNOWN" => Ok(AttemptState::OutcomeUnknown),
        "OBSERVED" => Ok(AttemptState::Observed),
        "TERMINAL_FAILED" => Ok(AttemptState::TerminalFailed),
        "FINALIZED" => Ok(AttemptState::Finalized),
        "PUBLISHED" => Ok(AttemptState::Published),
        "RELEASE_PREPARED" => Ok(AttemptState::ReleasePrepared),
        "ARCHIVED" => Ok(AttemptState::Archived),
        other => Err(AuthorityError::Backend {
            code: "unknown_attempt_state",
            reason: other.to_owned(),
        }),
    }
}

fn parse_target_effect_state(
    value: &str,
) -> AuthorityResult<TargetEffectState> {
    match value {
        "DISPATCHING" => Ok(TargetEffectState::Dispatching),
        "OUTCOME_UNKNOWN" => Ok(TargetEffectState::OutcomeUnknown),
        "OBSERVED" => Ok(TargetEffectState::Observed),
        "RECONCILED_FAILURE" => {
            Ok(TargetEffectState::ReconciledFailure)
        }
        other => Err(AuthorityError::Backend {
            code: "unknown_target_effect_state",
            reason: other.to_owned(),
        }),
    }
}

fn parse_fence_state(value: &str) -> AuthorityResult<FenceState> {
    match value {
        "ACTIVE" => Ok(FenceState::Active),
        "REVOKED" => Ok(FenceState::Revoked),
        "QUIESCENT" => Ok(FenceState::Quiescent),
        other => Err(AuthorityError::Backend {
            code: "unknown_fence_state",
            reason: other.to_owned(),
        }),
    }
}

fn parse_generation_status(
    value: &str,
) -> AuthorityResult<GenerationStatus> {
    match value {
        "PROVISIONED" => Ok(GenerationStatus::Provisioned),
        "RECONCILING" => Ok(GenerationStatus::Reconciling),
        "READY" => Ok(GenerationStatus::Ready),
        "QUARANTINED" => Ok(GenerationStatus::Quarantined),
        "RETIRED" => Ok(GenerationStatus::Retired),
        other => Err(AuthorityError::Backend {
            code: "unknown_generation_status",
            reason: other.to_owned(),
        }),
    }
}

fn parse_service_role(value: &str) -> AuthorityResult<ServiceRole> {
    match value {
        "custody-router" => Ok(ServiceRole::CustodyRouter),
        "state-authority" => Ok(ServiceRole::StateAuthority),
        "credential-transport" => Ok(ServiceRole::CredentialTransport),
        "policy-proof-verifier" => Ok(ServiceRole::PolicyProofVerifier),
        "immutable-artifact-ledger" => {
            Ok(ServiceRole::ImmutableArtifactLedger)
        }
        "release-attestor-publisher" => {
            Ok(ServiceRole::ReleaseAttestorPublisher)
        }
        "cleanup-watchdog" => Ok(ServiceRole::CleanupWatchdog),
        other => Err(AuthorityError::Backend {
            code: "unknown_service_role",
            reason: other.to_owned(),
        }),
    }
}

fn parse_reconciliation_state(
    value: &str,
) -> AuthorityResult<ReconciliationState> {
    match value {
        "PENDING" => Ok(ReconciliationState::Pending),
        "RUNNING" => Ok(ReconciliationState::Running),
        "BLOCKED" => Ok(ReconciliationState::Blocked),
        "COMPLETE" => Ok(ReconciliationState::Complete),
        "FAILED" => Ok(ReconciliationState::Failed),
        other => Err(AuthorityError::Backend {
            code: "unknown_reconciliation_state",
            reason: other.to_owned(),
        }),
    }
}

fn parse_reconciliation_domain(
    value: &str,
) -> AuthorityResult<ReconciliationDomain> {
    match value {
        "PROVIDER_GENERATIONS" => {
            Ok(ReconciliationDomain::ProviderGenerations)
        }
        "ROLE_IDENTITIES" => Ok(ReconciliationDomain::RoleIdentities),
        "OPERATIONS" => Ok(ReconciliationDomain::Operations),
        "ATTEMPTS" => Ok(ReconciliationDomain::Attempts),
        "REPLAY_LEDGERS" => Ok(ReconciliationDomain::ReplayLedger),
        "TERMINAL_SETTLEMENTS" => {
            Ok(ReconciliationDomain::TerminalSettlements)
        }
        "TARGET_EFFECTS" => Ok(ReconciliationDomain::TargetEffects),
        "FENCES" => Ok(ReconciliationDomain::Fences),
        "RELEASE_LEDGERS" => Ok(ReconciliationDomain::Releases),
        "CREDENTIAL_USES" => {
            Ok(ReconciliationDomain::CredentialUses)
        }
        "POLICY_DECISIONS" => {
            Ok(ReconciliationDomain::PolicyDecisions)
        }
        "EVIDENCE" => Ok(ReconciliationDomain::Evidence),
        "IMMUTABLE_INSPECTIONS" => {
            Ok(ReconciliationDomain::ImmutableInspections)
        }
        "FINALIZATIONS" => Ok(ReconciliationDomain::Finalizations),
        "IMMUTABLE_OBJECTS" => {
            Ok(ReconciliationDomain::ImmutableObjects)
        }
        "ARCHIVES" => Ok(ReconciliationDomain::Archives),
        "PUBLISHER_OUTBOX" => {
            Ok(ReconciliationDomain::PublisherOutbox)
        }
        "TRANSPARENCY_LEAVES" => {
            Ok(ReconciliationDomain::TransparencyLeaves)
        }
        "TRANSPARENCY_CHECKPOINTS" => {
            Ok(ReconciliationDomain::TransparencyCheckpoints)
        }
        "TRUSTED_TIME_HIGHWATER" => {
            Ok(ReconciliationDomain::TrustedTimeHighwater)
        }
        other => Err(AuthorityError::Backend {
            code: "unknown_reconciliation_domain",
            reason: other.to_owned(),
        }),
    }
}

fn reconciliation_job_id(
    domain: ReconciliationDomain,
) -> Identifier {
    Identifier(format!("reconciliation:{}", domain.as_str()))
}

fn reconciliation_transition_allowed(
    predecessor: ReconciliationState,
    successor: ReconciliationState,
) -> bool {
    matches!(
        (predecessor, successor),
        (
            ReconciliationState::Pending,
            ReconciliationState::Running
        ) | (
            ReconciliationState::Running,
            ReconciliationState::Blocked
                | ReconciliationState::Complete
                | ReconciliationState::Failed
        ) | (
            ReconciliationState::Blocked,
            ReconciliationState::Running
                | ReconciliationState::Failed
        )
    )
}

fn target_effect_state_text(state: TargetEffectState) -> String {
    match state {
        TargetEffectState::Dispatching => "DISPATCHING",
        TargetEffectState::OutcomeUnknown => "OUTCOME_UNKNOWN",
        TargetEffectState::Observed => "OBSERVED",
        TargetEffectState::ReconciledFailure => "RECONCILED_FAILURE",
    }
    .to_owned()
}

fn reconciliation_state_text(state: ReconciliationState) -> String {
    match state {
        ReconciliationState::Pending => "PENDING",
        ReconciliationState::Running => "RUNNING",
        ReconciliationState::Blocked => "BLOCKED",
        ReconciliationState::Complete => "COMPLETE",
        ReconciliationState::Failed => "FAILED",
    }
    .to_owned()
}

fn text(identifier: &Identifier) -> PgValue {
    PgValue::Text(identifier.0.clone())
}

fn text_digest(digest: &Digest) -> PgValue {
    PgValue::Text(digest.0.clone())
}

fn authority_error_code(error: &AuthorityError) -> &'static str {
    match error {
        AuthorityError::InvalidContract { .. } => "invalid_contract",
        AuthorityError::Conflict { code, .. } => *code,
        AuthorityError::Authentication { code, .. } => *code,
        AuthorityError::Backend { code, .. } => *code,
        AuthorityError::Serialization { .. } => "serialization_failure",
        AuthorityError::NotReady { .. } => "not_ready",
    }
}
