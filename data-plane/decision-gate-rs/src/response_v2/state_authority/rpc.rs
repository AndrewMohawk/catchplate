use super::canonical::{
    canonical_jcs_bytes, decode_base64url, encode_base64url,
    sha256_digest, signature_message, NESTED_AUTHORITY_SIGNATURE_DOMAIN,
    STATE_AUTHORITY_SIGNATURE_DOMAIN,
};
use super::contract::{
    AuthorityError, AuthorityResult, BootDeadline, Digest,
    FINAL_ENVELOPE_API_VERSION, FINAL_ENVELOPE_KIND, Identifier,
    IMMUTABLE_RAW_OBJECT_API_VERSION, IMMUTABLE_RAW_OBJECT_KIND,
    NESTED_AUTHORITY_API_VERSION, NESTED_AUTHORITY_KIND,
    SIGNATURE_ALGORITHM, SIGNED_CHECKPOINT_API_VERSION,
    SIGNED_CHECKPOINT_KIND, STATE_AUTHORITY_API_VERSION,
    STATE_AUTHORITY_GENERATION_RESULT_KIND,
    STATE_AUTHORITY_GENERATION_RPC_KIND,
    STATE_AUTHORITY_RESULT_KIND, STATE_AUTHORITY_RPC_KIND,
    STATE_AUTHORITY_SCHEMA_VERSION,
};
use super::lifecycle::{
    AttemptState, OperationKind, ReconciliationDomain, ReconciliationState,
    TargetEffectState,
};
use super::topology::{
    GenerationStatus, ProviderGeneration, RoleIdentity, ServiceRole,
};
use super::transparency_contract::{
    canonical_transparency_sha256,
    validate_release_transparency_proof_untrusted,
    ReleaseTransparencyArtifactV2,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const NESTED_AUTHORITY_SIGNING_DOMAIN: &str =
    "serverware.responseV2.nestedAuthorityArtifact.signature/v1";
const RELEASE_PREPARATION_MUTATION_RECEIPT_SIGNING_DOMAIN: &[u8] =
    b"serverware.responseV2.releasePreparationMutationReceipt.signature/v1";
const FINAL_AUTHORITY_ARTIFACTS: [AuthorityArtifactType; 10] = [
    AuthorityArtifactType::ReleasePreparationReceipt,
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
const INSPECTION_SEED_AUTHORITY_ARTIFACTS: [AuthorityArtifactType; 9] = [
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameAuthentication {
    pub algorithm: String,
    pub key_id: Identifier,
    pub signed_payload_sha256: Digest,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FenceExpectationMode {
    Allocate,
    Exact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FenceExpectation {
    pub mode: FenceExpectationMode,
    pub fence_token: Option<Identifier>,
}

impl FenceExpectation {
    pub fn validate(
        &self,
        operation: OperationKind,
    ) -> AuthorityResult<()> {
        match (&self.mode, &self.fence_token, operation) {
            (
                FenceExpectationMode::Allocate,
                None,
                OperationKind::AttemptReserve,
            ) => Ok(()),
            (FenceExpectationMode::Exact, Some(token), operation)
                if operation != OperationKind::AttemptReserve =>
            {
                token.validate("request.fence.fenceToken", 128)
            }
            _ => Err(AuthorityError::InvalidContract {
                field: "request.fence",
                reason: "reserve must allocate a fence; every other mutation must carry the exact allocated fence"
                    .to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRequest {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub caller_role_id: Identifier,
    pub operation: OperationKind,
    pub attempt_id: Identifier,
    pub expected_revision: u64,
    pub expected_state: AttemptState,
    pub fence: FenceExpectation,
    pub deadline: BootDeadline,
    pub payload: MutationPayload,
}

impl RpcRequest {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != STATE_AUTHORITY_API_VERSION
            || self.kind != STATE_AUTHORITY_RPC_KIND
            || self.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        {
            return Err(AuthorityError::InvalidContract {
                field: "request",
                reason: "unsupported API version, kind, or schema version"
                    .to_owned(),
            });
        }
        self.generation_id.validate("request.generationId", 128)?;
        self.request_id.validate("request.requestId", 128)?;
        self.operation_id.validate("request.operationId", 128)?;
        self.caller_role_id
            .validate("request.callerRoleId", 128)?;
        self.attempt_id.validate("request.attemptId", 128)?;
        self.deadline.validate()?;
        if self.operation.is_generation_scoped() {
            return Err(AuthorityError::InvalidContract {
                field: "request.operation",
                reason: "generation-scoped operations require the generation RPC frame"
                    .to_owned(),
            });
        }
        self.fence.validate(self.operation)?;
        if self.payload.operation() != self.operation {
            return Err(AuthorityError::InvalidContract {
                field: "request.payload",
                reason: "payload does not match operation".to_owned(),
            });
        }
        if self.operation == OperationKind::AttemptReserve {
            if self.expected_revision != 0
                || self.expected_state != AttemptState::Absent
            {
                return Err(AuthorityError::InvalidContract {
                    field: "request.expectedState",
                    reason:
                        "reserve requires revision 0 and state ABSENT"
                            .to_owned(),
                });
            }
        } else if self.expected_state == AttemptState::Absent {
            return Err(AuthorityError::InvalidContract {
                field: "request.expectedState",
                reason: "only reserve may expect ABSENT".to_owned(),
            });
        }
        if !self.operation.permits_attempt_state(self.expected_state) {
            return Err(AuthorityError::InvalidContract {
                field: "request.expectedState",
                reason: "operation is not permitted in the expected durable attempt state"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRequestFrame {
    pub request: RpcRequest,
    pub authentication: FrameAuthentication,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationRpcRequest {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub caller_role_id: Identifier,
    pub operation: OperationKind,
    pub deadline: BootDeadline,
    pub payload: GenerationMutationPayload,
}

impl GenerationRpcRequest {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != STATE_AUTHORITY_API_VERSION
            || self.kind != STATE_AUTHORITY_GENERATION_RPC_KIND
            || self.schema_version != STATE_AUTHORITY_SCHEMA_VERSION
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationRequest",
                reason: "unsupported generation RPC version or kind"
                    .to_owned(),
            });
        }
        self.generation_id
            .validate("generationRequest.generationId", 128)?;
        self.request_id
            .validate("generationRequest.requestId", 128)?;
        self.operation_id
            .validate("generationRequest.operationId", 128)?;
        self.caller_role_id
            .validate("generationRequest.callerRoleId", 128)?;
        self.deadline.validate()?;
        if !self.operation.is_generation_scoped()
            || self.payload.operation() != self.operation
        {
            return Err(AuthorityError::InvalidContract {
                field: "generationRequest.operation",
                reason: "generation frame requires an exactly matching generation-scoped operation"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationRpcRequestFrame {
    pub request: GenerationRpcRequest,
    pub authentication: FrameAuthentication,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mutation", content = "parameters")]
pub enum GenerationMutationPayload {
    #[serde(rename = "responseV2.generation.install/v1")]
    Install(GenerationInstallMutation),
    #[serde(rename = "responseV2.generation.reconcile/v1")]
    Reconcile(GenerationReconcileMutation),
    #[serde(rename = "responseV2.generation.ready/v1")]
    MarkReady(GenerationReadyMutation),
    #[serde(rename = "responseV2.state.query/v1")]
    Query(StateQueryMutation),
}

impl GenerationMutationPayload {
    pub const fn operation(&self) -> OperationKind {
        match self {
            Self::Install(_) => OperationKind::GenerationInstall,
            Self::Reconcile(_) => OperationKind::GenerationReconcile,
            Self::MarkReady(_) => OperationKind::GenerationReady,
            Self::Query(_) => OperationKind::StateQuery,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationInstallMutation {
    pub generation: ProviderGeneration,
    pub canonical_generation_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationReconcileMutation {
    pub reconciliation_job_id: Identifier,
    pub domain: ReconciliationDomain,
    pub predecessor_state: ReconciliationState,
    pub successor_state: ReconciliationState,
    pub authoritative_cursor: u64,
    pub blocker_code: Option<Identifier>,
    pub result_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateQueryMutation {
    pub query_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationOperationResultBody {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub exact_request_sha256: Digest,
    pub operation: OperationKind,
    pub disposition: ResultDisposition,
    pub predecessor_generation_status: Option<GenerationStatus>,
    pub generation_status: GenerationStatus,
    pub generation_sha256: Digest,
    pub completed_domains: Vec<ReconciliationDomain>,
    pub blockers: Vec<Identifier>,
    pub result_artifact_ids: Vec<Identifier>,
    pub conflict_code: Option<Identifier>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedGenerationOperationResult {
    pub body: GenerationOperationResultBody,
    pub authentication: FrameAuthentication,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mutation", content = "parameters")]
pub enum MutationPayload {
    #[serde(rename = "responseV2.attempt.reserve/v1")]
    Reserve(ReserveMutation),
    #[serde(rename = "responseV2.attempt.authorize/v1")]
    Authorize(AuthorizeMutation),
    #[serde(rename = "responseV2.object.commitRaw/v1")]
    CommitRawObject(CommitRawObjectMutation),
    #[serde(rename = "responseV2.object.inspectImmutableRaw/v1")]
    InspectImmutableRaw(InspectImmutableRawMutation),
    #[serde(rename = "responseV2.attempt.stage/v1")]
    Stage(StageMutation),
    #[serde(rename = "responseV2.dispatch.begin/v1")]
    BeginDispatch(BeginDispatchMutation),
    #[serde(rename = "responseV2.dispatch.recordOutcome/v1")]
    RecordDispatchOutcome(RecordDispatchOutcomeMutation),
    #[serde(rename = "responseV2.attempt.terminalize/v1")]
    Terminalize(TerminalizeMutation),
    #[serde(rename = "responseV2.attempt.finalize/v1")]
    Finalize(FinalizeMutation),
    #[serde(rename = "responseV2.attempt.publish/v1")]
    Publish(PublishMutation),
    #[serde(rename = "responseV2.release.consumeAndRetrieveExact/v1")]
    ConsumeReleaseAndRetrieveExact(ConsumeReleaseAndRetrieveExactMutation),
    #[serde(rename = "responseV2.release.resolveReplay/v1")]
    ResolveReplay(ResolveReplayMutation),
    #[serde(rename = "responseV2.attempt.settle/v1")]
    SettleAttempt(SettleAttemptMutation),
    #[serde(rename = "responseV2.attempt.archive/v1")]
    Archive(ArchiveMutation),
    #[serde(rename = "responseV2.fence.revoke/v1")]
    RevokeFence(RevokeFenceMutation),
    #[serde(rename = "responseV2.fence.observeQuiescence/v1")]
    ObserveQuiescence(ObserveQuiescenceMutation),
    #[serde(rename = "responseV2.evidence.append/v1")]
    AppendEvidence(AppendEvidenceMutation),
    #[serde(rename = "responseV2.publisher.enqueue/v1")]
    EnqueuePublication(EnqueuePublicationMutation),
    #[serde(rename = "responseV2.publisher.acknowledge/v1")]
    AcknowledgePublication(AcknowledgePublicationMutation),
    #[serde(rename = "responseV2.transparency.checkpoint/v1")]
    PublishCheckpoint(PublishCheckpointMutation),
    #[serde(rename = "responseV2.trustedTime.advance/v1")]
    AdvanceTrustedTime(AdvanceTrustedTimeMutation),
    #[serde(rename = "responseV2.reconciliation.transition/v1")]
    Reconcile(ReconciliationMutation),
    #[serde(
        rename = "responseV2.reconciliation.terminalizeExpiredAttempt/v1"
    )]
    TerminalizeExpiredAttempt(TerminalizeExpiredAttemptMutation),
}

impl MutationPayload {
    pub const fn operation(&self) -> OperationKind {
        match self {
            Self::Reserve(_) => OperationKind::AttemptReserve,
            Self::Authorize(_) => OperationKind::AttemptAuthorize,
            Self::CommitRawObject(_) => OperationKind::ObjectCommitRaw,
            Self::InspectImmutableRaw(_) => {
                OperationKind::ObjectInspectImmutableRaw
            }
            Self::Stage(_) => OperationKind::AttemptStage,
            Self::BeginDispatch(_) => OperationKind::DispatchBegin,
            Self::RecordDispatchOutcome(_) => {
                OperationKind::DispatchRecordOutcome
            }
            Self::Terminalize(_) => OperationKind::AttemptTerminalize,
            Self::Finalize(_) => OperationKind::AttemptFinalize,
            Self::Publish(_) => OperationKind::AttemptPublish,
            Self::ConsumeReleaseAndRetrieveExact(_) => {
                OperationKind::ReleaseConsumeAndRetrieveExact
            }
            Self::ResolveReplay(_) => OperationKind::ReleaseResolveReplay,
            Self::SettleAttempt(_) => OperationKind::AttemptSettle,
            Self::Archive(_) => OperationKind::AttemptArchive,
            Self::RevokeFence(_) => OperationKind::FenceRevoke,
            Self::ObserveQuiescence(_) => {
                OperationKind::FenceObserveQuiescence
            }
            Self::AppendEvidence(_) => OperationKind::EvidenceAppend,
            Self::EnqueuePublication(_) => OperationKind::PublisherEnqueue,
            Self::AcknowledgePublication(_) => {
                OperationKind::PublisherAcknowledge
            }
            Self::PublishCheckpoint(_) => {
                OperationKind::TransparencyCheckpoint
            }
            Self::AdvanceTrustedTime(_) => OperationKind::TrustedTimeAdvance,
            Self::Reconcile(_) => OperationKind::ReconciliationTransition,
            Self::TerminalizeExpiredAttempt(_) => {
                OperationKind::ReconciliationTerminalizeExpiredAttempt
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationReadyMutation {
    pub reconciliation_checkpoint_sha256: Digest,
    pub role_readiness_artifacts: Vec<SignedAuthorityArtifact>,
    pub router_topology_attestation: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationReadinessScope {
    pub attempt_id: Identifier,
    pub attempt_revision: u64,
    pub fence_token: Identifier,
}

pub fn derive_generation_readiness_scope(
    generation: &ProviderGeneration,
    reconciliation_checkpoint_sha256: &Digest,
) -> AuthorityResult<GenerationReadinessScope> {
    let scope_sha256 = sha256_digest(&canonical_jcs_bytes(&(
        "GENERATION_READINESS",
        &generation.generation_id,
        generation.rollback_floor,
        &generation.source_tree_sha256,
        &generation.topology.readiness_contract.contract_sha256,
        reconciliation_checkpoint_sha256,
    ))?);
    let suffix = &scope_sha256.0["sha256:".len()..];
    Ok(GenerationReadinessScope {
        attempt_id: Identifier(format!(
            "generation-readiness:{suffix}"
        )),
        attempt_revision: generation.rollback_floor,
        fence_token: Identifier(format!(
            "generation-readiness-fence:{suffix}"
        )),
    })
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReserveMutation {
    pub stable_resume_id: Identifier,
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub attempt_deadline: BootDeadline,
    pub request_sha256: Digest,
    pub route_sha256: Digest,
    pub credential_scope_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizeMutation {
    pub policy_decision_id: Identifier,
    pub policy_generation_sha256: Digest,
    pub authorization_artifacts: Vec<SignedAuthorityArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitRawObjectMutation {
    pub object_id: Identifier,
    pub object_kind: Identifier,
    pub media_type: String,
    pub expected_content_length: u64,
    pub expected_content_sha256: Digest,
    pub storage_locator: String,
    pub immutable_storage_receipt_sha256: Digest,
    pub artifact_commit: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectImmutableRawMutation {
    pub inspection_id: Identifier,
    pub object: RawObjectReference,
    pub inspection_purpose_sha256: Digest,
    pub expected_immutable_storage_receipt_sha256: Digest,
    pub require_no_byte_release: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageMutation {
    pub staged_request_object: RawObjectReference,
    pub credential_binding_sha256: Digest,
    pub transition_artifacts: Vec<SignedAuthorityArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginDispatchMutation {
    pub target_effect_id: Identifier,
    pub credential_use_id: Identifier,
    pub credential_binding_sha256: Digest,
    pub idempotency_key_sha256: Digest,
    pub request_object: RawObjectReference,
    pub transport_authorization: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordDispatchOutcomeMutation {
    pub target_effect_id: Identifier,
    pub outcome: TargetEffectState,
    pub response_object: Option<RawObjectReference>,
    pub uncertainty_code: Option<Identifier>,
    pub transport_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalizeMutation {
    pub stable_resume_id: Identifier,
    pub terminal_code: Identifier,
    pub terminal_detail_sha256: Digest,
    pub terminal_artifacts: Vec<SignedAuthorityArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizeMutation {
    pub finalization_id: Identifier,
    pub final_envelope: CanonicalFinalEnvelope,
    pub final_envelope_verification: SignedAuthorityArtifact,
    pub artifact_ledger_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishMutation {
    pub publication_id: Identifier,
    pub outbox_id: Identifier,
    pub finalization_id: Identifier,
    pub payload_object: RawObjectReference,
    pub publisher_authorization: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "phase", content = "parameters")]
pub enum ConsumeReleaseAndRetrieveExactMutation {
    #[serde(rename = "PREPARE")]
    Prepare(PrepareReleaseConsumptionMutation),
    #[serde(rename = "RETRIEVE")]
    Retrieve(RetrievePreparedReleaseMutation),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationMutationBinding {
    pub release_authorization_id: Identifier,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object: RawObjectReference,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareReleaseConsumptionMutation {
    pub binding: ReleasePreparationMutationBinding,
    pub inspection_seed: CanonicalInspectionSeed,
    pub release_authorization: SignedAuthorityArtifact,
    pub release_consumption_preauthorization: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrievePreparedReleaseMutation {
    pub binding: ReleasePreparationMutationBinding,
    pub prepared_consumption_receipt:
        SignedReleasePreparationMutationReceipt,
    pub final_envelope_verification: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolveReplayMutation {
    pub source_replay_id: Identifier,
    pub source_operation_id: Identifier,
    pub source_exact_request_sha256: Digest,
    pub source_canonical_result_sha256: Digest,
    pub stable_resume_id: Identifier,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettleAttemptMutation {
    pub stable_resume_id: Identifier,
    pub terminal_code: Identifier,
    pub terminal_detail_sha256: Digest,
    pub target_effect_id: Option<Identifier>,
    pub upstream_response_sha256: Option<Digest>,
    pub observed_boot_id: Identifier,
    pub observed_boot_millis: u64,
    pub cleanup_deadline: BootDeadline,
    pub reconciliation_evidence: SignedAuthorityArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_evidence: Option<SignedAuthorityArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchiveMutation {
    pub archive_id: Identifier,
    pub finalization_id: Identifier,
    pub object_ids: Vec<Identifier>,
    pub canonical_archive_sha256: Digest,
    pub archive_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeFenceMutation {
    pub reason_code: Identifier,
    pub cleanup_authorization: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObserveQuiescenceMutation {
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
    pub cleanup_observation: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendEvidenceMutation {
    pub evidence_id: Identifier,
    pub evidence_type: Identifier,
    pub object: Option<RawObjectReference>,
    pub evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnqueuePublicationMutation {
    pub outbox_id: Identifier,
    pub publication_id: Identifier,
    pub finalization_id: Identifier,
    pub payload_object: RawObjectReference,
    pub publisher_authorization: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcknowledgePublicationMutation {
    pub outbox_id: Identifier,
    pub publication_id: Identifier,
    pub finalization_id: Identifier,
    pub delivered_object_sha256: Digest,
    pub publisher_receipt: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishCheckpointMutation {
    pub checkpoint: SignedCheckpoint,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdvanceTrustedTimeMutation {
    pub clock_id: Identifier,
    pub epoch_millis: u64,
    pub sequence: u64,
    pub trusted_time_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciliationMutation {
    pub reconciliation_job_id: Identifier,
    pub domain: Identifier,
    pub expected_reconciliation_state: ReconciliationState,
    pub successor_reconciliation_state: ReconciliationState,
    pub authoritative_cursor: u64,
    pub blocker_code: Option<Identifier>,
    pub reconciliation_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalizeExpiredAttemptMutation {
    pub stable_resume_id: Identifier,
    pub observed_boot_id: Identifier,
    pub observed_boot_millis: u64,
    pub cleanup_deadline: BootDeadline,
    pub terminal_detail_sha256: Digest,
    pub recovery_evidence: SignedAuthorityArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawObjectReference {
    pub generation_id: Identifier,
    pub object_id: Identifier,
    pub object_kind: Identifier,
    pub content_sha256: Digest,
    pub content_length: u64,
    pub media_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalInspectionSeed {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub body: CanonicalInspectionSeedBody,
    pub body_sha256: Digest,
    pub authority_artifacts: Vec<SignedAuthorityArtifact>,
}

impl CanonicalInspectionSeed {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != FINAL_ENVELOPE_API_VERSION
            || self.kind != "ResponseV2InspectionSeed"
            || self.schema_version != "1"
        {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed",
                reason: "unsupported inspection seed version or kind"
                    .to_owned(),
            });
        }
        self.body.validate()?;
        if self.authority_artifacts.len()
            != INSPECTION_SEED_AUTHORITY_ARTIFACTS.len()
        {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed.authorityArtifacts",
                reason: "exactly nine ordered inspection-seed authority artifacts are required"
                    .to_owned(),
            });
        }
        let mut artifact_ids = BTreeSet::new();
        let mut canonical_artifacts = BTreeSet::new();
        for (index, (artifact, expected_class)) in self
            .authority_artifacts
            .iter()
            .zip(INSPECTION_SEED_AUTHORITY_ARTIFACTS)
            .enumerate()
        {
            artifact.validate_contract()?;
            if artifact.body.artifact_class != expected_class
                || artifact.body.payload.artifact_type() != expected_class
            {
                return Err(AuthorityError::InvalidContract {
                    field: "inspectionSeed.authorityArtifacts",
                    reason: format!(
                        "artifact {index} must be {}",
                        expected_class.as_str()
                    ),
                });
            }
            if artifact.body.generation_id != self.body.generation_id
                || artifact.body.attempt_id != self.body.attempt_id
                || artifact.body.fence_token != self.body.fence_token
            {
                return Err(AuthorityError::InvalidContract {
                    field: "inspectionSeed.authorityArtifacts",
                    reason: format!(
                        "artifact {index} does not bind the seed generation, attempt, and fence"
                    ),
                });
            }
            let canonical = canonical_jcs_bytes(artifact)?;
            if !artifact_ids.insert(artifact.body.artifact_id.clone())
                || !canonical_artifacts.insert(sha256_digest(&canonical))
            {
                return Err(AuthorityError::InvalidContract {
                    field: "inspectionSeed.authorityArtifacts",
                    reason: "artifact IDs and canonical signed artifacts must be unique"
                        .to_owned(),
                });
            }
        }
        let canonical_artifacts =
            canonical_jcs_bytes(&self.authority_artifacts)?;
        if sha256_digest(&canonical_artifacts)
            != self.body.authority_artifacts_root_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed.body.authorityArtifactsRootSha256",
                reason: "inspection-seed authority artifact array digest mismatch"
                    .to_owned(),
            });
        }
        if sha256_digest(&canonical_jcs_bytes(&self.body)?)
            != self.body_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed.bodySha256",
                reason: "inspection-seed body digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalInspectionSeedBody {
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub attempt_revision: u64,
    pub fence_token: Identifier,
    pub stable_resume_id: Identifier,
    pub raw_response_object: RawObjectReference,
    pub inspection_result_sha256: Digest,
    pub authority_artifacts_root_sha256: Digest,
}

impl CanonicalInspectionSeedBody {
    pub fn validate(&self) -> AuthorityResult<()> {
        self.generation_id
            .validate("inspectionSeed.body.generationId", 128)?;
        self.attempt_id
            .validate("inspectionSeed.body.attemptId", 128)?;
        if self.attempt_revision == 0 {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed.body.attemptRevision",
                reason: "attempt revision must be positive".to_owned(),
            });
        }
        self.fence_token
            .validate("inspectionSeed.body.fenceToken", 128)?;
        self.stable_resume_id
            .validate("inspectionSeed.body.stableResumeId", 128)?;
        self.inspection_result_sha256
            .validate("inspectionSeed.body.inspectionResultSha256")?;
        self.authority_artifacts_root_sha256
            .validate("inspectionSeed.body.authorityArtifactsRootSha256")?;
        if self.raw_response_object.generation_id != self.generation_id {
            return Err(AuthorityError::InvalidContract {
                field: "inspectionSeed.body.rawResponseObject.generationId",
                reason: "inspection seed object belongs to a different generation"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalFinalEnvelope {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub body: CanonicalFinalEnvelopeBody,
    pub body_sha256: Digest,
    pub authority_artifacts: Vec<SignedAuthorityArtifact>,
}

impl CanonicalFinalEnvelope {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != FINAL_ENVELOPE_API_VERSION
            || self.kind != FINAL_ENVELOPE_KIND
            || self.schema_version != "1"
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope",
                reason: "unsupported final envelope version or kind"
                    .to_owned(),
            });
        }
        self.body.validate()?;
        if self.authority_artifacts.len()
            != FINAL_AUTHORITY_ARTIFACTS.len()
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.authorityArtifacts",
                reason: "exactly ten ordered final authority artifacts are required"
                    .to_owned(),
            });
        }
        let mut artifact_ids = BTreeSet::new();
        let mut canonical_artifacts = BTreeSet::new();
        for (index, (artifact, expected_class)) in self
            .authority_artifacts
            .iter()
            .zip(FINAL_AUTHORITY_ARTIFACTS)
            .enumerate()
        {
            artifact.validate_contract()?;
            if artifact.body.artifact_class != expected_class
                || artifact.body.payload.artifact_type() != expected_class
            {
                return Err(AuthorityError::InvalidContract {
                    field: "finalEnvelope.authorityArtifacts",
                    reason: format!(
                        "artifact {index} must be {}",
                        expected_class.as_str()
                    ),
                });
            }
            if artifact.body.generation_id != self.body.generation_id
                || artifact.body.attempt_id != self.body.attempt_id
                || artifact.body.fence_token != self.body.fence_token
            {
                return Err(AuthorityError::InvalidContract {
                    field: "finalEnvelope.authorityArtifacts",
                    reason: format!(
                        "artifact {index} does not bind the envelope generation, attempt, and fence"
                    ),
                });
            }
            let canonical = canonical_jcs_bytes(artifact)?;
            if !artifact_ids.insert(artifact.body.artifact_id.clone())
                || !canonical_artifacts.insert(sha256_digest(&canonical))
            {
                return Err(AuthorityError::InvalidContract {
                    field: "finalEnvelope.authorityArtifacts",
                    reason: "artifact IDs and canonical signed artifacts must be unique"
                        .to_owned(),
                });
            }
        }
        let canonical_artifacts =
            canonical_jcs_bytes(&self.authority_artifacts)?;
        if sha256_digest(&canonical_artifacts)
            != self.body.authority_artifacts_root_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.authorityArtifactsRootSha256",
                reason: "authority artifact array digest mismatch".to_owned(),
            });
        }
        let canonical_body = canonical_jcs_bytes(&self.body)?;
        if sha256_digest(&canonical_body) != self.body_sha256 {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.bodySha256",
                reason: "body digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalFinalEnvelopeBody {
    pub generation_id: Identifier,
    pub attempt_id: Identifier,
    pub attempt_revision: u64,
    pub fence_token: Identifier,
    pub stable_resume_id: Identifier,
    pub finalization_id: Identifier,
    pub staged_request_object: RawObjectReference,
    pub raw_response_object: RawObjectReference,
    pub http11_framing: Http11FramingResult,
    pub credential_use_id: Identifier,
    pub target_effect_id: Identifier,
    pub policy_decision_id: Identifier,
    pub released_projection_sha256: Digest,
    pub transition_chain_sha256: Digest,
    pub evidence_root_sha256: Digest,
    pub authority_artifacts_root_sha256: Digest,
}

impl CanonicalFinalEnvelopeBody {
    pub fn validate(&self) -> AuthorityResult<()> {
        self.generation_id
            .validate("finalEnvelope.body.generationId", 128)?;
        self.attempt_id
            .validate("finalEnvelope.body.attemptId", 128)?;
        if self.attempt_revision == 0 {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.attemptRevision",
                reason: "attempt revision must be positive".to_owned(),
            });
        }
        self.fence_token
            .validate("finalEnvelope.body.fenceToken", 128)?;
        self.stable_resume_id
            .validate("finalEnvelope.body.stableResumeId", 128)?;
        self.finalization_id
            .validate("finalEnvelope.body.finalizationId", 128)?;
        self.credential_use_id
            .validate("finalEnvelope.body.credentialUseId", 128)?;
        self.target_effect_id
            .validate("finalEnvelope.body.targetEffectId", 128)?;
        self.policy_decision_id
            .validate("finalEnvelope.body.policyDecisionId", 128)?;
        self.http11_framing.validate()?;
        if self.raw_response_object.content_length
            != self.http11_framing.physical_message_length
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.rawResponseObject.contentLength",
                reason: "raw response object length must equal the strictly framed physical HTTP message length"
                    .to_owned(),
            });
        }
        for (field, digest) in [
            (
                "finalEnvelope.body.releasedProjectionSha256",
                &self.released_projection_sha256,
            ),
            (
                "finalEnvelope.body.transitionChainSha256",
                &self.transition_chain_sha256,
            ),
            (
                "finalEnvelope.body.evidenceRootSha256",
                &self.evidence_root_sha256,
            ),
            (
                "finalEnvelope.body.authorityArtifactsRootSha256",
                &self.authority_artifacts_root_sha256,
            ),
        ] {
            digest.validate(field)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Http11FramingResult {
    pub http_version: String,
    pub informational_statuses: Vec<u16>,
    pub final_status: u16,
    pub header_section_length: u64,
    pub transfer_coding: TransferCoding,
    pub declared_content_length: Option<u64>,
    pub decoded_entity_length: u64,
    pub trailer_section_length: u64,
    pub trailer_names: Vec<String>,
    pub physical_message_length: u64,
    pub surplus_length: u64,
    pub canonical_framing_sha256: Digest,
}

impl Http11FramingResult {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.http_version != "HTTP/1.1"
            || !(200..=599).contains(&self.final_status)
            || self
                .informational_statuses
                .iter()
                .any(|status| !(100..=199).contains(status) || *status == 101)
            || self.surplus_length != 0
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.http11Framing",
                reason: "requires strict HTTP/1.1, bounded non-101 informational responses, one final response, and zero surplus bytes"
                    .to_owned(),
            });
        }
        if self.informational_statuses.len() > 8
            || self.header_section_length > 262_144
            || self.trailer_section_length > 262_144
            || self.decoded_entity_length > 33_554_432
            || self.physical_message_length == 0
            || self.physical_message_length > 34_603_008
            || self.trailer_names.len() > 128
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.http11Framing",
                reason: "framing metadata exceeds fixed response-v2 bounds"
                    .to_owned(),
            });
        }
        let mut trailers = std::collections::BTreeSet::new();
        for name in &self.trailer_names {
            if name.is_empty()
                || name.len() > 128
                || name.bytes().any(|byte| {
                    !byte.is_ascii_lowercase()
                        && !byte.is_ascii_digit()
                        && !matches!(
                            byte,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )
                })
                || !trailers.insert(name)
            {
                return Err(AuthorityError::InvalidContract {
                    field:
                        "finalEnvelope.body.http11Framing.trailerNames",
                    reason: "trailer names must be unique lowercase HTTP field names"
                        .to_owned(),
                });
            }
        }
        if self.transfer_coding == TransferCoding::Chunked
            && self.declared_content_length.is_some()
        {
            return Err(AuthorityError::InvalidContract {
                field:
                    "finalEnvelope.body.http11Framing.declaredContentLength",
                reason:
                    "Content-Length is forbidden with chunked transfer coding"
                        .to_owned(),
            });
        }
        if self.transfer_coding == TransferCoding::Identity
            && self.declared_content_length
                != Some(self.decoded_entity_length)
        {
            return Err(AuthorityError::InvalidContract {
                field:
                    "finalEnvelope.body.http11Framing.declaredContentLength",
                reason: "identity framing requires one exact Content-Length"
                    .to_owned(),
            });
        }
        if self.transfer_coding == TransferCoding::Identity
            && (self.trailer_section_length != 0
                || !self.trailer_names.is_empty())
        {
            return Err(AuthorityError::InvalidContract {
                field: "finalEnvelope.body.http11Framing.trailers",
                reason: "trailers require chunked transfer coding"
                    .to_owned(),
            });
        }
        self.canonical_framing_sha256.validate(
            "finalEnvelope.body.http11Framing.canonicalFramingSha256",
        )
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferCoding {
    Identity,
    Chunked,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuthorityArtifact {
    pub body: AuthorityArtifactBody,
    pub authentication: NestedArtifactAuthentication,
}

impl SignedAuthorityArtifact {
    pub fn canonical_signed_bytes(&self) -> AuthorityResult<Vec<u8>> {
        canonical_jcs_bytes(self)
    }

    pub fn canonical_body_bytes(&self) -> AuthorityResult<Vec<u8>> {
        canonical_jcs_bytes(&self.body)
    }

    pub fn validate_contract(&self) -> AuthorityResult<()> {
        let body = &self.body;
        if body.api_version != NESTED_AUTHORITY_API_VERSION
            || body.kind != NESTED_AUTHORITY_KIND
            || body.schema_version != "1"
            || body.issued_at_epoch_millis >= body.expires_at_epoch_millis
            || body.artifact_class != body.payload.artifact_type()
        {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body",
                reason: "version, validity, artifact class, and payload tag must match the closed nested-artifact contract"
                    .to_owned(),
            });
        }
        body.generation_id
            .validate("nestedAuthorityArtifact.body.generationId", 128)?;
        body.artifact_id
            .validate("nestedAuthorityArtifact.body.artifactId", 128)?;
        body.producing_role_id
            .validate("nestedAuthorityArtifact.body.producingRoleId", 128)?;
        body.producing_process_id.validate(
            "nestedAuthorityArtifact.body.producingProcessId",
            128,
        )?;
        if let Some(logical_role) = &body.producing_logical_role {
            logical_role.validate(
                "nestedAuthorityArtifact.body.producingLogicalRole",
                128,
            )?;
        }
        body.key_id
            .validate("nestedAuthorityArtifact.body.keyId", 128)?;
        body.key_material_sha256
            .validate("nestedAuthorityArtifact.body.keyMaterialSha256")?;
        body.authority_scope.validate()?;
        body.authority_scope_sha256
            .validate("nestedAuthorityArtifact.body.authorityScopeSha256")?;
        body.operation_id
            .validate("nestedAuthorityArtifact.body.operationId", 128)?;
        body.attempt_id
            .validate("nestedAuthorityArtifact.body.attemptId", 128)?;
        if body.attempt_revision == 0 {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.attemptRevision",
                reason: "attempt revision must be positive".to_owned(),
            });
        }
        body.fence_token
            .validate("nestedAuthorityArtifact.body.fenceToken", 128)?;
        body.payload_sha256
            .validate("nestedAuthorityArtifact.body.payloadSha256")?;
        let payload_sha256 =
            sha256_digest(&canonical_jcs_bytes(&body.payload)?);
        if payload_sha256 != body.payload_sha256 {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.payloadSha256",
                reason: "payload digest mismatch".to_owned(),
            });
        }
        if let NestedAuthorityPayload::TransparencyCheckpoint(transparency) =
            &body.payload
        {
            let summary = validate_release_transparency_proof_untrusted(
                &transparency.release_transparency_proof,
            )
            .map_err(|error| AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.payload.artifact.releaseTransparencyProof",
                reason: error.to_string(),
            })?;
            let proof_sha256 = canonical_transparency_sha256(
                &transparency.release_transparency_proof,
            )
            .map_err(|error| AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.payload.artifact.releaseTransparencyProofSha256",
                reason: error.to_string(),
            })?;
            if transparency.release_transparency_proof_sha256
                != proof_sha256
                || summary.checkpoint_sha256
                    != transparency
                        .release_transparency_proof
                        .checkpoint_sha256
            {
                return Err(AuthorityError::InvalidContract {
                    field: "nestedAuthorityArtifact.body.payload.artifact.releaseTransparencyProofSha256",
                    reason: "transparency artifact does not carry the exact validated release proof"
                        .to_owned(),
                });
            }
        }
        if body.key_id != self.authentication.key_id
            || body.key_material_sha256
                != self.authentication.key_material_sha256
            || body.authority_scope_sha256
                != self.authentication.authority_scope_sha256
            || self.authentication.signing_domain
                != NESTED_AUTHORITY_SIGNING_DOMAIN
        {
            return Err(AuthorityError::Authentication {
                code: "nested_artifact_authentication_binding_mismatch",
                reason: "body key material, authority scope, and signing domain must match authentication"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityArtifactBody {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub artifact_id: Identifier,
    pub producing_role_id: Identifier,
    pub producing_process_id: Identifier,
    pub producing_service_role: ServiceRole,
    pub producing_logical_role: Option<Identifier>,
    pub key_id: Identifier,
    pub key_material_sha256: Digest,
    pub authority_scope: AuthorityScope,
    pub authority_scope_sha256: Digest,
    pub artifact_class: AuthorityArtifactType,
    pub operation: OperationKind,
    pub operation_id: Identifier,
    pub attempt_id: Identifier,
    pub attempt_revision: u64,
    pub fence_token: Identifier,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub payload_sha256: Digest,
    pub payload: NestedAuthorityPayload,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityScope {
    pub generation_id: Identifier,
    pub process_id: Identifier,
    pub service_role: ServiceRole,
    pub logical_role: Option<Identifier>,
    pub role_id: Identifier,
    pub key_id: Identifier,
    pub key_material_sha256: Digest,
    pub executable_sha256: Digest,
    pub configuration_sha256: Digest,
    pub allowed_operations: Vec<OperationKind>,
    pub scope_sha256: Digest,
}

impl AuthorityScope {
    pub fn validate(&self) -> AuthorityResult<()> {
        self.generation_id
            .validate("nestedAuthorityArtifact.body.authorityScope.generationId", 128)?;
        self.process_id
            .validate("nestedAuthorityArtifact.body.authorityScope.processId", 128)?;
        if let Some(logical_role) = &self.logical_role {
            logical_role.validate(
                "nestedAuthorityArtifact.body.authorityScope.logicalRole",
                128,
            )?;
        }
        self.role_id
            .validate("nestedAuthorityArtifact.body.authorityScope.roleId", 128)?;
        self.key_id
            .validate("nestedAuthorityArtifact.body.authorityScope.keyId", 128)?;
        self.key_material_sha256.validate(
            "nestedAuthorityArtifact.body.authorityScope.keyMaterialSha256",
        )?;
        self.executable_sha256.validate(
            "nestedAuthorityArtifact.body.authorityScope.executableSha256",
        )?;
        self.configuration_sha256.validate(
            "nestedAuthorityArtifact.body.authorityScope.configurationSha256",
        )?;
        self.scope_sha256
            .validate("nestedAuthorityArtifact.body.authorityScope.scopeSha256")?;
        if self.allowed_operations.is_empty()
            || self.allowed_operations.len() > 27
        {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.authorityScope.allowedOperations",
                reason: "authority scope requires one to 27 exact operations"
                    .to_owned(),
            });
        }
        let mut operations = BTreeSet::new();
        if self
            .allowed_operations
            .iter()
            .any(|operation| !operations.insert(*operation))
        {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.authorityScope.allowedOperations",
                reason: "authority scope operations must be unique".to_owned(),
            });
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct UnsignedScope<'a> {
            generation_id: &'a Identifier,
            process_id: &'a Identifier,
            service_role: ServiceRole,
            logical_role: &'a Option<Identifier>,
            role_id: &'a Identifier,
            key_id: &'a Identifier,
            key_material_sha256: &'a Digest,
            executable_sha256: &'a Digest,
            configuration_sha256: &'a Digest,
            allowed_operations: &'a [OperationKind],
        }
        let unsigned = UnsignedScope {
            generation_id: &self.generation_id,
            process_id: &self.process_id,
            service_role: self.service_role,
            logical_role: &self.logical_role,
            role_id: &self.role_id,
            key_id: &self.key_id,
            key_material_sha256: &self.key_material_sha256,
            executable_sha256: &self.executable_sha256,
            configuration_sha256: &self.configuration_sha256,
            allowed_operations: &self.allowed_operations,
        };
        if sha256_digest(&canonical_jcs_bytes(&unsigned)?)
            != self.scope_sha256
        {
            return Err(AuthorityError::InvalidContract {
                field: "nestedAuthorityArtifact.body.authorityScope.scopeSha256",
                reason: "authority scope digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NestedArtifactAuthentication {
    pub algorithm: String,
    pub key_id: Identifier,
    pub key_material_sha256: Digest,
    pub authority_scope_sha256: Digest,
    pub signing_domain: String,
    pub signed_payload_sha256: Digest,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "artifactType", content = "artifact")]
pub enum NestedAuthorityPayload {
    #[serde(rename = "ROLE_READINESS")]
    RoleReadiness(RoleReadinessArtifact),
    #[serde(rename = "ROUTER_TOPOLOGY_ATTESTATION")]
    RouterTopologyAttestation(RouterTopologyAttestationArtifact),
    #[serde(rename = "STATE_CAS")]
    StateCas(StateCasArtifact),
    #[serde(rename = "RELEASE_PREPARATION_RECEIPT")]
    ReleasePreparationReceipt(ReleasePreparationReceiptArtifact),
    #[serde(rename = "CREDENTIAL_USE")]
    CredentialUse(CredentialUseArtifact),
    #[serde(rename = "TARGET_EFFECT")]
    TargetEffect(TargetEffectArtifact),
    #[serde(rename = "POLICY_PROOF")]
    PolicyProof(PolicyProofArtifact),
    #[serde(rename = "TRANSITION_AUTHORIZATION")]
    TransitionAuthorization(TransitionAuthorizationArtifact),
    #[serde(rename = "IMMUTABLE_INSPECTION")]
    ImmutableInspection(ImmutableInspectionArtifact),
    #[serde(rename = "FINAL_ENVELOPE_VERIFICATION")]
    FinalEnvelopeVerification(FinalEnvelopeVerificationArtifact),
    #[serde(rename = "ATTESTATION")]
    Attestation(AttestationArtifact),
    #[serde(rename = "RECOVERY")]
    Recovery(RecoveryArtifact),
    #[serde(rename = "ARTIFACT_COMMIT")]
    ArtifactCommit(ArtifactCommitArtifact),
    #[serde(rename = "RELEASE_AUTHORIZATION")]
    ReleaseAuthorization(ReleaseAuthorizationArtifact),
    #[serde(rename = "RELEASE_CONSUMPTION_PREAUTHORIZATION")]
    ReleaseConsumptionPreauthorization(
        ReleaseConsumptionPreauthorizationArtifact,
    ),
    #[serde(rename = "CLEANUP_OBSERVATION")]
    CleanupObservation(CleanupObservationArtifact),
    #[serde(rename = "TRUSTED_TIME")]
    TrustedTime(TrustedTimeArtifact),
    #[serde(rename = "TRANSPARENCY_CHECKPOINT")]
    TransparencyCheckpoint(TransparencyCheckpointArtifact),
    #[serde(rename = "RECONCILIATION")]
    Reconciliation(ReconciliationArtifact),
    #[serde(rename = "PUBLICATION")]
    Publication(PublicationArtifact),
    #[serde(rename = "ARCHIVE")]
    Archive(ArchiveArtifact),
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityArtifactType {
    RoleReadiness,
    RouterTopologyAttestation,
    StateCas,
    ReleasePreparationReceipt,
    CredentialUse,
    TargetEffect,
    PolicyProof,
    TransitionAuthorization,
    ImmutableInspection,
    FinalEnvelopeVerification,
    Attestation,
    Recovery,
    ArtifactCommit,
    ReleaseAuthorization,
    ReleaseConsumptionPreauthorization,
    CleanupObservation,
    TrustedTime,
    TransparencyCheckpoint,
    Reconciliation,
    Publication,
    Archive,
}

impl AuthorityArtifactType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoleReadiness => "ROLE_READINESS",
            Self::RouterTopologyAttestation => {
                "ROUTER_TOPOLOGY_ATTESTATION"
            }
            Self::StateCas => "STATE_CAS",
            Self::ReleasePreparationReceipt => {
                "RELEASE_PREPARATION_RECEIPT"
            }
            Self::CredentialUse => "CREDENTIAL_USE",
            Self::TargetEffect => "TARGET_EFFECT",
            Self::PolicyProof => "POLICY_PROOF",
            Self::TransitionAuthorization => "TRANSITION_AUTHORIZATION",
            Self::ImmutableInspection => "IMMUTABLE_INSPECTION",
            Self::FinalEnvelopeVerification => {
                "FINAL_ENVELOPE_VERIFICATION"
            }
            Self::Attestation => "ATTESTATION",
            Self::Recovery => "RECOVERY",
            Self::ArtifactCommit => "ARTIFACT_COMMIT",
            Self::ReleaseAuthorization => "RELEASE_AUTHORIZATION",
            Self::ReleaseConsumptionPreauthorization => {
                "RELEASE_CONSUMPTION_PREAUTHORIZATION"
            }
            Self::CleanupObservation => "CLEANUP_OBSERVATION",
            Self::TrustedTime => "TRUSTED_TIME",
            Self::TransparencyCheckpoint => "TRANSPARENCY_CHECKPOINT",
            Self::Reconciliation => "RECONCILIATION",
            Self::Publication => "PUBLICATION",
            Self::Archive => "ARCHIVE",
        }
    }
}

impl NestedAuthorityPayload {
    pub const fn artifact_type(&self) -> AuthorityArtifactType {
        match self {
            Self::RoleReadiness(_) => AuthorityArtifactType::RoleReadiness,
            Self::RouterTopologyAttestation(_) => {
                AuthorityArtifactType::RouterTopologyAttestation
            }
            Self::StateCas(_) => AuthorityArtifactType::StateCas,
            Self::ReleasePreparationReceipt(_) => {
                AuthorityArtifactType::ReleasePreparationReceipt
            }
            Self::CredentialUse(_) => AuthorityArtifactType::CredentialUse,
            Self::TargetEffect(_) => AuthorityArtifactType::TargetEffect,
            Self::PolicyProof(_) => AuthorityArtifactType::PolicyProof,
            Self::TransitionAuthorization(_) => {
                AuthorityArtifactType::TransitionAuthorization
            }
            Self::ImmutableInspection(_) => {
                AuthorityArtifactType::ImmutableInspection
            }
            Self::FinalEnvelopeVerification(_) => {
                AuthorityArtifactType::FinalEnvelopeVerification
            }
            Self::Attestation(_) => AuthorityArtifactType::Attestation,
            Self::Recovery(_) => AuthorityArtifactType::Recovery,
            Self::ArtifactCommit(_) => AuthorityArtifactType::ArtifactCommit,
            Self::ReleaseAuthorization(_) => {
                AuthorityArtifactType::ReleaseAuthorization
            }
            Self::ReleaseConsumptionPreauthorization(_) => {
                AuthorityArtifactType::ReleaseConsumptionPreauthorization
            }
            Self::CleanupObservation(_) => {
                AuthorityArtifactType::CleanupObservation
            }
            Self::TrustedTime(_) => AuthorityArtifactType::TrustedTime,
            Self::TransparencyCheckpoint(_) => {
                AuthorityArtifactType::TransparencyCheckpoint
            }
            Self::Reconciliation(_) => AuthorityArtifactType::Reconciliation,
            Self::Publication(_) => AuthorityArtifactType::Publication,
            Self::Archive(_) => AuthorityArtifactType::Archive,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleReadinessArtifact {
    pub role: ServiceRole,
    pub role_id: Identifier,
    pub process_id: Identifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Identifier>,
    pub reconciled_generation_id: Identifier,
    pub reconciliation_checkpoint_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterTopologyAttestationArtifact {
    pub router_role_id: Identifier,
    pub router_process_id: Identifier,
    pub router_key_id: Identifier,
    pub reconciled_generation_id: Identifier,
    pub topology_sha256: Digest,
    pub readiness_contract_sha256: Digest,
    pub reconciliation_checkpoint_sha256: Digest,
    pub role_readiness_root_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateCasArtifact {
    pub expected_revision: u64,
    pub expected_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
    pub mutation_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationReceiptArtifact {
    pub release_authorization_id: Identifier,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub preauthorization_artifact_sha256: Digest,
    pub signed_state_mutation_receipt_sha256: Digest,
    pub predecessor_revision: u64,
    pub predecessor_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
    pub fence_token: Identifier,
    pub one_use_nonce_sha256: Digest,
    pub durable_canonical_result_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialUseArtifact {
    pub credential_use_id: Identifier,
    pub credential_binding_sha256: Digest,
    pub target_effect_id: Identifier,
    pub one_use_nonce_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetEffectArtifact {
    pub target_effect_id: Identifier,
    pub idempotency_key_sha256: Digest,
    pub request_object_sha256: Digest,
    pub response_object_sha256: Option<Digest>,
    pub outcome: TargetEffectState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyProofArtifact {
    pub policy_decision_id: Identifier,
    pub policy_generation_sha256: Digest,
    pub raw_response_object_sha256: Option<Digest>,
    pub response_framing_sha256: Option<Digest>,
    pub released_projection_sha256: Option<Digest>,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionAuthorizationArtifact {
    pub policy_decision_id: Identifier,
    pub policy_generation_sha256: Digest,
    pub expected_revision: u64,
    pub expected_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableInspectionArtifact {
    pub inspection_id: Identifier,
    pub inspection_operation_id: Identifier,
    pub object_id: Identifier,
    pub object_kind: Identifier,
    pub content_sha256: Digest,
    pub content_length: u64,
    pub media_type: String,
    pub immutable_storage_receipt_sha256: Digest,
    pub inspection_purpose_sha256: Digest,
    pub inspected_at_boot_id: Identifier,
    pub inspected_at_boot_millis: u64,
    pub bytes_immutable: bool,
    pub replacement_prohibited: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalEnvelopeVerificationArtifact {
    pub policy_decision_id: Identifier,
    pub policy_generation_sha256: Digest,
    pub final_envelope_body_sha256: Digest,
    pub raw_response_object_sha256: Digest,
    pub response_framing_sha256: Digest,
    pub released_projection_sha256: Digest,
    pub passed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationArtifact {
    pub attestation_mode: String,
    pub source_commit_sha256: Digest,
    pub source_tree_sha256: Digest,
    pub executable_sha256: Digest,
    pub configuration_sha256: Digest,
    pub evidence_object_sha256: Digest,
    pub hardware_proof: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryArtifact {
    pub recovery_action: Identifier,
    pub stable_resume_id: Identifier,
    pub predecessor_state: AttemptState,
    pub successor_state: AttemptState,
    pub deadline_boot_id: Identifier,
    pub deadline_boot_millis: u64,
    pub observed_boot_id: Identifier,
    pub observed_boot_millis: u64,
    pub cleanup_deadline_boot_id: Identifier,
    pub cleanup_deadline_boot_millis: u64,
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
    pub fence_token: Identifier,
    pub predecessor_fence_state: super::lifecycle::FenceState,
    pub successor_fence_state: super::lifecycle::FenceState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactCommitArtifact {
    pub object_id: Identifier,
    pub object_kind: Identifier,
    pub content_sha256: Digest,
    pub content_length: u64,
    pub immutable_storage_receipt_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorizationArtifact {
    pub release_authorization_id: Identifier,
    pub finalization_id: Identifier,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub inspection_artifact_sha256: Digest,
    pub inspection_seed_body_sha256: Digest,
    pub inspection_seed_root_sha256: Digest,
    pub release_object_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseConsumptionPreauthorizationArtifact {
    pub release_authorization_id: Identifier,
    pub finalization_id: Identifier,
    pub mutation_binding_sha256: Digest,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
    pub expected_revision: u64,
    pub expected_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupObservationArtifact {
    pub cleanup_action: Identifier,
    pub owner_process_id: Identifier,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: Identifier,
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
    pub predecessor_fence_state: super::lifecycle::FenceState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedTimeArtifact {
    pub clock_id: Identifier,
    pub epoch_millis: u64,
    pub sequence: u64,
    pub predecessor_sequence: u64,
}

pub type TransparencyCheckpointArtifact = ReleaseTransparencyArtifactV2;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciliationArtifact {
    pub reconciliation_job_id: Identifier,
    pub domain: Identifier,
    pub predecessor_state: ReconciliationState,
    pub successor_state: ReconciliationState,
    pub authoritative_cursor: u64,
    pub result_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationArtifact {
    pub publication_id: Identifier,
    pub outbox_id: Identifier,
    pub finalization_id: Identifier,
    pub payload_object_sha256: Digest,
    pub publication_state: super::lifecycle::OutboxState,
    pub delivery_receipt_sha256: Option<Digest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchiveArtifact {
    pub archive_id: Identifier,
    pub finalization_id: Identifier,
    pub canonical_archive_sha256: Digest,
    pub object_set_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableRawObject {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub reference: RawObjectReference,
    pub raw_content_base64url: String,
}

impl ImmutableRawObject {
    pub fn from_committed(
        reference: RawObjectReference,
        raw_content: &[u8],
    ) -> AuthorityResult<Self> {
        if raw_content.len() as u64 != reference.content_length
            || sha256_digest(raw_content) != reference.content_sha256
        {
            return Err(AuthorityError::Backend {
                code: "immutable_raw_object_integrity_failure",
                reason: "stored immutable bytes fail committed length or digest"
                    .to_owned(),
            });
        }
        Ok(Self {
            api_version: IMMUTABLE_RAW_OBJECT_API_VERSION.to_owned(),
            kind: IMMUTABLE_RAW_OBJECT_KIND.to_owned(),
            schema_version: "1".to_owned(),
            reference,
            raw_content_base64url: encode_base64url(raw_content),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub checkpoint_id: Identifier,
    pub tree_size: u64,
    pub root_sha256: Digest,
    pub predecessor_checkpoint_sha256: Option<Digest>,
    pub issued_at_epoch_millis: u64,
    pub signer_role_id: Identifier,
    pub authentication: FrameAuthentication,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultDisposition {
    Applied,
    OutcomeUnknown,
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationResultBody {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub exact_request_sha256: Digest,
    pub operation: OperationKind,
    pub attempt_id: Identifier,
    pub disposition: ResultDisposition,
    pub authoritative_revision: u64,
    pub authoritative_state: AttemptState,
    pub fence_token: Identifier,
    pub stable_resume_id: Identifier,
    pub result_artifact_ids: Vec<Identifier>,
    pub conflict_code: Option<Identifier>,
    pub immutable_inspection: Option<ImmutableInspectionResult>,
    pub retrieved_immutable_raw: Option<ImmutableRawObject>,
    pub response_data_result: Option<ResponseDataStateResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "resultType",
    content = "result",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum ResponseDataStateResult {
    ReleasePreparation(ReleasePreparationResult),
    ReleaseRetrieval(ReleaseRetrievalResult),
    ReplayResolution(ReplayResolutionResult),
    Settlement(SettlementResult),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationResult {
    pub durable_result: ReleasePreparationDurableResult,
    pub durable_canonical_result_sha256: Digest,
    pub release_preparation_receipt: SignedAuthorityArtifact,
    pub release_preparation_receipt_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationDurableResult {
    pub release_authorization_id: Identifier,
    pub finalization_id: Identifier,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
    pub preauthorization_artifact_id: Identifier,
    pub preauthorization_artifact_sha256: Digest,
    pub signed_state_mutation_receipt:
        SignedReleasePreparationMutationReceipt,
    pub signed_state_mutation_receipt_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationMutationReceiptBody {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub exact_request_sha256: Digest,
    pub attempt_id: Identifier,
    pub stable_resume_id: Identifier,
    pub release_authorization_id: Identifier,
    pub release_request_sha256: Digest,
    pub inspection_result_sha256: Digest,
    pub release_object_sha256: Digest,
    pub client_binding_sha256: Digest,
    pub exact_replay_key_sha256: Digest,
    pub preauthorization_artifact_sha256: Digest,
    pub one_use_nonce_sha256: Digest,
    pub predecessor_revision: u64,
    pub predecessor_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
    pub fence_token: Identifier,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePreparationMutationReceipt {
    pub body: ReleasePreparationMutationReceiptBody,
    pub authentication: FrameAuthentication,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseRetrievalResult {
    pub release_authorization_id: Identifier,
    pub exact_replay_key_sha256: Digest,
    pub prepared_canonical_result_sha256: Digest,
    pub signed_state_mutation_receipt_sha256: Digest,
    pub release_preparation_receipt_sha256: Digest,
    pub finalization_id: Identifier,
    pub final_envelope_sha256: Digest,
    pub final_envelope_verification_sha256: Digest,
    pub release_object_sha256: Digest,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayResolutionResult {
    pub source_replay_id: Identifier,
    pub source_operation_id: Identifier,
    pub source_exact_request_sha256: Digest,
    pub source_canonical_result_sha256: Digest,
    pub source_canonical_result_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementResult {
    pub terminal_code: Identifier,
    pub terminal_detail_sha256: Digest,
    pub predecessor_revision: u64,
    pub predecessor_state: AttemptState,
    pub successor_revision: u64,
    pub successor_state: AttemptState,
    pub target_effect_id: Option<Identifier>,
    pub target_effect_state: Option<TargetEffectState>,
    pub upstream_response_sha256: Option<Digest>,
    pub reconciliation_artifact_id: Identifier,
    pub reconciliation_artifact_sha256: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_artifact_id: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_artifact_sha256: Option<Digest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableInspectionResult {
    pub inspection_id: Identifier,
    pub inspection_operation_id: Identifier,
    pub object_reference: RawObjectReference,
    pub immutable_storage_receipt_sha256: Digest,
    pub inspection_purpose_sha256: Digest,
    pub inspected_at_boot_id: Identifier,
    pub inspected_at_boot_millis: u64,
    pub signed_inspection_artifact: SignedAuthorityArtifact,
    pub inspection_artifact_sha256: Digest,
    pub bytes_immutable: bool,
    pub replacement_prohibited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySignerIdentity {
    pub role_id: Identifier,
    pub process_id: Identifier,
    pub service_role: ServiceRole,
    pub logical_role: Identifier,
    pub key_id: Identifier,
    pub key_material_sha256: Digest,
    pub executable_sha256: Digest,
    pub configuration_sha256: Digest,
    pub allowed_operations: Vec<OperationKind>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedOperationResult {
    pub body: OperationResultBody,
    pub authentication: FrameAuthentication,
}

pub trait AuthorityResultSigner: Send + Sync {
    fn role_id(&self) -> &Identifier;
    fn key_id(&self) -> &Identifier;
    fn identity(&self) -> &AuthoritySignerIdentity;
    fn sign_digest(
        &self,
        digest: &[u8; 32],
        deadline: &BootDeadline,
    ) -> AuthorityResult<Vec<u8>>;
}

pub fn sign_authority_artifact(
    signer: &dyn AuthorityResultSigner,
    generation_id: &Identifier,
    artifact_id: Identifier,
    operation: OperationKind,
    operation_id: &Identifier,
    attempt_id: &Identifier,
    attempt_revision: u64,
    fence_token: &Identifier,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
    payload: NestedAuthorityPayload,
    deadline: &BootDeadline,
) -> AuthorityResult<SignedAuthorityArtifact> {
    let identity = signer.identity();
    if !identity.allowed_operations.contains(&operation) {
        return Err(AuthorityError::Authentication {
            code: "local_nested_artifact_operation_unassigned",
            reason: "local nested signer is not assigned the requested operation"
                .to_owned(),
        });
    }
    let mut authority_scope = AuthorityScope {
        generation_id: generation_id.clone(),
        process_id: identity.process_id.clone(),
        service_role: identity.service_role,
        logical_role: Some(identity.logical_role.clone()),
        role_id: identity.role_id.clone(),
        key_id: identity.key_id.clone(),
        key_material_sha256: identity.key_material_sha256.clone(),
        executable_sha256: identity.executable_sha256.clone(),
        configuration_sha256: identity.configuration_sha256.clone(),
        allowed_operations: identity.allowed_operations.clone(),
        scope_sha256: Digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
        ),
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct UnsignedScope<'a> {
        generation_id: &'a Identifier,
        process_id: &'a Identifier,
        service_role: ServiceRole,
        logical_role: &'a Option<Identifier>,
        role_id: &'a Identifier,
        key_id: &'a Identifier,
        key_material_sha256: &'a Digest,
        executable_sha256: &'a Digest,
        configuration_sha256: &'a Digest,
        allowed_operations: &'a [OperationKind],
    }
    let unsigned_scope = UnsignedScope {
        generation_id: &authority_scope.generation_id,
        process_id: &authority_scope.process_id,
        service_role: authority_scope.service_role,
        logical_role: &authority_scope.logical_role,
        role_id: &authority_scope.role_id,
        key_id: &authority_scope.key_id,
        key_material_sha256: &authority_scope.key_material_sha256,
        executable_sha256: &authority_scope.executable_sha256,
        configuration_sha256: &authority_scope.configuration_sha256,
        allowed_operations: &authority_scope.allowed_operations,
    };
    authority_scope.scope_sha256 =
        sha256_digest(&canonical_jcs_bytes(&unsigned_scope)?);
    let payload_sha256 = sha256_digest(&canonical_jcs_bytes(&payload)?);
    let artifact_class = payload.artifact_type();
    let body = AuthorityArtifactBody {
        api_version: NESTED_AUTHORITY_API_VERSION.to_owned(),
        kind: NESTED_AUTHORITY_KIND.to_owned(),
        schema_version: "1".to_owned(),
        generation_id: generation_id.clone(),
        artifact_id,
        producing_role_id: identity.role_id.clone(),
        producing_process_id: identity.process_id.clone(),
        producing_service_role: identity.service_role,
        producing_logical_role: Some(identity.logical_role.clone()),
        key_id: identity.key_id.clone(),
        key_material_sha256: identity.key_material_sha256.clone(),
        authority_scope_sha256: authority_scope.scope_sha256.clone(),
        authority_scope,
        artifact_class,
        operation,
        operation_id: operation_id.clone(),
        attempt_id: attempt_id.clone(),
        attempt_revision,
        fence_token: fence_token.clone(),
        issued_at_epoch_millis,
        expires_at_epoch_millis,
        payload_sha256,
        payload,
    };
    let canonical_body = canonical_jcs_bytes(&body)?;
    let signed_payload_sha256 = sha256_digest(&canonical_body);
    let message =
        signature_message(NESTED_AUTHORITY_SIGNATURE_DOMAIN, &canonical_body);
    let signature = signer.sign_digest(&message, deadline)?;
    if signature.len() != 64 {
        return Err(AuthorityError::Authentication {
            code: "invalid_nested_signer_output",
            reason: "Ed25519 signature must be 64 bytes".to_owned(),
        });
    }
    Ok(SignedAuthorityArtifact {
        authentication: NestedArtifactAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: identity.key_id.clone(),
            key_material_sha256: identity.key_material_sha256.clone(),
            authority_scope_sha256: body.authority_scope_sha256.clone(),
            signing_domain: NESTED_AUTHORITY_SIGNING_DOMAIN.to_owned(),
            signed_payload_sha256,
            signature_base64url: encode_base64url(&signature),
        },
        body,
    })
}

pub fn sign_operation_result(
    signer: &dyn AuthorityResultSigner,
    body: OperationResultBody,
    deadline: &BootDeadline,
) -> AuthorityResult<(SignedOperationResult, Vec<u8>)> {
    let canonical_body = canonical_jcs_bytes(&body)?;
    let body_sha256 = sha256_digest(&canonical_body);
    let message =
        signature_message(STATE_AUTHORITY_SIGNATURE_DOMAIN, &canonical_body);
    let signature = signer.sign_digest(&message, deadline)?;
    if signature.len() != 64 {
        return Err(AuthorityError::Authentication {
            code: "invalid_signer_output",
            reason: "Ed25519 signature must be 64 bytes".to_owned(),
        });
    }
    let signed = SignedOperationResult {
        body,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: signer.key_id().clone(),
            signed_payload_sha256: body_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    };
    let exact_bytes = canonical_jcs_bytes(&signed)?;
    Ok((signed, exact_bytes))
}

pub fn sign_release_preparation_mutation_receipt(
    signer: &dyn AuthorityResultSigner,
    body: ReleasePreparationMutationReceiptBody,
    deadline: &BootDeadline,
) -> AuthorityResult<SignedReleasePreparationMutationReceipt> {
    let canonical_body = canonical_jcs_bytes(&body)?;
    let body_sha256 = sha256_digest(&canonical_body);
    let message = signature_message(
        RELEASE_PREPARATION_MUTATION_RECEIPT_SIGNING_DOMAIN,
        &canonical_body,
    );
    let signature = signer.sign_digest(&message, deadline)?;
    if signature.len() != 64 {
        return Err(AuthorityError::Authentication {
            code: "invalid_release_preparation_receipt_signer_output",
            reason: "Ed25519 signature must be 64 bytes".to_owned(),
        });
    }
    Ok(SignedReleasePreparationMutationReceipt {
        body,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: signer.key_id().clone(),
            signed_payload_sha256: body_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    })
}

pub fn verify_release_preparation_mutation_receipt(
    receipt: &SignedReleasePreparationMutationReceipt,
    generation: &ProviderGeneration,
) -> AuthorityResult<Vec<u8>> {
    let identity = generation.role(ServiceRole::StateAuthority)?;
    verify_authenticated_value(
        &receipt.body,
        &receipt.authentication,
        identity,
        RELEASE_PREPARATION_MUTATION_RECEIPT_SIGNING_DOMAIN,
    )
}

pub fn verify_signed_operation_result(
    result: &SignedOperationResult,
    generation: &ProviderGeneration,
) -> AuthorityResult<Vec<u8>> {
    let identity = generation.role(ServiceRole::StateAuthority)?;
    verify_authenticated_value(
        &result.body,
        &result.authentication,
        identity,
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
    )
}

pub fn sign_generation_operation_result(
    signer: &dyn AuthorityResultSigner,
    body: GenerationOperationResultBody,
    deadline: &BootDeadline,
) -> AuthorityResult<(SignedGenerationOperationResult, Vec<u8>)> {
    let canonical_body = canonical_jcs_bytes(&body)?;
    let body_sha256 = sha256_digest(&canonical_body);
    let message =
        signature_message(STATE_AUTHORITY_SIGNATURE_DOMAIN, &canonical_body);
    let signature = signer.sign_digest(&message, deadline)?;
    if signature.len() != 64 {
        return Err(AuthorityError::Authentication {
            code: "invalid_signer_output",
            reason: "Ed25519 signature must be 64 bytes".to_owned(),
        });
    }
    let signed = SignedGenerationOperationResult {
        body,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: signer.key_id().clone(),
            signed_payload_sha256: body_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    };
    let exact_bytes = canonical_jcs_bytes(&signed)?;
    Ok((signed, exact_bytes))
}

pub fn verify_request_frame(
    frame: &RpcRequestFrame,
    generation: &ProviderGeneration,
    identity: &RoleIdentity,
) -> AuthorityResult<Vec<u8>> {
    frame.request.validate()?;
    if frame.request.generation_id != generation.generation_id
        || frame.request.caller_role_id != identity.role_id
    {
        return Err(AuthorityError::Authentication {
            code: "request_identity_mismatch",
            reason: "generation or role identity mismatch".to_owned(),
        });
    }
    let operation_id = Identifier(frame.request.operation.as_str().to_owned());
    if !identity.enabled_operations.contains(&operation_id) {
        return Err(AuthorityError::Authentication {
            code: "operation_not_authorized",
            reason: format!(
                "{} cannot perform {}",
                identity.role.as_str(),
                frame.request.operation.as_str()
            ),
        });
    }
    verify_authenticated_value(
        &frame.request,
        &frame.authentication,
        identity,
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
    )
}

pub fn verify_generation_request_frame(
    frame: &GenerationRpcRequestFrame,
    generation: &ProviderGeneration,
    identity: &RoleIdentity,
) -> AuthorityResult<Vec<u8>> {
    frame.request.validate()?;
    if frame.request.generation_id != generation.generation_id
        || frame.request.caller_role_id != identity.role_id
        || identity.role == ServiceRole::CustodyRouter
    {
        return Err(AuthorityError::Authentication {
            code: "generation_frame_identity_mismatch",
            reason: "generation request is not bound to its designated authority-role signer; custody-router may sign readiness artifacts but cannot execute generation RPCs"
                .to_owned(),
        });
    }
    let operation_id = Identifier(frame.request.operation.as_str().to_owned());
    if !identity.enabled_operations.contains(&operation_id) {
        return Err(AuthorityError::Authentication {
            code: "generation_operation_not_authorized",
            reason: format!(
                "{} cannot perform {}",
                identity.role.as_str(),
                frame.request.operation.as_str()
            ),
        });
    }
    verify_authenticated_value(
        &frame.request,
        &frame.authentication,
        identity,
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
    )
}

pub fn verify_authority_artifact(
    artifact: &SignedAuthorityArtifact,
    generation: &ProviderGeneration,
    expected_role: ServiceRole,
    expected_operation: OperationKind,
    expected_operation_id: &Identifier,
    expected_attempt_id: &Identifier,
    expected_attempt_revision: u64,
    expected_fence_token: &Identifier,
) -> AuthorityResult<Vec<u8>> {
    artifact.validate_contract()?;
    let body = &artifact.body;
    if body.api_version != NESTED_AUTHORITY_API_VERSION
        || body.kind != NESTED_AUTHORITY_KIND
        || body.schema_version != "1"
        || body.generation_id != generation.generation_id
        || body.operation != expected_operation
        || &body.operation_id != expected_operation_id
        || &body.attempt_id != expected_attempt_id
        || body.attempt_revision != expected_attempt_revision
        || &body.fence_token != expected_fence_token
        || body.issued_at_epoch_millis >= body.expires_at_epoch_millis
    {
        return Err(AuthorityError::Authentication {
            code: "nested_artifact_binding_mismatch",
            reason: "nested artifact version, generation, role operation, operation ID, attempt revision, fence, or validity does not match"
                .to_owned(),
        });
    }
    let identity = generation.role(expected_role)?;
    if body.producing_role_id != identity.role_id
        || body.producing_process_id != identity.process_id
        || body.producing_service_role != identity.role
        || body.authority_scope.generation_id != generation.generation_id
        || body.authority_scope.process_id != identity.process_id
        || body.authority_scope.service_role != identity.role
        || body.authority_scope.role_id != identity.role_id
        || body.authority_scope.logical_role != body.producing_logical_role
        || body.authority_scope.key_id != body.key_id
        || body.authority_scope.key_material_sha256
            != body.key_material_sha256
        || body.authority_scope.executable_sha256
            != identity.executable_sha256
        || body.authority_scope.configuration_sha256
            != identity.configuration_sha256
        || body.authority_scope_sha256 != body.authority_scope.scope_sha256
        || !body
            .authority_scope
            .allowed_operations
            .contains(&body.operation)
    {
        return Err(AuthorityError::Authentication {
            code: "nested_artifact_role_mismatch",
            reason: "nested artifact process, service role, scope, or operation was not assigned by the generation"
                .to_owned(),
        });
    }
    let (
        expected_key_id,
        expected_public_key,
        expected_public_key_sha256,
        expected_scope_sha256,
    ) = if let Some(logical_role) = &body.producing_logical_role {
        let binding = generation.logical_role(logical_role)?;
        let body_operations: BTreeSet<_> = body
            .authority_scope
            .allowed_operations
            .iter()
            .map(|operation| Identifier(operation.as_str().to_owned()))
            .collect();
        let assigned_operations: BTreeSet<_> =
            binding.enabled_operations.iter().cloned().collect();
        if binding.service_role != identity.role
            || binding.process_id != identity.process_id
            || binding.role_id != identity.role_id
            || binding.key_id != body.key_id
            || binding.public_key_sha256 != body.key_material_sha256
            || binding.authority_scope_sha256
                != body.authority_scope_sha256
            || body_operations != assigned_operations
        {
            return Err(AuthorityError::Authentication {
                code: "nested_artifact_logical_scope_mismatch",
                reason: "logical subkey, operation set, or authority scope differs from the authenticated generation"
                    .to_owned(),
            });
        }
        (
            &binding.key_id,
            &binding.public_key_base64url,
            &binding.public_key_sha256,
            &binding.authority_scope_sha256,
        )
    } else {
        let key_id = identity.key_id.as_ref().ok_or_else(|| {
            AuthorityError::Authentication {
                code: "nested_artifact_physical_key_missing",
                reason: "physical authority artifact has no assigned key"
                    .to_owned(),
            }
        })?;
        let public_key =
            identity.public_key_base64url.as_ref().ok_or_else(|| {
                AuthorityError::Authentication {
                    code: "nested_artifact_physical_public_key_missing",
                    reason: "physical authority artifact has no public key"
                        .to_owned(),
                }
            })?;
        let public_key_sha256 =
            identity.public_key_sha256.as_ref().ok_or_else(|| {
                AuthorityError::Authentication {
                    code: "nested_artifact_physical_key_digest_missing",
                    reason: "physical authority artifact has no key digest"
                        .to_owned(),
                }
            })?;
        (
            key_id,
            public_key,
            public_key_sha256,
            &body.authority_scope_sha256,
        )
    };
    verify_nested_authenticated_value(
        body,
        &artifact.authentication,
        expected_key_id,
        expected_public_key,
        expected_public_key_sha256,
        expected_scope_sha256,
    )
}

pub fn verify_signed_checkpoint(
    checkpoint: &SignedCheckpoint,
    generation: &ProviderGeneration,
) -> AuthorityResult<Vec<u8>> {
    if checkpoint.api_version != SIGNED_CHECKPOINT_API_VERSION
        || checkpoint.kind != SIGNED_CHECKPOINT_KIND
        || checkpoint.schema_version != "1"
        || checkpoint.generation_id != generation.generation_id
        || checkpoint.tree_size == 0
    {
        return Err(AuthorityError::Authentication {
            code: "checkpoint_binding_mismatch",
            reason: "checkpoint version, generation, or tree size is invalid"
                .to_owned(),
        });
    }
    let identity =
        generation.role(ServiceRole::ReleaseAttestorPublisher)?;
    if checkpoint.signer_role_id != identity.role_id {
        return Err(AuthorityError::Authentication {
            code: "checkpoint_signer_mismatch",
            reason: "checkpoint signer is not the assigned publisher"
                .to_owned(),
        });
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct UnsignedCheckpoint<'a> {
        api_version: &'a str,
        kind: &'a str,
        schema_version: &'a str,
        generation_id: &'a Identifier,
        checkpoint_id: &'a Identifier,
        tree_size: u64,
        root_sha256: &'a Digest,
        predecessor_checkpoint_sha256: &'a Option<Digest>,
        issued_at_epoch_millis: u64,
        signer_role_id: &'a Identifier,
    }
    let unsigned = UnsignedCheckpoint {
        api_version: &checkpoint.api_version,
        kind: &checkpoint.kind,
        schema_version: &checkpoint.schema_version,
        generation_id: &checkpoint.generation_id,
        checkpoint_id: &checkpoint.checkpoint_id,
        tree_size: checkpoint.tree_size,
        root_sha256: &checkpoint.root_sha256,
        predecessor_checkpoint_sha256:
            &checkpoint.predecessor_checkpoint_sha256,
        issued_at_epoch_millis: checkpoint.issued_at_epoch_millis,
        signer_role_id: &checkpoint.signer_role_id,
    };
    verify_authenticated_value(
        &unsigned,
        &checkpoint.authentication,
        identity,
        super::canonical::CHECKPOINT_SIGNATURE_DOMAIN,
    )
}

fn verify_authenticated_value<T: Serialize>(
    value: &T,
    authentication: &FrameAuthentication,
    identity: &RoleIdentity,
    domain: &[u8],
) -> AuthorityResult<Vec<u8>> {
    let key_id = identity.key_id.as_ref().ok_or_else(|| {
        AuthorityError::Authentication {
            code: "signer_role_has_no_key",
            reason: "authenticated state-authority frame signer has no installed key"
                .to_owned(),
        }
    })?;
    let public_key_base64url =
        identity.public_key_base64url.as_ref().ok_or_else(|| {
            AuthorityError::Authentication {
                code: "signer_role_has_no_public_key",
                reason: "authority role has no configured public key"
                    .to_owned(),
            }
        })?;
    let public_key_sha256 =
        identity.public_key_sha256.as_ref().ok_or_else(|| {
            AuthorityError::Authentication {
                code: "signer_role_has_no_public_key_digest",
                reason: "authority role has no configured public-key digest"
                    .to_owned(),
            }
        })?;
    if authentication.algorithm != SIGNATURE_ALGORITHM
        || &authentication.key_id != key_id
    {
        return Err(AuthorityError::Authentication {
            code: "signer_identity_mismatch",
            reason: "algorithm or key ID mismatch".to_owned(),
        });
    }
    let canonical = canonical_jcs_bytes(value)?;
    let digest = sha256_digest(&canonical);
    if digest != authentication.signed_payload_sha256 {
        return Err(AuthorityError::Authentication {
            code: "signed_payload_digest_mismatch",
            reason: "canonical payload digest mismatch".to_owned(),
        });
    }
    let public_key = decode_base64url(
        "roleIdentity.publicKeyBase64url",
        public_key_base64url,
    )?;
    let public_key: [u8; 32] =
        public_key.try_into().map_err(|_| {
            AuthorityError::Authentication {
                code: "invalid_public_key_length",
                reason: "Ed25519 public key must be 32 bytes".to_owned(),
            }
        })?;
    if &sha256_digest(&public_key) != public_key_sha256 {
        return Err(AuthorityError::Authentication {
            code: "public_key_digest_mismatch",
            reason: "role public key does not match its assigned digest"
                .to_owned(),
        });
    }
    let signature = decode_base64url(
        "authentication.signatureBase64url",
        &authentication.signature_base64url,
    )?;
    let signature = Signature::from_slice(&signature).map_err(|error| {
        AuthorityError::Authentication {
            code: "invalid_signature_encoding",
            reason: error.to_string(),
        }
    })?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|error| {
            AuthorityError::Authentication {
                code: "invalid_public_key",
                reason: error.to_string(),
            }
        })?;
    let message = signature_message(domain, &canonical);
    verifying_key
        .verify(&message, &signature)
        .map_err(|error| AuthorityError::Authentication {
            code: "signature_verification_failed",
            reason: error.to_string(),
        })?;
    Ok(canonical)
}

fn verify_nested_authenticated_value<T: Serialize>(
    value: &T,
    authentication: &NestedArtifactAuthentication,
    expected_key_id: &Identifier,
    public_key_base64url: &str,
    public_key_sha256: &Digest,
    authority_scope_sha256: &Digest,
) -> AuthorityResult<Vec<u8>> {
    if authentication.algorithm != SIGNATURE_ALGORITHM
        || &authentication.key_id != expected_key_id
        || &authentication.key_material_sha256 != public_key_sha256
        || &authentication.authority_scope_sha256
            != authority_scope_sha256
        || authentication.signing_domain != NESTED_AUTHORITY_SIGNING_DOMAIN
    {
        return Err(AuthorityError::Authentication {
            code: "nested_signer_identity_mismatch",
            reason: "nested artifact algorithm, key material, signing domain, or scope mismatch"
                .to_owned(),
        });
    }
    let canonical = canonical_jcs_bytes(value)?;
    let digest = sha256_digest(&canonical);
    if digest != authentication.signed_payload_sha256 {
        return Err(AuthorityError::Authentication {
            code: "nested_signed_payload_digest_mismatch",
            reason: "canonical nested payload digest mismatch".to_owned(),
        });
    }
    let public_key = decode_base64url(
        "logicalRoleBinding.publicKeyBase64url",
        public_key_base64url,
    )?;
    if sha256_digest(&public_key) != *public_key_sha256 {
        return Err(AuthorityError::Authentication {
            code: "nested_public_key_digest_mismatch",
            reason: "generation public key does not match its digest"
                .to_owned(),
        });
    }
    let public_key: [u8; 32] =
        public_key.try_into().map_err(|_| {
            AuthorityError::Authentication {
                code: "nested_invalid_public_key_length",
                reason: "Ed25519 public key must be 32 bytes".to_owned(),
            }
        })?;
    let signature = decode_base64url(
        "nestedAuthorityArtifact.authentication.signatureBase64url",
        &authentication.signature_base64url,
    )?;
    let signature: [u8; 64] =
        signature.try_into().map_err(|_| {
            AuthorityError::Authentication {
                code: "nested_invalid_signature_length",
                reason: "Ed25519 signature must be 64 bytes".to_owned(),
            }
        })?;
    let message =
        signature_message(NESTED_AUTHORITY_SIGNATURE_DOMAIN, &canonical);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| AuthorityError::Authentication {
            code: "nested_invalid_public_key",
            reason: error.to_string(),
        })?
        .verify(&message, &Signature::from_bytes(&signature))
        .map_err(|error| AuthorityError::Authentication {
            code: "nested_signature_verification_failed",
            reason: error.to_string(),
        })?;
    Ok(canonical)
}
