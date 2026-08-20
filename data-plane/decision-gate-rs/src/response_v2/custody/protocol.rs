use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::response_observation_v2_api::{
    ExactByteObjectDescriptor, V2CanonicalFinalEnvelopeV1, V2HelloResult,
    V2MonotonicDeadlineV1, V2OperationRequest, V2ReadBinding,
    V2ResponseDataControlResponse, V2ResponseDataOperation,
    V2ResponseDataRequest, V2ResponseDataResult,
};
use super::config::CustodyServiceRole;

pub(crate) const SERVICE_RPC_API_VERSION: &str =
    "serverware.responseObservationV2CustodyServiceRpc/v1";
pub(crate) const SERVICE_HANDSHAKE_API_VERSION: &str =
    "serverware.responseObservationV2CustodyServiceHandshake/v1";
pub(crate) const READINESS_RECORD_API_VERSION: &str =
    "serverware.responseObservationV2CustodyReadiness/v1";
pub(crate) const STATE_AUTHORITY_API_VERSION: &str =
    "serverware.responseObservationV2StateAuthority/v1";
pub(crate) const STATE_MUTATION_RECEIPT_API_VERSION: &str =
    "serverware.responseObservationV2StateMutationReceipt/v1";
pub(crate) const ATTEMPT_STATE_OBSERVATION_API_VERSION: &str =
    "serverware.responseObservationV2AttemptStateObservation/v1";
pub(crate) const TRANSITION_AUTHORIZATION_API_VERSION: &str =
    "serverware.responseObservationV2TransitionAuthorization/v1";
pub(crate) const FINAL_ENVELOPE_VERIFICATION_API_VERSION: &str =
    "serverware.responseObservationV2FinalEnvelopeVerification/v1";
pub(crate) const CANONICAL_FINAL_ENVELOPE_API_VERSION: &str =
    "serverware.responseObservationV2FinalEnvelope/v1";
pub const CANONICAL_AUTHORITY_ENVELOPE_API_VERSION: &str =
    "serverware.responseObservationV2FinalEnvelopeAuthority/v2";
pub const AUTHORITY_ARTIFACTS_ROOT_API_VERSION: &str =
    "serverware.responseObservationV2AuthorityArtifactsRoot/v2";
pub const FINAL_AUTHORITY_ARTIFACT_COUNT: usize = 10;
pub const AUTHORITY_PROOF_SEED_ARTIFACT_COUNT: usize = 9;
pub const PRE_RELEASE_AUTHORITY_ARTIFACT_COUNT: usize =
    FINAL_AUTHORITY_ARTIFACT_COUNT;
pub const CANONICAL_AUTHORITY_PROOF_SEED_API_VERSION: &str =
    "serverware.responseObservationV2CanonicalAuthorityProofSeed/v2";
pub(crate) const IMMUTABLE_RAW_INSPECTION_API_VERSION: &str =
    "serverware.responseObservationV2ImmutableRawInspection/v1";
pub(crate) const RELEASE_METADATA_API_VERSION: &str =
    "serverware.responseObservationV2ReleaseMetadata/v1";
pub(crate) const RELEASE_AUTHORIZATION_API_VERSION: &str =
    "serverware.responseObservationV2ReleaseAuthorization/v2";
pub(crate) const RELEASE_CONSUMPTION_API_VERSION: &str =
    "serverware.responseObservationV2ReleaseConsumption/v2";
pub(crate) const RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION: &str =
    "serverware.responseObservationV2ReleaseConsumptionPreauthorization/v1";
pub(crate) const RELEASE_PREPARATION_RECEIPT_API_VERSION: &str =
    "serverware.responseObservationV2ReleasePreparationReceipt/v1";
pub(crate) const CUSTODY_ATTESTATION_API_VERSION: &str =
    "serverware.responseObservationV2CustodyAttestation/v1";
pub(crate) const CUSTODY_RECOVERY_API_VERSION: &str =
    "serverware.responseObservationV2CustodyRecovery/v1";
pub(crate) const CUSTODY_ERROR_API_VERSION: &str =
    "serverware.responseObservationV2CustodyError/v1";
pub const PUBLIC_CUSTODY_API_VERSION: &str =
    crate::response_observation_v2_api::
        RESPONSE_OBSERVATION_V2_API_VERSION;
pub(crate) const PUBLICATION_API_VERSION: &str =
    "serverware.responseObservationV2Publication/v1";
pub(crate) const SETTLEMENT_API_VERSION: &str =
    "serverware.responseObservationV2Settlement/v1";
pub(crate) const SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION: &str =
    "serverware.responseObservationV2SettlementEvidenceContext/v1";
pub const AUTHORITY_SCOPE_API_VERSION: &str =
    "serverware.responseObservationV2ProviderAuthorityScope/v2";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServiceHelloV1 {
    pub api_version: String,
    pub request_id: String,
    pub expected_service_role: CustodyServiceRole,
    pub generation_id: String,
    pub generation: u64,
    pub topology_sha256: String,
    pub challenge_nonce: String,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServiceHelloResultV1 {
    pub api_version: String,
    pub request_id: String,
    pub challenge_nonce: String,
    pub handshake: Option<SignedServiceHandshakeV1>,
    pub dependency_handshakes:
        BTreeMap<CustodyServiceRole, SignedServiceHandshakeV1>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServiceRpcEnvelopeV1 {
    pub api_version: String,
    pub request_id: String,
    pub generation_id: String,
    pub generation: u64,
    pub deadline_boottime_ns: u64,
    pub operation: ServiceOperationV1,
    pub payload_sha256: String,
    pub payload: serde_json::Value,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceOperationV1 {
    Readiness,
    TransitionAuthorize,
    FinalEnvelopeVerify,
    StateCas,
    CommitReleaseMetadata,
    ReplayResolve,
    ConsumeReleaseAndRetrieveExact,
    FenceAllocate,
    FenceRevoke,
    QuiescenceObserve,
    ImmutablePut,
    InspectImmutableRaw,
    TargetDispatch,
    ExactResponseValidate,
    Attest,
    AuthorizeRelease,
    Publish,
    Recover,
    Reconcile,
    Cleanup,
}

impl ServiceOperationV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Readiness => "READINESS",
            Self::TransitionAuthorize => "TRANSITION_AUTHORIZE",
            Self::FinalEnvelopeVerify => "FINAL_ENVELOPE_VERIFY",
            Self::StateCas => "STATE_CAS",
            Self::CommitReleaseMetadata => "COMMIT_RELEASE_METADATA",
            Self::ReplayResolve => "REPLAY_RESOLVE",
            Self::ConsumeReleaseAndRetrieveExact => {
                "CONSUME_RELEASE_AND_RETRIEVE_EXACT"
            }
            Self::FenceAllocate => "FENCE_ALLOCATE",
            Self::FenceRevoke => "FENCE_REVOKE",
            Self::QuiescenceObserve => "QUIESCENCE_OBSERVE",
            Self::ImmutablePut => "IMMUTABLE_PUT",
            Self::InspectImmutableRaw => "INSPECT_IMMUTABLE_RAW",
            Self::TargetDispatch => "TARGET_DISPATCH",
            Self::ExactResponseValidate => "EXACT_RESPONSE_VALIDATE",
            Self::Attest => "ATTEST",
            Self::AuthorizeRelease => "AUTHORIZE_RELEASE",
            Self::Publish => "PUBLISH",
            Self::Recover => "RECOVER",
            Self::Reconcile => "RECONCILE",
            Self::Cleanup => "CLEANUP",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuthorityScopeV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub service_role: CustodyServiceRole,
    pub service_id: String,
    pub logical_role: String,
    pub role_identity_root_sha256: String,
    pub key_id: String,
    pub key_material_sha256: String,
    pub operation: ServiceOperationV1,
    pub operation_id: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub executable_sha256: String,
    pub configuration_sha256: String,
    pub allowed_operations: Vec<ServiceOperationV1>,
    pub operation_binding_sha256: String,
}

impl Default for ProviderAuthorityScopeV2 {
    fn default() -> Self {
        Self {
            api_version: String::new(),
            generation_id: String::new(),
            generation: 0,
            service_role: CustodyServiceRole::CustodyRouter,
            service_id: String::new(),
            logical_role: String::new(),
            role_identity_root_sha256: String::new(),
            key_id: String::new(),
            key_material_sha256: String::new(),
            operation: ServiceOperationV1::Readiness,
            operation_id: String::new(),
            attempt_id: String::new(),
            attempt_revision: 0,
            fencing_token: 0,
            executable_sha256: String::new(),
            configuration_sha256: String::new(),
            allowed_operations: Vec::new(),
            operation_binding_sha256: String::new(),
        }
    }
}

impl ProviderAuthorityScopeV2 {
    pub(crate) fn without_binding_digest(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.operation_binding_sha256.clear();
        unsigned
    }
}

// Compatibility names retained for the crate facade. They are aliases to the
// one authenticated-session contract, not a second public wire protocol.
pub type PublicLifecycleDeadlineV1 = V2MonotonicDeadlineV1;
pub type PublicHelloRequestV1 = V2OperationRequest;
pub type PublicHelloResultV1 = V2HelloResult;
pub type PublicCustodyOperationV1 = V2ResponseDataOperation;
pub type PublicRequestContextV1 = V2ReadBinding;
pub type PublicCustodyRequestV1 = V2ResponseDataRequest;
pub type PublicCustodyResultV1 = V2ResponseDataResult;
pub type PublicCustodyResponseV1 = V2ResponseDataControlResponse;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRpcResultV1 {
    pub api_version: String,
    pub request_id: String,
    pub generation_id: String,
    pub generation: u64,
    pub service_role: CustodyServiceRole,
    pub operation: ServiceOperationV1,
    pub succeeded: bool,
    pub result_sha256: String,
    pub result: serde_json::Value,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedServiceHandshakeV1 {
    pub api_version: String,
    pub request_id: String,
    pub challenge_nonce: String,
    pub service_role: CustodyServiceRole,
    pub service_id: String,
    pub generation_id: String,
    pub generation: u64,
    pub fault_domain_id: String,
    pub quorum_mode: String,
    pub fault_domain_count: u32,
    pub external_witness_count: u32,
    pub hardware_proof: bool,
    pub executable_sha256: String,
    pub configuration_sha256: String,
    pub logical_role_key_root_sha256: String,
    pub implemented_operations: Vec<ServiceOperationV1>,
    pub reconciliation_high_water: u64,
    pub reconciliation_state_sha256: String,
    pub ready_after_reconciliation: bool,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedServiceHandshakeV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CustodyReadinessRecordV1 {
    pub api_version: String,
    pub service_role: CustodyServiceRole,
    pub service_id: String,
    pub generation_id: String,
    pub generation: u64,
    pub topology_sha256: String,
    pub service_handshake: Option<SignedServiceHandshakeV1>,
    pub dependency_handshakes:
        BTreeMap<CustodyServiceRole, SignedServiceHandshakeV1>,
    pub reconciliation_complete: bool,
    pub reconciliation_high_water: u64,
    pub reconciliation_state_sha256: String,
    pub socket_identity_sha256: String,
    pub transaction_socket_identity_sha256: Option<String>,
    pub published_at_epoch_ms: u64,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleTransitionV1 {
    Reserve,
    Authority,
    Stage,
    Dispatch,
    TerminalCompleted,
    TerminalFailed,
    TerminalReleasePrepared,
    TerminalOutcomeUnknown,
    Finalize,
    Attest,
    Publish,
    Retrieve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TransitionAuthorizationRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub expected_revision: u64,
    pub expected_state: String,
    pub expected_state_sha256: String,
    pub fencing_token: u64,
    pub transition: LifecycleTransitionV1,
    pub transition_input_sha256: String,
    pub policy_decision_sha256: Option<String>,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTransitionAuthorizationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub authorized_revision: u64,
    pub predecessor_state_sha256: String,
    pub transition: LifecycleTransitionV1,
    pub transition_input_sha256: String,
    pub policy_decision_sha256: Option<String>,
    pub fencing_token: u64,
    pub authority_sequence: u64,
    pub canonical_result_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedStateMutationReceiptV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub exact_request_sha256: String,
    pub exact_result_sha256: String,
    pub disposition: String,
    pub authoritative_revision: u64,
    pub authoritative_state: String,
    pub fencing_token: u64,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedStateMutationReceiptV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AttemptStateQueryRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub expected_stable_resume_id: String,
    pub raw_response_object_id: Option<String>,
    pub include_proof_material: bool,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettlementEvidenceContextRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_observation: SignedAttemptStateObservationV1,
    pub terminal_code: String,
    pub expected_upstream_response_sha256: Option<String>,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedSettlementEvidenceContextV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub authoritative_state:
        super::super::state_authority::lifecycle::AttemptState,
    pub authoritative_state_sha256: String,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub fence_state:
        super::super::state_authority::lifecycle::FenceState,
    pub owner_process_id: String,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: String,
    pub deadline_boot_id: String,
    pub deadline_boot_millis: u64,
    pub observed_boot_id: String,
    pub observed_boot_millis: u64,
    pub cleanup_deadline_boot_id: String,
    pub cleanup_deadline_boot_millis: u64,
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
    pub target_effect_id: Option<String>,
    pub target_effect_state:
        Option<
            super::super::state_authority::lifecycle::
                TargetEffectState,
        >,
    pub upstream_response_sha256: Option<String>,
    pub terminal_code: String,
    pub terminal_detail_sha256: String,
    pub recovery_required: bool,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedSettlementEvidenceContextV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistedAuthorityProofMaterialV1 {
    pub staged_request_object:
        super::super::state_authority::rpc::RawObjectReference,
    pub raw_response_object:
        super::super::state_authority::rpc::RawObjectReference,
    pub raw_response_immutable_storage_receipt_sha256:
        super::super::state_authority::contract::Digest,
    pub raw_response_storage_locator: String,
    pub inspection_canonical_result_sha256:
        super::super::state_authority::contract::Digest,
    pub credential_use_id:
        super::super::state_authority::contract::Identifier,
    pub target_effect_id:
        super::super::state_authority::contract::Identifier,
    pub policy_decision_id:
        super::super::state_authority::contract::Identifier,
    pub authority_artifacts:
        Vec<super::super::state_authority::rpc::SignedAuthorityArtifact>,
    pub authority_artifacts_root_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAttemptStateObservationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub authoritative_state:
        super::super::state_authority::lifecycle::AttemptState,
    pub authoritative_state_sha256: String,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub owner_process_id: String,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub owner_cgroup_id: String,
    pub deadline_boot_id: String,
    pub deadline_boot_millis: u64,
    pub proof_material: Option<PersistedAuthorityProofMaterialV1>,
    pub observation_sha256: String,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReplaySourceObservationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub source_replay_id: String,
    pub source_operation_id: String,
    pub source_attempt_id: String,
    pub source_exact_request_sha256: String,
    pub source_canonical_result_sha256: String,
    pub source_canonical_result_base64url: String,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReplaySourceObservationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

impl SignedAttemptStateObservationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }

    pub(crate) fn without_observation_digest_and_signature(
        &self,
    ) -> Self {
        let mut unsigned = self.without_signature();
        unsigned.observation_sha256.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateMutationExecutionRequestV1 {
    pub api_version: String,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub deadline_boottime_ns: u64,
    pub frame:
        super::super::state_authority::rpc::RpcRequestFrame,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateMutationExecutionResultV1 {
    pub receipt: SignedStateMutationReceiptV1,
    pub response_data_result:
        Option<
            super::super::state_authority::rpc::
                ResponseDataStateResult,
        >,
    pub exact_object: Option<ExactByteObjectDescriptor>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsignedStateAuthorityIntentV1 {
    pub expected_state:
        super::super::state_authority::lifecycle::AttemptState,
    pub payload:
        super::super::state_authority::rpc::MutationPayload,
}

impl SignedTransitionAuthorizationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalFinalEnvelopeDescriptorV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub terminal_revision: u64,
    pub fencing_token: u64,
    pub transition_chain_root_sha256: String,
    pub raw_response_object_sha256: String,
    pub raw_response_byte_length: u64,
    pub framing_validation_sha256: String,
    pub parsed_response_sha256: String,
    pub exact_policy_decision_sha256: String,
    pub released_projection_sha256: String,
    pub release_authorization_sha256: String,
    pub evidence_root_sha256: String,
    pub final_envelope_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalAuthorityEnvelopeDescriptorV2 {
    pub api_version: String,
    pub finalization_id: String,
    pub public_envelope: V2CanonicalFinalEnvelopeV1,
    pub authority_envelope:
        super::super::state_authority::rpc::CanonicalFinalEnvelope,
    pub authority_artifacts_root_sha256: String,
    pub final_envelope_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalAuthorityEnvelopeProofInputV2 {
    pub api_version: String,
    pub finalization_id: String,
    /// The caller supplies all non-authority public fields, but both
    /// authorityArtifactsRootSha256 and finalEnvelopeSha256 must be empty.
    pub public_envelope: V2CanonicalFinalEnvelopeV1,
    /// The caller supplies the state-authority body inputs, but its artifact
    /// root is ignored and must be empty. The verifier computes the root and
    /// canonical body digest after verifying all ten signed artifacts.
    pub authority_body:
        super::super::state_authority::rpc::CanonicalFinalEnvelopeBody,
    pub authority_artifacts:
        Vec<super::super::state_authority::rpc::SignedAuthorityArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalAuthorityEnvelopeProofSeedV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub stable_resume_id: String,
    pub staged_request_object:
        super::super::state_authority::rpc::RawObjectReference,
    pub raw_response_object:
        super::super::state_authority::rpc::RawObjectReference,
    pub http11_framing:
        super::super::state_authority::rpc::Http11FramingResult,
    pub credential_use_id:
        super::super::state_authority::contract::Identifier,
    pub target_effect_id:
        super::super::state_authority::contract::Identifier,
    pub policy_decision_id:
        super::super::state_authority::contract::Identifier,
    pub inspection_receipt_sha256: String,
    pub authority_artifacts:
        Vec<super::super::state_authority::rpc::SignedAuthorityArtifact>,
    pub authority_artifacts_root_sha256: String,
    pub seed_sha256: String,
}

impl CanonicalAuthorityEnvelopeProofSeedV2 {
    fn without_seed_sha256(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.seed_sha256.clear();
        unsigned
    }

    pub fn recompute_seed_sha256(
        &self,
    ) -> Result<String, super::V2RuntimeError> {
        let canonical =
            super::super::state_authority::canonical::canonical_jcs_bytes(
                &self.without_seed_sha256(),
            )
            .map_err(|error| {
                super::V2RuntimeError::new(
                    "authority_proof_seed_invalid",
                    error.to_string(),
                )
            })?;
        Ok(
            super::super::state_authority::canonical::sha256_digest(
                &canonical,
            )
            .0,
        )
    }

    pub fn validate_integrity(
        &self,
    ) -> Result<(), super::V2RuntimeError> {
        use super::super::state_authority::contract::Digest;

        let expected_root =
            ordered_authority_proof_seed_artifacts_root_sha256(
            &self.authority_artifacts,
        )?;
        if self.api_version
                != CANONICAL_AUTHORITY_PROOF_SEED_API_VERSION
            || self.generation_id.is_empty()
            || self.generation == 0
            || self.attempt_id.is_empty()
            || self.attempt_revision == 0
            || self.fencing_token == 0
            || self.stable_resume_id.is_empty()
            || self.staged_request_object.generation_id.0
                != self.generation_id
            || self.raw_response_object.generation_id.0
                != self.generation_id
            || self.raw_response_object.content_length
                != self.http11_framing.physical_message_length
            || self.authority_artifacts_root_sha256 != expected_root
            || self.seed_sha256 != self.recompute_seed_sha256()?
        {
            return Err(super::V2RuntimeError::new(
                "authority_proof_seed_binding_invalid",
                "proof seed is not bound to one generation, attempt, revision, fence, raw response, ordered authority root, and canonical seed digest",
            ));
        }
        self.http11_framing.validate().map_err(|error| {
            super::V2RuntimeError::new(
                "authority_proof_seed_framing_invalid",
                error.to_string(),
            )
        })?;
        for (field, value) in [
            (
                "authorityProofSeed.stableResumeId",
                &self.stable_resume_id,
            ),
            (
                "authorityProofSeed.authorityArtifactsRootSha256",
                &self.authority_artifacts_root_sha256,
            ),
            (
                "authorityProofSeed.inspectionReceiptSha256",
                &self.inspection_receipt_sha256,
            ),
            (
                "authorityProofSeed.policyDecisionId",
                &self.policy_decision_id.0,
            ),
            ("authorityProofSeed.seedSha256", &self.seed_sha256),
        ] {
            Digest(value.clone()).validate(field).map_err(|error| {
                super::V2RuntimeError::new(
                    "authority_proof_seed_digest_invalid",
                    error.to_string(),
                )
            })?;
        }
        for artifact in &self.authority_artifacts {
            if artifact.body.generation_id.0 != self.generation_id
                || artifact.body.attempt_id.0 != self.attempt_id
                || artifact.body.fence_token.0
                    != self.fencing_token.to_string()
            {
                return Err(super::V2RuntimeError::new(
                    "authority_proof_seed_artifact_scope_invalid",
                    "every proof-seed artifact must bind the exact generation, attempt, and state-allocated fence",
                ));
            }
        }
        Ok(())
    }
}

pub fn build_canonical_authority_proof_input_from_seed(
    seed: &CanonicalAuthorityEnvelopeProofSeedV2,
    preparation: &SignedReleasePreparationReceiptV1,
    incomplete_public_envelope: V2CanonicalFinalEnvelopeV1,
) -> Result<CanonicalAuthorityEnvelopeProofInputV2, super::V2RuntimeError> {
    use super::super::state_authority::contract::{
        Digest, Identifier,
    };
    use super::super::state_authority::rpc::{
        CanonicalFinalEnvelopeBody, NestedAuthorityPayload,
    };

    seed.validate_integrity()?;
    preparation.validate_integrity()?;
    let policy = match &seed.authority_artifacts[2].body.payload {
        NestedAuthorityPayload::PolicyProof(policy) if policy.passed => {
            policy
        }
        _ => {
            return Err(super::V2RuntimeError::new(
                "authority_proof_seed_policy_artifact_invalid",
                "the third proof-seed artifact must be a passing policy proof",
            ))
        }
    };
    let transition =
        match &seed.authority_artifacts[3].body.payload {
            NestedAuthorityPayload::TransitionAuthorization(transition)
                if transition.passed =>
            {
                transition
            }
            _ => {
                return Err(super::V2RuntimeError::new(
                    "authority_proof_seed_transition_artifact_invalid",
                    "the fourth proof-seed artifact must be a passing transition authorization",
                ))
            }
        };
    let successor_revision = seed
        .attempt_revision
        .checked_add(1)
        .ok_or_else(|| {
            super::V2RuntimeError::new(
                "release_preparation_revision_overflow",
                "release preparation successor revision overflows u64",
            )
        })?;
    if incomplete_public_envelope.generation_id != seed.generation_id
        || incomplete_public_envelope.generation != seed.generation
        || incomplete_public_envelope.attempt_id != seed.attempt_id
        || incomplete_public_envelope.terminal_revision
            != successor_revision
        || incomplete_public_envelope.fencing_token
            != seed.fencing_token
        || incomplete_public_envelope.stable_resume_id
            != seed.stable_resume_id
        || incomplete_public_envelope.raw_response_object_sha256
            != seed.raw_response_object.content_sha256.0
        || incomplete_public_envelope.raw_response_byte_length
            != seed.raw_response_object.content_length
        || incomplete_public_envelope.framing_validation_sha256
            != seed.http11_framing.canonical_framing_sha256.0
        || incomplete_public_envelope.released_projection_sha256
            != policy
                .released_projection_sha256
                .as_ref()
                .map(|digest| digest.0.as_str())
                .unwrap_or_default()
        || incomplete_public_envelope.exact_policy_decision_sha256
            != seed.policy_decision_id.0
        || policy.policy_decision_id != seed.policy_decision_id
        || policy.raw_response_object_sha256.as_ref()
            != Some(&seed.raw_response_object.content_sha256)
        || policy.response_framing_sha256.as_ref()
            != Some(&seed.http11_framing.canonical_framing_sha256)
        || transition.policy_decision_id != seed.policy_decision_id
        || transition.policy_generation_sha256
            != policy.policy_generation_sha256
        || preparation.generation_id != seed.generation_id
        || preparation.generation != seed.generation
        || preparation.attempt_id != seed.attempt_id
        || preparation.stable_resume_id != seed.stable_resume_id
        || preparation.predecessor_revision
            != seed.attempt_revision
        || preparation.successor_revision != successor_revision
        || preparation.fencing_token != seed.fencing_token
        || preparation.release_object_sha256
            != seed.raw_response_object.content_sha256.0
        || preparation.inspection_receipt_sha256
            != seed.inspection_receipt_sha256
        || incomplete_public_envelope.release_authorization_sha256
            != preparation.release_authorization_sha256
        || incomplete_public_envelope
            .authority_artifacts_root_sha256
            .is_empty()
            == false
        || incomplete_public_envelope.final_envelope_sha256.is_empty()
            == false
    {
        return Err(super::V2RuntimeError::new(
            "authority_proof_seed_public_envelope_mismatch",
            "incomplete public envelope and release preparation are not bound to the proof seed's generation, state, raw response, framing, projection, policy, and release authorization",
        ));
    }
    for (field, value) in [
        (
            "publicEnvelope.transitionChainRootSha256",
            &incomplete_public_envelope.transition_chain_root_sha256,
        ),
        (
            "publicEnvelope.evidenceRootSha256",
            &incomplete_public_envelope.evidence_root_sha256,
        ),
        (
            "publicEnvelope.releasedProjectionSha256",
            &incomplete_public_envelope.released_projection_sha256,
        ),
        (
            "publicEnvelope.exactPolicyDecisionSha256",
            &incomplete_public_envelope.exact_policy_decision_sha256,
        ),
    ] {
        Digest(value.clone()).validate(field).map_err(|error| {
            super::V2RuntimeError::new(
                "authority_proof_seed_public_digest_invalid",
                error.to_string(),
            )
        })?;
    }
    let finalization_id = incomplete_public_envelope
        .finalization_id
        .clone();
    if finalization_id.is_empty() {
        return Err(super::V2RuntimeError::new(
            "authority_proof_seed_finalization_missing",
            "incomplete public envelope requires a deterministic finalization ID",
        ));
    }
    let mut authority_artifacts =
        Vec::with_capacity(FINAL_AUTHORITY_ARTIFACT_COUNT);
    authority_artifacts.push(
        preparation.release_preparation_artifact.clone(),
    );
    authority_artifacts.extend(seed.authority_artifacts.iter().cloned());
    ordered_authority_artifacts_root_sha256(&authority_artifacts)?;
    Ok(CanonicalAuthorityEnvelopeProofInputV2 {
        api_version:
            CANONICAL_AUTHORITY_ENVELOPE_API_VERSION.to_owned(),
        finalization_id: finalization_id.clone(),
        public_envelope: incomplete_public_envelope.clone(),
        authority_body: CanonicalFinalEnvelopeBody {
            generation_id: Identifier(seed.generation_id.clone()),
            attempt_id: Identifier(seed.attempt_id.clone()),
            attempt_revision: successor_revision,
            fence_token:
                Identifier(seed.fencing_token.to_string()),
            stable_resume_id:
                Identifier(seed.stable_resume_id.clone()),
            finalization_id: Identifier(finalization_id),
            staged_request_object:
                seed.staged_request_object.clone(),
            raw_response_object:
                seed.raw_response_object.clone(),
            http11_framing: seed.http11_framing.clone(),
            credential_use_id: seed.credential_use_id.clone(),
            target_effect_id: seed.target_effect_id.clone(),
            policy_decision_id: seed.policy_decision_id.clone(),
            released_projection_sha256: Digest(
                incomplete_public_envelope
                    .released_projection_sha256,
            ),
            transition_chain_sha256: Digest(
                incomplete_public_envelope
                    .transition_chain_root_sha256,
            ),
            evidence_root_sha256: Digest(
                incomplete_public_envelope.evidence_root_sha256,
            ),
            authority_artifacts_root_sha256:
                Digest(String::new()),
        },
        authority_artifacts,
    })
}

fn expected_authority_proof_seed_artifact_classes(
) -> [super::super::state_authority::rpc::AuthorityArtifactType;
    AUTHORITY_PROOF_SEED_ARTIFACT_COUNT] {
    use super::super::state_authority::rpc::AuthorityArtifactType;
    [
        AuthorityArtifactType::CredentialUse,
        AuthorityArtifactType::TargetEffect,
        AuthorityArtifactType::PolicyProof,
        AuthorityArtifactType::TransitionAuthorization,
        AuthorityArtifactType::ImmutableInspection,
        AuthorityArtifactType::Attestation,
        AuthorityArtifactType::ArtifactCommit,
        AuthorityArtifactType::TrustedTime,
        AuthorityArtifactType::TransparencyCheckpoint,
    ]
}

pub fn ordered_authority_proof_seed_artifacts_root_sha256(
    artifacts: &[super::super::state_authority::rpc::SignedAuthorityArtifact],
) -> Result<String, super::V2RuntimeError> {
    if artifacts.len() != AUTHORITY_PROOF_SEED_ARTIFACT_COUNT {
        return Err(super::V2RuntimeError::new(
            "authority_proof_seed_artifact_count_invalid",
            "canonical authority proof seed requires exactly nine ordered prerequisite authority artifacts",
        ));
    }
    let mut artifact_ids = std::collections::BTreeSet::new();
    for (index, (artifact, expected_class)) in artifacts
        .iter()
        .zip(expected_authority_proof_seed_artifact_classes())
        .enumerate()
    {
        let body = &artifact.body;
        if !artifact_ids.insert(body.artifact_id.0.as_str())
            || body.artifact_class != expected_class
            || body.payload.artifact_type() != expected_class
        {
            return Err(super::V2RuntimeError::new(
                "authority_proof_seed_artifact_order_invalid",
                format!(
                    "proof-seed artifact {index} must be a unique {} artifact",
                    expected_class.as_str(),
                ),
            ));
        }
    }
    canonical_artifact_array_sha256(artifacts)
}

pub fn ordered_authority_artifacts_root_sha256(
    artifacts: &[super::super::state_authority::rpc::SignedAuthorityArtifact],
) -> Result<String, super::V2RuntimeError> {
    if artifacts.len() != FINAL_AUTHORITY_ARTIFACT_COUNT {
        return Err(super::V2RuntimeError::new(
            "final_envelope_authority_artifact_count_invalid",
            "canonical final envelope requires the release-preparation receipt followed by exactly nine prerequisite authority artifacts",
        ));
    }
    let mut artifact_ids = std::collections::BTreeSet::new();
    let preparation = artifacts.first().ok_or_else(|| {
        super::V2RuntimeError::new(
            "final_envelope_release_preparation_missing",
            "canonical final envelope has no release-preparation receipt",
        )
    })?;
    if preparation.body.artifact_class
        != super::super::state_authority::rpc::
            AuthorityArtifactType::ReleasePreparationReceipt
        || preparation.body.payload.artifact_type()
            != super::super::state_authority::rpc::
                AuthorityArtifactType::ReleasePreparationReceipt
        || !artifact_ids.insert(
            preparation.body.artifact_id.0.as_str(),
        )
    {
        return Err(super::V2RuntimeError::new(
            "final_envelope_release_preparation_invalid",
            "final artifact slot 1 must be the unique dedicated RELEASE_PREPARATION_RECEIPT nested artifact",
        ));
    }
    for (index, (artifact, expected_class)) in artifacts[1..]
        .iter()
        .zip(expected_authority_proof_seed_artifact_classes())
        .enumerate()
    {
        let body = &artifact.body;
        if !artifact_ids.insert(body.artifact_id.0.as_str())
            || body.artifact_class != expected_class
            || body.payload.artifact_type() != expected_class
        {
            return Err(super::V2RuntimeError::new(
                "final_envelope_authority_artifact_order_invalid",
                format!(
                    "final-envelope artifact {} must be a unique {} artifact",
                    index + 2,
                    expected_class.as_str(),
                ),
            ));
        }
    }
    canonical_artifact_array_sha256(artifacts)
}

fn canonical_artifact_array_sha256(
    artifacts: &[super::super::state_authority::rpc::SignedAuthorityArtifact],
) -> Result<String, super::V2RuntimeError> {
    let canonical =
        super::super::state_authority::canonical::canonical_jcs_bytes(
            &artifacts,
        )
        .map_err(|error| {
            super::V2RuntimeError::new(
                "final_envelope_authority_artifacts_invalid",
                error.to_string(),
            )
        })?;
    Ok(
        super::super::state_authority::canonical::sha256_digest(
            &canonical,
        )
        .0,
    )
}

pub fn validate_canonical_authority_envelope(
    descriptor: &CanonicalAuthorityEnvelopeDescriptorV2,
) -> Result<(), super::V2RuntimeError> {
    let public = &descriptor.public_envelope;
    let authority = &descriptor.authority_envelope;
    authority.validate().map_err(|error| {
        super::V2RuntimeError::new(
            "final_envelope_authority_contract_invalid",
            error.to_string(),
        )
    })?;
    let root = ordered_authority_artifacts_root_sha256(
        &authority.authority_artifacts,
    )?;
    let fence = authority.body.fence_token.0.parse::<u64>().ok();
    if descriptor.api_version != CANONICAL_AUTHORITY_ENVELOPE_API_VERSION
        || descriptor.finalization_id.is_empty()
        || descriptor.finalization_id != public.finalization_id
        || descriptor.authority_artifacts_root_sha256 != root
        || public.authority_artifacts_root_sha256 != root
        || authority.body.generation_id.0 != public.generation_id
        || authority.body.attempt_id.0 != public.attempt_id
        || authority.body.attempt_revision != public.terminal_revision
        || authority.body.stable_resume_id.0 != public.stable_resume_id
        || fence != Some(public.fencing_token)
        || authority.body.raw_response_object.content_sha256.0
            != public.raw_response_object_sha256
        || authority.body.raw_response_object.content_length
            != public.raw_response_byte_length
        || authority.body.http11_framing.canonical_framing_sha256.0
            != public.framing_validation_sha256
        || authority.body.released_projection_sha256.0
            != public.released_projection_sha256
        || authority.body.transition_chain_sha256.0
            != public.transition_chain_root_sha256
        || authority.body.evidence_root_sha256.0
            != public.evidence_root_sha256
        || descriptor.final_envelope_sha256
            != public.final_envelope_sha256
    {
        return Err(super::V2RuntimeError::new(
            "final_envelope_authority_binding_mismatch",
            "public and state-authority final envelopes do not bind the same finalization, generation, attempt, fence, object, HTTP framing, released projection, transition root, evidence root, and ordered artifact root",
        ));
    }
    let expected =
        canonical_authority_envelope_preimage_sha256(descriptor)?;
    if descriptor.final_envelope_sha256 != expected {
        return Err(super::V2RuntimeError::new(
            "final_envelope_preimage_mismatch",
            "finalEnvelopeSha256 does not match the digest-cleared canonical authority-envelope preimage",
        ));
    }
    Ok(())
}

pub fn canonical_authority_envelope_preimage_sha256(
    envelope: &CanonicalAuthorityEnvelopeDescriptorV2,
) -> Result<String, super::V2RuntimeError> {
    let mut preimage = envelope.clone();
    preimage.final_envelope_sha256.clear();
    preimage.public_envelope.final_envelope_sha256.clear();
    canonical_sha256(&preimage)
}

pub fn released_projection_sha256_v2(
    raw_response_sha256: &str,
    raw_response_byte_length: u64,
    request_method: &str,
    response_status: u16,
    framing_validation_sha256: &str,
    parsed_response_sha256: &str,
    response_body_sha256: &str,
) -> Result<String, super::V2RuntimeError> {
    canonical_sha256(&serde_json::json!({
        "domain":
            "serverware.responseObservationV2ReleasedProjection/v2",
        "rawResponseSha256": raw_response_sha256,
        "rawResponseByteLength": raw_response_byte_length,
        "requestMethod": request_method,
        "responseStatus": response_status,
        "framingValidationSha256": framing_validation_sha256,
        "parsedResponseSha256": parsed_response_sha256,
        "responseBodySha256": response_body_sha256,
    }))
}

pub fn canonical_final_envelope_preimage_sha256(
    envelope: &CanonicalFinalEnvelopeDescriptorV1,
) -> Result<String, super::V2RuntimeError> {
    let mut preimage = envelope.clone();
    preimage.final_envelope_sha256.clear();
    let bytes = crate::canonical_json_bytes(&preimage).map_err(|_| {
        super::V2RuntimeError::new(
            "final_envelope_preimage_invalid",
            "canonical final-envelope preimage cannot be serialized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, super::V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(value).map_err(|_| {
        super::V2RuntimeError::new(
            "canonical_authority_envelope_invalid",
            "canonical authority-envelope value cannot be serialized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalEnvelopeVerificationRequestV1 {
    pub api_version: String,
    pub operation_id: String,
    pub envelope: CanonicalFinalEnvelopeDescriptorV1,
    pub inspection: SignedImmutableRawInspectionV1,
    pub canonical_envelope_bytes_sha256: String,
    pub transition_authorizations:
        Vec<SignedTransitionAuthorizationV1>,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedFinalEnvelopeVerificationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub final_envelope_sha256: String,
    pub authority_artifacts_root_sha256: String,
    pub canonical_envelope_bytes_sha256: String,
    pub transition_chain_root_sha256: String,
    pub raw_response_object_sha256: String,
    pub raw_response_byte_length: u64,
    pub framing_validation_sha256: String,
    pub parsed_response_sha256: String,
    pub released_projection_sha256: String,
    pub verified: bool,
    pub verification_sequence: u64,
    pub verification_result_sha256: String,
    pub final_envelope_verification_artifact:
        super::super::state_authority::rpc::SignedAuthorityArtifact,
    pub final_envelope_verification_artifact_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedFinalEnvelopeVerificationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitReleaseMetadataRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub raw_object_id: String,
    pub raw_object_sha256: String,
    pub raw_object_byte_length: u64,
    pub expected_attempt_revision: u64,
    pub fencing_token: u64,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseMetadataV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub raw_object_id: String,
    pub raw_object_sha256: String,
    pub raw_object_byte_length: u64,
    pub raw_target_bytes_unchanged: bool,
    pub metadata_is_separate_record: bool,
    pub metadata_commit_sequence: u64,
    pub object_commit_sequence: u64,
    pub committed_before_object: bool,
    pub metadata_record_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReleaseMetadataV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectImmutableRawRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub raw_object_id: String,
    pub raw_object_sha256: String,
    pub raw_object_byte_length: u64,
    pub request_method: String,
    pub inspection_purpose_sha256: String,
    pub state_authority_intent: UnsignedStateAuthorityIntentV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedImmutableRawInspectionV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub raw_object_id: String,
    pub raw_object_sha256: String,
    pub raw_object_byte_length: u64,
    pub exact_object: ExactByteObjectDescriptor,
    pub request_method: String,
    pub framing_validation_sha256: String,
    pub parsed_response_sha256: String,
    pub released_projection_sha256: String,
    pub final_status: u16,
    pub decoded_body_sha256: String,
    pub decoded_body_byte_length: u64,
    pub immutable: bool,
    pub consumed: bool,
    pub inspection_sequence: u64,
    pub inspection_receipt_sha256: String,
    pub state_observation: SignedAttemptStateObservationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_authority_receipt: Option<SignedStateMutationReceiptV1>,
    pub authority_proof_seed:
        CanonicalAuthorityEnvelopeProofSeedV2,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedImmutableRawInspectionV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorizationRequestV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub inspection: SignedImmutableRawInspectionV1,
    pub policy_decision_sha256: String,
    pub exact_replay_key_sha256: String,
    pub expires_at_epoch_ms: u64,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseAuthorizationV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub fencing_token: u64,
    pub authorization_id: String,
    pub finalization_id: String,
    pub exact_release_request_sha256: String,
    pub one_use_nonce_sha256: String,
    pub inspection_receipt_sha256: String,
    pub authority_proof_seed_sha256: String,
    pub authority_proof_seed_artifacts_root_sha256: String,
    pub raw_object_sha256: String,
    pub policy_decision_sha256: String,
    pub exact_replay_key_sha256: String,
    pub expires_at_epoch_ms: u64,
    pub authorization_result_sha256: String,
    pub release_authorization_artifact:
        super::super::state_authority::rpc::SignedAuthorityArtifact,
    pub release_authorization_artifact_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReleaseAuthorizationV2 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseConsumptionPhaseV1 {
    Prepare,
    Retrieve,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreparationMutationBindingV1 {
    pub expected_revision: u64,
    pub expected_state: String,
    pub successor_revision: u64,
    pub successor_state: String,
    pub release_authorization_id: String,
    pub exact_release_request_sha256: String,
    pub inspection_receipt_sha256: String,
    pub release_object_sha256: String,
    pub client_binding_sha256: String,
    pub exact_replay_key_sha256: String,
    pub one_use_nonce_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReleaseConsumptionPreauthorizationArtifactRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub finalization_id: String,
    pub one_use_nonce_sha256: String,
    pub release_object:
        super::super::state_authority::rpc::RawObjectReference,
    pub mutation_binding: ReleasePreparationMutationBindingV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareExactReleaseRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub expected_authority_revision: u64,
    pub fencing_token: u64,
    pub exact_replay_key_sha256: String,
    pub inspection: SignedImmutableRawInspectionV1,
    pub release_authorization: SignedReleaseAuthorizationV2,
    pub client_binding_sha256: String,
    pub mutation_binding: ReleasePreparationMutationBindingV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrievePreparedExactReleaseRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub exact_replay_key_sha256: String,
    pub inspection: SignedImmutableRawInspectionV1,
    pub release_authorization: SignedReleaseAuthorizationV2,
    pub prepared_consumption: SignedReleasePreparationReceiptV1,
    pub final_envelope_verification:
        SignedFinalEnvelopeVerificationV1,
    pub client_binding_sha256: String,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "phase",
    content = "request",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ConsumeReleaseAndRetrieveExactRequestV1 {
    Prepare(PrepareExactReleaseRequestV1),
    Retrieve(RetrievePreparedExactReleaseRequestV1),
}

impl ConsumeReleaseAndRetrieveExactRequestV1 {
    pub fn phase(&self) -> ReleaseConsumptionPhaseV1 {
        match self {
            Self::Prepare(_) => ReleaseConsumptionPhaseV1::Prepare,
            Self::Retrieve(_) => ReleaseConsumptionPhaseV1::Retrieve,
        }
    }

    pub(crate) fn request_id(&self) -> &str {
        match self {
            Self::Prepare(request) => &request.request_id,
            Self::Retrieve(request) => &request.request_id,
        }
    }

    pub(crate) fn request_sha256(&self) -> &str {
        match self {
            Self::Prepare(request) => &request.request_sha256,
            Self::Retrieve(request) => &request.request_sha256,
        }
    }

    pub(crate) fn attempt_id(&self) -> &str {
        match self {
            Self::Prepare(request) => &request.attempt_id,
            Self::Retrieve(request) => &request.attempt_id,
        }
    }

    pub(crate) fn stable_resume_id(&self) -> &str {
        match self {
            Self::Prepare(request) => &request.stable_resume_id,
            Self::Retrieve(request) => &request.stable_resume_id,
        }
    }

    pub(crate) fn fencing_token(&self) -> u64 {
        match self {
            Self::Prepare(request) => request.fencing_token,
            Self::Retrieve(request) => request.fencing_token,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseConsumptionPreauthorizationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub fencing_token: u64,
    pub mutation_binding: ReleasePreparationMutationBindingV1,
    pub mutation_binding_sha256: String,
    pub preauthorization_artifact:
        super::super::state_authority::rpc::SignedAuthorityArtifact,
    pub preauthorization_artifact_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReleaseConsumptionPreauthorizationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePreparationReceiptV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub fencing_token: u64,
    pub release_authorization_id: String,
    pub release_authorization_sha256: String,
    pub exact_release_request_sha256: String,
    pub inspection_receipt_sha256: String,
    pub release_object_sha256: String,
    pub client_binding_sha256: String,
    pub exact_replay_key_sha256: String,
    pub preauthorization_artifact_sha256: String,
    pub state_mutation_receipt_sha256: String,
    pub predecessor_revision: u64,
    pub predecessor_state: String,
    pub successor_revision: u64,
    pub successor_state: String,
    pub one_use_nonce_sha256: String,
    pub durable_canonical_result_sha256: String,
    pub preauthorization:
        SignedReleaseConsumptionPreauthorizationV1,
    pub state_authority_receipt: SignedStateMutationReceiptV1,
    pub release_preparation_mutation_receipt:
        super::super::state_authority::rpc::
            SignedReleasePreparationMutationReceipt,
    pub release_preparation_artifact:
        super::super::state_authority::rpc::SignedAuthorityArtifact,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReleasePreparationReceiptV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }

    pub fn validate_integrity(
        &self,
    ) -> Result<(), super::V2RuntimeError> {
        use super::super::state_authority::contract::Digest;

        let successor = self
            .predecessor_revision
            .checked_add(1)
            .ok_or_else(|| {
                super::V2RuntimeError::new(
                    "release_preparation_revision_overflow",
                    "release preparation predecessor revision overflows u64",
                )
            })?;
        if self.api_version
                != RELEASE_PREPARATION_RECEIPT_API_VERSION
            || self.operation
                != ServiceOperationV1::ConsumeReleaseAndRetrieveExact
            || self.generation_id.is_empty()
            || self.generation == 0
            || self.attempt_id.is_empty()
            || self.stable_resume_id.is_empty()
            || self.fencing_token == 0
            || self.predecessor_revision == 0
            || self.successor_revision != successor
            || self.predecessor_state != "OBSERVED"
            || self.successor_state != "RELEASE_PREPARED"
            || self.state_authority_receipt.authoritative_revision
                != self.successor_revision
            || self.state_authority_receipt.authoritative_state
                != self.successor_state
            || self.state_authority_receipt.fencing_token
                != self.fencing_token
            || self.state_authority_receipt.attempt_id
                != self.attempt_id
            || self.state_authority_receipt.stable_resume_id
                != self.stable_resume_id
            || self.preauthorization.generation_id
                != self.generation_id
            || self.preauthorization.generation != self.generation
            || self.preauthorization.attempt_id != self.attempt_id
            || self.preauthorization.stable_resume_id
                != self.stable_resume_id
            || self.preauthorization.fencing_token
                != self.fencing_token
            || self.preauthorization.mutation_binding
                .expected_revision
                != self.predecessor_revision
            || self.preauthorization.mutation_binding
                .successor_revision
                != self.successor_revision
            || self.preauthorization.mutation_binding
                .expected_state
                != self.predecessor_state
            || self.preauthorization.mutation_binding
                .successor_state
                != self.successor_state
        {
            return Err(super::V2RuntimeError::new(
                "release_preparation_binding_invalid",
                "release preparation is not one signed preauthorization followed by one exact state CAS into RELEASE_PREPARED",
            ));
        }
        for (field, value) in [
            (
                "releasePreparation.releaseAuthorizationSha256",
                &self.release_authorization_sha256,
            ),
            (
                "releasePreparation.exactReleaseRequestSha256",
                &self.exact_release_request_sha256,
            ),
            (
                "releasePreparation.inspectionReceiptSha256",
                &self.inspection_receipt_sha256,
            ),
            (
                "releasePreparation.releaseObjectSha256",
                &self.release_object_sha256,
            ),
            (
                "releasePreparation.clientBindingSha256",
                &self.client_binding_sha256,
            ),
            (
                "releasePreparation.exactReplayKeySha256",
                &self.exact_replay_key_sha256,
            ),
            (
                "releasePreparation.preauthorizationArtifactSha256",
                &self.preauthorization_artifact_sha256,
            ),
            (
                "releasePreparation.stateMutationReceiptSha256",
                &self.state_mutation_receipt_sha256,
            ),
            (
                "releasePreparation.oneUseNonceSha256",
                &self.one_use_nonce_sha256,
            ),
            (
                "releasePreparation.durableCanonicalResultSha256",
                &self.durable_canonical_result_sha256,
            ),
        ] {
            Digest(value.clone()).validate(field).map_err(|error| {
                super::V2RuntimeError::new(
                    "release_preparation_digest_invalid",
                    error.to_string(),
                )
            })?;
        }
        if canonical_sha256(
            &self.release_preparation_mutation_receipt,
        )? != self.state_mutation_receipt_sha256
        {
            return Err(super::V2RuntimeError::new(
                "release_preparation_mutation_receipt_mismatch",
                "release preparation mutation receipt digest does not match the exact state-authority receipt",
            ));
        }
        let payload = match &self
            .release_preparation_artifact
            .body
            .payload
        {
            super::super::state_authority::rpc::
                NestedAuthorityPayload::ReleasePreparationReceipt(
                    payload,
                ) => payload,
            _ => {
                return Err(super::V2RuntimeError::new(
                    "release_preparation_artifact_invalid",
                    "release preparation does not carry the dedicated nested artifact payload",
                ))
            }
        };
        if payload.release_authorization_id.0
                != self.release_authorization_id
            || payload.release_request_sha256.0
                != self.exact_release_request_sha256
            || payload.inspection_result_sha256.0
                != self.inspection_receipt_sha256
            || payload.release_object_sha256.0
                != self.release_object_sha256
            || payload.client_binding_sha256.0
                != self.client_binding_sha256
            || payload.exact_replay_key_sha256.0 != self.exact_replay_key_sha256
            || payload.preauthorization_artifact_sha256.0
                != self.preauthorization_artifact_sha256
            || payload.signed_state_mutation_receipt_sha256.0
                != self.state_mutation_receipt_sha256
            || payload.predecessor_revision
                != self.predecessor_revision
            || payload.predecessor_state.as_str()
                != self.predecessor_state
            || payload.successor_revision != self.successor_revision
            || payload.successor_state.as_str()
                != self.successor_state
            || payload.fence_token.0 != self.fencing_token.to_string()
            || payload.one_use_nonce_sha256.0
                != self.one_use_nonce_sha256
            || payload.durable_canonical_result_sha256.0
                != self.durable_canonical_result_sha256
            || self.release_preparation_artifact
                .body
                .generation_id
                .0
                != self.generation_id
            || self.release_preparation_artifact.body.attempt_id.0
                != self.attempt_id
            || self.release_preparation_artifact.body.attempt_revision
                != self.successor_revision
            || self.release_preparation_artifact.body.fence_token.0
                != self.fencing_token.to_string()
        {
            return Err(super::V2RuntimeError::new(
                "release_preparation_artifact_binding_mismatch",
                "dedicated release-preparation artifact does not match the exact post-CAS receipt bindings",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "phase",
    content = "receipt",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ReleaseConsumptionResultV2 {
    Prepare(SignedReleasePreparationReceiptV1),
    Retrieve(SignedReleaseConsumptionV2),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseConsumptionV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub fencing_token: u64,
    pub authorization_id: String,
    pub inspection_receipt_sha256: String,
    pub final_envelope_verification_sha256: String,
    pub release_preparation_receipt_sha256: String,
    pub exact_replay_key_sha256: String,
    pub raw_object_sha256: String,
    pub raw_object_byte_length: u64,
    pub exact_object: ExactByteObjectDescriptor,
    pub authority_revision: u64,
    pub consumption_sequence: u64,
    pub consumption_receipt_sha256: String,
    pub canonical_result_sha256: String,
    pub prepared_consumption: SignedReleasePreparationReceiptV1,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedReleaseConsumptionV2 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyAttestationRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub final_envelope_verification:
        SignedFinalEnvelopeVerificationV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCustodyAttestationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub final_envelope_sha256: String,
    pub attestation_evidence_sha256: String,
    pub attestation_sequence: u64,
    pub attestation_result_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedCustodyAttestationV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyRecoveryRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub expected_terminal_state_sha256: String,
    pub reconciliation_cursor: u64,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCustodyRecoveryV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub recovered_terminal_state_sha256: String,
    pub recovered_result_sha256: String,
    pub reconciliation_high_water: u64,
    pub recovery_sequence: u64,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedCustodyRecoveryV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCustodyErrorV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub error_code: String,
    pub retryable: bool,
    pub deadline_expired: bool,
    pub durable_terminalized: bool,
    pub terminal_state: String,
    pub terminal_state_sha256: String,
    pub reconciliation_id: String,
    pub reconciliation_record_sha256: String,
    pub authority_sequence: u64,
    pub canonical_error_sha256: String,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedCustodyErrorV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub final_envelope_verification:
        SignedFinalEnvelopeVerificationV1,
    pub publication_id: String,
    pub outbox_id: String,
    pub finalization_id: String,
    pub payload_object_id: String,
    pub payload_object_sha256: String,
    pub payload_object_byte_length: u64,
    pub publisher_authorization_sha256: String,
    pub state_authority_intent: UnsignedStateAuthorityIntentV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPublicationReceiptV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub publication_id: String,
    pub outbox_id: String,
    pub finalization_id: String,
    pub payload_object_sha256: String,
    pub publication_sequence: u64,
    pub durable_publication_receipt_sha256: String,
    pub state_authority_receipt: SignedStateMutationReceiptV1,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedPublicationReceiptV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementRequestV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub expected_terminal_state_sha256: String,
    pub settlement_input_sha256: String,
    pub state_authority_intent: UnsignedStateAuthorityIntentV1,
    pub deadline_boottime_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedDurableTerminalReceiptV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: ServiceOperationV1,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    #[serde(default)]
    pub authority_scope: ProviderAuthorityScopeV2,
    pub terminal_state: String,
    pub terminal_state_sha256: String,
    pub durable: bool,
    pub reconciled: bool,
    pub authority_sequence: u64,
    pub settlement_receipt_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_artifact:
        Option<super::super::state_authority::rpc::SignedAuthorityArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_artifact_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_artifact:
        Option<super::super::state_authority::rpc::SignedAuthorityArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_artifact_sha256: Option<String>,
    pub state_authority_receipt: SignedStateMutationReceiptV1,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedDurableTerminalReceiptV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

impl ServiceRpcResultV1 {
    pub(crate) fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

pub fn stable_resume_id_sha256(
    generation_id: &str,
    generation: u64,
    request_sha256: &str,
    attempt_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    let generation_bytes = generation.to_be_bytes();
    for value in [
        b"serverware.response-v2/stable-resume/v1".as_slice(),
        generation_id.as_bytes(),
        generation_bytes.as_slice(),
        request_sha256.as_bytes(),
        attempt_id.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("sha256:{:x}", hasher.finalize())
}
