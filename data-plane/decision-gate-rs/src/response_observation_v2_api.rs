//! Closed control-plane DTOs for the response-observation v2 custody runtime.
//!
//! Bulk operation bytes never appear in these messages. They are transferred
//! as sealed memfd file descriptors and bound here by index, exact byte
//! length, and SHA-256 digest. The sole bounded inline binary field is fresh
//! public TEE evidence needed to verify the response without private access.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RESPONSE_OBSERVATION_V2_API_VERSION: &str =
    "serverware.responseObservationCustody/v2";
pub const RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES: usize = 256 * 1024;
pub const RESPONSE_OBSERVATION_V2_MAX_ATTESTATION_EVIDENCE_BYTES: usize =
    128 * 1024;
pub const RESPONSE_OBSERVATION_V2_MAX_OBJECTS: usize = 16;
pub const RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
pub const RESPONSE_OBSERVATION_V2_MAX_OPERATION_MS: u64 = 30_000;

pub const V2_HELLO_OPERATION: &str = "responseObservationV2.hello/v1";
pub const V2_RESERVE_OPERATION: &str = "responseObservationV2.reserve/v1";
pub const V2_AUTHORITY_OPERATION: &str = "responseObservationV2.authority/v1";
pub const V2_STAGE_OPERATION: &str = "responseObservationV2.stage/v1";
pub const V2_DISPATCH_OPERATION: &str = "responseObservationV2.dispatch/v1";
pub const V2_TERMINAL_OPERATION: &str = "responseObservationV2.terminal/v1";
pub const V2_FINALIZE_OPERATION: &str = "responseObservationV2.finalize/v1";
pub const V2_ATTEST_OPERATION: &str = "responseObservationV2.attest/v1";
pub const V2_PUBLISH_OPERATION: &str = "responseObservationV2.publish/v1";
pub const V2_RETRIEVE_OPERATION: &str = "responseObservationV2.retrieve/v1";
pub const V2_RECOVER_OPERATION: &str = "responseObservationV2.recover/v1";
pub const V2_VERIFY_ARCHIVE_OPERATION: &str =
    "responseObservationV2.verifyArchive/v1";
pub const V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION: &str =
    "responseObservationV2.inspectImmutableResponse/v1";
pub const V2_APPEND_RELEASE_TRANSPARENCY_OPERATION: &str =
    "responseObservationV2.appendReleaseTransparency/v1";
pub const V2_VALIDATE_FINAL_ENVELOPE_OPERATION: &str =
    "responseObservationV2.validateFinalEnvelope/v1";
pub const V2_AUTHORIZE_EXACT_RELEASE_OPERATION: &str =
    "responseObservationV2.authorizeExactRelease/v1";
pub const V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION: &str =
    "responseObservationV2.consumeAndRetrieveExact/v1";
pub const V2_RESOLVE_EXACT_REPLAY_OPERATION: &str =
    "responseObservationV2.resolveExactReplay/v1";
pub const V2_SETTLE_ATTEMPT_OPERATION: &str =
    "responseObservationV2.settleAttempt/v1";
pub const V2_DURABLE_REPLAY_RECORD_VERSION: &str =
    "serverware.responseObservationDurableReplay/v1";
pub const V2_CROSS_BOOT_RECOVERY_AUTHORIZATION_VERSION: &str =
    "serverware.responseObservationRecoveryAuthorization/v1";
pub const V2_CROSS_BOOT_RECOVERY_OUTCOME_VERSION: &str =
    "serverware.responseObservationRecoveryOutcome/v1";
pub const V2_RELEASE_AUTHORIZATION_CONSUME_OUTCOME_VERSION: &str =
    "serverware.publicReleaseAuthorizationConsumeOutcome/v1";
pub const V2_RELEASE_REQUEST_COMMITMENT_VERSION: &str =
    "serverware.publicReleaseRequestCommitment/v1";
pub const V2_FRESH_RESPONSE_ATTESTATION_VERSION: &str =
    "serverware.responseObservationFreshResponseAttestation/v1";
pub const V2_FRESH_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/fresh-hardware-proof/v1\0";
pub const V2_MONOTONIC_DEADLINE_VERSION: &str =
    "serverware.responseObservationMonotonicDeadline/v1";
pub const V2_RETRIEVAL_EVIDENCE_BINDING_VERSION: &str =
    "serverware.responseObservationRetrievalEvidenceBinding/v1";
pub const V2_CANONICAL_FINAL_ENVELOPE_VERSION: &str =
    "serverware.responseObservationV2FinalEnvelope/v1";
pub const V2_DURABLE_REPLAY_RECORD_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/durable-replay-record/v1\0";
pub const V2_RECOVERY_OUTCOME_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/recovery-resolution/v1\0";
pub const V2_OUTCOME_UNKNOWN_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.outcome-unknown/v1\0";
pub const V2_PUBLIC_RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.public-release-authorization/v1\0";
pub const V2_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.public-release-consume-outcome/v1\0";
pub const V2_IMMUTABLE_RESPONSE_INSPECTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/immutable-response-inspection/v1\0";
pub const V2_FINAL_ENVELOPE_VERIFICATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/final-envelope-verification/v1\0";
pub const V2_EXACT_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/exact-release-consumption/v2\0";
pub const V2_EXACT_RELEASE_PREPARATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/exact-release-preparation/v1\0";
pub const V2_EXACT_REPLAY_RESOLUTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/exact-replay-resolution/v1\0";
pub const V2_DURABLE_SETTLEMENT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/durable-settlement/v1\0";
pub const V2_DURABLE_SETTLEMENT_VERSION: &str =
    "serverware.responseObservationDurableSettlement/v1";
pub const V2_EXACT_REPLAY_RESOLUTION_VERSION: &str =
    "serverware.responseObservationV2ExactReplayResolution/v1";
pub const V2_IMMUTABLE_RESPONSE_INSPECTION_VERSION: &str =
    "serverware.responseObservationV2ImmutableInspection/v1";
pub const V2_FINAL_ENVELOPE_VERIFICATION_VERSION: &str =
    "serverware.responseObservationV2FinalEnvelopeVerification/v1";
pub const V2_EXACT_RELEASE_AUTHORIZATION_VERSION: &str =
    "serverware.responseObservationV2ExactReleaseAuthorization/v2";
pub const V2_EXACT_RELEASE_CONSUMPTION_VERSION: &str =
    "serverware.responseObservationV2ExactReleaseConsumption/v2";
pub const V2_EXACT_RELEASE_PREPARATION_VERSION: &str =
    "serverware.responseObservationV2ExactReleasePreparation/v1";

pub const RESPONSE_OBSERVATION_V2_CAPABILITIES: [&str; 18] = [
    V2_HELLO_OPERATION,
    V2_RESERVE_OPERATION,
    V2_AUTHORITY_OPERATION,
    V2_STAGE_OPERATION,
    V2_DISPATCH_OPERATION,
    V2_TERMINAL_OPERATION,
    V2_FINALIZE_OPERATION,
    V2_ATTEST_OPERATION,
    V2_PUBLISH_OPERATION,
    V2_RETRIEVE_OPERATION,
    V2_RECOVER_OPERATION,
    V2_VERIFY_ARCHIVE_OPERATION,
    V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION,
    V2_VALIDATE_FINAL_ENVELOPE_OPERATION,
    V2_AUTHORIZE_EXACT_RELEASE_OPERATION,
    V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION,
    V2_RESOLVE_EXACT_REPLAY_OPERATION,
    V2_SETTLE_ATTEMPT_OPERATION,
];

pub type V2ControlRequest = V2OperationRequest;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2PinnedRoleKeyV1 {
    pub role: String,
    pub generation_id: String,
    pub provider_id: String,
    pub provider_generation: u64,
    pub key_id: String,
    pub key_material_sha256: String,
    pub key_material_path: String,
    pub executable_measurement_sha256: String,
    pub executable_path: String,
    pub provider_config_sha256: String,
    pub provider_config_path: String,
    pub tee_measurement_sha256: String,
    pub public_key_base64: String,
    pub public_key_sha256: String,
    pub allowed_operations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2CanonicalFinalEnvelopeV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub finalization_id: String,
    pub terminal_revision: u64,
    pub fencing_token: u64,
    pub transition_chain_root_sha256: String,
    pub authority_artifacts_root_sha256: String,
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2Http11TransferCodingV1 {
    NoBody,
    Identity,
    Chunked,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2Http11FramingResultV1 {
    pub http_version: String,
    pub informational_statuses: Vec<u16>,
    pub final_status: u16,
    pub header_section_length: u64,
    pub transfer_coding: V2Http11TransferCodingV1,
    pub declared_content_length: Option<u64>,
    pub decoded_entity_length: u64,
    pub trailer_section_length: u64,
    pub trailer_names: Vec<String>,
    pub physical_message_length: u64,
    pub surplus_length: u64,
    pub canonical_framing_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ParsedHttp11ResponseCommitmentV1 {
    pub api_version: String,
    pub raw_response_sha256: String,
    pub raw_response_byte_length: u64,
    pub framing_validation_sha256: String,
    pub final_status: u16,
    pub decoded_entity_sha256: String,
    pub decoded_entity_length: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2OperationRequest {
    #[serde(rename = "responseObservationV2.hello/v1")]
    Hello {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2HelloParams,
    },
    #[serde(rename = "responseObservationV2.reserve/v1")]
    Reserve {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2ReserveParams,
    },
    #[serde(rename = "responseObservationV2.authority/v1")]
    Authority {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2AuthorityParams,
    },
    #[serde(rename = "responseObservationV2.stage/v1")]
    Stage {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2StageParams,
    },
    #[serde(rename = "responseObservationV2.dispatch/v1")]
    Dispatch {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2DispatchParams,
    },
    #[serde(rename = "responseObservationV2.terminal/v1")]
    Terminal {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2TerminalParams,
    },
    #[serde(rename = "responseObservationV2.finalize/v1")]
    Finalize {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2FinalizeParams,
    },
    #[serde(rename = "responseObservationV2.attest/v1")]
    Attest {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2AttestParams,
    },
    #[serde(rename = "responseObservationV2.publish/v1")]
    Publish {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2PublishParams,
    },
    #[serde(rename = "responseObservationV2.retrieve/v1")]
    Retrieve {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2RetrieveParams,
    },
    #[serde(rename = "responseObservationV2.recover/v1")]
    Recover {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2RecoverParams,
    },
    #[serde(rename = "responseObservationV2.verifyArchive/v1")]
    VerifyArchive {
        api_version: String,
        request_id: String,
        boot_id: Option<String>,
        params: V2ArchiveVerifyParams,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ControlResponse {
    Success {
        api_version: String,
        request_id: String,
        boot_id: String,
        result: V2OperationResult,
        attestation: Option<V2FreshResponseAttestationV1>,
    },
    Error {
        api_version: String,
        request_id: String,
        boot_id: String,
        operation: V2ErrorOperation,
        error: V2ErrorBody,
        attestation: Option<V2FreshResponseAttestationV1>,
    },
    OutcomeUnknown {
        api_version: String,
        request_id: String,
        boot_id: String,
        operation: V2ErrorOperation,
        result: V2OutcomeUnknownResult,
        attestation: Option<V2FreshResponseAttestationV1>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ResponseDataRequest {
    #[serde(rename = "responseObservationV2.nativeStaging/v1")]
    NativeStaging {api_version:String,request_id:String,boot_id:String,params:V2NativeStagingParams},
    #[serde(rename = "responseObservationV2.targetDispatchBegin/v1")]
    TargetDispatchBegin {api_version:String,request_id:String,boot_id:String,
        params:crate::response_observation_v2::custody::target_dispatch::wire::BeginRequest},
    #[serde(rename = "responseObservationV2.capturePersist/v1")]
    CapturePersist {api_version:String,request_id:String,boot_id:String,
        params:crate::response_observation_v2::custody::target_dispatch::wire::CapturePersistRequest},
    #[serde(rename = "responseObservationV2.appendReleaseTransparency/v1")]
    AppendReleaseTransparency {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2AppendReleaseTransparencyParams,
    },
    #[serde(rename = "responseObservationV2.inspectImmutableResponse/v1")]
    InspectImmutableResponse {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2InspectImmutableResponseParams,
    },
    #[serde(rename = "responseObservationV2.validateFinalEnvelope/v1")]
    ValidateFinalEnvelope {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2ValidateFinalEnvelopeParams,
    },
    #[serde(rename = "responseObservationV2.authorizeExactRelease/v1")]
    AuthorizeExactRelease {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2AuthorizeExactReleaseParams,
    },
    #[serde(rename = "responseObservationV2.consumeAndRetrieveExact/v1")]
    ConsumeAndRetrieveExact {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2ConsumeAndRetrieveExactParams,
    },
    #[serde(rename = "responseObservationV2.resolveExactReplay/v1")]
    ResolveExactReplay {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2ResolveExactReplayParams,
    },
    #[serde(rename = "responseObservationV2.settleAttempt/v1")]
    SettleAttempt {
        api_version: String,
        request_id: String,
        boot_id: String,
        params: V2SettleAttemptParams,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ResponseDataControlResponse {
    Success {
        api_version: String,
        request_id: String,
        boot_id: String,
        result: V2ResponseDataResult,
        attestation: Option<V2FreshResponseAttestationV1>,
    },
    Error {
        api_version: String,
        request_id: String,
        boot_id: String,
        operation: V2ResponseDataOperation,
        error: SignedV2ResponseDataErrorV1,
        attestation: Option<V2FreshResponseAttestationV1>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum V2ResponseDataOperation {
    #[serde(rename = "responseObservationV2.nativeStaging/v1")]
    NativeStaging,
    #[serde(rename = "responseObservationV2.targetDispatchBegin/v1")]
    TargetDispatchBegin,
    #[serde(rename = "responseObservationV2.capturePersist/v1")]
    CapturePersist,
    #[serde(rename = "responseObservationV2.appendReleaseTransparency/v1")]
    AppendReleaseTransparency,
    #[serde(rename = "responseObservationV2.inspectImmutableResponse/v1")]
    InspectImmutableResponse,
    #[serde(rename = "responseObservationV2.validateFinalEnvelope/v1")]
    ValidateFinalEnvelope,
    #[serde(rename = "responseObservationV2.authorizeExactRelease/v1")]
    AuthorizeExactRelease,
    #[serde(rename = "responseObservationV2.consumeAndRetrieveExact/v1")]
    ConsumeAndRetrieveExact,
    #[serde(rename = "responseObservationV2.resolveExactReplay/v1")]
    ResolveExactReplay,
    #[serde(rename = "responseObservationV2.settleAttempt/v1")]
    SettleAttempt,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "result",
    deny_unknown_fields
)]
pub enum V2ResponseDataResult {
    #[serde(rename = "responseObservationV2.nativeStaging/v1")]
    NativeStaging(crate::response_observation_v2::custody::staging::wire::SignedStagingResult),
    #[serde(rename = "responseObservationV2.targetDispatchBegin/v1")]
    TargetDispatchBegin(crate::response_observation_v2::custody::target_dispatch::wire::SignedTargetDispatchPermit),
    #[serde(rename = "responseObservationV2.capturePersist/v1")]
    CapturePersist(crate::response_observation_v2::custody::target_dispatch::wire::CompletedCapture),
    #[serde(rename = "responseObservationV2.appendReleaseTransparency/v1")]
    AppendReleaseTransparency(V2AppendReleaseTransparencyResult),
    #[serde(rename = "responseObservationV2.inspectImmutableResponse/v1")]
    InspectImmutableResponse(V2InspectImmutableResponseResult),
    #[serde(rename = "responseObservationV2.validateFinalEnvelope/v1")]
    ValidateFinalEnvelope(V2ValidateFinalEnvelopeResult),
    #[serde(rename = "responseObservationV2.authorizeExactRelease/v1")]
    AuthorizeExactRelease(V2AuthorizeExactReleaseResult),
    #[serde(rename = "responseObservationV2.consumeAndRetrieveExact/v1")]
    ConsumeAndRetrieveExact(V2ConsumeAndRetrieveExactResult),
    #[serde(rename = "responseObservationV2.resolveExactReplay/v1")]
    ResolveExactReplay(V2ResolveExactReplayResult),
    #[serde(rename = "responseObservationV2.settleAttempt/v1")]
    SettleAttempt(V2SettleAttemptResult),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AppendReleaseTransparencyParams {
    pub binding: V2OperationBinding,
    pub stable_resume_id: String,
    pub raw_response: ImmutableObjectReference,
    pub transparency_trust_pin_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AppendReleaseTransparencyResult {
    pub attempt: AttemptStateReference,
    pub evidence_id: String,
    pub transparency_artifact:
        crate::response_observation_v2::custody::SignedAuthorityArtifact,
    pub transparency_artifact_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2InspectImmutableResponseParams {
    pub binding: V2ReadBinding,
    pub stable_resume_id: String,
    pub raw_response: ImmutableObjectReference,
    pub request_method: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2InspectImmutableResponseResult {
    pub inspection: SignedV2ImmutableResponseInspectionV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ImmutableResponseInspectionV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub raw_response: ImmutableObjectReference,
    pub exact_object: ExactByteObjectDescriptor,
    pub request_method: String,
    pub http11_framing: V2Http11FramingResultV1,
    pub parsed_response: V2ParsedHttp11ResponseCommitmentV1,
    pub framing_validation_sha256: String,
    pub parsed_response_sha256: String,
    pub released_projection_sha256: String,
    pub response_status: u16,
    pub response_body_sha256: String,
    pub immutable: bool,
    pub consumed: bool,
    pub inspection_sequence: u64,
    pub inspection_receipt_sha256: String,
    /// State-derived inputs for the canonical authority envelope. The
    /// immutable-inspection signature covers this seed, including the exact
    /// ordered set of nine prerequisite authority artifacts. The later
    /// post-CAS release-preparation receipt is the tenth collected body and is
    /// placed first in the canonical order. The policy-proof verifier
    /// recomputes every nested signature, the artifact root, and the final
    /// envelope digest before exact bytes can be released.
    pub authority_proof_seed:
        crate::response_observation_v2::custody::
            CanonicalAuthorityEnvelopeProofSeedV2,
    /// Lossless, topology-scoped receipt used by downstream internal
    /// authority operations. Its signature and authority scope are verified
    /// again before conversion; the duplicated public fields are not trusted.
    pub authority_receipt:
        crate::response_observation_v2::custody::
            SignedImmutableRawInspectionV1,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ValidateFinalEnvelopeParams {
    pub binding: V2OperationBinding,
    pub stable_resume_id: String,
    pub terminal_evidence: EvidenceReference,
    pub inspection: SignedV2ImmutableResponseInspectionV1,
    pub release_preparation:
        SignedV2ExactReleasePreparationV1,
    pub http11_framing: V2Http11FramingResultV1,
    pub parsed_response: V2ParsedHttp11ResponseCommitmentV1,
    /// A sealed canonical JSON proof input containing the incomplete public
    /// and authority envelope bodies plus exactly ten signed final
    /// authority artifacts. Artifact-root and final-envelope digests are
    /// computed only by the policy-proof engine.
    pub authority_proof: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ValidateFinalEnvelopeResult {
    pub attempt: AttemptStateReference,
    pub envelope: ImmutableObjectReference,
    pub persistence_evidence: EvidenceReference,
    pub finalization_checkpoint: EvidenceReference,
    pub finalized_response: ImmutableObjectReference,
    pub canonical_authority_envelope:
        crate::response_observation_v2::custody::
            CanonicalAuthorityEnvelopeDescriptorV2,
    pub authority_artifacts_root_sha256: String,
    pub verification: SignedV2FinalEnvelopeVerificationV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2FinalEnvelopeVerificationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub final_envelope_sha256: String,
    pub authority_artifacts_root_sha256: String,
    pub canonical_envelope_bytes_sha256: String,
    pub transition_chain_root_sha256: String,
    pub raw_response_sha256: String,
    pub framing_validation_sha256: String,
    pub parsed_response_sha256: String,
    pub verified: bool,
    pub verification_sequence: u64,
    pub verification_result_sha256: String,
    pub authority_receipt:
        crate::response_observation_v2::custody::
            SignedFinalEnvelopeVerificationV1,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AuthorizeExactReleaseParams {
    pub binding: V2ReadBinding,
    pub stable_resume_id: String,
    pub inspection: SignedV2ImmutableResponseInspectionV1,
    pub authority_proof_seed_sha256: String,
    pub authority_prerequisites_root_sha256: String,
    pub policy_decision_sha256: String,
    pub exact_replay_key_sha256: String,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AuthorizeExactReleaseResult {
    pub authorization: SignedV2ExactReleaseAuthorizationV2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ExactReleaseAuthorizationV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub authorization_id: String,
    pub inspection_receipt_sha256: String,
    pub authority_proof_seed_sha256: String,
    pub authority_prerequisites_root_sha256: String,
    pub raw_response_sha256: String,
    pub policy_decision_sha256: String,
    pub exact_replay_key_sha256: String,
    pub expires_at_epoch_ms: u64,
    pub authorization_result_sha256: String,
    pub authority_receipt:
        crate::response_observation_v2::custody::
            SignedReleaseAuthorizationV2,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "phase",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ConsumeAndRetrieveExactParams {
    Prepare {
        binding: V2OperationBinding,
        stable_resume_id: String,
        object: ImmutableObjectReference,
        release_authorization:
            SignedV2ExactReleaseAuthorizationV2,
        inspection: SignedV2ImmutableResponseInspectionV1,
        exact_replay_key_sha256: String,
    },
    Retrieve {
        binding: V2ReadBinding,
        stable_resume_id: String,
        object: ImmutableObjectReference,
        preparation: SignedV2ExactReleasePreparationV1,
        final_envelope_verification:
            SignedV2FinalEnvelopeVerificationV1,
        exact_replay_key_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "phase",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ConsumeAndRetrieveExactResult {
    Prepared {
        attempt: AttemptStateReference,
        preparation: SignedV2ExactReleasePreparationV1,
    },
    Retrieved {
        object: ImmutableObjectReference,
        exact_bytes: ExactByteObjectDescriptor,
        retrieval_evidence: EvidenceReference,
        consumption: SignedV2ExactReleaseConsumptionV2,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ExactReleasePreparationV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub predecessor_revision: u64,
    pub prepared_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub authorization_id: String,
    pub inspection_receipt_sha256: String,
    pub authority_proof_seed_sha256: String,
    pub authority_prerequisites_root_sha256: String,
    pub exact_replay_key_sha256: String,
    pub raw_response_sha256: String,
    pub raw_response_byte_length: u64,
    pub preauthorization_artifact_sha256: String,
    pub state_mutation_receipt_sha256: String,
    pub release_preparation_artifact_sha256: String,
    pub durable_canonical_result_sha256: String,
    pub authority_receipt:
        crate::response_observation_v2::custody::
            SignedReleasePreparationReceiptV1,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ExactReleaseConsumptionV2 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub stable_resume_id: String,
    pub fencing_token: u64,
    pub preparation_receipt_sha256: String,
    pub final_envelope_verification_sha256: String,
    pub exact_replay_key_sha256: String,
    pub raw_response_sha256: String,
    pub raw_response_byte_length: u64,
    pub exact_object: ExactByteObjectDescriptor,
    pub retrieval_sequence: u64,
    pub retrieval_receipt_sha256: String,
    pub canonical_result_sha256: String,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ResponseDataReplayKeyV1 {
    pub original_request_id: String,
    pub request_sha256: String,
    pub descriptor_manifest_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub operation: V2ResponseDataOperation,
    pub phase: V2ResponseDataReplayPhaseV1,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ResponseDataReplayPhaseV1 {
    Prepare,
    Retrieve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ResolveExactReplayParams {
    pub stable_request: V2ResponseDataReplayKeyV1,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ResolveExactReplayResult {
    pub resolution: SignedV2ExactReplayResolutionV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ExactReplayResolutionV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub stable_request: V2ResponseDataReplayKeyV1,
    pub exact_canonical_response:
        V2DurableExactCanonicalResponseReferenceV1,
    pub replay_record_sha256: String,
    pub replay_evidence_sha256: String,
    pub replay_evidence:
        crate::response_observation_v2::custody::
            SignedAuthorityArtifact,
    pub state_authority_receipt:
        crate::response_observation_v2::custody::
            SignedStateMutationReceiptV1,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2SettleAttemptParams {
    pub stable_resume_id: String,
    pub attempt: AttemptStateReference,
    pub transaction: V2TransactionBindingV1,
    pub lifecycle_deadline: V2MonotonicDeadlineV1,
    pub lifecycle_deadline_at_epoch_ms: u64,
    pub settlement_deadline: V2MonotonicDeadlineV1,
    pub settlement_deadline_at_epoch_ms: u64,
    pub terminal_kind: V2TerminalKind,
    pub error_class: String,
    pub upstream_response: Option<ImmutableObjectReference>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2SettleAttemptResult {
    pub receipt: SignedV2DurableSettlementReceiptV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2DurableSettlementReceiptV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub predecessor_revision: u64,
    pub predecessor_fencing_token: u64,
    pub deadline_expired: bool,
    pub terminal_attempt: AttemptStateReference,
    pub terminal_receipt_sha256: String,
    pub reconciliation_id: String,
    pub reconciliation_record_sha256: String,
    pub reconciliation_evidence:
        crate::response_observation_v2::custody::
            SignedAuthorityArtifact,
    pub recovery_evidence:
        Option<
            crate::response_observation_v2::custody::
                SignedAuthorityArtifact,
        >,
    pub recovery_evidence_sha256: Option<String>,
    pub authority_sequence: u64,
    pub authority_receipt:
        crate::response_observation_v2::custody::
            SignedDurableTerminalReceiptV1,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ResponseDataErrorV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub operation: V2ResponseDataOperation,
    pub request_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub stable_resume_id: String,
    pub error_code: String,
    pub retryable: bool,
    pub deadline_expired: bool,
    pub durable_terminalized: bool,
    pub terminal_state_sha256: String,
    pub reconciliation_id: String,
    pub reconciliation_record_sha256: String,
    pub provider_scope:
        crate::response_observation_v2::custody::
            ProviderAuthorityScopeV2,
    pub provider_operation_binding_sha256: String,
    pub signer_logical_role: String,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2FreshResponseAttestationV1 {
    pub api_version: String,
    pub attestation_mode: V2AttestationMode,
    pub request_sha256: String,
    pub unsigned_response_sha256: String,
    pub output_manifest_sha256: String,
    pub custody_boot_id: String,
    pub authenticated_session_sha256: String,
    pub client_identity_sha256: String,
    pub role_identity_root_sha256: String,
    pub proof_independent_pins_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub custody_executable_measurement_sha256: String,
    pub custody_provider_config_sha256: String,
    pub custody_key_material_sha256: String,
    pub custody_tee_measurement_sha256: String,
    pub provider_generation: u64,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
    pub challenge_nonce: String,
    pub attestation_evidence_format:
        V2FreshAttestationEvidenceFormat,
    pub attestation_evidence_base64: String,
    pub attestation_evidence_sha256: String,
    pub attestation_evidence_retrieval_id: String,
    pub current_revocation_receipt_sha256: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub signature_algorithm: V2FreshAttestationSignatureAlgorithm,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signer_key: V2AttestationSignerKeyV1,
    pub tee_report_binding: V2TeeReportBindingV1,
    pub trust_evidence: V2AttestationTrustEvidenceV1,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum V2FreshAttestationEvidenceFormat {
    #[serde(rename = "serverware.trustedHostEvidence.measurementBundle.json/v1")]
    TrustedHostMeasurementBundleJsonV1,
    #[serde(rename = "serverware.teeEvidence.eatCoseBundle.cbor/v1")]
    EatCoseBundleCborV1,
    #[serde(rename = "serverware.teeEvidence.sevSnpBundle.cbor/v1")]
    SevSnpBundleCborV1,
    #[serde(rename = "serverware.teeEvidence.tdxQuoteBundle.cbor/v1")]
    TdxQuoteBundleCborV1,
    #[serde(rename = "serverware.teeEvidence.nitroDocumentBundle.cbor/v1")]
    NitroDocumentBundleCborV1,
    #[serde(rename = "serverware.teeEvidence.ccaTokenBundle.cbor/v1")]
    CcaTokenBundleCborV1,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2AttestationMode {
    #[serde(rename = "TRUSTED_HOST_NO_TEE")]
    TrustedHost,
    TeeHardware,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2FreshAttestationSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2AttestationSignerKeyV1 {
    InlineEd25519PublicKey {
        public_key_base64: String,
        public_key_sha256: String,
    },
    ImmutableKeyReference {
        retrieval_id: String,
        public_key_sha256: String,
        persistence_receipt_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2TeeReportBindingV1 {
    pub report_data_sha256: String,
    pub unsigned_response_sha256: String,
    pub output_manifest_sha256: String,
    pub authenticated_session_sha256: String,
    pub challenge_nonce: String,
    pub signer_key_sha256: String,
    pub custody_measurement_sha256: String,
    pub provider_generation: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2AttestationTrustArtifactV1 {
    InlineDerBundle {
        der_bundle_base64: String,
        der_bundle_sha256: String,
    },
    ImmutableTrustReference {
        retrieval_id: String,
        artifact_sha256: String,
        persistence_receipt_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AttestationTrustEvidenceV1 {
    pub trust_chain: V2AttestationTrustArtifactV1,
    pub endorsements: V2AttestationTrustArtifactV1,
    pub trust_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub signer_revocation_receipt_sha256: String,
    pub signer_revocation_receipt_retrieval_id: String,
    pub evidence_verification_receipt_sha256: String,
    pub evidence_verification_receipt_retrieval_id: String,
    pub verified_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum V2ErrorOperation {
    #[serde(rename = "responseObservationV2.hello/v1")]
    Hello,
    #[serde(rename = "responseObservationV2.reserve/v1")]
    Reserve,
    #[serde(rename = "responseObservationV2.authority/v1")]
    Authority,
    #[serde(rename = "responseObservationV2.stage/v1")]
    Stage,
    #[serde(rename = "responseObservationV2.dispatch/v1")]
    Dispatch,
    #[serde(rename = "responseObservationV2.terminal/v1")]
    Terminal,
    #[serde(rename = "responseObservationV2.finalize/v1")]
    Finalize,
    #[serde(rename = "responseObservationV2.attest/v1")]
    Attest,
    #[serde(rename = "responseObservationV2.publish/v1")]
    Publish,
    #[serde(rename = "responseObservationV2.retrieve/v1")]
    Retrieve,
    #[serde(rename = "responseObservationV2.recover/v1")]
    Recover,
    #[serde(rename = "responseObservationV2.verifyArchive/v1")]
    VerifyArchive,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ErrorBody {
    pub code: V2PublicErrorCode,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2PublicErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AuthorizationDenied,
    Conflict,
    CapacityUnavailable,
    DeadlineExceeded,
    ProviderUnavailable,
    InternalFailure,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactByteObjectDescriptor {
    pub object_id: String,
    pub media_type: ExactObjectMediaType,
    pub fd_index: u16,
    pub byte_length: u64,
    pub sha256: String,
    pub required_seals: MemfdSealProfile,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExactObjectMediaType {
    CanonicalJson,
    Http11Request,
    Http11Response,
    EvidenceBundle,
    AttestationArtifact,
    PublicationArtifact,
    OpaqueProviderArtifact,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemfdSealProfile {
    ImmutableV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2HelloParams {
    pub clock_id: V2MonotonicClockId,
    pub absolute_boottime_ns: String,
    pub deadline_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2HelloResult {
    pub api_version: String,
    pub boot_id: String,
    pub authenticated_client_identity_sha256: String,
    pub pinned_genesis_state_sha256: String,
    pub capabilities: Vec<String>,
    pub transport: V2TransportLimits,
    pub providers_ready: bool,
    pub attestation_mode: V2AttestationMode,
    pub attestation_present: bool,
    pub hardware_proof: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2TransportLimits {
    pub socket_type: String,
    pub max_control_bytes: usize,
    pub max_exact_objects: usize,
    pub max_exact_object_bytes: u64,
    pub whole_operation_timeout_ms: u64,
    pub bulk_transfer: String,
    pub insecure_fallback_available: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2OperationBinding {
    pub request_id: String,
    pub custody_boot_id: String,
    pub client_identity_sha256: String,
    pub transaction: V2TransactionBindingV1,
    pub attempt_id: String,
    pub predecessor_lifecycle_state: V2AttemptState,
    pub predecessor_state_sha256: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReadBinding {
    pub request_id: String,
    pub custody_boot_id: String,
    pub client_identity_sha256: String,
    pub transaction: V2TransactionBindingV1,
    pub attempt_id: String,
    pub lifecycle_state: V2AttemptState,
    pub state_sha256: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2MonotonicDeadlineV1 {
    pub api_version: String,
    pub custody_boot_id: String,
    pub clock_id: V2MonotonicClockId,
    /// Canonical unsigned decimal CLOCK_BOOTTIME nanoseconds. A string keeps
    /// the full u64 range without lossy JSON number conversions.
    pub absolute_boottime_ns: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2MonotonicClockId {
    ClockBoottime,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2TransactionBindingV1 {
    pub principal_id: String,
    pub connection_identity_sha256: String,
    pub client_request_sha256: String,
    pub decision_request_sha256: String,
    pub route_id: String,
    pub route_semantics_sha256: String,
    pub policy_sha256: String,
    pub credential_binding_sha256: Option<String>,
    pub upstream_response_sha256: Option<String>,
    pub tls_session_sha256: String,
    pub enrollment_session_id: Option<String>,
    pub observation_session_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReserveParams {
    pub binding: V2OperationBinding,
    pub route_semantics: ExactByteObjectDescriptor,
    pub policy_decision: ExactByteObjectDescriptor,
    pub runtime_attestation: ExactByteObjectDescriptor,
}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct V2NativeStagingParams {
    pub binding:V2OperationBinding,
    pub stable_resume_id:String,
    pub request:crate::response_observation_v2::custody::staging::wire::StagingRequest,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ReserveResult {
    Denied {
        attempt: AttemptStateReference,
        terminal_evidence: EvidenceReference,
    },
    Reserved {
        attempt: AttemptStateReference,
        reservation_evidence: EvidenceReference,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AuthorityParams {
    pub binding: V2OperationBinding,
    pub reservation_evidence: EvidenceReference,
    pub authority_plan: ExactByteObjectDescriptor,
    pub authorization_evidence: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2AuthorityResult {
    Ready {
        attempt: AttemptStateReference,
        authority_evidence_root: EvidenceReference,
        authority_state: EvidenceReference,
    },
    Terminalized {
        attempt: AttemptStateReference,
        terminal_evidence: EvidenceReference,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2StageParams {
    pub binding: V2OperationBinding,
    pub authority_state: EvidenceReference,
    pub credential_template: ExactByteObjectDescriptor,
    pub credential_reference: Option<CredentialReference>,
    pub credential_free_request: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2StageResult {
    pub attempt: AttemptStateReference,
    pub staged_request: ImmutableObjectReference,
    pub staging_evidence: EvidenceReference,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DispatchParams {
    pub binding: V2OperationBinding,
    pub staged_request: ImmutableObjectReference,
    pub staging_evidence: EvidenceReference,
    pub live_policy_snapshot: ExactByteObjectDescriptor,
    pub authorization_evidence: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DispatchResult {
    pub attempt: AttemptStateReference,
    pub dispatch_evidence: EvidenceReference,
    pub upstream_response: ImmutableObjectReference,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2TerminalParams {
    pub binding: V2OperationBinding,
    pub terminal_kind: V2TerminalKind,
    pub lifecycle_state: ExactByteObjectDescriptor,
    pub upstream_response: Option<ImmutableObjectReference>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2TerminalKind {
    Cancelled,
    Failed,
    Completed,
    ReleasePrepared,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2TerminalResult {
    pub attempt: AttemptStateReference,
    pub terminal_evidence: EvidenceReference,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2FinalizeParams {
    pub binding: V2OperationBinding,
    pub terminal_evidence: EvidenceReference,
    pub proof_document: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2FinalizeResult {
    pub attempt: AttemptStateReference,
    pub envelope: ImmutableObjectReference,
    pub persistence_evidence: EvidenceReference,
    pub finalization_checkpoint: EvidenceReference,
    pub finalized_response: Option<ImmutableObjectReference>,
    pub release_cas_expectation: Option<V2ReleaseCasExpectationV1>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AttestParams {
    pub binding: V2OperationBinding,
    pub envelope: ImmutableObjectReference,
    pub finalization_checkpoint: EvidenceReference,
    pub attestation_challenge: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2AttestResult {
    pub attempt: AttemptStateReference,
    pub attestation_artifact: ImmutableObjectReference,
    pub artifact_time_checkpoint: EvidenceReference,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2PublishParams {
    pub binding: V2OperationBinding,
    pub envelope: ImmutableObjectReference,
    pub attestation_artifact: ImmutableObjectReference,
    pub attestation_checkpoint: EvidenceReference,
    pub publication_target: PublicationTarget,
    pub release_intent: V2PublishReleaseIntentV1,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2PublishReleaseIntentV1 {
    pub retrieve_request_id: String,
    pub one_use_nonce: String,
    pub object: ImmutableObjectReference,
    pub release_cas_expectation: V2ReleaseCasExpectationV1,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2PublishResult {
    pub attempt: AttemptStateReference,
    pub publication_artifact: ImmutableObjectReference,
    pub artifact_time_checkpoint: EvidenceReference,
    pub released_object: ImmutableObjectReference,
    pub public_release_authorization: ExactByteObjectDescriptor,
    pub release_cas_expectation: V2ReleaseCasExpectationV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2RetrieveParams {
    pub binding: V2ReadBinding,
    pub object: ImmutableObjectReference,
    pub release_cas_expectation: V2ReleaseCasExpectationV1,
    pub public_release_authorization: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReleaseCasExpectationV1 {
    pub expected_authority_revision: u64,
    pub expected_unconsumed_state_sha256: String,
}

pub const V2_PUBLIC_RELEASE_AUTHORIZATION_VERSION: &str =
    "serverware.publicReleaseAuthorization/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPublicReleaseAuthorizationV1 {
    pub api_version: String,
    pub authorization_id: String,
    pub request_id: String,
    pub release_request_commitment_sha256: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub one_use_nonce: String,
    pub release_cas_expectation: V2ReleaseCasExpectationV1,
    pub subject_client_identity_sha256: String,
    pub object: ImmutableObjectReference,
    pub policy_sha256: String,
    pub trust_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub signer_role: V2ReleaseAuthorityRole,
    pub signer_provider_id: String,
    pub provider_generation: u64,
    pub issuance_scope: V2ProviderAuthorityScopeV1,
    pub provider_operation_binding_sha256: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReleaseRequestCommitmentV1 {
    pub api_version: String,
    pub request_id: String,
    pub subject_client_identity_sha256: String,
    pub object: ImmutableObjectReference,
    pub attempt_id: String,
    pub lifecycle_state: V2AttemptState,
    pub state_sha256: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
    pub one_use_nonce: String,
    pub release_cas_expectation: V2ReleaseCasExpectationV1,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReleaseRequestCommitmentDigestV1 {
    pub commitment: V2ReleaseRequestCommitmentV1,
    pub canonicalization:
        V2ReleaseRequestCommitmentCanonicalization,
    pub digest_algorithm: V2ReleaseRequestCommitmentDigestAlgorithm,
    pub commitment_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ReleaseRequestCommitmentCanonicalization {
    JcsRfc8785,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ReleaseRequestCommitmentDigestAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ReleaseAuthorityRole {
    PublicRelease,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2RetrieveResult {
    pub object: ImmutableObjectReference,
    pub exact_bytes: ExactByteObjectDescriptor,
    pub retrieval_evidence: EvidenceReference,
    pub release_authorization_consumption:
        SignedV2ReleaseAuthorizationConsumeOutcomeV1,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2RetrievalEvidenceBindingV1 {
    pub api_version: String,
    pub request_sha256: String,
    pub descriptor_manifest_sha256: String,
    pub request_id: String,
    pub client_identity_sha256: String,
    pub object: ImmutableObjectReference,
    pub exact_bytes: ExactByteObjectDescriptor,
    pub attempt_id: String,
    pub lifecycle_state: V2AttemptState,
    pub state_sha256: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
    pub release_consume_binding_sha256: String,
    pub consumption_receipt_sha256: String,
    pub retrieval_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ReleaseAuthorizationConsumeCasV1 {
    pub authorization_id: String,
    pub request_sha256: String,
    pub descriptor_manifest_sha256: String,
    pub one_use_nonce: String,
    pub subject_client_identity_sha256: String,
    pub object: ImmutableObjectReference,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub release_request_commitment:
        V2ReleaseRequestCommitmentDigestV1,
    pub expected_authority_revision: u64,
    pub expected_unconsumed_state_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2ReleaseAuthorizationConsumeOutcomeV1 {
    pub api_version: String,
    pub consume: V2ReleaseAuthorizationConsumeCasV1,
    pub outcome: V2ReleaseAuthorizationConsumeOutcomeV1,
    pub trust_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub recorded_at_epoch_ms: u64,
    pub signer_role: V2ReleaseConsumeAuthorityRole,
    pub signer_provider_id: String,
    pub provider_generation: u64,
    pub provider_operation_binding_sha256: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2ReleaseAuthorizationConsumeOutcomeV1 {
    ConsumedBeforeRelease {
        authority_revision: u64,
        consume_binding_sha256: String,
        consumption_receipt_sha256: String,
    },
    ExactReplay {
        authority_revision: u64,
        consume_binding_sha256: String,
        consumption_receipt_sha256: String,
        replay_record_sha256: String,
        replay_key: V2DurableReplayKeyV1,
        exact_canonical_response:
            V2DurableExactCanonicalResponseReferenceV1,
    },
    Denied {
        authority_revision: u64,
        consume_binding_sha256: String,
        denial: V2ReleaseAuthorizationConsumeDenial,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ReleaseAuthorizationConsumeDenial {
    AlreadyConsumedByDifferentRequest,
    AuthorityStateConflict,
    AuthorizationInvalid,
    AuthorizationExpired,
    AuthorizationRevoked,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2ReleaseConsumeAuthorityRole {
    PublicReleaseConsumption,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2RecoverParams {
    pub stable_request: V2DurableReplayKeyV1,
    pub recovery_authorization: V2RecoveryAuthorizationV1,
    pub monotonic_deadline: V2MonotonicDeadlineV1,
    pub deadline_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2RecoveryAuthorizationV1 {
    SameBootAuthenticatedClient {
        authorization_id: String,
        one_use_nonce: String,
        original_custody_boot_id: String,
        subject_client_identity_sha256: String,
    },
    CrossBootSigned {
        authorization: ExactByteObjectDescriptor,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "terminalClass",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2RecoverResult {
    Success {
        replay_record: V2CanonicalDurableReplayRecordV1,
        recovery_authority_evidence: EvidenceReference,
        signed_outcome: SignedV2CrossBootRecoveryOutcomeV1,
    },
    Denied {
        replay_record: V2CanonicalDurableReplayRecordV1,
        recovery_authority_evidence: EvidenceReference,
        signed_outcome: SignedV2CrossBootRecoveryOutcomeV1,
    },
    OutcomeUnknown {
        replay_record: V2CanonicalDurableReplayRecordV1,
        recovery_authority_evidence: EvidenceReference,
        signed_outcome: SignedV2CrossBootRecoveryOutcomeV1,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2CrossBootRecoveryAuthorizationV1 {
    pub api_version: String,
    pub authorization_id: String,
    pub recovery_request_id: String,
    pub subject_client_identity_sha256: String,
    pub stable_request: V2DurableReplayKeyV1,
    pub one_use_nonce: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub trust_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub signer_role: V2RecoveryAuthorityRole,
    pub signer_provider_id: String,
    pub provider_generation: u64,
    pub provider_operation_binding_sha256: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedV2CrossBootRecoveryOutcomeV1 {
    pub api_version: String,
    pub recovery_request_id: String,
    pub subject_client_identity_sha256: String,
    pub stable_request: V2DurableReplayKeyV1,
    pub statement: V2CrossBootRecoveryStatementV1,
    pub reconciliation: EvidenceReference,
    pub output_references: Vec<V2DurableReplayOutputReferenceV1>,
    pub trust_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub recorded_at_epoch_ms: u64,
    pub signer_role: V2RecoveryOutcomeAuthorityRole,
    pub signer_provider_id: String,
    pub provider_generation: u64,
    pub provider_operation_binding_sha256: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "terminalClass",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum V2CrossBootRecoveryStatementV1 {
    Success {
        replay_record_sha256: String,
        canonical_response_sha256: String,
        output_manifest_sha256: String,
    },
    Denied {
        replay_record_sha256: String,
        canonical_response_sha256: String,
        output_manifest_sha256: String,
    },
    OutcomeUnknown {
        replay_record_sha256: String,
        canonical_response_sha256: String,
        output_manifest_sha256: String,
        provider_operation_id: String,
        durable_start_receipt_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2RecoveryAuthorityRole {
    RecoveryLookup,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2RecoveryOutcomeAuthorityRole {
    RecoveryOutcome,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DurableReplayKeyV1 {
    pub original_request_id: String,
    pub request_sha256: String,
    pub descriptor_manifest_sha256: String,
    pub attempt_id: String,
    pub operation: V2DurableReplayOperation,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum V2DurableReplayOperation {
    #[serde(rename = "responseObservationV2.reserve/v1")]
    Reserve,
    #[serde(rename = "responseObservationV2.authority/v1")]
    Authority,
    #[serde(rename = "responseObservationV2.stage/v1")]
    Stage,
    #[serde(rename = "responseObservationV2.dispatch/v1")]
    Dispatch,
    #[serde(rename = "responseObservationV2.terminal/v1")]
    Terminal,
    #[serde(rename = "responseObservationV2.finalize/v1")]
    Finalize,
    #[serde(rename = "responseObservationV2.attest/v1")]
    Attest,
    #[serde(rename = "responseObservationV2.publish/v1")]
    Publish,
    #[serde(rename = "responseObservationV2.retrieve/v1")]
    Retrieve,
    #[serde(rename = "responseObservationV2.recover/v1")]
    Recover,
    #[serde(rename = "responseObservationV2.verifyArchive/v1")]
    VerifyArchive,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2CanonicalDurableReplayRecordV1 {
    pub api_version: String,
    pub key: V2DurableReplayKeyV1,
    pub outcome: V2DurableReplayOutcome,
    pub exact_canonical_response:
        V2DurableExactCanonicalResponseReferenceV1,
    pub output_references: Vec<V2DurableReplayOutputReferenceV1>,
    pub output_manifest_sha256: String,
    pub commit: V2DurableReplayCommitReceiptV1,
    pub signer_role: V2DurableReplayAuthorityRole,
    pub signer_provider_id: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2DurableReplayOutcome {
    Success,
    Denied,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DurableExactCanonicalResponseReferenceV1 {
    pub encoding: V2CanonicalControlResponseEncoding,
    pub byte_length: u64,
    pub sha256: String,
    pub storage_reference_id: String,
    pub persistence_receipt_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2CanonicalControlResponseEncoding {
    CanonicalJsonUtf8,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "referenceType",
    content = "reference",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum V2DurableReplayOutputReferenceV1 {
    ExactBytes(V2DurableStoredObjectReferenceV1),
    ImmutableObject(ImmutableObjectReference),
    Evidence(EvidenceReference),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DurableStoredObjectReferenceV1 {
    pub media_type: ExactObjectMediaType,
    pub byte_length: u64,
    pub sha256: String,
    pub storage_reference_id: String,
    pub persistence_receipt_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2DurableReplayCommitReceiptV1 {
    pub commit_order: V2DurableReplayCommitOrder,
    pub durable_store_id: String,
    pub transaction_id: String,
    pub durable_index_revision: u64,
    pub record_sha256: String,
    pub committed_at_epoch_ms: u64,
    pub persistence_receipt_sha256: String,
    pub provider_generation: u64,
    pub provider_operation_scope: V2ProviderAuthorityScopeV1,
    pub provider_operation_binding_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ProviderAuthorityScopeV1 {
    pub role: String,
    pub provider_id: String,
    pub provider_generation: u64,
    pub provider_operation_id: String,
    pub request_sha256: String,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub predecessor_state_sha256: String,
    pub launch_nonce: String,
    pub fencing_token: u64,
    pub kernel_process_identity_sha256: String,
    pub executable_measurement_sha256: String,
    pub provider_config_sha256: String,
    pub key_material_sha256: String,
    pub tee_measurement_sha256: String,
    pub launch_attestation_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2DurableReplayCommitOrder {
    CommittedBeforeResponseSend,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2DurableReplayAuthorityRole {
    DurableReplayStore,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ArchiveVerifyParams {
    pub binding: V2ReadBinding,
    pub proof_document: ExactByteObjectDescriptor,
    pub historical_runtime_attestation: ExactByteObjectDescriptor,
    pub finalization_checkpoint: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2ArchiveVerifyResult {
    pub attempt_id: String,
    pub envelope: ImmutableObjectReference,
    pub verification_evidence: EvidenceReference,
    pub mutation_capability: ArchiveMutationCapability,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2OutcomeUnknownResult {
    pub attempt: AttemptStateReference,
    pub request_sha256: String,
    pub descriptor_manifest_sha256: String,
    pub provider_operation_id: String,
    pub durable_start_receipt_sha256: String,
    pub reconciliation: EvidenceReference,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub recorded_at_epoch_ms: u64,
    pub signer_role: V2OutcomeAuthorityRole,
    pub signer_provider_id: String,
    pub provider_generation: u64,
    pub provider_operation_binding_sha256: String,
    pub signer_key_id: String,
    pub signer_key_material_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2OutcomeAuthorityRole {
    Reconciliation,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchiveMutationCapability {
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "result",
    deny_unknown_fields
)]
pub enum V2OperationResult {
    #[serde(rename = "responseObservationV2.hello/v1")]
    Hello(V2HelloResult),
    #[serde(rename = "responseObservationV2.reserve/v1")]
    Reserve(V2ReserveResult),
    #[serde(rename = "responseObservationV2.authority/v1")]
    Authority(V2AuthorityResult),
    #[serde(rename = "responseObservationV2.stage/v1")]
    Stage(V2StageResult),
    #[serde(rename = "responseObservationV2.dispatch/v1")]
    Dispatch(V2DispatchResult),
    #[serde(rename = "responseObservationV2.terminal/v1")]
    Terminal(V2TerminalResult),
    #[serde(rename = "responseObservationV2.finalize/v1")]
    Finalize(V2FinalizeResult),
    #[serde(rename = "responseObservationV2.attest/v1")]
    Attest(V2AttestResult),
    #[serde(rename = "responseObservationV2.publish/v1")]
    Publish(V2PublishResult),
    #[serde(rename = "responseObservationV2.retrieve/v1")]
    Retrieve(V2RetrieveResult),
    #[serde(rename = "responseObservationV2.recover/v1")]
    Recover(V2RecoverResult),
    #[serde(rename = "responseObservationV2.verifyArchive/v1")]
    VerifyArchive(V2ArchiveVerifyResult),
}

impl V2OperationResult {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Hello(_) => V2_HELLO_OPERATION,
            Self::Reserve(_) => V2_RESERVE_OPERATION,
            Self::Authority(_) => V2_AUTHORITY_OPERATION,
            Self::Stage(_) => V2_STAGE_OPERATION,
            Self::Dispatch(_) => V2_DISPATCH_OPERATION,
            Self::Terminal(_) => V2_TERMINAL_OPERATION,
            Self::Finalize(_) => V2_FINALIZE_OPERATION,
            Self::Attest(_) => V2_ATTEST_OPERATION,
            Self::Publish(_) => V2_PUBLISH_OPERATION,
            Self::Retrieve(_) => V2_RETRIEVE_OPERATION,
            Self::Recover(_) => V2_RECOVER_OPERATION,
            Self::VerifyArchive(_) => V2_VERIFY_ARCHIVE_OPERATION,
        }
    }
}

pub fn response_observation_v2_transition_evidence_sha256(
    request: &V2OperationRequest,
    result: &V2OperationResult,
) -> Option<String> {
    let request_bytes = crate::canonical_json_bytes(request).ok()?;
    let request_sha256 =
        format!("sha256:{:x}", Sha256::digest(&request_bytes));
    let (
        attempt,
        transition_evidence,
        result_binding,
    ) = match (request, result) {
        (
            V2OperationRequest::Reserve { .. },
            V2OperationResult::Reserve(
                V2ReserveResult::Reserved {
                    attempt,
                    reservation_evidence,
                },
            ),
        ) => (
            attempt,
            reservation_evidence,
            serde_json::json!({"terminalClass":"RESERVED"}),
        ),
        (
            V2OperationRequest::Reserve { .. },
            V2OperationResult::Reserve(
                V2ReserveResult::Denied {
                    attempt,
                    terminal_evidence,
                },
            ),
        ) => (
            attempt,
            terminal_evidence,
            serde_json::json!({"terminalClass":"DENIED"}),
        ),
        (
            V2OperationRequest::Authority { .. },
            V2OperationResult::Authority(
                V2AuthorityResult::Ready {
                    attempt,
                    authority_evidence_root,
                    authority_state,
                },
            ),
        ) => (
            attempt,
            authority_state,
            serde_json::json!({
                "terminalClass":"READY",
                "authorityEvidenceRoot":authority_evidence_root,
            }),
        ),
        (
            V2OperationRequest::Authority { .. },
            V2OperationResult::Authority(
                V2AuthorityResult::Terminalized {
                    attempt,
                    terminal_evidence,
                },
            ),
        ) => (
            attempt,
            terminal_evidence,
            serde_json::json!({"terminalClass":"TERMINALIZED"}),
        ),
        (
            V2OperationRequest::Stage { .. },
            V2OperationResult::Stage(result),
        ) => (
            &result.attempt,
            &result.staging_evidence,
            serde_json::json!({
                "stagedRequest":result.staged_request,
            }),
        ),
        (
            V2OperationRequest::Dispatch { .. },
            V2OperationResult::Dispatch(result),
        ) => (
            &result.attempt,
            &result.dispatch_evidence,
            serde_json::json!({
                "upstreamResponse":result.upstream_response,
            }),
        ),
        (
            V2OperationRequest::Terminal { params, .. },
            V2OperationResult::Terminal(result),
        ) => (
            &result.attempt,
            &result.terminal_evidence,
            serde_json::json!({
                "terminalKind":params.terminal_kind,
                "upstreamResponse":params.upstream_response,
            }),
        ),
        (
            V2OperationRequest::Finalize { .. },
            V2OperationResult::Finalize(result),
        ) => (
            &result.attempt,
            &result.finalization_checkpoint,
            serde_json::json!({
                "envelope":result.envelope,
                "persistenceEvidence":result.persistence_evidence,
                "finalizedResponse":result.finalized_response,
                "releaseCasExpectation":
                    result.release_cas_expectation,
            }),
        ),
        (
            V2OperationRequest::Attest { .. },
            V2OperationResult::Attest(result),
        ) => (
            &result.attempt,
            &result.artifact_time_checkpoint,
            serde_json::json!({
                "attestationArtifact":
                    result.attestation_artifact,
            }),
        ),
        (
            V2OperationRequest::Publish { .. },
            V2OperationResult::Publish(result),
        ) => (
            &result.attempt,
            &result.artifact_time_checkpoint,
            serde_json::json!({
                "publicationArtifact":
                    result.publication_artifact,
                "releasedObject":result.released_object,
                "publicReleaseAuthorization":
                    result.public_release_authorization,
                "releaseCasExpectation":
                    result.release_cas_expectation,
            }),
        ),
        _ => return None,
    };
    response_observation_v2_canonical_binding_sha256(
        b"serverware.response-v2/transition-evidence/v1",
        &serde_json::json!({
            "requestSha256":request_sha256,
            "operation":request.operation(),
            "attempt":{
                "attemptId":attempt.attempt_id,
                "state":attempt.state,
                "attemptRevision":attempt.attempt_revision,
                "fencingToken":attempt.fencing_token,
            },
            "transitionEvidence":{
                "evidenceType":transition_evidence.evidence_type,
                "retrievalId":transition_evidence.retrieval_id,
            },
            "resultBinding":result_binding,
        }),
    )
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReference {
    pub evidence_type: V2EvidenceType,
    pub evidence_sha256: String,
    pub retrieval_id: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2EvidenceType {
    Reservation,
    Terminal,
    AuthorityEvidenceRoot,
    AuthorityState,
    Staging,
    Dispatch,
    Persistence,
    FinalizationCheckpoint,
    ArtifactTimeCheckpoint,
    Retrieval,
    ReleaseAuthorizationConsumption,
    CrossBootRecoveryAuthority,
    CrossBootRecoveryReconciliation,
    ArchiveVerification,
    OutcomeUnknownReconciliation,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImmutableObjectReference {
    pub object_type: ImmutableObjectType,
    pub object_sha256: String,
    pub byte_length: u64,
    pub retrieval_id: String,
    pub persistence_receipt_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImmutableObjectType {
    StagedRequest,
    UpstreamResponse,
    ResponseObservationEnvelope,
    AttestationArtifact,
    PublicationArtifact,
    ReleasedResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptStateReference {
    pub attempt_id: String,
    pub state: V2AttemptState,
    pub state_sha256: String,
    pub attempt_revision: u64,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum V2AttemptState {
    Genesis,
    Denied,
    Reserved,
    AuthorityReady,
    Staged,
    Dispatched,
    Cancelled,
    Failed,
    Completed,
    ReleasePrepared,
    OutcomeUnknown,
    Terminalized,
    Finalized,
    Attested,
    Published,
}

pub fn response_observation_v2_lifecycle_state_sha256(
    request: &V2OperationRequest,
    binding: &V2OperationBinding,
    successor: &AttemptStateReference,
    transition_evidence_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    append_lifecycle_hash_frame(
        &mut hasher,
        b"serverware.response-v2/lifecycle-state/v2",
    );
    for value in [
        request.operation().as_bytes(),
        binding.request_id.as_bytes(),
        binding.custody_boot_id.as_bytes(),
        binding.client_identity_sha256.as_bytes(),
        binding.attempt_id.as_bytes(),
        binding.transaction.principal_id.as_bytes(),
        binding
            .transaction
            .connection_identity_sha256
            .as_bytes(),
        binding.transaction.client_request_sha256.as_bytes(),
        binding.transaction.decision_request_sha256.as_bytes(),
        binding.transaction.route_id.as_bytes(),
        binding.transaction.route_semantics_sha256.as_bytes(),
        binding.transaction.policy_sha256.as_bytes(),
        binding.transaction.tls_session_sha256.as_bytes(),
        binding.transaction.observation_session_id.as_bytes(),
        v2_lifecycle_state_label(
            binding.predecessor_lifecycle_state,
        ),
        binding.predecessor_state_sha256.as_bytes(),
        v2_lifecycle_state_label(successor.state),
        transition_evidence_sha256.as_bytes(),
        binding.monotonic_deadline.api_version.as_bytes(),
        binding.monotonic_deadline.custody_boot_id.as_bytes(),
        v2_monotonic_clock_label(
            binding.monotonic_deadline.clock_id,
        ),
        binding
            .monotonic_deadline
            .absolute_boottime_ns
            .as_bytes(),
    ] {
        append_lifecycle_hash_frame(&mut hasher, value);
    }
    append_lifecycle_hash_frame(
        &mut hasher,
        binding
            .transaction
            .credential_binding_sha256
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    append_lifecycle_hash_frame(
        &mut hasher,
        binding
            .transaction
            .upstream_response_sha256
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    append_lifecycle_hash_frame(
        &mut hasher,
        binding
            .transaction
            .enrollment_session_id
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    append_lifecycle_hash_frame(
        &mut hasher,
        &binding.deadline_at_epoch_ms.to_be_bytes(),
    );
    append_lifecycle_hash_frame(
        &mut hasher,
        &successor.attempt_revision.to_be_bytes(),
    );
    append_lifecycle_hash_frame(
        &mut hasher,
        &successor.fencing_token.to_be_bytes(),
    );
    format!("sha256:{:x}", hasher.finalize())
}

pub fn response_observation_v2_release_consume_binding_sha256(
    consume: &V2ReleaseAuthorizationConsumeCasV1,
) -> Option<String> {
    response_observation_v2_canonical_binding_sha256(
        b"serverware.public-release-consume-binding/v1",
        consume,
    )
}

pub fn response_observation_v2_release_request_commitment_sha256(
    commitment: &V2ReleaseRequestCommitmentV1,
) -> Option<String> {
    response_observation_v2_canonical_binding_sha256(
        b"serverware.public-release-request-commitment/v1",
        commitment,
    )
}

pub fn response_observation_v2_retrieval_evidence_sha256(
    binding: &V2RetrievalEvidenceBindingV1,
) -> Option<String> {
    response_observation_v2_canonical_binding_sha256(
        b"serverware.response-v2/retrieval-evidence/v1",
        binding,
    )
}

pub(crate) fn response_observation_v2_canonical_binding_sha256<
    T: Serialize,
>(
    domain: &[u8],
    value: &T,
) -> Option<String> {
    let canonical = crate::canonical_json_bytes(value).ok()?;
    let mut hasher = Sha256::new();
    append_lifecycle_hash_frame(&mut hasher, domain);
    append_lifecycle_hash_frame(&mut hasher, &canonical);
    Some(format!("sha256:{:x}", hasher.finalize()))
}

fn append_lifecycle_hash_frame(
    hasher: &mut Sha256,
    value: &[u8],
) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn v2_lifecycle_state_label(
    state: V2AttemptState,
) -> &'static [u8] {
    match state {
        V2AttemptState::Genesis => b"GENESIS",
        V2AttemptState::Denied => b"DENIED",
        V2AttemptState::Reserved => b"RESERVED",
        V2AttemptState::AuthorityReady => b"AUTHORITY_READY",
        V2AttemptState::Staged => b"STAGED",
        V2AttemptState::Dispatched => b"DISPATCHED",
        V2AttemptState::Cancelled => b"CANCELLED",
        V2AttemptState::Failed => b"FAILED",
        V2AttemptState::Completed => b"COMPLETED",
        V2AttemptState::ReleasePrepared => b"RELEASE_PREPARED",
        V2AttemptState::OutcomeUnknown => b"OUTCOME_UNKNOWN",
        V2AttemptState::Terminalized => b"TERMINALIZED",
        V2AttemptState::Finalized => b"FINALIZED",
        V2AttemptState::Attested => b"ATTESTED",
        V2AttemptState::Published => b"PUBLISHED",
    }
}

fn v2_monotonic_clock_label(
    clock_id: V2MonotonicClockId,
) -> &'static [u8] {
    match clock_id {
        V2MonotonicClockId::ClockBoottime => b"CLOCK_BOOTTIME",
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialReference {
    pub credential_id: String,
    pub credential_generation: u64,
    pub credential_binding_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationTarget {
    pub target_id: String,
    pub target_policy_sha256: String,
}

impl V2OperationRequest {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Hello { .. } => V2_HELLO_OPERATION,
            Self::Reserve { .. } => V2_RESERVE_OPERATION,
            Self::Authority { .. } => V2_AUTHORITY_OPERATION,
            Self::Stage { .. } => V2_STAGE_OPERATION,
            Self::Dispatch { .. } => V2_DISPATCH_OPERATION,
            Self::Terminal { .. } => V2_TERMINAL_OPERATION,
            Self::Finalize { .. } => V2_FINALIZE_OPERATION,
            Self::Attest { .. } => V2_ATTEST_OPERATION,
            Self::Publish { .. } => V2_PUBLISH_OPERATION,
            Self::Retrieve { .. } => V2_RETRIEVE_OPERATION,
            Self::Recover { .. } => V2_RECOVER_OPERATION,
            Self::VerifyArchive { .. } => V2_VERIFY_ARCHIVE_OPERATION,
        }
    }

    pub fn api_version(&self) -> &str {
        match self {
            Self::Hello { api_version, .. }
            | Self::Reserve { api_version, .. }
            | Self::Authority { api_version, .. }
            | Self::Stage { api_version, .. }
            | Self::Dispatch { api_version, .. }
            | Self::Terminal { api_version, .. }
            | Self::Finalize { api_version, .. }
            | Self::Attest { api_version, .. }
            | Self::Publish { api_version, .. }
            | Self::Retrieve { api_version, .. }
            | Self::Recover { api_version, .. }
            | Self::VerifyArchive { api_version, .. } => api_version,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::Hello { request_id, .. }
            | Self::Reserve { request_id, .. }
            | Self::Authority { request_id, .. }
            | Self::Stage { request_id, .. }
            | Self::Dispatch { request_id, .. }
            | Self::Terminal { request_id, .. }
            | Self::Finalize { request_id, .. }
            | Self::Attest { request_id, .. }
            | Self::Publish { request_id, .. }
            | Self::Retrieve { request_id, .. }
            | Self::Recover { request_id, .. }
            | Self::VerifyArchive { request_id, .. } => request_id,
        }
    }

    pub fn boot_id(&self) -> Option<&str> {
        match self {
            Self::Hello { boot_id, .. }
            | Self::Reserve { boot_id, .. }
            | Self::Authority { boot_id, .. }
            | Self::Stage { boot_id, .. }
            | Self::Dispatch { boot_id, .. }
            | Self::Terminal { boot_id, .. }
            | Self::Finalize { boot_id, .. }
            | Self::Attest { boot_id, .. }
            | Self::Publish { boot_id, .. }
            | Self::Retrieve { boot_id, .. }
            | Self::Recover { boot_id, .. }
            | Self::VerifyArchive { boot_id, .. } => boot_id.as_deref(),
        }
    }

    pub fn mutation_binding(&self) -> Option<&V2OperationBinding> {
        match self {
            Self::Reserve { params, .. } => Some(&params.binding),
            Self::Authority { params, .. } => Some(&params.binding),
            Self::Stage { params, .. } => Some(&params.binding),
            Self::Dispatch { params, .. } => Some(&params.binding),
            Self::Terminal { params, .. } => Some(&params.binding),
            Self::Finalize { params, .. } => Some(&params.binding),
            Self::Attest { params, .. } => Some(&params.binding),
            Self::Publish { params, .. } => Some(&params.binding),
            Self::Hello { .. }
            | Self::Retrieve { .. }
            | Self::Recover { .. }
            | Self::VerifyArchive { .. } => None,
        }
    }

    pub fn read_binding(&self) -> Option<&V2ReadBinding> {
        match self {
            Self::Retrieve { params, .. } => Some(&params.binding),
            Self::VerifyArchive { params, .. } => Some(&params.binding),
            _ => None,
        }
    }

    pub fn exact_object_descriptors(
        &self,
    ) -> Vec<ExactByteObjectDescriptor> {
        match self {
            Self::Hello { .. } | Self::Publish { .. } => Vec::new(),
            Self::Reserve { params, .. } => vec![
                params.route_semantics.clone(),
                params.policy_decision.clone(),
                params.runtime_attestation.clone(),
            ],
            Self::Authority { params, .. } => vec![
                params.authority_plan.clone(),
                params.authorization_evidence.clone(),
            ],
            Self::Stage { params, .. } => vec![
                params.credential_template.clone(),
                params.credential_free_request.clone(),
            ],
            Self::Dispatch { params, .. } => vec![
                params.live_policy_snapshot.clone(),
                params.authorization_evidence.clone(),
            ],
            Self::Terminal { params, .. } => {
                vec![params.lifecycle_state.clone()]
            }
            Self::Finalize { params, .. } => {
                vec![params.proof_document.clone()]
            }
            Self::Attest { params, .. } => {
                vec![params.attestation_challenge.clone()]
            }
            Self::Retrieve { params, .. } => {
                vec![params.public_release_authorization.clone()]
            }
            Self::Recover { params, .. } => {
                match &params.recovery_authorization {
                    V2RecoveryAuthorizationV1::SameBootAuthenticatedClient {
                        ..
                    } => Vec::new(),
                    V2RecoveryAuthorizationV1::CrossBootSigned {
                        authorization,
                    } => vec![authorization.clone()],
                }
            }
            Self::VerifyArchive { params, .. } => vec![
                params.proof_document.clone(),
                params.historical_runtime_attestation.clone(),
                params.finalization_checkpoint.clone(),
            ],
        }
    }

    pub fn error_operation(&self) -> V2ErrorOperation {
        match self {
            Self::Hello { .. } => V2ErrorOperation::Hello,
            Self::Reserve { .. } => V2ErrorOperation::Reserve,
            Self::Authority { .. } => V2ErrorOperation::Authority,
            Self::Stage { .. } => V2ErrorOperation::Stage,
            Self::Dispatch { .. } => V2ErrorOperation::Dispatch,
            Self::Terminal { .. } => V2ErrorOperation::Terminal,
            Self::Finalize { .. } => V2ErrorOperation::Finalize,
            Self::Attest { .. } => V2ErrorOperation::Attest,
            Self::Publish { .. } => V2ErrorOperation::Publish,
            Self::Retrieve { .. } => V2ErrorOperation::Retrieve,
            Self::Recover { .. } => V2ErrorOperation::Recover,
            Self::VerifyArchive { .. } => V2ErrorOperation::VerifyArchive,
        }
    }

    pub fn durable_replay_operation(
        &self,
    ) -> Option<V2DurableReplayOperation> {
        match self {
            Self::Hello { .. } => None,
            Self::Reserve { .. } => {
                Some(V2DurableReplayOperation::Reserve)
            }
            Self::Authority { .. } => {
                Some(V2DurableReplayOperation::Authority)
            }
            Self::Stage { .. } => {
                Some(V2DurableReplayOperation::Stage)
            }
            Self::Dispatch { .. } => {
                Some(V2DurableReplayOperation::Dispatch)
            }
            Self::Terminal { .. } => {
                Some(V2DurableReplayOperation::Terminal)
            }
            Self::Finalize { .. } => {
                Some(V2DurableReplayOperation::Finalize)
            }
            Self::Attest { .. } => {
                Some(V2DurableReplayOperation::Attest)
            }
            Self::Publish { .. } => {
                Some(V2DurableReplayOperation::Publish)
            }
            Self::Retrieve { .. } => {
                Some(V2DurableReplayOperation::Retrieve)
            }
            Self::Recover { .. } => {
                Some(V2DurableReplayOperation::Recover)
            }
            Self::VerifyArchive { .. } => {
                Some(V2DurableReplayOperation::VerifyArchive)
            }
        }
    }
}

pub fn result_exact_object_descriptors(
    result: &V2OperationResult,
) -> Vec<ExactByteObjectDescriptor> {
    match result {
        V2OperationResult::Publish(result) => {
            vec![result.public_release_authorization.clone()]
        }
        V2OperationResult::Retrieve(result) => {
            vec![result.exact_bytes.clone()]
        }
        V2OperationResult::Recover(_) => Vec::new(),
        _ => Vec::new(),
    }
}

impl V2ResponseDataRequest {
    pub fn operation(&self) -> V2ResponseDataOperation {
        match self {
            Self::NativeStaging {..}=>V2ResponseDataOperation::NativeStaging,
            Self::TargetDispatchBegin {..}=>V2ResponseDataOperation::TargetDispatchBegin,
            Self::CapturePersist {..}=>V2ResponseDataOperation::CapturePersist,
            Self::AppendReleaseTransparency { .. } => {
                V2ResponseDataOperation::AppendReleaseTransparency
            }
            Self::InspectImmutableResponse { .. } => {
                V2ResponseDataOperation::InspectImmutableResponse
            }
            Self::ValidateFinalEnvelope { .. } => {
                V2ResponseDataOperation::ValidateFinalEnvelope
            }
            Self::AuthorizeExactRelease { .. } => {
                V2ResponseDataOperation::AuthorizeExactRelease
            }
            Self::ConsumeAndRetrieveExact { .. } => {
                V2ResponseDataOperation::ConsumeAndRetrieveExact
            }
            Self::ResolveExactReplay { .. } => {
                V2ResponseDataOperation::ResolveExactReplay
            }
            Self::SettleAttempt { .. } => {
                V2ResponseDataOperation::SettleAttempt
            }
        }
    }

    pub fn operation_name(&self) -> &'static str {
        match self.operation() {
            V2ResponseDataOperation::NativeStaging=>"responseObservationV2.nativeStaging/v1",
            V2ResponseDataOperation::TargetDispatchBegin=>"responseObservationV2.targetDispatchBegin/v1",
            V2ResponseDataOperation::CapturePersist=>"responseObservationV2.capturePersist/v1",
            V2ResponseDataOperation::AppendReleaseTransparency => {
                V2_APPEND_RELEASE_TRANSPARENCY_OPERATION
            }
            V2ResponseDataOperation::InspectImmutableResponse => {
                V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION
            }
            V2ResponseDataOperation::ValidateFinalEnvelope => {
                V2_VALIDATE_FINAL_ENVELOPE_OPERATION
            }
            V2ResponseDataOperation::AuthorizeExactRelease => {
                V2_AUTHORIZE_EXACT_RELEASE_OPERATION
            }
            V2ResponseDataOperation::ConsumeAndRetrieveExact => {
                V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION
            }
            V2ResponseDataOperation::ResolveExactReplay => {
                V2_RESOLVE_EXACT_REPLAY_OPERATION
            }
            V2ResponseDataOperation::SettleAttempt => {
                V2_SETTLE_ATTEMPT_OPERATION
            }
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::NativeStaging {request_id,..}=>request_id,
            Self::TargetDispatchBegin {request_id,..}|Self::CapturePersist {request_id,..}=>request_id,
            Self::AppendReleaseTransparency { request_id, .. }
            | Self::InspectImmutableResponse { request_id, .. }
            | Self::ValidateFinalEnvelope { request_id, .. }
            | Self::AuthorizeExactRelease { request_id, .. }
            | Self::ConsumeAndRetrieveExact { request_id, .. }
            | Self::ResolveExactReplay { request_id, .. }
            | Self::SettleAttempt { request_id, .. } => request_id,
        }
    }

    pub fn boot_id(&self) -> &str {
        match self {
            Self::NativeStaging {boot_id,..}=>boot_id,
            Self::TargetDispatchBegin {boot_id,..}|Self::CapturePersist {boot_id,..}=>boot_id,
            Self::AppendReleaseTransparency { boot_id, .. }
            | Self::InspectImmutableResponse { boot_id, .. }
            | Self::ValidateFinalEnvelope { boot_id, .. }
            | Self::AuthorizeExactRelease { boot_id, .. }
            | Self::ConsumeAndRetrieveExact { boot_id, .. }
            | Self::ResolveExactReplay { boot_id, .. }
            | Self::SettleAttempt { boot_id, .. } => boot_id,
        }
    }

    pub fn attempt_id(&self) -> &str {
        match self {
            Self::NativeStaging {params,..}=>&params.binding.attempt_id,
            Self::TargetDispatchBegin {params,..}=>&params.original.binding.attempt_id,
            Self::CapturePersist {params,..}=>&params.permit.original.binding.attempt_id,
            Self::AppendReleaseTransparency { params, .. } => {
                &params.binding.attempt_id
            }
            Self::InspectImmutableResponse { params, .. } => {
                &params.binding.attempt_id
            }
            Self::ValidateFinalEnvelope { params, .. } => {
                &params.binding.attempt_id
            }
            Self::AuthorizeExactRelease { params, .. } => {
                &params.binding.attempt_id
            }
            Self::ConsumeAndRetrieveExact { params, .. } => {
                match params {
                    V2ConsumeAndRetrieveExactParams::Prepare {
                        binding,
                        ..
                    } => &binding.attempt_id,
                    V2ConsumeAndRetrieveExactParams::Retrieve {
                        binding,
                        ..
                    } => &binding.attempt_id,
                }
            }
            Self::ResolveExactReplay { params, .. } => {
                &params.stable_request.attempt_id
            }
            Self::SettleAttempt { params, .. } => {
                &params.attempt.attempt_id
            }
        }
    }

    pub fn stable_resume_id(&self) -> &str {
        match self {
            Self::NativeStaging {params,..}=>&params.stable_resume_id,
            Self::TargetDispatchBegin {params,..}=>&params.original.stable_resume_id,
            Self::CapturePersist {params,..}=>&params.stable_resume_id,
            Self::AppendReleaseTransparency { params, .. } => {
                &params.stable_resume_id
            }
            Self::InspectImmutableResponse { params, .. } => {
                &params.stable_resume_id
            }
            Self::ValidateFinalEnvelope { params, .. } => {
                &params.stable_resume_id
            }
            Self::AuthorizeExactRelease { params, .. } => {
                &params.stable_resume_id
            }
            Self::ConsumeAndRetrieveExact { params, .. } => {
                match params {
                    V2ConsumeAndRetrieveExactParams::Prepare {
                        stable_resume_id,
                        ..
                    }
                    | V2ConsumeAndRetrieveExactParams::Retrieve {
                        stable_resume_id,
                        ..
                    } => stable_resume_id,
                }
            }
            Self::ResolveExactReplay { params, .. } => {
                &params.stable_request.stable_resume_id
            }
            Self::SettleAttempt { params, .. } => {
                &params.stable_resume_id
            }
        }
    }

    pub fn fencing_token(&self) -> u64 {
        match self {
            Self::NativeStaging {params,..}=>params.binding.fencing_token,
            Self::TargetDispatchBegin {params,..}=>params.original.binding.fencing_token,
            Self::CapturePersist {params,..}=>params.permit.original.binding.fencing_token,
            Self::AppendReleaseTransparency { params, .. } => {
                params.binding.fencing_token
            }
            Self::InspectImmutableResponse { params, .. } => {
                params.binding.fencing_token
            }
            Self::ValidateFinalEnvelope { params, .. } => {
                params.binding.fencing_token
            }
            Self::AuthorizeExactRelease { params, .. } => {
                params.binding.fencing_token
            }
            Self::ConsumeAndRetrieveExact { params, .. } => {
                match params {
                    V2ConsumeAndRetrieveExactParams::Prepare {
                        binding,
                        ..
                    } => binding.fencing_token,
                    V2ConsumeAndRetrieveExactParams::Retrieve {
                        binding,
                        ..
                    } => binding.fencing_token,
                }
            }
            Self::ResolveExactReplay { params, .. } => {
                params.stable_request.fencing_token
            }
            Self::SettleAttempt { params, .. } => {
                params.attempt.fencing_token
            }
        }
    }

    pub fn deadline(&self) -> (&V2MonotonicDeadlineV1, u64) {
        match self {
            Self::NativeStaging {params,..}=>(&params.binding.monotonic_deadline,params.binding.deadline_at_epoch_ms),
            Self::TargetDispatchBegin {params,..}=>(&params.original.binding.monotonic_deadline,params.original.binding.deadline_at_epoch_ms),
            Self::CapturePersist {params,..}=>(&params.permit.original.binding.monotonic_deadline,params.permit.original.binding.deadline_at_epoch_ms),
            Self::AppendReleaseTransparency { params, .. } => (
                &params.binding.monotonic_deadline,
                params.binding.deadline_at_epoch_ms,
            ),
            Self::InspectImmutableResponse { params, .. } => (
                &params.binding.monotonic_deadline,
                params.binding.deadline_at_epoch_ms,
            ),
            Self::ValidateFinalEnvelope { params, .. } => (
                &params.binding.monotonic_deadline,
                params.binding.deadline_at_epoch_ms,
            ),
            Self::AuthorizeExactRelease { params, .. } => (
                &params.binding.monotonic_deadline,
                params.binding.deadline_at_epoch_ms,
            ),
            Self::ConsumeAndRetrieveExact { params, .. } => {
                match params {
                    V2ConsumeAndRetrieveExactParams::Prepare {
                        binding,
                        ..
                    } => (
                        &binding.monotonic_deadline,
                        binding.deadline_at_epoch_ms,
                    ),
                    V2ConsumeAndRetrieveExactParams::Retrieve {
                        binding,
                        ..
                    } => (
                        &binding.monotonic_deadline,
                        binding.deadline_at_epoch_ms,
                    ),
                }
            }
            Self::ResolveExactReplay { params, .. } => (
                &params.monotonic_deadline,
                params.deadline_at_epoch_ms,
            ),
            Self::SettleAttempt { params, .. } => (
                &params.settlement_deadline,
                params.settlement_deadline_at_epoch_ms,
            ),
        }
    }

    pub fn exact_object_descriptors(
        &self,
    ) -> Vec<ExactByteObjectDescriptor> {
        match self {
            Self::NativeStaging {params,..}=>params.request.evidence.statement.original.request.exact_object_descriptors(),
            Self::TargetDispatchBegin {..}=>Vec::new(),
            Self::CapturePersist {params,..}=>vec![params.raw_response.clone()],
            Self::ValidateFinalEnvelope { params, .. } => {
                vec![params.authority_proof.clone()]
            }
            Self::AppendReleaseTransparency { .. }
            | Self::InspectImmutableResponse { .. }
            | Self::AuthorizeExactRelease { .. }
            | Self::ConsumeAndRetrieveExact { .. }
            | Self::ResolveExactReplay { .. }
            | Self::SettleAttempt { .. } => Vec::new(),
        }
    }
}

impl V2ResponseDataResult {
    pub fn operation(&self) -> V2ResponseDataOperation {
        match self {
            Self::NativeStaging(_)=>V2ResponseDataOperation::NativeStaging,
            Self::TargetDispatchBegin(_)=>V2ResponseDataOperation::TargetDispatchBegin,
            Self::CapturePersist(_)=>V2ResponseDataOperation::CapturePersist,
            Self::AppendReleaseTransparency(_) => {
                V2ResponseDataOperation::AppendReleaseTransparency
            }
            Self::InspectImmutableResponse(_) => {
                V2ResponseDataOperation::InspectImmutableResponse
            }
            Self::ValidateFinalEnvelope(_) => {
                V2ResponseDataOperation::ValidateFinalEnvelope
            }
            Self::AuthorizeExactRelease(_) => {
                V2ResponseDataOperation::AuthorizeExactRelease
            }
            Self::ConsumeAndRetrieveExact(_) => {
                V2ResponseDataOperation::ConsumeAndRetrieveExact
            }
            Self::ResolveExactReplay(_) => {
                V2ResponseDataOperation::ResolveExactReplay
            }
            Self::SettleAttempt(_) => {
                V2ResponseDataOperation::SettleAttempt
            }
        }
    }
}

pub fn response_data_result_exact_object_descriptors(
    result: &V2ResponseDataResult,
) -> Vec<ExactByteObjectDescriptor> {
    match result {
        V2ResponseDataResult::ConsumeAndRetrieveExact(
            V2ConsumeAndRetrieveExactResult::Retrieved {
                exact_bytes,
                ..
            },
        ) => vec![exact_bytes.clone()],
        _ => Vec::new(),
    }
}

pub fn response_observation_v2_stable_resume_id_sha256(
    generation_id: &str,
    generation: u64,
    request_sha256: &str,
    attempt_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    let generation_bytes = generation.to_be_bytes();
    append_lifecycle_hash_frame(
        &mut hasher,
        b"serverware.response-v2/stable-resume/v1",
    );
    for value in [
        generation_id.as_bytes(),
        generation_bytes.as_slice(),
        request_sha256.as_bytes(),
        attempt_id.as_bytes(),
    ] {
        append_lifecycle_hash_frame(&mut hasher, value);
    }
    format!("sha256:{:x}", hasher.finalize())
}
