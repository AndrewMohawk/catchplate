use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::common::{
    provider_authority_scope, readiness_signer_role,
};
use super::super::attestation::{
    verify_final_envelope_verification,
    verify_immutable_raw_inspection,
    verify_state_mutation_receipt,
};
use super::super::config::{
    CustodyServiceRole, ScopedCustodyServiceConfig,
};
use super::super::protocol::{
    canonical_authority_envelope_preimage_sha256,
    ordered_authority_artifacts_root_sha256,
    released_projection_sha256_v2,
    validate_canonical_authority_envelope,
    CanonicalAuthorityEnvelopeDescriptorV2,
    CanonicalAuthorityEnvelopeProofInputV2,
    CanonicalAuthorityEnvelopeProofSeedV2,
    AttemptStateQueryRequestV1,
    ConsumeReleaseAndRetrieveExactRequestV1,
    FinalEnvelopeVerificationRequestV1,
    InspectImmutableRawRequestV1, ProviderAuthorityScopeV2,
    PublishRequestV1, ReleaseAuthorizationRequestV2,
    ReleaseConsumptionPreauthorizationArtifactRequestV1,
    ReleasePreparationMutationBindingV1,
    ServiceOperationV1, ServiceRpcEnvelopeV1,
    SettlementEvidenceContextRequestV1,
    SettlementRequestV1, SignedDurableTerminalReceiptV1,
    SignedFinalEnvelopeVerificationV1,
    SignedImmutableRawInspectionV1, SignedPublicationReceiptV1,
    SignedReleaseAuthorizationV2, SignedReleaseConsumptionV2,
    StateMutationExecutionRequestV1,
    StateMutationExecutionResultV1,
    UnsignedStateAuthorityIntentV1,
    FINAL_ENVELOPE_VERIFICATION_API_VERSION,
    IMMUTABLE_RAW_INSPECTION_API_VERSION,
    PUBLICATION_API_VERSION, RELEASE_AUTHORIZATION_API_VERSION,
    RELEASE_CONSUMPTION_API_VERSION, SETTLEMENT_API_VERSION,
    STATE_AUTHORITY_API_VERSION,
    ATTEMPT_STATE_OBSERVATION_API_VERSION,
    CANONICAL_AUTHORITY_PROOF_SEED_API_VERSION,
};
use super::super::{
    RootOwnedResponseObservationV2Config, V2RuntimeError,
};
use super::super::attestation::RoleSigningKey;
use super::super::super::state_authority::canonical::{
    canonical_jcs_bytes, decode_base64url, encode_base64url,
    sha256_digest, signature_message,
    NESTED_AUTHORITY_SIGNATURE_DOMAIN,
    STATE_AUTHORITY_SIGNATURE_DOMAIN,
};
use super::super::super::state_authority::contract::{
    BootDeadline as AuthorityBootDeadline, Identifier,
    Digest as AuthorityDigest, FINAL_ENVELOPE_API_VERSION,
    FINAL_ENVELOPE_KIND, SIGNATURE_ALGORITHM,
    STATE_AUTHORITY_API_VERSION as AUTHORITY_API_VERSION,
    STATE_AUTHORITY_RPC_KIND, STATE_AUTHORITY_SCHEMA_VERSION,
};
use super::super::super::state_authority::rpc::{
    CanonicalFinalEnvelope,
    FenceExpectation, FenceExpectationMode, FrameAuthentication,
    RpcRequest, RpcRequestFrame, SignedAuthorityArtifact,
};
use super::super::super::state_authority::topology::ServiceRole;
use super::super::super::state_authority::transparency_contract::
    canonical_transparency_sha256;

pub(super) struct EngineResult {
    pub result: serde_json::Value,
    pub exact_object_fds: Vec<OwnedFd>,
}

struct LocalAuthorityArtifactSigner<'a> {
    key: &'a RoleSigningKey,
    role_id: Identifier,
    key_id: Identifier,
    identity:
        super::super::super::state_authority::rpc::
            AuthoritySignerIdentity,
}

impl super::super::super::state_authority::AuthorityResultSigner
    for LocalAuthorityArtifactSigner<'_>
{
    fn role_id(&self) -> &Identifier {
        &self.role_id
    }

    fn key_id(&self) -> &Identifier {
        &self.key_id
    }

    fn identity(
        &self,
    ) -> &super::super::super::state_authority::rpc::
        AuthoritySignerIdentity {
        &self.identity
    }

    fn sign_digest(
        &self,
        digest: &[u8; 32],
        deadline: &AuthorityBootDeadline,
    ) -> super::super::super::state_authority::
        AuthorityResult<Vec<u8>> {
        let instant =
            super::super::super::state_authority::BootInstant {
                clock: "CLOCK_BOOTTIME".to_owned(),
                boot_id: Identifier(
                    super::super::recovery::kernel_boot_id().map_err(
                        |error| {
                            super::super::super::state_authority::
                                AuthorityError::Backend {
                                    code:
                                        "read_kernel_boot_id",
                                    reason: error.to_string(),
                                }
                        },
                    )?,
                ),
                boot_millis:
                    super::super::recovery::boottime_ns()
                        .map_err(|error| {
                            super::super::super::state_authority::
                                AuthorityError::Backend {
                                    code: "read_boottime",
                                    reason: error.to_string(),
                                }
                        })?
                        / 1_000_000,
            };
        deadline.ensure_current(&instant)?;
        let signature = self.key.sign_digest_bytes(digest);
        let after = super::super::super::state_authority::BootInstant {
            clock: "CLOCK_BOOTTIME".to_owned(),
            boot_id: instant.boot_id,
            boot_millis: super::super::recovery::boottime_ns()
                .map_err(|error| {
                    super::super::super::state_authority::
                        AuthorityError::Backend {
                            code: "read_boottime",
                            reason: error.to_string(),
                        }
                })?
                / 1_000_000,
        };
        deadline.ensure_current(&after)?;
        Ok(signature)
    }
}

pub(super) fn execute(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    request_exact_object_fds: Vec<OwnedFd>,
) -> Result<EngineResult, V2RuntimeError> {
    if scoped.role == CustodyServiceRole::ImmutableArtifactLedger
        && request.operation == ServiceOperationV1::ImmutablePut {
        return super::ledger_put::execute(config,scoped,request,signing_keys,request_exact_object_fds);
    }
    if let Ok(response_data_request) =
        serde_json::from_value::<
            crate::response_observation_v2_api::V2ResponseDataRequest,
        >(request.payload.clone())
    {
        return execute_response_data_request(
            config,
            scoped,
            request,
            response_data_request,
            signing_keys,
            request_exact_object_fds,
        );
    }
    if !request_exact_object_fds.is_empty() {
        return Err(V2RuntimeError::new(
            "custody_engine_exact_object_unexpected",
            "legacy service operation received an undeclared exact object",
        ));
    }
    match (scoped.role, request.operation) {
        (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::StateCas,
        ) => execute_state_mutation(config, request, signing_keys),
        (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        ) => execute_consumption(
            config,
            scoped,
            request,
            signing_keys,
        ),
        (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::Reconcile,
        ) => execute_settlement(
            config,
            scoped,
            request,
            signing_keys,
            ServiceOperationV1::Reconcile,
        ),
        (
            CustodyServiceRole::PolicyProofVerifier,
            ServiceOperationV1::FinalEnvelopeVerify,
        ) => execute_final_verification(request),
        (
            CustodyServiceRole::ImmutableArtifactLedger,
            ServiceOperationV1::InspectImmutableRaw,
        ) => execute_inspection(
            config,
            scoped,
            request,
            signing_keys,
        ),
        (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::AuthorizeRelease,
        ) => execute_release_authorization(
            config,
            scoped,
            request,
            signing_keys,
        ),
        (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::Publish,
        ) => execute_publication(
            config,
            scoped,
            request,
            signing_keys,
        ),
        (
            CustodyServiceRole::CleanupWatchdog,
            ServiceOperationV1::Cleanup,
        ) => execute_settlement(
            config,
            scoped,
            request,
            signing_keys,
            ServiceOperationV1::Cleanup,
        ),
        _ => Err(V2RuntimeError::new(
            "custody_service_operation_unimplemented",
            "operation is not implemented by the in-process bounded role engine",
        )),
    }
}

fn execute_response_data_request(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    envelope: &ServiceRpcEnvelopeV1,
    request:
        crate::response_observation_v2_api::V2ResponseDataRequest,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    request_exact_object_fds: Vec<OwnedFd>,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::
        V2ResponseDataRequest as Request;
    if matches!(&request,Request::TargetDispatchBegin {..}|Request::CapturePersist {..}) {
        if scoped.role!=CustodyServiceRole::CredentialTransport || envelope.operation!=ServiceOperationV1::TargetDispatch {
            return Err(V2RuntimeError::new("target_dispatch_wrong_service","target capture must use actual CredentialTransport service"));
        }
        let result=super::super::target_dispatch::execute(config,scoped,&request,signing_keys,request_exact_object_fds)?;
        return Ok(EngineResult {result:serde_json::to_value(result).map_err(|_|V2RuntimeError::new("target_dispatch_encoding","encode actual result"))?,exact_object_fds:Vec::new()});
    }
    let expected = match &request {
        Request::TargetDispatchBegin {..}|Request::CapturePersist {..}=>unreachable!("source fixed target dispatch branch above"),
        Request::AppendReleaseTransparency { .. } => (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::Publish,
            0,
        ),
        Request::InspectImmutableResponse { .. } => (
            CustodyServiceRole::ImmutableArtifactLedger,
            ServiceOperationV1::InspectImmutableRaw,
            0,
        ),
        Request::ValidateFinalEnvelope { .. } => (
            CustodyServiceRole::PolicyProofVerifier,
            ServiceOperationV1::FinalEnvelopeVerify,
            1,
        ),
        Request::AuthorizeExactRelease { .. } => (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::AuthorizeRelease,
            0,
        ),
        Request::ConsumeAndRetrieveExact { .. } => (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
            0,
        ),
        Request::ResolveExactReplay { .. } => (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::ReplayResolve,
            0,
        ),
        Request::SettleAttempt { .. } => (
            CustodyServiceRole::CleanupWatchdog,
            ServiceOperationV1::Reconcile,
            0,
        ),
    };
    if scoped.role != expected.0
        || envelope.operation != expected.1
        || request_exact_object_fds.len() != expected.2
    {
        return Err(V2RuntimeError::new(
            "response_data_engine_dispatch_mismatch",
            "response-data request is not assigned to the exact service operation or proof-object cardinality",
        ));
    }
    let public_request_sha256 = canonical_sha256(&request)?;
    match request {
        Request::TargetDispatchBegin {..}|Request::CapturePersist {..}=>unreachable!("source fixed target dispatch branch above"),
        Request::AppendReleaseTransparency {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_release_transparency(
            config,
            scoped,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
        Request::ValidateFinalEnvelope {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_final_envelope_validation(
            config,
            scoped,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
            request_exact_object_fds,
        ),
        Request::InspectImmutableResponse {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_inspection(
            config,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
        Request::AuthorizeExactRelease {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_release_authorization(
            config,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
        Request::ConsumeAndRetrieveExact {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_consumption(
            config,
            scoped,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
        Request::ResolveExactReplay {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_replay_resolution(
            config,
            scoped,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
        Request::SettleAttempt {
            api_version,
            request_id,
            boot_id,
            params,
        } => execute_public_settlement(
            config,
            scoped,
            envelope,
            signing_keys,
            &api_version,
            &request_id,
            &boot_id,
            &public_request_sha256,
            params,
        ),
    }
}

fn execute_public_release_transparency(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    _request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2AppendReleaseTransparencyParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        AttemptStateReference, V2AppendReleaseTransparencyResult,
        V2AttemptState, V2ResponseDataResult,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, OperationKind,
    };
    use super::super::super::state_authority::rpc::{
        AppendEvidenceMutation, AuthorityArtifactType, MutationPayload,
        NestedAuthorityPayload,
    };

    let deadline_boottime_ns =
        public_deadline_boottime_ns(&params.binding.monotonic_deadline)?;
    let expected_pin_sha256 = canonical_transparency_sha256(
        config.release_transparency_trust_pin(),
    )
    .map_err(|error| {
        V2RuntimeError::new(
            "release_transparency_trust_pin_invalid",
            error.to_string(),
        )
    })?;
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || request_id != params.binding.request_id
        || boot_id != params.binding.custody_boot_id
        || boot_id != params.binding.monotonic_deadline.custody_boot_id
        || params.binding.predecessor_lifecycle_state
            != V2AttemptState::Completed
        || params.stable_resume_id.is_empty()
        || params.raw_response.retrieval_id.is_empty()
        || params.transparency_trust_pin_sha256
            != expected_pin_sha256
    {
        return Err(V2RuntimeError::new(
            "release_transparency_request_invalid",
            "release transparency append is not bound to the exact completed attempt, raw response, independent trust pin, boot, and deadline",
        ));
    }

    let observation_request =
        |suffix: &str, include_proof_material: bool| {
        AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: format!("{request_id}:{suffix}"),
            operation_id: format!("{request_id}:{suffix}-observation"),
            attempt_id: params.binding.attempt_id.clone(),
            expected_stable_resume_id:
                params.stable_resume_id.clone(),
            raw_response_object_id: include_proof_material.then(|| {
                params.raw_response.retrieval_id.clone()
            }),
            include_proof_material,
            deadline_boottime_ns,
        }
    };
    let predecessor = super::query_attempt_state(
        config,
        &observation_request("transparency-predecessor", true),
    )?;
    if predecessor.authoritative_state != AttemptState::Observed
        || predecessor.fencing_token != params.binding.fencing_token
        || predecessor.attempt_id != params.binding.attempt_id
        || predecessor.stable_resume_id != params.stable_resume_id
    {
        return Err(V2RuntimeError::new(
            "release_transparency_state_mismatch",
            "release transparency append requires the exact signed OBSERVED attempt and fence",
        ));
    }

    let artifact_id = format!("{request_id}:release-transparency");
    let evidence_id = format!("{request_id}:release-transparency-evidence");
    let (post, transparency_artifact) = if predecessor.attempt_revision
        == params.binding.attempt_revision
    {
        let predecessor_proof = predecessor
            .proof_material
            .as_ref()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "release_transparency_predecessor_proof_missing",
                    "state authority omitted the exact raw-response provenance required for release transparency",
                )
            })?;
        if predecessor.authoritative_state_sha256
                != params.binding.predecessor_state_sha256
            || params.raw_response.object_sha256
                != params
                    .binding
                    .transaction
                    .upstream_response_sha256
                    .clone()
                    .unwrap_or_default()
            || predecessor_proof.raw_response_object.object_id.0
                != params.raw_response.retrieval_id
            || predecessor_proof.raw_response_object.content_sha256.0
                != params.raw_response.object_sha256
            || predecessor_proof.raw_response_object.content_length
                != params.raw_response.byte_length
            || predecessor_proof
                .raw_response_immutable_storage_receipt_sha256
                .0
                != params.raw_response.persistence_receipt_sha256
        {
            return Err(V2RuntimeError::new(
                "release_transparency_predecessor_mismatch",
                "release transparency predecessor differs from the caller's exact completed projection",
            ));
        }
        let transparency_key =
            require_signing_key(signing_keys, "transparency")?;
        let transparency_artifact = sign_nested_artifact(
            config,
            CustodyServiceRole::ReleaseAttestorPublisher,
            transparency_key,
            OperationKind::TransparencyCheckpoint,
            &artifact_id,
            &predecessor.attempt_id,
            predecessor.attempt_revision,
            predecessor.fencing_token,
            config
                .release_transparency_artifact()
                .release_transparency_proof
                .checkpoint
                .payload
                .expires_at_epoch_ms,
            NestedAuthorityPayload::TransparencyCheckpoint(
                config.release_transparency_artifact().clone(),
            ),
            Some(
                config
                    .release_transparency_artifact()
                    .release_transparency_proof
                    .checkpoint
                    .payload
                    .issued_at_epoch_ms,
            ),
            deadline_boottime_ns,
        )?;
        let intent = UnsignedStateAuthorityIntentV1 {
            expected_state: AttemptState::Observed,
            payload: MutationPayload::AppendEvidence(
                AppendEvidenceMutation {
                    evidence_id: Identifier(evidence_id.clone()),
                    evidence_type: Identifier(
                        AuthorityArtifactType::TransparencyCheckpoint
                            .as_str()
                            .to_owned(),
                    ),
                    object: None,
                    evidence: transparency_artifact.clone(),
                },
            ),
        };
        let operation_id = artifact_id.clone();
        let frame = signed_state_authority_frame(
            config,
            scoped,
            request_id,
            &operation_id,
            &predecessor.attempt_id,
            predecessor.attempt_revision,
            predecessor.fencing_token,
            deadline_boottime_ns,
            &intent,
            signing_keys,
        )?;
        let state_request = state_execution_request(
            request_id,
            &operation_id,
            &predecessor.attempt_id,
            &predecessor.stable_resume_id,
            predecessor.attempt_revision,
            predecessor.fencing_token,
            deadline_boottime_ns,
            frame,
        );
        let (_, exact) =
            super::execute_state_mutation(config, &state_request, false)?;
        if exact.is_some() {
            return Err(V2RuntimeError::new(
                "release_transparency_exact_object_unexpected",
                "release transparency evidence append returned raw bytes",
            ));
        }
        let post = super::query_attempt_state(
            config,
            &observation_request("transparency-successor", false),
        )?;
        (post, transparency_artifact)
    } else if predecessor.attempt_revision
        == params.binding.attempt_revision.saturating_add(1)
    {
        let recovered = super::query_attempt_state(
            config,
            &observation_request("transparency-recovery", true),
        )?;
        let artifact = recovered
            .proof_material
            .as_ref()
            .and_then(|proof| {
                proof.authority_artifacts.iter().find(|artifact| {
                    artifact.body.artifact_class
                        == AuthorityArtifactType::TransparencyCheckpoint
                        && artifact.body.artifact_id.0 == artifact_id
                })
            })
            .cloned()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "release_transparency_recovery_missing",
                    "successor revision does not contain the exact previously appended transparency artifact",
                )
            })?;
        (recovered, artifact)
    } else {
        return Err(V2RuntimeError::new(
            "release_transparency_revision_conflict",
            "release transparency append observed neither its exact predecessor nor its sole recoverable successor",
        ));
    };

    if post.authoritative_state != AttemptState::Observed
        || post.attempt_revision
            != params.binding.attempt_revision.saturating_add(1)
        || post.fencing_token != params.binding.fencing_token
        || post.stable_resume_id != params.stable_resume_id
        || transparency_artifact.body.artifact_id.0 != artifact_id
        || transparency_artifact.body.attempt_revision
            != params.binding.attempt_revision
        || transparency_artifact.body.operation
            != OperationKind::TransparencyCheckpoint
        || transparency_artifact.body.payload
            != NestedAuthorityPayload::TransparencyCheckpoint(
                config.release_transparency_artifact().clone(),
            )
    {
        return Err(V2RuntimeError::new(
            "release_transparency_successor_mismatch",
            "release transparency result is not the exact single-revision evidence successor",
        ));
    }
    verify_pinned_authority_artifact(
        config.custody_topology(),
        &transparency_artifact,
        &post.attempt_id,
        post.fencing_token,
    )?;
    let transparency_artifact_sha256 =
        canonical_sha256(&transparency_artifact)?;
    encode_result(
        V2ResponseDataResult::AppendReleaseTransparency(
            V2AppendReleaseTransparencyResult {
                attempt: AttemptStateReference {
                    attempt_id: post.attempt_id,
                    state: V2AttemptState::Completed,
                    state_sha256: post.authoritative_state_sha256,
                    attempt_revision: post.attempt_revision,
                    fencing_token: post.fencing_token,
                },
                evidence_id,
                transparency_artifact,
                transparency_artifact_sha256,
            },
        ),
        Vec::new(),
    )
}

fn execute_public_inspection(
    config: &RootOwnedResponseObservationV2Config,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2InspectImmutableResponseParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        SignedV2ImmutableResponseInspectionV1,
        V2InspectImmutableResponseResult, V2ResponseDataOperation,
        V2ResponseDataResult, V2AttemptState,
        V2_IMMUTABLE_RESPONSE_INSPECTION_SIGNATURE_DOMAIN,
        V2_IMMUTABLE_RESPONSE_INSPECTION_VERSION,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };

    let deadline_boottime_ns =
        public_deadline_boottime_ns(&params.binding.monotonic_deadline)?;
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || boot_id != params.binding.custody_boot_id
        || boot_id != params.binding.monotonic_deadline.custody_boot_id
        || params.stable_resume_id.is_empty()
        || params.binding.attempt_id.is_empty()
        || params.raw_response.retrieval_id.is_empty()
    {
        return Err(V2RuntimeError::new(
            "response_data_inspection_request_invalid",
            "immutable inspection request is not bound to one live boot, attempt, raw object, and deadline",
        ));
    }
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: request_id.to_owned(),
            operation_id: format!("{request_id}:inspection-observation"),
            attempt_id: params.binding.attempt_id.clone(),
            expected_stable_resume_id:
                params.stable_resume_id.clone(),
            raw_response_object_id:
                Some(params.raw_response.retrieval_id.clone()),
            include_proof_material: true,
            deadline_boottime_ns,
        },
    )?;
    if observation.attempt_revision != params.binding.attempt_revision
        || observation.fencing_token != params.binding.fencing_token
        || observation.authoritative_state_sha256
            != params.binding.state_sha256
        || observation.authoritative_state
            != super::super::super::state_authority::lifecycle::
                AttemptState::Observed
        || params.binding.lifecycle_state != V2AttemptState::Completed
    {
        return Err(V2RuntimeError::new(
            "response_data_inspection_state_mismatch",
            "public COMPLETED projection does not match the signed internal OBSERVED attempt",
        ));
    }
    let proof = observation.proof_material.clone().ok_or_else(|| {
        V2RuntimeError::new(
            "response_data_inspection_proof_missing",
            "state authority omitted persisted inspection proof material",
        )
    })?;
    if proof.raw_response_object.object_id.0
            != params.raw_response.retrieval_id
        || proof.raw_response_object.content_sha256.0
            != params.raw_response.object_sha256
        || proof.raw_response_object.content_length
            != params.raw_response.byte_length
        || proof.raw_response_immutable_storage_receipt_sha256.0
            != params.raw_response.persistence_receipt_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_inspection_object_mismatch",
            "public raw-object reference differs from state-derived immutable provenance",
        ));
    }
    for artifact in &proof.authority_artifacts {
        verify_pinned_authority_artifact(
            config.custody_topology(),
            artifact,
            &observation.attempt_id,
            observation.fencing_token,
        )?;
    }
    let raw = super::state_authority::retrieve_observed_raw_object(
        config,
        &proof,
        deadline_boottime_ns,
    )?;
    let parsed = crate::response_v2_http11::
        response_observation_v2_parse_http11(
            &raw,
            Some(&params.request_method),
        )
        .map_err(|reason| {
            V2RuntimeError::new(
                "response_data_inspection_http11_invalid",
                reason,
            )
        })?;
    let transfer_coding = match parsed.framing.transfer_coding {
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::Identity => {
                super::super::super::state_authority::rpc::
                    TransferCoding::Identity
            }
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::Chunked => {
                super::super::super::state_authority::rpc::
                    TransferCoding::Chunked
            }
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::NoBody => {
                return Err(V2RuntimeError::new(
                    "response_data_inspection_no_body_schema_missing",
                    "state-authority framing cannot losslessly represent NO_BODY",
                ))
            }
    };
    let parsed_response_sha256 =
        canonical_sha256(&parsed.parsed_response)?;
    let released_projection_sha256 =
        released_projection_sha256_v2(
            &proof.raw_response_object.content_sha256.0,
            proof.raw_response_object.content_length,
            &params.request_method,
            parsed.status,
            &parsed.framing.canonical_framing_sha256,
            &parsed_response_sha256,
            &parsed.parsed_response.decoded_entity_sha256,
        )?;
    let mut seed = CanonicalAuthorityEnvelopeProofSeedV2 {
        api_version:
            CANONICAL_AUTHORITY_PROOF_SEED_API_VERSION.to_owned(),
        generation_id: observation.generation_id.clone(),
        generation: observation.generation,
        attempt_id: observation.attempt_id.clone(),
        attempt_revision: observation.attempt_revision,
        fencing_token: observation.fencing_token,
        stable_resume_id: observation.stable_resume_id.clone(),
        staged_request_object: proof.staged_request_object,
        raw_response_object: proof.raw_response_object,
        http11_framing:
            super::super::super::state_authority::rpc::
                Http11FramingResult {
                http_version: parsed.framing.http_version.clone(),
                informational_statuses:
                    parsed.framing.informational_statuses.clone(),
                final_status: parsed.framing.final_status,
                header_section_length:
                    parsed.framing.header_section_length,
                transfer_coding,
                declared_content_length:
                    parsed.framing.declared_content_length,
                decoded_entity_length:
                    parsed.framing.decoded_entity_length,
                trailer_section_length:
                    parsed.framing.trailer_section_length,
                trailer_names: parsed.framing.trailer_names.clone(),
                physical_message_length:
                    parsed.framing.physical_message_length,
                surplus_length: parsed.framing.surplus_length,
                canonical_framing_sha256: AuthorityDigest(
                    parsed
                        .framing
                        .canonical_framing_sha256
                        .clone(),
                ),
            },
        credential_use_id: proof.credential_use_id,
        target_effect_id: proof.target_effect_id,
        policy_decision_id: proof.policy_decision_id,
        inspection_receipt_sha256:
            proof.inspection_canonical_result_sha256.0,
        authority_artifacts: proof.authority_artifacts,
        authority_artifacts_root_sha256:
            proof.authority_artifacts_root_sha256,
        seed_sha256: String::new(),
    };
    seed.seed_sha256 = seed.recompute_seed_sha256()?;
    seed.validate_integrity()?;
    let descriptor =
        crate::response_observation_v2_api::ExactByteObjectDescriptor {
            object_id: params.raw_response.retrieval_id.clone(),
            media_type:
                crate::response_observation_v2_api::
                    ExactObjectMediaType::Http11Response,
            fd_index: 0,
            byte_length: params.raw_response.byte_length,
            sha256: params.raw_response.object_sha256.clone(),
            required_seals:
                crate::response_observation_v2_api::
                    MemfdSealProfile::ImmutableV1,
        };
    let archive_key = require_signing_key(signing_keys, "archive-store")?;
    let archive_scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::ImmutableArtifactLedger,
        archive_key,
        ServiceOperationV1::InspectImmutableRaw,
        &format!("{request_id}:immutable-inspection"),
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut authority_receipt = SignedImmutableRawInspectionV1 {
        api_version: IMMUTABLE_RAW_INSPECTION_API_VERSION.to_owned(),
        generation_id: observation.generation_id.clone(),
        generation: observation.generation,
        operation: ServiceOperationV1::InspectImmutableRaw,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: observation.attempt_id.clone(),
        stable_resume_id: observation.stable_resume_id.clone(),
        authority_scope: archive_scope,
        raw_object_id: params.raw_response.retrieval_id.clone(),
        raw_object_sha256: params.raw_response.object_sha256.clone(),
        raw_object_byte_length: params.raw_response.byte_length,
        exact_object: descriptor.clone(),
        request_method: params.request_method.clone(),
        framing_validation_sha256:
            parsed.framing.canonical_framing_sha256.clone(),
        parsed_response_sha256: parsed_response_sha256.clone(),
        released_projection_sha256:
            released_projection_sha256.clone(),
        final_status: parsed.status,
        decoded_body_sha256:
            parsed.parsed_response.decoded_entity_sha256.clone(),
        decoded_body_byte_length:
            parsed.parsed_response.decoded_entity_length,
        immutable: true,
        consumed: false,
        inspection_sequence: observation.attempt_revision,
        inspection_receipt_sha256:
            seed.inspection_receipt_sha256.clone(),
        state_observation: observation.clone(),
        state_authority_receipt: None,
        authority_proof_seed: seed.clone(),
        signer_logical_role: archive_key.logical_role().to_owned(),
        signer_key_id: archive_key.key_id().to_owned(),
        signature: String::new(),
    };
    authority_receipt.signature = archive_key.sign(
        super::super::attestation::
            IMMUTABLE_RAW_INSPECTION_SIGNATURE_DOMAIN,
        &authority_receipt.without_signature(),
    )?;
    verify_immutable_raw_inspection(
        config.custody_topology(),
        &authority_receipt,
    )?;
    let public_key = require_signing_key(signing_keys, "persistence")?;
    let public_scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::ImmutableArtifactLedger,
        public_key,
        ServiceOperationV1::InspectImmutableRaw,
        request_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let provider_operation_binding_sha256 =
        public_scope.operation_binding_sha256.clone();
    let provider_scope = public_scope.clone();
    let mut public = SignedV2ImmutableResponseInspectionV1 {
        api_version:
            V2_IMMUTABLE_RESPONSE_INSPECTION_VERSION.to_owned(),
        generation_id: observation.generation_id,
        generation: observation.generation,
        operation: V2ResponseDataOperation::InspectImmutableResponse,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: observation.attempt_id,
        attempt_revision: observation.attempt_revision,
        stable_resume_id: observation.stable_resume_id,
        fencing_token: observation.fencing_token,
        raw_response: params.raw_response,
        exact_object: descriptor,
        request_method: params.request_method,
        http11_framing: parsed.framing,
        parsed_response: parsed.parsed_response,
        framing_validation_sha256:
            authority_receipt.framing_validation_sha256.clone(),
        parsed_response_sha256,
        released_projection_sha256,
        response_status: authority_receipt.final_status,
        response_body_sha256:
            authority_receipt.decoded_body_sha256.clone(),
        immutable: true,
        consumed: false,
        inspection_sequence: authority_receipt.inspection_sequence,
        inspection_receipt_sha256:
            authority_receipt.inspection_receipt_sha256.clone(),
        authority_proof_seed: seed,
        authority_receipt,
        provider_scope,
        provider_operation_binding_sha256,
        signer_logical_role: public_key.logical_role().to_owned(),
        signer_provider_id:
            public_scope.service_id.clone(),
        signer_key_id: public_key.key_id().to_owned(),
        signer_key_material_sha256:
            public_scope.key_material_sha256.clone(),
        signature: String::new(),
    };
    public.signature = public_key.sign(
        V2_IMMUTABLE_RESPONSE_INSPECTION_SIGNATURE_DOMAIN,
        &public,
    )?;
    encode_result(
        V2ResponseDataResult::InspectImmutableResponse(
            V2InspectImmutableResponseResult {
                inspection: public,
            },
        ),
        vec![sealed_memfd(&raw)?],
    )
}

fn execute_public_release_authorization(
    config: &RootOwnedResponseObservationV2Config,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2AuthorizeExactReleaseParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        SignedV2ExactReleaseAuthorizationV2,
        V2AuthorizeExactReleaseResult, V2AttemptState,
        V2ResponseDataOperation, V2ResponseDataResult,
        V2_EXACT_RELEASE_AUTHORIZATION_VERSION,
        V2_PUBLIC_RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, OperationKind,
    };
    use super::super::super::state_authority::rpc::{
        AuthorityArtifactType, NestedAuthorityPayload,
        ReleaseAuthorizationArtifact,
    };

    let deadline_boottime_ns =
        public_deadline_boottime_ns(&params.binding.monotonic_deadline)?;
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || boot_id != params.binding.custody_boot_id
        || params.binding.lifecycle_state != V2AttemptState::Completed
    {
        return Err(V2RuntimeError::new(
            "response_data_release_authorization_request_invalid",
            "release authorization requires one live public COMPLETED projection",
        ));
    }
    verify_immutable_raw_inspection(
        config.custody_topology(),
        &params.inspection.authority_receipt,
    )?;
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: request_id.to_owned(),
            operation_id:
                format!("{request_id}:authorization-observation"),
            attempt_id: params.binding.attempt_id.clone(),
            expected_stable_resume_id:
                params.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    verify_public_observed_projection(
        &observation,
        &params.binding.attempt_id,
        params.binding.attempt_revision,
        params.binding.fencing_token,
        &params.binding.state_sha256,
        &params.stable_resume_id,
    )?;
    let inspection = &params.inspection.authority_receipt;
    let seed = &inspection.authority_proof_seed;
    if inspection.attempt_id != observation.attempt_id
        || inspection.inspection_sequence
            != observation.attempt_revision
        || inspection.authority_scope.fencing_token
            != observation.fencing_token
        || params.authority_proof_seed_sha256 != seed.seed_sha256
        || params.authority_prerequisites_root_sha256
            != seed.authority_artifacts_root_sha256
        || params.policy_decision_sha256
            != seed.policy_decision_id.0
        || params.exact_replay_key_sha256.is_empty()
        || params.expires_at_epoch_ms == 0
    {
        return Err(V2RuntimeError::new(
            "response_data_release_authorization_binding_mismatch",
            "authorization does not bind the signed observation, inspection seed, policy decision, and replay key",
        ));
    }
    let exact_release_request_sha256 =
        canonical_sha256(&serde_json::json!({
            "apiVersion":
                "serverware.responseV2ExactReleaseRequest/v1",
            "generationId": observation.generation_id,
            "attemptId": observation.attempt_id,
            "attemptRevision": observation.attempt_revision,
            "fencingToken": observation.fencing_token,
            "inspectionReceiptSha256":
                inspection.inspection_receipt_sha256,
            "authorityProofSeedSha256": seed.seed_sha256,
            "releaseObjectSha256": inspection.raw_object_sha256,
            "policyDecisionSha256":
                params.policy_decision_sha256,
            "exactReplayKeySha256":
                params.exact_replay_key_sha256,
        }))?;
    let authorization_id =
        canonical_sha256(&serde_json::json!({
            "apiVersion":
                "serverware.responseV2ReleaseAuthorizationId/v1",
            "operationId": request_id,
            "exactReleaseRequestSha256":
                exact_release_request_sha256,
        }))?;
    let finalization_id =
        canonical_sha256(&serde_json::json!({
            "apiVersion":
                "serverware.responseV2ReleaseFinalizationId/v1",
            "authorizationId": authorization_id,
            "inspectionReceiptSha256":
                inspection.inspection_receipt_sha256,
            "authorityProofSeedSha256": seed.seed_sha256,
        }))?;
    let one_use_nonce_sha256 =
        canonical_sha256(&serde_json::json!({
            "apiVersion":
                "serverware.responseV2ReleaseOneUseNonce/v1",
            "authorizationId": authorization_id,
            "exactReplayKeySha256":
                params.exact_replay_key_sha256,
            "fencingToken": observation.fencing_token,
        }))?;
    let canonical_seed = canonical_inspection_seed(seed)?;
    let inspection_artifact = seed
        .authority_artifacts
        .iter()
        .find(|artifact| {
            artifact.body.artifact_class
                == AuthorityArtifactType::ImmutableInspection
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_inspection_artifact_missing",
                "nine-artifact seed lacks immutable inspection",
            )
        })?;
    let inspection_artifact_sha256 =
        canonical_sha256(inspection_artifact)?;
    let release_key =
        require_signing_key(signing_keys, "public-release")?;
    let nested = sign_nested_artifact(
        config,
        CustodyServiceRole::ReleaseAttestorPublisher,
        release_key,
        OperationKind::ReleaseConsumeAndRetrieveExact,
        &format!("{request_id}:release-authorization-artifact"),
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
        params.expires_at_epoch_ms,
        NestedAuthorityPayload::ReleaseAuthorization(
            ReleaseAuthorizationArtifact {
                release_authorization_id:
                    Identifier(authorization_id.clone()),
                finalization_id:
                    Identifier(finalization_id.clone()),
                release_request_sha256:
                    AuthorityDigest(
                        exact_release_request_sha256.clone(),
                    ),
                inspection_result_sha256:
                    AuthorityDigest(
                        inspection.inspection_receipt_sha256.clone(),
                    ),
                inspection_artifact_sha256:
                    AuthorityDigest(inspection_artifact_sha256),
                inspection_seed_body_sha256:
                    canonical_seed.body_sha256.clone(),
                inspection_seed_root_sha256:
                    AuthorityDigest(
                        seed.authority_artifacts_root_sha256.clone(),
                    ),
                release_object_sha256:
                    AuthorityDigest(
                        inspection.raw_object_sha256.clone(),
                    ),
                one_use_nonce_sha256:
                    AuthorityDigest(one_use_nonce_sha256.clone()),
            },
        ),
        None,
        deadline_boottime_ns,
    )?;
    let nested_sha256 = canonical_sha256(&nested)?;
    verify_pinned_authority_artifact(
        config.custody_topology(),
        &nested,
        &observation.attempt_id,
        observation.fencing_token,
    )?;
    let authorization_result_sha256 =
        canonical_sha256(&serde_json::json!({
            "authorizationId": authorization_id,
            "finalizationId": finalization_id,
            "exactReleaseRequestSha256":
                exact_release_request_sha256,
            "oneUseNonceSha256": one_use_nonce_sha256,
            "releaseAuthorizationArtifactSha256":
                nested_sha256,
            "authorized": true,
        }))?;
    let authority_scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::ReleaseAttestorPublisher,
        release_key,
        ServiceOperationV1::AuthorizeRelease,
        request_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut authority_receipt = SignedReleaseAuthorizationV2 {
        api_version: RELEASE_AUTHORIZATION_API_VERSION.to_owned(),
        generation_id: observation.generation_id.clone(),
        generation: observation.generation,
        operation: ServiceOperationV1::AuthorizeRelease,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: observation.attempt_id.clone(),
        stable_resume_id: observation.stable_resume_id.clone(),
        authority_scope: authority_scope.clone(),
        fencing_token: observation.fencing_token,
        authorization_id: authorization_id.clone(),
        finalization_id,
        exact_release_request_sha256,
        one_use_nonce_sha256,
        inspection_receipt_sha256:
            inspection.inspection_receipt_sha256.clone(),
        authority_proof_seed_sha256: seed.seed_sha256.clone(),
        authority_proof_seed_artifacts_root_sha256:
            seed.authority_artifacts_root_sha256.clone(),
        raw_object_sha256: inspection.raw_object_sha256.clone(),
        policy_decision_sha256:
            params.policy_decision_sha256.clone(),
        exact_replay_key_sha256:
            params.exact_replay_key_sha256.clone(),
        expires_at_epoch_ms: params.expires_at_epoch_ms,
        authorization_result_sha256:
            authorization_result_sha256.clone(),
        release_authorization_artifact: nested,
        release_authorization_artifact_sha256: nested_sha256,
        signer_logical_role:
            release_key.logical_role().to_owned(),
        signer_key_id: release_key.key_id().to_owned(),
        signature: String::new(),
    };
    authority_receipt.signature = release_key.sign(
        super::super::attestation::
            RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
        &authority_receipt.without_signature(),
    )?;
    super::super::attestation::verify_release_authorization(
        config.custody_topology(),
        &authority_receipt,
    )?;
    let provider_operation_binding_sha256 =
        authority_scope.operation_binding_sha256.clone();
    let provider_scope = authority_scope.clone();
    let mut public = SignedV2ExactReleaseAuthorizationV2 {
        api_version:
            V2_EXACT_RELEASE_AUTHORIZATION_VERSION.to_owned(),
        generation_id: observation.generation_id,
        generation: observation.generation,
        operation: V2ResponseDataOperation::AuthorizeExactRelease,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: observation.attempt_id,
        attempt_revision: observation.attempt_revision,
        stable_resume_id: observation.stable_resume_id,
        fencing_token: observation.fencing_token,
        authorization_id,
        inspection_receipt_sha256:
            inspection.inspection_receipt_sha256.clone(),
        authority_proof_seed_sha256: seed.seed_sha256.clone(),
        authority_prerequisites_root_sha256:
            seed.authority_artifacts_root_sha256.clone(),
        raw_response_sha256: inspection.raw_object_sha256.clone(),
        policy_decision_sha256: params.policy_decision_sha256,
        exact_replay_key_sha256:
            params.exact_replay_key_sha256,
        expires_at_epoch_ms: params.expires_at_epoch_ms,
        authorization_result_sha256,
        authority_receipt,
        provider_scope,
        provider_operation_binding_sha256,
        signer_logical_role:
            release_key.logical_role().to_owned(),
        signer_provider_id: authority_scope.service_id,
        signer_key_id: release_key.key_id().to_owned(),
        signer_key_material_sha256:
            authority_scope.key_material_sha256,
        signature: String::new(),
    };
    public.signature = release_key.sign(
        V2_PUBLIC_RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
        &public,
    )?;
    encode_result(
        V2ResponseDataResult::AuthorizeExactRelease(
            V2AuthorizeExactReleaseResult {
                authorization: public,
            },
        ),
        Vec::new(),
    )
}

fn execute_public_consumption(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2ConsumeAndRetrieveExactParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        AttemptStateReference, EvidenceReference,
        SignedV2ExactReleaseConsumptionV2,
        SignedV2ExactReleasePreparationV1,
        V2AttemptState, V2ConsumeAndRetrieveExactParams,
        V2ConsumeAndRetrieveExactResult, V2EvidenceType,
        V2ResponseDataOperation, V2ResponseDataResult,
        V2_EXACT_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
        V2_EXACT_RELEASE_CONSUMPTION_VERSION,
        V2_EXACT_RELEASE_PREPARATION_SIGNATURE_DOMAIN,
        V2_EXACT_RELEASE_PREPARATION_VERSION,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, OperationKind,
    };
    use super::super::super::state_authority::rpc::{
        ConsumeReleaseAndRetrieveExactMutation,
        MutationPayload, NestedAuthorityPayload,
        PrepareReleaseConsumptionMutation,
        ReleasePreparationMutationBinding,
        ReleaseConsumptionPreauthorizationArtifact,
        ResponseDataStateResult, RetrievePreparedReleaseMutation,
    };

    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || scoped.role != CustodyServiceRole::StateAuthority
    {
        return Err(V2RuntimeError::new(
            "response_data_consumption_request_invalid",
            "release operation is not assigned to the installed state authority",
        ));
    }
    match params {
        V2ConsumeAndRetrieveExactParams::Prepare {
            binding,
            stable_resume_id,
            object,
            release_authorization,
            inspection,
            exact_replay_key_sha256,
        } => {
            let deadline_boottime_ns =
                public_deadline_boottime_ns(
                    &binding.monotonic_deadline,
                )?;
            if boot_id != binding.custody_boot_id
                || binding.predecessor_lifecycle_state
                    != V2AttemptState::Completed
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_prepare_projection_invalid",
                    "PREPARE requires the public COMPLETED projection of internal OBSERVED",
                ));
            }
            verify_immutable_raw_inspection(
                config.custody_topology(),
                &inspection.authority_receipt,
            )?;
            super::super::attestation::verify_release_authorization(
                config.custody_topology(),
                &release_authorization.authority_receipt,
            )?;
            let observation = super::query_attempt_state(
                config,
                &AttemptStateQueryRequestV1 {
                    api_version:
                        ATTEMPT_STATE_OBSERVATION_API_VERSION
                            .to_owned(),
                    generation_id:
                        config.custody_topology()
                            .generation_id
                            .clone(),
                    generation:
                        config.custody_topology().generation,
                    request_id: request_id.to_owned(),
                    operation_id:
                        format!("{request_id}:prepare-observation"),
                    attempt_id: binding.attempt_id.clone(),
                    expected_stable_resume_id:
                        stable_resume_id.clone(),
                    raw_response_object_id:
                        Some(object.retrieval_id.clone()),
                    include_proof_material: true,
                    deadline_boottime_ns,
                },
            )?;
            verify_public_observed_projection(
                &observation,
                &binding.attempt_id,
                binding.attempt_revision,
                binding.fencing_token,
                &binding.predecessor_state_sha256,
                &stable_resume_id,
            )?;
            let proof =
                observation.proof_material.clone().ok_or_else(|| {
                    V2RuntimeError::new(
                        "response_data_release_prepare_proof_missing",
                        "PREPARE requires the signed nine-artifact inspection seed",
                    )
                })?;
            let authorization =
                &release_authorization.authority_receipt;
            let inspection_receipt = &inspection.authority_receipt;
            if authorization.attempt_id != observation.attempt_id
                || authorization.fencing_token
                    != observation.fencing_token
                || authorization.exact_replay_key_sha256
                    != exact_replay_key_sha256
                || authorization.inspection_receipt_sha256
                    != inspection_receipt.inspection_receipt_sha256
                || object.object_sha256
                    != proof.raw_response_object.content_sha256.0
                || object.byte_length
                    != proof.raw_response_object.content_length
                || object.retrieval_id
                    != proof.raw_response_object.object_id.0
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_prepare_binding_mismatch",
                    "PREPARE inputs differ from signed authorization, observation, inspection, or immutable object",
                ));
            }
            let client_binding_sha256 =
                canonical_sha256(&serde_json::json!({
                    "apiVersion":
                        "serverware.responseV2ReleaseClientBinding/v1",
                    "clientIdentitySha256":
                        binding.client_identity_sha256,
                    "connectionIdentitySha256":
                        binding.transaction
                            .connection_identity_sha256,
                    "tlsSessionSha256":
                        binding.transaction.tls_session_sha256,
                }))?;
            let mutation_binding =
                ReleasePreparationMutationBindingV1 {
                    expected_revision:
                        observation.attempt_revision,
                    expected_state: "OBSERVED".to_owned(),
                    successor_revision:
                        observation
                            .attempt_revision
                            .checked_add(1)
                            .ok_or_else(|| {
                                V2RuntimeError::new(
                                    "response_data_release_revision_overflow",
                                    "PREPARE revision overflows u64",
                                )
                            })?,
                    successor_state:
                        "RELEASE_PREPARED".to_owned(),
                    release_authorization_id:
                        authorization.authorization_id.clone(),
                    exact_release_request_sha256:
                        authorization
                            .exact_release_request_sha256
                            .clone(),
                    inspection_receipt_sha256:
                        inspection_receipt
                            .inspection_receipt_sha256
                            .clone(),
                    release_object_sha256:
                        proof
                            .raw_response_object
                            .content_sha256
                            .0
                            .clone(),
                    client_binding_sha256:
                        client_binding_sha256.clone(),
                    exact_replay_key_sha256:
                        exact_replay_key_sha256.clone(),
                    one_use_nonce_sha256:
                        authorization.one_use_nonce_sha256.clone(),
                };
            let preauthorization_request =
                ReleaseConsumptionPreauthorizationArtifactRequestV1 {
                    api_version:
                        super::super::protocol::
                            RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION
                            .to_owned(),
                    generation_id:
                        observation.generation_id.clone(),
                    generation: observation.generation,
                    request_id:
                        format!("{request_id}:preauthorization"),
                    operation_id:
                        format!("{request_id}:preauthorization-artifact"),
                    attempt_id: observation.attempt_id.clone(),
                    stable_resume_id:
                        observation.stable_resume_id.clone(),
                    attempt_revision:
                        observation.attempt_revision,
                    fencing_token: observation.fencing_token,
                    finalization_id:
                        authorization.finalization_id.clone(),
                    one_use_nonce_sha256:
                        authorization.one_use_nonce_sha256.clone(),
                    release_object:
                        proof.raw_response_object.clone(),
                    mutation_binding:
                        mutation_binding.clone(),
                    deadline_boottime_ns,
                };
            let preauthorization_artifact: SignedAuthorityArtifact =
                super::invoke_service(
                    config,
                    CustodyServiceRole::ReleaseAttestorPublisher,
                    ServiceOperationV1::AuthorizeRelease,
                    &preauthorization_request.request_id,
                    &preauthorization_request,
                    deadline_boottime_ns,
                )?;
            let preauthorization_artifact_sha256 =
                canonical_sha256(&preauthorization_artifact)?;
            verify_pinned_authority_artifact(
                config.custody_topology(),
                &preauthorization_artifact,
                &observation.attempt_id,
                observation.fencing_token,
            )?;
            if !matches!(
                preauthorization_artifact.body.payload,
                NestedAuthorityPayload::
                    ReleaseConsumptionPreauthorization(_)
            ) {
                return Err(V2RuntimeError::new(
                    "response_data_release_preauthorization_invalid",
                    "release service returned the wrong nested artifact class",
                ));
            }
            let state_binding = ReleasePreparationMutationBinding {
                release_authorization_id: Identifier(
                    authorization.authorization_id.clone(),
                ),
                release_request_sha256: AuthorityDigest(
                    authorization
                        .exact_release_request_sha256
                        .clone(),
                ),
                inspection_result_sha256: AuthorityDigest(
                    inspection_receipt
                        .inspection_receipt_sha256
                        .clone(),
                ),
                release_object:
                    proof.raw_response_object.clone(),
                client_binding_sha256: AuthorityDigest(
                    client_binding_sha256,
                ),
                exact_replay_key_sha256: AuthorityDigest(
                    exact_replay_key_sha256.clone(),
                ),
            };
            let intent = UnsignedStateAuthorityIntentV1 {
                expected_state: AttemptState::Observed,
                payload:
                    MutationPayload::
                        ConsumeReleaseAndRetrieveExact(
                            ConsumeReleaseAndRetrieveExactMutation::
                                Prepare(
                                    PrepareReleaseConsumptionMutation {
                                        binding: state_binding,
                                        inspection_seed:
                                            canonical_inspection_seed(
                                                &inspection_receipt
                                                    .authority_proof_seed,
                                            )?,
                                        release_authorization:
                                            authorization
                                                .release_authorization_artifact
                                                .clone(),
                                        release_consumption_preauthorization:
                                            preauthorization_artifact
                                                .clone(),
                                    },
                                ),
                        ),
            };
            let frame = signed_state_authority_frame(
                config,
                scoped,
                request_id,
                &format!("{request_id}:prepare-cas"),
                &observation.attempt_id,
                observation.attempt_revision,
                observation.fencing_token,
                deadline_boottime_ns,
                &intent,
                signing_keys,
            )?;
            let linearizable =
                require_signing_key(
                    signing_keys,
                    "linearizable-store",
                )?;
            let state =
                super::state_authority::execute_postgres(
                    config,
                    &frame,
                    request_id,
                    &format!("{request_id}:prepare-cas"),
                    &observation.attempt_id,
                    &observation.stable_resume_id,
                    observation.attempt_revision,
                    observation.fencing_token,
                    linearizable,
                )?;
            if state.exact_raw.is_some()
                || state.exact_descriptor.is_some()
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_prepare_bytes_forbidden",
                    "PREPARE returned bytes before final-envelope verification",
                ));
            }
            let preparation = match state.response_data_result {
                Some(ResponseDataStateResult::ReleasePreparation(
                    preparation,
                )) => preparation,
                _ => {
                    return Err(V2RuntimeError::new(
                        "response_data_release_prepare_result_missing",
                        "state authority omitted durable PREPARE result",
                    ))
                }
            };
            let state_receipt_sha256 = canonical_sha256(
                &preparation
                    .durable_result
                    .signed_state_mutation_receipt,
            )?;
            if state_receipt_sha256
                    != preparation
                        .durable_result
                        .signed_state_mutation_receipt_sha256
                        .0
                || canonical_sha256(
                    &preparation.release_preparation_receipt,
                )? != preparation
                    .release_preparation_receipt_sha256
                    .0
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_prepare_digest_mismatch",
                    "state PREPARE result failed exact receipt digests",
                ));
            }
            let state_key = require_signing_key(
                signing_keys,
                "public-release-consumption",
            )?;
            let preauthorization_scope =
                provider_authority_scope(
                    config.custody_topology(),
                    CustodyServiceRole::StateAuthority,
                    state_key,
                    ServiceOperationV1::
                        ConsumeReleaseAndRetrieveExact,
                    &preauthorization_request.operation_id,
                    &observation.attempt_id,
                    observation.attempt_revision,
                    observation.fencing_token,
                )?;
            let mut signed_preauthorization =
                super::super::protocol::
                    SignedReleaseConsumptionPreauthorizationV1 {
                    api_version:
                        super::super::protocol::
                            RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION
                            .to_owned(),
                    generation_id:
                        observation.generation_id.clone(),
                    generation: observation.generation,
                    operation: ServiceOperationV1::
                        ConsumeReleaseAndRetrieveExact,
                    request_id:
                        preauthorization_request.request_id,
                    request_sha256: request_sha256.to_owned(),
                    attempt_id: observation.attempt_id.clone(),
                    stable_resume_id:
                        observation.stable_resume_id.clone(),
                    authority_scope:
                        preauthorization_scope,
                    fencing_token: observation.fencing_token,
                    mutation_binding:
                        mutation_binding.clone(),
                    mutation_binding_sha256:
                        canonical_sha256(&mutation_binding)?,
                    preauthorization_artifact,
                    preauthorization_artifact_sha256:
                        preauthorization_artifact_sha256.clone(),
                    signer_logical_role:
                        state_key.logical_role().to_owned(),
                    signer_key_id:
                        state_key.key_id().to_owned(),
                    signature: String::new(),
                };
            signed_preauthorization.signature =
                state_key.sign(
                    super::super::attestation::
                        RELEASE_CONSUMPTION_PREAUTHORIZATION_SIGNATURE_DOMAIN,
                    &signed_preauthorization.without_signature(),
                )?;
            let authority_scope = provider_authority_scope(
                config.custody_topology(),
                CustodyServiceRole::StateAuthority,
                state_key,
                ServiceOperationV1::
                    ConsumeReleaseAndRetrieveExact,
                request_id,
                &observation.attempt_id,
                preparation
                    .durable_result
                    .signed_state_mutation_receipt
                    .body
                    .successor_revision,
                observation.fencing_token,
            )?;
            let release_authorization_sha256 =
                canonical_sha256(authorization)?;
            let durable = preparation.durable_result;
            let mutation_receipt =
                durable.signed_state_mutation_receipt;
            let mut authority_receipt =
                super::super::protocol::
                    SignedReleasePreparationReceiptV1 {
                    api_version:
                        super::super::protocol::
                            RELEASE_PREPARATION_RECEIPT_API_VERSION
                            .to_owned(),
                    generation_id:
                        observation.generation_id.clone(),
                    generation: observation.generation,
                    operation: ServiceOperationV1::
                        ConsumeReleaseAndRetrieveExact,
                    request_id: request_id.to_owned(),
                    request_sha256: request_sha256.to_owned(),
                    attempt_id: observation.attempt_id.clone(),
                    stable_resume_id:
                        observation.stable_resume_id.clone(),
                    authority_scope: authority_scope.clone(),
                    fencing_token: observation.fencing_token,
                    release_authorization_id:
                        durable.release_authorization_id.0,
                    release_authorization_sha256,
                    exact_release_request_sha256:
                        durable.release_request_sha256.0,
                    inspection_receipt_sha256:
                        durable.inspection_result_sha256.0,
                    release_object_sha256:
                        durable.release_object_sha256.0,
                    client_binding_sha256:
                        durable.client_binding_sha256.0,
                    exact_replay_key_sha256:
                        durable.exact_replay_key_sha256.0,
                    preauthorization_artifact_sha256:
                        durable
                            .preauthorization_artifact_sha256
                            .0,
                    state_mutation_receipt_sha256:
                        durable
                            .signed_state_mutation_receipt_sha256
                            .0,
                    predecessor_revision:
                        mutation_receipt.body.predecessor_revision,
                    predecessor_state:
                        mutation_receipt
                            .body
                            .predecessor_state
                            .as_str()
                            .to_owned(),
                    successor_revision:
                        mutation_receipt.body.successor_revision,
                    successor_state:
                        mutation_receipt
                            .body
                            .successor_state
                            .as_str()
                            .to_owned(),
                    one_use_nonce_sha256:
                        durable.one_use_nonce_sha256.0,
                    durable_canonical_result_sha256:
                        preparation
                            .durable_canonical_result_sha256
                            .0,
                    preauthorization:
                        signed_preauthorization,
                    state_authority_receipt:
                        state.receipt,
                    release_preparation_mutation_receipt:
                        mutation_receipt,
                    release_preparation_artifact:
                        preparation.release_preparation_receipt,
                    signer_logical_role:
                        state_key.logical_role().to_owned(),
                    signer_key_id:
                        state_key.key_id().to_owned(),
                    signature: String::new(),
                };
            authority_receipt.signature = state_key.sign(
                super::super::attestation::
                    RELEASE_PREPARATION_RECEIPT_SIGNATURE_DOMAIN,
                &authority_receipt.without_signature(),
            )?;
            super::super::attestation::
                verify_release_preparation_receipt(
                    config.custody_topology(),
                    &authority_receipt,
                )?;
            let post = super::query_attempt_state(
                config,
                &AttemptStateQueryRequestV1 {
                    api_version:
                        ATTEMPT_STATE_OBSERVATION_API_VERSION
                            .to_owned(),
                    generation_id:
                        observation.generation_id.clone(),
                    generation: observation.generation,
                    request_id:
                        format!("{request_id}:prepared-state"),
                    operation_id:
                        format!("{request_id}:prepared-observation"),
                    attempt_id: observation.attempt_id.clone(),
                    expected_stable_resume_id:
                        observation.stable_resume_id.clone(),
                    raw_response_object_id: None,
                    include_proof_material: false,
                    deadline_boottime_ns,
                },
            )?;
            if post.authoritative_state
                    != AttemptState::ReleasePrepared
                || post.attempt_revision
                    != authority_receipt.successor_revision
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_prepare_post_state_mismatch",
                    "signed post-CAS observation is not RELEASE_PREPARED",
                ));
            }
            let public_state_receipt_sha256 =
                canonical_sha256(
                    &authority_receipt.state_authority_receipt,
                )?;
            let public_preparation_artifact_sha256 =
                canonical_sha256(
                    &authority_receipt
                        .release_preparation_artifact,
                )?;
            let provider_binding =
                authority_scope.operation_binding_sha256.clone();
            let provider_scope = authority_scope.clone();
            let mut public =
                SignedV2ExactReleasePreparationV1 {
                api_version:
                    V2_EXACT_RELEASE_PREPARATION_VERSION.to_owned(),
                generation_id: post.generation_id.clone(),
                generation: post.generation,
                operation:
                    V2ResponseDataOperation::
                        ConsumeAndRetrieveExact,
                request_id: request_id.to_owned(),
                request_sha256: request_sha256.to_owned(),
                attempt_id: post.attempt_id.clone(),
                predecessor_revision:
                    authority_receipt.predecessor_revision,
                prepared_revision:
                    authority_receipt.successor_revision,
                stable_resume_id:
                    post.stable_resume_id.clone(),
                fencing_token: post.fencing_token,
                authorization_id:
                    authority_receipt
                        .release_authorization_id
                        .clone(),
                inspection_receipt_sha256:
                    authority_receipt
                        .inspection_receipt_sha256
                        .clone(),
                authority_proof_seed_sha256:
                    inspection.authority_proof_seed
                        .seed_sha256.clone(),
                authority_prerequisites_root_sha256:
                    inspection.authority_proof_seed
                        .authority_artifacts_root_sha256
                        .clone(),
                exact_replay_key_sha256:
                    authority_receipt
                        .exact_replay_key_sha256
                        .clone(),
                raw_response_sha256:
                    authority_receipt
                        .release_object_sha256
                        .clone(),
                raw_response_byte_length: object.byte_length,
                preauthorization_artifact_sha256:
                    preauthorization_artifact_sha256,
                state_mutation_receipt_sha256:
                    public_state_receipt_sha256,
                release_preparation_artifact_sha256:
                    public_preparation_artifact_sha256,
                durable_canonical_result_sha256:
                    authority_receipt
                        .durable_canonical_result_sha256
                        .clone(),
                authority_receipt,
                provider_scope,
                provider_operation_binding_sha256:
                    provider_binding,
                signer_logical_role:
                    state_key.logical_role().to_owned(),
                signer_provider_id:
                    authority_scope.service_id,
                signer_key_id:
                    state_key.key_id().to_owned(),
                signer_key_material_sha256:
                    authority_scope.key_material_sha256,
                signature: String::new(),
            };
            public.signature = state_key.sign(
                V2_EXACT_RELEASE_PREPARATION_SIGNATURE_DOMAIN,
                &public,
            )?;
            encode_result(
                V2ResponseDataResult::
                    ConsumeAndRetrieveExact(
                        V2ConsumeAndRetrieveExactResult::Prepared {
                            attempt: AttemptStateReference {
                                attempt_id: post.attempt_id,
                                state:
                                    V2AttemptState::ReleasePrepared,
                                state_sha256:
                                    post.authoritative_state_sha256,
                                attempt_revision:
                                    post.attempt_revision,
                                fencing_token:
                                    post.fencing_token,
                            },
                            preparation: public,
                        },
                    ),
                Vec::new(),
            )
        }
        V2ConsumeAndRetrieveExactParams::Retrieve {
            binding,
            stable_resume_id,
            object,
            preparation,
            final_envelope_verification,
            exact_replay_key_sha256,
        } => {
            let deadline_boottime_ns =
                public_deadline_boottime_ns(
                    &binding.monotonic_deadline,
                )?;
            if boot_id != binding.custody_boot_id {
                return Err(V2RuntimeError::new(
                    "response_data_release_retrieve_boot_mismatch",
                    "RETRIEVE boot binding differs from the service boot",
                ));
            }
            super::super::attestation::
                verify_release_preparation_receipt(
                    config.custody_topology(),
                    &preparation.authority_receipt,
                )?;
            verify_final_envelope_verification(
                config.custody_topology(),
                &final_envelope_verification.authority_receipt,
            )?;
            let observation = super::query_attempt_state(
                config,
                &AttemptStateQueryRequestV1 {
                    api_version:
                        ATTEMPT_STATE_OBSERVATION_API_VERSION
                            .to_owned(),
                    generation_id:
                        config.custody_topology()
                            .generation_id
                            .clone(),
                    generation:
                        config.custody_topology().generation,
                    request_id: request_id.to_owned(),
                    operation_id:
                        format!("{request_id}:retrieve-observation"),
                    attempt_id: binding.attempt_id.clone(),
                    expected_stable_resume_id:
                        stable_resume_id.clone(),
                    raw_response_object_id:
                        Some(object.retrieval_id.clone()),
                    include_proof_material: true,
                    deadline_boottime_ns,
                },
            )?;
            if observation.authoritative_state
                    != AttemptState::ReleasePrepared
                || observation.attempt_revision
                    != binding.attempt_revision
                || observation.fencing_token
                    != binding.fencing_token
                || observation.authoritative_state_sha256
                    != binding.state_sha256
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_retrieve_state_mismatch",
                    "RETRIEVE requires the exact signed RELEASE_PREPARED observation",
                ));
            }
            let proof =
                observation.proof_material.clone().ok_or_else(|| {
                    V2RuntimeError::new(
                        "response_data_release_retrieve_proof_missing",
                        "RETRIEVE lacks state-derived immutable object provenance",
                    )
                })?;
            let prepared = &preparation.authority_receipt;
            if prepared.successor_revision
                    != observation.attempt_revision
                || prepared.exact_replay_key_sha256
                    != exact_replay_key_sha256
                || prepared.release_object_sha256
                    != object.object_sha256
                || proof.raw_response_object.object_id.0
                    != object.retrieval_id
                || proof.raw_response_object.content_length
                    != object.byte_length
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_retrieve_binding_mismatch",
                    "RETRIEVE differs from durable PREPARE or immutable state",
                ));
            }
            let state_binding =
                ReleasePreparationMutationBinding {
                    release_authorization_id: Identifier(
                        prepared
                            .release_authorization_id
                            .clone(),
                    ),
                    release_request_sha256: AuthorityDigest(
                        prepared
                            .exact_release_request_sha256
                            .clone(),
                    ),
                    inspection_result_sha256: AuthorityDigest(
                        prepared
                            .inspection_receipt_sha256
                            .clone(),
                    ),
                    release_object:
                        proof.raw_response_object.clone(),
                    client_binding_sha256: AuthorityDigest(
                        prepared.client_binding_sha256.clone(),
                    ),
                    exact_replay_key_sha256: AuthorityDigest(
                        exact_replay_key_sha256.clone(),
                    ),
                };
            let intent = UnsignedStateAuthorityIntentV1 {
                expected_state: AttemptState::ReleasePrepared,
                payload:
                    MutationPayload::
                        ConsumeReleaseAndRetrieveExact(
                            ConsumeReleaseAndRetrieveExactMutation::
                                Retrieve(
                                    RetrievePreparedReleaseMutation {
                                        binding: state_binding,
                                        prepared_consumption_receipt:
                                            prepared
                                                .release_preparation_mutation_receipt
                                                .clone(),
                                        final_envelope_verification:
                                            final_envelope_verification
                                                .authority_receipt
                                                .final_envelope_verification_artifact
                                                .clone(),
                                    },
                                ),
                        ),
            };
            let operation_id =
                format!("{request_id}:retrieve-exact");
            let frame = signed_state_authority_frame(
                config,
                scoped,
                request_id,
                &operation_id,
                &observation.attempt_id,
                observation.attempt_revision,
                observation.fencing_token,
                deadline_boottime_ns,
                &intent,
                signing_keys,
            )?;
            let linearizable =
                require_signing_key(
                    signing_keys,
                    "linearizable-store",
                )?;
            let state =
                super::state_authority::execute_postgres(
                    config,
                    &frame,
                    request_id,
                    &operation_id,
                    &observation.attempt_id,
                    &observation.stable_resume_id,
                    observation.attempt_revision,
                    observation.fencing_token,
                    linearizable,
                )?;
            let retrieval = match state.response_data_result {
                Some(ResponseDataStateResult::ReleaseRetrieval(
                    retrieval,
                )) => retrieval,
                _ => {
                    return Err(V2RuntimeError::new(
                        "response_data_release_retrieval_result_missing",
                        "state authority omitted durable RETRIEVE result",
                    ))
                }
            };
            let bytes = state.exact_raw.ok_or_else(|| {
                V2RuntimeError::new(
                    "response_data_release_retrieval_bytes_missing",
                    "verified RETRIEVE omitted exact bytes",
                )
            })?;
            let exact_object =
                state.exact_descriptor.ok_or_else(|| {
                    V2RuntimeError::new(
                        "response_data_release_retrieval_descriptor_missing",
                        "verified RETRIEVE omitted exact descriptor",
                    )
                })?;
            if retrieval.release_object_sha256.0
                    != object.object_sha256
                || retrieval.exact_replay_key_sha256.0
                    != exact_replay_key_sha256
                || exact_object.sha256 != object.object_sha256
                || exact_object.byte_length != object.byte_length
            {
                return Err(V2RuntimeError::new(
                    "response_data_release_retrieval_result_mismatch",
                    "durable RETRIEVE result differs from exact prepared object",
                ));
            }
            let state_key = require_signing_key(
                signing_keys,
                "public-release-consumption",
            )?;
            let authority_scope = provider_authority_scope(
                config.custody_topology(),
                CustodyServiceRole::StateAuthority,
                state_key,
                ServiceOperationV1::
                    ConsumeReleaseAndRetrieveExact,
                &operation_id,
                &observation.attempt_id,
                observation.attempt_revision,
                observation.fencing_token,
            )?;
            let final_verification_sha256 =
                canonical_sha256(
                    &final_envelope_verification,
                )?;
            let preparation_sha256 =
                canonical_sha256(&preparation)?;
            let consumption_receipt_sha256 =
                canonical_sha256(&retrieval)?;
            let mut internal = SignedReleaseConsumptionV2 {
                api_version:
                    RELEASE_CONSUMPTION_API_VERSION.to_owned(),
                generation_id:
                    observation.generation_id.clone(),
                generation: observation.generation,
                operation: ServiceOperationV1::
                    ConsumeReleaseAndRetrieveExact,
                request_id: request_id.to_owned(),
                request_sha256: request_sha256.to_owned(),
                attempt_id: observation.attempt_id.clone(),
                stable_resume_id:
                    observation.stable_resume_id.clone(),
                authority_scope: authority_scope.clone(),
                fencing_token: observation.fencing_token,
                authorization_id:
                    prepared.release_authorization_id.clone(),
                inspection_receipt_sha256:
                    prepared.inspection_receipt_sha256.clone(),
                final_envelope_verification_sha256:
                    final_verification_sha256.clone(),
                release_preparation_receipt_sha256:
                    preparation_sha256.clone(),
                exact_replay_key_sha256:
                    exact_replay_key_sha256.clone(),
                raw_object_sha256:
                    object.object_sha256.clone(),
                raw_object_byte_length: object.byte_length,
                exact_object: exact_object.clone(),
                authority_revision:
                    observation.attempt_revision,
                consumption_sequence:
                    observation.attempt_revision,
                consumption_receipt_sha256:
                    consumption_receipt_sha256.clone(),
                canonical_result_sha256:
                    state.receipt.exact_result_sha256,
                prepared_consumption:
                    preparation.authority_receipt,
                signer_logical_role:
                    state_key.logical_role().to_owned(),
                signer_key_id:
                    state_key.key_id().to_owned(),
                signature: String::new(),
            };
            internal.signature = state_key.sign(
                super::super::attestation::
                    RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
                &internal.without_signature(),
            )?;
            super::super::attestation::
                verify_release_consumption(
                    config.custody_topology(),
                    &internal,
                )?;
            let provider_binding =
                authority_scope.operation_binding_sha256.clone();
            let provider_scope = authority_scope.clone();
            let mut public =
                SignedV2ExactReleaseConsumptionV2 {
                api_version:
                    V2_EXACT_RELEASE_CONSUMPTION_VERSION.to_owned(),
                generation_id: observation.generation_id,
                generation: observation.generation,
                operation:
                    V2ResponseDataOperation::
                        ConsumeAndRetrieveExact,
                request_id: request_id.to_owned(),
                request_sha256: request_sha256.to_owned(),
                attempt_id: observation.attempt_id,
                attempt_revision:
                    observation.attempt_revision,
                stable_resume_id:
                    observation.stable_resume_id,
                fencing_token: observation.fencing_token,
                preparation_receipt_sha256:
                    preparation_sha256,
                final_envelope_verification_sha256:
                    final_verification_sha256,
                exact_replay_key_sha256,
                raw_response_sha256:
                    object.object_sha256.clone(),
                raw_response_byte_length: object.byte_length,
                exact_object: exact_object.clone(),
                retrieval_sequence:
                    internal.consumption_sequence,
                retrieval_receipt_sha256:
                    consumption_receipt_sha256.clone(),
                canonical_result_sha256:
                    internal.canonical_result_sha256.clone(),
                provider_scope,
                provider_operation_binding_sha256:
                    provider_binding,
                signer_logical_role:
                    state_key.logical_role().to_owned(),
                signer_provider_id:
                    authority_scope.service_id,
                signer_key_id:
                    state_key.key_id().to_owned(),
                signer_key_material_sha256:
                    authority_scope.key_material_sha256,
                signature: String::new(),
            };
            public.signature = state_key.sign(
                V2_EXACT_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
                &public,
            )?;
            encode_result(
                V2ResponseDataResult::
                    ConsumeAndRetrieveExact(
                        V2ConsumeAndRetrieveExactResult::Retrieved {
                            object,
                            exact_bytes: exact_object,
                            retrieval_evidence:
                                EvidenceReference {
                                    evidence_type:
                                        V2EvidenceType::Retrieval,
                                    evidence_sha256:
                                        consumption_receipt_sha256,
                                    retrieval_id:
                                        format!(
                                            "{request_id}:retrieval"
                                        ),
                                },
                            consumption: public,
                        },
                    ),
                vec![sealed_memfd(&bytes)?],
            )
        }
    }
}

fn execute_public_replay_resolution(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2ResolveExactReplayParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        SignedV2ExactReplayResolutionV1,
        V2CanonicalControlResponseEncoding,
        V2DurableExactCanonicalResponseReferenceV1,
        V2ResolveExactReplayResult, V2ResponseDataOperation,
        V2ResponseDataReplayPhaseV1, V2ResponseDataResult,
        V2_EXACT_REPLAY_RESOLUTION_VERSION,
        V2_EXACT_REPLAY_RESOLUTION_SIGNATURE_DOMAIN,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        OperationKind, ReconciliationState,
    };
    use super::super::super::state_authority::rpc::{
        MutationPayload, NestedAuthorityPayload,
        ReconciliationArtifact, ResolveReplayMutation,
        ResponseDataStateResult, SignedOperationResult,
    };

    let deadline_boottime_ns =
        public_deadline_boottime_ns(&params.monotonic_deadline)?;
    let stable = &params.stable_request;
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || scoped.role != CustodyServiceRole::StateAuthority
        || boot_id != params.monotonic_deadline.custody_boot_id
        || params.deadline_at_epoch_ms == 0
        || stable.original_request_id.is_empty()
        || stable.attempt_id.is_empty()
        || stable.stable_resume_id.is_empty()
        || stable.operation
            != V2ResponseDataOperation::ConsumeAndRetrieveExact
        || stable.fencing_token == 0
    {
        return Err(V2RuntimeError::new(
            "response_data_replay_request_invalid",
            "replay resolution is not bound to one prior release phase, attempt, fence, and live deadline",
        ));
    }
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: format!("{request_id}:replay-state"),
            operation_id:
                format!("{request_id}:replay-state-observation"),
            attempt_id: stable.attempt_id.clone(),
            expected_stable_resume_id:
                stable.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    if observation.fencing_token != stable.fencing_token {
        return Err(V2RuntimeError::new(
            "response_data_replay_fence_mismatch",
            "replay request differs from the signed active attempt fence",
        ));
    }
    let linearizable =
        require_signing_key(signing_keys, "linearizable-store")?;
    let source_operation_id =
        format!("{request_id}:replay-source");
    let source =
        super::state_authority::query_replay_source_postgres(
            config,
            request_id,
            &source_operation_id,
            &stable.original_request_id,
            &observation,
            deadline_boottime_ns,
            linearizable,
        )?;
    let canonical_source = decode_base64url(
        "replaySource.sourceCanonicalResultBase64url",
        &source.source_canonical_result_base64url,
    )
    .map_err(|error| {
        V2RuntimeError::new(
            "response_data_replay_source_invalid",
            error.to_string(),
        )
    })?;
    let source_result: SignedOperationResult =
        serde_json::from_slice(&canonical_source).map_err(|_| {
            V2RuntimeError::new(
                "response_data_replay_source_invalid",
                "durable replay source is not a signed operation result",
            )
        })?;
    let source_phase = match &source_result.body.response_data_result {
        Some(ResponseDataStateResult::ReleasePreparation(_)) => {
            V2ResponseDataReplayPhaseV1::Prepare
        }
        Some(ResponseDataStateResult::ReleaseRetrieval(_)) => {
            V2ResponseDataReplayPhaseV1::Retrieve
        }
        _ => {
            return Err(V2RuntimeError::new(
                "response_data_replay_source_phase_invalid",
                "durable replay source is not PREPARE or RETRIEVE",
            ))
        }
    };
    if stable.phase != source_phase
        || stable.request_sha256
            != source.source_exact_request_sha256
        || stable.descriptor_manifest_sha256
            != source.source_canonical_result_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_replay_source_binding_mismatch",
            "replay key differs from the exact durable request, result, or release phase",
        ));
    }
    let operation_id = format!("{request_id}:resolve-replay");
    let intent = UnsignedStateAuthorityIntentV1 {
        expected_state: observation.authoritative_state,
        payload: MutationPayload::ResolveReplay(
            ResolveReplayMutation {
                source_replay_id:
                    Identifier(source.source_replay_id.clone()),
                source_operation_id:
                    Identifier(source.source_operation_id.clone()),
                source_exact_request_sha256:
                    AuthorityDigest(
                        source
                            .source_exact_request_sha256
                            .clone(),
                    ),
                source_canonical_result_sha256:
                    AuthorityDigest(
                        source
                            .source_canonical_result_sha256
                            .clone(),
                    ),
                stable_resume_id:
                    Identifier(observation.stable_resume_id.clone()),
            },
        ),
    };
    let frame = signed_state_authority_frame(
        config,
        scoped,
        request_id,
        &operation_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
        deadline_boottime_ns,
        &intent,
        signing_keys,
    )?;
    let state = super::state_authority::execute_postgres(
        config,
        &frame,
        request_id,
        &operation_id,
        &observation.attempt_id,
        &observation.stable_resume_id,
        observation.attempt_revision,
        observation.fencing_token,
        linearizable,
    )?;
    if state.exact_raw.is_some()
        || state.exact_descriptor.is_some()
    {
        return Err(V2RuntimeError::new(
            "response_data_replay_bytes_forbidden",
            "replay resolution returns a durable canonical reference, not raw response bytes",
        ));
    }
    let resolution = match state.response_data_result {
        Some(ResponseDataStateResult::ReplayResolution(
            resolution,
        )) => resolution,
        _ => {
            return Err(V2RuntimeError::new(
                "response_data_replay_result_missing",
                "state authority omitted replay resolution",
            ))
        }
    };
    if resolution.source_replay_id.0
            != source.source_replay_id
        || resolution.source_operation_id.0
            != source.source_operation_id
        || resolution.source_exact_request_sha256.0
            != source.source_exact_request_sha256
        || resolution.source_canonical_result_sha256.0
            != source.source_canonical_result_sha256
        || resolution.source_canonical_result_base64url
            != source.source_canonical_result_base64url
    {
        return Err(V2RuntimeError::new(
            "response_data_replay_result_mismatch",
            "state replay result differs from the signed durable source",
        ));
    }
    let replay_key =
        require_signing_key(signing_keys, "linearizable-store")?;
    let replay_evidence = sign_nested_artifact(
        config,
        CustodyServiceRole::StateAuthority,
        replay_key,
        OperationKind::ReleaseResolveReplay,
        &format!("{request_id}:replay-evidence"),
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
        params.deadline_at_epoch_ms,
        NestedAuthorityPayload::Reconciliation(
            ReconciliationArtifact {
                reconciliation_job_id:
                    Identifier(format!(
                        "replay:{}",
                        source.source_replay_id
                    )),
                domain: Identifier("REPLAY_LEDGER".to_owned()),
                predecessor_state:
                    ReconciliationState::Pending,
                successor_state:
                    ReconciliationState::Complete,
                authoritative_cursor:
                    observation.attempt_revision,
                result_sha256:
                    AuthorityDigest(
                        source
                            .source_canonical_result_sha256
                            .clone(),
                ),
            },
        ),
        None,
        deadline_boottime_ns,
    )?;
    let replay_evidence_sha256 =
        canonical_sha256(&replay_evidence)?;
    let source_observation_sha256 =
        canonical_sha256(&source)?;
    let replay_record_sha256 =
        canonical_sha256(&resolution)?;
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::StateAuthority,
        replay_key,
        ServiceOperationV1::ReplayResolve,
        request_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut public = SignedV2ExactReplayResolutionV1 {
        api_version:
            V2_EXACT_REPLAY_RESOLUTION_VERSION.to_owned(),
        generation_id: observation.generation_id,
        generation: observation.generation,
        operation: V2ResponseDataOperation::ResolveExactReplay,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: observation.attempt_id,
        attempt_revision: observation.attempt_revision,
        fencing_token: observation.fencing_token,
        stable_request: params.stable_request,
        exact_canonical_response:
            V2DurableExactCanonicalResponseReferenceV1 {
                encoding:
                    V2CanonicalControlResponseEncoding::
                        CanonicalJsonUtf8,
                byte_length:
                    u64::try_from(canonical_source.len())
                        .map_err(|_| {
                            V2RuntimeError::new(
                                "response_data_replay_result_too_large",
                                "durable replay result length exceeds u64",
                            )
                        })?,
                sha256:
                    source.source_canonical_result_sha256,
                storage_reference_id:
                    source.source_replay_id,
                persistence_receipt_sha256:
                    source_observation_sha256,
            },
        replay_record_sha256,
        replay_evidence_sha256,
        replay_evidence,
        state_authority_receipt: state.receipt,
        provider_scope: scope.clone(),
        provider_operation_binding_sha256:
            scope.operation_binding_sha256.clone(),
        signer_logical_role:
            replay_key.logical_role().to_owned(),
        signer_provider_id: scope.service_id.clone(),
        signer_key_id: replay_key.key_id().to_owned(),
        signer_key_material_sha256:
            scope.key_material_sha256.clone(),
        signature: String::new(),
    };
    public.signature = replay_key.sign(
        V2_EXACT_REPLAY_RESOLUTION_SIGNATURE_DOMAIN,
        &public,
    )?;
    encode_result(
        V2ResponseDataResult::ResolveExactReplay(
            V2ResolveExactReplayResult {
                resolution: public,
            },
        ),
        Vec::new(),
    )
}

fn execute_public_settlement(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::V2SettleAttemptParams,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        AttemptStateReference, SignedV2DurableSettlementReceiptV1,
        V2AttemptState, V2ResponseDataOperation,
        V2ResponseDataResult, V2SettleAttemptResult, V2TerminalKind,
        V2_DURABLE_SETTLEMENT_SIGNATURE_DOMAIN,
        V2_DURABLE_SETTLEMENT_VERSION,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::protocol::{
        SignedSettlementEvidenceContextV1,
        SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, FenceState, OperationKind,
        ReconciliationState,
    };
    use super::super::super::state_authority::rpc::{
        MutationPayload, NestedAuthorityPayload,
        ReconciliationArtifact, RecoveryArtifact,
        ResponseDataStateResult, SettleAttemptMutation,
    };

    let deadline_boottime_ns =
        public_deadline_boottime_ns(
            &params.settlement_deadline,
        )?;
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || scoped.role != CustodyServiceRole::CleanupWatchdog
        || boot_id != params.settlement_deadline.custody_boot_id
        || params.stable_resume_id.is_empty()
        || params.attempt.attempt_id.is_empty()
        || params.attempt.attempt_revision == 0
        || params.attempt.fencing_token == 0
        || params.settlement_deadline_at_epoch_ms == 0
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_request_invalid",
            "settlement is not bound to one live cleanup deadline and attempt projection",
        ));
    }
    let terminal_code = match (
        params.terminal_kind,
        params.error_class.as_str(),
    ) {
        (V2TerminalKind::OutcomeUnknown, "OUTCOME_UNKNOWN") => {
            "OUTCOME_UNKNOWN"
        }
        (V2TerminalKind::Failed, "DENIED") => "DENIED",
        (V2TerminalKind::Failed, "UNAVAILABLE") => "UNAVAILABLE",
        (V2TerminalKind::Failed, "INVALID_RESPONSE") => {
            "INVALID_RESPONSE"
        }
        (V2TerminalKind::Cancelled, _) => "CANCELLED",
        _ => {
            return Err(V2RuntimeError::new(
                "response_data_settlement_terminal_code_invalid",
                "settlement terminal code is outside the closed failure set",
            ))
        }
    };
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: format!("{request_id}:settlement-state"),
            operation_id:
                format!("{request_id}:settlement-observation"),
            attempt_id: params.attempt.attempt_id.clone(),
            expected_stable_resume_id:
                params.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    if observation.attempt_revision
            != params.attempt.attempt_revision
        || observation.fencing_token
            != params.attempt.fencing_token
        || observation.authoritative_state_sha256
            != params.attempt.state_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_state_mismatch",
            "unsigned settlement attempt differs from signed authoritative state",
        ));
    }
    if params
        .upstream_response
        .as_ref()
        .map(|object| object.object_sha256.clone())
        .is_some_and(|digest| {
            params.transaction.upstream_response_sha256.as_ref()
                != Some(&digest)
        })
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_upstream_projection_invalid",
            "settlement response object differs from the transaction commitment",
        ));
    }
    let context_request = SettlementEvidenceContextRequestV1 {
        api_version:
            SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION.to_owned(),
        generation_id: observation.generation_id.clone(),
        generation: observation.generation,
        request_id: format!("{request_id}:settlement-context"),
        operation_id:
            format!("{request_id}:settlement-context-query"),
        attempt_observation: observation.clone(),
        terminal_code: terminal_code.to_owned(),
        expected_upstream_response_sha256:
            params.transaction.upstream_response_sha256.clone(),
        deadline_boottime_ns,
    };
    let context: SignedSettlementEvidenceContextV1 =
        super::invoke_service(
            config,
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::StateCas,
            &context_request.request_id,
            &context_request,
            deadline_boottime_ns,
        )?;
    super::super::attestation::
        verify_settlement_evidence_context(
            config.custody_topology(),
            &context,
        )?;
    if context.attempt_id != observation.attempt_id
        || context.attempt_revision
            != observation.attempt_revision
        || context.authoritative_state
            != observation.authoritative_state
        || context.authoritative_state_sha256
            != observation.authoritative_state_sha256
        || context.fencing_token != observation.fencing_token
        || context.stable_resume_id
            != observation.stable_resume_id
        || context.terminal_code != terminal_code
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_context_mismatch",
            "state settlement context differs from signed attempt observation",
        ));
    }
    let reconciliation_key =
        require_signing_key(signing_keys, "outcome-reconciliation")?;
    let reconciliation_id = format!(
        "settlement:{}:{}",
        context.attempt_id, context.attempt_revision
    );
    let reconciliation_evidence = sign_nested_artifact(
        config,
        CustodyServiceRole::CleanupWatchdog,
        reconciliation_key,
        OperationKind::AttemptSettle,
        &format!("{request_id}:settlement-reconciliation"),
        &context.attempt_id,
        context.attempt_revision,
        context.fencing_token,
        params.settlement_deadline_at_epoch_ms,
        NestedAuthorityPayload::Reconciliation(
            ReconciliationArtifact {
                reconciliation_job_id:
                    Identifier(reconciliation_id.clone()),
                domain:
                    Identifier("TERMINAL_SETTLEMENTS".to_owned()),
                predecessor_state:
                    ReconciliationState::Pending,
                successor_state:
                    ReconciliationState::Complete,
                authoritative_cursor:
                    context.attempt_revision,
                result_sha256:
                    AuthorityDigest(
                        context.terminal_detail_sha256.clone(),
                ),
            },
        ),
        None,
        deadline_boottime_ns,
    )?;
    let recovery_evidence = if context.recovery_required {
        let recovery_key = require_signing_key(
            signing_keys,
            "emergency-cleanup-executor",
        )?;
        Some(sign_nested_artifact(
            config,
            CustodyServiceRole::CleanupWatchdog,
            recovery_key,
            OperationKind::AttemptSettle,
            &format!("{request_id}:settlement-recovery"),
            &context.attempt_id,
            context.attempt_revision,
            context.fencing_token,
            params.settlement_deadline_at_epoch_ms,
            NestedAuthorityPayload::Recovery(RecoveryArtifact {
                recovery_action:
                    Identifier("SETTLE_ATTEMPT".to_owned()),
                stable_resume_id:
                    Identifier(context.stable_resume_id.clone()),
                predecessor_state:
                    context.authoritative_state,
                successor_state: AttemptState::TerminalFailed,
                deadline_boot_id:
                    Identifier(context.deadline_boot_id.clone()),
                deadline_boot_millis:
                    context.deadline_boot_millis,
                observed_boot_id:
                    Identifier(context.observed_boot_id.clone()),
                observed_boot_millis:
                    context.observed_boot_millis,
                cleanup_deadline_boot_id:
                    Identifier(
                        context.cleanup_deadline_boot_id.clone(),
                    ),
                cleanup_deadline_boot_millis:
                    context.cleanup_deadline_boot_millis,
                owner_process_id:
                    Identifier(context.owner_process_id.clone()),
                owner_pid: context.owner_pid,
                owner_start_time_ticks:
                    context.owner_start_time_ticks,
                owner_cgroup_id:
                    Identifier(context.owner_cgroup_id.clone()),
                owner_death_observed:
                    context.owner_death_observed,
                cgroup_empty_observed:
                    context.cgroup_empty_observed,
                cgroup_death_observed:
                    context.cgroup_death_observed,
                fence_token:
                    Identifier(context.fencing_token.to_string()),
                predecessor_fence_state: FenceState::Active,
                successor_fence_state: FenceState::Revoked,
            }),
            None,
            deadline_boottime_ns,
        )?)
    } else {
        None
    };
    let reconciliation_evidence_sha256 =
        canonical_sha256(&reconciliation_evidence)?;
    let recovery_evidence_sha256 = recovery_evidence
        .as_ref()
        .map(canonical_sha256)
        .transpose()?;
    let intent = UnsignedStateAuthorityIntentV1 {
        expected_state: context.authoritative_state,
        payload: MutationPayload::SettleAttempt(
            SettleAttemptMutation {
                stable_resume_id:
                    Identifier(context.stable_resume_id.clone()),
                terminal_code:
                    Identifier(context.terminal_code.clone()),
                terminal_detail_sha256:
                    AuthorityDigest(
                        context.terminal_detail_sha256.clone(),
                    ),
                target_effect_id: context
                    .target_effect_id
                    .clone()
                    .map(Identifier),
                upstream_response_sha256: context
                    .upstream_response_sha256
                    .clone()
                    .map(AuthorityDigest),
                observed_boot_id:
                    Identifier(context.observed_boot_id.clone()),
                observed_boot_millis:
                    context.observed_boot_millis,
                cleanup_deadline: AuthorityBootDeadline {
                    clock: "CLOCK_BOOTTIME".to_owned(),
                    boot_id:
                        Identifier(
                            context
                                .cleanup_deadline_boot_id
                                .clone(),
                        ),
                    deadline_boot_millis:
                        context.cleanup_deadline_boot_millis,
                },
                reconciliation_evidence:
                    reconciliation_evidence.clone(),
                recovery_evidence:
                    recovery_evidence.clone(),
            },
        ),
    };
    let operation_id = format!("{request_id}:settlement-cas");
    let frame = signed_state_authority_frame(
        config,
        scoped,
        request_id,
        &operation_id,
        &context.attempt_id,
        context.attempt_revision,
        context.fencing_token,
        deadline_boottime_ns,
        &intent,
        signing_keys,
    )?;
    let state_request = state_execution_request(
        request_id,
        &operation_id,
        &context.attempt_id,
        &context.stable_resume_id,
        context.attempt_revision,
        context.fencing_token,
        deadline_boottime_ns,
        frame,
    );
    let (state, exact) =
        super::execute_state_mutation(config, &state_request, false)?;
    if exact.is_some() {
        return Err(V2RuntimeError::new(
            "response_data_settlement_bytes_unexpected",
            "settlement state mutation returned raw bytes",
        ));
    }
    let settlement = match state.response_data_result.as_ref() {
        Some(ResponseDataStateResult::Settlement(settlement)) => {
            settlement
        }
        _ => {
            return Err(V2RuntimeError::new(
                "response_data_settlement_result_missing",
                "state authority omitted the closed settlement result",
            ))
        }
    };
    if settlement.terminal_code.0 != context.terminal_code
        || settlement.terminal_detail_sha256.0
            != context.terminal_detail_sha256
        || settlement.predecessor_revision
            != context.attempt_revision
        || settlement.predecessor_state
            != context.authoritative_state
        || settlement.successor_revision
            != context.attempt_revision.saturating_add(1)
        || settlement.successor_state
            != AttemptState::TerminalFailed
        || settlement.target_effect_id.as_ref().map(|value| &value.0)
            != context.target_effect_id.as_ref()
        || settlement
            .upstream_response_sha256
            .as_ref()
            .map(|value| &value.0)
            != context.upstream_response_sha256.as_ref()
        || settlement.reconciliation_artifact_id.0
            != format!("{request_id}:settlement-reconciliation")
        || settlement.reconciliation_artifact_sha256.0
            != reconciliation_evidence_sha256
        || settlement.recovery_artifact_sha256
            .as_ref()
            .map(|value| &value.0)
            != recovery_evidence_sha256.as_ref()
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_result_mismatch",
            "state settlement result differs from signed context and evidence",
        ));
    }
    let post = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id: context.generation_id.clone(),
            generation: context.generation,
            request_id: format!("{request_id}:settled-state"),
            operation_id:
                format!("{request_id}:settled-observation"),
            attempt_id: context.attempt_id.clone(),
            expected_stable_resume_id:
                context.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    if post.authoritative_state != AttemptState::TerminalFailed
        || post.attempt_revision
            != context.attempt_revision.saturating_add(1)
    {
        return Err(V2RuntimeError::new(
            "response_data_settlement_state_invalid",
            "settlement did not produce the exact TERMINAL_FAILED successor",
        ));
    }
    let settlement_result_sha256 =
        state.receipt.exact_result_sha256.clone();
    let scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::CleanupWatchdog,
        reconciliation_key,
        ServiceOperationV1::Reconcile,
        request_id,
        &context.attempt_id,
        context.attempt_revision,
        context.fencing_token,
    )?;
    let mut authority_receipt = SignedDurableTerminalReceiptV1 {
        api_version: SETTLEMENT_API_VERSION.to_owned(),
        generation_id: context.generation_id.clone(),
        generation: context.generation,
        operation: ServiceOperationV1::Reconcile,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: context.attempt_id.clone(),
        stable_resume_id: context.stable_resume_id.clone(),
        authority_scope: scope.clone(),
        terminal_state: "TERMINAL_FAILED".to_owned(),
        terminal_state_sha256:
            post.authoritative_state_sha256.clone(),
        durable: true,
        reconciled: true,
        authority_sequence: post.attempt_revision,
        settlement_receipt_sha256:
            settlement_result_sha256.clone(),
        reconciliation_id: Some(reconciliation_id.clone()),
        reconciliation_artifact:
            Some(reconciliation_evidence.clone()),
        reconciliation_artifact_sha256:
            Some(reconciliation_evidence_sha256.clone()),
        recovery_artifact: recovery_evidence.clone(),
        recovery_artifact_sha256:
            recovery_evidence_sha256.clone(),
        state_authority_receipt: state.receipt,
        signer_logical_role:
            reconciliation_key.logical_role().to_owned(),
        signer_key_id:
            reconciliation_key.key_id().to_owned(),
        signature: String::new(),
    };
    authority_receipt.signature = reconciliation_key.sign(
        super::super::attestation::SETTLEMENT_SIGNATURE_DOMAIN,
        &authority_receipt.without_signature(),
    )?;
    super::super::attestation::verify_durable_terminal_receipt(
        config.custody_topology(),
        CustodyServiceRole::CleanupWatchdog,
        &authority_receipt,
    )?;
    let lifecycle_deadline_ns = params
        .lifecycle_deadline
        .absolute_boottime_ns
        .parse::<u64>()
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_lifecycle_deadline_invalid",
                "lifecycle deadline is not canonical u64 nanoseconds",
            )
        })?;
    let mut public = SignedV2DurableSettlementReceiptV1 {
        api_version: V2_DURABLE_SETTLEMENT_VERSION.to_owned(),
        generation_id: context.generation_id,
        generation: context.generation,
        operation: V2ResponseDataOperation::SettleAttempt,
        request_id: request_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        attempt_id: context.attempt_id.clone(),
        stable_resume_id: context.stable_resume_id,
        predecessor_revision: context.attempt_revision,
        predecessor_fencing_token: context.fencing_token,
        deadline_expired:
            context.observed_boot_millis.saturating_mul(1_000_000)
                >= lifecycle_deadline_ns,
        terminal_attempt: AttemptStateReference {
            attempt_id: post.attempt_id,
            state: V2AttemptState::Terminalized,
            state_sha256: post.authoritative_state_sha256,
            attempt_revision: post.attempt_revision,
            fencing_token: post.fencing_token,
        },
        terminal_receipt_sha256:
            settlement_result_sha256,
        reconciliation_id,
        reconciliation_record_sha256:
            reconciliation_evidence_sha256,
        reconciliation_evidence,
        recovery_evidence,
        recovery_evidence_sha256,
        authority_sequence: post.attempt_revision,
        authority_receipt,
        provider_scope: scope.clone(),
        provider_operation_binding_sha256:
            scope.operation_binding_sha256.clone(),
        signer_logical_role:
            reconciliation_key.logical_role().to_owned(),
        signer_provider_id: scope.service_id.clone(),
        signer_key_id:
            reconciliation_key.key_id().to_owned(),
        signer_key_material_sha256:
            scope.key_material_sha256.clone(),
        signature: String::new(),
    };
    public.signature = reconciliation_key.sign(
        V2_DURABLE_SETTLEMENT_SIGNATURE_DOMAIN,
        &public,
    )?;
    encode_result(
        V2ResponseDataResult::SettleAttempt(
            V2SettleAttemptResult { receipt: public },
        ),
        Vec::new(),
    )
}

fn execute_public_final_envelope_validation(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    rpc: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    api_version: &str,
    request_id: &str,
    boot_id: &str,
    request_sha256: &str,
    params:
        crate::response_observation_v2_api::
            V2ValidateFinalEnvelopeParams,
    request_exact_object_fds: Vec<OwnedFd>,
) -> Result<EngineResult, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        AttemptStateReference, EvidenceReference,
        ExactObjectMediaType, ImmutableObjectReference,
        ImmutableObjectType, SignedV2FinalEnvelopeVerificationV1,
        V2AttemptState, V2EvidenceType, V2ResponseDataOperation,
        V2ResponseDataResult, V2ValidateFinalEnvelopeResult,
        V2_FINAL_ENVELOPE_VERIFICATION_SIGNATURE_DOMAIN,
        V2_FINAL_ENVELOPE_VERIFICATION_VERSION,
        RESPONSE_OBSERVATION_V2_API_VERSION,
    };
    use super::super::super::state_authority::lifecycle::{
        AttemptState, OperationKind,
    };
    use super::super::super::state_authority::rpc::{
        FinalEnvelopeVerificationArtifact, FinalizeMutation,
        MutationPayload, NestedAuthorityPayload,
    };

    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != rpc.request_id
        || scoped.role != CustodyServiceRole::PolicyProofVerifier
        || boot_id != params.binding.custody_boot_id
        || params.binding.predecessor_lifecycle_state
            != V2AttemptState::ReleasePrepared
        || params.binding.attempt_revision == 0
        || params.binding.fencing_token == 0
        || params.stable_resume_id.is_empty()
        || params.authority_proof.media_type
            != ExactObjectMediaType::CanonicalJson
    {
        return Err(V2RuntimeError::new(
            "response_data_final_envelope_request_invalid",
            "final-envelope validation requires the exact completed attempt binding and one sealed canonical authority envelope",
        ));
    }
    let deadline_boottime_ns =
        public_deadline_boottime_ns(
            &params.binding.monotonic_deadline,
        )?;
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id:
                config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            request_id: format!("{request_id}:pre-finalize-state"),
            operation_id:
                format!("{request_id}:pre-finalize-observation"),
            attempt_id: params.binding.attempt_id.clone(),
            expected_stable_resume_id:
                params.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    if observation.authoritative_state
            != AttemptState::ReleasePrepared
        || observation.attempt_revision
            != params.binding.attempt_revision
        || observation.fencing_token
            != params.binding.fencing_token
        || observation.authoritative_state_sha256
            != params.binding.predecessor_state_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_final_envelope_state_mismatch",
            "final-envelope validation is not bound to the signed RELEASE_PREPARED state",
        ));
    }
    verify_immutable_raw_inspection(
        config.custody_topology(),
        &params.inspection.authority_receipt,
    )?;
    verify_state_mutation_receipt(
        config.custody_topology(),
        &params
            .release_preparation
            .authority_receipt
            .state_authority_receipt,
    )?;
    if params.release_preparation.attempt_id
            != params.binding.attempt_id
        || params.release_preparation.prepared_revision
            != params.binding.attempt_revision
        || params.release_preparation.fencing_token
            != params.binding.fencing_token
        || params.release_preparation.stable_resume_id
            != params.stable_resume_id
        || params.release_preparation
            .authority_receipt
            .release_preparation_artifact
            .body
            .attempt_id
            .0
            != params.binding.attempt_id
    {
        return Err(V2RuntimeError::new(
            "response_data_release_preparation_mismatch",
            "final-envelope validation requires the exact post-CAS RELEASE_PREPARED receipt",
        ));
    }
    let mut fds = request_exact_object_fds.into_iter();
    let fd = fds.next().ok_or_else(|| {
        V2RuntimeError::new(
            "response_data_authority_envelope_missing",
            "canonical authority-envelope descriptor has no sealed object",
        )
    })?;
    if fds.next().is_some() {
        return Err(V2RuntimeError::new(
            "response_data_authority_envelope_cardinality_invalid",
            "canonical final-envelope validation accepts exactly one sealed object",
        ));
    }
    let exact = super::super::validate_exact_object_files(
        std::slice::from_ref(&params.authority_proof),
        vec![File::from(fd)],
        None,
    )?
    .into_single()?;
    let bytes = read_exact_object_bytes(&exact)?;
    let proof_input: CanonicalAuthorityEnvelopeProofInputV2 =
        crate::decode_canonical_json(&bytes).map_err(|_| {
            V2RuntimeError::new(
                "response_data_authority_proof_noncanonical",
                "authority proof is not the exact closed canonical JSON DTO",
            )
        })?;
    if crate::canonical_json_bytes(&proof_input)
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_authority_proof_invalid",
                "authority proof cannot be canonicalized",
            )
        })?
        != bytes
    {
        return Err(V2RuntimeError::new(
            "response_data_authority_proof_noncanonical",
            "authority proof bytes are not canonical",
        ));
    }
    let authority_envelope =
        complete_authority_envelope(config, proof_input)?;
    validate_canonical_authority_envelope(&authority_envelope)?;
    verify_pinned_authority_envelope(
        config,
        &authority_envelope,
        &params,
        request_id,
    )?;
    let public = &authority_envelope.public_envelope;
    let canonical_envelope_bytes_sha256 =
        canonical_sha256(&authority_envelope)?;
    let canonical_envelope_bytes =
        canonical_jcs_bytes(&authority_envelope).map_err(|error| {
            V2RuntimeError::new(
                "response_data_authority_envelope_invalid",
                error.to_string(),
            )
        })?;
    let policy = match &authority_envelope
        .authority_envelope
        .authority_artifacts
        .get(3)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_policy_proof_missing",
                "canonical ten-artifact envelope has no policy proof",
            )
        })?
        .body
        .payload
    {
        NestedAuthorityPayload::PolicyProof(policy)
            if policy.passed => policy,
        _ => {
            return Err(V2RuntimeError::new(
                "response_data_policy_proof_invalid",
                "canonical policy-proof artifact is not passing",
            ))
        }
    };
    let proof_key =
        require_signing_key(signing_keys, "live-proof-verifier")?;
    let verification_artifact = sign_nested_artifact(
        config,
        CustodyServiceRole::PolicyProofVerifier,
        proof_key,
        OperationKind::AttemptFinalize,
        &format!("{request_id}:final-envelope-verification"),
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
        params.binding.deadline_at_epoch_ms,
        NestedAuthorityPayload::FinalEnvelopeVerification(
            FinalEnvelopeVerificationArtifact {
                policy_decision_id:
                    policy.policy_decision_id.clone(),
                policy_generation_sha256:
                    policy.policy_generation_sha256.clone(),
                final_envelope_body_sha256:
                    authority_envelope
                        .authority_envelope
                        .body_sha256
                        .clone(),
                raw_response_object_sha256:
                    authority_envelope
                        .authority_envelope
                        .body
                        .raw_response_object
                        .content_sha256
                        .clone(),
                response_framing_sha256:
                    authority_envelope
                        .authority_envelope
                        .body
                        .http11_framing
                        .canonical_framing_sha256
                        .clone(),
                released_projection_sha256:
                    authority_envelope
                        .authority_envelope
                        .body
                        .released_projection_sha256
                        .clone(),
                passed: true,
            },
        ),
        None,
        deadline_boottime_ns,
    )?;
    let verification_artifact_sha256 =
        canonical_sha256(&verification_artifact)?;
    let artifact_ledger_evidence = authority_envelope
        .authority_envelope
        .authority_artifacts
        .get(7)
        .cloned()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_artifact_commit_missing",
                "canonical ten-artifact envelope has no artifact commit",
            )
        })?;
    let finalization_intent = UnsignedStateAuthorityIntentV1 {
        expected_state: AttemptState::ReleasePrepared,
        payload: MutationPayload::Finalize(FinalizeMutation {
            finalization_id: Identifier(
                authority_envelope.finalization_id.clone(),
            ),
            final_envelope:
                authority_envelope.authority_envelope.clone(),
            final_envelope_verification:
                verification_artifact.clone(),
            artifact_ledger_evidence,
        }),
    };
    let finalize_operation_id =
        format!("{request_id}:finalize-cas");
    let frame = signed_state_authority_frame(
        config,
        scoped,
        request_id,
        &finalize_operation_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
        deadline_boottime_ns,
        &finalization_intent,
        signing_keys,
    )?;
    let state_request = state_execution_request(
        request_id,
        &finalize_operation_id,
        &observation.attempt_id,
        &observation.stable_resume_id,
        observation.attempt_revision,
        observation.fencing_token,
        deadline_boottime_ns,
        frame,
    );
    let (state, exact) =
        super::execute_state_mutation(config, &state_request, false)?;
    if exact.is_some() {
        return Err(V2RuntimeError::new(
            "response_data_finalization_bytes_unexpected",
            "finalization state mutation returned raw bytes",
        ));
    }
    let post = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id: observation.generation_id.clone(),
            generation: observation.generation,
            request_id: format!("{request_id}:finalized-state"),
            operation_id:
                format!("{request_id}:finalized-observation"),
            attempt_id: observation.attempt_id.clone(),
            expected_stable_resume_id:
                observation.stable_resume_id.clone(),
            raw_response_object_id: None,
            include_proof_material: false,
            deadline_boottime_ns,
        },
    )?;
    if post.authoritative_state != AttemptState::Finalized
        || post.attempt_revision
            != observation.attempt_revision.saturating_add(1)
        || post.fencing_token != observation.fencing_token
    {
        return Err(V2RuntimeError::new(
            "response_data_finalization_state_mismatch",
            "post-finalization state is not the exact FINALIZED successor",
        ));
    }
    let result_sha256 = canonical_sha256(&serde_json::json!({
        "operationId": rpc.request_id,
        "finalEnvelopeSha256": public.final_envelope_sha256,
        "authorityArtifactsRootSha256":
            public.authority_artifacts_root_sha256,
        "canonicalEnvelopeBytesSha256":
            canonical_envelope_bytes_sha256,
        "finalizedRevision": post.attempt_revision,
        "verified": true
    }))?;
    let proof_scope = provider_authority_scope(
        config.custody_topology(),
        CustodyServiceRole::PolicyProofVerifier,
        proof_key,
        ServiceOperationV1::FinalEnvelopeVerify,
        request_id,
        &observation.attempt_id,
        observation.attempt_revision,
        observation.fencing_token,
    )?;
    let mut authority_receipt =
        SignedFinalEnvelopeVerificationV1 {
            api_version:
                FINAL_ENVELOPE_VERIFICATION_API_VERSION.to_owned(),
            generation_id: public.generation_id.clone(),
            generation: public.generation,
            operation: ServiceOperationV1::FinalEnvelopeVerify,
            request_id: request_id.to_owned(),
            attempt_id: public.attempt_id.clone(),
            stable_resume_id: public.stable_resume_id.clone(),
            authority_scope: proof_scope.clone(),
            final_envelope_sha256:
                public.final_envelope_sha256.clone(),
            authority_artifacts_root_sha256:
                public.authority_artifacts_root_sha256.clone(),
            canonical_envelope_bytes_sha256:
                canonical_envelope_bytes_sha256.clone(),
            transition_chain_root_sha256:
                public.transition_chain_root_sha256.clone(),
            raw_response_object_sha256:
                public.raw_response_object_sha256.clone(),
            raw_response_byte_length:
                public.raw_response_byte_length,
            framing_validation_sha256:
                public.framing_validation_sha256.clone(),
            parsed_response_sha256:
                public.parsed_response_sha256.clone(),
            released_projection_sha256:
                public.released_projection_sha256.clone(),
            verified: true,
            verification_sequence: post.attempt_revision,
            verification_result_sha256:
                result_sha256.clone(),
            final_envelope_verification_artifact:
                verification_artifact,
            final_envelope_verification_artifact_sha256:
                verification_artifact_sha256,
            signer_logical_role:
                proof_key.logical_role().to_owned(),
            signer_key_id: proof_key.key_id().to_owned(),
            signature: String::new(),
        };
    authority_receipt.signature = proof_key.sign(
        super::super::attestation::
            FINAL_ENVELOPE_SIGNATURE_DOMAIN,
        &authority_receipt.without_signature(),
    )?;
    verify_final_envelope_verification(
        config.custody_topology(),
        &authority_receipt,
    )?;
    let mut verification =
        SignedV2FinalEnvelopeVerificationV1 {
            api_version:
                V2_FINAL_ENVELOPE_VERIFICATION_VERSION.to_owned(),
            generation_id: public.generation_id.clone(),
            generation: public.generation,
            operation:
                V2ResponseDataOperation::ValidateFinalEnvelope,
            request_id: request_id.to_owned(),
            request_sha256: request_sha256.to_owned(),
            attempt_id: public.attempt_id.clone(),
            attempt_revision: post.attempt_revision,
            stable_resume_id: public.stable_resume_id.clone(),
            fencing_token: public.fencing_token,
            final_envelope_sha256:
                public.final_envelope_sha256.clone(),
            authority_artifacts_root_sha256:
                public.authority_artifacts_root_sha256.clone(),
            canonical_envelope_bytes_sha256:
                canonical_envelope_bytes_sha256.clone(),
            transition_chain_root_sha256:
                public.transition_chain_root_sha256.clone(),
            raw_response_sha256:
                public.raw_response_object_sha256.clone(),
            framing_validation_sha256:
                public.framing_validation_sha256.clone(),
            parsed_response_sha256:
                public.parsed_response_sha256.clone(),
            verified: true,
            verification_sequence: post.attempt_revision,
            verification_result_sha256: result_sha256,
            authority_receipt,
            provider_scope: proof_scope.clone(),
            provider_operation_binding_sha256:
                proof_scope.operation_binding_sha256.clone(),
            signer_logical_role:
                proof_key.logical_role().to_owned(),
            signer_provider_id:
                proof_scope.service_id.clone(),
            signer_key_id: proof_key.key_id().to_owned(),
            signer_key_material_sha256:
                proof_scope.key_material_sha256.clone(),
            signature: String::new(),
        };
    verification.signature = proof_key.sign(
        V2_FINAL_ENVELOPE_VERIFICATION_SIGNATURE_DOMAIN,
        &verification,
    )?;
    let state_receipt_sha256 =
        canonical_sha256(&state.receipt)?;
    let envelope_reference = ImmutableObjectReference {
        object_type: ImmutableObjectType::ResponseObservationEnvelope,
        object_sha256:
            canonical_envelope_bytes_sha256.clone(),
        byte_length:
            u64::try_from(canonical_envelope_bytes.len())
                .map_err(|_| {
                    V2RuntimeError::new(
                        "response_data_authority_envelope_too_large",
                        "canonical authority envelope length exceeds u64",
                    )
                })?,
        retrieval_id: authority_envelope.finalization_id.clone(),
        persistence_receipt_sha256:
            state_receipt_sha256.clone(),
    };
    let authority_artifacts_root_sha256 =
        authority_envelope
            .public_envelope
            .authority_artifacts_root_sha256
            .clone();
    encode_result(
        V2ResponseDataResult::ValidateFinalEnvelope(
            V2ValidateFinalEnvelopeResult {
                attempt: AttemptStateReference {
                    attempt_id: post.attempt_id,
                    state: V2AttemptState::Finalized,
                    state_sha256:
                        post.authoritative_state_sha256,
                    attempt_revision: post.attempt_revision,
                    fencing_token: post.fencing_token,
                },
                envelope: envelope_reference,
                persistence_evidence: EvidenceReference {
                    evidence_type: V2EvidenceType::Persistence,
                    evidence_sha256:
                        state_receipt_sha256.clone(),
                    retrieval_id:
                        format!("{request_id}:finalization-state"),
                },
                finalization_checkpoint: EvidenceReference {
                    evidence_type:
                        V2EvidenceType::FinalizationCheckpoint,
                    evidence_sha256:
                        state.receipt.exact_result_sha256.clone(),
                    retrieval_id:
                        format!("{request_id}:finalization-checkpoint"),
                },
                finalized_response:
                    params.inspection.raw_response,
                canonical_authority_envelope:
                    authority_envelope,
                authority_artifacts_root_sha256:
                    authority_artifacts_root_sha256,
                verification,
            },
        ),
        Vec::new(),
    )
}

fn complete_authority_envelope(
    config: &RootOwnedResponseObservationV2Config,
    mut proof: CanonicalAuthorityEnvelopeProofInputV2,
) -> Result<CanonicalAuthorityEnvelopeDescriptorV2, V2RuntimeError> {
    use super::super::protocol::
        CANONICAL_AUTHORITY_ENVELOPE_API_VERSION;
    use crate::response_observation_v2_api::
        V2_CANONICAL_FINAL_ENVELOPE_VERSION;

    if proof.api_version
            != CANONICAL_AUTHORITY_ENVELOPE_API_VERSION
        || proof.finalization_id.is_empty()
        || proof.public_envelope.api_version
            != V2_CANONICAL_FINAL_ENVELOPE_VERSION
        || proof.public_envelope.finalization_id
            != proof.finalization_id
        || !proof
            .public_envelope
            .authority_artifacts_root_sha256
            .is_empty()
        || !proof.public_envelope.final_envelope_sha256.is_empty()
        || !proof
            .authority_body
            .authority_artifacts_root_sha256
            .0
            .is_empty()
        || proof.authority_body.finalization_id.0
            != proof.finalization_id
    {
        return Err(V2RuntimeError::new(
            "response_data_authority_proof_precompleted",
            "authority proof must leave both artifact-root fields and final-envelope digest empty for engine completion",
        ));
    }
    for artifact in &proof.authority_artifacts {
        verify_pinned_authority_artifact(
            config.custody_topology(),
            artifact,
            &proof.public_envelope.attempt_id,
            proof.public_envelope.fencing_token,
        )?;
    }
    let root = ordered_authority_artifacts_root_sha256(
        &proof.authority_artifacts,
    )?;
    proof.public_envelope.authority_artifacts_root_sha256 =
        root.clone();
    proof.authority_body.authority_artifacts_root_sha256 =
        AuthorityDigest(root.clone());
    let body_sha256 = sha256_digest(
        &canonical_jcs_bytes(&proof.authority_body).map_err(
            |error| {
                V2RuntimeError::new(
                    "response_data_authority_body_invalid",
                    error.to_string(),
                )
            },
        )?,
    );
    let authority_envelope = CanonicalFinalEnvelope {
        api_version: FINAL_ENVELOPE_API_VERSION.to_owned(),
        kind: FINAL_ENVELOPE_KIND.to_owned(),
        schema_version: "1".to_owned(),
        body: proof.authority_body,
        body_sha256,
        authority_artifacts: proof.authority_artifacts,
    };
    authority_envelope.validate().map_err(|error| {
        V2RuntimeError::new(
            "response_data_authority_envelope_invalid",
            error.to_string(),
        )
    })?;
    let mut completed = CanonicalAuthorityEnvelopeDescriptorV2 {
        api_version:
            CANONICAL_AUTHORITY_ENVELOPE_API_VERSION.to_owned(),
        finalization_id: proof.finalization_id,
        public_envelope: proof.public_envelope,
        authority_envelope,
        authority_artifacts_root_sha256: root,
        final_envelope_sha256: String::new(),
    };
    let final_envelope_sha256 =
        canonical_authority_envelope_preimage_sha256(&completed)?;
    completed.final_envelope_sha256 =
        final_envelope_sha256.clone();
    completed.public_envelope.final_envelope_sha256 =
        final_envelope_sha256;
    Ok(completed)
}

fn read_exact_object_bytes(
    exact: &super::super::ValidatedExactObject,
) -> Result<Vec<u8>, V2RuntimeError> {
    let length = usize::try_from(exact.descriptor().byte_length)
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_exact_object_too_large",
                "exact authority-envelope length does not fit memory",
            )
        })?;
    let mut bytes = vec![0u8; length];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = exact.read_at(
            &mut bytes[offset..],
            offset as u64,
        )?;
        if read == 0 {
            return Err(V2RuntimeError::new(
                "response_data_exact_object_truncated",
                "sealed authority-envelope object ended before its committed length",
            ));
        }
        offset = offset.checked_add(read).ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_exact_object_overflow",
                "exact authority-envelope read offset overflowed",
            )
        })?;
    }
    Ok(bytes)
}

fn verify_pinned_authority_envelope(
    config: &RootOwnedResponseObservationV2Config,
    descriptor: &CanonicalAuthorityEnvelopeDescriptorV2,
    params:
        &crate::response_observation_v2_api::
            V2ValidateFinalEnvelopeParams,
    request_id: &str,
) -> Result<(), V2RuntimeError> {
    let topology = config.custody_topology();
    let public = &descriptor.public_envelope;
    let binding = &params.binding;
    let expected_preimage =
        canonical_authority_envelope_preimage_sha256(descriptor)?;
    if public.generation_id != topology.generation_id
        || public.generation != topology.generation
        || public.request_id != request_id
        || public.attempt_id != binding.attempt_id
        || public.stable_resume_id != params.stable_resume_id
        || public.terminal_revision != binding.attempt_revision
        || public.fencing_token != binding.fencing_token
        || public.raw_response_object_sha256
            != params.inspection.raw_response.object_sha256
        || public.raw_response_byte_length
            != params.inspection.raw_response.byte_length
        || public.framing_validation_sha256
            != params.http11_framing.canonical_framing_sha256
        || public.parsed_response_sha256
            != params.inspection.parsed_response_sha256
        || public.released_projection_sha256
            != params.inspection.released_projection_sha256
        || public.exact_policy_decision_sha256
            != binding.transaction.policy_sha256
        || binding.transaction.upstream_response_sha256.as_deref()
            != Some(public.raw_response_object_sha256.as_str())
        || descriptor.final_envelope_sha256 != expected_preimage
    {
        return Err(V2RuntimeError::new(
            "response_data_authority_envelope_binding_mismatch",
            "canonical authority envelope is not bound to the installed generation and exact completed public attempt",
        ));
    }
    let inspection = &params.inspection.authority_receipt;
    if inspection.generation_id != public.generation_id
        || inspection.generation != public.generation
        || inspection.attempt_id != public.attempt_id
        || inspection.stable_resume_id != public.stable_resume_id
        || inspection.raw_object_sha256
            != public.raw_response_object_sha256
        || inspection.raw_object_byte_length
            != public.raw_response_byte_length
        || inspection.framing_validation_sha256
            != public.framing_validation_sha256
        || inspection.parsed_response_sha256
            != public.parsed_response_sha256
        || inspection.released_projection_sha256
            != public.released_projection_sha256
        || inspection.authority_scope.fencing_token
            != public.fencing_token
    {
        return Err(V2RuntimeError::new(
            "response_data_inspection_authority_binding_mismatch",
            "signed immutable inspection does not bind the canonical authority envelope",
        ));
    }
    Ok(())
}

pub(in super::super) fn verify_pinned_authority_artifact(
    topology: &super::super::config::SignedCustodyTopologyV1,
    artifact: &SignedAuthorityArtifact,
    attempt_id: &str,
    fencing_token: u64,
) -> Result<(), V2RuntimeError> {
    artifact.validate_contract().map_err(|error| {
        V2RuntimeError::new(
            "response_data_nested_authority_contract_invalid",
            error.to_string(),
        )
    })?;
    let body = &artifact.body;
    let service_role =
        custody_service_role(body.producing_service_role);
    let process = topology.process(service_role).ok_or_else(|| {
        V2RuntimeError::new(
            "response_data_nested_authority_process_missing",
            "nested authority artifact names a service absent from the installed topology",
        )
    })?;
    let logical_role = body
        .producing_logical_role
        .as_ref()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_nested_authority_logical_role_missing",
                "nested authority artifact must use an installed role-scoped subkey",
            )
        })?;
    let binding = topology
        .logical_role(&logical_role.0)
        .filter(|binding| {
            binding.service_role == service_role
                && binding.key_id == body.key_id.0
                && binding.public_key_sha256
                    == body.key_material_sha256.0
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_nested_authority_key_unassigned",
                "nested authority artifact signer is not assigned by the installed topology",
            )
        })?;
    let key = process
        .role_keys
        .iter()
        .find(|key| {
            key.logical_role == binding.logical_role
                && key.key_id == binding.key_id
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_nested_authority_key_missing",
                "installed topology has no public-key descriptor for the nested authority signer",
            )
        })?;
    if body.generation_id.0 != topology.generation_id
        || body.attempt_id.0 != attempt_id
        || body.fence_token.0 != fencing_token.to_string()
        || body.producing_process_id.0 != process.service_id
        || body.authority_scope.generation_id.0
            != topology.generation_id
        || body.authority_scope.process_id.0
            != process.service_id
        || body.authority_scope.service_role
            != body.producing_service_role
        || body.authority_scope.logical_role.as_ref()
            != body.producing_logical_role.as_ref()
        || body.authority_scope.key_id != body.key_id
        || body.authority_scope.key_material_sha256
            != body.key_material_sha256
        || body.authority_scope.executable_sha256.0
            != process.executable_sha256
        || body.authority_scope.configuration_sha256.0
            != process.configuration_sha256
        || !body
            .authority_scope
            .allowed_operations
            .contains(&body.operation)
        || artifact.authentication.algorithm != SIGNATURE_ALGORITHM
        || artifact.authentication.key_id != body.key_id
        || artifact.authentication.key_material_sha256
            != body.key_material_sha256
        || artifact.authentication.authority_scope_sha256
            != body.authority_scope_sha256
        || artifact.authentication.signing_domain
            != "serverware.responseV2.nestedAuthorityArtifact.signature/v1"
    {
        return Err(V2RuntimeError::new(
            "response_data_nested_authority_binding_mismatch",
            "nested authority artifact identity or scope differs from the installed generation, attempt, fence, process, executable, configuration, and subkey",
        ));
    }
    let canonical = canonical_jcs_bytes(body).map_err(|error| {
        V2RuntimeError::new(
            "response_data_nested_authority_body_invalid",
            error.to_string(),
        )
    })?;
    if sha256_digest(&canonical)
        != artifact.authentication.signed_payload_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_nested_authority_digest_mismatch",
            "nested authority signature does not cover the canonical artifact body",
        ));
    }
    let mut public_key_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&key.public_key_path)
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_nested_authority_public_key_unavailable",
                "open installed nested-authority public key",
            )
        })?;
    let metadata = public_key_file.metadata().map_err(|_| {
        V2RuntimeError::new(
            "response_data_nested_authority_public_key_unavailable",
            "inspect installed nested-authority public key",
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(V2RuntimeError::new(
            "response_data_nested_authority_public_key_unsafe",
            "nested-authority public key must be a root-owned immutable regular file",
        ));
    }
    let mut public_key = Vec::with_capacity(metadata.len() as usize);
    public_key_file.read_to_end(&mut public_key).map_err(|_| {
        V2RuntimeError::new(
            "response_data_nested_authority_public_key_unavailable",
            "read installed nested-authority public key",
        )
    })?;
    if public_key.len() != 32
        || format!("sha256:{:x}", Sha256::digest(&public_key))
            != key.public_key_sha256
    {
        return Err(V2RuntimeError::new(
            "response_data_nested_authority_public_key_invalid",
            "installed nested-authority public key does not match the signed topology",
        ));
    }
    let public_key: [u8; 32] =
        public_key.try_into().map_err(|_| {
            V2RuntimeError::new(
                "response_data_nested_authority_public_key_invalid",
                "nested-authority public key is not Ed25519",
            )
        })?;
    let signature = decode_base64url(
        "nestedAuthorityArtifact.authentication.signatureBase64url",
        &artifact.authentication.signature_base64url,
    )
    .map_err(|error| {
        V2RuntimeError::new(
            "response_data_nested_authority_signature_invalid",
            error.to_string(),
        )
    })?;
    let signature = Signature::from_slice(&signature).map_err(|_| {
        V2RuntimeError::new(
            "response_data_nested_authority_signature_invalid",
            "nested authority signature is not 64-byte Ed25519",
        )
    })?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_nested_authority_public_key_invalid",
                "nested-authority public key is not a valid Ed25519 point",
            )
        })?
        .verify(
            &signature_message(
                NESTED_AUTHORITY_SIGNATURE_DOMAIN,
                &canonical,
            ),
            &signature,
        )
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_nested_authority_signature_invalid",
                "nested authority signature is not valid for the installed subkey",
            )
        })
}

fn custody_service_role(role: ServiceRole) -> CustodyServiceRole {
    match role {
        ServiceRole::CustodyRouter => {
            CustodyServiceRole::CustodyRouter
        }
        ServiceRole::StateAuthority => {
            CustodyServiceRole::StateAuthority
        }
        ServiceRole::CredentialTransport => {
            CustodyServiceRole::CredentialTransport
        }
        ServiceRole::PolicyProofVerifier => {
            CustodyServiceRole::PolicyProofVerifier
        }
        ServiceRole::ImmutableArtifactLedger => {
            CustodyServiceRole::ImmutableArtifactLedger
        }
        ServiceRole::ReleaseAttestorPublisher => {
            CustodyServiceRole::ReleaseAttestorPublisher
        }
        ServiceRole::CleanupWatchdog => {
            CustodyServiceRole::CleanupWatchdog
        }
    }
}

fn authority_service_role(role: CustodyServiceRole) -> ServiceRole {
    match role {
        CustodyServiceRole::CustodyRouter => ServiceRole::CustodyRouter,
        CustodyServiceRole::StateAuthority => ServiceRole::StateAuthority,
        CustodyServiceRole::CredentialTransport => {
            ServiceRole::CredentialTransport
        }
        CustodyServiceRole::PolicyProofVerifier => {
            ServiceRole::PolicyProofVerifier
        }
        CustodyServiceRole::ImmutableArtifactLedger => {
            ServiceRole::ImmutableArtifactLedger
        }
        CustodyServiceRole::ReleaseAttestorPublisher => {
            ServiceRole::ReleaseAttestorPublisher
        }
        CustodyServiceRole::CleanupWatchdog => {
            ServiceRole::CleanupWatchdog
        }
    }
}

fn require_signing_key<'a>(
    signing_keys: &'a BTreeMap<String, RoleSigningKey>,
    logical_role: &str,
) -> Result<&'a RoleSigningKey, V2RuntimeError> {
    signing_keys.get(logical_role).ok_or_else(|| {
        V2RuntimeError::new(
            "response_data_signing_key_missing",
            format!(
                "installed service did not load the {logical_role} role key"
            ),
        )
    })
}

fn public_deadline_boottime_ns(
    deadline:
        &crate::response_observation_v2_api::V2MonotonicDeadlineV1,
) -> Result<u64, V2RuntimeError> {
    use crate::response_observation_v2_api::{
        V2MonotonicClockId, V2_MONOTONIC_DEADLINE_VERSION,
    };
    let absolute = deadline
        .absolute_boottime_ns
        .parse::<u64>()
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_deadline_invalid",
                "response-data deadline is not canonical u64 nanoseconds",
            )
        })?;
    let boot_id = super::super::recovery::kernel_boot_id()?;
    let now = super::super::recovery::boottime_ns()?;
    if deadline.api_version != V2_MONOTONIC_DEADLINE_VERSION
        || deadline.clock_id != V2MonotonicClockId::ClockBoottime
        || deadline.custody_boot_id != boot_id
        || absolute <= now
    {
        return Err(V2RuntimeError::new(
            "response_data_deadline_invalid",
            "response-data deadline is not a live CLOCK_BOOTTIME deadline for this boot",
        ));
    }
    Ok(absolute)
}

fn verify_public_observed_projection(
    observation: &super::super::protocol::
        SignedAttemptStateObservationV1,
    attempt_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
    state_sha256: &str,
    stable_resume_id: &str,
) -> Result<(), V2RuntimeError> {
    use super::super::super::state_authority::lifecycle::AttemptState;
    if observation.attempt_id != attempt_id
        || observation.attempt_revision != attempt_revision
        || observation.authoritative_state != AttemptState::Observed
        || observation.fencing_token != fencing_token
        || observation.authoritative_state_sha256 != state_sha256
        || observation.stable_resume_id != stable_resume_id
    {
        return Err(V2RuntimeError::new(
            "response_data_observed_projection_mismatch",
            "unsigned public projection differs from the signed internal OBSERVED attempt",
        ));
    }
    Ok(())
}

fn canonical_inspection_seed(
    seed: &CanonicalAuthorityEnvelopeProofSeedV2,
) -> Result<
    super::super::super::state_authority::rpc::
        CanonicalInspectionSeed,
    V2RuntimeError,
> {
    use super::super::super::state_authority::rpc::{
        CanonicalInspectionSeed, CanonicalInspectionSeedBody,
    };
    let body = CanonicalInspectionSeedBody {
        generation_id: Identifier(seed.generation_id.clone()),
        attempt_id: Identifier(seed.attempt_id.clone()),
        attempt_revision: seed.attempt_revision,
        fence_token: Identifier(seed.fencing_token.to_string()),
        stable_resume_id: Identifier(seed.stable_resume_id.clone()),
        raw_response_object: seed.raw_response_object.clone(),
        inspection_result_sha256: AuthorityDigest(
            seed.inspection_receipt_sha256.clone(),
        ),
        authority_artifacts_root_sha256: AuthorityDigest(
            seed.authority_artifacts_root_sha256.clone(),
        ),
    };
    let canonical = CanonicalInspectionSeed {
        api_version: FINAL_ENVELOPE_API_VERSION.to_owned(),
        kind: "ResponseV2InspectionSeed".to_owned(),
        schema_version: "1".to_owned(),
        body_sha256: sha256_digest(
            &canonical_jcs_bytes(&body).map_err(|error| {
                V2RuntimeError::new(
                    "response_data_inspection_seed_invalid",
                    error.to_string(),
                )
            })?,
        ),
        body,
        authority_artifacts: seed.authority_artifacts.clone(),
    };
    canonical.validate().map_err(|error| {
        V2RuntimeError::new(
            "response_data_inspection_seed_invalid",
            error.to_string(),
        )
    })?;
    Ok(canonical)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn sign_nested_artifact(
    config: &RootOwnedResponseObservationV2Config,
    service_role: CustodyServiceRole,
    key: &RoleSigningKey,
    operation:
        super::super::super::state_authority::lifecycle::OperationKind,
    artifact_id: &str,
    attempt_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
    expires_at_epoch_millis: u64,
    payload:
        super::super::super::state_authority::rpc::
            NestedAuthorityPayload,
    issued_at_epoch_millis: Option<u64>,
    deadline_boottime_ns: u64,
) -> Result<SignedAuthorityArtifact, V2RuntimeError> {
    if let super::super::super::state_authority::rpc::
        NestedAuthorityPayload::TransparencyCheckpoint(transparency) =
        &payload
    {
        if service_role != CustodyServiceRole::ReleaseAttestorPublisher
            || transparency != config.release_transparency_artifact()
        {
            return Err(V2RuntimeError::new(
                "release_transparency_artifact_substitution",
                "release-attestor-publisher may sign only the exact root-owned prevalidated release transparency proof",
            ));
        }
    }
    let topology = config.custody_topology();
    let process = topology.process(service_role).ok_or_else(|| {
        V2RuntimeError::new(
            "response_data_artifact_process_missing",
            "nested artifact service is absent from installed topology",
        )
    })?;
    let binding = topology
        .logical_role(key.logical_role())
        .filter(|binding| {
            binding.service_role == service_role
                && binding.key_id == key.key_id()
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "response_data_artifact_key_unassigned",
                "nested artifact key is not assigned by installed topology",
            )
        })?;
    let authority_role = authority_service_role(service_role);
    let signer = LocalAuthorityArtifactSigner {
        key,
        role_id: Identifier(process.service_id.clone()),
        key_id: Identifier(binding.key_id.clone()),
        identity:
            super::super::super::state_authority::rpc::
                AuthoritySignerIdentity {
                role_id: Identifier(process.service_id.clone()),
                process_id: Identifier(process.service_id.clone()),
                service_role: authority_role,
                logical_role:
                    Identifier(binding.logical_role.clone()),
                key_id: Identifier(binding.key_id.clone()),
                key_material_sha256:
                    AuthorityDigest(
                        binding.public_key_sha256.clone(),
                    ),
                executable_sha256:
                    AuthorityDigest(process.executable_sha256.clone()),
                configuration_sha256:
                    AuthorityDigest(
                        process.configuration_sha256.clone(),
                    ),
                allowed_operations:
                    super::super::super::state_authority::services::
                        service_contract(authority_role)
                        .operations
                        .to_vec(),
            },
    };
    let observed_epoch_millis: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_artifact_time_invalid",
                "system clock predates Unix epoch",
            )
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_artifact_time_invalid",
                "system epoch milliseconds overflow u64",
            )
        })?;
    let issued_at_epoch_millis =
        issued_at_epoch_millis.unwrap_or(observed_epoch_millis);
    if issued_at_epoch_millis == 0
        || issued_at_epoch_millis > observed_epoch_millis
    {
        return Err(V2RuntimeError::new(
            "response_data_artifact_time_invalid",
            "nested artifact issuance must be a positive time no later than the observed clock",
        ));
    }
    if let super::super::super::state_authority::rpc::
        NestedAuthorityPayload::TransparencyCheckpoint(transparency) =
        &payload
    {
        config.verify_release_transparency_artifact(
            transparency,
            issued_at_epoch_millis,
            observed_epoch_millis,
        )?;
    }
    if expires_at_epoch_millis <= issued_at_epoch_millis {
        return Err(V2RuntimeError::new(
            "response_data_artifact_expired",
            "nested artifact expiry is not in the future",
        ));
    }
    let deadline = AuthorityBootDeadline {
        clock: "CLOCK_BOOTTIME".to_owned(),
        boot_id: Identifier(
            super::super::recovery::kernel_boot_id()?,
        ),
        deadline_boot_millis: deadline_boottime_ns / 1_000_000,
    };
    super::super::super::state_authority::rpc::
        sign_authority_artifact(
            &signer,
            &Identifier(topology.generation_id.clone()),
            Identifier(artifact_id.to_owned()),
            operation,
            &Identifier(artifact_id.to_owned()),
            &Identifier(attempt_id.to_owned()),
            attempt_revision,
            &Identifier(fencing_token.to_string()),
            issued_at_epoch_millis,
            expires_at_epoch_millis,
            payload,
            &deadline,
        )
        .map_err(|error| {
            V2RuntimeError::new(
                "response_data_artifact_signing_failed",
                error.to_string(),
            )
        })
}

fn execute_state_mutation(
    config: &RootOwnedResponseObservationV2Config,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<EngineResult, V2RuntimeError> {
    if let Ok(query) = serde_json::from_value::<super::super::protocol::StagedOriginalQueryV1>(
        request.payload.clone()) {
        if query.request_id != request.request_id
            || query.deadline_boottime_ns != request.deadline_boottime_ns {
            return Err(V2RuntimeError::new("staged_original_envelope_mismatch",
                "original query must retain the actual StateCas request and deadline"));
        }
        let signing_key = require_signing_key(signing_keys, "linearizable-store")?;
        return encode_result(super::state_authority::query_staged_original_postgres(
            config, &query, signing_key)?, Vec::new());
    }
    if let Ok(query) =
        serde_json::from_value::<SettlementEvidenceContextRequestV1>(
            request.payload.clone(),
        )
    {
        let signing_key =
            require_signing_key(signing_keys, "linearizable-store")?;
        return encode_result(
            super::state_authority::
                query_settlement_evidence_context_postgres(
                    config,
                    &query,
                    signing_key,
                )?,
            Vec::new(),
        );
    }
    if let Ok(query) =
        serde_json::from_value::<AttemptStateQueryRequestV1>(
            request.payload.clone(),
        )
    {
        let signing_key = signing_keys
            .get("linearizable-store")
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "state_authority_engine_key_missing",
                    "state-authority did not load linearizable-store",
                )
            })?;
        return encode_result(
            super::state_authority::
                query_attempt_observation_postgres(
                    config,
                    &query,
                    signing_key,
                )?,
            Vec::new(),
        );
    }
    let execution: StateMutationExecutionRequestV1 =
        decode_payload(request)?;
    validate_state_execution(config, &execution)?;
    let sequence_profile = execution.api_version
        == super::super::protocol::SEQUENCE_STATE_AUTHORITY_API_VERSION;
    let signing_key = signing_keys
        .get("linearizable-store")
        .ok_or_else(|| {
            V2RuntimeError::new(
                "state_authority_engine_key_missing",
                "state-authority did not load linearizable-store",
            )
        })?;
    let state = super::state_authority::execute_profile_postgres(
        config,
        &execution.frame,
        &execution.request_id,
        &execution.operation_id,
        &execution.attempt_id,
        &execution.stable_resume_id,
        execution.attempt_revision,
        execution.fencing_token,
        signing_key,
        sequence_profile,
    )?;
    let response_data_result = state.response_data_result;
    let (exact_object, exact_object_fds) =
        match (state.exact_descriptor, state.exact_raw) {
            (Some(descriptor), Some(bytes)) => (
                Some(descriptor),
                vec![sealed_memfd(&bytes)?],
            ),
            (None, None) => (None, Vec::new()),
            _ => {
                return Err(V2RuntimeError::new(
                    "state_authority_exact_object_mismatch",
                    "authority result descriptor and bytes disagree",
                ))
            }
        };
    encode_result(
        StateMutationExecutionResultV1 {
            receipt: state.receipt,
            response_data_result,
            exact_object,
        },
        exact_object_fds,
    )
}

fn execute_final_verification(
    request: &ServiceRpcEnvelopeV1,
) -> Result<EngineResult, V2RuntimeError> {
    let _: FinalEnvelopeVerificationRequestV1 =
        decode_payload(request)?;
    Err(V2RuntimeError::new(
        "canonical_authority_envelope_required",
        "legacy final-envelope verification without exactly ten pinned signed authority artifacts is disabled",
    ))
}

fn execute_inspection(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<EngineResult, V2RuntimeError> {
    let request: InspectImmutableRawRequestV1 =
        decode_payload(request)?;
    validate_inspection_state_intent(&request)?;
    let frame = signed_state_authority_frame(
        config,
        scoped,
        &request.request_id,
        &request.operation_id,
        &request.attempt_id,
        request.attempt_revision,
        request.fencing_token,
        request.deadline_boottime_ns,
        &request.state_authority_intent,
        signing_keys,
    )?;
    let state_request = StateMutationExecutionRequestV1 {
        api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        attempt_id: request.attempt_id.clone(),
        stable_resume_id: request.stable_resume_id.clone(),
        attempt_revision: request.attempt_revision,
        fencing_token: request.fencing_token,
        deadline_boottime_ns: request.deadline_boottime_ns,
        frame,
    };
    let (state, exact) =
        super::execute_state_mutation(config, &state_request, true)?;
    let exact = exact.ok_or_else(|| {
        V2RuntimeError::new(
            "immutable_raw_inspection_object_missing",
            "state authority did not return the committed immutable object",
        )
    })?;
    if exact.descriptor().object_id != request.raw_object_id
        || exact.descriptor().sha256 != request.raw_object_sha256
        || exact.descriptor().byte_length
            != request.raw_object_byte_length
    {
        return Err(V2RuntimeError::new(
            "immutable_raw_inspection_object_mismatch",
            "state authority returned a different immutable object",
        ));
    }
    let inspection_receipt_sha256 =
        canonical_sha256(&serde_json::json!({
            "operationId": request.operation_id,
            "attemptId": request.attempt_id,
            "attemptRevision": state.receipt.authoritative_revision,
            "fencingToken": request.fencing_token,
            "rawObjectId": request.raw_object_id,
            "rawObjectSha256": request.raw_object_sha256,
            "rawObjectByteLength": request.raw_object_byte_length,
            "stateResultSha256": state.receipt.exact_result_sha256
        }))?;
    let raw_response = read_validated_exact_object(&exact)?;
    let parsed = crate::response_v2_http11::
        response_observation_v2_parse_http11(
            &raw_response,
            Some(&request.request_method),
        )
        .map_err(|reason| {
            V2RuntimeError::new(
                "immutable_raw_http11_invalid",
                reason,
            )
        })?;
    let parsed_response_sha256 =
        canonical_sha256(&parsed.parsed_response)?;
    let decoded_body_sha256 =
        format!("sha256:{:x}", Sha256::digest(&parsed.entity_body));
    let released_projection_sha256 =
        released_projection_sha256_v2(
            &request.raw_object_sha256,
            request.raw_object_byte_length,
            &request.request_method,
            parsed.status,
            &parsed.framing.canonical_framing_sha256,
            &parsed_response_sha256,
            &decoded_body_sha256,
        )?;
    let observation = super::query_attempt_state(
        config,
        &AttemptStateQueryRequestV1 {
            api_version:
                ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),
            generation_id: request.generation_id.clone(),
            generation: request.generation,
            request_id: request.request_id.clone(),
            operation_id: format!(
                "{}:proof-seed",
                request.operation_id
            ),
            attempt_id: request.attempt_id.clone(),
            expected_stable_resume_id:
                request.stable_resume_id.clone(),
            raw_response_object_id:
                Some(request.raw_object_id.clone()),
            include_proof_material: true,
            deadline_boottime_ns: request.deadline_boottime_ns,
        },
    )?;
    if observation.attempt_revision
            != state.receipt.authoritative_revision
        || observation.fencing_token != request.fencing_token
    {
        return Err(V2RuntimeError::new(
            "immutable_raw_inspection_state_changed",
            "attempt state changed between inspection CAS and proof-material observation",
        ));
    }
    let proof_material =
        observation.proof_material.clone().ok_or_else(|| {
            V2RuntimeError::new(
                "immutable_raw_inspection_proof_material_missing",
                "state authority omitted persisted proof material",
            )
        })?;
    let transfer_coding = match parsed.framing.transfer_coding {
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::Identity => {
                super::super::super::state_authority::rpc::
                    TransferCoding::Identity
            }
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::Chunked => {
                super::super::super::state_authority::rpc::
                    TransferCoding::Chunked
            }
        crate::response_observation_v2_api::
            V2Http11TransferCodingV1::NoBody => {
                return Err(V2RuntimeError::new(
                    "immutable_raw_inspection_no_body_schema_missing",
                    "state-authority framing schema cannot losslessly represent NO_BODY",
                ))
            }
    };
    let http11_framing =
        super::super::super::state_authority::rpc::
            Http11FramingResult {
                http_version:
                    parsed.framing.http_version.clone(),
                informational_statuses:
                    parsed.framing.informational_statuses.clone(),
                final_status: parsed.framing.final_status,
                header_section_length:
                    parsed.framing.header_section_length,
                transfer_coding,
                declared_content_length:
                    parsed.framing.declared_content_length,
                decoded_entity_length:
                    parsed.framing.decoded_entity_length,
                trailer_section_length:
                    parsed.framing.trailer_section_length,
                trailer_names:
                    parsed.framing.trailer_names.clone(),
                physical_message_length:
                    parsed.framing.physical_message_length,
                surplus_length:
                    parsed.framing.surplus_length,
                canonical_framing_sha256: AuthorityDigest(
                    parsed
                        .framing
                        .canonical_framing_sha256
                        .clone(),
                ),
            };
    let mut authority_proof_seed =
        CanonicalAuthorityEnvelopeProofSeedV2 {
            api_version:
                CANONICAL_AUTHORITY_PROOF_SEED_API_VERSION.to_owned(),
            generation_id: request.generation_id.clone(),
            generation: request.generation,
            attempt_id: request.attempt_id.clone(),
            attempt_revision: observation.attempt_revision,
            fencing_token: observation.fencing_token,
            stable_resume_id: observation.stable_resume_id.clone(),
            staged_request_object:
                proof_material.staged_request_object,
            raw_response_object:
                proof_material.raw_response_object,
            http11_framing,
            credential_use_id:
                proof_material.credential_use_id,
            target_effect_id: proof_material.target_effect_id,
            policy_decision_id:
                proof_material.policy_decision_id,
            inspection_receipt_sha256:
                inspection_receipt_sha256.clone(),
            authority_artifacts:
                proof_material.authority_artifacts,
            authority_artifacts_root_sha256:
                proof_material.authority_artifacts_root_sha256,
            seed_sha256: String::new(),
        };
    authority_proof_seed.seed_sha256 =
        authority_proof_seed.recompute_seed_sha256()?;
    authority_proof_seed.validate_integrity()?;
    let descriptor = exact.descriptor().clone();
    encode_result(
        SignedImmutableRawInspectionV1 {
            api_version:
                IMMUTABLE_RAW_INSPECTION_API_VERSION.to_owned(),
            generation_id: request.generation_id,
            generation: request.generation,
            operation: ServiceOperationV1::InspectImmutableRaw,
            request_id: request.request_id,
            request_sha256: request.request_sha256,
            attempt_id: request.attempt_id,
            stable_resume_id: request.stable_resume_id,
            authority_scope: ProviderAuthorityScopeV2::default(),
            raw_object_id: request.raw_object_id,
            raw_object_sha256: request.raw_object_sha256,
            raw_object_byte_length: request.raw_object_byte_length,
            exact_object: descriptor,
            request_method: request.request_method,
            framing_validation_sha256:
                parsed.framing.canonical_framing_sha256,
            parsed_response_sha256,
            released_projection_sha256,
            final_status: parsed.status,
            decoded_body_sha256,
            decoded_body_byte_length:
                parsed.parsed_response.decoded_entity_length,
            immutable: true,
            consumed: false,
            inspection_sequence:
                state.receipt.authoritative_revision,
            inspection_receipt_sha256,
            state_observation: observation,
            state_authority_receipt: Some(state.receipt),
            authority_proof_seed,
            signer_logical_role: String::new(),
            signer_key_id: String::new(),
            signature: String::new(),
        },
        vec![exact.into_file().into()],
    )
}

fn execute_release_authorization(
    config: &RootOwnedResponseObservationV2Config,
    _scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<EngineResult, V2RuntimeError> {
    if let Ok(preauthorization) = serde_json::from_value::<
        ReleaseConsumptionPreauthorizationArtifactRequestV1,
    >(request.payload.clone())
    {
        use super::super::super::state_authority::lifecycle::{
            AttemptState, OperationKind,
        };
        use super::super::super::state_authority::rpc::{
            NestedAuthorityPayload,
            ReleaseConsumptionPreauthorizationArtifact,
        };
        let binding_sha256 = canonical_sha256(
            &super::super::super::state_authority::rpc::
                ReleasePreparationMutationBinding {
                release_authorization_id: Identifier(
                    preauthorization
                        .mutation_binding
                        .release_authorization_id
                        .clone(),
                ),
                release_request_sha256: AuthorityDigest(
                    preauthorization
                        .mutation_binding
                        .exact_release_request_sha256
                        .clone(),
                ),
                inspection_result_sha256: AuthorityDigest(
                    preauthorization
                        .mutation_binding
                        .inspection_receipt_sha256
                        .clone(),
                ),
                release_object: preauthorization
                    .release_object
                    .clone(),
                client_binding_sha256: AuthorityDigest(
                    preauthorization
                        .mutation_binding
                        .client_binding_sha256
                        .clone(),
                ),
                exact_replay_key_sha256: AuthorityDigest(
                    preauthorization
                        .mutation_binding
                        .exact_replay_key_sha256
                        .clone(),
                ),
            },
        )?;
        if preauthorization
                .mutation_binding
                .expected_state
                .as_str()
                != AttemptState::Observed.as_str()
            || preauthorization
                .mutation_binding
                .successor_state
                .as_str()
                != AttemptState::ReleasePrepared.as_str()
            || preauthorization.attempt_revision
                != preauthorization
                    .mutation_binding
                    .expected_revision
            || preauthorization.fencing_token == 0
            || preauthorization.release_object.content_sha256.0
                != preauthorization
                    .mutation_binding
                    .release_object_sha256
        {
            return Err(V2RuntimeError::new(
                "release_preauthorization_request_invalid",
                "release preauthorization must bind exactly OBSERVED to RELEASE_PREPARED",
            ));
        }
        let key =
            require_signing_key(signing_keys, "public-release")?;
        let artifact = sign_nested_artifact(
            config,
            CustodyServiceRole::ReleaseAttestorPublisher,
            key,
            OperationKind::ReleaseConsumeAndRetrieveExact,
            &preauthorization.operation_id,
            &preauthorization.attempt_id,
            preauthorization.attempt_revision,
            preauthorization.fencing_token,
            u64::MAX / 2,
            NestedAuthorityPayload::
                ReleaseConsumptionPreauthorization(
                    ReleaseConsumptionPreauthorizationArtifact {
                        release_authorization_id: Identifier(
                            preauthorization
                                .mutation_binding
                                .release_authorization_id,
                        ),
                        finalization_id: Identifier(
                            preauthorization.finalization_id,
                        ),
                        mutation_binding_sha256:
                            AuthorityDigest(binding_sha256),
                        release_request_sha256: AuthorityDigest(
                            preauthorization
                                .mutation_binding
                                .exact_release_request_sha256,
                        ),
                        inspection_result_sha256: AuthorityDigest(
                            preauthorization
                                .mutation_binding
                                .inspection_receipt_sha256,
                        ),
                        release_object_sha256: AuthorityDigest(
                            preauthorization
                                .mutation_binding
                                .release_object_sha256,
                        ),
                        client_binding_sha256: AuthorityDigest(
                            preauthorization
                                .mutation_binding
                                .client_binding_sha256,
                        ),
                        exact_replay_key_sha256: AuthorityDigest(
                            preauthorization
                                .mutation_binding
                                .exact_replay_key_sha256,
                        ),
                        one_use_nonce_sha256: AuthorityDigest(
                            preauthorization.one_use_nonce_sha256,
                        ),
                        expected_revision: preauthorization
                            .mutation_binding
                            .expected_revision,
                        expected_state: AttemptState::Observed,
                        successor_revision: preauthorization
                            .mutation_binding
                            .successor_revision,
                        successor_state:
                            AttemptState::ReleasePrepared,
                    },
                ),
            None,
            preauthorization.deadline_boottime_ns,
        )?;
        return encode_result(artifact, Vec::new());
    }
    let request: ReleaseAuthorizationRequestV2 =
        decode_payload(request)?;
    verify_immutable_raw_inspection(
        config.custody_topology(),
        &request.inspection,
    )?;
    request.inspection.authority_proof_seed.validate_integrity()?;
    let authorization_id =
        canonical_sha256(&serde_json::json!({
            "operationId": request.operation_id,
            "inspectionReceiptSha256": request.inspection.inspection_receipt_sha256,
            "authorityProofSeedSha256":
                request.inspection.authority_proof_seed.seed_sha256,
            "authorityProofSeedArtifactsRootSha256":
                request.inspection.authority_proof_seed.authority_artifacts_root_sha256,
            "policyDecisionSha256": request.policy_decision_sha256,
            "exactReplayKeySha256": request.exact_replay_key_sha256,
            "expiresAtEpochMs": request.expires_at_epoch_ms
        }))?;
    let authorization_result_sha256 =
        canonical_sha256(&serde_json::json!({
            "authorizationId": authorization_id,
            "attemptRevision": request.attempt_revision,
            "fencingToken": request.fencing_token,
            "authorized": true
        }))?;
    let finalization_id = canonical_sha256(&serde_json::json!({
        "authorizationId": authorization_id,
        "inspectionReceiptSha256":
            request.inspection.inspection_receipt_sha256,
    }))?;
    let exact_release_request_sha256 =
        canonical_sha256(&serde_json::json!({
            "authorizationId": authorization_id,
            "rawObjectSha256":
                request.inspection.raw_object_sha256,
            "exactReplayKeySha256":
                request.exact_replay_key_sha256,
        }))?;
    let one_use_nonce_sha256 =
        canonical_sha256(&serde_json::json!({
            "authorizationId": authorization_id,
            "fencingToken": request.fencing_token,
        }))?;
    let release_key =
        require_signing_key(signing_keys, "public-release")?;
    let canonical_seed =
        canonical_inspection_seed(
            &request.inspection.authority_proof_seed,
        )?;
    let inspection_artifact =
        request.inspection.authority_proof_seed
            .authority_artifacts
            .get(4)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "release_authorization_inspection_missing",
                    "inspection seed lacks slot five",
                )
            })?;
    let release_authorization_artifact = sign_nested_artifact(
        config,
        CustodyServiceRole::ReleaseAttestorPublisher,
        release_key,
        super::super::super::state_authority::lifecycle::
            OperationKind::ReleaseConsumeAndRetrieveExact,
        &request.operation_id,
        &request.attempt_id,
        request.attempt_revision,
        request.fencing_token,
        request.expires_at_epoch_ms,
        super::super::super::state_authority::rpc::
            NestedAuthorityPayload::ReleaseAuthorization(
                super::super::super::state_authority::rpc::
                    ReleaseAuthorizationArtifact {
                    release_authorization_id:
                        Identifier(authorization_id.clone()),
                    finalization_id:
                        Identifier(finalization_id.clone()),
                    release_request_sha256: AuthorityDigest(
                        exact_release_request_sha256.clone(),
                    ),
                    inspection_result_sha256: AuthorityDigest(
                        request
                            .inspection
                            .inspection_receipt_sha256
                            .clone(),
                    ),
                    inspection_artifact_sha256: AuthorityDigest(
                        canonical_sha256(inspection_artifact)?,
                    ),
                    inspection_seed_body_sha256:
                        canonical_seed.body_sha256,
                    inspection_seed_root_sha256:
                        AuthorityDigest(
                            request
                                .inspection
                                .authority_proof_seed
                                .authority_artifacts_root_sha256
                                .clone(),
                        ),
                    release_object_sha256: AuthorityDigest(
                        request.inspection.raw_object_sha256.clone(),
                    ),
                    one_use_nonce_sha256: AuthorityDigest(
                        one_use_nonce_sha256.clone(),
                    ),
                },
            ),
        None,
        request.deadline_boottime_ns,
    )?;
    let release_authorization_artifact_sha256 =
        canonical_sha256(&release_authorization_artifact)?;
    encode_result(
        SignedReleaseAuthorizationV2 {
            api_version: RELEASE_AUTHORIZATION_API_VERSION.to_owned(),
            generation_id: request.generation_id,
            generation: request.generation,
            operation: ServiceOperationV1::AuthorizeRelease,
            request_id: request.request_id,
            request_sha256: request.request_sha256,
            attempt_id: request.attempt_id,
            stable_resume_id: request.stable_resume_id,
            authority_scope: ProviderAuthorityScopeV2::default(),
            fencing_token: request.fencing_token,
            authorization_id,
            finalization_id,
            exact_release_request_sha256,
            one_use_nonce_sha256,
            inspection_receipt_sha256:
                request.inspection.inspection_receipt_sha256,
            authority_proof_seed_sha256:
                request.inspection.authority_proof_seed.seed_sha256,
            authority_proof_seed_artifacts_root_sha256:
                request
                    .inspection
                    .authority_proof_seed
                    .authority_artifacts_root_sha256,
            raw_object_sha256:
                request.inspection.raw_object_sha256,
            policy_decision_sha256:
                request.policy_decision_sha256,
            exact_replay_key_sha256:
                request.exact_replay_key_sha256,
            expires_at_epoch_ms: request.expires_at_epoch_ms,
            authorization_result_sha256,
            release_authorization_artifact,
            release_authorization_artifact_sha256,
            signer_logical_role: String::new(),
            signer_key_id: String::new(),
            signature: String::new(),
        },
        Vec::new(),
    )
}

fn execute_consumption(
    _config: &RootOwnedResponseObservationV2Config,
    _scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    _signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<EngineResult, V2RuntimeError> {
    let request: ConsumeReleaseAndRetrieveExactRequestV1 =
        decode_payload(request)?;
    Err(V2RuntimeError::new(
        match request.phase() {
            super::super::protocol::ReleaseConsumptionPhaseV1::Prepare => {
                "release_preparation_requires_public_choreography"
            }
            super::super::protocol::ReleaseConsumptionPhaseV1::Retrieve => {
                "release_retrieval_requires_public_choreography"
            }
        },
        "phase-specific release operations are accepted only through the response-data choreography",
    ))
}

fn execute_publication(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<EngineResult, V2RuntimeError> {
    let request: PublishRequestV1 = decode_payload(request)?;
    validate_publish_state_intent(&request)?;
    verify_final_envelope_verification(
        config.custody_topology(),
        &request.final_envelope_verification,
    )?;
    let frame = signed_state_authority_frame(
        config,
        scoped,
        &request.request_id,
        &request.operation_id,
        &request.attempt_id,
        request.attempt_revision,
        request.fencing_token,
        request.deadline_boottime_ns,
        &request.state_authority_intent,
        signing_keys,
    )?;
    let state_request = state_execution_request(
        &request.request_id,
        &request.operation_id,
        &request.attempt_id,
        &request.stable_resume_id,
        request.attempt_revision,
        request.fencing_token,
        request.deadline_boottime_ns,
        frame,
    );
    let (state, exact) =
        super::execute_state_mutation(config, &state_request, false)?;
    if exact.is_some() {
        return Err(V2RuntimeError::new(
            "publication_exact_object_unexpected",
            "publication state transition returned raw bytes",
        ));
    }
    let receipt_sha256 =
        canonical_sha256(&serde_json::json!({
            "publicationId": request.publication_id,
            "outboxId": request.outbox_id,
            "finalizationId": request.finalization_id,
            "payloadObjectSha256": request.payload_object_sha256,
            "stateResultSha256": state.receipt.exact_result_sha256
        }))?;
    encode_result(
        SignedPublicationReceiptV1 {
            api_version: PUBLICATION_API_VERSION.to_owned(),
            generation_id: request.generation_id,
            generation: request.generation,
            operation: ServiceOperationV1::Publish,
            request_id: request.request_id,
            request_sha256: request.request_sha256,
            attempt_id: request.attempt_id,
            stable_resume_id: request.stable_resume_id,
            authority_scope: ProviderAuthorityScopeV2::default(),
            publication_id: request.publication_id,
            outbox_id: request.outbox_id,
            finalization_id: request.finalization_id,
            payload_object_sha256:
                request.payload_object_sha256,
            publication_sequence:
                state.receipt.authoritative_revision,
            durable_publication_receipt_sha256: receipt_sha256,
            state_authority_receipt: state.receipt,
            signer_logical_role: String::new(),
            signer_key_id: String::new(),
            signature: String::new(),
        },
        Vec::new(),
    )
}

fn execute_settlement(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
    operation: ServiceOperationV1,
) -> Result<EngineResult, V2RuntimeError> {
    let request: SettlementRequestV1 = decode_payload(request)?;
    validate_settlement_state_intent(&request)?;
    use super::super::super::state_authority::rpc::MutationPayload;
    let (
        reconciliation_id,
        reconciliation_artifact,
        reconciliation_artifact_sha256,
        recovery_artifact,
        recovery_artifact_sha256,
    ) = match (operation, &request.state_authority_intent.payload) {
        (ServiceOperationV1::Reconcile, MutationPayload::Reconcile(mutation)) => {
            let artifact = mutation.reconciliation_evidence.clone();
            let artifact_sha256 = canonical_sha256(&artifact)?;
            (
                Some(mutation.reconciliation_job_id.0.clone()),
                Some(artifact),
                Some(artifact_sha256),
                None,
                None,
            )
        }
        (
            ServiceOperationV1::Cleanup,
            MutationPayload::TerminalizeExpiredAttempt(mutation),
        ) => {
            let artifact = mutation.recovery_evidence.clone();
            let artifact_sha256 = canonical_sha256(&artifact)?;
            (
                None,
                None,
                None,
                Some(artifact),
                Some(artifact_sha256),
            )
        }
        _ => {
            return Err(V2RuntimeError::new(
                "settlement_state_mutation_mismatch",
                "reconciliation requires signed reconciliation evidence and cleanup requires signed deadline-recovery evidence",
            ));
        }
    };
    let frame = signed_state_authority_frame(
        config,
        scoped,
        &request.request_id,
        &request.operation_id,
        &request.attempt_id,
        request.attempt_revision,
        request.fencing_token,
        request.deadline_boottime_ns,
        &request.state_authority_intent,
        signing_keys,
    )?;
    let state = if scoped.role == CustodyServiceRole::StateAuthority {
        let signing_key = signing_keys
            .get("linearizable-store")
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "state_authority_engine_key_missing",
                    "state-authority did not load linearizable-store",
                )
            })?;
        super::state_authority::execute_postgres(
            config,
            &frame,
            &request.request_id,
            &request.operation_id,
            &request.attempt_id,
            &request.stable_resume_id,
            request.attempt_revision,
            request.fencing_token,
            signing_key,
        )?
        .receipt
    } else {
        let state_request = state_execution_request(
            &request.request_id,
            &request.operation_id,
            &request.attempt_id,
            &request.stable_resume_id,
            request.attempt_revision,
            request.fencing_token,
            request.deadline_boottime_ns,
            frame,
        );
        let (state, exact) =
            super::execute_state_mutation(config, &state_request, false)?;
        if exact.is_some() {
            return Err(V2RuntimeError::new(
                "settlement_exact_object_unexpected",
                "settlement returned raw bytes",
            ));
        }
        state.receipt
    };
    let receipt_sha256 =
        canonical_sha256(&serde_json::json!({
            "operation": operation.as_str(),
            "operationId": request.operation_id,
            "terminalStateSha256": request.expected_terminal_state_sha256,
            "settlementInputSha256": request.settlement_input_sha256,
            "stateResultSha256": state.exact_result_sha256
        }))?;
    encode_result(
        SignedDurableTerminalReceiptV1 {
            api_version: SETTLEMENT_API_VERSION.to_owned(),
            generation_id: request.generation_id,
            generation: request.generation,
            operation,
            request_id: request.request_id,
            request_sha256: request.request_sha256,
            attempt_id: request.attempt_id,
            stable_resume_id: request.stable_resume_id,
            authority_scope: ProviderAuthorityScopeV2::default(),
            terminal_state:
                state.authoritative_state.clone(),
            terminal_state_sha256:
                request.expected_terminal_state_sha256,
            durable: true,
            reconciled: true,
            authority_sequence: state.authoritative_revision,
            settlement_receipt_sha256: receipt_sha256,
            reconciliation_id,
            reconciliation_artifact,
            reconciliation_artifact_sha256,
            recovery_artifact,
            recovery_artifact_sha256,
            state_authority_receipt: state,
            signer_logical_role: String::new(),
            signer_key_id: String::new(),
            signature: String::new(),
        },
        Vec::new(),
    )
}

fn validate_state_execution(
    config: &RootOwnedResponseObservationV2Config,
    request: &StateMutationExecutionRequestV1,
) -> Result<(), V2RuntimeError> {
    request.frame.request.validate().map_err(|error| {
        V2RuntimeError::new(
            "state_authority_request_invalid",
            error.to_string(),
        )
    })?;
    let frame = &request.frame.request;
    let sequence = request.api_version
        == super::super::protocol::SEQUENCE_STATE_AUTHORITY_API_VERSION;
    let reserve = match &frame.payload {
        super::super::super::state_authority::rpc::MutationPayload::Reserve(value) => {
            sequence && request.fencing_token == 0 && request.attempt_revision == 0
                && frame.fence.fence_token.is_none()
                && value.stable_resume_id.0 == request.stable_resume_id
        }
        _ => false,
    };
    let exact_fence = frame.fence.fence_token.as_ref().is_some_and(|value| {
        request.fencing_token > 0 && value.0 == request.fencing_token.to_string()
    });
    if (!sequence && request.api_version != STATE_AUTHORITY_API_VERSION)
        || frame.generation_id.0
            != config.custody_topology().generation_id
        || frame.request_id.0 != request.request_id
        || frame.operation_id.0 != request.operation_id
        || frame.attempt_id.0 != request.attempt_id
        || frame.expected_revision != request.attempt_revision
        || (!reserve && !exact_fence)
        || frame.deadline.clock != "CLOCK_BOOTTIME"
        || frame.deadline.deadline_boot_millis
            != request.deadline_boottime_ns / 1_000_000
    {
        return Err(V2RuntimeError::new(
            "state_authority_request_binding_mismatch",
            "state frame does not bind the exact custody request, operation, attempt, revision, fence, and CLOCK_BOOTTIME deadline",
        ));
    }
    Ok(())
}

fn validate_inspection_state_intent(
    request: &InspectImmutableRawRequestV1,
) -> Result<(), V2RuntimeError> {
    match &request.state_authority_intent.payload {
        super::super::super::state_authority::rpc::
            MutationPayload::InspectImmutableRaw(mutation)
            if mutation.object.object_id.0 == request.raw_object_id
                && mutation.object.content_sha256.0
                    == request.raw_object_sha256
                && mutation.object.content_length
                    == request.raw_object_byte_length => Ok(()),
        _ => Err(V2RuntimeError::new(
            "immutable_raw_state_mutation_mismatch",
            "inspection state mutation does not bind the exact raw object",
        )),
    }
}

fn validate_consumption_state_intent(
    _request: &ConsumeReleaseAndRetrieveExactRequestV1,
) -> Result<(), V2RuntimeError> {
    Ok(())
}

fn validate_publish_state_intent(
    request: &PublishRequestV1,
) -> Result<(), V2RuntimeError> {
    match &request.state_authority_intent.payload {
        super::super::super::state_authority::rpc::
            MutationPayload::Publish(mutation)
            if mutation.publication_id.0 == request.publication_id
                && mutation.outbox_id.0 == request.outbox_id
                && mutation.finalization_id.0
                    == request.finalization_id
                && mutation.payload_object.object_id.0
                    == request.payload_object_id
                && mutation.payload_object.content_sha256.0
                    == request.payload_object_sha256
                && mutation.payload_object.content_length
                    == request.payload_object_byte_length => Ok(()),
        _ => Err(V2RuntimeError::new(
            "publication_state_mutation_mismatch",
            "publication mutation does not bind the exact outbox, finalization, and payload object",
        )),
    }
}

fn validate_settlement_state_intent(
    request: &SettlementRequestV1,
) -> Result<(), V2RuntimeError> {
    if !matches!(
        request.state_authority_intent.payload,
        super::super::super::state_authority::rpc::
            MutationPayload::Reconcile(_)
            | super::super::super::state_authority::rpc::
                MutationPayload::TerminalizeExpiredAttempt(_)
    ) {
        return Err(V2RuntimeError::new(
            "settlement_state_mutation_mismatch",
            "settlement requires independently signed reconciliation or deadline-recovery evidence",
        ));
    }
    Ok(())
}

pub(in super::super) fn signed_state_authority_frame(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
    request_id: &str,
    operation_id: &str,
    attempt_id: &str,
    expected_revision: u64,
    fencing_token: u64,
    deadline_boottime_ns: u64,
    intent: &UnsignedStateAuthorityIntentV1,
    signing_keys: &BTreeMap<String, RoleSigningKey>,
) -> Result<RpcRequestFrame, V2RuntimeError> {
    let signer_role = readiness_signer_role(scoped.role).ok_or_else(|| {
        V2RuntimeError::new(
            "state_authority_caller_signer_unassigned",
            "zero-key custody router cannot originate a state-authority frame",
        )
    })?;
    let signer = signing_keys.get(signer_role).ok_or_else(|| {
        V2RuntimeError::new(
            "state_authority_caller_key_missing",
            "service did not load its state-authority caller key",
        )
    })?;
    let deadline = AuthorityBootDeadline {
        clock: "CLOCK_BOOTTIME".to_owned(),
        boot_id: Identifier(
            super::super::recovery::kernel_boot_id()?,
        ),
        deadline_boot_millis: deadline_boottime_ns / 1_000_000,
    };
    let request = RpcRequest {
        api_version: AUTHORITY_API_VERSION.to_owned(),
        kind: STATE_AUTHORITY_RPC_KIND.to_owned(),
        schema_version: STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
        generation_id: Identifier(
            config.custody_topology().generation_id.clone(),
        ),
        request_id: Identifier(request_id.to_owned()),
        operation_id: Identifier(operation_id.to_owned()),
        caller_role_id: Identifier(
            scoped.process.service_id.clone(),
        ),
        operation: intent.payload.operation(),
        attempt_id: Identifier(attempt_id.to_owned()),
        expected_revision,
        expected_state: intent.expected_state,
        fence: FenceExpectation {
            mode: FenceExpectationMode::Exact,
            fence_token: Some(Identifier(fencing_token.to_string())),
        },
        deadline,
        payload: intent.payload.clone(),
    };
    request.validate().map_err(|error| {
        V2RuntimeError::new(
            "state_authority_intent_invalid",
            error.to_string(),
        )
    })?;
    let canonical = canonical_jcs_bytes(&request).map_err(|error| {
        V2RuntimeError::new(
            "state_authority_intent_canonicalization_failed",
            error.to_string(),
        )
    })?;
    let signed_payload_sha256 = sha256_digest(&canonical);
    let signature = signer.sign_digest_bytes(&signature_message(
        STATE_AUTHORITY_SIGNATURE_DOMAIN,
        &canonical,
    ));
    if signature.len() != 64 {
        return Err(V2RuntimeError::new(
            "state_authority_intent_signature_invalid",
            "Ed25519 state-authority frame signature is not 64 bytes",
        ));
    }
    Ok(RpcRequestFrame {
        request,
        authentication: FrameAuthentication {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: Identifier(signer.key_id().to_owned()),
            signed_payload_sha256,
            signature_base64url: encode_base64url(&signature),
        },
    })
}

pub(in super::super) fn state_execution_request(
    request_id: &str,
    operation_id: &str,
    attempt_id: &str,
    stable_resume_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
    deadline_boottime_ns: u64,
    frame:
        super::super::super::state_authority::rpc::RpcRequestFrame,
) -> StateMutationExecutionRequestV1 {
    StateMutationExecutionRequestV1 {
        api_version: STATE_AUTHORITY_API_VERSION.to_owned(),
        request_id: request_id.to_owned(),
        operation_id: operation_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        stable_resume_id: stable_resume_id.to_owned(),
        attempt_revision,
        fencing_token,
        deadline_boottime_ns,
        frame,
    }
}

fn read_validated_exact_object(
    object: &super::super::ValidatedExactObject,
) -> Result<Vec<u8>, V2RuntimeError> {
    let length = usize::try_from(object.descriptor().byte_length)
        .map_err(|_| {
            V2RuntimeError::new(
                "exact_object_length_invalid",
                "exact object length is not addressable",
            )
        })?;
    let mut bytes = vec![0u8; length];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = object.read_at(
            &mut bytes[offset..],
            u64::try_from(offset).map_err(|_| {
                V2RuntimeError::new(
                    "exact_object_offset_invalid",
                    "exact object offset is not representable",
                )
            })?,
        )?;
        if read == 0 {
            return Err(V2RuntimeError::new(
                "exact_object_truncated",
                "exact object ended before its committed byte length",
            ));
        }
        offset = offset.checked_add(read).ok_or_else(|| {
            V2RuntimeError::new(
                "exact_object_offset_overflow",
                "exact object read offset overflowed",
            )
        })?;
    }
    Ok(bytes)
}

fn decode_payload<T: serde::de::DeserializeOwned>(
    request: &ServiceRpcEnvelopeV1,
) -> Result<T, V2RuntimeError> {
    serde_json::from_value(request.payload.clone()).map_err(|_| {
        V2RuntimeError::new(
            "custody_engine_payload_invalid",
            "service payload is not the closed operation DTO",
        )
    })
}

fn encode_result<T: Serialize>(
    result: T,
    exact_object_fds: Vec<OwnedFd>,
) -> Result<EngineResult, V2RuntimeError> {
    Ok(EngineResult {
        result: serde_json::to_value(result).map_err(|_| {
            V2RuntimeError::new(
                "custody_engine_result_invalid",
                "in-process engine result cannot be represented",
            )
        })?,
        exact_object_fds,
    })
}

fn canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(value).map_err(|_| {
        V2RuntimeError::new(
            "custody_engine_canonicalization_failed",
            "engine value cannot be canonicalized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn sealed_memfd(bytes: &[u8]) -> Result<OwnedFd, V2RuntimeError> {
    let name = CString::new("serverware-response-v2-exact")
        .map_err(|_| {
            V2RuntimeError::new(
                "exact_object_memfd_failed",
                "construct memfd name",
            )
        })?;
    let fd = unsafe {
        libc::memfd_create(
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(V2RuntimeError::new(
            "exact_object_memfd_failed",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).map_err(|error| {
        V2RuntimeError::new(
            "exact_object_memfd_write_failed",
            error.to_string(),
        )
    })?;
    let seals = libc::F_SEAL_SEAL
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_GROW
        | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(V2RuntimeError::new(
            "exact_object_memfd_seal_failed",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let raw = file.into_raw_fd();
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
