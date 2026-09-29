use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use super::config::{
    CustodyServiceRole, ServiceRoleKeyDescriptorV1,
    SignedCustodyTopologyV1,
};
use super::generation::{
    required_service_operations, role_identity_root_sha256,
    validate_post_reconciliation_handshake,
};
use super::protocol::{
    ProviderAuthorityScopeV2,
    ServiceOperationV1, SignedCustodyAttestationV1,
    SignedCustodyErrorV1, SignedCustodyRecoveryV1,
    SignedFinalEnvelopeVerificationV1,
    SignedImmutableRawInspectionV1, SignedReleaseAuthorizationV2,
    SignedReleaseConsumptionPreauthorizationV1,
    SignedReleaseConsumptionV2, SignedReleaseMetadataV1,
    SignedReleasePreparationReceiptV1,
    SignedServiceHandshakeV1, SignedTransitionAuthorizationV1,
    SignedStateMutationReceiptV1,
    SignedAttemptStateObservationV1,
    SignedPublicationReceiptV1, SignedDurableTerminalReceiptV1,
    CUSTODY_ATTESTATION_API_VERSION, CUSTODY_ERROR_API_VERSION,
    CUSTODY_RECOVERY_API_VERSION,
    FINAL_ENVELOPE_VERIFICATION_API_VERSION,
    IMMUTABLE_RAW_INSPECTION_API_VERSION,
    RELEASE_AUTHORIZATION_API_VERSION,
    RELEASE_CONSUMPTION_API_VERSION,
    RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION,
    RELEASE_METADATA_API_VERSION,
    RELEASE_PREPARATION_RECEIPT_API_VERSION,
    TRANSITION_AUTHORIZATION_API_VERSION,
    AUTHORITY_SCOPE_API_VERSION, PUBLICATION_API_VERSION,
    SETTLEMENT_API_VERSION, STATE_MUTATION_RECEIPT_API_VERSION,
    ATTEMPT_STATE_OBSERVATION_API_VERSION,
    SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION,
};
use super::V2RuntimeError;

const SERVICE_HANDSHAKE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/service-handshake/v1\0";
pub(crate) const TRANSITION_AUTHORIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/transition-authorization/v1\0";
pub(crate) const FINAL_ENVELOPE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/final-envelope-verification/v1\0";
pub(crate) const SERVICE_RESULT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/service-result/v1\0";
pub(crate) const STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/state-authority-result/v1\0";
pub(crate) const REPLAY_SOURCE_OBSERVATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/replay-source-observation/v1\0";
pub(crate) const SETTLEMENT_EVIDENCE_CONTEXT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/settlement-evidence-context/v1\0";
pub(crate) const STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/state-mutation-receipt/v1\0";
pub(crate) const RELEASE_METADATA_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/release-metadata/v1\0";
pub(crate) const IMMUTABLE_RAW_INSPECTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/immutable-raw-inspection/v1\0";
pub(crate) const RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/release-authorization/v2\0";
pub(crate) const RELEASE_CONSUMPTION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/release-consumption/v2\0";
pub(crate) const RELEASE_CONSUMPTION_PREAUTHORIZATION_SIGNATURE_DOMAIN:
    &[u8] =
    b"serverware.response-v2/release-consumption-preauthorization/v1\0";
pub(crate) const RELEASE_PREPARATION_RECEIPT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/release-preparation-receipt/v1\0";
pub(crate) const CUSTODY_ATTESTATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/custody-attestation/v1\0";
pub(crate) const CUSTODY_RECOVERY_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/custody-recovery/v1\0";
pub(crate) const CUSTODY_ERROR_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/custody-error/v1\0";
pub(crate) const PUBLICATION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/publication/v1\0";
pub(crate) const SETTLEMENT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/settlement/v1\0";

pub(crate) struct RoleSigningKey {
    logical_role: String,
    key_id: String,
    key: SigningKey,
}

impl RoleSigningKey {
    pub(crate) fn from_retained_originals(
        descriptor: &ServiceRoleKeyDescriptorV1,
        seed: &[u8],
        public: &[u8],
    ) -> Result<Self, V2RuntimeError> {
        if seed.len() != 32 || public.len() != 32 {
            return Err(V2RuntimeError::new("custody_service_secret_invalid",
                "retained role seed and public key must each be exactly 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(seed);
        let key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        if key.verifying_key().as_bytes().as_slice() != public
            || format!("sha256:{:x}", Sha256::digest(public)) != descriptor.public_key_sha256
            || descriptor.key_id != descriptor.public_key_sha256
        {
            return Err(V2RuntimeError::new("custody_service_secret_mismatch",
                "retained seed/public/key ID do not match the signed role assignment"));
        }
        Ok(Self { logical_role:descriptor.logical_role.clone(), key_id:descriptor.key_id.clone(), key })
    }

    pub(crate) fn load(
        descriptor: &ServiceRoleKeyDescriptorV1,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, V2RuntimeError> {
        let metadata =
            fs::symlink_metadata(&descriptor.secret_key_path)
                .map_err(|_| {
                    V2RuntimeError::new(
                        "custody_service_secret_unavailable",
                        "open role-scoped signing seed",
                    )
                })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.file_type().is_file()
                || metadata.uid() != expected_uid
                || metadata.gid() != expected_gid
                || metadata.mode() & 0o777 != 0o400
                || metadata.nlink() != 1
            {
                return Err(V2RuntimeError::new(
                    "custody_service_secret_unsafe",
                    "role signing seed must be an owner-only single-link file owned by the exact service UID/GID",
                ));
            }
        }
        let mut seed =
            fs::read(&descriptor.secret_key_path).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_secret_unreadable",
                    "read role-scoped signing seed",
                )
            })?;
        if seed.len() != 32 {
            seed.zeroize();
            return Err(V2RuntimeError::new(
                "custody_service_secret_invalid",
                "role signing seed must be exactly 32 bytes",
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&seed);
        seed.zeroize();
        let key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        let public = key.verifying_key().to_bytes();
        if format!("sha256:{:x}", Sha256::digest(public))
            != descriptor.public_key_sha256
            || descriptor.key_id != descriptor.public_key_sha256
        {
            return Err(V2RuntimeError::new(
                "custody_service_secret_mismatch",
                "role signing seed does not match the signed topology public key digest",
            ));
        }
        Ok(Self {
            logical_role: descriptor.logical_role.clone(),
            key_id: descriptor.key_id.clone(),
            key,
        })
    }

    pub(crate) fn logical_role(&self) -> &str {
        &self.logical_role
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().as_bytes())
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
    ) -> Result<String, V2RuntimeError> {
        let canonical =
            crate::canonical_json_bytes(value).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_signature_payload_invalid",
                    "signed service value cannot be canonicalized",
                )
            })?;
        let mut message =
            Vec::with_capacity(domain.len() + canonical.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(&canonical);
        Ok(base64::engine::general_purpose::STANDARD
            .encode(self.key.sign(&message).to_bytes()))
    }

    pub(crate) fn sign_digest_bytes(
        &self,
        digest: &[u8; 32],
    ) -> Vec<u8> {
        self.key.sign(digest).to_bytes().to_vec()
    }
}

pub(crate) fn sign_service_handshake(
    key: &RoleSigningKey,
    handshake: &mut SignedServiceHandshakeV1,
) -> Result<(), V2RuntimeError> {
    handshake.signer_logical_role =
        key.logical_role().to_owned();
    handshake.signer_key_id = key.key_id().to_owned();
    handshake.signature = key.sign(
        SERVICE_HANDSHAKE_SIGNATURE_DOMAIN,
        &handshake.without_signature(),
    )?;
    Ok(())
}

pub fn verify_provider_authority_scope(
    topology: &SignedCustodyTopologyV1,
    expected_service_role: CustodyServiceRole,
    expected_operation: ServiceOperationV1,
    scope: &ProviderAuthorityScopeV2,
) -> Result<(), V2RuntimeError> {
    let process = topology
        .process(expected_service_role)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "provider_authority_scope_process_missing",
                "scope service is absent from signed topology",
            )
        })?;
    let binding = topology
        .logical_role(&scope.logical_role)
        .filter(|binding| {
            binding.service_role == expected_service_role
                && binding.key_id == scope.key_id
                && binding.public_key_sha256
                    == scope.key_material_sha256
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "provider_authority_scope_key_invalid",
                "scope key is not assigned to the claimed logical role and service",
            )
        })?;
    let expected_operations = required_service_operations(
        expected_service_role,
    )
    .into_iter()
    .collect::<Vec<_>>();
    let canonical = crate::canonical_json_bytes(
        &scope.without_binding_digest(),
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "provider_authority_scope_invalid",
            "scope cannot be canonicalized",
        )
    })?;
    let expected_binding =
        format!("sha256:{:x}", Sha256::digest(canonical));
    if scope.api_version != AUTHORITY_SCOPE_API_VERSION
        || scope.generation_id != topology.generation_id
        || scope.generation != topology.generation
        || scope.service_role != expected_service_role
        || scope.service_id != process.service_id
        || scope.logical_role != binding.logical_role
        || scope.role_identity_root_sha256
            != role_identity_root_sha256(topology)
        || scope.operation != expected_operation
        || scope.operation_id.is_empty()
        || scope.attempt_id.is_empty()
        || scope.attempt_revision == 0
        || scope.fencing_token == 0
        || scope.executable_sha256 != process.executable_sha256
        || scope.configuration_sha256
            != process.configuration_sha256
        || scope.allowed_operations != expected_operations
        || scope.operation_binding_sha256 != expected_binding
    {
        return Err(V2RuntimeError::new(
            "provider_authority_scope_invalid",
            "scope is not bound to the exact generation, process, subkey, sorted capabilities, operation, attempt, revision, fence, executable, and configuration",
        ));
    }
    Ok(())
}

pub(crate) fn verify_service_handshake(
    topology: &SignedCustodyTopologyV1,
    handshake: &SignedServiceHandshakeV1,
) -> Result<(), V2RuntimeError> {
    validate_post_reconciliation_handshake(topology, handshake)?;
    let binding = topology
        .logical_role(&handshake.signer_logical_role)
        .filter(|binding| {
            binding.service_role == handshake.service_role
                && binding.key_id == handshake.signer_key_id
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_handshake_signer_invalid",
                "service handshake signer is not assigned to that service in the signed topology",
            )
        })?;
    let process = topology
        .process(handshake.service_role)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_handshake_process_unknown",
                "service handshake process is absent from the signed topology",
            )
        })?;
    let descriptor = process
        .role_keys
        .iter()
        .find(|key| {
            key.logical_role == binding.logical_role
                && key.key_id == binding.key_id
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_handshake_key_unknown",
                "service handshake key descriptor is absent",
            )
        })?;
    verify_with_descriptor(
        descriptor,
        SERVICE_HANDSHAKE_SIGNATURE_DOMAIN,
        &handshake.without_signature(),
        &handshake.signature,
    )
}

pub fn verify_transition_authorization(
    topology: &SignedCustodyTopologyV1,
    authorization: &SignedTransitionAuthorizationV1,
) -> Result<(), V2RuntimeError> {
    if authorization.api_version
            != TRANSITION_AUTHORIZATION_API_VERSION
        || authorization.generation_id != topology.generation_id
        || authorization.generation != topology.generation
        || authorization.operation
            != ServiceOperationV1::TransitionAuthorize
        || authorization.authority_sequence == 0
        || !is_sha256(&authorization.request_sha256)
        || !is_sha256(&authorization.stable_resume_id)
        || !is_sha256(&authorization.predecessor_state_sha256)
        || !is_sha256(&authorization.transition_input_sha256)
        || authorization
            .policy_decision_sha256
            .as_ref()
            .is_some_and(|digest| !is_sha256(digest))
        || !is_sha256(&authorization.canonical_result_sha256)
        || authorization.signer_logical_role
            != "linearizable-store"
    {
        return Err(V2RuntimeError::new(
            "transition_authorization_signer_invalid",
            "transition authorization is not issued by the generation-bound state authority",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &authorization.signer_logical_role,
        &authorization.signer_key_id,
        TRANSITION_AUTHORIZATION_SIGNATURE_DOMAIN,
        &authorization.without_signature(),
        &authorization.signature,
    )
}

pub(crate) fn verify_attempt_state_observation(
    topology: &SignedCustodyTopologyV1,
    observation: &SignedAttemptStateObservationV1,
) -> Result<(), V2RuntimeError> {
    let canonical = crate::canonical_json_bytes(
        &observation.without_observation_digest_and_signature(),
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "attempt_state_observation_invalid",
            "state observation cannot be canonicalized",
        )
    })?;
    let observation_sha256 =
        format!("sha256:{:x}", Sha256::digest(canonical));
    if observation.api_version
            != ATTEMPT_STATE_OBSERVATION_API_VERSION
        || observation.generation_id != topology.generation_id
        || observation.generation != topology.generation
        || observation.operation != ServiceOperationV1::StateCas
        || observation.signer_logical_role != "linearizable-store"
        || observation.attempt_revision == 0
        || observation.fencing_token == 0
        || !is_sha256(&observation.stable_resume_id)
        || !is_sha256(&observation.authoritative_state_sha256)
        || observation.observation_sha256 != observation_sha256
    {
        return Err(V2RuntimeError::new(
            "attempt_state_observation_invalid",
            "state observation is not bound to the installed generation, attempt state, revision, fence, and canonical digest",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,
        &observation.authority_scope,
    )?;
    if observation.authority_scope.key_id
            != observation.signer_key_id
        || observation.authority_scope.logical_role
            != observation.signer_logical_role
        || observation.authority_scope.attempt_id
            != observation.attempt_id
        || observation.authority_scope.attempt_revision
            != observation.attempt_revision
        || observation.authority_scope.fencing_token
            != observation.fencing_token
    {
        return Err(V2RuntimeError::new(
            "attempt_state_observation_scope_mismatch",
            "state observation signer scope differs from the observed attempt",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &observation.signer_logical_role,
        &observation.signer_key_id,
        STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN,
        &observation.without_signature(),
        &observation.signature,
    )
}

pub fn verify_final_envelope_verification(
    topology: &SignedCustodyTopologyV1,
    verification: &SignedFinalEnvelopeVerificationV1,
) -> Result<(), V2RuntimeError> {
    if verification.api_version
            != FINAL_ENVELOPE_VERIFICATION_API_VERSION
        || verification.generation_id != topology.generation_id
        || verification.generation != topology.generation
        || verification.operation
            != ServiceOperationV1::FinalEnvelopeVerify
        || verification.signer_logical_role
            != "live-proof-verifier"
        || !verification.verified
        || verification.verification_sequence == 0
        || !is_sha256(&verification.final_envelope_sha256)
        || !is_sha256(
            &verification.authority_artifacts_root_sha256,
        )
        || !is_sha256(&verification.stable_resume_id)
        || !is_sha256(
            &verification.canonical_envelope_bytes_sha256,
        )
        || !is_sha256(
            &verification.transition_chain_root_sha256,
        )
        || !is_sha256(&verification.verification_result_sha256)
    {
        return Err(V2RuntimeError::new(
            "final_envelope_verification_signer_invalid",
            "canonical final-envelope verification is not issued by the assigned proof verifier",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::PolicyProofVerifier,
        ServiceOperationV1::FinalEnvelopeVerify,
        &verification.authority_scope,
    )?;
    if verification.authority_scope.key_id
            != verification.signer_key_id
        || verification.authority_scope.logical_role
            != verification.signer_logical_role
        || verification.authority_scope.attempt_id
            != verification.attempt_id
    {
        return Err(V2RuntimeError::new(
            "final_envelope_authority_scope_mismatch",
            "final verification signer and attempt differ from its authority scope",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::PolicyProofVerifier,
        &verification.signer_logical_role,
        &verification.signer_key_id,
        FINAL_ENVELOPE_SIGNATURE_DOMAIN,
        &verification.without_signature(),
        &verification.signature,
    )
}

pub fn verify_settlement_evidence_context(
    topology: &SignedCustodyTopologyV1,
    context:
        &super::protocol::SignedSettlementEvidenceContextV1,
) -> Result<(), V2RuntimeError> {
    if context.api_version
            != SETTLEMENT_EVIDENCE_CONTEXT_API_VERSION
        || context.generation_id != topology.generation_id
        || context.generation != topology.generation
        || context.signer_logical_role != "linearizable-store"
        || context.attempt_revision == 0
        || context.fencing_token == 0
        || !context.owner_death_observed
        || !context.cgroup_empty_observed
        || !context.cgroup_death_observed
        || !is_sha256(&context.authoritative_state_sha256)
        || !is_sha256(&context.stable_resume_id)
        || !is_sha256(&context.terminal_detail_sha256)
        || context
            .upstream_response_sha256
            .as_ref()
            .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(V2RuntimeError::new(
            "settlement_evidence_context_invalid",
            "settlement evidence context is not a complete signed state observation",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::Reconcile,
        &context.authority_scope,
    )?;
    if context.authority_scope.attempt_id != context.attempt_id
        || context.authority_scope.attempt_revision
            != context.attempt_revision
        || context.authority_scope.fencing_token
            != context.fencing_token
        || context.authority_scope.logical_role
            != context.signer_logical_role
        || context.authority_scope.key_id != context.signer_key_id
    {
        return Err(V2RuntimeError::new(
            "settlement_evidence_context_scope_mismatch",
            "settlement context signer scope differs from authoritative state",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &context.signer_logical_role,
        &context.signer_key_id,
        SETTLEMENT_EVIDENCE_CONTEXT_SIGNATURE_DOMAIN,
        &context.without_signature(),
        &context.signature,
    )
}

pub fn verify_release_metadata(
    topology: &SignedCustodyTopologyV1,
    metadata: &SignedReleaseMetadataV1,
) -> Result<(), V2RuntimeError> {
    if metadata.api_version != RELEASE_METADATA_API_VERSION
        || metadata.generation_id != topology.generation_id
        || metadata.generation != topology.generation
        || metadata.operation
            != ServiceOperationV1::CommitReleaseMetadata
        || metadata.signer_logical_role != "linearizable-store"
        || !metadata.raw_target_bytes_unchanged
        || !metadata.metadata_is_separate_record
        || !metadata.committed_before_object
        || metadata.metadata_commit_sequence == 0
        || metadata.object_commit_sequence
            <= metadata.metadata_commit_sequence
        || !is_sha256(&metadata.stable_resume_id)
        || !is_sha256(&metadata.request_sha256)
        || !is_sha256(&metadata.raw_object_sha256)
        || !is_sha256(&metadata.metadata_record_sha256)
        || metadata.raw_object_byte_length == 0
    {
        return Err(V2RuntimeError::new(
            "release_metadata_binding_invalid",
            "release metadata is not generation-bound, committed before the immutable raw object, or signed by linearizable-store",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &metadata.signer_logical_role,
        &metadata.signer_key_id,
        RELEASE_METADATA_SIGNATURE_DOMAIN,
        &metadata.without_signature(),
        &metadata.signature,
    )
}

pub fn verify_immutable_raw_inspection(
    topology: &SignedCustodyTopologyV1,
    inspection: &SignedImmutableRawInspectionV1,
) -> Result<(), V2RuntimeError> {
    inspection.authority_proof_seed.validate_integrity()?;
    if inspection.api_version
            != IMMUTABLE_RAW_INSPECTION_API_VERSION
        || inspection.generation_id != topology.generation_id
        || inspection.generation != topology.generation
        || inspection.operation
            != ServiceOperationV1::InspectImmutableRaw
        || inspection.signer_logical_role != "archive-store"
        || !inspection.immutable
        || inspection.consumed
        || inspection.inspection_sequence == 0
        || !is_sha256(&inspection.stable_resume_id)
        || !is_sha256(&inspection.request_sha256)
        || !is_sha256(&inspection.raw_object_sha256)
        || !is_sha256(&inspection.inspection_receipt_sha256)
        || inspection.raw_object_byte_length == 0
        || inspection.exact_object.sha256
            != inspection.raw_object_sha256
        || inspection.exact_object.byte_length
            != inspection.raw_object_byte_length
        || inspection.exact_object.object_id
            != inspection.raw_object_id
        || inspection.exact_object.fd_index != 0
        || inspection.exact_object.media_type
            != crate::response_observation_v2_api::
                ExactObjectMediaType::Http11Response
        || inspection.exact_object.required_seals
            != crate::response_observation_v2_api::
                MemfdSealProfile::ImmutableV1
        || inspection.authority_proof_seed.generation_id
            != inspection.generation_id
        || inspection.authority_proof_seed.generation
            != inspection.generation
        || inspection.authority_proof_seed.attempt_id
            != inspection.attempt_id
        || inspection.authority_proof_seed.attempt_revision
            != inspection.inspection_sequence
        || inspection.authority_proof_seed.fencing_token
            != inspection.authority_scope.fencing_token
        || inspection.authority_proof_seed.stable_resume_id
            != inspection.stable_resume_id
        || inspection
            .authority_proof_seed
            .raw_response_object
            .object_id
            .0
            != inspection.raw_object_id
        || inspection
            .authority_proof_seed
            .raw_response_object
            .content_sha256
            .0
            != inspection.raw_object_sha256
        || inspection.authority_proof_seed.http11_framing
            .canonical_framing_sha256
            .0
            != inspection.framing_validation_sha256
    {
        return Err(V2RuntimeError::new(
            "immutable_raw_inspection_binding_invalid",
            "inspection is not a non-consuming signed view of the exact immutable raw object and its pre-commit release metadata",
        ));
    }
    verify_attempt_state_observation(
        topology,
        &inspection.state_observation,
    )?;
    if let Some(receipt) = &inspection.state_authority_receipt {
        verify_state_mutation_receipt(topology, receipt)?;
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::ImmutableArtifactLedger,
        ServiceOperationV1::InspectImmutableRaw,
        &inspection.authority_scope,
    )?;
    if inspection.authority_scope.key_id != inspection.signer_key_id
        || inspection.authority_scope.logical_role
            != inspection.signer_logical_role
        || inspection.authority_scope.attempt_id
            != inspection.attempt_id
        || inspection.authority_scope.attempt_revision
            != inspection.inspection_sequence
        || inspection.state_observation.attempt_id
            != inspection.attempt_id
        || inspection.state_observation.stable_resume_id
            != inspection.stable_resume_id
        || inspection.state_observation.attempt_revision
            != inspection.inspection_sequence
        || inspection.state_observation.fencing_token
            != inspection.authority_scope.fencing_token
        || inspection.state_authority_receipt.as_ref().is_some_and(
            |receipt| {
                receipt.attempt_id != inspection.attempt_id
                    || receipt.stable_resume_id
                        != inspection.stable_resume_id
            },
        )
    {
        return Err(V2RuntimeError::new(
            "immutable_raw_authority_scope_mismatch",
            "inspection authorities do not bind the same attempt, revision, resume ID, and signer",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::ImmutableArtifactLedger,
        &inspection.signer_logical_role,
        &inspection.signer_key_id,
        IMMUTABLE_RAW_INSPECTION_SIGNATURE_DOMAIN,
        &inspection.without_signature(),
        &inspection.signature,
    )
}

pub fn verify_release_authorization(
    topology: &SignedCustodyTopologyV1,
    authorization: &SignedReleaseAuthorizationV2,
) -> Result<(), V2RuntimeError> {
    if authorization.api_version != RELEASE_AUTHORIZATION_API_VERSION
        || authorization.generation_id != topology.generation_id
        || authorization.generation != topology.generation
        || authorization.operation
            != ServiceOperationV1::AuthorizeRelease
        || authorization.signer_logical_role != "public-release"
        || !is_sha256(&authorization.request_sha256)
        || !is_sha256(&authorization.stable_resume_id)
        || !is_sha256(&authorization.inspection_receipt_sha256)
        || !is_sha256(
            &authorization.authority_proof_seed_sha256,
        )
        || !is_sha256(
            &authorization
                .authority_proof_seed_artifacts_root_sha256,
        )
        || !is_sha256(&authorization.raw_object_sha256)
        || !is_sha256(&authorization.policy_decision_sha256)
        || !is_sha256(&authorization.exact_replay_key_sha256)
        || !is_sha256(&authorization.exact_release_request_sha256)
        || !is_sha256(&authorization.one_use_nonce_sha256)
        || !is_sha256(
            &authorization.release_authorization_artifact_sha256,
        )
        || authorization.finalization_id.is_empty()
        || !is_sha256(&authorization.authorization_result_sha256)
        || authorization.fencing_token == 0
        || authorization.expires_at_epoch_ms == 0
    {
        return Err(V2RuntimeError::new(
            "release_authorization_binding_invalid",
            "release authorization is not generation-, operation-, inspection-, nine-artifact seed-, policy-, object-, and replay-bound",
        ));
    }
    let nested = match &authorization
        .release_authorization_artifact
        .body
        .payload
    {
        super::super::state_authority::rpc::
            NestedAuthorityPayload::ReleaseAuthorization(nested) => {
                nested
            }
        _ => {
            return Err(V2RuntimeError::new(
                "release_authorization_artifact_invalid",
                "release authorization lacks its dedicated nested artifact",
            ))
        }
    };
    let nested_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(
            crate::canonical_json_bytes(
                &authorization.release_authorization_artifact,
            )
            .map_err(|_| {
                V2RuntimeError::new(
                    "release_authorization_artifact_invalid",
                    "release authorization artifact cannot be canonicalized",
                )
            })?,
        ),
    );
    if nested_sha256
            != authorization.release_authorization_artifact_sha256
        || nested.release_authorization_id.0
            != authorization.authorization_id
        || nested.finalization_id.0 != authorization.finalization_id
        || nested.release_request_sha256.0
            != authorization.exact_release_request_sha256
        || nested.inspection_result_sha256.0
            != authorization.inspection_receipt_sha256
        || nested.release_object_sha256.0
            != authorization.raw_object_sha256
        || nested.one_use_nonce_sha256.0
            != authorization.one_use_nonce_sha256
    {
        return Err(V2RuntimeError::new(
            "release_authorization_artifact_mismatch",
            "nested release authorization differs from its signed custody receipt",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::ReleaseAttestorPublisher,
        ServiceOperationV1::AuthorizeRelease,
        &authorization.authority_scope,
    )?;
    if authorization.authority_scope.key_id
            != authorization.signer_key_id
        || authorization.authority_scope.logical_role
            != authorization.signer_logical_role
        || authorization.authority_scope.attempt_id
            != authorization.attempt_id
        || authorization.authority_scope.fencing_token
            != authorization.fencing_token
    {
        return Err(V2RuntimeError::new(
            "release_authority_scope_mismatch",
            "release authorization signer, attempt, or fence differs from its authority scope",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::ReleaseAttestorPublisher,
        &authorization.signer_logical_role,
        &authorization.signer_key_id,
        RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
        &authorization.without_signature(),
        &authorization.signature,
    )
}

pub fn verify_release_consumption_preauthorization(
    topology: &SignedCustodyTopologyV1,
    preauthorization:
        &SignedReleaseConsumptionPreauthorizationV1,
) -> Result<(), V2RuntimeError> {
    let canonical = crate::canonical_json_bytes(
        &preauthorization.mutation_binding,
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "release_consumption_preauthorization_invalid",
            "preauthorization mutation binding cannot be canonicalized",
        )
    })?;
    let binding_sha256 =
        format!("sha256:{:x}", Sha256::digest(canonical));
    if preauthorization.api_version
            != RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION
        || preauthorization.generation_id != topology.generation_id
        || preauthorization.generation != topology.generation
        || preauthorization.operation
            != ServiceOperationV1::ConsumeReleaseAndRetrieveExact
        || preauthorization.signer_logical_role
            != "public-release-consumption"
        || preauthorization.fencing_token == 0
        || preauthorization.mutation_binding_sha256
            != binding_sha256
        || !is_sha256(
            &preauthorization.preauthorization_artifact_sha256,
        )
        || preauthorization.mutation_binding.expected_revision == 0
        || preauthorization.mutation_binding.successor_revision
            != preauthorization
                .mutation_binding
                .expected_revision
                .saturating_add(1)
        || preauthorization.mutation_binding.expected_state
            != "OBSERVED"
        || preauthorization.mutation_binding.successor_state
            != "RELEASE_PREPARED"
    {
        return Err(V2RuntimeError::new(
            "release_consumption_preauthorization_invalid",
            "preauthorization does not bind one exact CAS into RELEASE_PREPARED",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        &preauthorization.authority_scope,
    )?;
    if preauthorization.authority_scope.key_id
            != preauthorization.signer_key_id
        || preauthorization.authority_scope.logical_role
            != preauthorization.signer_logical_role
        || preauthorization.authority_scope.attempt_id
            != preauthorization.attempt_id
        || preauthorization.authority_scope.attempt_revision
            != preauthorization.mutation_binding.expected_revision
        || preauthorization.authority_scope.fencing_token
            != preauthorization.fencing_token
    {
        return Err(V2RuntimeError::new(
            "release_consumption_preauthorization_scope_mismatch",
            "preauthorization signer scope differs from the exact attempt CAS binding",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &preauthorization.signer_logical_role,
        &preauthorization.signer_key_id,
        RELEASE_CONSUMPTION_PREAUTHORIZATION_SIGNATURE_DOMAIN,
        &preauthorization.without_signature(),
        &preauthorization.signature,
    )
}

pub fn verify_release_preparation_receipt(
    topology: &SignedCustodyTopologyV1,
    preparation: &SignedReleasePreparationReceiptV1,
) -> Result<(), V2RuntimeError> {
    preparation.validate_integrity()?;
    if preparation.generation_id != topology.generation_id
        || preparation.generation != topology.generation
        || preparation.signer_logical_role
            != "public-release-consumption"
    {
        return Err(V2RuntimeError::new(
            "release_preparation_receipt_invalid",
            "release preparation is not issued by the installed state authority generation",
        ));
    }
    verify_release_consumption_preauthorization(
        topology,
        &preparation.preauthorization,
    )?;
    verify_state_mutation_receipt(
        topology,
        &preparation.state_authority_receipt,
    )?;
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        &preparation.authority_scope,
    )?;
    if preparation.authority_scope.key_id
            != preparation.signer_key_id
        || preparation.authority_scope.logical_role
            != preparation.signer_logical_role
        || preparation.authority_scope.attempt_id
            != preparation.attempt_id
        || preparation.authority_scope.attempt_revision
            != preparation.successor_revision
        || preparation.authority_scope.fencing_token
            != preparation.fencing_token
    {
        return Err(V2RuntimeError::new(
            "release_preparation_authority_scope_mismatch",
            "release preparation signer scope differs from the post-CAS state",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &preparation.signer_logical_role,
        &preparation.signer_key_id,
        RELEASE_PREPARATION_RECEIPT_SIGNATURE_DOMAIN,
        &preparation.without_signature(),
        &preparation.signature,
    )
}

pub fn verify_release_consumption(
    topology: &SignedCustodyTopologyV1,
    consumption: &SignedReleaseConsumptionV2,
) -> Result<(), V2RuntimeError> {
    if consumption.api_version != RELEASE_CONSUMPTION_API_VERSION
        || consumption.generation_id != topology.generation_id
        || consumption.generation != topology.generation
        || consumption.operation
            != ServiceOperationV1::ConsumeReleaseAndRetrieveExact
        || consumption.signer_logical_role
            != "public-release-consumption"
        || !is_sha256(&consumption.request_sha256)
        || !is_sha256(&consumption.stable_resume_id)
        || !is_sha256(&consumption.inspection_receipt_sha256)
        || !is_sha256(
            &consumption.final_envelope_verification_sha256,
        )
        || !is_sha256(
            &consumption.release_preparation_receipt_sha256,
        )
        || !is_sha256(&consumption.exact_replay_key_sha256)
        || !is_sha256(&consumption.raw_object_sha256)
        || !is_sha256(&consumption.consumption_receipt_sha256)
        || !is_sha256(&consumption.canonical_result_sha256)
        || consumption.fencing_token == 0
        || consumption.raw_object_byte_length == 0
        || consumption.authority_revision == 0
        || consumption.consumption_sequence == 0
        || consumption.exact_object.sha256
            != consumption.raw_object_sha256
        || consumption.exact_object.byte_length
            != consumption.raw_object_byte_length
        || consumption.exact_object.fd_index != 0
        || consumption.exact_object.media_type
            != crate::response_observation_v2_api::
                ExactObjectMediaType::Http11Response
        || consumption.exact_object.required_seals
            != crate::response_observation_v2_api::
                MemfdSealProfile::ImmutableV1
    {
        return Err(V2RuntimeError::new(
            "release_consumption_binding_invalid",
            "release consumption is not an exact signed generation-, inspection-, proof-, replay-, and immutable-object result",
        ));
    }
    verify_release_preparation_receipt(
        topology,
        &consumption.prepared_consumption,
    )?;
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        &consumption.authority_scope,
    )?;
    if consumption.authority_scope.key_id
            != consumption.signer_key_id
        || consumption.authority_scope.logical_role
            != consumption.signer_logical_role
        || consumption.authority_scope.attempt_id
            != consumption.attempt_id
        || consumption.authority_scope.attempt_revision
            != consumption.authority_revision
        || consumption.authority_scope.fencing_token
            != consumption.fencing_token
        || consumption.prepared_consumption.successor_revision
            != consumption.authority_revision
        || consumption.prepared_consumption
            .durable_canonical_result_sha256
            != consumption.canonical_result_sha256
    {
        return Err(V2RuntimeError::new(
            "release_consumption_authority_scope_mismatch",
            "release consumption authorities do not bind the same exact result, attempt, revision, fence, and signer",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &consumption.signer_logical_role,
        &consumption.signer_key_id,
        RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
        &consumption.without_signature(),
        &consumption.signature,
    )
}

pub fn verify_custody_attestation(
    topology: &SignedCustodyTopologyV1,
    attestation: &SignedCustodyAttestationV1,
) -> Result<(), V2RuntimeError> {
    if attestation.api_version != CUSTODY_ATTESTATION_API_VERSION
        || attestation.generation_id != topology.generation_id
        || attestation.generation != topology.generation
        || attestation.operation != ServiceOperationV1::Attest
        || attestation.signer_logical_role != "attester"
        || !is_sha256(&attestation.request_sha256)
        || !is_sha256(&attestation.stable_resume_id)
        || !is_sha256(&attestation.final_envelope_sha256)
        || !is_sha256(&attestation.attestation_evidence_sha256)
        || !is_sha256(&attestation.attestation_result_sha256)
        || attestation.attestation_sequence == 0
    {
        return Err(V2RuntimeError::new(
            "custody_attestation_binding_invalid",
            "attestation is not bound to the exact generation, operation, request, attempt, resume ID, and final envelope",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::ReleaseAttestorPublisher,
        &attestation.signer_logical_role,
        &attestation.signer_key_id,
        CUSTODY_ATTESTATION_SIGNATURE_DOMAIN,
        &attestation.without_signature(),
        &attestation.signature,
    )
}

pub fn verify_custody_recovery(
    topology: &SignedCustodyTopologyV1,
    recovery: &SignedCustodyRecoveryV1,
) -> Result<(), V2RuntimeError> {
    if recovery.api_version != CUSTODY_RECOVERY_API_VERSION
        || recovery.generation_id != topology.generation_id
        || recovery.generation != topology.generation
        || recovery.operation != ServiceOperationV1::Recover
        || recovery.signer_logical_role != "recovery"
        || !is_sha256(&recovery.request_sha256)
        || !is_sha256(&recovery.stable_resume_id)
        || !is_sha256(&recovery.recovered_terminal_state_sha256)
        || !is_sha256(&recovery.recovered_result_sha256)
        || recovery.reconciliation_high_water == 0
        || recovery.recovery_sequence == 0
    {
        return Err(V2RuntimeError::new(
            "custody_recovery_binding_invalid",
            "recovery result is not generation-, operation-, request-, attempt-, resume-, terminal-, and reconciliation-bound",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::Recover,
        &recovery.authority_scope,
    )?;
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &recovery.signer_logical_role,
        &recovery.signer_key_id,
        CUSTODY_RECOVERY_SIGNATURE_DOMAIN,
        &recovery.without_signature(),
        &recovery.signature,
    )
}

pub fn verify_custody_error(
    topology: &SignedCustodyTopologyV1,
    service_role: CustodyServiceRole,
    error: &SignedCustodyErrorV1,
) -> Result<(), V2RuntimeError> {
    if error.api_version != CUSTODY_ERROR_API_VERSION
        || error.generation_id != topology.generation_id
        || error.generation != topology.generation
        || expected_operation_signer(service_role, error.operation)
            != Some(error.signer_logical_role.as_str())
        || !is_sha256(&error.request_sha256)
        || !is_sha256(&error.stable_resume_id)
        || !error.durable_terminalized
        || !matches!(
            error.terminal_state.as_str(),
            "FAILED" | "OUTCOME_UNKNOWN"
        )
        || !is_sha256(&error.terminal_state_sha256)
        || error.reconciliation_id.is_empty()
        || !is_sha256(&error.reconciliation_record_sha256)
        || error.authority_sequence == 0
        || !is_sha256(&error.canonical_error_sha256)
    {
        return Err(V2RuntimeError::new(
            "custody_error_binding_invalid",
            "authenticated error is not durably terminalized and bound to the exact generation, operation, attempt, stable resume ID, and reconciliation record",
        ));
    }
    verify_provider_authority_scope(
        topology,
        service_role,
        error.operation,
        &error.authority_scope,
    )?;
    if error.authority_scope.key_id != error.signer_key_id
        || error.authority_scope.logical_role
            != error.signer_logical_role
        || error.authority_scope.attempt_id != error.attempt_id
    {
        return Err(V2RuntimeError::new(
            "custody_error_authority_scope_mismatch",
            "custody error signer and attempt differ from its authority scope",
        ));
    }
    verify_logical_role_signature(
        topology,
        service_role,
        &error.signer_logical_role,
        &error.signer_key_id,
        CUSTODY_ERROR_SIGNATURE_DOMAIN,
        &error.without_signature(),
        &error.signature,
    )
}

pub fn verify_state_mutation_receipt(
    topology: &SignedCustodyTopologyV1,
    receipt: &SignedStateMutationReceiptV1,
) -> Result<(), V2RuntimeError> {
    if receipt.api_version != STATE_MUTATION_RECEIPT_API_VERSION
        || receipt.generation_id != topology.generation_id
        || receipt.generation != topology.generation
        || receipt.operation != ServiceOperationV1::StateCas
        || receipt.signer_logical_role != "linearizable-store"
        || receipt.request_id.is_empty()
        || receipt.operation_id.is_empty()
        || receipt.attempt_id.is_empty()
        || !is_sha256(&receipt.stable_resume_id)
        || !is_sha256(&receipt.exact_request_sha256)
        || !is_sha256(&receipt.exact_result_sha256)
        || receipt.authoritative_revision == 0
        || receipt.fencing_token == 0
    {
        return Err(V2RuntimeError::new(
            "state_mutation_receipt_invalid",
            "state mutation receipt lacks exact durable authority bindings",
        ));
    }
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,
        &receipt.authority_scope,
    )?;
    if receipt.authority_scope.key_id != receipt.signer_key_id
        || receipt.authority_scope.logical_role
            != receipt.signer_logical_role
        || receipt.authority_scope.operation_id != receipt.operation_id
        || receipt.authority_scope.attempt_id != receipt.attempt_id
        || receipt.authority_scope.attempt_revision
            != receipt.authoritative_revision
        || receipt.authority_scope.fencing_token
            != receipt.fencing_token
    {
        return Err(V2RuntimeError::new(
            "state_mutation_authority_scope_mismatch",
            "state mutation signer, operation, attempt, revision, or fence differs from its authority scope",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &receipt.signer_logical_role,
        &receipt.signer_key_id,
        STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN,
        &receipt.without_signature(),
        &receipt.signature,
    )
}

pub fn verify_publication_receipt(
    topology: &SignedCustodyTopologyV1,
    receipt: &SignedPublicationReceiptV1,
) -> Result<(), V2RuntimeError> {
    if receipt.api_version != PUBLICATION_API_VERSION
        || receipt.generation_id != topology.generation_id
        || receipt.generation != topology.generation
        || receipt.operation != ServiceOperationV1::Publish
        || receipt.signer_logical_role != "publisher"
        || receipt.publication_sequence == 0
        || !is_sha256(&receipt.request_sha256)
        || !is_sha256(&receipt.stable_resume_id)
        || !is_sha256(&receipt.payload_object_sha256)
        || !is_sha256(
            &receipt.durable_publication_receipt_sha256,
        )
    {
        return Err(V2RuntimeError::new(
            "publication_receipt_invalid",
            "publication receipt lacks exact durable publication bindings",
        ));
    }
    verify_state_mutation_receipt(
        topology,
        &receipt.state_authority_receipt,
    )?;
    verify_provider_authority_scope(
        topology,
        CustodyServiceRole::ReleaseAttestorPublisher,
        ServiceOperationV1::Publish,
        &receipt.authority_scope,
    )?;
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::ReleaseAttestorPublisher,
        &receipt.signer_logical_role,
        &receipt.signer_key_id,
        PUBLICATION_SIGNATURE_DOMAIN,
        &receipt.without_signature(),
        &receipt.signature,
    )
}

pub fn verify_durable_terminal_receipt(
    topology: &SignedCustodyTopologyV1,
    service_role: CustodyServiceRole,
    receipt: &SignedDurableTerminalReceiptV1,
) -> Result<(), V2RuntimeError> {
    let reconciliation_evidence_valid = match (
        receipt.reconciliation_id.as_deref(),
        receipt.reconciliation_artifact.as_ref(),
        receipt.reconciliation_artifact_sha256.as_deref(),
    ) {
        (Some(id), Some(artifact), Some(expected_sha256)) => {
            let payload_matches = matches!(
                &artifact.body.payload,
                super::super::state_authority::rpc::
                    NestedAuthorityPayload::Reconciliation(value)
                    if value.reconciliation_job_id.0.as_str() == id
            );
            artifact.validate_contract().is_ok()
                && payload_matches
                && artifact.body.generation_id.0
                    == receipt.generation_id
                && artifact.body.attempt_id.0 == receipt.attempt_id
                && artifact.body.fence_token.0
                    == receipt.authority_scope.fencing_token.to_string()
                && canonical_sha256(artifact)? == expected_sha256
        }
        (None, None, None) => true,
        _ => false,
    };
    let recovery_evidence_valid = match (
        receipt.recovery_artifact.as_ref(),
        receipt.recovery_artifact_sha256.as_deref(),
    ) {
        (Some(artifact), Some(expected_sha256)) => {
            artifact.validate_contract().is_ok()
                && matches!(
                    &artifact.body.payload,
                    super::super::state_authority::rpc::
                        NestedAuthorityPayload::Recovery(_)
                )
                && artifact.body.generation_id.0
                    == receipt.generation_id
                && artifact.body.attempt_id.0 == receipt.attempt_id
                && artifact.body.fence_token.0
                    == receipt.authority_scope.fencing_token.to_string()
                && canonical_sha256(artifact)? == expected_sha256
        }
        (None, None) => true,
        _ => false,
    };
    let operation_evidence_valid = match receipt.operation {
        ServiceOperationV1::Reconcile => {
            receipt.reconciliation_artifact.is_some()
        }
        ServiceOperationV1::Cleanup => {
            receipt.reconciliation_artifact.is_none()
                && receipt.recovery_artifact.is_some()
        }
        _ => false,
    };
    if receipt.api_version != SETTLEMENT_API_VERSION
        || receipt.generation_id != topology.generation_id
        || receipt.generation != topology.generation
        || !matches!(
            receipt.operation,
            ServiceOperationV1::Reconcile
                | ServiceOperationV1::Cleanup
        )
        || expected_operation_signer(service_role, receipt.operation)
            != Some(receipt.signer_logical_role.as_str())
        || !receipt.durable
        || !receipt.reconciled
        || receipt.authority_sequence == 0
        || !is_sha256(&receipt.request_sha256)
        || !is_sha256(&receipt.stable_resume_id)
        || !is_sha256(&receipt.terminal_state_sha256)
        || !is_sha256(&receipt.settlement_receipt_sha256)
        || !reconciliation_evidence_valid
        || !recovery_evidence_valid
        || !operation_evidence_valid
    {
        return Err(V2RuntimeError::new(
            "durable_terminal_receipt_invalid",
            "settlement is not a signed durable reconciliation result",
        ));
    }
    verify_state_mutation_receipt(
        topology,
        &receipt.state_authority_receipt,
    )?;
    verify_provider_authority_scope(
        topology,
        service_role,
        receipt.operation,
        &receipt.authority_scope,
    )?;
    verify_logical_role_signature(
        topology,
        service_role,
        &receipt.signer_logical_role,
        &receipt.signer_key_id,
        SETTLEMENT_SIGNATURE_DOMAIN,
        &receipt.without_signature(),
        &receipt.signature,
    )
}

pub(crate) fn verify_state_authority_response(
    topology: &SignedCustodyTopologyV1,
    response: &super::state::StateAuthorityResponseV1,
) -> Result<(), V2RuntimeError> {
    if response.generation_id != topology.generation_id
        || response.generation != topology.generation
        || response.signer_logical_role != "linearizable-store"
    {
        return Err(V2RuntimeError::new(
            "state_authority_response_signer_invalid",
            "state result is not generation-bound and signed by linearizable-store",
        ));
    }
    verify_logical_role_signature(
        topology,
        CustodyServiceRole::StateAuthority,
        &response.signer_logical_role,
        &response.signer_key_id,
        STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN,
        &response.without_signature(),
        &response.signature,
    )
}

pub fn verify_service_rpc_result(
    topology: &SignedCustodyTopologyV1,
    result: &super::protocol::ServiceRpcResultV1,
) -> Result<(), V2RuntimeError> {
    if result.api_version
            != super::protocol::SERVICE_RPC_API_VERSION
        || result.generation_id != topology.generation_id
        || result.generation != topology.generation
        || expected_operation_signer(
            result.service_role,
            result.operation,
        ) != Some(result.signer_logical_role.as_str())
    {
        return Err(V2RuntimeError::new(
            "custody_service_result_binding_invalid",
            "service result is not bound to the active signed generation and exact operation-specific logical role",
        ));
    }
    verify_logical_role_signature(
        topology,
        result.service_role,
        &result.signer_logical_role,
        &result.signer_key_id,
        SERVICE_RESULT_SIGNATURE_DOMAIN,
        &result.without_signature(),
        &result.signature,
    )
}

pub(crate) fn expected_operation_signer(
    role: CustodyServiceRole,
    operation: ServiceOperationV1,
) -> Option<&'static str> {
    use ServiceOperationV1::*;
    match (role, operation) {
        (
            CustodyServiceRole::StateAuthority,
            ConsumeReleaseAndRetrieveExact,
        ) => {
            Some("public-release-consumption")
        }
        (CustodyServiceRole::StateAuthority, Recover) => {
            Some("recovery")
        }
        (CustodyServiceRole::StateAuthority, ReplayResolve) => {
            Some("linearizable-store")
        }
        (
            CustodyServiceRole::StateAuthority,
            FenceRevoke | QuiescenceObserve,
        ) => Some("emergency-fence-revoker"),
        (CustodyServiceRole::StateAuthority, _) => {
            Some("linearizable-store")
        }
        (CustodyServiceRole::CredentialTransport, TargetDispatch) => {
            Some("target-transport")
        }
        (CustodyServiceRole::CredentialTransport, _) => {
            Some("mutation-supervisor")
        }
        (
            CustodyServiceRole::PolicyProofVerifier,
            FinalEnvelopeVerify,
        ) => Some("live-proof-verifier"),
        (CustodyServiceRole::PolicyProofVerifier, _) => {
            Some("evidence-trust")
        }
        (
            CustodyServiceRole::ImmutableArtifactLedger,
            InspectImmutableRaw,
        ) => {
            Some("archive-store")
        }
        (CustodyServiceRole::ImmutableArtifactLedger, _) => {
            Some("persistence")
        }
        (CustodyServiceRole::ReleaseAttestorPublisher, Publish) => {
            Some("publisher")
        }
        (CustodyServiceRole::ReleaseAttestorPublisher, Attest) => {
            Some("attester")
        }
        (CustodyServiceRole::CleanupWatchdog, Reconcile) => {
            Some("outcome-reconciliation")
        }
        (
            CustodyServiceRole::ReleaseAttestorPublisher,
            AuthorizeRelease,
        ) => Some("public-release"),
        (CustodyServiceRole::ReleaseAttestorPublisher, _) => {
            Some("public-release")
        }
        (CustodyServiceRole::CleanupWatchdog, _) => {
            Some("emergency-cleanup-executor")
        }
        _ => None,
    }
}

fn verify_logical_role_signature<T: Serialize>(
    topology: &SignedCustodyTopologyV1,
    service_role: CustodyServiceRole,
    logical_role: &str,
    key_id: &str,
    domain: &[u8],
    value: &T,
    signature: &str,
) -> Result<(), V2RuntimeError> {
    let binding = topology
        .logical_role(logical_role)
        .filter(|binding| {
            binding.service_role == service_role
                && binding.key_id == key_id
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_role_signature_unassigned",
                "signature key is not assigned to the claimed logical role and service",
            )
        })?;
    let process = topology.process(service_role).ok_or_else(|| {
        V2RuntimeError::new(
            "custody_role_process_unassigned",
            "signature service is absent from the signed topology",
        )
    })?;
    let descriptor = process
        .role_keys
        .iter()
        .find(|descriptor| {
            descriptor.logical_role == binding.logical_role
                && descriptor.key_id == binding.key_id
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_role_key_unassigned",
                "signature key descriptor is absent from the service scope",
            )
        })?;
    verify_with_descriptor(
        descriptor,
        domain,
        value,
        signature,
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, V2RuntimeError> {
    let canonical = crate::canonical_json_bytes(value).map_err(|_| {
        V2RuntimeError::new(
            "custody_canonical_hash_invalid",
            "signed custody evidence cannot be canonicalized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn verify_with_descriptor<T: Serialize>(
    descriptor: &ServiceRoleKeyDescriptorV1,
    domain: &[u8],
    value: &T,
    signature: &str,
) -> Result<(), V2RuntimeError> {
    let public_key =
        read_exact_public_key(&descriptor.public_key_path)?;
    if format!("sha256:{:x}", Sha256::digest(public_key))
        != descriptor.public_key_sha256
    {
        return Err(V2RuntimeError::new(
            "custody_role_public_key_mismatch",
            "role public key does not match the signed topology digest",
        ));
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_role_signature_invalid",
                "role signature is not canonical base64",
            )
        })?;
    let canonical = crate::canonical_json_bytes(value).map_err(|_| {
        V2RuntimeError::new(
            "custody_role_signature_payload_invalid",
            "role-signed payload cannot be canonicalized",
        )
    })?;
    let mut message =
        Vec::with_capacity(domain.len() + canonical.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&canonical);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        public_key,
    )
    .verify(&message, &signature)
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_role_signature_invalid",
            "role signature is invalid",
        )
    })
}

fn read_exact_public_key(path: &Path) -> Result<[u8; 32], V2RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_role_public_key_unavailable",
            "open role public key",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(V2RuntimeError::new(
                "custody_role_public_key_unsafe",
                "role public key must be a root-owned immutable regular file",
            ));
        }
    }
    let bytes = fs::read(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_role_public_key_unreadable",
            "read role public key",
        )
    })?;
    bytes.try_into().map_err(|_| {
        V2RuntimeError::new(
            "custody_role_public_key_invalid",
            "role public key must be exactly 32 bytes",
        )
    })
}
