//! Closed five-service production dispatch protocol.
//!
//! One-use verified Rust capabilities never cross the process boundary as
//! caller-authored JSON. They are represented by a service-issued sealed
//! reference which names the exact originating operation and signed receipt.
//! Serializable values use a closed artifact kind plus exact canonical bytes.
//! There is no generic command, path, argument, or executable field.

use super::authority_history::{
    AuthorityEpochRefV3, HistoricalServiceRoleV3,HistoricalAuthorityRoleV3,
};
use super::services::RuntimeAuthorityHistory;
use super::protocol::PolicyCustodyOperation;
use super::terminal_settlement::FiveServiceHistoricalKeyringsV4;
use super::super::{
    canonical_json_bytes, hash_domain_frames, CanonicalAscii, Identifier,
    PolicyShadowCustodySignerRole, ProductionCustodyResultDisposition,
    Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const PRODUCTION_DISPATCH_PROTOCOL_VERSION: &str =
    "serverware.policyCustodyProductionDispatch/v4";
pub(super) const PRODUCTION_GENERATION_PROTOCOL_VERSION: &str =
    "serverware.policyCustodyProductionGeneration/v4";
pub(super) const MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES: usize =
    8 * 1024 * 1024;
pub(super) const MAX_PRODUCTION_DISPATCH_RECEIPTS: usize = 5;

const ARTIFACT_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionArtifact/v4";
const ARTIFACT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionArtifactSignature/v4";
const ARTIFACT_SIGNED_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionArtifactSignedReceipt/v4";
const SEALED_REFERENCE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionSealedReference/v4";
const DISPATCH_BINDING_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionDispatchBinding/v4";
const DISPATCH_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionDispatchRequest/v4";
pub(super) const SERVICE_TRANSITION_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionServiceTransition/v4";
pub(super) const SERVICE_TRANSITION_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionServiceTransitionReceipt/v4";
const DISPATCH_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionDispatchResponse/v4";
const GENERATION_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionGenerationRequest/v4";
const GENERATION_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionGenerationResponse/v4";
pub(super) const GENERATION_SERVICE_TRANSITION_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionGenerationServiceTransition/v4";
pub(super) const GENERATION_SERVICE_TRANSITION_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionGenerationServiceTransitionReceipt/v4";

pub(super) const PRODUCTION_RPC_PROTOCOL_VERSION: &str =
    "serverware.policyCustodyProductionRpc/v4";
pub(super) const PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION: &str =
    "serverware.policyCustodyProductionAuthorityEndpoint/v4";
pub(super) const MAX_PRODUCTION_RPC_PAYLOAD_BYTES: usize =
    MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES;

const ACTIVATION_TRANSACTION_DOMAIN: &[u8] =
    b"serverware.policyActivationAtomicConsumption/v1";
const MAX_ACTIVATION_ASSERTIONS: usize = 64;

const PRODUCTION_RPC_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionRpcRequest/v4";
const PRODUCTION_RPC_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionRpcResponse/v4";
const PRODUCTION_RPC_REJECTION_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionRpcRejection/v4";

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProductionArtifactKindV4 {
    ShadowGenerationIdentity,
    ObservationEvidenceTuple,
    PublicationReconciliationReceipt,
    PreparedGenerationPublication,
    ShadowSpoolEvent,
    AuthenticatedSpoolCompactionRequest,
    ProtectedRequestFacts,
    RequestCommitmentContext,
    ActiveEffectPreparation,
    ActiveEffectCommitState,
    TerminalSlotAppendRequest,
    ActivationPublicationTransaction,
    IngressCustodyAdmission,
    SpoolAppendReservationOutcome,
    ShadowSpillReceipt,
    SpoolCompactionReceipt,
    RequestCommitment,
    ActiveEffectPermit,
    ActiveEffectCommitReceipt,
    TerminalSlotAppendOutcome,
    ActivationPublicationReceipt,
    GenerationTransitionPreparation,
    GenerationInstallAttestation,
    GenerationAbortSettlement,
    NativeGenerationRecovery,
    TerminalCleanupAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CanonicalProductionArtifactV4 {
    pub(super) api_version: String,
    pub(super) kind: ProductionArtifactKindV4,
    pub(super) canonical_bytes_base64: String,
    pub(super) canonical_bytes_length: u64,
    pub(super) canonical_bytes_sha256: Sha256Digest,
    pub(super) artifact_sha256: Sha256Digest,
}

impl CanonicalProductionArtifactV4 {
    pub(super) fn from_serializable<T: Serialize>(
        kind: ProductionArtifactKindV4,
        value: &T,
    ) -> Result<Self, &'static str> {
        let bytes = canonical_json_bytes(value).map_err(|_| {
            "production artifact payload is not canonical"
        })?;
        if bytes.is_empty()
            || bytes.len() > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err("production artifact payload exceeds its fixed bound");
        }
        let canonical_bytes_length =
            u64::try_from(bytes.len()).map_err(|_| {
                "production artifact payload length overflowed"
            })?;
        let canonical_bytes_sha256 = Sha256Digest::compute(&bytes);
        let artifact_sha256 = hash_domain_frames(
            ARTIFACT_DOMAIN,
            &[&canonical_json_bytes(&(
                PRODUCTION_DISPATCH_PROTOCOL_VERSION,
                kind,
                canonical_bytes_length,
                &canonical_bytes_sha256,
            ))
            .map_err(|_| "production artifact is not canonical")?],
        );
        Ok(Self {
            api_version:
                PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            kind,
            canonical_bytes_base64: URL_SAFE_NO_PAD.encode(bytes),
            canonical_bytes_length,
            canonical_bytes_sha256,
            artifact_sha256,
        })
    }

    pub(super) fn exact_bytes(
        &self,
    ) -> Result<Vec<u8>, &'static str> {
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || self.canonical_bytes_base64.is_empty()
            || self.canonical_bytes_base64.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
                    .saturating_mul(2)
        {
            return Err("production artifact envelope is invalid");
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.canonical_bytes_base64)
            .map_err(|_| {
                "production artifact bytes are not canonical base64url"
            })?;
        if decoded.is_empty()
            || decoded.len() > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || u64::try_from(decoded.len()).ok()
                != Some(self.canonical_bytes_length)
            || URL_SAFE_NO_PAD.encode(&decoded)
                != self.canonical_bytes_base64
            || Sha256Digest::compute(&decoded)
                != self.canonical_bytes_sha256
        {
            return Err(
                "production artifact bytes differ from their exact length or digest",
            );
        }
        let expected = hash_domain_frames(
            ARTIFACT_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                self.kind,
                self.canonical_bytes_length,
                &self.canonical_bytes_sha256,
            ))
            .map_err(|_| "production artifact is not canonical")?],
        );
        if expected != self.artifact_sha256 {
            return Err("production artifact identity is invalid");
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SealedProductionArtifactReferenceV4 {
    pub(super) api_version: String,
    pub(super) kind: ProductionArtifactKindV4,
    pub(super) origin_operation_id_sha256: Sha256Digest,
    pub(super) origin_request_sha256: Sha256Digest,
    pub(super) signed_receipt_sha256: Sha256Digest,
    pub(super) trust_checkpoint_sha256: Sha256Digest,
    pub(super) custody_slot_nonce_sha256: Sha256Digest,
    pub(super) issuing_service_role: HistoricalServiceRoleV3,
    pub(super) reference_sha256: Sha256Digest,
}

impl SealedProductionArtifactReferenceV4 {
    fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.origin_operation_id_sha256,
            &self.origin_request_sha256,
            &self.signed_receipt_sha256,
            &self.trust_checkpoint_sha256,
            &self.custody_slot_nonce_sha256,
            &self.reference_sha256,
        ] {
            require_digest(digest)?;
        }
        let expected = hash_domain_frames(
            SEALED_REFERENCE_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                self.kind,
                &self.origin_operation_id_sha256,
                &self.origin_request_sha256,
                &self.signed_receipt_sha256,
                &self.trust_checkpoint_sha256,
                &self.custody_slot_nonce_sha256,
                self.issuing_service_role,
            ))
            .map_err(|_| {
                "production sealed reference is not canonical"
            })?],
        );
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || expected != self.reference_sha256
        {
            return Err("production sealed reference is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedProductionArtifactMaterialV4 {
    pub(super) api_version: String,
    pub(super) kind: ProductionArtifactKindV4,
    pub(super) issuing_service_role: HistoricalServiceRoleV3,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) origin_operation_id_sha256: Sha256Digest,
    pub(super) origin_request_sha256: Sha256Digest,
    pub(super) trust_checkpoint_sha256: Sha256Digest,
    pub(super) custody_slot_nonce_sha256: Sha256Digest,
    pub(super) artifact: CanonicalProductionArtifactV4,
    pub(super) exact_canonical_signature_payload_bytes: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
    pub(super) signed_receipt_sha256: Sha256Digest,
}

impl SignedProductionArtifactMaterialV4 {
    fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, &'static str> {
        canonical_json_bytes(&(
            &self.api_version,
            self.kind,
            self.issuing_service_role,
            &self.authority_epoch,
            &self.origin_operation_id_sha256,
            &self.origin_request_sha256,
            &self.trust_checkpoint_sha256,
            &self.custody_slot_nonce_sha256,
            &self.artifact,
        ))
        .map_err(|_| {
            "sealed production artifact signature payload is not canonical"
        })
    }

    fn validate(
        &self,
        reference: &SealedProductionArtifactReferenceV4,
        binding: &ProductionDispatchBindingV4,
        expected_kind: ProductionArtifactKindV4,
        expected_role: HistoricalServiceRoleV3,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<(), &'static str> {
        for digest in [
            &self.origin_operation_id_sha256,
            &self.origin_request_sha256,
            &self.trust_checkpoint_sha256,
            &self.custody_slot_nonce_sha256,
            &self.signed_receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || self.kind != expected_kind
            || self.issuing_service_role != expected_role
            || self.origin_operation_id_sha256
                != binding.operation_id_sha256
            || self.origin_request_sha256 != binding.request_sha256
            || self.kind != reference.kind
            || self.issuing_service_role
                != reference.issuing_service_role
            || self.origin_operation_id_sha256
                != reference.origin_operation_id_sha256
            || self.origin_request_sha256
                != reference.origin_request_sha256
            || self.trust_checkpoint_sha256
                != reference.trust_checkpoint_sha256
            || self.custody_slot_nonce_sha256
                != reference.custody_slot_nonce_sha256
            || self.artifact.kind != expected_kind
            || self.signature_base64.is_empty()
            || self.signature_base64.len() > 128
            || self.exact_canonical_signature_payload_bytes.is_empty()
            || self.exact_canonical_signature_payload_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || self.exact_signed_envelope_bytes.is_empty()
            || self.exact_signed_envelope_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err(
                "sealed production artifact material differs from its exact reference or dispatch",
            );
        }
        self.artifact.exact_bytes()?;
        let payload = self.canonical_signature_payload()?;
        if self.exact_canonical_signature_payload_bytes != payload {
            return Err(
                "sealed production artifact signature payload bytes are not exact canonical bytes",
            );
        }
        keyrings
            .history(self.issuing_service_role)
            .verify_service_signature(
                &self.authority_epoch,
                ARTIFACT_SIGNATURE_DOMAIN,
                &payload,
                &self.signature_base64,
            )
            .map_err(|_| {
                "sealed production artifact signature is invalid or its authority epoch is not retained"
            })?;
        let envelope = canonical_json_bytes(&(
            &self.api_version,
            self.issuing_service_role,
            &self.authority_epoch,
            &self.exact_canonical_signature_payload_bytes,
            &self.signature_base64,
        ))
        .map_err(|_| {
            "sealed production artifact signed envelope is not canonical"
        })?;
        if self.exact_signed_envelope_bytes != envelope {
            return Err(
                "sealed production artifact signed-envelope bytes are not exact canonical bytes",
            );
        }
        let digest = hash_domain_frames(
            ARTIFACT_SIGNED_RECEIPT_DOMAIN,
            &[self.exact_signed_envelope_bytes.as_slice()],
        );
        if digest != self.signed_receipt_sha256
            || digest != reference.signed_receipt_sha256
        {
            return Err(
                "sealed production artifact reference does not bind its exact signed receipt bytes",
            );
        }
        Ok(())
    }

    pub(super) fn sign_for_service(
        kind: ProductionArtifactKindV4,
        issuing_service_role: HistoricalServiceRoleV3,
        authority_epoch: AuthorityEpochRefV3,
        binding: &ProductionDispatchBindingV4,
        trust_checkpoint_sha256: Sha256Digest,
        custody_slot_nonce_sha256: Sha256Digest,
        artifact: CanonicalProductionArtifactV4,
        signing_key: &SigningKey,
    ) -> Result<(SealedProductionArtifactReferenceV4, Self), &'static str> {
        if artifact.kind != kind {
            return Err("sealed artifact kind differs from its service request");
        }
        let mut material = Self {
            api_version: PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            kind,
            issuing_service_role,
            authority_epoch,
            origin_operation_id_sha256:
                binding.operation_id_sha256.clone(),
            origin_request_sha256: binding.request_sha256.clone(),
            trust_checkpoint_sha256,
            custody_slot_nonce_sha256,
            artifact,
            exact_canonical_signature_payload_bytes: Vec::new(),
            signature_base64: String::new(),
            exact_signed_envelope_bytes: Vec::new(),
            signed_receipt_sha256: Sha256Digest::compute(&[]),
        };
        material.exact_canonical_signature_payload_bytes =
            material.canonical_signature_payload()?;
        let preimage = super::protocol::
            domain_separated_signature_preimage(
                ARTIFACT_SIGNATURE_DOMAIN,
                &material.exact_canonical_signature_payload_bytes,
            )
            .map_err(|_| {
                "sealed artifact signature preimage is invalid"
            })?;
        material.signature_base64 = URL_SAFE_NO_PAD.encode(
            signing_key.sign(&preimage).to_bytes(),
        );
        material.exact_signed_envelope_bytes = canonical_json_bytes(&(
            &material.api_version,
            material.issuing_service_role,
            &material.authority_epoch,
            &material.exact_canonical_signature_payload_bytes,
            &material.signature_base64,
        ))
        .map_err(|_| {
            "sealed artifact signed envelope is not canonical"
        })?;
        material.signed_receipt_sha256 = hash_domain_frames(
            ARTIFACT_SIGNED_RECEIPT_DOMAIN,
            &[material.exact_signed_envelope_bytes.as_slice()],
        );
        let mut reference = SealedProductionArtifactReferenceV4 {
            api_version: PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            kind,
            origin_operation_id_sha256:
                binding.operation_id_sha256.clone(),
            origin_request_sha256: binding.request_sha256.clone(),
            signed_receipt_sha256:
                material.signed_receipt_sha256.clone(),
            trust_checkpoint_sha256:
                material.trust_checkpoint_sha256.clone(),
            custody_slot_nonce_sha256:
                material.custody_slot_nonce_sha256.clone(),
            issuing_service_role,
            reference_sha256: Sha256Digest::compute(&[]),
        };
        reference.reference_sha256 = hash_domain_frames(
            SEALED_REFERENCE_DOMAIN,
            &[&canonical_json_bytes(&(
                &reference.api_version,
                reference.kind,
                &reference.origin_operation_id_sha256,
                &reference.origin_request_sha256,
                &reference.signed_receipt_sha256,
                &reference.trust_checkpoint_sha256,
                &reference.custody_slot_nonce_sha256,
                reference.issuing_service_role,
            ))
            .map_err(|_| {
                "sealed artifact reference is not canonical"
            })?],
        );
        reference.validate()?;
        Ok((reference, material))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionDispatchBindingV4 {
    pub(super) api_version: String,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
    pub(super) production_configuration_binding_sha256:
        Sha256Digest,
    pub(super) kernel_driver_identity_sha256: Sha256Digest,
    pub(super) retained_descriptor_set_sha256: Sha256Digest,
    pub(super) driver_generation_receipt_sha256: Sha256Digest,
    pub(super) opened_at_boottime_nanos: u64,
    pub(super) operation_deadline_boottime_nanos: u64,
    pub(super) cleanup_deadline_boottime_nanos: u64,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) binding_sha256: Sha256Digest,
}

impl ProductionDispatchBindingV4 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_verified_parent_permit(
        operation: PolicyCustodyOperation,
        operation_id_sha256: Sha256Digest,
        request_sha256: Sha256Digest,
        durable_request_sha256: Sha256Digest,
        termination_fence_sha256: Sha256Digest,
        production_configuration_binding_sha256: Sha256Digest,
        kernel_driver_identity_sha256: Sha256Digest,
        retained_descriptor_set_sha256: Sha256Digest,
        driver_generation_receipt_sha256: Sha256Digest,
        opened_at_boottime_nanos: u64,
        operation_deadline_boottime_nanos: u64,
        cleanup_deadline_boottime_nanos: u64,
    ) -> Result<Self, &'static str> {
        let replay_id_sha256 = hash_domain_frames(
            b"serverware.policyCustodyProductionReplay/v4",
            &[&canonical_json_bytes(&(
                operation,
                &operation_id_sha256,
                &request_sha256,
                &durable_request_sha256,
                &production_configuration_binding_sha256,
            ))
            .map_err(|_| "production replay identity is not canonical")?],
        );
        let mut binding = Self {
            api_version:
                PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            operation,
            operation_id_sha256,
            request_sha256,
            durable_request_sha256,
            termination_fence_sha256,
            production_configuration_binding_sha256,
            kernel_driver_identity_sha256,
            retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
            opened_at_boottime_nanos,
            operation_deadline_boottime_nanos,
            cleanup_deadline_boottime_nanos,
            replay_id_sha256,
            binding_sha256: Sha256Digest::compute(&[]),
        };
        binding.binding_sha256 = hash_domain_frames(
            DISPATCH_BINDING_DOMAIN,
            &[&canonical_json_bytes(&(
                &binding.api_version,
                binding.operation,
                &binding.operation_id_sha256,
                &binding.request_sha256,
                &binding.durable_request_sha256,
                &binding.termination_fence_sha256,
                &binding.production_configuration_binding_sha256,
                &binding.kernel_driver_identity_sha256,
                &binding.retained_descriptor_set_sha256,
                &binding.driver_generation_receipt_sha256,
                binding.opened_at_boottime_nanos,
                binding.operation_deadline_boottime_nanos,
                binding.cleanup_deadline_boottime_nanos,
                &binding.replay_id_sha256,
            ))
            .map_err(|_| {
                "production dispatch binding is not canonical"
            })?],
        );
        binding.validate(operation)?;
        Ok(binding)
    }

    fn validate(
        &self,
        expected_operation: PolicyCustodyOperation,
    ) -> Result<(), &'static str> {
        for digest in [
            &self.operation_id_sha256,
            &self.request_sha256,
            &self.durable_request_sha256,
            &self.termination_fence_sha256,
            &self.production_configuration_binding_sha256,
            &self.kernel_driver_identity_sha256,
            &self.retained_descriptor_set_sha256,
            &self.driver_generation_receipt_sha256,
            &self.replay_id_sha256,
            &self.binding_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || self.operation != expected_operation
            || self.opened_at_boottime_nanos == 0
            || self.opened_at_boottime_nanos
                >= self.operation_deadline_boottime_nanos
            || self.operation_deadline_boottime_nanos
                >= self.cleanup_deadline_boottime_nanos
        {
            return Err("production dispatch binding is invalid");
        }
        let expected = hash_domain_frames(
            DISPATCH_BINDING_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                self.operation,
                &self.operation_id_sha256,
                &self.request_sha256,
                &self.durable_request_sha256,
                &self.termination_fence_sha256,
                &self.production_configuration_binding_sha256,
                &self.kernel_driver_identity_sha256,
                &self.retained_descriptor_set_sha256,
                &self.driver_generation_receipt_sha256,
                self.opened_at_boottime_nanos,
                self.operation_deadline_boottime_nanos,
                self.cleanup_deadline_boottime_nanos,
                &self.replay_id_sha256,
            ))
            .map_err(|_| {
                "production dispatch binding is not canonical"
            })?],
        );
        if expected != self.binding_sha256 {
            return Err("production dispatch binding digest is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ClosedProductionDispatchRequestV4 {
    RecoverCurrentState {
        binding: ProductionDispatchBindingV4,
    },
    VerifyCheckpointSuccessor {
        binding: ProductionDispatchBindingV4,
        generation: CanonicalProductionArtifactV4,
        checkpoint_sequence: u64,
        previous_checkpoint_sha256: Sha256Digest,
        checkpoint_payload_sha256: Sha256Digest,
    },
    VerifyCurrentCheckpointHead {
        binding: ProductionDispatchBindingV4,
        generation: CanonicalProductionArtifactV4,
        checkpoint_sequence: u64,
        checkpoint_sha256: Sha256Digest,
    },
    VerifyObservationEvidence {
        binding: ProductionDispatchBindingV4,
        evidence_tuple: CanonicalProductionArtifactV4,
    },
    PrepareGenerationPublication {
        binding: ProductionDispatchBindingV4,
        recovered:
            SealedProductionArtifactReferenceV4,
        previous: Option<CanonicalProductionArtifactV4>,
        successor: CanonicalProductionArtifactV4,
    },
    CommitGenerationPublication {
        binding: ProductionDispatchBindingV4,
        prepared: CanonicalProductionArtifactV4,
    },
    AbortGenerationPublication {
        binding: ProductionDispatchBindingV4,
        prepared: CanonicalProductionArtifactV4,
    },
    BeginIngress {
        binding: ProductionDispatchBindingV4,
        request_binding_sha256: Sha256Digest,
    },
    ReserveSpoolAppend {
        binding: ProductionDispatchBindingV4,
        event: CanonicalProductionArtifactV4,
    },
    AppendSpoolEvent {
        binding: ProductionDispatchBindingV4,
        reservation:
            SealedProductionArtifactReferenceV4,
        event: CanonicalProductionArtifactV4,
    },
    CompactSpool {
        binding: ProductionDispatchBindingV4,
        request: CanonicalProductionArtifactV4,
    },
    CommitRequest {
        binding: ProductionDispatchBindingV4,
        facts: CanonicalProductionArtifactV4,
        context: CanonicalProductionArtifactV4,
    },
    AppendActiveEffectBarrier {
        binding: ProductionDispatchBindingV4,
        preparation: CanonicalProductionArtifactV4,
    },
    CommitActiveEffect {
        binding: ProductionDispatchBindingV4,
        effect_permit:
            SealedProductionArtifactReferenceV4,
        terminal_state: CanonicalProductionArtifactV4,
        result_sha256: Sha256Digest,
    },
    ReconcileActiveEffect {
        binding: ProductionDispatchBindingV4,
        generation_id: Sha256Digest,
        ingress_sequence: u64,
        effect_id_sha256: Sha256Digest,
    },
    AppendTerminal {
        binding: ProductionDispatchBindingV4,
        request: CanonicalProductionArtifactV4,
    },
    ConsumeAndPublishActivation {
        binding: ProductionDispatchBindingV4,
        transaction: CanonicalProductionArtifactV4,
    },
}

impl ClosedProductionDispatchRequestV4 {
    pub(super) fn operation(&self) -> PolicyCustodyOperation {
        match self {
            Self::RecoverCurrentState { .. } => {
                PolicyCustodyOperation::RecoverCurrentState
            }
            Self::VerifyCheckpointSuccessor { .. } => {
                PolicyCustodyOperation::VerifyCheckpointSuccessor
            }
            Self::VerifyCurrentCheckpointHead { .. } => {
                PolicyCustodyOperation::VerifyCurrentCheckpointHead
            }
            Self::VerifyObservationEvidence { .. } => {
                PolicyCustodyOperation::VerifyObservationEvidence
            }
            Self::PrepareGenerationPublication { .. } => {
                PolicyCustodyOperation::PrepareGenerationPublication
            }
            Self::CommitGenerationPublication { .. } => {
                PolicyCustodyOperation::CommitGenerationPublication
            }
            Self::AbortGenerationPublication { .. } => {
                PolicyCustodyOperation::AbortGenerationPublication
            }
            Self::BeginIngress { .. } => {
                PolicyCustodyOperation::BeginIngress
            }
            Self::ReserveSpoolAppend { .. } => {
                PolicyCustodyOperation::ReserveSpoolAppend
            }
            Self::AppendSpoolEvent { .. } => {
                PolicyCustodyOperation::AppendSpoolEvent
            }
            Self::CompactSpool { .. } => {
                PolicyCustodyOperation::CompactSpool
            }
            Self::CommitRequest { .. } => {
                PolicyCustodyOperation::CommitRequest
            }
            Self::AppendActiveEffectBarrier { .. } => {
                PolicyCustodyOperation::AppendActiveEffectBarrier
            }
            Self::CommitActiveEffect { .. } => {
                PolicyCustodyOperation::CommitActiveEffect
            }
            Self::ReconcileActiveEffect { .. } => {
                PolicyCustodyOperation::ReconcileActiveEffect
            }
            Self::AppendTerminal { .. } => {
                PolicyCustodyOperation::AppendTerminal
            }
            Self::ConsumeAndPublishActivation { .. } => {
                PolicyCustodyOperation::ConsumeAndPublishActivation
            }
        }
    }

    pub(super) fn binding(&self) -> &ProductionDispatchBindingV4 {
        match self {
            Self::RecoverCurrentState { binding }
            | Self::VerifyCheckpointSuccessor { binding, .. }
            | Self::VerifyCurrentCheckpointHead { binding, .. }
            | Self::VerifyObservationEvidence { binding, .. }
            | Self::PrepareGenerationPublication { binding, .. }
            | Self::CommitGenerationPublication { binding, .. }
            | Self::AbortGenerationPublication { binding, .. }
            | Self::BeginIngress { binding, .. }
            | Self::ReserveSpoolAppend { binding, .. }
            | Self::AppendSpoolEvent { binding, .. }
            | Self::CompactSpool { binding, .. }
            | Self::CommitRequest { binding, .. }
            | Self::AppendActiveEffectBarrier { binding, .. }
            | Self::CommitActiveEffect { binding, .. }
            | Self::ReconcileActiveEffect { binding, .. }
            | Self::AppendTerminal { binding, .. }
            | Self::ConsumeAndPublishActivation {
                binding, ..
            } => binding,
        }
    }

    pub(super) fn validate(
        &self,
    ) -> Result<Sha256Digest, &'static str> {
        let operation = self.operation();
        self.binding().validate(operation)?;
        validate_request_artifacts(self)?;
        let canonical = canonical_json_bytes(self)
            .map_err(|_| "production dispatch request is not canonical")?;
        if canonical.is_empty()
            || canonical.len() > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err(
                "production dispatch request exceeds its fixed byte bound",
            );
        }
        Ok(hash_domain_frames(
            DISPATCH_REQUEST_DOMAIN,
            &[canonical.as_slice()],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationPublicationTransactionWireV4 {
    transaction_sha256: Sha256Digest,
    activation_request_sha256: Sha256Digest,
    activation_request_id: Identifier,
    activation_replay_id: Identifier,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    readiness_envelope_sha256: Sha256Digest,
    readiness_payload_sha256: Sha256Digest,
    readiness_core_sha256: Sha256Digest,
    consumption: ActivationConsumptionBindingWireV4,
}

/// Data-only extraction after the same exact closed transaction validation.
pub(super) fn persistence_activation_transaction_sha256(artifact:&CanonicalProductionArtifactV4)->Result<Sha256Digest,&'static str>{
    if artifact.kind!=ProductionArtifactKindV4::ActivationPublicationTransaction {return Err("wrong activation artifact");}
    let bytes=artifact.exact_bytes()?;
    let wire:ActivationPublicationTransactionWireV4=serde_json::from_slice(&bytes).map_err(|_|"invalid activation original")?;
    wire.validate_exact(&bytes)?;Ok(wire.transaction_sha256)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ActivationConsumptionBindingWireV4 {
    NoExpansion {
        readiness_core_sha256: Sha256Digest,
        trust_checkpoint_id: Sha256Digest,
        trust_checkpoint_as_of_unix_nanos: i64,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        trusted_now_unix_nanos: i64,
        maximum_checkpoint_age_nanos: u64,
        expected_publication_revision: u64,
        expected_predecessor_policy_sha256: Sha256Digest,
        expected_predecessor_policy_sequence: u64,
        expected_predecessor_rollback_epoch: u64,
        candidate_policy_sha256: Sha256Digest,
        candidate_policy_sequence: u64,
        candidate_rollback_epoch: u64,
        activation_deadline_unix_nanos: i64,
    },
    ApprovedExpansion {
        approval_id: Sha256Digest,
        approval_envelope_sha256: Sha256Digest,
        approval_payload_sha256: Sha256Digest,
        readiness_core_sha256: Sha256Digest,
        trust_checkpoint_id: Sha256Digest,
        trust_checkpoint_as_of_unix_nanos: i64,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        trusted_now_unix_nanos: i64,
        maximum_checkpoint_age_nanos: u64,
        assertions: Vec<ActivationAssertionConsumptionWireV4>,
        expected_publication_revision: u64,
        expected_predecessor_policy_sha256: Sha256Digest,
        expected_predecessor_policy_sequence: u64,
        expected_predecessor_rollback_epoch: u64,
        candidate_policy_sha256: Sha256Digest,
        candidate_policy_sequence: u64,
        candidate_rollback_epoch: u64,
        activation_deadline_unix_nanos: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationAssertionConsumptionWireV4 {
    assertion_evidence_sha256: Sha256Digest,
    principal_id: Identifier,
    credential_id: Sha256Digest,
    assertion_object_sha256: Sha256Digest,
    authenticator_data_sha256: Sha256Digest,
    client_data_json_sha256: Sha256Digest,
    assertion_signature_sha256: Sha256Digest,
    cose_public_key_sha256: Sha256Digest,
    rp_id: Identifier,
    origin: CanonicalAscii,
    credential_state_revision: u64,
    previous_signature_counter: Option<u64>,
    signature_counter: u64,
    replay_state_sha256: Sha256Digest,
}

impl ActivationPublicationTransactionWireV4 {
    fn validate_exact(
        &self,
        exact: &[u8],
    ) -> Result<(), &'static str> {
        if canonical_json_bytes(self)
            .map_err(|_| "activation transaction is not canonical")?
            != exact
        {
            return Err(
                "activation transaction bytes are not exact canonical bytes",
            );
        }
        if self.activation_request_id == self.activation_replay_id
            || self.assignment_revision == 0
        {
            return Err(
                "activation request and replay identifiers must be distinct and the assignment revision must be positive",
            );
        }
        for digest in [
            &self.transaction_sha256,
            &self.activation_request_sha256,
            &self.assignment_sha256,
            &self.assignment_payload_sha256,
            &self.authority_key_independence_sha256,
            &self.readiness_envelope_sha256,
            &self.readiness_payload_sha256,
            &self.readiness_core_sha256,
        ] {
            require_digest(digest)?;
        }
        self.consumption
            .validate(&self.readiness_core_sha256)?;
        let expected = hash_domain_frames(
            ACTIVATION_TRANSACTION_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.activation_request_sha256,
                &self.activation_request_id,
                &self.activation_replay_id,
                &self.readiness_envelope_sha256,
                &self.readiness_payload_sha256,
                &self.readiness_core_sha256,
                &self.assignment_sha256,
                &self.assignment_payload_sha256,
                self.assignment_revision,
                &self.authority_key_independence_sha256,
                &self.consumption,
            ))
            .map_err(|_| {
                "activation transaction digest payload is not canonical"
            })?],
        );
        if self.transaction_sha256 != expected {
            return Err(
                "activation transaction digest does not bind its exact request and replay identifiers",
            );
        }
        Ok(())
    }
}

impl ActivationConsumptionBindingWireV4 {
    fn validate(
        &self,
        expected_readiness_core_sha256: &Sha256Digest,
    ) -> Result<(), &'static str> {
        let (
            readiness_core_sha256,
            trust_checkpoint_id,
            trust_checkpoint_as_of_unix_nanos,
            trust_revocation_generation,
            trust_revocation_root_sha256,
            trusted_now_unix_nanos,
            maximum_checkpoint_age_nanos,
            assertions,
            expected_publication_revision,
            expected_predecessor_policy_sha256,
            expected_predecessor_policy_sequence,
            expected_predecessor_rollback_epoch,
            candidate_policy_sha256,
            candidate_policy_sequence,
            candidate_rollback_epoch,
            activation_deadline_unix_nanos,
        ) = match self {
            Self::NoExpansion {
                readiness_core_sha256,
                trust_checkpoint_id,
                trust_checkpoint_as_of_unix_nanos,
                trust_revocation_generation,
                trust_revocation_root_sha256,
                trusted_now_unix_nanos,
                maximum_checkpoint_age_nanos,
                expected_publication_revision,
                expected_predecessor_policy_sha256,
                expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch,
                candidate_policy_sha256,
                candidate_policy_sequence,
                candidate_rollback_epoch,
                activation_deadline_unix_nanos,
            } => (
                readiness_core_sha256,
                trust_checkpoint_id,
                *trust_checkpoint_as_of_unix_nanos,
                *trust_revocation_generation,
                trust_revocation_root_sha256,
                *trusted_now_unix_nanos,
                *maximum_checkpoint_age_nanos,
                None,
                *expected_publication_revision,
                expected_predecessor_policy_sha256,
                *expected_predecessor_policy_sequence,
                *expected_predecessor_rollback_epoch,
                candidate_policy_sha256,
                *candidate_policy_sequence,
                *candidate_rollback_epoch,
                *activation_deadline_unix_nanos,
            ),
            Self::ApprovedExpansion {
                approval_id,
                approval_envelope_sha256,
                approval_payload_sha256,
                readiness_core_sha256,
                trust_checkpoint_id,
                trust_checkpoint_as_of_unix_nanos,
                trust_revocation_generation,
                trust_revocation_root_sha256,
                trusted_now_unix_nanos,
                maximum_checkpoint_age_nanos,
                assertions,
                expected_publication_revision,
                expected_predecessor_policy_sha256,
                expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch,
                candidate_policy_sha256,
                candidate_policy_sequence,
                candidate_rollback_epoch,
                activation_deadline_unix_nanos,
            } => {
                for digest in [
                    approval_id,
                    approval_envelope_sha256,
                    approval_payload_sha256,
                ] {
                    require_digest(digest)?;
                }
                if assertions.is_empty()
                    || assertions.len() > MAX_ACTIVATION_ASSERTIONS
                {
                    return Err(
                        "approved activation expansion assertion count is outside its fixed bound",
                    );
                }
                let mut assertion_ids = BTreeSet::new();
                for assertion in assertions {
                    assertion.validate()?;
                    if !assertion_ids.insert(
                        assertion.assertion_evidence_sha256.as_str(),
                    ) {
                        return Err(
                            "approved activation expansion repeats assertion evidence",
                        );
                    }
                }
                (
                    readiness_core_sha256,
                    trust_checkpoint_id,
                    *trust_checkpoint_as_of_unix_nanos,
                    *trust_revocation_generation,
                    trust_revocation_root_sha256,
                    *trusted_now_unix_nanos,
                    *maximum_checkpoint_age_nanos,
                    Some(assertions.as_slice()),
                    *expected_publication_revision,
                    expected_predecessor_policy_sha256,
                    *expected_predecessor_policy_sequence,
                    *expected_predecessor_rollback_epoch,
                    candidate_policy_sha256,
                    *candidate_policy_sequence,
                    *candidate_rollback_epoch,
                    *activation_deadline_unix_nanos,
                )
            }
        };
        for digest in [
            readiness_core_sha256,
            trust_checkpoint_id,
            trust_revocation_root_sha256,
            expected_predecessor_policy_sha256,
            candidate_policy_sha256,
        ] {
            require_digest(digest)?;
        }
        if readiness_core_sha256 != expected_readiness_core_sha256
            || trust_checkpoint_as_of_unix_nanos <= 0
            || trust_revocation_generation == 0
            || trusted_now_unix_nanos < trust_checkpoint_as_of_unix_nanos
            || maximum_checkpoint_age_nanos == 0
            || expected_publication_revision == 0
            || expected_predecessor_policy_sequence == 0
            || expected_predecessor_rollback_epoch == 0
            || candidate_policy_sequence
                <= expected_predecessor_policy_sequence
            || candidate_rollback_epoch == 0
            || candidate_policy_sha256
                == expected_predecessor_policy_sha256
            || activation_deadline_unix_nanos <= trusted_now_unix_nanos
            || assertions.is_some_and(|values| values.is_empty())
        {
            return Err(
                "activation consumption binding is incomplete or contradicts its transaction",
            );
        }
        Ok(())
    }
}

impl ActivationAssertionConsumptionWireV4 {
    fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.assertion_evidence_sha256,
            &self.credential_id,
            &self.assertion_object_sha256,
            &self.authenticator_data_sha256,
            &self.client_data_json_sha256,
            &self.assertion_signature_sha256,
            &self.cose_public_key_sha256,
            &self.replay_state_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.credential_state_revision == 0
            || self.signature_counter
                < self.previous_signature_counter.unwrap_or(0)
        {
            return Err(
                "activation assertion consumption revision or counter is invalid",
            );
        }
        Ok(())
    }
}

fn validate_request_artifacts(
    request: &ClosedProductionDispatchRequestV4,
) -> Result<(), &'static str> {
    let validate_artifact =
        |artifact: &CanonicalProductionArtifactV4,
         expected: ProductionArtifactKindV4| {
            if artifact.kind != expected {
                return Err("production artifact kind is incorrect");
            }
            artifact.exact_bytes().map(|_| ())
        };
    match request {
        ClosedProductionDispatchRequestV4::
            RecoverCurrentState { .. } => Ok(()),
        ClosedProductionDispatchRequestV4::
            VerifyCheckpointSuccessor {
                generation,
                checkpoint_sequence,
                previous_checkpoint_sha256,
                checkpoint_payload_sha256,
                ..
            } => {
                validate_artifact(
                    generation,
                    ProductionArtifactKindV4::
                        ShadowGenerationIdentity,
                )?;
                if *checkpoint_sequence == 0 {
                    return Err("checkpoint sequence is zero");
                }
                require_digest(previous_checkpoint_sha256)?;
                require_digest(checkpoint_payload_sha256)
            }
        ClosedProductionDispatchRequestV4::
            VerifyCurrentCheckpointHead {
                generation,
                checkpoint_sequence,
                checkpoint_sha256,
                ..
            } => {
                validate_artifact(
                    generation,
                    ProductionArtifactKindV4::
                        ShadowGenerationIdentity,
                )?;
                if *checkpoint_sequence == 0 {
                    return Err("checkpoint sequence is zero");
                }
                require_digest(checkpoint_sha256)
            }
        ClosedProductionDispatchRequestV4::
            VerifyObservationEvidence {
                evidence_tuple, ..
            } => validate_artifact(
                evidence_tuple,
                ProductionArtifactKindV4::ObservationEvidenceTuple,
            ),
        ClosedProductionDispatchRequestV4::
            PrepareGenerationPublication {
                recovered,
                previous,
                successor,
                ..
            } => {
                recovered.validate()?;
                if recovered.kind
                    != ProductionArtifactKindV4::
                        PublicationReconciliationReceipt
                {
                    return Err(
                        "recovered publication reference has the wrong kind",
                    );
                }
                if let Some(previous) = previous {
                    validate_artifact(
                        previous,
                        ProductionArtifactKindV4::
                            ShadowGenerationIdentity,
                    )?;
                }
                validate_artifact(
                    successor,
                    ProductionArtifactKindV4::
                        ShadowGenerationIdentity,
                )
            }
        ClosedProductionDispatchRequestV4::
            CommitGenerationPublication { prepared, .. }
        | ClosedProductionDispatchRequestV4::
            AbortGenerationPublication { prepared, .. } => {
                validate_artifact(
                    prepared,
                    ProductionArtifactKindV4::
                        PreparedGenerationPublication,
                )
            }
        ClosedProductionDispatchRequestV4::BeginIngress {
            request_binding_sha256,
            ..
        } => require_digest(request_binding_sha256),
        ClosedProductionDispatchRequestV4::
            ReserveSpoolAppend { event, .. } => validate_artifact(
                event,
                ProductionArtifactKindV4::ShadowSpoolEvent,
            ),
        ClosedProductionDispatchRequestV4::AppendSpoolEvent {
            reservation,
            event,
            ..
        } => {
            reservation.validate()?;
            if reservation.kind
                != ProductionArtifactKindV4::
                    SpoolAppendReservationOutcome
            {
                return Err(
                    "spool reservation reference has the wrong kind",
                );
            }
            validate_artifact(
                event,
                ProductionArtifactKindV4::ShadowSpoolEvent,
            )
        }
        ClosedProductionDispatchRequestV4::CompactSpool {
            request, ..
        } => validate_artifact(
            request,
            ProductionArtifactKindV4::
                AuthenticatedSpoolCompactionRequest,
        ),
        ClosedProductionDispatchRequestV4::CommitRequest {
            facts,
            context,
            ..
        } => {
            validate_artifact(
                facts,
                ProductionArtifactKindV4::ProtectedRequestFacts,
            )?;
            validate_artifact(
                context,
                ProductionArtifactKindV4::RequestCommitmentContext,
            )
        }
        ClosedProductionDispatchRequestV4::
            AppendActiveEffectBarrier { preparation, .. } => {
                validate_artifact(
                    preparation,
                    ProductionArtifactKindV4::
                        ActiveEffectPreparation,
                )
            }
        ClosedProductionDispatchRequestV4::CommitActiveEffect {
            effect_permit,
            terminal_state,
            result_sha256,
            ..
        } => {
            effect_permit.validate()?;
            if effect_permit.kind
                != ProductionArtifactKindV4::ActiveEffectPermit
            {
                return Err(
                    "active effect permit reference has the wrong kind",
                );
            }
            validate_artifact(
                terminal_state,
                ProductionArtifactKindV4::ActiveEffectCommitState,
            )?;
            require_digest(result_sha256)
        }
        ClosedProductionDispatchRequestV4::
            ReconcileActiveEffect {
                generation_id,
                ingress_sequence,
                effect_id_sha256,
                ..
            } => {
                if *ingress_sequence == 0 {
                    return Err("ingress sequence is zero");
                }
                require_digest(generation_id)?;
                require_digest(effect_id_sha256)
            }
        ClosedProductionDispatchRequestV4::AppendTerminal {
            request, ..
        } => validate_artifact(
            request,
            ProductionArtifactKindV4::TerminalSlotAppendRequest,
        ),
        ClosedProductionDispatchRequestV4::
            ConsumeAndPublishActivation {
                binding,
                transaction,
            } => {
                validate_artifact(
                    transaction,
                    ProductionArtifactKindV4::
                        ActivationPublicationTransaction,
                )?;
                let exact = transaction.exact_bytes()?;
                let decoded: ActivationPublicationTransactionWireV4 =
                    serde_json::from_slice(&exact).map_err(|_| {
                        "activation transaction has the wrong closed wire type"
                    })?;
                decoded.validate_exact(&exact)?;
                if decoded.transaction_sha256 != binding.request_sha256 {
                    return Err(
                        "activation transaction digest differs from the exact custody request binding",
                    );
                }
                Ok(())
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ClosedProductionDispatchResultV4 {
    Verified,
    Artifact(CanonicalProductionArtifactV4),
    SealedArtifact {
        reference: SealedProductionArtifactReferenceV4,
        exact_signed_artifact: SignedProductionArtifactMaterialV4,
    },
    Aborted {
        abort_evidence_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedProductionServiceTransitionV4 {
    pub(super) api_version: String,
    pub(super) service_role: HistoricalServiceRoleV3,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) predecessor_head_sha256: Sha256Digest,
    pub(super) resulting_head_sha256: Sha256Digest,
    pub(super) result_sha256: Sha256Digest,
    pub(super) completed_at_boottime_nanos: u64,
    pub(super) exact_canonical_payload_bytes: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
    pub(super) receipt_sha256: Sha256Digest,
}

impl SignedProductionServiceTransitionV4 {
    fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, &'static str> {
        canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            self.operation,
            &self.operation_id_sha256,
            &self.request_sha256,
            &self.durable_request_sha256,
            &self.replay_id_sha256,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            &self.result_sha256,
            self.completed_at_boottime_nanos,
        ))
        .map_err(|_| {
            "production service transition is not canonical"
        })
    }

    fn validate(
        &self,
        binding: &ProductionDispatchBindingV4,
        result_sha256: &Sha256Digest,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<(), &'static str> {
        self.validate_with_history(binding,result_sha256,|epoch,domain,payload,signature|{
            keyrings.history(self.service_role).verify_service_signature(epoch,domain,payload,signature)
                .map_err(|_|"production service transition signature is invalid or its epoch is not retained")
        })
    }

    pub(super) fn validate_with_history(&self,binding:&ProductionDispatchBindingV4,result_sha256:&Sha256Digest,
        verify:impl FnOnce(&AuthorityEpochRefV3,&[u8],&[u8],&str)->Result<(),&'static str>)->Result<(),&'static str> {
        for digest in [
            &self.operation_id_sha256,
            &self.request_sha256,
            &self.durable_request_sha256,
            &self.replay_id_sha256,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            &self.result_sha256,
            &self.receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || self.operation != binding.operation
            || self.operation_id_sha256
                != binding.operation_id_sha256
            || self.request_sha256 != binding.request_sha256
            || self.durable_request_sha256
                != binding.durable_request_sha256
            || self.replay_id_sha256 != binding.replay_id_sha256
            || self.predecessor_head_sha256
                == self.resulting_head_sha256
            || self.result_sha256 != *result_sha256
            || self.completed_at_boottime_nanos
                < binding.opened_at_boottime_nanos
            || self.completed_at_boottime_nanos
                >= binding.operation_deadline_boottime_nanos
            || self.signature_base64.is_empty()
            || self.signature_base64.len() > 128
            || self.exact_canonical_payload_bytes.is_empty()
            || self.exact_canonical_payload_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || self.exact_signed_envelope_bytes.is_empty()
            || self.exact_signed_envelope_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err(
                "production service transition differs from its exact dispatch",
            );
        }
        let payload = self.canonical_signature_payload()?;
        if self.exact_canonical_payload_bytes != payload {
            return Err(
                "production service transition payload bytes are not exact canonical bytes",
            );
        }
        verify(
                &self.authority_epoch,
                SERVICE_TRANSITION_DOMAIN,
                &payload,
                &self.signature_base64,
            )?;
        let expected_envelope = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            &self.exact_canonical_payload_bytes,
            &self.signature_base64,
        ))
        .map_err(|_| {
            "production service transition signed envelope is not canonical"
        })?;
        if self.exact_signed_envelope_bytes != expected_envelope {
            return Err(
                "production service transition signed-envelope bytes are not exact canonical bytes",
            );
        }
        let expected = hash_domain_frames(
            SERVICE_TRANSITION_RECEIPT_DOMAIN,
            &[self.exact_signed_envelope_bytes.as_slice()],
        );
        if expected != self.receipt_sha256 {
            return Err(
                "production service transition receipt digest is invalid",
            );
        }
        Ok(())
    }

    pub(super) fn sign(
        service_role: HistoricalServiceRoleV3,
        authority_epoch: AuthorityEpochRefV3,
        binding: &ProductionDispatchBindingV4,
        predecessor_head_sha256: Sha256Digest,
        result_sha256: Sha256Digest,
        completed_at_boottime_nanos: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, &'static str> {
        require_digest(&predecessor_head_sha256)?;
        require_digest(&result_sha256)?;
        let resulting_head_sha256 = hash_domain_frames(
            b"serverware.policyCustodyProductionServiceHead/v4",
            &[&canonical_json_bytes(&(
                service_role,
                &authority_epoch,
                &predecessor_head_sha256,
                binding.operation,
                &binding.operation_id_sha256,
                &binding.request_sha256,
                &binding.durable_request_sha256,
                &binding.replay_id_sha256,
                &result_sha256,
                completed_at_boottime_nanos,
            ))
            .map_err(|_| {
                "production service head is not canonical"
            })?],
        );
        let mut transition = Self {
            api_version: PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            service_role,
            authority_epoch,
            operation: binding.operation,
            operation_id_sha256: binding.operation_id_sha256.clone(),
            request_sha256: binding.request_sha256.clone(),
            durable_request_sha256:
                binding.durable_request_sha256.clone(),
            replay_id_sha256: binding.replay_id_sha256.clone(),
            predecessor_head_sha256,
            resulting_head_sha256,
            result_sha256,
            completed_at_boottime_nanos,
            exact_canonical_payload_bytes: Vec::new(),
            signature_base64: String::new(),
            exact_signed_envelope_bytes: Vec::new(),
            receipt_sha256: Sha256Digest::compute(&[]),
        };
        transition.exact_canonical_payload_bytes =
            transition.canonical_signature_payload()?;
        let preimage = super::protocol::
            domain_separated_signature_preimage(
                SERVICE_TRANSITION_DOMAIN,
                &transition.exact_canonical_payload_bytes,
            )
            .map_err(|_| {
                "production service transition signature preimage is invalid"
            })?;
        transition.signature_base64 = URL_SAFE_NO_PAD.encode(
            signing_key.sign(&preimage).to_bytes(),
        );
        transition.exact_signed_envelope_bytes = canonical_json_bytes(&(
            &transition.api_version,
            transition.service_role,
            &transition.authority_epoch,
            &transition.exact_canonical_payload_bytes,
            &transition.signature_base64,
        ))
        .map_err(|_| {
            "production service transition envelope is not canonical"
        })?;
        transition.receipt_sha256 = hash_domain_frames(
            SERVICE_TRANSITION_RECEIPT_DOMAIN,
            &[transition.exact_signed_envelope_bytes.as_slice()],
        );
        Ok(transition)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ClosedProductionDispatchResponseV4 {
    pub(super) api_version: String,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) result: ClosedProductionDispatchResultV4,
    pub(super) result_sha256: Sha256Digest,
    pub(super) service_transitions:
        Vec<SignedProductionServiceTransitionV4>,
    pub(super) response_sha256: Sha256Digest,
}

impl ClosedProductionDispatchResponseV4 {
    pub(super) fn from_parts(
        request: &ClosedProductionDispatchRequestV4,
        result: ClosedProductionDispatchResultV4,
        service_transitions: Vec<SignedProductionServiceTransitionV4>,
    ) -> Result<Self, &'static str> {
        let binding = request.binding();
        let result_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(&result)
                .map_err(|_| "production dispatch result is not canonical")?,
        );
        if service_transitions.iter().any(|transition| {
            transition.result_sha256 != result_sha256
        }) {
            return Err(
                "production service transition differs from the final result digest",
            );
        }
        let mut response = Self {
            api_version: PRODUCTION_DISPATCH_PROTOCOL_VERSION.to_owned(),
            operation: request.operation(),
            operation_id_sha256: binding.operation_id_sha256.clone(),
            request_sha256: binding.request_sha256.clone(),
            replay_id_sha256: binding.replay_id_sha256.clone(),
            result,
            result_sha256,
            service_transitions,
            response_sha256: Sha256Digest::compute(&[]),
        };
        response.response_sha256 = hash_domain_frames(
            DISPATCH_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&(
                &response.api_version,
                response.operation,
                &response.operation_id_sha256,
                &response.request_sha256,
                &response.replay_id_sha256,
                &response.result_sha256,
                &response.service_transitions,
            ))
            .map_err(|_| {
                "production dispatch response is not canonical"
            })?],
        );
        Ok(response)
    }

    pub(super) fn validate(
        &self,
        request: &ClosedProductionDispatchRequestV4,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<(), &'static str> {
        let binding = request.binding();
        if self.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || self.operation != request.operation()
            || self.operation_id_sha256
                != binding.operation_id_sha256
            || self.request_sha256 != binding.request_sha256
            || self.replay_id_sha256 != binding.replay_id_sha256
            || self.service_transitions.is_empty()
            || self.service_transitions.len()
                > MAX_PRODUCTION_DISPATCH_RECEIPTS
        {
            return Err(
                "production dispatch response differs from its exact request",
            );
        }
        validate_dispatch_result(
            self.operation,
            &self.result,
            binding,
            keyrings,
        )?;
        let exact_result = canonical_json_bytes(&self.result)
            .map_err(|_| "production dispatch result is not canonical")?;
        if Sha256Digest::compute(&exact_result) != self.result_sha256 {
            return Err("production dispatch result digest is invalid");
        }
        let expected_roles = required_service_roles(self.operation);
        let mut roles = BTreeSet::new();
        for transition in &self.service_transitions {
            if !roles.insert(transition.service_role) {
                return Err(
                    "production dispatch response repeats a service role",
                );
            }
            transition.validate(
                binding,
                &self.result_sha256,
                keyrings,
            )?;
        }
        if roles != expected_roles {
            return Err(
                "production dispatch response omits an exact required service role",
            );
        }
        let expected_response = hash_domain_frames(
            DISPATCH_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                self.operation,
                &self.operation_id_sha256,
                &self.request_sha256,
                &self.replay_id_sha256,
                &self.result_sha256,
                &self.service_transitions,
            ))
            .map_err(|_| {
                "production dispatch response is not canonical"
            })?],
        );
        if expected_response != self.response_sha256 {
            return Err(
                "production dispatch response digest is invalid",
            );
        }
        Ok(())
    }
}

fn validate_dispatch_result(
    operation: PolicyCustodyOperation,
    result: &ClosedProductionDispatchResultV4,
    binding: &ProductionDispatchBindingV4,
    keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
) -> Result<(), &'static str> {
    let expected_artifact = match operation {
        PolicyCustodyOperation::RecoverCurrentState
        | PolicyCustodyOperation::CommitGenerationPublication => {
            Some((
                true,
                ProductionArtifactKindV4::
                    PublicationReconciliationReceipt,
            ))
        }
        PolicyCustodyOperation::PrepareGenerationPublication => {
            Some((
                false,
                ProductionArtifactKindV4::
                    PreparedGenerationPublication,
            ))
        }
        PolicyCustodyOperation::BeginIngress => Some((
            false,
            ProductionArtifactKindV4::IngressCustodyAdmission,
        )),
        PolicyCustodyOperation::ReserveSpoolAppend => Some((
            true,
            ProductionArtifactKindV4::
                SpoolAppendReservationOutcome,
        )),
        PolicyCustodyOperation::AppendSpoolEvent => Some((
            false,
            ProductionArtifactKindV4::ShadowSpillReceipt,
        )),
        PolicyCustodyOperation::CompactSpool => Some((
            false,
            ProductionArtifactKindV4::SpoolCompactionReceipt,
        )),
        PolicyCustodyOperation::CommitRequest => Some((
            false,
            ProductionArtifactKindV4::RequestCommitment,
        )),
        PolicyCustodyOperation::AppendActiveEffectBarrier => {
            Some((
                true,
                ProductionArtifactKindV4::ActiveEffectPermit,
            ))
        }
        PolicyCustodyOperation::CommitActiveEffect
        | PolicyCustodyOperation::ReconcileActiveEffect => Some((
            false,
            ProductionArtifactKindV4::ActiveEffectCommitReceipt,
        )),
        PolicyCustodyOperation::AppendTerminal => Some((
            false,
            ProductionArtifactKindV4::TerminalSlotAppendOutcome,
        )),
        PolicyCustodyOperation::ConsumeAndPublishActivation => {
            Some((
                false,
                ProductionArtifactKindV4::
                    ActivationPublicationReceipt,
            ))
        }
        PolicyCustodyOperation::VerifyCheckpointSuccessor
        | PolicyCustodyOperation::VerifyCurrentCheckpointHead
        | PolicyCustodyOperation::VerifyObservationEvidence
        | PolicyCustodyOperation::AbortGenerationPublication => None,
    };
    match (expected_artifact, result) {
        (None, ClosedProductionDispatchResultV4::Verified) => Ok(()),
        (
            Some((false, expected_kind)),
            ClosedProductionDispatchResultV4::Artifact(artifact),
        ) if artifact.kind == expected_kind => {
            artifact.exact_bytes().map(|_| ())
        }
        (
            Some((true, expected_kind)),
            ClosedProductionDispatchResultV4::SealedArtifact {
                reference,
                exact_signed_artifact,
            },
        ) if reference.kind == expected_kind
            && exact_signed_artifact.kind == expected_kind => {
            reference.validate()?;
            exact_signed_artifact.validate(
                reference,
                binding,
                expected_kind,
                sealed_artifact_issuing_role(operation),
                keyrings,
            )
        }
        (
            None,
            ClosedProductionDispatchResultV4::Aborted {
                abort_evidence_sha256,
            },
        ) if operation
            == PolicyCustodyOperation::AbortGenerationPublication => {
            require_digest(abort_evidence_sha256)
        }
        _ => Err(
            "production dispatch result variant or artifact kind does not match its operation",
        ),
    }
}

fn sealed_artifact_issuing_role(
    operation: PolicyCustodyOperation,
) -> HistoricalServiceRoleV3 {
    match operation {
        PolicyCustodyOperation::AppendActiveEffectBarrier => {
            HistoricalServiceRoleV3::CleanupAuthorizationConsumer
        }
        PolicyCustodyOperation::RecoverCurrentState
        | PolicyCustodyOperation::CommitGenerationPublication
        | PolicyCustodyOperation::ReserveSpoolAppend => {
            HistoricalServiceRoleV3::DurableRecoveryStore
        }
        _ => HistoricalServiceRoleV3::CurrentSignatureAuthority,
    }
}

pub(super) fn required_service_roles(
    operation: PolicyCustodyOperation,
) -> BTreeSet<HistoricalServiceRoleV3> {
    let mut roles = BTreeSet::from([
        HistoricalServiceRoleV3::DurableRecoveryStore,
        HistoricalServiceRoleV3::CurrentSignatureAuthority,
    ]);
    if matches!(
        operation,
        PolicyCustodyOperation::AppendActiveEffectBarrier
            | PolicyCustodyOperation::CommitActiveEffect
            | PolicyCustodyOperation::ReconcileActiveEffect
            | PolicyCustodyOperation::ConsumeAndPublishActivation
    ) {
        roles.insert(
            HistoricalServiceRoleV3::
                CleanupAuthorizationConsumer,
        );
    }
    roles
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "transition",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ClosedProductionGenerationRequestV4 {
    Recover {
        transition_id_sha256: Sha256Digest,
        previous_configuration_binding_sha256:
            Option<Sha256Digest>,
        successor_configuration_binding_sha256: Sha256Digest,
        dispatch_manifest_sha256: Sha256Digest,
        kernel_driver_identity_sha256: Sha256Digest,
        retained_descriptor_set_sha256: Sha256Digest,
        driver_generation_receipt_sha256: Sha256Digest,
        install_context: ProductionGenerationInstallContextWireV4,
        deadline_boottime_nanos: u64,
        replay_id_sha256: Sha256Digest,
    },
    Prepare {
        transition_id_sha256: Sha256Digest,
        previous_configuration_binding_sha256:
            Option<Sha256Digest>,
        successor_configuration_binding_sha256: Sha256Digest,
        dispatch_manifest_sha256: Sha256Digest,
        kernel_driver_identity_sha256: Sha256Digest,
        retained_descriptor_set_sha256: Sha256Digest,
        driver_generation_receipt_sha256: Sha256Digest,
        install_context: ProductionGenerationInstallContextWireV4,
        deadline_boottime_nanos: u64,
        replay_id_sha256: Sha256Digest,
    },
    Commit {
        transition_id_sha256: Sha256Digest,
        preparation_receipt_sha256: Sha256Digest,
        deadline_boottime_nanos: u64,
        replay_id_sha256: Sha256Digest,
    },
    Abort {
        transition_id_sha256: Sha256Digest,
        preparation_receipt_sha256: Sha256Digest,
        deadline_boottime_nanos: u64,
        replay_id_sha256: Sha256Digest,
    },
}

/// Successor-owned values that cannot be reconstructed from generation
/// digests. The facade derives this from the already verified production
/// configuration; services bind it into prepare/recover and the exact signed
/// parent installation envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionGenerationInstallContextWireV4 {
    pub(super) assignment_id: Sha256Digest,
    pub(super) assignment_payload_sha256: Sha256Digest,
    pub(super) assignment_revision: u64,
    pub(super) operation_coverage_root_sha256: Sha256Digest,
    pub(super) five_service_protocol_set_sha256: Sha256Digest,
    pub(super) envelope_authority_role:
        ProductionGenerationInstallEnvelopeRoleV4,
    pub(super) envelope_authority_key_id: Sha256Digest,
    pub(super) envelope_authority_key_spki_sha256: Sha256Digest,
    pub(super) trusted_time_checkpoint_sha256: Sha256Digest,
    pub(super) trusted_time_revocation_generation: u64,
    pub(super) trusted_time_revocation_root_sha256: Sha256Digest,
    pub(super) issued_at_unix_nanos: i64,
    pub(super) expires_at_unix_nanos: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProductionGenerationInstallEnvelopeRoleV4 {
    CustodyResultEnvelope,
}

impl ProductionGenerationInstallContextWireV4 {
    fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.assignment_id,
            &self.assignment_payload_sha256,
            &self.operation_coverage_root_sha256,
            &self.five_service_protocol_set_sha256,
            &self.envelope_authority_key_id,
            &self.envelope_authority_key_spki_sha256,
            &self.trusted_time_checkpoint_sha256,
            &self.trusted_time_revocation_root_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.assignment_revision == 0
            || self.trusted_time_revocation_generation == 0
            || self.envelope_authority_role
                != ProductionGenerationInstallEnvelopeRoleV4::CustodyResultEnvelope
            || self.issued_at_unix_nanos <= 0
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err("generation install context is incomplete or uses the wrong parent authority");
        }
        Ok(())
    }
}

impl ClosedProductionGenerationRequestV4 {
    pub(super) fn transition(
        &self,
    ) -> ProductionGenerationTransitionV4 {
        match self {
            Self::Recover { .. } => {
                ProductionGenerationTransitionV4::Recover
            }
            Self::Prepare { .. } => {
                ProductionGenerationTransitionV4::Prepare
            }
            Self::Commit { .. } => {
                ProductionGenerationTransitionV4::Commit
            }
            Self::Abort { .. } => {
                ProductionGenerationTransitionV4::Abort
            }
        }
    }

    pub(super) fn transition_id_sha256(&self) -> &Sha256Digest {
        match self {
            Self::Recover {
                transition_id_sha256,
                ..
            }
            | Self::Prepare {
                transition_id_sha256,
                ..
            }
            | Self::Commit {
                transition_id_sha256,
                ..
            }
            | Self::Abort {
                transition_id_sha256,
                ..
            } => transition_id_sha256,
        }
    }

    pub(super) fn replay_id_sha256(&self) -> &Sha256Digest {
        match self {
            Self::Recover {
                replay_id_sha256,
                ..
            }
            | Self::Prepare {
                replay_id_sha256,
                ..
            }
            | Self::Commit {
                replay_id_sha256,
                ..
            }
            | Self::Abort {
                replay_id_sha256,
                ..
            } => replay_id_sha256,
        }
    }

    pub(super) fn deadline_boottime_nanos(&self) -> u64 {
        match self {
            Self::Recover {
                deadline_boottime_nanos,
                ..
            }
            | Self::Prepare {
                deadline_boottime_nanos,
                ..
            }
            | Self::Commit {
                deadline_boottime_nanos,
                ..
            }
            | Self::Abort {
                deadline_boottime_nanos,
                ..
            } => *deadline_boottime_nanos,
        }
    }

    pub(super) fn request_sha256(
        &self,
    ) -> Result<Sha256Digest, &'static str> {
        require_digest(self.transition_id_sha256())?;
        require_digest(self.replay_id_sha256())?;
        if self.deadline_boottime_nanos() == 0 {
            return Err("generation request deadline is zero");
        }
        match self {
            Self::Recover {
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                install_context,
                ..
            }
            | Self::Prepare {
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                install_context,
                ..
            } => {
                if let Some(previous) =
                    previous_configuration_binding_sha256
                {
                    require_digest(previous)?;
                }
                for digest in [
                    successor_configuration_binding_sha256,
                    dispatch_manifest_sha256,
                    kernel_driver_identity_sha256,
                    retained_descriptor_set_sha256,
                    driver_generation_receipt_sha256,
                ] {
                    require_digest(digest)?;
                }
                install_context.validate()?;
            }
            Self::Commit {
                preparation_receipt_sha256,
                ..
            }
            | Self::Abort {
                preparation_receipt_sha256,
                ..
            } => require_digest(preparation_receipt_sha256)?,
        }
        let canonical = canonical_json_bytes(self)
            .map_err(|_| "generation request is not canonical")?;
        if canonical.is_empty()
            || canonical.len() > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err("generation request exceeds its fixed bound");
        }
        Ok(hash_domain_frames(
            GENERATION_REQUEST_DOMAIN,
            &[PRODUCTION_GENERATION_PROTOCOL_VERSION.as_bytes(), &canonical],
        ))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProductionGenerationTransitionV4 {
    Recover,
    Prepare,
    Commit,
    Abort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedProductionGenerationServiceTransitionV4 {
    pub(super) api_version: String,
    pub(super) service_role: HistoricalServiceRoleV3,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) transition: ProductionGenerationTransitionV4,
    pub(super) transition_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) predecessor_head_sha256: Sha256Digest,
    pub(super) resulting_head_sha256: Sha256Digest,
    pub(super) result_sha256: Sha256Digest,
    pub(super) completed_at_boottime_nanos: u64,
    pub(super) exact_canonical_payload_bytes: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
    pub(super) receipt_sha256: Sha256Digest,
}

impl SignedProductionGenerationServiceTransitionV4 {
    fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, &'static str> {
        canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            self.transition,
            &self.transition_id_sha256,
            &self.request_sha256,
            &self.replay_id_sha256,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            &self.result_sha256,
            self.completed_at_boottime_nanos,
        ))
        .map_err(|_| {
            "generation service transition is not canonical"
        })
    }

    fn validate(
        &self,
        request: &ClosedProductionGenerationRequestV4,
        request_sha256: &Sha256Digest,
        result_sha256: &Sha256Digest,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<(), &'static str> {
        self.validate_service(request,request_sha256,result_sha256,keyrings.history(self.service_role))
    }

    pub(super) fn validate_service(
        &self,
        request:&ClosedProductionGenerationRequestV4,
        request_sha256:&Sha256Digest,
        result_sha256:&Sha256Digest,
        history:&RuntimeAuthorityHistory,
    )->Result<(),&'static str> {
        if history.authority_role()!=HistoricalAuthorityRoleV3::IsolatedService(self.service_role) {
            return Err("generation certificate history role differs");
        }
        for digest in [
            &self.transition_id_sha256,
            &self.request_sha256,
            &self.replay_id_sha256,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            &self.result_sha256,
            &self.receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version
                != PRODUCTION_GENERATION_PROTOCOL_VERSION
            || self.transition != request.transition()
            || self.transition_id_sha256
                != *request.transition_id_sha256()
            || self.request_sha256 != *request_sha256
            || self.replay_id_sha256
                != *request.replay_id_sha256()
            || self.predecessor_head_sha256
                == self.resulting_head_sha256
            || self.result_sha256 != *result_sha256
            || self.completed_at_boottime_nanos == 0
            || self.completed_at_boottime_nanos
                >= request.deadline_boottime_nanos()
            || self.signature_base64.is_empty()
            || self.signature_base64.len() > 128
            || self.exact_canonical_payload_bytes.is_empty()
            || self.exact_canonical_payload_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || self.exact_signed_envelope_bytes.is_empty()
            || self.exact_signed_envelope_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
        {
            return Err(
                "generation service transition differs from its exact request",
            );
        }
        let payload = self.canonical_signature_payload()?;
        if self.exact_canonical_payload_bytes != payload {
            return Err(
                "generation service transition payload bytes are not exact canonical bytes",
            );
        }
        history.verify_service_signature(
                &self.authority_epoch,
                GENERATION_SERVICE_TRANSITION_DOMAIN,
                &payload,
                &self.signature_base64,
            )
            .map_err(|_| {
                "generation service transition signature is invalid or its epoch is not retained"
            })?;
        let expected_envelope = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            &self.exact_canonical_payload_bytes,
            &self.signature_base64,
        ))
        .map_err(|_| {
            "generation service transition signed envelope is not canonical"
        })?;
        if self.exact_signed_envelope_bytes != expected_envelope {
            return Err(
                "generation service transition signed-envelope bytes are not exact canonical bytes",
            );
        }
        let expected = hash_domain_frames(
            GENERATION_SERVICE_TRANSITION_RECEIPT_DOMAIN,
            &[self.exact_signed_envelope_bytes.as_slice()],
        );
        if expected != self.receipt_sha256 {
            return Err(
                "generation service transition receipt digest is invalid",
            );
        }
        Ok(())
    }

    pub(super) fn sign(
        service_role: HistoricalServiceRoleV3,
        authority_epoch: AuthorityEpochRefV3,
        request: &ClosedProductionGenerationRequestV4,
        predecessor_head_sha256: Sha256Digest,
        result_binding_sha256: Sha256Digest,
        completed_at_boottime_nanos: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, &'static str> {
        let request_sha256 = request.request_sha256()?;
        require_digest(&predecessor_head_sha256)?;
        require_digest(&result_binding_sha256)?;
        let resulting_head_sha256 = hash_domain_frames(
            b"serverware.policyCustodyProductionGenerationServiceHead/v4",
            &[&canonical_json_bytes(&(
                service_role,
                &authority_epoch,
                &predecessor_head_sha256,
                request.transition(),
                request.transition_id_sha256(),
                &request_sha256,
                request.replay_id_sha256(),
                &result_binding_sha256,
                completed_at_boottime_nanos,
            ))
            .map_err(|_| {
                "generation service head is not canonical"
            })?],
        );
        let mut transition = Self {
            api_version: PRODUCTION_GENERATION_PROTOCOL_VERSION.to_owned(),
            service_role,
            authority_epoch,
            transition: request.transition(),
            transition_id_sha256:
                request.transition_id_sha256().clone(),
            request_sha256,
            replay_id_sha256: request.replay_id_sha256().clone(),
            predecessor_head_sha256,
            resulting_head_sha256,
            result_sha256: result_binding_sha256,
            completed_at_boottime_nanos,
            exact_canonical_payload_bytes: Vec::new(),
            signature_base64: String::new(),
            exact_signed_envelope_bytes: Vec::new(),
            receipt_sha256: Sha256Digest::compute(&[]),
        };
        transition.exact_canonical_payload_bytes =
            transition.canonical_signature_payload()?;
        let preimage = super::protocol::
            domain_separated_signature_preimage(
                GENERATION_SERVICE_TRANSITION_DOMAIN,
                &transition.exact_canonical_payload_bytes,
            )
            .map_err(|_| {
                "generation service transition signature preimage is invalid"
            })?;
        transition.signature_base64 = URL_SAFE_NO_PAD.encode(
            signing_key.sign(&preimage).to_bytes(),
        );
        transition.exact_signed_envelope_bytes = canonical_json_bytes(&(
            &transition.api_version,
            transition.service_role,
            &transition.authority_epoch,
            &transition.exact_canonical_payload_bytes,
            &transition.signature_base64,
        ))
        .map_err(|_| {
            "generation service transition envelope is not canonical"
        })?;
        transition.receipt_sha256 = hash_domain_frames(
            GENERATION_SERVICE_TRANSITION_RECEIPT_DOMAIN,
            &[transition.exact_signed_envelope_bytes.as_slice()],
        );
        Ok(transition)
    }
}

pub(super) fn generation_service_result_binding_sha256(
    request: &ClosedProductionGenerationRequestV4,
    final_result_sha256: Option<&Sha256Digest>,
) -> Result<Sha256Digest, &'static str> {
    match request.transition() {
        ProductionGenerationTransitionV4::Recover
        | ProductionGenerationTransitionV4::Prepare => Ok(
            hash_domain_frames(
                b"serverware.policyCustodyProductionGenerationPrepareIntent/v4",
                &[&canonical_json_bytes(&(
                    request.transition(),
                    request.transition_id_sha256(),
                    request.request_sha256()?,
                    request.replay_id_sha256(),
                ))
                .map_err(|_| {
                    "generation prepare intent is not canonical"
                })?],
            ),
        ),
        ProductionGenerationTransitionV4::Commit
        | ProductionGenerationTransitionV4::Abort => final_result_sha256
            .cloned()
            .ok_or(
                "generation commit or abort requires its final result digest",
            ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ClosedProductionGenerationResponseV4 {
    pub(super) api_version: String,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) result: CanonicalProductionArtifactV4,
    pub(super) service_transitions:
        Vec<SignedProductionGenerationServiceTransitionV4>,
    pub(super) response_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionGenerationPreparationResultWireV4 {
    pub(super) transition_id_sha256: Sha256Digest,
    pub(super) previous_configuration_binding_sha256:
        Option<Sha256Digest>,
    pub(super) successor_configuration_binding_sha256:
        Sha256Digest,
    pub(super) dispatch_manifest_sha256: Sha256Digest,
    pub(super) kernel_driver_identity_sha256: Sha256Digest,
    pub(super) retained_descriptor_set_sha256: Sha256Digest,
    pub(super) driver_generation_receipt_sha256: Sha256Digest,
    pub(super) durable_recovery_store_prepare_receipt_sha256:
        Sha256Digest,
    pub(super) cleanup_authorization_prepare_receipt_sha256:
        Sha256Digest,
    pub(super) recovery_target_prepare_receipt_sha256:
        Sha256Digest,
    pub(super) bounded_cleanup_prepare_receipt_sha256:
        Sha256Digest,
    pub(super) current_signature_prepare_receipt_sha256:
        Sha256Digest,
    pub(super) durable_intent_receipt_sha256: Sha256Digest,
    pub(super) prepared_at_boottime_nanos: u64,
    pub(super) commit_deadline_boottime_nanos: u64,
}

impl ProductionGenerationPreparationResultWireV4 {
    pub(super) fn from_signed_transitions(
        request: &ClosedProductionGenerationRequestV4,
        transitions: &[SignedProductionGenerationServiceTransitionV4],
        prepared_at_boottime_nanos: u64,
    ) -> Result<Self, &'static str> {
        let (
            previous_configuration_binding_sha256,
            successor_configuration_binding_sha256,
            dispatch_manifest_sha256,
            kernel_driver_identity_sha256,
            retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
        ) = match request {
            ClosedProductionGenerationRequestV4::Recover {
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                ..
            }
            | ClosedProductionGenerationRequestV4::Prepare {
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                ..
            } => (
                previous_configuration_binding_sha256.clone(),
                successor_configuration_binding_sha256.clone(),
                dispatch_manifest_sha256.clone(),
                kernel_driver_identity_sha256.clone(),
                retained_descriptor_set_sha256.clone(),
                driver_generation_receipt_sha256.clone(),
            ),
            _ => {
                return Err(
                    "generation preparation requires recover or prepare",
                )
            }
        };
        let receipt = |role| {
            transitions
                .iter()
                .find(|transition| transition.service_role == role)
                .map(|transition| transition.receipt_sha256.clone())
                .ok_or("generation preparation is missing a service receipt")
        };
        let durable_recovery_store_prepare_receipt_sha256 = receipt(
            HistoricalServiceRoleV3::DurableRecoveryStore,
        )?;
        let cleanup_authorization_prepare_receipt_sha256 = receipt(
            HistoricalServiceRoleV3::CleanupAuthorizationConsumer,
        )?;
        let recovery_target_prepare_receipt_sha256 = receipt(
            HistoricalServiceRoleV3::RecoveryTargetProvider,
        )?;
        let bounded_cleanup_prepare_receipt_sha256 = receipt(
            HistoricalServiceRoleV3::BoundedCleanupHelper,
        )?;
        let current_signature_prepare_receipt_sha256 = receipt(
            HistoricalServiceRoleV3::CurrentSignatureAuthority,
        )?;
        let durable_intent_receipt_sha256 = hash_domain_frames(
            b"serverware.policyCustodyProductionGenerationDurableIntent/v4",
            &[&canonical_json_bytes(&(
                request.transition_id_sha256(),
                request.request_sha256()?,
                request.replay_id_sha256(),
                &durable_recovery_store_prepare_receipt_sha256,
                &cleanup_authorization_prepare_receipt_sha256,
                &recovery_target_prepare_receipt_sha256,
                &bounded_cleanup_prepare_receipt_sha256,
                &current_signature_prepare_receipt_sha256,
            ))
            .map_err(|_| {
                "generation durable intent is not canonical"
            })?],
        );
        let preparation = Self {
            transition_id_sha256:
                request.transition_id_sha256().clone(),
            previous_configuration_binding_sha256,
            successor_configuration_binding_sha256,
            dispatch_manifest_sha256,
            kernel_driver_identity_sha256,
            retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
            durable_recovery_store_prepare_receipt_sha256,
            cleanup_authorization_prepare_receipt_sha256,
            recovery_target_prepare_receipt_sha256,
            bounded_cleanup_prepare_receipt_sha256,
            current_signature_prepare_receipt_sha256,
            durable_intent_receipt_sha256,
            prepared_at_boottime_nanos,
            commit_deadline_boottime_nanos:
                request.deadline_boottime_nanos(),
        };
        preparation.validate_for_request(request)?;
        Ok(preparation)
    }

    pub(super) fn validate_for_request(
        &self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<(), &'static str> {
        for digest in [
            &self.transition_id_sha256,
            &self.successor_configuration_binding_sha256,
            &self.dispatch_manifest_sha256,
            &self.kernel_driver_identity_sha256,
            &self.retained_descriptor_set_sha256,
            &self.driver_generation_receipt_sha256,
            &self.durable_recovery_store_prepare_receipt_sha256,
            &self.cleanup_authorization_prepare_receipt_sha256,
            &self.recovery_target_prepare_receipt_sha256,
            &self.bounded_cleanup_prepare_receipt_sha256,
            &self.current_signature_prepare_receipt_sha256,
            &self.durable_intent_receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if let Some(previous) =
            &self.previous_configuration_binding_sha256
        {
            require_digest(previous)?;
        }
        let (
            transition_id_sha256,
            previous_configuration_binding_sha256,
            successor_configuration_binding_sha256,
            dispatch_manifest_sha256,
            kernel_driver_identity_sha256,
            retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
        ) = match request {
            ClosedProductionGenerationRequestV4::Recover {
                transition_id_sha256,
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                ..
            }
            | ClosedProductionGenerationRequestV4::Prepare {
                transition_id_sha256,
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
                ..
            } => (
                transition_id_sha256,
                previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,
                dispatch_manifest_sha256,
                kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,
            ),
            _ => {
                return Err(
                    "generation preparation material is not valid for commit or abort",
                )
            }
        };
        if self.transition_id_sha256 != *transition_id_sha256
            || self.previous_configuration_binding_sha256
                != *previous_configuration_binding_sha256
            || self.successor_configuration_binding_sha256
                != *successor_configuration_binding_sha256
            || self.dispatch_manifest_sha256
                != *dispatch_manifest_sha256
            || self.kernel_driver_identity_sha256
                != *kernel_driver_identity_sha256
            || self.retained_descriptor_set_sha256
                != *retained_descriptor_set_sha256
            || self.driver_generation_receipt_sha256
                != *driver_generation_receipt_sha256
            || self.prepared_at_boottime_nanos == 0
            || self.prepared_at_boottime_nanos
                >= self.commit_deadline_boottime_nanos
            || self.commit_deadline_boottime_nanos
                > request.deadline_boottime_nanos()
        {
            return Err(
                "generation preparation material differs from its exact request or BOOTTIME bounds",
            );
        }
        Ok(())
    }

    fn receipt_for_role(
        &self,
        role: HistoricalServiceRoleV3,
    ) -> &Sha256Digest {
        match role {
            HistoricalServiceRoleV3::DurableRecoveryStore => {
                &self
                    .durable_recovery_store_prepare_receipt_sha256
            }
            HistoricalServiceRoleV3::CleanupAuthorizationConsumer => {
                &self.cleanup_authorization_prepare_receipt_sha256
            }
            HistoricalServiceRoleV3::RecoveryTargetProvider => {
                &self.recovery_target_prepare_receipt_sha256
            }
            HistoricalServiceRoleV3::CurrentSignatureAuthority => {
                &self.current_signature_prepare_receipt_sha256
            }
            HistoricalServiceRoleV3::BoundedCleanupHelper => {
                &self.bounded_cleanup_prepare_receipt_sha256
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExactSignedProductionGenerationInstallEnvelopeWireV4 {
    pub(super) api_version: String,
    pub(super) transition: ProductionGenerationTransitionV4,
    pub(super) transition_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) preparation_receipt_sha256: Option<Sha256Digest>,
    pub(super) successor_configuration_binding_sha256:
        Option<Sha256Digest>,
    pub(super) install_context_sha256: Option<Sha256Digest>,
    pub(super) exact_signed_install_envelope_bytes: Vec<u8>,
    pub(super) exact_signed_install_envelope_sha256: Sha256Digest,
}

impl ExactSignedProductionGenerationInstallEnvelopeWireV4 {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.transition_id_sha256,
            &self.request_sha256,
            &self.replay_id_sha256,
            &self.exact_signed_install_envelope_sha256,
        ] {
            require_digest(digest)?;
        }
        for digest in [
            self.preparation_receipt_sha256.as_ref(),
            self.successor_configuration_binding_sha256.as_ref(),
            self.install_context_sha256.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            require_digest(digest)?;
        }
        let binding_shape_is_valid = match self.transition {
            ProductionGenerationTransitionV4::Recover => {
                self.preparation_receipt_sha256.is_none()
                    && self
                        .successor_configuration_binding_sha256
                        .is_some()
                    && self.install_context_sha256.is_some()
            }
            ProductionGenerationTransitionV4::Commit => {
                self.preparation_receipt_sha256.is_some()
                    && self
                        .successor_configuration_binding_sha256
                        .is_none()
                    && self.install_context_sha256.is_none()
            }
            ProductionGenerationTransitionV4::Prepare
            | ProductionGenerationTransitionV4::Abort => false,
        };
        if self.api_version != PRODUCTION_GENERATION_PROTOCOL_VERSION
            || !binding_shape_is_valid
            || self.exact_signed_install_envelope_bytes.is_empty()
            || self.exact_signed_install_envelope_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || Sha256Digest::compute(
                &self.exact_signed_install_envelope_bytes,
            ) != self.exact_signed_install_envelope_sha256
        {
            return Err(
                "signed generation install envelope is incomplete or invalid",
            );
        }
        Ok(())
    }

    pub(super) fn validate_for_request(
        &self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<(), &'static str> {
        let expected_request_sha256 = request.request_sha256()?;
        let (
            preparation_receipt_sha256,
            successor_configuration_binding_sha256,
            install_context_sha256,
        ) = match request {
            ClosedProductionGenerationRequestV4::Recover {
                successor_configuration_binding_sha256,
                install_context,
                ..
            } => (
                None,
                Some(successor_configuration_binding_sha256.clone()),
                Some(Sha256Digest::compute(
                    &canonical_json_bytes(install_context).map_err(|_| {
                        "generation install context is not canonical"
                    })?,
                )),
            ),
            ClosedProductionGenerationRequestV4::Commit {
                preparation_receipt_sha256,
                ..
            } => (
                Some(preparation_receipt_sha256.clone()),
                None,
                None,
            ),
            _ => {
                return Err(
                    "signed generation install envelope is not valid for prepare or abort",
                )
            }
        };
        self.validate()?;
        if self.transition != request.transition()
            || self.transition_id_sha256
                != *request.transition_id_sha256()
            || self.request_sha256 != expected_request_sha256
            || self.replay_id_sha256 != *request.replay_id_sha256()
            || self.preparation_receipt_sha256
                != preparation_receipt_sha256
            || self.successor_configuration_binding_sha256
                != successor_configuration_binding_sha256
            || self.install_context_sha256 != install_context_sha256
        {
            return Err(
                "signed generation install envelope differs from its exact transition request",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionGenerationRecoveredResultWireV4 {
    pub(super) preparation:
        ProductionGenerationPreparationResultWireV4,
    pub(super) installation:
        ExactSignedProductionGenerationInstallEnvelopeWireV4,
}

impl ProductionGenerationRecoveredResultWireV4 {
    pub(super) fn validate_for_request(
        &self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<(), &'static str> {
        if request.transition()
            != ProductionGenerationTransitionV4::Recover
        {
            return Err(
                "recovered generation material is not a recover result",
            );
        }
        self.preparation.validate_for_request(request)?;
        self.installation.validate_for_request(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionGenerationAbortResultWireV4 {
    pub(super) transition_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) preparation_receipt_sha256: Sha256Digest,
    pub(super) durable_abort_settlement_sha256: Sha256Digest,
    pub(super) aborted_at_boottime_nanos: u64,
}

impl ProductionGenerationAbortResultWireV4 {
    pub(super) fn validate_for_request(
        &self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<(), &'static str> {
        let preparation_receipt = match request {
            ClosedProductionGenerationRequestV4::Abort {
                preparation_receipt_sha256,
                ..
            } => preparation_receipt_sha256,
            _ => return Err("generation abort material is not an abort result"),
        };
        for digest in [
            &self.transition_id_sha256,
            &self.request_sha256,
            &self.replay_id_sha256,
            &self.preparation_receipt_sha256,
            &self.durable_abort_settlement_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.transition_id_sha256
                != *request.transition_id_sha256()
            || self.request_sha256 != request.request_sha256()?
            || self.replay_id_sha256
                != *request.replay_id_sha256()
            || self.preparation_receipt_sha256
                != *preparation_receipt
            || self.aborted_at_boottime_nanos == 0
            || self.aborted_at_boottime_nanos
                >= request.deadline_boottime_nanos()
        {
            return Err(
                "generation abort material differs from its exact request or deadline",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "requestKind",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ProductionRpcRequestBodyV4 {
    Dispatch(ClosedProductionDispatchRequestV4),
    Generation(ClosedProductionGenerationRequestV4),
    RequestTermination {
        operation_id_sha256: Sha256Digest,
        termination_fence_sha256: Sha256Digest,
    },
    Settle {
        operation_id_sha256: Sha256Digest,
        termination_fence_sha256: Sha256Digest,
        result_disposition: ProductionCustodyResultDisposition,
        cleanup_deadline_boottime_nanos: u64,
    },
    VerifyPersistence {
        signer_role: PolicyShadowCustodySignerRole,
        persistence_receipt_sha256: Sha256Digest,
        canonical_payload: Vec<u8>,
    },
    VerifyRetrieval {
        signer_role: PolicyShadowCustodySignerRole,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        canonical_payload: Vec<u8>,
    },
    VerifyAssignmentBoundPersistence {
        proof_scope_canonical_bytes: Vec<u8>,
        signer_role: PolicyShadowCustodySignerRole,
        persistence_receipt_sha256: Sha256Digest,
        canonical_receipt_payload: Vec<u8>,
        signed_authority_payload: Vec<u8>,
    },
    VerifyAssignmentBoundRetrieval {
        proof_scope_canonical_bytes: Vec<u8>,
        signer_role: PolicyShadowCustodySignerRole,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        canonical_receipt_payload: Vec<u8>,
        signed_authority_payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionRpcRequestV4 {
    pub(super) api_version: String,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) deadline_boottime_nanos: u64,
    pub(super) request: ProductionRpcRequestBodyV4,
    pub(super) request_sha256: Sha256Digest,
}

impl ProductionRpcRequestV4 {
    pub(super) fn computed_request_sha256(
        &self,
    ) -> Result<Sha256Digest, &'static str> {
        Ok(hash_domain_frames(
            PRODUCTION_RPC_REQUEST_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                &self.request_id_sha256,
                &self.replay_id_sha256,
                self.deadline_boottime_nanos,
                &self.request,
            ))
            .map_err(|_| "production RPC request is not canonical")?],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.request_id_sha256,
            &self.replay_id_sha256,
            &self.request_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version != PRODUCTION_RPC_PROTOCOL_VERSION
            || self.deadline_boottime_nanos == 0
            || self.request_sha256
                != self.computed_request_sha256()?
        {
            return Err(
                "production RPC request header, deadline, or digest is invalid",
            );
        }
        let bounded = |bytes: &[u8]| {
            !bytes.is_empty()
                && bytes.len() <= MAX_PRODUCTION_RPC_PAYLOAD_BYTES
        };
        match &self.request {
            ProductionRpcRequestBodyV4::Dispatch(request) => {
                request.validate()?;
                if self.replay_id_sha256
                        != request.binding().replay_id_sha256
                    || self.deadline_boottime_nanos
                        != request
                            .binding()
                            .operation_deadline_boottime_nanos
                {
                    return Err(
                        "production RPC dispatch changed its exact replay identity or operation deadline",
                    );
                }
            }
            ProductionRpcRequestBodyV4::Generation(request) => {
                request.request_sha256()?;
                if self.replay_id_sha256
                        != *request.replay_id_sha256()
                    || self.deadline_boottime_nanos
                        != request.deadline_boottime_nanos()
                {
                    return Err(
                        "production RPC generation request changed its replay identity or deadline",
                    );
                }
            }
            ProductionRpcRequestBodyV4::RequestTermination {
                operation_id_sha256,
                termination_fence_sha256,
            } => {
                require_digest(operation_id_sha256)?;
                require_digest(termination_fence_sha256)?;
            }
            ProductionRpcRequestBodyV4::Settle {
                operation_id_sha256,
                termination_fence_sha256,
                cleanup_deadline_boottime_nanos,
                ..
            } => {
                require_digest(operation_id_sha256)?;
                require_digest(termination_fence_sha256)?;
                if *cleanup_deadline_boottime_nanos
                        != self.deadline_boottime_nanos
                {
                    return Err(
                        "production settlement changed its exact cleanup deadline",
                    );
                }
            }
            ProductionRpcRequestBodyV4::VerifyPersistence {
                persistence_receipt_sha256,
                canonical_payload,
                ..
            } => {
                require_digest(persistence_receipt_sha256)?;
                if !bounded(canonical_payload) {
                    return Err(
                        "production persistence proof payload is outside its fixed bound",
                    );
                }
            }
            ProductionRpcRequestBodyV4::VerifyRetrieval {
                retrieval_id_sha256,
                retrieval_proof_sha256,
                canonical_payload,
                ..
            } => {
                require_digest(retrieval_id_sha256)?;
                require_digest(retrieval_proof_sha256)?;
                if !bounded(canonical_payload) {
                    return Err(
                        "production retrieval proof payload is outside its fixed bound",
                    );
                }
            }
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence {
                proof_scope_canonical_bytes,
                persistence_receipt_sha256,
                canonical_receipt_payload,
                signed_authority_payload,
                ..
            } => {
                require_digest(persistence_receipt_sha256)?;
                if !bounded(proof_scope_canonical_bytes)
                    || !bounded(canonical_receipt_payload)
                    || !bounded(signed_authority_payload)
                {
                    return Err(
                        "assignment-bound persistence proof is outside its fixed bounds",
                    );
                }
            }
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval {
                proof_scope_canonical_bytes,
                retrieval_id_sha256,
                retrieval_proof_sha256,
                canonical_receipt_payload,
                signed_authority_payload,
                ..
            } => {
                require_digest(retrieval_id_sha256)?;
                require_digest(retrieval_proof_sha256)?;
                if !bounded(proof_scope_canonical_bytes)
                    || !bounded(canonical_receipt_payload)
                    || !bounded(signed_authority_payload)
                {
                    return Err(
                        "assignment-bound retrieval proof is outside its fixed bounds",
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProductionRpcRejectionCodeV4 {
    InvalidRequest,
    DeadlineExpired,
    ReplayConflict,
    QueueFull,
    GenerationConflict,
    ArtifactPrimitiveUnavailable,
    PersistenceProofRejected,
    RetrievalProofRejected,
    CleanupUnauthorized,
    RecoveryNotReady,
    DurableStateUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionRpcRejectionV4 {
    pub(super) code: ProductionRpcRejectionCodeV4,
    pub(super) request_sha256: Sha256Digest,
    pub(super) reason_sha256: Sha256Digest,
}

impl ProductionRpcRejectionV4 {
    pub(super) fn new(
        code: ProductionRpcRejectionCodeV4,
        request_sha256: Sha256Digest,
        reason: &'static str,
    ) -> Self {
        let reason_sha256 = hash_domain_frames(
            PRODUCTION_RPC_REJECTION_DOMAIN,
            &[
                request_sha256.as_str().as_bytes(),
                reason.as_bytes(),
            ],
        );
        Self {
            code,
            request_sha256,
            reason_sha256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "responseKind",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ProductionRpcResponseBodyV4 {
    Dispatch(ClosedProductionDispatchResponseV4),
    Generation(ClosedProductionGenerationResponseV4),
    TerminationRequested,
    Settlement(CanonicalProductionArtifactV4),
    Verified,
    Rejected(ProductionRpcRejectionV4),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionRpcResponseV4 {
    pub(super) api_version: String,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) replay_id_sha256: Sha256Digest,
    pub(super) completed_at_boottime_nanos: u64,
    pub(super) response: ProductionRpcResponseBodyV4,
    pub(super) response_sha256: Sha256Digest,
}

impl ProductionRpcResponseV4 {
    pub(super) fn computed_response_sha256(
        &self,
    ) -> Result<Sha256Digest, &'static str> {
        Ok(hash_domain_frames(
            PRODUCTION_RPC_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                &self.request_id_sha256,
                &self.request_sha256,
                &self.replay_id_sha256,
                self.completed_at_boottime_nanos,
                &self.response,
            ))
            .map_err(|_| "production RPC response is not canonical")?],
        ))
    }

    pub(super) fn validate_for_request(
        &self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), &'static str> {
        request.validate()?;
        if self.api_version != PRODUCTION_RPC_PROTOCOL_VERSION
            || self.request_id_sha256 != request.request_id_sha256
            || self.request_sha256 != request.request_sha256
            || self.replay_id_sha256 != request.replay_id_sha256
            || self.completed_at_boottime_nanos == 0
            || self.completed_at_boottime_nanos
                >= request.deadline_boottime_nanos
            || self.response_sha256
                != self.computed_response_sha256()?
        {
            return Err(
                "production RPC response differs from its exact request or deadline",
            );
        }
        if let ProductionRpcResponseBodyV4::Rejected(rejection) =
            &self.response
        {
            if rejection.request_sha256 != request.request_sha256
                || require_digest(&rejection.reason_sha256).is_err()
            {
                return Err(
                    "production RPC rejection is not bound to its exact request",
                );
            }
        }
        if let ProductionRpcResponseBodyV4::Settlement(artifact) =
            &self.response
        {
            if artifact.kind
                    != ProductionArtifactKindV4::TerminalCleanupAttestation
                || artifact.exact_bytes().is_err()
            {
                return Err(
                    "production RPC settlement has the wrong tagged artifact wire",
                );
            }
        }
        let paired = matches!(
            (&request.request, &self.response),
            (
                ProductionRpcRequestBodyV4::Dispatch(_),
                ProductionRpcResponseBodyV4::Dispatch(_)
                    | ProductionRpcResponseBodyV4::Rejected(_)
            )
                | (
                    ProductionRpcRequestBodyV4::Generation(_),
                    ProductionRpcResponseBodyV4::Generation(_)
                        | ProductionRpcResponseBodyV4::Rejected(_)
                )
                | (
                    ProductionRpcRequestBodyV4::RequestTermination { .. },
                    ProductionRpcResponseBodyV4::TerminationRequested
                        | ProductionRpcResponseBodyV4::Rejected(_)
                )
                | (
                    ProductionRpcRequestBodyV4::Settle { .. },
                    ProductionRpcResponseBodyV4::Settlement(_)
                        | ProductionRpcResponseBodyV4::Rejected(_)
                )
                | (
                    ProductionRpcRequestBodyV4::VerifyPersistence { .. }
                        | ProductionRpcRequestBodyV4::VerifyRetrieval { .. }
                        | ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence { .. }
                        | ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval { .. },
                    ProductionRpcResponseBodyV4::Verified
                        | ProductionRpcResponseBodyV4::Rejected(_)
                )
        );
        if !paired {
            return Err(
                "production RPC response body does not match its exact closed request body",
            );
        }
        Ok(())
    }
}

impl ClosedProductionGenerationResponseV4 {
    pub(super) fn from_native_recovery(request:&ClosedProductionGenerationRequestV4,
        evidence:&super::services::generation_recovery::Evidence)->Result<Self,&'static str>{
        if request.transition()!=ProductionGenerationTransitionV4::Recover {return Err("native recovery requires recover");}
        let mut value=Self::from_parts(request,CanonicalProductionArtifactV4::from_serializable(
            ProductionArtifactKindV4::NativeGenerationRecovery,evidence)?,Vec::new())?;
        value.api_version=super::services::generation_recovery::RESPONSE_API.into();
        value.response_sha256=value.digest()?;Ok(value)
    }
    fn digest(&self)->Result<Sha256Digest,&'static str>{
        Ok(hash_domain_frames(GENERATION_RESPONSE_DOMAIN,&[&canonical_json_bytes(&(&self.api_version,&self.request_sha256,
            &self.replay_id_sha256,&self.result,&self.service_transitions)).map_err(|_|"generation response is not canonical")?]))
    }
    pub(super) fn from_parts(
        request: &ClosedProductionGenerationRequestV4,
        result: CanonicalProductionArtifactV4,
        service_transitions:
            Vec<SignedProductionGenerationServiceTransitionV4>,
    ) -> Result<Self, &'static str> {
        let mut response = Self {
            api_version: PRODUCTION_GENERATION_PROTOCOL_VERSION.to_owned(),
            request_sha256: request.request_sha256()?,
            replay_id_sha256: request.replay_id_sha256().clone(),
            result,
            service_transitions,
            response_sha256: Sha256Digest::compute(&[]),
        };
        response.response_sha256 = hash_domain_frames(
            GENERATION_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&(
                &response.api_version,
                &response.request_sha256,
                &response.replay_id_sha256,
                &response.result,
                &response.service_transitions,
            ))
            .map_err(|_| {
                "generation response is not canonical"
            })?],
        );
        Ok(response)
    }

    pub(super) fn validate(
        &self,
        request: &ClosedProductionGenerationRequestV4,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<(), &'static str> {
        if self.api_version==super::services::generation_recovery::RESPONSE_API {
            if request.transition()!=ProductionGenerationTransitionV4::Recover
                || self.request_sha256!=request.request_sha256()? || self.replay_id_sha256!=*request.replay_id_sha256()
                || self.result.kind!=ProductionArtifactKindV4::NativeGenerationRecovery
                || !self.service_transitions.is_empty() || self.response_sha256!=self.digest()? {
                return Err("native recovery wrapper differs from its actual recover request");
            }
            let evidence:super::services::generation_recovery::Evidence=decode_exact_artifact_wire(&self.result)?;
            return evidence.validate(request,keyrings);
        }
        require_digest(&self.request_sha256)?;
        require_digest(&self.replay_id_sha256)?;
        require_digest(&self.response_sha256)?;
        self.result.exact_bytes()?;
        let expected_request_sha256 = request.request_sha256()?;
        let result_bytes = canonical_json_bytes(&self.result)
            .map_err(|_| "generation result is not canonical")?;
        let result_sha256 = Sha256Digest::compute(&result_bytes);
        let service_result_binding_sha256 =
            generation_service_result_binding_sha256(
                request,
                Some(&result_sha256),
            )?;
        let expected_result_kind = match request.transition() {
            ProductionGenerationTransitionV4::Recover
            | ProductionGenerationTransitionV4::Commit => {
                ProductionArtifactKindV4::
                    GenerationInstallAttestation
            }
            ProductionGenerationTransitionV4::Prepare => {
                ProductionArtifactKindV4::
                    GenerationTransitionPreparation
            }
            ProductionGenerationTransitionV4::Abort => {
                ProductionArtifactKindV4::
                    GenerationAbortSettlement
            }
        };
        let roles = self
            .service_transitions
            .iter()
            .map(|transition| transition.service_role)
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            HistoricalServiceRoleV3::DurableRecoveryStore,
            HistoricalServiceRoleV3::
                CleanupAuthorizationConsumer,
            HistoricalServiceRoleV3::RecoveryTargetProvider,
            HistoricalServiceRoleV3::
                CurrentSignatureAuthority,
            HistoricalServiceRoleV3::BoundedCleanupHelper,
        ]);
        if self.api_version
                != PRODUCTION_GENERATION_PROTOCOL_VERSION
            || self.request_sha256 != expected_request_sha256
            || self.replay_id_sha256
                != *request.replay_id_sha256()
            || self.result.kind != expected_result_kind
            || self.service_transitions.len() != 5
            || roles != expected
        {
            return Err(
                "generation response does not contain exactly five service transitions",
            );
        }
        validate_generation_result_wire(
            request,
            &self.result,
            &self.service_transitions,
        )?;
        for transition in &self.service_transitions {
            transition.validate(
                request,
                &expected_request_sha256,
                &service_result_binding_sha256,
                keyrings,
            )?;
        }
        let expected_response = hash_domain_frames(
            GENERATION_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&(
                &self.api_version,
                &self.request_sha256,
                &self.replay_id_sha256,
                &self.result,
                &self.service_transitions,
            ))
            .map_err(|_| {
                "generation response is not canonical"
            })?],
        );
        if expected_response != self.response_sha256 {
            return Err("generation response digest is invalid");
        }
        Ok(())
    }
}

fn decode_exact_artifact_wire<T>(
    artifact: &CanonicalProductionArtifactV4,
) -> Result<T, &'static str>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let exact = artifact.exact_bytes()?;
    let value: T = serde_json::from_slice(&exact)
        .map_err(|_| "production result artifact has the wrong closed wire type")?;
    if canonical_json_bytes(&value)
        .map_err(|_| "production result wire is not canonical")?
        != exact
    {
        return Err(
            "production result artifact bytes are not exact canonical wire bytes",
        );
    }
    Ok(value)
}

fn validate_generation_result_wire(
    request: &ClosedProductionGenerationRequestV4,
    artifact: &CanonicalProductionArtifactV4,
    transitions: &[SignedProductionGenerationServiceTransitionV4],
) -> Result<(), &'static str> {
    match request.transition() {
        ProductionGenerationTransitionV4::Recover => {
            let recovered: ProductionGenerationRecoveredResultWireV4 =
                decode_exact_artifact_wire(artifact)?;
            recovered.validate_for_request(request)?;
            for transition in transitions {
                if recovered.preparation.receipt_for_role(
                    transition.service_role,
                ) != &transition.receipt_sha256
                {
                    return Err(
                        "recovered generation preparation does not carry the exact five signed receipt digests",
                    );
                }
            }
            Ok(())
        }
        ProductionGenerationTransitionV4::Prepare => {
            let preparation:
                ProductionGenerationPreparationResultWireV4 =
                decode_exact_artifact_wire(artifact)?;
            preparation.validate_for_request(request)?;
            for transition in transitions {
                if preparation.receipt_for_role(
                    transition.service_role,
                ) != &transition.receipt_sha256
                {
                    return Err(
                        "generation preparation does not carry the exact five signed prepare receipt digests",
                    );
                }
            }
            Ok(())
        }
        ProductionGenerationTransitionV4::Commit => {
            let installation:
                ExactSignedProductionGenerationInstallEnvelopeWireV4 =
                decode_exact_artifact_wire(artifact)?;
            installation.validate_for_request(request)
        }
        ProductionGenerationTransitionV4::Abort => {
            let abort: ProductionGenerationAbortResultWireV4 =
                decode_exact_artifact_wire(artifact)?;
            abort.validate_for_request(request)
        }
    }
}

pub(super) fn production_dispatch_protocol_set_sha256(
) -> Result<Sha256Digest, &'static str> {
    let operations = [
        PolicyCustodyOperation::RecoverCurrentState,
        PolicyCustodyOperation::VerifyCheckpointSuccessor,
        PolicyCustodyOperation::VerifyCurrentCheckpointHead,
        PolicyCustodyOperation::VerifyObservationEvidence,
        PolicyCustodyOperation::PrepareGenerationPublication,
        PolicyCustodyOperation::CommitGenerationPublication,
        PolicyCustodyOperation::AbortGenerationPublication,
        PolicyCustodyOperation::BeginIngress,
        PolicyCustodyOperation::ReserveSpoolAppend,
        PolicyCustodyOperation::AppendSpoolEvent,
        PolicyCustodyOperation::CompactSpool,
        PolicyCustodyOperation::CommitRequest,
        PolicyCustodyOperation::AppendActiveEffectBarrier,
        PolicyCustodyOperation::CommitActiveEffect,
        PolicyCustodyOperation::ReconcileActiveEffect,
        PolicyCustodyOperation::AppendTerminal,
        PolicyCustodyOperation::ConsumeAndPublishActivation,
    ];
    Ok(hash_domain_frames(
        b"serverware.policyCustodyProductionProtocolSet/v4",
        &[&canonical_json_bytes(&(
            PRODUCTION_DISPATCH_PROTOCOL_VERSION,
            PRODUCTION_GENERATION_PROTOCOL_VERSION,
            PRODUCTION_RPC_PROTOCOL_VERSION,
            PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,
            [
                ProductionGenerationTransitionV4::Recover,
                ProductionGenerationTransitionV4::Prepare,
                ProductionGenerationTransitionV4::Commit,
                ProductionGenerationTransitionV4::Abort,
            ],
            operations
                .iter()
                .map(|operation| {
                    (
                        *operation,
                        required_service_roles(*operation),
                    )
                })
                .collect::<Vec<_>>(),
        ))
        .map_err(|_| {
            "production dispatch protocol set is not canonical"
        })?],
    ))
}

fn require_digest(
    digest: &Sha256Digest,
) -> Result<(), &'static str> {
    if digest.as_str().starts_with("sha256:")
        && digest != &Sha256Digest::compute(&[])
    {
        Ok(())
    } else {
        Err("production dispatch contains an invalid digest")
    }
}
