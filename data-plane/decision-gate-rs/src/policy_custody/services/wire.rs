//! Closed v3 wire contract for the trusted-host policy-custody services.
//!
//! These DTOs deliberately contain no file descriptors. Descriptor-bearing
//! requests carry SCM_RIGHTS out of band and bind every received descriptor to
//! the exact identities in the corresponding request.

use super::super::protocol::{
    endpoint_response_sha256, require_nonzero_digest, CleanupAction,
    CleanupConsumptionCasReply,
    CleanupConsumptionCompareAndSwap, CleanupConsumptionQuery,
    CleanupConsumptionQueryReply, CleanupPredecessor,
    DurableSettlementRecord, EndpointProcessIdentity,
    PersistedCleanupAuthorizationConsumptionV3,
    PolicyCustodyEndpointRole, PolicyCustodyOperation,
    ProtocolBoottimeDeadline, ProtocolError,
    SignedCleanupAuthorizationV3, SignedCleanupResultV3,
    SignedEndpointKeyAuthorizationCheckpoint,
    SignedEndpointResponseEnvelope, SignedWatchdogOwnershipAckV3,
    WatchdogLeaseV3, WatchdogProcessIdentityV3,
    WatchdogRegistrationFdRole, WatchdogRegistrationV3,
    WatchdogRetainedCgroupIdentityV3, WatchdogRetainedFdIdentityV3,
    MAX_ENDPOINT_FRAME_BYTES, MAX_SETTLEMENT_CHAIN_STATES,
};
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const POLICY_CUSTODY_SERVICES_WIRE_VERSION: &str =
    "serverware.policyCustodyServices/v3";
pub(super) const POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION: &str =
    "serverware.policyCustodyDurableRecoveryStore/v3";
pub(super) const POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION: &str =
    "serverware.policyCustodyRecoveryTargetProvider/v3";
pub(super) const POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION: &str =
    "serverware.policyCustodyCurrentSignatureAuthority/v3";
pub(super) const POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION: &str =
    "serverware.policyCustodyBoundedCleanupHelper/v3";

pub(super) const MAX_RECOVERY_SCAN_RECORDS: usize = 1_024;
pub(super) const MAX_RECOVERY_MATERIAL_ACTIONS: usize = 16;
pub(super) const MAX_STORED_CLEANUP_RESULTS: usize = 16;
pub(super) const EXACT_RETAINED_DESCRIPTOR_COUNT: usize = 6;
pub(super) const MAX_EXACT_EVIDENCE_BYTES: usize = 64 * 1024;
pub(super) const MAX_SIGNATURE_DOMAIN_BYTES: usize = 256;
pub(super) const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

pub(super) const SERVICE_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyServiceResponse/v3";
pub(super) const OWNERSHIP_RECORD_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableOwnershipRecord/v3";
pub(super) const RECOVERY_MATERIAL_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryMaterial/v3";
const RECOVERY_TARGET_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTarget/v3";
const RECOVERY_TARGET_BOOTSTRAP_MANIFEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTargetBootstrapManifest/v3";
const RECOVERY_TARGET_READINESS_SEAL_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTargetReadinessSeal/v3";
const DESCRIPTOR_REGISTRATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyDescriptorRegistration/v3";
const CURRENT_TRUST_HEAD_DOMAIN: &[u8] =
    b"serverware.policyCustodyCurrentTrustHead/v3";
pub(super) const CLEANUP_EFFECT_INTENT_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectIntent/v3";
pub(super) const CLEANUP_EFFECT_INTENT_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectIntentReceipt/v3";
pub(super) const CLEANUP_EFFECT_RESULT_RECORD_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectResultRecord/v3";
pub(in crate::policy_shadow::policy_custody) const CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectExecutionRecord/v3";
const CLEANUP_HELPER_BOOTSTRAP_MANIFEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupHelperBootstrapManifest/v3";
const CLEANUP_HELPER_READINESS_SEAL_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupHelperReadinessSeal/v3";
pub(super) const CLEANUP_WORKER_PARENT_PROOF_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupWorkerParentProof/v3";

fn invalid(
    code: &'static str,
    message: impl Into<String>,
) -> ProtocolError {
    ProtocolError::new(code, message)
}

fn require_version(
    actual: &str,
    expected: &'static str,
) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(invalid(
            "unsupported_policy_custody_service_version",
            format!("expected {expected}, received {actual}"),
        ));
    }
    Ok(())
}

fn require_bounded_bytes(
    field: &'static str,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid(
            "invalid_policy_custody_service_bytes",
            format!("{field} must contain 1..={maximum} bytes"),
        ));
    }
    Ok(())
}

fn require_bounded_string(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum {
        return Err(invalid(
            "invalid_policy_custody_service_string",
            format!("{field} must contain 1..={maximum} bytes"),
        ));
    }
    Ok(())
}

fn validate_deadline_pair(
    operation_deadline: &ProtocolBoottimeDeadline,
    cleanup_deadline: &ProtocolBoottimeDeadline,
) -> Result<(), ProtocolError> {
    operation_deadline.to_runtime()?;
    cleanup_deadline.to_runtime()?;
    if operation_deadline.domain() != cleanup_deadline.domain()
        || operation_deadline.absolute_boottime_nanos()
            >= cleanup_deadline.absolute_boottime_nanos()
    {
        return Err(invalid(
            "invalid_policy_custody_service_deadlines",
            "operation and cleanup deadlines must share a BOOTTIME domain and be strictly ordered",
        ));
    }
    Ok(())
}

fn validate_cleanup_evidence_deadlines(
    operation_deadline: &ProtocolBoottimeDeadline,
    cleanup_deadline: &ProtocolBoottimeDeadline,
    evidence_query_deadline: &ProtocolBoottimeDeadline,
) -> Result<(), ProtocolError> {
    validate_deadline_pair(operation_deadline, cleanup_deadline)?;
    evidence_query_deadline.to_runtime()?;
    if cleanup_deadline.domain() != evidence_query_deadline.domain()
        || cleanup_deadline.absolute_boottime_nanos()
            >= evidence_query_deadline.absolute_boottime_nanos()
    {
        return Err(invalid(
            "invalid_cleanup_evidence_query_deadline",
            "the evidence-query deadline must share the BOOTTIME domain and be strictly later than the cleanup deadline",
        ));
    }
    Ok(())
}

fn require_distinct_nonzero(
    fields: &[(&'static str, &Sha256Digest)],
) -> Result<(), ProtocolError> {
    let mut unique = BTreeSet::new();
    for (field, digest) in fields {
        require_nonzero_digest(field, digest)?;
        if !unique.insert(digest.as_str()) {
            return Err(invalid(
                "reused_policy_custody_service_nonce",
                format!("{field} is not distinct"),
            ));
        }
    }
    Ok(())
}

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
pub(super) enum PolicyCustodyServiceRoleV3 {
    DurableRecoveryStore,
    CleanupAuthorizationConsumer,
    RecoveryTargetProvider,
    CurrentSignatureAuthority,
    BoundedCleanupHelper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceResponseSignatureV3 {
    pub(super) api_version: String,
    pub(super) service_role: PolicyCustodyServiceRoleV3,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) response_sha256: Sha256Digest,
    pub(super) endpoint_process_identity: EndpointProcessIdentity,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) receipt_sha256: Sha256Digest,
}

impl ServiceResponseSignatureV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.request_id_sha256,
            &self.response_sha256,
            &self.endpoint_process_identity,
            self.endpoint_generation,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            self.observed_at_boottime_nanos,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_policy_custody_service_signature",
                "service response signature payload is not canonical",
            )
        })
    }

    pub(super) fn expected_receipt_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            SERVICE_RESPONSE_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate(
        &self,
        expected_role: PolicyCustodyServiceRoleV3,
        expected_request_id: &Sha256Digest,
        response_bytes: &[u8],
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_SERVICES_WIRE_VERSION,
        )?;
        self.endpoint_process_identity.validate_shape()?;
        deadline.to_runtime()?;
        for (field, digest) in [
            ("serviceResponse.requestIdSha256", &self.request_id_sha256),
            ("serviceResponse.responseSha256", &self.response_sha256),
            (
                "serviceResponse.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "serviceResponse.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("serviceResponse.signingKeyId", &self.signing_key_id),
            (
                "serviceResponse.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            ("serviceResponse.receiptSha256", &self.receipt_sha256),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        require_bounded_string(
            "serviceResponse.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        if self.service_role != expected_role
            || &self.request_id_sha256 != expected_request_id
            || self.response_sha256
                != endpoint_response_sha256(response_bytes)
            || self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.observed_at_boottime_nanos == 0
            || self.observed_at_boottime_nanos
                >= deadline.absolute_boottime_nanos()
            || self.receipt_sha256 != self.expected_receipt_sha256()?
        {
            return Err(invalid(
                "policy_custody_service_response_binding_mismatch",
                "service response signature does not bind the exact request, response, current head, or deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedServiceResponseV3<T> {
    pub(super) response: T,
    pub(super) exact_canonical_response_bytes: Vec<u8>,
    pub(super) signature: ServiceResponseSignatureV3,
    pub(super) exact_signature_envelope_bytes: Vec<u8>,
}

impl<T: Serialize> SignedServiceResponseV3<T> {
    pub(super) fn validate(
        &self,
        expected_role: PolicyCustodyServiceRoleV3,
        expected_request_id: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), ProtocolError> {
        require_bounded_bytes(
            "serviceResponse.exactCanonicalResponseBytes",
            &self.exact_canonical_response_bytes,
            MAX_ENDPOINT_FRAME_BYTES,
        )?;
        require_bounded_bytes(
            "serviceResponse.exactSignatureEnvelopeBytes",
            &self.exact_signature_envelope_bytes,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        let canonical_response =
            canonical_json_bytes(&self.response).map_err(|_| {
                invalid(
                    "noncanonical_policy_custody_service_response",
                    "service response body is not canonical",
                )
            })?;
        let canonical_signature =
            canonical_json_bytes(&self.signature).map_err(|_| {
                invalid(
                    "noncanonical_policy_custody_service_envelope",
                    "service signature envelope is not canonical",
                )
            })?;
        if self.exact_canonical_response_bytes != canonical_response
            || self.exact_signature_envelope_bytes != canonical_signature
        {
            return Err(invalid(
                "policy_custody_service_exact_bytes_mismatch",
                "persisted service response bytes differ from their canonical DTOs",
            ));
        }
        self.signature.validate(
            expected_role,
            expected_request_id,
            &self.exact_canonical_response_bytes,
            deadline,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryKeyV3 {
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
}

impl RecoveryKeyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "recoveryKey.operationIdSha256",
            &self.operation_id_sha256,
        )?;
        require_nonzero_digest(
            "recoveryKey.durableRequestSha256",
            &self.durable_request_sha256,
        )?;
        require_nonzero_digest(
            "recoveryKey.terminationFenceSha256",
            &self.termination_fence_sha256,
        )
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum OwnershipPhaseV3 {
    Armed,
    Reconciling,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableOwnershipRecordV3 {
    pub(super) api_version: String,
    pub(super) registration: WatchdogRegistrationV3,
    pub(super) signed_ownership_ack: SignedWatchdogOwnershipAckV3,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) revision: u64,
    pub(super) phase: OwnershipPhaseV3,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
    pub(super) parent: WatchdogProcessIdentityV3,
    pub(super) supervisor: WatchdogProcessIdentityV3,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) cgroup: WatchdogRetainedCgroupIdentityV3,
    pub(super) predecessor_sha256: Sha256Digest,
    pub(super) state_sha256: Sha256Digest,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) cleanup_deadline: ProtocolBoottimeDeadline,
    pub(super) watchdog_lease: Option<WatchdogLeaseV3>,
    pub(super) record_sha256: Sha256Digest,
}

#[derive(Serialize)]
struct DurableOwnershipRecordHashPreimage<'a>(
    &'a str,
    &'a WatchdogRegistrationV3,
    &'a SignedWatchdogOwnershipAckV3,
    &'a Sha256Digest,
    u64,
    OwnershipPhaseV3,
    PolicyCustodyOperation,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a WatchdogProcessIdentityV3,
    &'a WatchdogProcessIdentityV3,
    &'a WatchdogProcessIdentityV3,
    &'a WatchdogRetainedCgroupIdentityV3,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a ProtocolBoottimeDeadline,
    &'a ProtocolBoottimeDeadline,
    &'a Option<WatchdogLeaseV3>,
);

impl DurableOwnershipRecordV3 {
    pub(super) fn expected_record_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let preimage = DurableOwnershipRecordHashPreimage(
            &self.api_version,
            &self.registration,
            &self.signed_ownership_ack,
            &self.ownership_id_sha256,
            self.revision,
            self.phase,
            self.operation,
            &self.operation_id_sha256,
            &self.durable_request_sha256,
            &self.request_sha256,
            &self.supervisor_capability_sha256,
            &self.termination_fence_sha256,
            &self.parent,
            &self.supervisor,
            &self.worker,
            &self.cgroup,
            &self.predecessor_sha256,
            &self.state_sha256,
            &self.operation_deadline,
            &self.cleanup_deadline,
            &self.watchdog_lease,
        );
        let canonical = canonical_json_bytes(&preimage)
            .map_err(|_| {
                invalid(
                    "noncanonical_durable_ownership_record",
                    "durable ownership record is not canonical",
                )
            })?;
        Ok(hash_domain_frames(
            OWNERSHIP_RECORD_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn recovery_key(&self) -> RecoveryKeyV3 {
        RecoveryKeyV3 {
            operation_id_sha256: self.operation_id_sha256.clone(),
            durable_request_sha256:
                self.durable_request_sha256.clone(),
            termination_fence_sha256:
                self.termination_fence_sha256.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
        )?;
        self.registration.validate()?;
        self.signed_ownership_ack.validate_shape()?;
        self.signed_ownership_ack
            .ownership
            .validate_against_registration(&self.registration)?;
        self.parent.validate()?;
        self.supervisor.validate()?;
        self.worker.validate()?;
        self.cgroup.validate()?;
        validate_deadline_pair(
            &self.operation_deadline,
            &self.cleanup_deadline,
        )?;
        for (field, digest) in [
            ("ownership.ownershipIdSha256", &self.ownership_id_sha256),
            ("ownership.operationIdSha256", &self.operation_id_sha256),
            (
                "ownership.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            ("ownership.requestSha256", &self.request_sha256),
            (
                "ownership.supervisorCapabilitySha256",
                &self.supervisor_capability_sha256,
            ),
            (
                "ownership.terminationFenceSha256",
                &self.termination_fence_sha256,
            ),
            ("ownership.predecessorSha256", &self.predecessor_sha256),
            ("ownership.stateSha256", &self.state_sha256),
            ("ownership.recordSha256", &self.record_sha256),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        let lease_shape_valid = match (&self.phase, &self.watchdog_lease) {
            (OwnershipPhaseV3::Armed, None) => true,
            (
                OwnershipPhaseV3::Reconciling
                | OwnershipPhaseV3::Terminal,
                Some(lease),
            ) => {
                lease.validate()?;
                true
            }
            _ => false,
        };
        if self.revision == 0
            || !lease_shape_valid
            || self.ownership_id_sha256
                != self
                    .signed_ownership_ack
                    .ownership
                    .ownership_id_sha256
            || self.operation != self.registration.operation
            || self.operation_id_sha256
                != self.registration.operation_id_sha256
            || self.durable_request_sha256
                != self.registration.durable_request_sha256
            || self.request_sha256 != self.registration.request_sha256
            || self.supervisor_capability_sha256
                != self.registration.supervisor_capability_sha256
            || self.termination_fence_sha256
                != self.registration.fence_token_sha256
            || self.parent != self.registration.parent
            || self.supervisor != self.registration.supervisor
            || self.worker != self.registration.worker
            || self.cgroup != self.registration.cgroup
            || self.operation_deadline
                != self.registration.operation_deadline
            || self.cleanup_deadline != self.registration.cleanup_deadline
            || self.record_sha256 != self.expected_record_sha256()?
        {
            return Err(invalid(
                "invalid_durable_ownership_record",
                "durable ownership projection is incomplete or does not bind its registration",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupStepMaterialV3 {
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(super) expected_consumption_sequence: u64,
    pub(super) expected_consumption_predecessor_receipt_sha256:
        Sha256Digest,
    pub(super) expected_result_sequence: u64,
    pub(super) before_query_nonce_sha256: Sha256Digest,
    pub(super) before_query_request_sha256: Sha256Digest,
    pub(super) cas_nonce_sha256: Sha256Digest,
    pub(super) cas_request_sha256: Sha256Digest,
    pub(super) after_query_nonce_sha256: Sha256Digest,
    pub(super) after_query_request_sha256: Sha256Digest,
}

impl CleanupStepMaterialV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.authorization.validate_shape()?;
        require_nonzero_digest(
            "cleanupStep.expectedConsumptionPredecessorReceiptSha256",
            &self.expected_consumption_predecessor_receipt_sha256,
        )?;
        require_distinct_nonzero(&[
            (
                "cleanupStep.beforeQueryNonceSha256",
                &self.before_query_nonce_sha256,
            ),
            ("cleanupStep.casNonceSha256", &self.cas_nonce_sha256),
            (
                "cleanupStep.afterQueryNonceSha256",
                &self.after_query_nonce_sha256,
            ),
        ])?;
        require_distinct_nonzero(&[
            (
                "cleanupStep.beforeQueryRequestSha256",
                &self.before_query_request_sha256,
            ),
            ("cleanupStep.casRequestSha256", &self.cas_request_sha256),
            (
                "cleanupStep.afterQueryRequestSha256",
                &self.after_query_request_sha256,
            ),
        ])?;
        if self.expected_consumption_sequence == 0
            || self.expected_result_sequence == 0
        {
            return Err(invalid(
                "invalid_cleanup_step_sequences",
                "cleanup consumption and result sequences must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredCleanupResultV3 {
    pub(super) step: CleanupStepMaterialV3,
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(super) consumption: StoredCleanupConsumptionEvidenceV3,
    pub(super) result: SignedCleanupResultV3,
    pub(super) durable_effect: DurableCleanupEffectEvidenceV3,
}

impl StoredCleanupResultV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.step.validate()?;
        self.authorization.validate_shape()?;
        self.consumption.validate(&self.step)?;
        let endpoint_role =
            self.authorization.payload.endpoint_role;
        self.consumption.persisted.validate_cleanup_exact_bytes(
            endpoint_role,
            Some(&self.authorization),
        )?;
        self.result.validate_shape()?;
        self.durable_effect.validate()?;
        if self.authorization != self.step.authorization
            || self.durable_effect.result.signed_result
                != self.result
            || self.durable_effect.intent.intent.authorization
                != self.authorization
            || self
                .durable_effect
                .intent
                .intent
                .authorization_consumption
                != self.consumption.persisted
            || self.result.payload.authorization_sha256
                != self.authorization.authorization_sha256
            || self
                .result
                .payload
                .authorization_consumption_receipt_sha256
                != self
                    .consumption
                    .persisted
                    .signed_envelope
                    .envelope_sha256
            || self.result.payload.authorization_consumption_sequence
                != self
                    .consumption
                    .persisted
                    .statement
                    .consumer_sequence
            || self.result.payload.result_sequence
                != self.step.expected_result_sequence
        {
            return Err(invalid(
                "stored_cleanup_result_binding_mismatch",
                "stored cleanup result does not bind its exact cleanup step, trace, authorization, durable consumption receipt, and result sequence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredSignedEndpointResponseV3<R> {
    pub(super) response: R,
    pub(super) envelope: SignedEndpointResponseEnvelope,
    pub(super) exact_canonical_response: Vec<u8>,
    pub(super) exact_signature_payload: Vec<u8>,
}

impl<R> StoredSignedEndpointResponseV3<R>
where
    R: Serialize,
{
    fn validate(
        &self,
        request_nonce_sha256: &Sha256Digest,
        request_sha256: &Sha256Digest,
    ) -> Result<(), ProtocolError> {
        self.envelope.validate_shape()?;
        require_bounded_bytes(
            "storedEndpoint.exactCanonicalResponse",
            &self.exact_canonical_response,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        require_bounded_bytes(
            "storedEndpoint.exactSignaturePayload",
            &self.exact_signature_payload,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        let canonical = canonical_json_bytes(&self.response).map_err(
            |_| {
                invalid(
                    "noncanonical_stored_endpoint_response",
                    "stored endpoint response is not canonical",
                )
            },
        )?;
        let signature_payload =
            self.envelope.canonical_signature_payload()?;
        let envelope_response = URL_SAFE_NO_PAD
            .decode(&self.envelope.canonical_response_base64)
            .map_err(|_| {
                invalid(
                    "invalid_stored_endpoint_response_base64",
                    "stored endpoint response envelope is not canonical base64url",
                )
            })?;
        if canonical != self.exact_canonical_response
            || envelope_response != self.exact_canonical_response
            || signature_payload != self.exact_signature_payload
            || self.envelope.response_sha256
                != endpoint_response_sha256(
                    &self.exact_canonical_response,
                )
            || self.envelope.request_nonce_sha256
                != *request_nonce_sha256
            || self.envelope.request_sha256 != *request_sha256
        {
            return Err(invalid(
                "stored_endpoint_response_exact_bytes_mismatch",
                "stored endpoint response does not preserve its exact response, signature payload, and request binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredCleanupConsumptionEvidenceV3 {
    pub(super) before:
        StoredSignedEndpointResponseV3<CleanupConsumptionQueryReply>,
    pub(super) compare_and_swap:
        StoredSignedEndpointResponseV3<CleanupConsumptionCasReply>,
    pub(super) after:
        StoredSignedEndpointResponseV3<CleanupConsumptionQueryReply>,
    pub(super) persisted:
        PersistedCleanupAuthorizationConsumptionV3,
    pub(super) exact_consumption_signature_payload: Vec<u8>,
}

impl StoredCleanupConsumptionEvidenceV3 {
    fn validate(
        &self,
        step: &CleanupStepMaterialV3,
    ) -> Result<(), ProtocolError> {
        self.before.validate(
            &step.before_query_nonce_sha256,
            &step.before_query_request_sha256,
        )?;
        self.compare_and_swap.validate(
            &step.cas_nonce_sha256,
            &step.cas_request_sha256,
        )?;
        self.after.validate(
            &step.after_query_nonce_sha256,
            &step.after_query_request_sha256,
        )?;
        self.persisted.validate_cleanup_exact_bytes(
            step.authorization.payload.endpoint_role,
            Some(&step.authorization),
        )?;
        require_bounded_bytes(
            "storedCleanup.exactConsumptionSignaturePayload",
            &self.exact_consumption_signature_payload,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        let exact_consumption_signature_payload = self
            .persisted
            .signed_envelope
            .canonical_signature_payload()?;
        let cas_consumption =
            self.compare_and_swap.response.consumption();
        if exact_consumption_signature_payload
                != self.exact_consumption_signature_payload
            || cas_consumption != Some(&self.persisted)
            || self.after.response.authoritative_consumption.as_ref()
                != Some(&self.persisted)
            || self.persisted.statement.consumer_sequence
                != step.expected_consumption_sequence
            || self
                .persisted
                .statement
                .predecessor_receipt_sha256
                != step
                    .expected_consumption_predecessor_receipt_sha256
        {
            return Err(invalid(
                "stored_cleanup_trace_binding_mismatch",
                "stored cleanup Query/CAS/Query evidence is not byte-exact or does not converge on the expected durable consumption",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryMaterialV3 {
    pub(super) api_version: String,
    pub(super) owner: DurableOwnershipRecordV3,
    pub(super) settlement_chain: Vec<DurableSettlementRecord>,
    pub(super) cleanup_plan: Vec<CleanupStepMaterialV3>,
    pub(super) stored_cleanup_results: Vec<StoredCleanupResultV3>,
    pub(super) material_sha256: Sha256Digest,
}

impl RecoveryMaterialV3 {
    pub(super) fn expected_material_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            &self.owner,
            &self.settlement_chain,
            &self.cleanup_plan,
            &self.stored_cleanup_results,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_recovery_material",
                "recovery material is not canonical",
            )
        })?;
        if canonical.len() > MAX_ENDPOINT_FRAME_BYTES {
            return Err(invalid(
                "recovery_material_too_large",
                "recovery material exceeds the maximum service frame",
            ));
        }
        Ok(hash_domain_frames(
            RECOVERY_MATERIAL_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
        )?;
        self.owner.validate()?;
        require_nonzero_digest(
            "recoveryMaterial.materialSha256",
            &self.material_sha256,
        )?;
        if self.settlement_chain.is_empty()
            || self.settlement_chain.len()
                > MAX_SETTLEMENT_CHAIN_STATES
            || self.cleanup_plan.len()
                > MAX_RECOVERY_MATERIAL_ACTIONS
            || self.stored_cleanup_results.len()
                > MAX_STORED_CLEANUP_RESULTS
        {
            return Err(invalid(
                "invalid_recovery_material_bounds",
                "recovery material exceeds a hard record or action bound",
            ));
        }
        for (index, record) in self.settlement_chain.iter().enumerate() {
            record.validate_shape()?;
            if index > 0 {
                record.validate_successor(
                    &self.settlement_chain[index - 1],
                )?;
            }
            if record.identity.operation != self.owner.operation
                || record.identity.operation_id_sha256
                    != self.owner.operation_id_sha256
                || record.identity.durable_request_sha256
                    != self.owner.durable_request_sha256
                || record.identity.request_sha256
                    != self.owner.request_sha256
                || record.identity.fence_token_sha256
                    != self.owner.termination_fence_sha256
            {
                return Err(invalid(
                    "recovery_material_owner_mismatch",
                    "settlement chain does not belong to the projected owner",
                ));
            }
        }
        for step in &self.cleanup_plan {
            step.validate()?;
        }
        for stored in &self.stored_cleanup_results {
            stored.validate()?;
            if !self.cleanup_plan.iter().any(|step| {
                step == &stored.step
            }) {
                return Err(invalid(
                    "stored_cleanup_step_not_in_plan",
                    "stored cleanup evidence is not attached to an exact authorized step in the recovery plan",
                ));
            }
            let payload = &stored.authorization.payload;
            if payload.operation != self.owner.operation
                || payload.operation_id_sha256
                    != self.owner.operation_id_sha256
                || payload.durable_request_sha256
                    != self.owner.durable_request_sha256
                || payload.request_sha256
                    != self.owner.request_sha256
                || payload.fence_token_sha256
                    != self.owner.termination_fence_sha256
            {
                return Err(invalid(
                    "stored_cleanup_owner_mismatch",
                    "stored cleanup evidence belongs to a different durable owner",
                ));
            }
        }
        if self.material_sha256 != self.expected_material_sha256()? {
            return Err(invalid(
                "recovery_material_digest_mismatch",
                "recovery material digest does not bind the exact material",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum DurableRecoveryStoreRequestV3 {
    ScanIncomplete {
        api_version: String,
        request_id_sha256: Sha256Digest,
        continuation: Option<Sha256Digest>,
        maximum_records: u16,
        deadline: ProtocolBoottimeDeadline,
    },
    QueryOwnership {
        api_version: String,
        request_id_sha256: Sha256Digest,
        ownership_id_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    },
    CasOwnership {
        api_version: String,
        request_id_sha256: Sha256Digest,
        expected: DurableOwnershipRecordV3,
        transition: OwnershipCasTransitionV3,
        deadline: ProtocolBoottimeDeadline,
    },
    QuerySettlement {
        api_version: String,
        request_id_sha256: Sha256Digest,
        key: RecoveryKeyV3,
        deadline: ProtocolBoottimeDeadline,
    },
    CasSettlement {
        api_version: String,
        request_id_sha256: Sha256Digest,
        key: RecoveryKeyV3,
        expected_revision: u64,
        expected_state_sha256: Sha256Digest,
        candidate: DurableSettlementRecord,
        deadline: ProtocolBoottimeDeadline,
    },
    RecoveryMaterial {
        api_version: String,
        request_id_sha256: Sha256Digest,
        ownership_id_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    },
}

impl DurableRecoveryStoreRequestV3 {
    pub(super) fn request_id_sha256(&self) -> &Sha256Digest {
        match self {
            Self::ScanIncomplete {
                request_id_sha256,
                ..
            }
            | Self::QueryOwnership {
                request_id_sha256,
                ..
            }
            | Self::CasOwnership {
                request_id_sha256,
                ..
            }
            | Self::QuerySettlement {
                request_id_sha256,
                ..
            }
            | Self::CasSettlement {
                request_id_sha256,
                ..
            }
            | Self::RecoveryMaterial {
                request_id_sha256,
                ..
            } => request_id_sha256,
        }
    }

    pub(super) fn deadline(&self) -> &ProtocolBoottimeDeadline {
        match self {
            Self::ScanIncomplete { deadline, .. }
            | Self::QueryOwnership { deadline, .. }
            | Self::CasOwnership { deadline, .. }
            | Self::QuerySettlement { deadline, .. }
            | Self::CasSettlement { deadline, .. }
            | Self::RecoveryMaterial { deadline, .. } => deadline,
        }
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "recoveryStore.requestIdSha256",
            self.request_id_sha256(),
        )?;
        self.deadline().to_runtime()?;
        match self {
            Self::ScanIncomplete {
                api_version,
                continuation,
                maximum_records,
                ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
                )?;
                if let Some(continuation) = continuation {
                    require_nonzero_digest(
                        "recoveryStore.continuation",
                        continuation,
                    )?;
                }
                if *maximum_records == 0
                    || usize::from(*maximum_records)
                        > MAX_RECOVERY_SCAN_RECORDS
                {
                    return Err(invalid(
                        "invalid_recovery_scan_limit",
                        "recovery scan limit is outside its hard bound",
                    ));
                }
            }
            Self::QueryOwnership {
                api_version,
                ownership_id_sha256,
                ..
            }
            | Self::RecoveryMaterial {
                api_version,
                ownership_id_sha256,
                ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "recoveryStore.ownershipIdSha256",
                    ownership_id_sha256,
                )?;
            }
            Self::CasOwnership {
                api_version,
                expected,
                transition,
                ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
                )?;
                expected.validate()?;
                transition.validate(expected)?;
            }
            Self::QuerySettlement {
                api_version, key, ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
                )?;
                key.validate()?;
            }
            Self::CasSettlement {
                api_version,
                key,
                expected_revision,
                expected_state_sha256,
                candidate,
                ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
                )?;
                key.validate()?;
                require_nonzero_digest(
                    "recoveryStore.expectedStateSha256",
                    expected_state_sha256,
                )?;
                candidate.validate_shape()?;
                if *expected_revision == 0
                    || candidate.state_revision
                        != expected_revision.saturating_add(1)
                    || candidate.identity.operation_id_sha256
                        != key.operation_id_sha256
                    || candidate.identity.durable_request_sha256
                        != key.durable_request_sha256
                    || candidate.identity.fence_token_sha256
                        != key.termination_fence_sha256
                {
                    return Err(invalid(
                        "invalid_settlement_cas_request",
                        "settlement CAS is not one adjacent transition for the exact recovery key",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "targetPhase",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum OwnershipCasTransitionV3 {
    Reconciling {
        watchdog_lease: WatchdogLeaseV3,
    },
    Terminal {
        watchdog_lease: WatchdogLeaseV3,
        settlement_state_sha256: Sha256Digest,
    },
}

impl OwnershipCasTransitionV3 {
    fn validate(
        &self,
        expected: &DurableOwnershipRecordV3,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::Reconciling { watchdog_lease } => {
                watchdog_lease.validate()?;
                if expected.phase != OwnershipPhaseV3::Armed {
                    return Err(invalid(
                        "invalid_ownership_reconciling_cas",
                        "only armed ownership may transition to reconciling",
                    ));
                }
            }
            Self::Terminal {
                watchdog_lease,
                settlement_state_sha256,
            } => {
                watchdog_lease.validate()?;
                require_nonzero_digest(
                    "ownershipCas.settlementStateSha256",
                    settlement_state_sha256,
                )?;
                if expected.phase != OwnershipPhaseV3::Reconciling
                    || expected.watchdog_lease.as_ref()
                        != Some(watchdog_lease)
                {
                    return Err(invalid(
                        "invalid_ownership_terminal_cas",
                        "only the exact reconciling lease may transition ownership to terminal",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CasDispositionV3 {
    Applied,
    AlreadyApplied,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum DurableRecoveryStoreReplyV3 {
    ScanIncomplete {
        records: Vec<DurableOwnershipRecordV3>,
        continuation: Option<Sha256Digest>,
    },
    QueryOwnership {
        authoritative: Option<DurableOwnershipRecordV3>,
    },
    CasOwnership {
        disposition: CasDispositionV3,
        authoritative: DurableOwnershipRecordV3,
    },
    QuerySettlement {
        authoritative: Option<DurableSettlementRecord>,
    },
    CasSettlement {
        disposition: CasDispositionV3,
        authoritative: DurableSettlementRecord,
    },
    RecoveryMaterial {
        material: Option<RecoveryMaterialV3>,
    },
}

impl DurableRecoveryStoreReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ScanIncomplete {
                records,
                continuation,
            } => {
                if records.len() > MAX_RECOVERY_SCAN_RECORDS {
                    return Err(invalid(
                        "recovery_scan_reply_too_large",
                        "recovery scan reply exceeds the hard record bound",
                    ));
                }
                for record in records {
                    record.validate()?;
                }
                if let Some(continuation) = continuation {
                    require_nonzero_digest(
                        "recoveryScan.continuation",
                        continuation,
                    )?;
                }
            }
            Self::QueryOwnership { authoritative } => {
                if let Some(record) = authoritative {
                    record.validate()?;
                }
            }
            Self::CasOwnership { authoritative, .. } => {
                authoritative.validate()?;
            }
            Self::QuerySettlement { authoritative } => {
                if let Some(record) = authoritative {
                    record.validate_shape()?;
                }
            }
            Self::CasSettlement { authoritative, .. } => {
                authoritative.validate_shape()?;
            }
            Self::RecoveryMaterial { material } => {
                if let Some(material) = material {
                    material.validate()?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupAuthorizationConsumerRequestV3 {
    Query(CleanupConsumptionQuery),
    CompareAndSwap(CleanupConsumptionCompareAndSwap),
}

impl CleanupAuthorizationConsumerRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Query(query) => query.validate(),
            Self::CompareAndSwap(compare_and_swap) => {
                compare_and_swap.validate_shape()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupAuthorizationConsumerReplyV3 {
    Query(CleanupConsumptionQueryReply),
    CompareAndSwap(CleanupConsumptionCasReply),
}

impl CleanupAuthorizationConsumerReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Query(reply) => {
                reply.authoritative_cursor.validate_shape()?;
                if let Some(consumption) =
                    &reply.authoritative_consumption
                {
                    consumption.validate_cleanup_exact_bytes(
                        reply
                            .authoritative_cursor
                            .cursor
                            .endpoint_role,
                        None,
                    )?;
                }
            }
            Self::CompareAndSwap(reply) => {
                reply.authoritative_cursor().validate_shape()?;
                if let Some(consumption) = reply.consumption() {
                    consumption.validate_cleanup_exact_bytes(
                        reply
                            .authoritative_cursor()
                            .cursor
                            .endpoint_role,
                        None,
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RetainedDescriptorIdentitySetV3 {
    pub(super) parent_pidfd: WatchdogRetainedFdIdentityV3,
    pub(super) supervisor_pidfd: WatchdogRetainedFdIdentityV3,
    pub(super) worker_pidfd: WatchdogRetainedFdIdentityV3,
    pub(super) operation_cgroup: WatchdogRetainedFdIdentityV3,
    pub(super) supervisor_heartbeat_eventfd:
        WatchdogRetainedFdIdentityV3,
    pub(super) watchdog_heartbeat_eventfd:
        WatchdogRetainedFdIdentityV3,
    pub(super) fd_manifest_sha256: Sha256Digest,
}

impl RetainedDescriptorIdentitySetV3 {
    pub(super) fn ordered(
        &self,
    ) -> [
        &WatchdogRetainedFdIdentityV3;
        EXACT_RETAINED_DESCRIPTOR_COUNT
    ] {
        [
            &self.parent_pidfd,
            &self.supervisor_pidfd,
            &self.worker_pidfd,
            &self.operation_cgroup,
            &self.supervisor_heartbeat_eventfd,
            &self.watchdog_heartbeat_eventfd,
        ]
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        const EXPECTED_ROLES: [
            WatchdogRegistrationFdRole;
            EXACT_RETAINED_DESCRIPTOR_COUNT
        ] = [
            WatchdogRegistrationFdRole::ParentPidfd,
            WatchdogRegistrationFdRole::SupervisorPidfd,
            WatchdogRegistrationFdRole::WorkerPidfd,
            WatchdogRegistrationFdRole::OperationCgroup,
            WatchdogRegistrationFdRole::SupervisorHeartbeatEventfd,
            WatchdogRegistrationFdRole::WatchdogHeartbeatEventfd,
        ];
        require_nonzero_digest(
            "retainedDescriptors.fdManifestSha256",
            &self.fd_manifest_sha256,
        )?;
        let ordered = self.ordered();
        let mut open_file_descriptions = BTreeSet::new();
        for (identity, expected_role) in
            ordered.iter().zip(EXPECTED_ROLES)
        {
            identity.validate()?;
            if identity.role != expected_role
                || !open_file_descriptions.insert((
                    identity.device,
                    identity.inode,
                    identity.mount_id,
                ))
            {
                return Err(invalid(
                    "invalid_retained_descriptor_set",
                    "retained descriptors must have exact roles and distinct open-file identities",
                ));
            }
        }
        let canonical = canonical_json_bytes(&ordered).map_err(|_| {
            invalid(
                "noncanonical_retained_descriptor_set",
                "retained descriptor set is not canonical",
            )
        })?;
        let expected = hash_domain_frames(
            b"serverware.policyCustodyWatchdogFdManifest/v3",
            &[canonical.as_slice()],
        );
        if self.fd_manifest_sha256 != expected {
            return Err(invalid(
                "retained_descriptor_manifest_mismatch",
                "retained descriptor manifest digest does not bind the exact six identities",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DescriptorRegistrationV3 {
    pub(super) api_version: String,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) registration: WatchdogRegistrationV3,
    pub(super) signed_ownership_ack: SignedWatchdogOwnershipAckV3,
    pub(super) retained_descriptors: RetainedDescriptorIdentitySetV3,
    pub(super) registered_at_boottime_nanos: u64,
    pub(super) registration_record_sha256: Sha256Digest,
}

impl DescriptorRegistrationV3 {
    fn expected_record_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            &self.ownership_id_sha256,
            &self.registration,
            &self.signed_ownership_ack,
            &self.retained_descriptors,
            self.registered_at_boottime_nanos,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_descriptor_registration",
                "descriptor registration is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            DESCRIPTOR_REGISTRATION_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
        )?;
        self.registration.validate()?;
        self.signed_ownership_ack.validate_shape()?;
        self.signed_ownership_ack
            .ownership
            .validate_against_registration(&self.registration)?;
        self.retained_descriptors.validate()?;
        require_nonzero_digest(
            "descriptorRegistration.ownershipIdSha256",
            &self.ownership_id_sha256,
        )?;
        require_nonzero_digest(
            "descriptorRegistration.recordSha256",
            &self.registration_record_sha256,
        )?;
        let projected: Vec<_> = self
            .retained_descriptors
            .ordered()
            .into_iter()
            .cloned()
            .collect();
        if self.registered_at_boottime_nanos == 0
            || self.registered_at_boottime_nanos
                >= self
                    .registration
                    .operation_deadline
                    .absolute_boottime_nanos()
            || self.ownership_id_sha256
                != self
                    .signed_ownership_ack
                    .ownership
                    .ownership_id_sha256
            || projected != self.registration.retained_fds
            || self.retained_descriptors.fd_manifest_sha256
                != self.registration.fd_manifest_sha256
            || self.registration_record_sha256
                != self.expected_record_sha256()?
        {
            return Err(invalid(
                "descriptor_registration_binding_mismatch",
                "descriptor registration does not bind the exact owner, registration, six descriptors, and deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryTargetV3 {
    pub(super) api_version: String,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) cgroup: WatchdogRetainedCgroupIdentityV3,
    pub(super) retained_descriptors: RetainedDescriptorIdentitySetV3,
    pub(super) target_sha256: Sha256Digest,
}

impl RecoveryTargetV3 {
    fn expected_target_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            &self.ownership_id_sha256,
            &self.operation_id_sha256,
            &self.durable_request_sha256,
            &self.termination_fence_sha256,
            &self.worker,
            &self.cgroup,
            &self.retained_descriptors,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_recovery_target",
                "recovery target is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            RECOVERY_TARGET_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
        )?;
        self.worker.validate()?;
        self.cgroup.validate()?;
        self.retained_descriptors.validate()?;
        for (field, digest) in [
            ("recoveryTarget.ownershipIdSha256", &self.ownership_id_sha256),
            ("recoveryTarget.operationIdSha256", &self.operation_id_sha256),
            (
                "recoveryTarget.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            (
                "recoveryTarget.terminationFenceSha256",
                &self.termination_fence_sha256,
            ),
            ("recoveryTarget.targetSha256", &self.target_sha256),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        if self.worker.pidfd_stat_sha256
                != self
                    .retained_descriptors
                    .worker_pidfd
                    .retained_fd_stat_sha256
            || self.cgroup.retained_fd_stat_sha256
                != self
                    .retained_descriptors
                    .operation_cgroup
                    .retained_fd_stat_sha256
            || self.target_sha256 != self.expected_target_sha256()?
        {
            return Err(invalid(
                "recovery_target_binding_mismatch",
                "recovery target does not bind its exact retained worker pidfd and cgroup descriptor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum RecoveryTargetProviderRequestV3 {
    Register {
        api_version: String,
        request_id_sha256: Sha256Digest,
        registration: DescriptorRegistrationV3,
        deadline: ProtocolBoottimeDeadline,
    },
    Query {
        api_version: String,
        request_id_sha256: Sha256Digest,
        ownership_id_sha256: Sha256Digest,
        expected_worker_pidfd_stat_sha256: Sha256Digest,
        expected_cgroup_fd_stat_sha256: Sha256Digest,
        expected_fd_manifest_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    },
}

impl RecoveryTargetProviderRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Register {
                api_version,
                request_id_sha256,
                registration,
                deadline,
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "recoveryTarget.requestIdSha256",
                    request_id_sha256,
                )?;
                deadline.to_runtime()?;
                registration.validate()
            }
            Self::Query {
                api_version,
                request_id_sha256,
                ownership_id_sha256,
                expected_worker_pidfd_stat_sha256,
                expected_cgroup_fd_stat_sha256,
                expected_fd_manifest_sha256,
                deadline,
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
                )?;
                deadline.to_runtime()?;
                require_nonzero_digest(
                    "recoveryTarget.requestIdSha256",
                    request_id_sha256,
                )?;
                require_nonzero_digest(
                    "recoveryTarget.ownershipIdSha256",
                    ownership_id_sha256,
                )?;
                require_nonzero_digest(
                    "recoveryTarget.expectedWorkerPidfdStatSha256",
                    expected_worker_pidfd_stat_sha256,
                )?;
                require_nonzero_digest(
                    "recoveryTarget.expectedCgroupFdStatSha256",
                    expected_cgroup_fd_stat_sha256,
                )?;
                require_nonzero_digest(
                    "recoveryTarget.expectedFdManifestSha256",
                    expected_fd_manifest_sha256,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum RecoveryTargetProviderReplyV3 {
    Register {
        authoritative: DescriptorRegistrationV3,
    },
    Query {
        target: Option<RecoveryTargetV3>,
    },
}

impl RecoveryTargetProviderReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Register { authoritative } => {
                authoritative.validate()
            }
            Self::Query { target } => {
                if let Some(target) = target {
                    target.validate()?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryTargetExpectedManifestV3 {
    pub(super) api_version: String,
    pub(super) operation_generation: u64,
    pub(super) shared_configuration_sha256: Sha256Digest,
    pub(super) service_configuration_sha256: Sha256Digest,
    pub(super) ordered_registrations: Vec<DescriptorRegistrationV3>,
    pub(super) manifest_sha256: Sha256Digest,
}

impl RecoveryTargetExpectedManifestV3 {
    pub(super) fn expected_manifest_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.operation_generation,
            &self.shared_configuration_sha256,
            &self.service_configuration_sha256,
            &self.ordered_registrations,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_recovery_target_manifest",
                "recovery-target expected manifest is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            RECOVERY_TARGET_BOOTSTRAP_MANIFEST_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
        )?;
        require_nonzero_digest(
            "recoveryTargetManifest.sharedConfigurationSha256",
            &self.shared_configuration_sha256,
        )?;
        require_nonzero_digest(
            "recoveryTargetManifest.serviceConfigurationSha256",
            &self.service_configuration_sha256,
        )?;
        require_nonzero_digest(
            "recoveryTargetManifest.manifestSha256",
            &self.manifest_sha256,
        )?;
        if self.operation_generation == 0
            || self.ordered_registrations.is_empty()
            || self.ordered_registrations.len()
                > MAX_RECOVERY_SCAN_RECORDS
        {
            return Err(invalid(
                "invalid_recovery_target_manifest_bounds",
                "recovery-target expected manifest must be nonempty and within its fixed bound",
            ));
        }
        let mut owners = BTreeSet::new();
        for registration in &self.ordered_registrations {
            registration.validate()?;
            if !owners.insert(
                registration.ownership_id_sha256.as_str(),
            ) {
                return Err(invalid(
                    "duplicate_recovery_target_manifest_owner",
                    "recovery-target expected manifest repeats an ownership identity",
                ));
            }
        }
        if self.manifest_sha256
            != self.expected_manifest_sha256()?
        {
            return Err(invalid(
                "recovery_target_manifest_digest_mismatch",
                "recovery-target expected manifest digest is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryTargetReadinessSealV3 {
    pub(super) api_version: String,
    pub(super) operation_generation: u64,
    pub(super) reattachment_epoch_sha256: Sha256Digest,
    pub(super) shared_configuration_sha256: Sha256Digest,
    pub(super) service_configuration_sha256: Sha256Digest,
    pub(super) manifest_sha256: Sha256Digest,
    pub(super) ordered_ownership_ids: Vec<Sha256Digest>,
    pub(super) ordered_registration_sha256: Vec<Sha256Digest>,
    pub(super) journal_head_before_seal_sha256: Sha256Digest,
    pub(super) seal_sha256: Sha256Digest,
}

impl RecoveryTargetReadinessSealV3 {
    pub(super) fn expected_seal_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.operation_generation,
            &self.reattachment_epoch_sha256,
            &self.shared_configuration_sha256,
            &self.service_configuration_sha256,
            &self.manifest_sha256,
            &self.ordered_ownership_ids,
            &self.ordered_registration_sha256,
            &self.journal_head_before_seal_sha256,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_recovery_target_seal",
                "recovery-target readiness seal is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            RECOVERY_TARGET_READINESS_SEAL_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate_against(
        &self,
        manifest: &RecoveryTargetExpectedManifestV3,
    ) -> Result<(), ProtocolError> {
        manifest.validate()?;
        require_nonzero_digest(
            "recoveryTargetSeal.reattachmentEpochSha256",
            &self.reattachment_epoch_sha256,
        )?;
        require_nonzero_digest(
            "recoveryTargetSeal.journalHeadBeforeSealSha256",
            &self.journal_head_before_seal_sha256,
        )?;
        require_nonzero_digest(
            "recoveryTargetSeal.sealSha256",
            &self.seal_sha256,
        )?;
        let expected_owners: Vec<Sha256Digest> = manifest
            .ordered_registrations
            .iter()
            .map(|registration| {
                registration.ownership_id_sha256.clone()
            })
            .collect();
        let expected_registrations: Vec<Sha256Digest> = manifest
            .ordered_registrations
            .iter()
            .map(|registration| {
                registration.registration.registration_sha256.clone()
            })
            .collect();
        if self.api_version
                != POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION
            || self.operation_generation
                != manifest.operation_generation
            || self.shared_configuration_sha256
                != manifest.shared_configuration_sha256
            || self.service_configuration_sha256
                != manifest.service_configuration_sha256
            || self.manifest_sha256 != manifest.manifest_sha256
            || self.ordered_ownership_ids != expected_owners
            || self.ordered_registration_sha256
                != expected_registrations
            || self.ordered_ownership_ids.is_empty()
            || self.seal_sha256 != self.expected_seal_sha256()?
        {
            return Err(invalid(
                "recovery_target_readiness_seal_mismatch",
                "recovery-target readiness seal does not bind the exact nonempty ordered manifest, configuration, generation, and durable predecessor head",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "bootstrapOperation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum RecoveryTargetBootstrapRequestV3 {
    InstallManifest {
        manifest: RecoveryTargetExpectedManifestV3,
    },
    Register {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        registration: DescriptorRegistrationV3,
    },
    Seal {
        manifest_sha256: Sha256Digest,
        reattachment_epoch_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "bootstrapOutcome",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum RecoveryTargetBootstrapReplyV3 {
    ManifestInstalled {
        manifest_sha256: Sha256Digest,
    },
    Registered {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        ownership_id_sha256: Sha256Digest,
        registration_sha256: Sha256Digest,
    },
    Sealed {
        seal: RecoveryTargetReadinessSealV3,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "authority",
    content = "identity",
    rename_all = "kebab-case"
)]
pub(super) enum CurrentAuthoritySubjectV3 {
    Endpoint {
        endpoint_role: PolicyCustodyEndpointRole,
    },
    CleanupAuthorizationAuthority {
        authority_role: PolicyCustodyEndpointRole,
    },
}

impl CurrentAuthoritySubjectV3 {
    fn endpoint_role(&self) -> PolicyCustodyEndpointRole {
        match self {
            Self::Endpoint { endpoint_role } => *endpoint_role,
            Self::CleanupAuthorizationAuthority {
                authority_role,
            } => *authority_role,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CurrentTrustHeadV3 {
    pub(super) api_version: String,
    pub(super) subject: CurrentAuthoritySubjectV3,
    pub(super) endpoint_process_identity: EndpointProcessIdentity,
    pub(super) endpoint_generation: u64,
    pub(super) key_authorization_checkpoint:
        SignedEndpointKeyAuthorizationCheckpoint,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) valid_until_boottime: ProtocolBoottimeDeadline,
    pub(super) head_sha256: Sha256Digest,
}

impl CurrentTrustHeadV3 {
    fn expected_head_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            &self.subject,
            &self.endpoint_process_identity,
            self.endpoint_generation,
            &self.key_authorization_checkpoint,
            self.revocation_generation,
            &self.revocation_root_sha256,
            self.observed_at_boottime_nanos,
            &self.valid_until_boottime,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_current_trust_head",
                "current trust head is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            CURRENT_TRUST_HEAD_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION,
        )?;
        self.endpoint_process_identity.validate_shape()?;
        self.key_authorization_checkpoint.validate_shape()?;
        self.valid_until_boottime.to_runtime()?;
        require_nonzero_digest(
            "currentTrustHead.revocationRootSha256",
            &self.revocation_root_sha256,
        )?;
        require_nonzero_digest(
            "currentTrustHead.headSha256",
            &self.head_sha256,
        )?;
        let payload = &self.key_authorization_checkpoint.payload;
        if self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.observed_at_boottime_nanos == 0
            || self.observed_at_boottime_nanos
                >= self
                    .valid_until_boottime
                    .absolute_boottime_nanos()
            || payload.endpoint_role != self.subject.endpoint_role()
            || payload.endpoint_process_identity_sha256
                != self.endpoint_process_identity.identity_sha256
            || payload.exact_endpoint_generation
                != self.endpoint_generation
            || payload.revocation_generation_high_water
                != self.revocation_generation
            || payload.revocation_root_sha256
                != self.revocation_root_sha256
            || payload.valid_until_boottime
                != self.valid_until_boottime
            || self.head_sha256 != self.expected_head_sha256()?
        {
            return Err(invalid(
                "current_trust_head_binding_mismatch",
                "current trust head does not bind the exact process, generation, checkpoint, revocation head, and validity deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CurrentEndpointSignatureVerificationV3 {
    pub(super) api_version: String,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) trust_checkpoint_id_sha256: Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signature_domain: Vec<u8>,
    pub(super) signature_payload: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl CurrentEndpointSignatureVerificationV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION,
        )?;
        for (field, digest) in [
            ("currentEndpoint.requestIdSha256", &self.request_id_sha256),
            (
                "currentEndpoint.processIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            ("currentEndpoint.signingKeyId", &self.signing_key_id),
            (
                "currentEndpoint.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "currentEndpoint.trustCheckpointIdSha256",
                &self.trust_checkpoint_id_sha256,
            ),
            (
                "currentEndpoint.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        require_bounded_bytes(
            "currentEndpoint.signatureDomain",
            &self.signature_domain,
            MAX_SIGNATURE_DOMAIN_BYTES,
        )?;
        require_bounded_bytes(
            "currentEndpoint.signaturePayload",
            &self.signature_payload,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        require_bounded_string(
            "currentEndpoint.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        self.deadline.to_runtime()?;
        if self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.observed_at_boottime_nanos == 0
            || self.observed_at_boottime_nanos
                >= self.deadline.absolute_boottime_nanos()
        {
            return Err(invalid(
                "invalid_current_endpoint_signature_request",
                "current endpoint verification request is incomplete or outside its deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CurrentCleanupAuthorityVerificationV3 {
    pub(super) api_version: String,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) authority_role: PolicyCustodyEndpointRole,
    pub(super) authority_key_id: Sha256Digest,
    pub(super) authority_key_spki_sha256: Sha256Digest,
    pub(super) trust_checkpoint_id_sha256: Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signature_preimage: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl CurrentCleanupAuthorityVerificationV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION,
        )?;
        for (field, digest) in [
            ("currentCleanup.requestIdSha256", &self.request_id_sha256),
            ("currentCleanup.authorityKeyId", &self.authority_key_id),
            (
                "currentCleanup.authorityKeySpkiSha256",
                &self.authority_key_spki_sha256,
            ),
            (
                "currentCleanup.trustCheckpointIdSha256",
                &self.trust_checkpoint_id_sha256,
            ),
            (
                "currentCleanup.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        require_bounded_bytes(
            "currentCleanup.signaturePreimage",
            &self.signature_preimage,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        require_bounded_string(
            "currentCleanup.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        self.deadline.to_runtime()?;
        if self.revocation_generation == 0 {
            return Err(invalid(
                "invalid_current_cleanup_signature_request",
                "cleanup authority verification requires a current revocation generation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CurrentSignatureAuthorityRequestV3 {
    VerifyEndpoint(CurrentEndpointSignatureVerificationV3),
    VerifyCleanup(CurrentCleanupAuthorityVerificationV3),
    CurrentHead {
        api_version: String,
        request_id_sha256: Sha256Digest,
        subject: CurrentAuthoritySubjectV3,
        minimum_checkpoint_sequence: u64,
        minimum_revocation_generation: u64,
        deadline: ProtocolBoottimeDeadline,
    },
}

impl CurrentSignatureAuthorityRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::VerifyEndpoint(request) => request.validate(),
            Self::VerifyCleanup(request) => request.validate(),
            Self::CurrentHead {
                api_version,
                request_id_sha256,
                minimum_checkpoint_sequence,
                minimum_revocation_generation,
                deadline,
                ..
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "currentHead.requestIdSha256",
                    request_id_sha256,
                )?;
                deadline.to_runtime()?;
                if *minimum_checkpoint_sequence == 0
                    || *minimum_revocation_generation == 0
                {
                    return Err(invalid(
                        "invalid_current_head_floor",
                        "current trust head query requires nonzero rollback floors",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SignatureRejectionV3 {
    StaleCheckpoint,
    RevokedKey,
    KeyMismatch,
    InvalidSignature,
    ExpiredDeadline,
    RollbackDetected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum CurrentSignatureAuthorityReplyV3 {
    Verified {
        current_head: CurrentTrustHeadV3,
    },
    Rejected {
        reason: SignatureRejectionV3,
        current_head: CurrentTrustHeadV3,
    },
    CurrentHead {
        current_head: CurrentTrustHeadV3,
    },
}

impl CurrentSignatureAuthorityReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Verified { current_head }
            | Self::Rejected { current_head, .. }
            | Self::CurrentHead { current_head } => {
                current_head.validate()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupEffectKeyV3 {
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) action: CleanupAction,
    pub(super) expected_result_sequence: u64,
    pub(super) intent_sha256: Sha256Digest,
}

impl CleanupEffectKeyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "cleanupEffectKey.ownershipIdSha256",
            &self.ownership_id_sha256,
        )?;
        require_nonzero_digest(
            "cleanupEffectKey.intentSha256",
            &self.intent_sha256,
        )?;
        if self.expected_result_sequence == 0 {
            return Err(invalid(
                "invalid_cleanup_effect_sequence",
                "cleanup effect result sequence must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct CleanupEffectIntentV3 {
    pub(super) api_version: String,
    pub(in crate::policy_shadow::policy_custody) action: CleanupAction,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) operation: PolicyCustodyOperation,
    pub(in crate::policy_shadow::policy_custody) operation_id_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) durable_request_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) request_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) termination_fence_sha256: Sha256Digest,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) cgroup: WatchdogRetainedCgroupIdentityV3,
    pub(super) retained_descriptors: RetainedDescriptorIdentitySetV3,
    pub(super) worker_pidfd_identity_sha256: Sha256Digest,
    pub(super) cgroup_fd_identity_sha256: Sha256Digest,
    pub(super) retained_fd_manifest_sha256: Sha256Digest,
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(in crate::policy_shadow::policy_custody) authorization_consumption:
        PersistedCleanupAuthorizationConsumptionV3,
    pub(in crate::policy_shadow::policy_custody) predecessor: CleanupPredecessor,
    pub(in crate::policy_shadow::policy_custody) operation_deadline: ProtocolBoottimeDeadline,
    pub(in crate::policy_shadow::policy_custody) cleanup_deadline: ProtocolBoottimeDeadline,
    pub(super) evidence_query_deadline: ProtocolBoottimeDeadline,
    pub(in crate::policy_shadow::policy_custody) expected_result_sequence: u64,
    pub(super) intent_nonce_sha256: Sha256Digest,
    pub(super) intent_sha256: Sha256Digest,
}

#[derive(Serialize)]
struct CleanupEffectIntentHashPreimage<'a>(
    &'a str,
    CleanupAction,
    &'a Sha256Digest,
    PolicyCustodyOperation,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a WatchdogProcessIdentityV3,
    &'a WatchdogRetainedCgroupIdentityV3,
    &'a RetainedDescriptorIdentitySetV3,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a Sha256Digest,
    &'a SignedCleanupAuthorizationV3,
    &'a PersistedCleanupAuthorizationConsumptionV3,
    &'a CleanupPredecessor,
    &'a ProtocolBoottimeDeadline,
    &'a ProtocolBoottimeDeadline,
    &'a ProtocolBoottimeDeadline,
    u64,
    &'a Sha256Digest,
);

impl CleanupEffectIntentV3 {
    pub(super) fn expected_intent_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let preimage = CleanupEffectIntentHashPreimage(
            &self.api_version,
            self.action,
            &self.ownership_id_sha256,
            self.operation,
            &self.operation_id_sha256,
            &self.durable_request_sha256,
            &self.request_sha256,
            &self.termination_fence_sha256,
            &self.worker,
            &self.cgroup,
            &self.retained_descriptors,
            &self.worker_pidfd_identity_sha256,
            &self.cgroup_fd_identity_sha256,
            &self.retained_fd_manifest_sha256,
            &self.authorization,
            &self.authorization_consumption,
            &self.predecessor,
            &self.operation_deadline,
            &self.cleanup_deadline,
            &self.evidence_query_deadline,
            self.expected_result_sequence,
            &self.intent_nonce_sha256,
        );
        let canonical = canonical_json_bytes(&preimage)
            .map_err(|_| {
                invalid(
                    "noncanonical_cleanup_effect_intent",
                    "cleanup effect intent is not canonical",
                )
            })?;
        if canonical.len() > MAX_ENDPOINT_FRAME_BYTES {
            return Err(invalid(
                "cleanup_effect_intent_too_large",
                "cleanup effect intent exceeds the maximum service frame",
            ));
        }
        Ok(hash_domain_frames(
            CLEANUP_EFFECT_INTENT_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn key(&self) -> CleanupEffectKeyV3 {
        CleanupEffectKeyV3 {
            ownership_id_sha256: self.ownership_id_sha256.clone(),
            action: self.action,
            expected_result_sequence: self.expected_result_sequence,
            intent_sha256: self.intent_sha256.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
        )?;
        self.worker.validate()?;
        self.cgroup.validate()?;
        self.retained_descriptors.validate()?;
        self.authorization.validate_shape()?;
        self.authorization_consumption
            .validate_cleanup_exact_bytes(
                self.authorization.payload.endpoint_role,
                Some(&self.authorization),
            )?;
        self.predecessor.validate()?;
        validate_cleanup_evidence_deadlines(
            &self.operation_deadline,
            &self.cleanup_deadline,
            &self.evidence_query_deadline,
        )?;
        for (field, digest) in [
            ("cleanupIntent.ownershipIdSha256", &self.ownership_id_sha256),
            ("cleanupIntent.operationIdSha256", &self.operation_id_sha256),
            (
                "cleanupIntent.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            ("cleanupIntent.requestSha256", &self.request_sha256),
            (
                "cleanupIntent.terminationFenceSha256",
                &self.termination_fence_sha256,
            ),
            (
                "cleanupIntent.workerPidfdIdentitySha256",
                &self.worker_pidfd_identity_sha256,
            ),
            (
                "cleanupIntent.cgroupFdIdentitySha256",
                &self.cgroup_fd_identity_sha256,
            ),
            (
                "cleanupIntent.retainedFdManifestSha256",
                &self.retained_fd_manifest_sha256,
            ),
            ("cleanupIntent.intentNonceSha256", &self.intent_nonce_sha256),
            ("cleanupIntent.intentSha256", &self.intent_sha256),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        let authorization = &self.authorization.payload;
        let consumption = &self.authorization_consumption;
        if self.expected_result_sequence == 0
            || self.action != authorization.action
            || self.operation != authorization.operation
            || self.operation_id_sha256
                != authorization.operation_id_sha256
            || self.durable_request_sha256
                != authorization.durable_request_sha256
            || self.request_sha256 != authorization.request_sha256
            || self.termination_fence_sha256
                != authorization.fence_token_sha256
            || self.cgroup.protocol != authorization.cgroup_identity
            || self.predecessor != authorization.predecessor
            || self.operation_deadline
                != authorization.operation_deadline
            || self.cleanup_deadline
                != authorization.absolute_boottime_deadline
            || !matches!(
                self.action,
                CleanupAction::KillCgroup | CleanupAction::ReapWorker
            )
            || self.authorization.authorization_sha256
                != consumption.statement.authorization_sha256
            || self.authorization.payload.authorization_nonce_sha256
                != consumption.statement.authorization_nonce_sha256
            || self.worker.pidfd_stat_sha256
                != self.worker_pidfd_identity_sha256
            || self.cgroup.retained_fd_stat_sha256
                != self.cgroup_fd_identity_sha256
            || self.retained_descriptors.fd_manifest_sha256
                != self.retained_fd_manifest_sha256
            || self
                .retained_descriptors
                .worker_pidfd
                .retained_fd_stat_sha256
                != self.worker_pidfd_identity_sha256
            || self
                .retained_descriptors
                .operation_cgroup
                .retained_fd_stat_sha256
                != self.cgroup_fd_identity_sha256
            || self.intent_sha256 != self.expected_intent_sha256()?
        {
            return Err(invalid(
                "cleanup_effect_intent_binding_mismatch",
                "cleanup effect intent is unsupported or does not bind the exact owner, action, fence, worker, cgroup, descriptors, authorization, receipt, predecessor, deadlines, and result sequence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct PersistedCleanupEffectIntentV3 {
    pub(in crate::policy_shadow::policy_custody) intent: CleanupEffectIntentV3,
    pub(in crate::policy_shadow::policy_custody) exact_canonical_intent_bytes: Vec<u8>,
    pub(in crate::policy_shadow::policy_custody) persisted_at_boottime_nanos: u64,
    pub(in crate::policy_shadow::policy_custody) endpoint_process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) endpoint_generation: u64,
    pub(in crate::policy_shadow::policy_custody) helper_generation: u64,
    pub(in crate::policy_shadow::policy_custody) signing_key_id: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) signing_key_spki_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) revocation_generation: u64,
    pub(in crate::policy_shadow::policy_custody) revocation_root_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) signature_base64: String,
    pub(in crate::policy_shadow::policy_custody) intent_receipt_sha256: Sha256Digest,
}

impl PersistedCleanupEffectIntentV3 {
    pub(in crate::policy_shadow::policy_custody) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.intent.intent_sha256,
            &self.exact_canonical_intent_bytes,
            self.persisted_at_boottime_nanos,
            &self.endpoint_process_identity_sha256,
            self.endpoint_generation,
            self.helper_generation,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_effect_intent_receipt",
                "cleanup effect intent receipt is not canonical",
            )
        })
    }

    pub(super) fn expected_receipt_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            CLEANUP_EFFECT_INTENT_RECEIPT_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.intent.validate()?;
        require_bounded_bytes(
            "cleanupIntent.exactCanonicalIntentBytes",
            &self.exact_canonical_intent_bytes,
            MAX_ENDPOINT_FRAME_BYTES,
        )?;
        require_bounded_string(
            "cleanupIntent.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        for (field, digest) in [
            (
                "cleanupIntent.endpointProcessIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            ("cleanupIntent.signingKeyId", &self.signing_key_id),
            (
                "cleanupIntent.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "cleanupIntent.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanupIntent.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            (
                "cleanupIntent.intentReceiptSha256",
                &self.intent_receipt_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        let canonical = canonical_json_bytes(&self.intent).map_err(|_| {
            invalid(
                "noncanonical_cleanup_effect_intent",
                "cleanup effect intent is not canonical",
            )
        })?;
        if self.exact_canonical_intent_bytes != canonical
            || self.persisted_at_boottime_nanos == 0
            || self.persisted_at_boottime_nanos
                >= self
                    .intent
                    .cleanup_deadline
                    .absolute_boottime_nanos()
            || self.endpoint_generation == 0
            || self.helper_generation == 0
            || self.revocation_generation == 0
            || self.intent_receipt_sha256
                != self.expected_receipt_sha256()?
        {
            return Err(invalid(
                "persisted_cleanup_effect_intent_mismatch",
                "persisted cleanup intent bytes, signature, current head, or deadline are inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PersistedCleanupWorkerParentProofV3 {
    pub(super) api_version: String,
    pub(super) key: CleanupEffectKeyV3,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) worker_pidfd_identity: WatchdogRetainedFdIdentityV3,
    pub(super) helper_process_identity_sha256: Sha256Digest,
    pub(super) helper_pid: i32,
    pub(super) subreaper_enabled: bool,
    pub(super) relationship_proved_at_boottime_nanos: u64,
    pub(super) evidence_query_deadline: ProtocolBoottimeDeadline,
    pub(super) helper_generation: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) proof_sha256: Sha256Digest,
}

impl PersistedCleanupWorkerParentProofV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.api_version,
            &self.key,
            &self.worker,
            &self.worker_pidfd_identity,
            &self.helper_process_identity_sha256,
            self.helper_pid,
            self.subreaper_enabled,
            self.relationship_proved_at_boottime_nanos,
            &self.evidence_query_deadline,
            self.helper_generation,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_worker_parent_proof",
                "cleanup worker parent proof is not canonical",
            )
        })
    }

    pub(super) fn expected_proof_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            CLEANUP_WORKER_PARENT_PROOF_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_against(
        &self,
        intent: &CleanupEffectIntentV3,
    ) -> Result<(), ProtocolError> {
        intent.validate()?;
        self.key.validate()?;
        self.worker.validate()?;
        self.worker_pidfd_identity.validate()?;
        self.evidence_query_deadline.to_runtime()?;
        for (field, digest) in [
            (
                "cleanupParentProof.helperProcessIdentitySha256",
                &self.helper_process_identity_sha256,
            ),
            ("cleanupParentProof.signingKeyId", &self.signing_key_id),
            (
                "cleanupParentProof.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "cleanupParentProof.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanupParentProof.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("cleanupParentProof.proofSha256", &self.proof_sha256),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        require_bounded_string(
            "cleanupParentProof.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        if self.api_version != POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
            || intent.action != CleanupAction::ReapWorker
            || self.key != intent.key()
            || self.worker != intent.worker
            || self.worker_pidfd_identity
                != intent.retained_descriptors.worker_pidfd
            || self.worker_pidfd_identity.retained_fd_stat_sha256
                != intent.worker_pidfd_identity_sha256
            || self.helper_pid <= 0
            || !self.subreaper_enabled
            || self.relationship_proved_at_boottime_nanos == 0
            || self.relationship_proved_at_boottime_nanos
                >= intent.cleanup_deadline.absolute_boottime_nanos()
            || self.evidence_query_deadline
                != intent.evidence_query_deadline
            || self.helper_generation == 0
            || self.revocation_generation == 0
            || self.proof_sha256 != self.expected_proof_sha256()?
        {
            return Err(invalid(
                "cleanup_worker_parent_proof_mismatch",
                "cleanup worker parent proof does not bind the exact helper process, subreaper state, worker pidfd, intent, and evidence deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct PersistedCleanupEffectExecutionV3 {
    pub(super) api_version: String,
    pub(super) key: CleanupEffectKeyV3,
    pub(super) intent_receipt_sha256: Sha256Digest,
    pub(super) execute_request_id_sha256: Sha256Digest,
    pub(super) execute_idempotency_sha256: Sha256Digest,
    pub(super) exact_execute_request_bytes: Vec<u8>,
    pub(super) execute_request_sha256: Sha256Digest,
    pub(super) worker_pidfd_identity: WatchdogRetainedFdIdentityV3,
    pub(super) cgroup_fd_identity: WatchdogRetainedFdIdentityV3,
    pub(super) parent_proof:
        Option<PersistedCleanupWorkerParentProofV3>,
    pub(in crate::policy_shadow::policy_custody) entered_at_boottime_nanos: u64,
    pub(super) evidence_query_deadline: ProtocolBoottimeDeadline,
    pub(in crate::policy_shadow::policy_custody) endpoint_process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) endpoint_generation: u64,
    pub(in crate::policy_shadow::policy_custody) helper_generation: u64,
    pub(in crate::policy_shadow::policy_custody) signing_key_id: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) signing_key_spki_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) revocation_generation: u64,
    pub(in crate::policy_shadow::policy_custody) revocation_root_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) signature_base64: String,
    pub(super) execution_record_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupEffectExecutionSignaturePreimage<'a> {
    api_version: &'a str,
    key: &'a CleanupEffectKeyV3,
    intent_receipt_sha256: &'a Sha256Digest,
    execute_request_id_sha256: &'a Sha256Digest,
    execute_idempotency_sha256: &'a Sha256Digest,
    exact_execute_request_bytes: &'a [u8],
    execute_request_sha256: &'a Sha256Digest,
    worker_pidfd_identity: &'a WatchdogRetainedFdIdentityV3,
    cgroup_fd_identity: &'a WatchdogRetainedFdIdentityV3,
    parent_proof: &'a Option<PersistedCleanupWorkerParentProofV3>,
    entered_at_boottime_nanos: u64,
    evidence_query_deadline: &'a ProtocolBoottimeDeadline,
    endpoint_process_identity_sha256: &'a Sha256Digest,
    endpoint_generation: u64,
    helper_generation: u64,
    signing_key_id: &'a Sha256Digest,
    signing_key_spki_sha256: &'a Sha256Digest,
    current_key_authorization_checkpoint_sha256: &'a Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: &'a Sha256Digest,
}

impl PersistedCleanupEffectExecutionV3 {
    pub(in crate::policy_shadow::policy_custody) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(
            &CleanupEffectExecutionSignaturePreimage {
                api_version: &self.api_version,
                key: &self.key,
                intent_receipt_sha256:
                    &self.intent_receipt_sha256,
                execute_request_id_sha256:
                    &self.execute_request_id_sha256,
                execute_idempotency_sha256:
                    &self.execute_idempotency_sha256,
                exact_execute_request_bytes:
                    &self.exact_execute_request_bytes,
                execute_request_sha256:
                    &self.execute_request_sha256,
                worker_pidfd_identity:
                    &self.worker_pidfd_identity,
                cgroup_fd_identity: &self.cgroup_fd_identity,
                parent_proof: &self.parent_proof,
                entered_at_boottime_nanos:
                    self.entered_at_boottime_nanos,
                evidence_query_deadline:
                    &self.evidence_query_deadline,
                endpoint_process_identity_sha256:
                    &self.endpoint_process_identity_sha256,
                endpoint_generation: self.endpoint_generation,
                helper_generation: self.helper_generation,
                signing_key_id: &self.signing_key_id,
                signing_key_spki_sha256:
                    &self.signing_key_spki_sha256,
                current_key_authorization_checkpoint_sha256: &self
                    .current_key_authorization_checkpoint_sha256,
                revocation_generation: self.revocation_generation,
                revocation_root_sha256:
                    &self.revocation_root_sha256,
            },
        )
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_effect_execution",
                "cleanup effect execution checkpoint is not canonical",
            )
        })
    }

    pub(super) fn expected_record_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_against(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
    ) -> Result<(), ProtocolError> {
        prepared.validate()?;
        self.key.validate()?;
        self.worker_pidfd_identity.validate()?;
        self.cgroup_fd_identity.validate()?;
        self.evidence_query_deadline.to_runtime()?;
        require_bounded_bytes(
            "cleanupExecution.exactExecuteRequestBytes",
            &self.exact_execute_request_bytes,
            MAX_ENDPOINT_FRAME_BYTES,
        )?;
        require_bounded_string(
            "cleanupExecution.signatureBase64",
            &self.signature_base64,
            MAX_SIGNATURE_BYTES,
        )?;
        for (field, digest) in [
            (
                "cleanupExecution.intentReceiptSha256",
                &self.intent_receipt_sha256,
            ),
            (
                "cleanupExecution.executeRequestIdSha256",
                &self.execute_request_id_sha256,
            ),
            (
                "cleanupExecution.executeIdempotencySha256",
                &self.execute_idempotency_sha256,
            ),
            (
                "cleanupExecution.executeRequestSha256",
                &self.execute_request_sha256,
            ),
            (
                "cleanupExecution.endpointProcessIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            ("cleanupExecution.signingKeyId", &self.signing_key_id),
            (
                "cleanupExecution.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "cleanupExecution.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanupExecution.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            (
                "cleanupExecution.executionRecordSha256",
                &self.execution_record_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        let intent = &prepared.intent;
        let parent_proof_valid = match intent.action {
            CleanupAction::ReapWorker => self
                .parent_proof
                .as_ref()
                .map(|proof| proof.validate_against(intent))
                .transpose()?
                .is_some(),
            CleanupAction::KillCgroup => self.parent_proof.is_none(),
            CleanupAction::RevokeFence
            | CleanupAction::CommitResultAborted
            | CleanupAction::CommitFenceClosed
            | CleanupAction::CommitTermination => false,
        };
        if self.api_version != POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
            || self.key != intent.key()
            || self.intent_receipt_sha256
                != prepared.intent_receipt_sha256
            || self.execute_request_sha256
                != Sha256Digest::compute(
                    &self.exact_execute_request_bytes,
                )
            || self.worker_pidfd_identity
                != intent.retained_descriptors.worker_pidfd
            || self.cgroup_fd_identity
                != intent.retained_descriptors.operation_cgroup
            || !parent_proof_valid
            || self.entered_at_boottime_nanos
                < prepared.persisted_at_boottime_nanos
            || self.entered_at_boottime_nanos
                >= intent.cleanup_deadline.absolute_boottime_nanos()
            || self.evidence_query_deadline
                != intent.evidence_query_deadline
            || self.endpoint_process_identity_sha256
                != prepared.endpoint_process_identity_sha256
            || self.endpoint_generation
                != prepared.endpoint_generation
            || self.endpoint_generation == 0
            || self.helper_generation == 0
            || self.revocation_generation == 0
            || self.execution_record_sha256
                != self.expected_record_sha256()?
        {
            return Err(invalid(
                "persisted_cleanup_execution_mismatch",
                "persisted cleanup execution does not bind the exact prepared intent, execute request, retained capabilities, parent proof, and evidence deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct PersistedCleanupEffectResultV3 {
    pub(super) key: CleanupEffectKeyV3,
    pub(super) intent_receipt_sha256: Sha256Digest,
    pub(super) execution_record_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) signed_result: SignedCleanupResultV3,
    pub(super) exact_signed_result_bytes: Vec<u8>,
    pub(super) persisted_at_boottime_nanos: u64,
    pub(super) result_record_sha256: Sha256Digest,
}

impl PersistedCleanupEffectResultV3 {
    pub(super) fn expected_record_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.key,
            &self.intent_receipt_sha256,
            &self.execution_record_sha256,
            &self.signed_result,
            &self.exact_signed_result_bytes,
            self.persisted_at_boottime_nanos,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_effect_result_record",
                "cleanup effect result record is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            CLEANUP_EFFECT_RESULT_RECORD_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate_against(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        execution: &PersistedCleanupEffectExecutionV3,
    ) -> Result<(), ProtocolError> {
        self.key.validate()?;
        prepared.validate()?;
        execution.validate_against(prepared)?;
        self.signed_result.validate_shape()?;
        require_nonzero_digest(
            "cleanupResult.intentReceiptSha256",
            &self.intent_receipt_sha256,
        )?;
        require_nonzero_digest(
            "cleanupResult.executionRecordSha256",
            &self.execution_record_sha256,
        )?;
        require_nonzero_digest(
            "cleanupResult.resultRecordSha256",
            &self.result_record_sha256,
        )?;
        require_bounded_bytes(
            "cleanupResult.exactSignedResultBytes",
            &self.exact_signed_result_bytes,
            MAX_EXACT_EVIDENCE_BYTES,
        )?;
        let canonical =
            canonical_json_bytes(&self.signed_result).map_err(|_| {
                invalid(
                    "noncanonical_signed_cleanup_result",
                    "signed cleanup result is not canonical",
                )
            })?;
        let intent = &prepared.intent;
        let payload = &self.signed_result.payload;
        if self.key != intent.key()
            || self.intent_receipt_sha256
                != prepared.intent_receipt_sha256
            || self.execution_record_sha256
                != execution.execution_record_sha256
            || self.exact_signed_result_bytes != canonical
            || payload.action != intent.action
            || payload.operation != intent.operation
            || payload.operation_id_sha256
                != intent.operation_id_sha256
            || payload.durable_request_sha256
                != intent.durable_request_sha256
            || payload.request_sha256 != intent.request_sha256
            || payload.termination_fence_sha256
                != intent.termination_fence_sha256
            || payload.predecessor != intent.predecessor
            || payload.authorization_nonce_sha256
                != intent.authorization.payload.authorization_nonce_sha256
            || payload.authorization_sha256
                != intent.authorization.authorization_sha256
            || payload.authorization_consumption_receipt_sha256
                != intent
                    .authorization_consumption
                    .signed_envelope
                    .envelope_sha256
            || payload.authorization_consumption_sequence
                != intent
                    .authorization_consumption
                    .statement
                    .consumer_sequence
            || payload.endpoint_process_identity_sha256
                != prepared.endpoint_process_identity_sha256
            || payload.endpoint_generation
                != prepared.endpoint_generation
            || payload.signing_key_id
                != prepared.signing_key_id
            || payload.signing_key_spki_sha256
                != prepared.signing_key_spki_sha256
            || payload.trust_checkpoint_id_sha256
                != prepared
                    .current_key_authorization_checkpoint_sha256
            || payload.revocation_generation
                != prepared.revocation_generation
            || payload.revocation_root_sha256
                != prepared.revocation_root_sha256
            || payload.worker_pidfd_identity != intent.worker
            || payload.cgroup_fd_identity != intent.cgroup
            || payload.operation_deadline != intent.operation_deadline
            || payload.cleanup_deadline != intent.cleanup_deadline
            || payload.result_sequence
                != intent.expected_result_sequence
            || self.persisted_at_boottime_nanos
                < payload.observed_at_boottime_nanos
            || self.persisted_at_boottime_nanos
                >= intent
                    .evidence_query_deadline
                    .absolute_boottime_nanos()
            || self.result_record_sha256
                != self.expected_record_sha256()?
        {
            return Err(invalid(
                "persisted_cleanup_effect_result_mismatch",
                "persisted cleanup result does not exactly bind its prepared intent, retained identities, authorization receipt, deadlines, and result sequence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct DurableCleanupEffectEvidenceV3 {
    pub(in crate::policy_shadow::policy_custody) intent: PersistedCleanupEffectIntentV3,
    pub(in crate::policy_shadow::policy_custody) execution: PersistedCleanupEffectExecutionV3,
    pub(in crate::policy_shadow::policy_custody) result: PersistedCleanupEffectResultV3,
}

impl DurableCleanupEffectEvidenceV3 {
    pub(in crate::policy_shadow::policy_custody) fn validate(&self) -> Result<(), ProtocolError> {
        self.result
            .validate_against(&self.intent, &self.execution)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupEffectJournalStateV3 {
    Prepared {
        intent: PersistedCleanupEffectIntentV3,
    },
    Executing {
        intent: PersistedCleanupEffectIntentV3,
        execution: PersistedCleanupEffectExecutionV3,
    },
    Completed {
        intent: PersistedCleanupEffectIntentV3,
        execution: PersistedCleanupEffectExecutionV3,
        result: PersistedCleanupEffectResultV3,
    },
}

impl CleanupEffectJournalStateV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Prepared { intent } => intent.validate(),
            Self::Executing { intent, execution } => {
                execution.validate_against(intent)
            }
            Self::Completed {
                intent,
                execution,
                result,
            } => {
                result.validate_against(intent, execution)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum BoundedCleanupHelperRequestV3 {
    Query {
        api_version: String,
        request_id_sha256: Sha256Digest,
        key: CleanupEffectKeyV3,
        deadline: ProtocolBoottimeDeadline,
    },
    Prepare {
        api_version: String,
        request_id_sha256: Sha256Digest,
        intent: CleanupEffectIntentV3,
        deadline: ProtocolBoottimeDeadline,
    },
    Execute {
        api_version: String,
        request_id_sha256: Sha256Digest,
        key: CleanupEffectKeyV3,
        prepared_intent_receipt_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    },
}

impl BoundedCleanupHelperRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Query {
                api_version,
                request_id_sha256,
                key,
                deadline,
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "cleanupHelper.requestIdSha256",
                    request_id_sha256,
                )?;
                deadline.to_runtime()?;
                key.validate()
            }
            Self::Prepare {
                api_version,
                request_id_sha256,
                intent,
                deadline,
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "cleanupHelper.requestIdSha256",
                    request_id_sha256,
                )?;
                deadline.to_runtime()?;
                intent.validate()?;
                if deadline != &intent.cleanup_deadline {
                    return Err(invalid(
                        "cleanup_prepare_deadline_mismatch",
                        "cleanup prepare must use the exact cleanup deadline",
                    ));
                }
                Ok(())
            }
            Self::Execute {
                api_version,
                request_id_sha256,
                key,
                prepared_intent_receipt_sha256,
                deadline,
            } => {
                require_version(
                    api_version,
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
                )?;
                require_nonzero_digest(
                    "cleanupHelper.requestIdSha256",
                    request_id_sha256,
                )?;
                require_nonzero_digest(
                    "cleanupHelper.preparedIntentReceiptSha256",
                    prepared_intent_receipt_sha256,
                )?;
                deadline.to_runtime()?;
                key.validate()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum BoundedCleanupHelperReplyV3 {
    Query {
        authoritative: Option<CleanupEffectJournalStateV3>,
    },
    Prepare {
        authoritative: PersistedCleanupEffectIntentV3,
    },
    Execute {
        authoritative: PersistedCleanupEffectResultV3,
        prepared_intent: PersistedCleanupEffectIntentV3,
        execution: PersistedCleanupEffectExecutionV3,
    },
}

impl BoundedCleanupHelperReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Query { authoritative } => {
                if let Some(authoritative) = authoritative {
                    authoritative.validate()?;
                }
                Ok(())
            }
            Self::Prepare { authoritative } => {
                authoritative.validate()
            }
            Self::Execute {
                authoritative,
                prepared_intent,
                execution,
            } => authoritative
                .validate_against(prepared_intent, execution),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupEffectExpectedStateV3 {
    Prepared,
    Executing,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupHelperExpectedEffectV3 {
    pub(super) intent: CleanupEffectIntentV3,
    pub(super) expected_state: CleanupEffectExpectedStateV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupHelperExpectedManifestV3 {
    pub(super) api_version: String,
    pub(super) operation_generation: u64,
    pub(super) shared_configuration_sha256: Sha256Digest,
    pub(super) service_configuration_sha256: Sha256Digest,
    pub(super) ordered_effects: Vec<CleanupHelperExpectedEffectV3>,
    pub(super) manifest_sha256: Sha256Digest,
}

impl CleanupHelperExpectedManifestV3 {
    pub(super) fn expected_manifest_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.operation_generation,
            &self.shared_configuration_sha256,
            &self.service_configuration_sha256,
            &self.ordered_effects,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_helper_manifest",
                "cleanup-helper expected effect manifest is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            CLEANUP_HELPER_BOOTSTRAP_MANIFEST_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_version(
            &self.api_version,
            POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
        )?;
        require_nonzero_digest(
            "cleanupHelperManifest.sharedConfigurationSha256",
            &self.shared_configuration_sha256,
        )?;
        require_nonzero_digest(
            "cleanupHelperManifest.serviceConfigurationSha256",
            &self.service_configuration_sha256,
        )?;
        require_nonzero_digest(
            "cleanupHelperManifest.manifestSha256",
            &self.manifest_sha256,
        )?;
        if self.operation_generation == 0
            || self.ordered_effects.is_empty()
            || self.ordered_effects.len() > 256
        {
            return Err(invalid(
                "invalid_cleanup_helper_manifest_bounds",
                "cleanup-helper expected effect manifest must be nonempty and within its fixed bound",
            ));
        }
        let mut keys = BTreeSet::new();
        for effect in &self.ordered_effects {
            effect.intent.validate()?;
            let key = canonical_json_bytes(&effect.intent.key())
                .map_err(|_| {
                    invalid(
                        "noncanonical_cleanup_helper_effect_key",
                        "cleanup-helper effect key is not canonical",
                    )
                })?;
            if !keys.insert(Sha256Digest::compute(&key)) {
                return Err(invalid(
                    "duplicate_cleanup_helper_effect_key",
                    "cleanup-helper expected manifest repeats an effect key",
                ));
            }
        }
        if self.manifest_sha256
            != self.expected_manifest_sha256()?
        {
            return Err(invalid(
                "cleanup_helper_manifest_digest_mismatch",
                "cleanup-helper expected manifest digest is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupHelperReadinessSealV3 {
    pub(super) api_version: String,
    pub(super) operation_generation: u64,
    pub(super) reattachment_epoch_sha256: Sha256Digest,
    pub(super) shared_configuration_sha256: Sha256Digest,
    pub(super) service_configuration_sha256: Sha256Digest,
    pub(super) manifest_sha256: Sha256Digest,
    pub(super) ordered_effect_key_sha256: Vec<Sha256Digest>,
    pub(super) authorized_endpoint_roles:
        Vec<PolicyCustodyEndpointRole>,
    pub(super) reconciled_executing_effects: u16,
    pub(super) journal_head_before_seal_sha256: Sha256Digest,
    pub(super) seal_sha256: Sha256Digest,
}

impl CleanupHelperReadinessSealV3 {
    pub(super) fn expected_seal_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.operation_generation,
            &self.reattachment_epoch_sha256,
            &self.shared_configuration_sha256,
            &self.service_configuration_sha256,
            &self.manifest_sha256,
            &self.ordered_effect_key_sha256,
            &self.authorized_endpoint_roles,
            self.reconciled_executing_effects,
            &self.journal_head_before_seal_sha256,
        ))
        .map_err(|_| {
            invalid(
                "noncanonical_cleanup_helper_seal",
                "cleanup-helper readiness seal is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            CLEANUP_HELPER_READINESS_SEAL_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate_against(
        &self,
        manifest: &CleanupHelperExpectedManifestV3,
    ) -> Result<(), ProtocolError> {
        manifest.validate()?;
        require_nonzero_digest(
            "cleanupHelperSeal.reattachmentEpochSha256",
            &self.reattachment_epoch_sha256,
        )?;
        require_nonzero_digest(
            "cleanupHelperSeal.journalHeadBeforeSealSha256",
            &self.journal_head_before_seal_sha256,
        )?;
        require_nonzero_digest(
            "cleanupHelperSeal.sealSha256",
            &self.seal_sha256,
        )?;
        let mut expected_keys =
            Vec::with_capacity(manifest.ordered_effects.len());
        let mut expected_roles = BTreeSet::new();
        let mut executing = 0_u16;
        for effect in &manifest.ordered_effects {
            let canonical = canonical_json_bytes(&effect.intent.key())
                .map_err(|_| {
                    invalid(
                        "noncanonical_cleanup_helper_effect_key",
                        "cleanup-helper effect key is not canonical",
                    )
                })?;
            expected_keys.push(Sha256Digest::compute(&canonical));
            expected_roles.insert(
                effect.intent.action.required_endpoint_role(),
            );
            if effect.expected_state
                == CleanupEffectExpectedStateV3::Executing
            {
                executing = executing.checked_add(1).ok_or_else(|| {
                    invalid(
                        "cleanup_helper_executing_count_overflow",
                        "cleanup-helper executing count overflowed",
                    )
                })?;
            }
        }
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
            || self.operation_generation
                != manifest.operation_generation
            || self.shared_configuration_sha256
                != manifest.shared_configuration_sha256
            || self.service_configuration_sha256
                != manifest.service_configuration_sha256
            || self.manifest_sha256 != manifest.manifest_sha256
            || self.ordered_effect_key_sha256 != expected_keys
            || self.ordered_effect_key_sha256.is_empty()
            || self.authorized_endpoint_roles
                != expected_roles.into_iter().collect::<Vec<_>>()
            || self.authorized_endpoint_roles.is_empty()
            || self.reconciled_executing_effects != executing
            || self.seal_sha256 != self.expected_seal_sha256()?
        {
            return Err(invalid(
                "cleanup_helper_readiness_seal_mismatch",
                "cleanup-helper readiness seal does not bind its exact nonempty effect set, reconciliation count, generation, configuration, and durable predecessor head",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "bootstrapOperation",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupHelperBootstrapRequestV3 {
    InstallManifest {
        manifest: CleanupHelperExpectedManifestV3,
    },
    RegisterReapWorker {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        intent: CleanupEffectIntentV3,
    },
    ReconcileExecuting {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        key: CleanupEffectKeyV3,
    },
    Seal {
        manifest_sha256: Sha256Digest,
        reattachment_epoch_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "bootstrapOutcome",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupHelperBootstrapReplyV3 {
    ManifestInstalled {
        manifest_sha256: Sha256Digest,
    },
    ReapWorkerRegistered {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        key: CleanupEffectKeyV3,
    },
    ExecutingReconciled {
        manifest_sha256: Sha256Digest,
        ordinal: u16,
        key: CleanupEffectKeyV3,
        completed_result_record_sha256: Sha256Digest,
    },
    Sealed {
        seal: CleanupHelperReadinessSealV3,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "authority",
    content = "request",
    rename_all = "kebab-case"
)]
pub(super) enum PolicyCustodyServiceRequestV3 {
    DurableRecoveryStore(DurableRecoveryStoreRequestV3),
    CleanupAuthorizationConsumer(
        CleanupAuthorizationConsumerRequestV3,
    ),
    RecoveryTargetProvider(RecoveryTargetProviderRequestV3),
    CurrentSignatureAuthority(CurrentSignatureAuthorityRequestV3),
    BoundedCleanupHelper(BoundedCleanupHelperRequestV3),
}

impl PolicyCustodyServiceRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::DurableRecoveryStore(request) => request.validate(),
            Self::CleanupAuthorizationConsumer(request) => {
                request.validate()
            }
            Self::RecoveryTargetProvider(request) => request.validate(),
            Self::CurrentSignatureAuthority(request) => request.validate(),
            Self::BoundedCleanupHelper(request) => request.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "authority",
    content = "response",
    rename_all = "kebab-case"
)]
pub(super) enum PolicyCustodyServiceReplyV3 {
    DurableRecoveryStore(DurableRecoveryStoreReplyV3),
    CleanupAuthorizationConsumer(
        CleanupAuthorizationConsumerReplyV3,
    ),
    RecoveryTargetProvider(RecoveryTargetProviderReplyV3),
    CurrentSignatureAuthority(CurrentSignatureAuthorityReplyV3),
    BoundedCleanupHelper(BoundedCleanupHelperReplyV3),
}

impl PolicyCustodyServiceReplyV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::DurableRecoveryStore(reply) => reply.validate(),
            Self::CleanupAuthorizationConsumer(reply) => {
                reply.validate()
            }
            Self::RecoveryTargetProvider(reply) => reply.validate(),
            Self::CurrentSignatureAuthority(reply) => reply.validate(),
            Self::BoundedCleanupHelper(reply) => reply.validate(),
        }
    }
}

pub(super) type SignedPolicyCustodyServiceReplyV3 =
    SignedServiceResponseV3<PolicyCustodyServiceReplyV3>;
