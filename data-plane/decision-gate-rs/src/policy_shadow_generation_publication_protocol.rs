//! Existing generation-publication wire contract shared by its producer and consumer.
//! Runtime admission, retained custody and signature verification remain at callers.

use super::policy_shadow::{
    canonical_json_bytes, EnvelopePayload, Sha256Digest, ShadowError,
    SignedEnvelope, CANONICAL_PROFILE, SIGNATURE_ALGORITHM,
};
use super::sha256_prefixed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const INSTALL_RECEIPT_API_VERSION: &str =
    "catchplate.policyShadowGenerationPublication/v2";
pub(crate) const INSTALL_RECEIPT_KIND: &str =
    "PolicyShadowGenerationPublication";
pub(crate) const PUBLICATION_PREPARATION_API_VERSION: &str =
    "catchplate.policyShadowGenerationPublicationPreparation/v1";
pub(crate) const PUBLICATION_PREPARATION_KIND: &str =
    "PolicyShadowGenerationPublicationPreparation";
pub(crate) const PUBLICATION_HANDOFF_API_VERSION: &str =
    "catchplate.policyShadowGenerationPublicationHandoff/v1";
pub(crate) const PUBLICATION_SIGNATURE_DOMAIN: &str =
    "catchplate.policyShadowGenerationPublication/v2";
pub(crate) const PUBLICATION_PREPARATION_SIGNATURE_DOMAIN: &str =
    "catchplate.policyShadowGenerationPublicationPreparation/v1";
pub(crate) const STARTUP_ATTESTATION_HANDOFF_API_VERSION: &str =
    "catchplate.policyShadowRuntimeAttestationHandoff/v2";
pub(crate) const STARTUP_ATTESTATION_RECEIPT_API_VERSION: &str =
    "catchplate.policyRuntimeAttestation/v2";
pub(crate) const STARTUP_ATTESTATION_RECEIPT_KIND: &str =
    "PolicyRuntimeAttestation";
pub(crate) const SHADOW_ROLE_AUTHORIZATION_API_VERSION: &str =
    "catchplate.policyShadowRoleAuthorization/v1";
pub(crate) const SHADOW_ROLE_AUTHORIZATION_KIND: &str =
    "PolicyShadowRoleAuthorization";
pub(crate) const RUNTIME_EVIDENCE_API_VERSION: &str =
    "catchplate.policyShadowRuntimeAttestationEvidence/v1";

pub(crate) const RUNTIME_VERIFIER_RESPONSE_API_VERSION: &str =
    "catchplate.policyShadowRuntimeAttestationVerification/v2";
pub(crate) const RUNTIME_VERIFIER_RESPONSE_KIND: &str =
    "PolicyShadowRuntimeAttestationVerification";
pub(crate) const RUNTIME_VERIFIER_SIGNATURE_DOMAIN: &str =
    "catchplate.policyShadowRuntimeAttestationVerification/v2";

pub(crate) const MAX_RUNTIME_EVIDENCE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

pub(crate) const MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS: i64 =
    15 * 60 * 1_000_000_000;
pub(crate) const MAX_REPLAY_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeAttestationEvidence {
    pub(crate) api_version: String,
    pub(crate) evidence_id: Sha256Digest,
    pub(crate) evidence_revision: u64,
    pub(crate) evidence_type: String,
    pub(crate) evidence_sha256: Sha256Digest,
    pub(crate) evidence: Value,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartupRuntimeAttestationRecord {
    pub(crate) fleet_id: Sha256Digest,
    pub(crate) membership_revision: u64,
    pub(crate) member_ordinal: u64,
    pub(crate) member_id: Sha256Digest,
    pub(crate) instance_id: String,
    pub(crate) boot_id_sha256: Sha256Digest,
    pub(crate) spiffe_id: String,
    pub(crate) tee_platform: String,
    pub(crate) tee_evidence_sha256: Sha256Digest,
    pub(crate) tee_measurement_sha256: Sha256Digest,
    pub(crate) role_keys_digest: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartupRuntimeAttestationReceiptPayload {
    pub(crate) issued_at_epoch_ns: i64,
    pub(crate) expires_at_epoch_ns: i64,
    pub(crate) record: StartupRuntimeAttestationRecord,
}

impl EnvelopePayload for StartupRuntimeAttestationReceiptPayload {
    const API_VERSION: &'static str =
        STARTUP_ATTESTATION_RECEIPT_API_VERSION;
    const KIND: &'static str = STARTUP_ATTESTATION_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        STARTUP_ATTESTATION_RECEIPT_API_VERSION;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.membership_revision == 0
            || self.record.member_ordinal == 0
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || super::policy_shadow::SpiffeId::parse(self.record.spiffe_id.clone()).is_err()
            || !matches!(
                self.record.tee_platform.as_str(),
                "aws-nitro-enclave"
                    | "amd-sev-snp"
                    | "intel-tdx"
                    | "trusted-host-no-tee"
            )
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShadowRoleAuthorizationRecord {
    pub(crate) authorization_id: Sha256Digest,
    pub(crate) authorization_revision: u64,
    pub(crate) role: String,
    pub(crate) candidate_id: Sha256Digest,
    pub(crate) canary_id: Sha256Digest,
    pub(crate) assignment_sha256: Sha256Digest,
    pub(crate) assignment_payload_sha256: Sha256Digest,
    pub(crate) assignment_revision: u64,
    pub(crate) load_receipt_sha256: Sha256Digest,
    pub(crate) load_receipt_payload_sha256: Sha256Digest,
    pub(crate) fleet_id: Sha256Digest,
    pub(crate) fleet_membership_revision: u64,
    pub(crate) membership_root_sha256: Sha256Digest,
    pub(crate) member_ordinal: u64,
    pub(crate) member_id: Sha256Digest,
    pub(crate) instance_id: String,
    pub(crate) boot_id_sha256: Sha256Digest,
    pub(crate) runtime_attestation_receipt_id: Sha256Digest,
    pub(crate) runtime_attestation_receipt_revision: u64,
    pub(crate) runtime_attestation_receipt_sha256: Sha256Digest,
    pub(crate) runtime_attestation_payload_sha256: Sha256Digest,
    pub(crate) attestation_evidence_id: Sha256Digest,
    pub(crate) attestation_evidence_revision: u64,
    pub(crate) attestation_evidence_sha256: Sha256Digest,
    pub(crate) runtime_identity_sha256: Sha256Digest,
    pub(crate) runtime_executable_sha256: Sha256Digest,
    pub(crate) runtime_release_sha256: Sha256Digest,
    pub(crate) runtime_config_sha256: Sha256Digest,
    pub(crate) runtime_policy_sha256: Sha256Digest,
    pub(crate) attestation_policy_sha256: Sha256Digest,
    pub(crate) attestation_trust_checkpoint_sha256: Sha256Digest,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_root_sha256: Sha256Digest,
    pub(crate) shadow_signing_key_id: Sha256Digest,
    pub(crate) shadow_signing_key_spki_sha256: Sha256Digest,
    pub(crate) tee_measurement_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShadowRoleAuthorizationPayload {
    pub(crate) issued_at_epoch_ns: i64,
    pub(crate) expires_at_epoch_ns: i64,
    pub(crate) record: ShadowRoleAuthorizationRecord,
}

impl EnvelopePayload for ShadowRoleAuthorizationPayload {
    const API_VERSION: &'static str =
        SHADOW_ROLE_AUTHORIZATION_API_VERSION;
    const KIND: &'static str = SHADOW_ROLE_AUTHORIZATION_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        SHADOW_ROLE_AUTHORIZATION_API_VERSION;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.authorization_revision == 0
            || self.record.assignment_revision == 0
            || self.record.runtime_attestation_receipt_revision == 0
            || self.record.attestation_evidence_revision == 0
            || self.record.fleet_membership_revision == 0
            || self.record.member_ordinal == 0
            || self.record.revocation_generation == 0
            || self.record.role != "shadow"
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || self.record.shadow_signing_key_id
                != self.record.shadow_signing_key_spki_sha256
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeAttestationHandoff {
    pub(crate) api_version: String,
    pub(crate) receipt_id: Sha256Digest,
    pub(crate) receipt_revision: u64,
    pub(crate) receipt: SignedEnvelope<StartupRuntimeAttestationReceiptPayload>,
    pub(crate) receipt_sha256: Sha256Digest,
    pub(crate) receipt_payload_sha256: Sha256Digest,
    pub(crate) role_authorization_id: Sha256Digest,
    pub(crate) role_authorization_revision: u64,
    pub(crate) role_authorization:
        SignedEnvelope<ShadowRoleAuthorizationPayload>,
    pub(crate) role_authorization_sha256: Sha256Digest,
    pub(crate) role_authorization_payload_sha256: Sha256Digest,
    pub(crate) evidence: RuntimeAttestationEvidence,
    pub(crate) chain_sha256: Sha256Digest,
}


#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeAttestationVerificationResult {
    pub(crate) schema_version: String,
    pub(crate) status: String,
    pub(crate) attestation_policy_sha256: Sha256Digest,
    pub(crate) verifier_executable_sha256: Sha256Digest,
    pub(crate) attestation_mode: String,
    pub(crate) hardware_attested: bool,
    pub(crate) assignment_payload_sha256: Sha256Digest,
    pub(crate) load_receipt_payload_sha256: Sha256Digest,
    pub(crate) runtime_identity_sha256: Sha256Digest,
    pub(crate) runtime_attestation_receipt_sha256: Sha256Digest,
    pub(crate) runtime_attestation_payload_sha256: Sha256Digest,
    pub(crate) role_authorization_sha256: Sha256Digest,
    pub(crate) role_authorization_payload_sha256: Sha256Digest,
    pub(crate) attestation_evidence_id: Sha256Digest,
    pub(crate) attestation_evidence_revision: u64,
    pub(crate) tee_evidence_sha256: Sha256Digest,
    pub(crate) tee_measurement_sha256: Sha256Digest,
    pub(crate) runtime_executable_sha256: Sha256Digest,
    pub(crate) runtime_release_sha256: Sha256Digest,
    pub(crate) runtime_config_sha256: Sha256Digest,
    pub(crate) runtime_policy_sha256: Sha256Digest,
    pub(crate) shadow_signing_key_id: Sha256Digest,
    pub(crate) shadow_signing_key_spki_sha256: Sha256Digest,
    pub(crate) trust_checkpoint_sha256: Sha256Digest,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_root_sha256: Sha256Digest,
    pub(crate) evidence_chain_sha256: Sha256Digest,
    pub(crate) trusted_now_unix_nanos: i64,
    pub(crate) maximum_age_nanos: i64,
    pub(crate) issued_at_unix_nanos: i64,
    pub(crate) expires_at_unix_nanos: i64,
}


impl EnvelopePayload for RuntimeAttestationVerificationResult {
    const API_VERSION: &'static str =
        RUNTIME_VERIFIER_RESPONSE_API_VERSION;
    const KIND: &'static str = RUNTIME_VERIFIER_RESPONSE_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        RUNTIME_VERIFIER_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.schema_version != Self::API_VERSION
            || self.status != "verified"
            || self.revocation_generation == 0
            || self.attestation_evidence_revision == 0
            || self.shadow_signing_key_id
                != self.shadow_signing_key_spki_sha256
            || self.trusted_now_unix_nanos <= 0
            || self.maximum_age_nanos <= 0
            || self.maximum_age_nanos
                > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
            || self.issued_at_unix_nanos <= 0
            || self.trusted_now_unix_nanos
                < self.issued_at_unix_nanos
            || self.trusted_now_unix_nanos
                >= self.expires_at_unix_nanos
            || self.expires_at_unix_nanos
                <= self.issued_at_unix_nanos
            || self
                .expires_at_unix_nanos
                .checked_sub(self.issued_at_unix_nanos)
                .is_none_or(|lifetime| {
                    lifetime > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
                })
            || self
                .trusted_now_unix_nanos
                .checked_sub(self.issued_at_unix_nanos)
                .is_none_or(|age| age > self.maximum_age_nanos)
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}


#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationRequestBinding {
    pub(crate) request_id: String,
    pub(crate) replay_id: String,
    pub(crate) management_handoff_id: String,
    pub(crate) management_handoff_sha256: Sha256Digest,
    pub(crate) request_sha256: Sha256Digest,
}


#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationSnapshotBinding {
    pub(crate) policy_sha256: Sha256Digest,
    pub(crate) policy_sequence: u64,
    pub(crate) rollback_epoch: u64,
    pub(crate) compiled_snapshot_sha256: Sha256Digest,
    pub(crate) compiled_behavior_sha256: Sha256Digest,
    pub(crate) runtime_snapshot_epoch: u64,
    pub(crate) policy_trust_generation: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationGenerationBinding {
    pub(crate) generation_id: Sha256Digest,
    pub(crate) generation_epoch: u64,
    pub(crate) minimum_generation_tombstone_epoch: u64,
    pub(crate) generation_tombstone_epoch: u64,
    pub(crate) assignment_envelope_sha256: Sha256Digest,
    pub(crate) assignment_payload_sha256: Sha256Digest,
    pub(crate) assignment_revision: u64,
    pub(crate) load_receipt_envelope_sha256: Sha256Digest,
    pub(crate) load_receipt_payload_sha256: Sha256Digest,
    pub(crate) runtime_boot_id_sha256: Sha256Digest,
    pub(crate) active: PublicationSnapshotBinding,
    pub(crate) active_policy_bundle_sha256: Sha256Digest,
    pub(crate) candidate: PublicationSnapshotBinding,
    pub(crate) candidate_policy_bundle_sha256: Sha256Digest,
    pub(crate) request_commitment_key_epoch: u64,
    pub(crate) request_facts_schema_sha256: Sha256Digest,
    pub(crate) ingress_range_start_sequence: u64,
    pub(crate) ingress_range_predecessor_head_sha256: Sha256Digest,
    pub(crate) observation_interval_sha256: Sha256Digest,
    pub(crate) response_validation_obligations_root_sha256: Sha256Digest,
    pub(crate) signed_publication_revision: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationCustodyBinding {
    pub(crate) custody_configuration_sha256: Sha256Digest,
    pub(crate) preparation_receipt_sha256: Sha256Digest,
    pub(crate) publication_receipt_sha256: Sha256Digest,
    pub(crate) publication_revision: u64,
    pub(crate) publication_reconciliation_receipt_sha256: Sha256Digest,
    pub(crate) authoritative_ledger_event_ordinal: u64,
    pub(crate) authoritative_ledger_head_sha256: Sha256Digest,
    pub(crate) authoritative_spool_root_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationRuntimeBinding {
    pub(crate) decision_gate_executable_sha256: Sha256Digest,
    pub(crate) decision_gate_runtime_measurement_sha256: Sha256Digest,
    pub(crate) release_provenance_sha256: Sha256Digest,
    pub(crate) runtime_configuration_sha256: Sha256Digest,
    pub(crate) runtime_policy_sha256: Sha256Digest,
    pub(crate) image_signatures_sha256: Sha256Digest,
    pub(crate) generation_trust_manifest_sha256: Sha256Digest,
    pub(crate) policy_compiler_binary_sha256: Sha256Digest,
    pub(crate) policy_compiler_configuration_sha256: Sha256Digest,
    pub(crate) policy_schema_sha256: Sha256Digest,
    pub(crate) adapter_schema_sha256: Sha256Digest,
    pub(crate) policy_semantic_model_sha256: Sha256Digest,
    pub(crate) policy_plan_schema_sha256: Sha256Digest,
    pub(crate) request_facts_schema_sha256: Sha256Digest,
    pub(crate) runtime_attestation_verifier_executable_sha256: Sha256Digest,
    pub(crate) publication_handoff_executable_sha256: Sha256Digest,
    pub(crate) active_policy_signing_key_id: Sha256Digest,
    pub(crate) runtime_instance_id: String,
    pub(crate) runtime_identity_sha256: Sha256Digest,
    pub(crate) runtime_boot_id_sha256: Sha256Digest,
    pub(crate) runtime_tee_measurement_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationTrustBinding {
    pub(crate) trust_checkpoint_sha256: Sha256Digest,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_root_sha256: Sha256Digest,
    pub(crate) runtime_attestation_policy_sha256: Sha256Digest,
    pub(crate) runtime_attestation_verifier_signing_key_id: Sha256Digest,
    pub(crate) runtime_attestation_verifier_signing_key_spki_sha256: Sha256Digest,
    pub(crate) publication_signing_key_id: Sha256Digest,
    pub(crate) publication_signing_key_spki_sha256: Sha256Digest,
    pub(crate) publication_replay_store_sha256: Sha256Digest,
    pub(crate) replay_store_revision: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationAttestationChain {
    pub(crate) startup_attestation: RuntimeAttestationHandoff,
    pub(crate) runtime_attestation_verification:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
    pub(crate) runtime_attestation_verification_envelope_sha256: Sha256Digest,
    pub(crate) attestation_mode: String,
    pub(crate) hardware_attested: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationPublicationPreparationPayload {
    pub(crate) schema_version: String,
    pub(crate) signature_domain: String,
    pub(crate) signature_algorithm: String,
    pub(crate) canonicalization_profile: String,
    pub(crate) status: String,
    pub(crate) request: PublicationRequestBinding,
    pub(crate) generation: PublicationGenerationBinding,
    pub(crate) runtime: PublicationRuntimeBinding,
    pub(crate) trust: PublicationTrustBinding,
    pub(crate) attestation_chain: PublicationAttestationChain,
    pub(crate) durable_reservation_receipt_sha256: Sha256Digest,
    pub(crate) not_before_unix_nanos: i64,
    pub(crate) issued_at_unix_nanos: i64,
    pub(crate) expires_at_unix_nanos: i64,
}

impl EnvelopePayload for GenerationPublicationPreparationPayload {
    const API_VERSION: &'static str =
        PUBLICATION_PREPARATION_API_VERSION;
    const KIND: &'static str = PUBLICATION_PREPARATION_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_PREPARATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_publication_common(
            &self.schema_version,
            Self::API_VERSION,
            &self.signature_domain,
            Self::SIGNATURE_DOMAIN,
            &self.signature_algorithm,
            &self.canonicalization_profile,
            &self.status,
            "prepared",
            &self.request,
            &self.generation,
            &self.runtime,
            &self.trust,
            &self.attestation_chain,
            self.not_before_unix_nanos,
            self.issued_at_unix_nanos,
            self.expires_at_unix_nanos,
        )?;
        if self.durable_reservation_receipt_sha256
            != publication_reservation_receipt_sha256(
                &self.request,
                &self.generation,
                &self.trust,
            )?
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationPublicationPayload {
    pub(crate) schema_version: String,
    pub(crate) signature_domain: String,
    pub(crate) signature_algorithm: String,
    pub(crate) canonicalization_profile: String,
    pub(crate) status: String,
    pub(crate) request: PublicationRequestBinding,
    pub(crate) preparation_envelope_sha256: Sha256Digest,
    pub(crate) generation: PublicationGenerationBinding,
    pub(crate) custody: PublicationCustodyBinding,
    pub(crate) runtime: PublicationRuntimeBinding,
    pub(crate) trust: PublicationTrustBinding,
    pub(crate) attestation_chain: PublicationAttestationChain,
    pub(crate) external_record_sha256: Sha256Digest,
    pub(crate) durable_commit_receipt_sha256: Sha256Digest,
    pub(crate) not_before_unix_nanos: i64,
    pub(crate) issued_at_unix_nanos: i64,
    pub(crate) expires_at_unix_nanos: i64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationPublicationExternalRecord {
    pub(crate) request_id: String,
    pub(crate) replay_id: String,
    pub(crate) management_handoff_id: String,
    pub(crate) request_payload_sha256: Sha256Digest,
    pub(crate) management_handoff_identity_sha256: Sha256Digest,
    pub(crate) candidate_id: Sha256Digest,
    pub(crate) canary_id: Sha256Digest,
    pub(crate) assignment_sha256: Sha256Digest,
    pub(crate) assignment_payload_sha256: Sha256Digest,
    pub(crate) assignment_revision: u64,
    pub(crate) generation_epoch: u64,
    pub(crate) minimum_generation_tombstone_epoch: u64,
    pub(crate) fleet_id: Sha256Digest,
    pub(crate) fleet_membership_revision: u64,
    pub(crate) membership_root_sha256: Sha256Digest,
    pub(crate) member_ordinal: u64,
    pub(crate) member_id: Sha256Digest,
    pub(crate) instance_id: String,
    pub(crate) boot_id_sha256: Sha256Digest,
    pub(crate) load_receipt_sha256: Sha256Digest,
    pub(crate) load_receipt_payload_sha256: Sha256Digest,
    pub(crate) generation_id: Sha256Digest,
    pub(crate) publication_revision: u64,
    pub(crate) custody_preparation_receipt_sha256: Sha256Digest,
    pub(crate) custody_high_water_sha256: Sha256Digest,
    pub(crate) custody_sequence: u64,
    pub(crate) ingress_high_water_sha256: Sha256Digest,
    pub(crate) ingress_sequence: u64,
    pub(crate) active_policy_sha256: Sha256Digest,
    pub(crate) active_policy_sequence: u64,
    pub(crate) active_rollback_epoch: u64,
    pub(crate) active_policy_bundle_sha256: Sha256Digest,
    pub(crate) candidate_policy_sha256: Sha256Digest,
    pub(crate) candidate_policy_sequence: u64,
    pub(crate) candidate_rollback_epoch: u64,
    pub(crate) candidate_policy_bundle_sha256: Sha256Digest,
    pub(crate) runtime_executable_sha256: Sha256Digest,
    pub(crate) runtime_release_sha256: Sha256Digest,
    pub(crate) runtime_config_sha256: Sha256Digest,
    pub(crate) runtime_policy_sha256: Sha256Digest,
    pub(crate) attestation_policy_sha256: Sha256Digest,
    pub(crate) attestation_trust_checkpoint_sha256: Sha256Digest,
    pub(crate) runtime_attestation_receipt_sha256: Sha256Digest,
    pub(crate) runtime_attestation_payload_sha256: Sha256Digest,
    pub(crate) runtime_attestation_verification_receipt_sha256: Sha256Digest,
    pub(crate) attestation_role_authorization_sha256: Sha256Digest,
    pub(crate) attestation_evidence_sha256: Sha256Digest,
    pub(crate) tee_measurement_sha256: Sha256Digest,
    pub(crate) attestation_chain_sha256: Sha256Digest,
    pub(crate) attestation_mode: String,
    pub(crate) hardware_attested: bool,
    pub(crate) generation_evidence: GenerationPublicationPayload,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationPublicationExternalPayload {
    pub(crate) issued_at_epoch_ns: i64,
    pub(crate) expires_at_epoch_ns: i64,
    pub(crate) record: GenerationPublicationExternalRecord,
}

impl EnvelopePayload for GenerationPublicationExternalPayload {
    const API_VERSION: &'static str = INSTALL_RECEIPT_API_VERSION;
    const KIND: &'static str = INSTALL_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.assignment_revision == 0
            || self.record.generation_epoch == 0
            || self.record.minimum_generation_tombstone_epoch == 0
            || self.record.fleet_membership_revision == 0
            || self.record.member_ordinal == 0
            || self.record.publication_revision == 0
            || self.record.active_policy_sequence == 0
            || self.record.active_rollback_epoch == 0
            || self.record.candidate_policy_sequence == 0
            || self.record.candidate_rollback_epoch == 0
            || !bounded_ascii_token(
                &self.record.request_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || !matches!(
                self.record.attestation_mode.as_str(),
                "aws-nitro-enclave"
                    | "amd-sev-snp"
                    | "intel-tdx"
                    | "trusted-host-no-tee"
            )
            || self.record.hardware_attested
                == (self.record.attestation_mode
                    == "trusted-host-no-tee")
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}

impl EnvelopePayload for GenerationPublicationPayload {
    const API_VERSION: &'static str = INSTALL_RECEIPT_API_VERSION;
    const KIND: &'static str = INSTALL_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_publication_common(
            &self.schema_version,
            Self::API_VERSION,
            &self.signature_domain,
            Self::SIGNATURE_DOMAIN,
            &self.signature_algorithm,
            &self.canonicalization_profile,
            &self.status,
            "published",
            &self.request,
            &self.generation,
            &self.runtime,
            &self.trust,
            &self.attestation_chain,
            self.not_before_unix_nanos,
            self.issued_at_unix_nanos,
            self.expires_at_unix_nanos,
        )?;
        if self.custody.publication_revision == 0
            || self.custody.publication_revision
                != self.generation.signed_publication_revision
            || self.durable_commit_receipt_sha256
                != publication_commit_receipt_sha256(
                    &self.request,
                    &self.preparation_envelope_sha256,
                    &self.generation,
                    &self.custody,
                    &self.trust,
                )?
            || self.preparation_envelope_sha256.as_str().is_empty()
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}


#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationHandoffResponse {
    pub(crate) api_version: String,
    pub(crate) operation: String,
    pub(crate) status: String,
    pub(crate) preparation:
        Option<SignedEnvelope<GenerationPublicationPreparationPayload>>,
    pub(crate) internal_publication:
        Option<SignedEnvelope<GenerationPublicationPayload>>,
    pub(crate) publication:
        Option<SignedEnvelope<GenerationPublicationExternalPayload>>,
}

pub(crate) struct GenerationInstallError {
    pub(crate) status: &'static str,
    pub(crate) code: &'static str,
    pub(crate) detail: String,
}

impl GenerationInstallError {
    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Self {
            status: "422 Unprocessable Entity",
            code: "policy_shadow_generation_invalid",
            detail: detail.into(),
        }
    }

    pub(crate) fn conflict(detail: impl Into<String>) -> Self {
        Self {
            status: "409 Conflict",
            code: "policy_shadow_generation_conflict",
            detail: detail.into(),
        }
    }

    pub(crate) fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: "503 Service Unavailable",
            code: "policy_shadow_generation_unavailable",
            detail: detail.into(),
        }
    }

    pub(crate) fn status(&self) -> &'static str {
        self.status
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn detail_sha256(&self) -> String {
        sha256_prefixed(self.detail.as_bytes())
    }
}


pub(crate) fn startup_attestation_handoff_chain_sha256(
    handoff: &RuntimeAttestationHandoff,
    assignment_payload_sha256: &Sha256Digest,
    load_receipt_payload_sha256: &Sha256Digest,
    runtime_identity_sha256: &Sha256Digest,
    attestation_policy_sha256: &Sha256Digest,
) -> Result<Sha256Digest, String> {
    domain_digest(
        b"catchplate.policyShadowRuntimeAttestationEvidenceChain/v1",
        &(
            STARTUP_ATTESTATION_HANDOFF_API_VERSION,
            &handoff.receipt_id,
            handoff.receipt_revision,
            &handoff.receipt_sha256,
            &handoff.receipt_payload_sha256,
            &handoff.role_authorization_id,
            handoff.role_authorization_revision,
            &handoff.role_authorization_sha256,
            &handoff.role_authorization_payload_sha256,
            &handoff.evidence,
            assignment_payload_sha256,
            load_receipt_payload_sha256,
            runtime_identity_sha256,
            attestation_policy_sha256,
        ),
    )
}


pub(crate) fn framed_domain_digest(
    domain: &[u8],
    frames: &[&[u8]],
) -> Sha256Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for frame in frames {
        bytes.extend_from_slice(
            &u64::try_from(frame.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(frame);
    }
    Sha256Digest::compute(&bytes)
}

pub(crate) fn generation_publication_high_water_digests(
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    custody: &PublicationCustodyBinding,
    role: &ShadowRoleAuthorizationRecord,
) -> Result<(Sha256Digest, Sha256Digest), GenerationInstallError> {
    let custody_value = json!({
        "assignmentSha256":generation.assignment_envelope_sha256,
        "bootIdSha256":generation.runtime_boot_id_sha256,
        "canaryId":role.canary_id,
        "custodyPreparationReceiptSha256":
            custody.preparation_receipt_sha256,
        "custodySequence":
            custody.authoritative_ledger_event_ordinal,
        "generationId":generation.generation_id,
        "instanceId":role.instance_id,
        "memberOrdinal":role.member_ordinal,
    });
    let custody_bytes = canonical_json_bytes(&custody_value)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let custody_high_water_sha256 = framed_domain_digest(
        b"catchplate.policyShadowCustodyPublicationHighWater/v1",
        &[&custody_bytes],
    );
    let ingress_sequence = generation
        .ingress_range_start_sequence
        .checked_sub(1)
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "generation ingress range has no predecessor sequence",
            )
        })?;
    let ingress_value = json!({
        "assignmentSha256":generation.assignment_envelope_sha256,
        "bootIdSha256":generation.runtime_boot_id_sha256,
        "canaryId":role.canary_id,
        "custodyHighWaterSha256":custody_high_water_sha256,
        "generationId":generation.generation_id,
        "ingressSequence":ingress_sequence,
        "instanceId":role.instance_id,
        "memberOrdinal":role.member_ordinal,
    });
    let ingress_bytes = canonical_json_bytes(&ingress_value)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let ingress_high_water_sha256 = framed_domain_digest(
        b"catchplate.policyShadowIngressPublicationHighWater/v1",
        &[&ingress_bytes],
    );
    if custody.authoritative_ledger_head_sha256
            != custody_high_water_sha256
        || generation.ingress_range_predecessor_head_sha256
            != ingress_high_water_sha256
        || request.request_sha256.as_str().is_empty()
    {
        return Err(GenerationInstallError::conflict(
            "custody or ingress publication high-water evidence is not exact",
        ));
    }
    Ok((
        custody_high_water_sha256,
        ingress_high_water_sha256,
    ))
}

pub(crate) fn publication_attestation_chain_sha256(
    payload: &GenerationPublicationPayload,
) -> Result<Sha256Digest, GenerationInstallError> {
    let chain_bytes = canonical_json_bytes(&payload.attestation_chain)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let binding = json!({
        "attestationRoleAuthorizationSha256":
            payload
                .attestation_chain
                .startup_attestation
                .role_authorization_sha256,
        "runtimeAttestationPayloadSha256":
            payload
                .attestation_chain
                .startup_attestation
                .receipt_payload_sha256,
        "runtimeAttestationReceiptSha256":
            payload
                .attestation_chain
                .startup_attestation
                .receipt_sha256,
        "runtimeAttestationVerificationReceiptSha256":
            payload
                .attestation_chain
                .runtime_attestation_verification_envelope_sha256,
        "signingKeySpkiSha256":
            payload.trust.publication_signing_key_spki_sha256,
    });
    let binding_bytes = canonical_json_bytes(&binding)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    Ok(framed_domain_digest(
        b"catchplate.policyShadowRuntimeAttestationChain/v1",
        &[&chain_bytes, &binding_bytes],
    ))
}

pub(crate) fn generation_publication_external_record(
    request: &PublicationRequestBinding,
    startup_attestation: &RuntimeAttestationHandoff,
    payload: &GenerationPublicationPayload,
    active_policy_bundle_sha256: &Sha256Digest,
    candidate_policy_bundle_sha256: &Sha256Digest,
) -> Result<
    GenerationPublicationExternalRecord,
    GenerationInstallError,
> {
    let role = &startup_attestation
        .role_authorization
        .untrusted_payload()
        .record;
    if payload.request != *request
        || payload.generation.active_policy_bundle_sha256
            != *active_policy_bundle_sha256
        || payload.generation.candidate_policy_bundle_sha256
            != *candidate_policy_bundle_sha256
    {
        return Err(GenerationInstallError::conflict(
            "external publication inputs diverge from generation evidence",
        ));
    }
    let (custody_high_water_sha256, ingress_high_water_sha256) =
        generation_publication_high_water_digests(
            request,
            &payload.generation,
            &payload.custody,
            role,
        )?;
    let ingress_sequence = payload
        .generation
        .ingress_range_start_sequence
        .checked_sub(1)
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "generation ingress range has no predecessor sequence",
            )
        })?;
    let attestation_chain_sha256 =
        publication_attestation_chain_sha256(payload)?;
    Ok(GenerationPublicationExternalRecord {
        request_id: request.request_id.clone(),
        replay_id: request.replay_id.clone(),
        management_handoff_id:
            request.management_handoff_id.clone(),
        request_payload_sha256: request.request_sha256.clone(),
        management_handoff_identity_sha256:
            request.management_handoff_sha256.clone(),
        candidate_id: role.candidate_id.clone(),
        canary_id: role.canary_id.clone(),
        assignment_sha256: payload
            .generation
            .assignment_envelope_sha256
            .clone(),
        assignment_payload_sha256: payload
            .generation
            .assignment_payload_sha256
            .clone(),
        assignment_revision:
            payload.generation.assignment_revision,
        generation_epoch: payload.generation.generation_epoch,
        minimum_generation_tombstone_epoch: payload
            .generation
            .minimum_generation_tombstone_epoch,
        fleet_id: role.fleet_id.clone(),
        fleet_membership_revision:
            role.fleet_membership_revision,
        membership_root_sha256:
            role.membership_root_sha256.clone(),
        member_ordinal: role.member_ordinal,
        member_id: role.member_id.clone(),
        instance_id: role.instance_id.clone(),
        boot_id_sha256: role.boot_id_sha256.clone(),
        load_receipt_sha256: payload
            .generation
            .load_receipt_envelope_sha256
            .clone(),
        load_receipt_payload_sha256: payload
            .generation
            .load_receipt_payload_sha256
            .clone(),
        generation_id: payload.generation.generation_id.clone(),
        publication_revision:
            payload.custody.publication_revision,
        custody_preparation_receipt_sha256: payload
            .custody
            .preparation_receipt_sha256
            .clone(),
        custody_high_water_sha256,
        custody_sequence: payload
            .custody
            .authoritative_ledger_event_ordinal,
        ingress_high_water_sha256,
        ingress_sequence,
        active_policy_sha256:
            payload.generation.active.policy_sha256.clone(),
        active_policy_sequence:
            payload.generation.active.policy_sequence,
        active_rollback_epoch:
            payload.generation.active.rollback_epoch,
        active_policy_bundle_sha256:
            active_policy_bundle_sha256.clone(),
        candidate_policy_sha256:
            payload.generation.candidate.policy_sha256.clone(),
        candidate_policy_sequence:
            payload.generation.candidate.policy_sequence,
        candidate_rollback_epoch:
            payload.generation.candidate.rollback_epoch,
        candidate_policy_bundle_sha256:
            candidate_policy_bundle_sha256.clone(),
        runtime_executable_sha256: payload
            .runtime
            .decision_gate_executable_sha256
            .clone(),
        runtime_release_sha256:
            payload.runtime.release_provenance_sha256.clone(),
        runtime_config_sha256: payload
            .runtime
            .runtime_configuration_sha256
            .clone(),
        runtime_policy_sha256:
            payload.runtime.runtime_policy_sha256.clone(),
        attestation_policy_sha256: payload
            .trust
            .runtime_attestation_policy_sha256
            .clone(),
        attestation_trust_checkpoint_sha256:
            payload.trust.trust_checkpoint_sha256.clone(),
        runtime_attestation_receipt_sha256:
            startup_attestation.receipt_sha256.clone(),
        runtime_attestation_payload_sha256:
            startup_attestation.receipt_payload_sha256.clone(),
        runtime_attestation_verification_receipt_sha256: payload
            .attestation_chain
            .runtime_attestation_verification_envelope_sha256
            .clone(),
        attestation_role_authorization_sha256:
            startup_attestation.role_authorization_sha256.clone(),
        attestation_evidence_sha256:
            startup_attestation.evidence.evidence_sha256.clone(),
        tee_measurement_sha256:
            role.tee_measurement_sha256.clone(),
        attestation_chain_sha256,
        attestation_mode:
            payload.attestation_chain.attestation_mode.clone(),
        hardware_attested:
            payload.attestation_chain.hardware_attested,
        generation_evidence: payload.clone(),
    })
}

pub(crate) fn external_record_projection_sha256(
    record: &GenerationPublicationExternalRecord,
) -> Result<Sha256Digest, GenerationInstallError> {
    let mut value = serde_json::to_value(record).map_err(|error| {
        GenerationInstallError::invalid(error.to_string())
    })?;
    let fields = value.as_object_mut().ok_or_else(|| {
        GenerationInstallError::invalid(
            "external publication record is not an object",
        )
    })?;
    if fields.remove("generationEvidence").is_none() {
        return Err(GenerationInstallError::invalid(
            "external publication record omitted generation evidence",
        ));
    }
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        GenerationInstallError::invalid(error.to_string())
    })?;
    Ok(Sha256Digest::compute(&canonical))
}

pub(crate) fn verify_external_publication_record(
    record: &GenerationPublicationExternalRecord,
    payload: &GenerationPublicationPayload,
) -> Result<(), GenerationInstallError> {
    let expected = generation_publication_external_record(
        &payload.request,
        &payload.attestation_chain.startup_attestation,
        payload,
        &payload.generation.active_policy_bundle_sha256,
        &payload.generation.candidate_policy_bundle_sha256,
    )?;
    if record != &expected
        || payload.external_record_sha256
            != external_record_projection_sha256(record)?
    {
        return Err(GenerationInstallError::conflict(
            "external publication record is not the exact authenticated projection",
        ));
    }
    Ok(())
}

pub(crate) fn publication_reservation_receipt_sha256(
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    trust: &PublicationTrustBinding,
) -> Result<Sha256Digest, ShadowError> {
    domain_digest(
        b"catchplate.policyShadowGenerationDurableReplayReservation/v1",
        &(
            request,
            &generation.generation_id,
            generation.assignment_revision,
            &trust.publication_replay_store_sha256,
            trust.replay_store_revision,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "durable replay reservation digest failed",
        )
    })
}

pub(crate) fn publication_commit_receipt_sha256(
    request: &PublicationRequestBinding,
    preparation_envelope_sha256: &Sha256Digest,
    generation: &PublicationGenerationBinding,
    custody: &PublicationCustodyBinding,
    trust: &PublicationTrustBinding,
) -> Result<Sha256Digest, ShadowError> {
    domain_digest(
        b"catchplate.policyShadowGenerationDurableReplayCommit/v1",
        &(
            request,
            preparation_envelope_sha256,
            &generation.generation_id,
            generation.assignment_revision,
            custody,
            &trust.publication_replay_store_sha256,
            trust.replay_store_revision,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "durable replay commit digest failed",
        )
    })
}


#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_publication_common(
    schema_version: &str,
    expected_schema_version: &str,
    signature_domain: &str,
    expected_signature_domain: &str,
    signature_algorithm: &str,
    canonicalization_profile: &str,
    status: &str,
    expected_status: &str,
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    runtime: &PublicationRuntimeBinding,
    trust: &PublicationTrustBinding,
    attestation_chain: &PublicationAttestationChain,
    not_before_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
) -> Result<(), ShadowError> {
    let startup_attestation =
        &attestation_chain.startup_attestation;
    let evidence = &startup_attestation.evidence;
    let evidence_bytes = canonical_json_bytes(&evidence.evidence)?;
    let expected_handoff_sha256 = domain_digest(
        b"catchplate.policyShadowGenerationManagementHandoff/v1",
        &(
            request.request_id.as_str(),
            request.replay_id.as_str(),
            request.management_handoff_id.as_str(),
            &request.request_sha256,
            &runtime.runtime_identity_sha256,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "management handoff digest failed",
        )
    })?;
    let verification_envelope_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(
            &attestation_chain.runtime_attestation_verification,
        )?,
    );
    let verification = attestation_chain
        .runtime_attestation_verification
        .untrusted_payload();
    if schema_version != expected_schema_version
        || signature_domain != expected_signature_domain
        || signature_algorithm != SIGNATURE_ALGORITHM
        || canonicalization_profile != CANONICAL_PROFILE
        || status != expected_status
        || !bounded_ascii_token(
            &request.request_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || !bounded_ascii_token(
            &request.replay_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || !bounded_ascii_token(
            &request.management_handoff_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || request.request_id == request.replay_id
        || request.request_id == request.management_handoff_id
        || request.replay_id == request.management_handoff_id
        || request.management_handoff_sha256
            != expected_handoff_sha256
        || generation.generation_epoch == 0
        || generation.minimum_generation_tombstone_epoch == 0
        || generation.generation_tombstone_epoch == 0
        || generation.generation_tombstone_epoch
            > generation.generation_epoch
        || generation.generation_tombstone_epoch
            < generation.minimum_generation_tombstone_epoch
        || generation.assignment_revision == 0
        || generation.active.policy_sequence == 0
        || generation.active.rollback_epoch == 0
        || generation.candidate.policy_sequence
            <= generation.active.policy_sequence
        || generation.candidate.rollback_epoch == 0
        || generation.request_commitment_key_epoch == 0
        || generation.ingress_range_start_sequence == 0
        || generation.signed_publication_revision == 0
        || runtime.runtime_instance_id.is_empty()
        || runtime.runtime_boot_id_sha256
            != generation.runtime_boot_id_sha256
        || runtime.request_facts_schema_sha256
            != generation.request_facts_schema_sha256
        || trust.revocation_generation == 0
        || trust.replay_store_revision == 0
        || trust.replay_store_revision
            != generation.assignment_revision
        || evidence.api_version != RUNTIME_EVIDENCE_API_VERSION
        || evidence_bytes.is_empty()
        || evidence_bytes.len() > MAX_RUNTIME_EVIDENCE_BYTES
        || Sha256Digest::compute(&evidence_bytes)
            != evidence.evidence_sha256
        || verification.attestation_mode
            != attestation_chain.attestation_mode
        || verification.hardware_attested
            != attestation_chain.hardware_attested
        || verification.runtime_identity_sha256
            != runtime.runtime_identity_sha256
        || verification.runtime_executable_sha256
            != runtime.decision_gate_executable_sha256
        || verification.runtime_release_sha256
            != runtime.release_provenance_sha256
        || verification.runtime_config_sha256
            != runtime.runtime_configuration_sha256
        || verification.runtime_policy_sha256
            != runtime.runtime_policy_sha256
        || runtime.runtime_policy_sha256
            != generation.active.policy_sha256
        || verification.assignment_payload_sha256
            != generation.assignment_payload_sha256
        || verification.load_receipt_payload_sha256
            != generation.load_receipt_payload_sha256
        || verification_envelope_sha256
            != attestation_chain
                .runtime_attestation_verification_envelope_sha256
        || verification.evidence_chain_sha256
            != startup_attestation_handoff_chain_sha256(
                startup_attestation,
                &generation.assignment_payload_sha256,
                &generation.load_receipt_payload_sha256,
                &runtime.runtime_identity_sha256,
                &trust.runtime_attestation_policy_sha256,
            )
            .map_err(|_| {
                ShadowError::CanonicalizationFailure(
                    "runtime attestation evidence chain failed",
                )
            })?
        || issued_at_unix_nanos <= 0
        || not_before_unix_nanos != issued_at_unix_nanos
        || expires_at_unix_nanos <= issued_at_unix_nanos
        || expires_at_unix_nanos
            .checked_sub(issued_at_unix_nanos)
            .is_none_or(|lifetime| {
                lifetime > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
            })
    {
        return Err(ShadowError::GenerationIdentityMismatch);
    }
    Ok(())
}


pub(crate) fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, String> {
    let canonical = canonical_json_bytes(value).map_err(shadow_error)?;
    let mut bytes = Vec::with_capacity(
        domain.len().saturating_add(1).saturating_add(canonical.len()),
    );
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(Sha256Digest::compute(&bytes))
}

pub(crate) fn bounded_ascii_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'@' | b'+' | b'-')
        })
}


pub(crate) fn shadow_error(error: ShadowError) -> String {
    error.to_string()
}
