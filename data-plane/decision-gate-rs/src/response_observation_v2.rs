//! Negotiated response-observation proof v2 source contract.
//!
//! This module is deliberately separate from the v1 implementation. It is a
//! pure contract and verifier: it has no network, filesystem, clock, RNG,
//! credential, dispatch, activation, or publication capability.
//!
//! Canonicalization is UTF-8 RFC 8785 JSON Canonicalization Scheme (JCS).
//! Catchplate additionally rejects duplicate object members before typed
//! decoding, rejects floating-point numbers, and limits every integer to the
//! interoperable range 0..=2^53-1. `canonical_jcs_bytes` implements that
//! profile for typed values; `serde_json::to_vec` is not canonicalization.
//! Signatures and digests use incrementally hashed, length-framed,
//! domain-separated messages. `domain_separated_preimage` is retained only for
//! narrowly bounded diagnostics and must not be used on production-size data.
//! Ed25519 evidence signatures cover the fixed 32-byte result of that streamed
//! hash, while the role, payload, and signature domains remain independently
//! pinned by the trusted verifier. Credential-authority keys are additionally
//! authorized for one exact authorityId and operation by an independently
//! pinned trust policy. Their closed typed results are accumulated into an
//! ordered causal state machine and root bound by dispatch, terminal, and
//! custody evidence. Signed route semantics bind one canonical HTTPS target,
//! and the verifier independently retrieves and parses the immutable staged
//! HTTP/1.1 bytes before accepting that target.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[path = "response_observation_v2_custody.rs"]
pub mod custody;
#[path = "response_v2/state_authority/mod.rs"]
pub mod state_authority;

pub const PROOF_API_VERSION: &str = "catchplate.responseObservationProof/v2";
pub const PROOF_KIND: &str = "CatchplateResponseObservationProof";
pub const ENVELOPE_API_VERSION: &str = "catchplate.responseObservationEnvelope/v2";
pub const ENVELOPE_KIND: &str = "CatchplateResponseObservationEnvelope";
pub const EVIDENCE_API_VERSION: &str = "catchplate.responseObservationEvidence/v2";
pub const LOCAL_RECONCILIATION_API_VERSION: &str =
    "catchplate.localCredentialReconciliation/v2";
pub const LOCAL_RECONCILIATION_KIND: &str =
    "CatchplateLocalCredentialReconciliation";
pub const LOCAL_RECONCILIATION_LEDGER_WITNESS_API_VERSION: &str =
    "catchplate.localReconciliationLedgerWitness/v2";
pub const LOCAL_RECONCILIATION_LEDGER_WITNESS_KIND: &str =
    "CatchplateLocalReconciliationLedgerWitness";
pub const JCS_PROFILE: &str = "RFC8785-JCS/catchplate-integers-and-unique-keys/v1";

const PREIMAGE_MAGIC: &[u8] = b"CATCHPLATE\0RESPONSE-OBSERVATION-V2\0SHA-256\0";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_EVIDENCE_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_RUNTIME_ATTESTATION_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_LOCAL_RECONCILIATION_DELAY_MS: u64 = 10 * 60 * 1000;
const MAX_PROOF_AGE_MS: u64 = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 5_000;
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCAL_RECONCILIATION_RECORD_BYTES: usize = 64 * 1024;
const MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES: usize = 128 * 1024;
const MAX_LOCAL_RECONCILIATION_WITNESS_BYTES: usize = 64 * 1024;
const MAX_LOCAL_RECONCILIATION_QUORUM_MEMBERS: usize = 32;
const MAX_LOCAL_RECONCILIATION_MERKLE_PATH: usize = 64;
const MAX_RESPONSE_ENTITY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_HEAD_CHAIN_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_TRAILER_BYTES: u64 = 256 * 1024;
const MAX_RESPONSE_CHUNK_FRAMING_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_PHYSICAL_BODY_BYTES: u64 = MAX_RESPONSE_ENTITY_BYTES
    + MAX_RESPONSE_TRAILER_BYTES
    + MAX_RESPONSE_CHUNK_FRAMING_BYTES;
const MAX_PHYSICAL_RESPONSE_BYTES: u64 =
    MAX_RESPONSE_HEAD_CHAIN_BYTES + MAX_RESPONSE_PHYSICAL_BODY_BYTES;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_CHUNK_COUNT: u32 = 65_536;
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
const MAX_HEADER_BYTES: u64 = 256 * 1024;
const MAX_HEADER_COUNT: u32 = 1_024;
const MAX_CANONICAL_AUTHORITY_BYTES: usize = 259;
const MAX_CANONICAL_PATH_BYTES: usize = 8 * 1024;
const MAX_PATH_AND_QUERY_BYTES: usize = 16 * 1024;
const MAX_QUERY_PARAMETERS: usize = 32;
const MAX_QUERY_NAME_BYTES: usize = 63;
const MAX_QUERY_VALUE_BYTES: usize = 191;
const MAX_LIFECYCLE_TRANSITIONS: usize = 16;
const MAX_DOMAIN_BYTES: usize = 128;
const MAX_DIGEST_FRAMES: usize = 16;
const MAX_DIGEST_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_DIGEST_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXPORTED_PREIMAGE_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_AUTHORITY_OPERATIONS: usize = 8;

const NONCE_DIGEST_DOMAIN: &str = "catchplate.response-observation-v2/nonce";
const ATTEMPT_ID_DOMAIN: &str = "catchplate.response-observation-v2/attempt-id";
const ROUTE_SEMANTIC_PROFILE_DOMAIN: &str =
    "catchplate.response-observation-v2/route-semantic-profile";
const AUTHORIZATION_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/authorization-binding";
const CREDENTIAL_AUTHORITY_EFFECT_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-effect";
const CREDENTIAL_AUTHORITY_RECORD_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-record";
const CREDENTIAL_AUTHORITY_PLAN_LEAF_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-plan-leaf";
const CREDENTIAL_AUTHORITY_PLAN_ROOT_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-plan-root";
const CREDENTIAL_AUTHORITY_EVIDENCE_LEAF_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-evidence-leaf";
const CREDENTIAL_AUTHORITY_EVIDENCE_ROOT_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-evidence-root";
const CREDENTIAL_AUTHORITY_TRANSITION_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-transition-id";
const CREDENTIAL_AUTHORITY_RECOVERY_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-recovery-binding";
const LOCAL_CREDENTIAL_RECOVERY_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/local-credential-recovery-binding";
const LOCAL_RECONCILIATION_RECORD_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-record";
const LOCAL_RECONCILIATION_RECORD_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-record-id";
const LOCAL_RECONCILIATION_RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-retrieval-id";
const LOCAL_RECONCILIATION_CONTINUITY_RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-continuity-retrieval-id";
const LOCAL_RECONCILIATION_LEDGER_WITNESS_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-ledger-witness";
const LOCAL_RECONCILIATION_LEDGER_WITNESS_RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-ledger-witness-retrieval-id";
const LOCAL_RECONCILIATION_PREDECESSOR_EVIDENCE_RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-predecessor-evidence-retrieval-id";
const LOCAL_RECONCILIATION_GENESIS_EVIDENCE_RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-genesis-evidence-retrieval-id";
const LOCAL_RECONCILIATION_STORE_STATE_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-store-state";
const LOCAL_RECONCILIATION_PINNED_GENESIS_STATE_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-pinned-genesis-state";
const LOCAL_RECONCILIATION_STORE_TRANSITION_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-store-transition";
const LOCAL_RECONCILIATION_QUORUM_MEMBER_SIGNATURE_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-quorum-member-signature";
const LOCAL_RECONCILIATION_QUORUM_CERTIFICATE_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-quorum-certificate";
const LOCAL_RECONCILIATION_TRANSPARENCY_LEAF_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-transparency-leaf";
const LOCAL_RECONCILIATION_PREDECESSOR_SUCCESSOR_KEY_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-predecessor-successor-key";
const LOCAL_RECONCILIATION_GENESIS_MARKER: &str = "GENESIS";
const LOCAL_RECONCILIATION_TRANSPARENCY_PROOF_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-transparency-proof";
const LOCAL_RECONCILIATION_TRANSPARENCY_CHECKPOINT_DOMAIN: &str =
    "catchplate.response-observation-v2/local-reconciliation-transparency-checkpoint";
const OAUTH_EFFECTIVE_STATE_DOMAIN: &str =
    "catchplate.response-observation-v2/oauth-effective-state";
const CREDENTIAL_AUTHORITY_INITIAL_STATE_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-initial-state";
const CREDENTIAL_AUTHORITY_EXECUTION_STATE_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-execution-state";
const CREDENTIAL_AUTHORITY_STATE_MACHINE_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-state-machine";
const CREDENTIAL_AUTHORITY_UNRESOLVED_RESERVATION_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-unresolved-reservation";
const CREDENTIAL_AUTHORITY_PLAN_STEP_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-plan-step";
const CREDENTIAL_AUTHORITY_SELECTED_PATH_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-selected-path";
const CREDENTIAL_AUTHORITY_EXTERNAL_FAILURE_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-authority-external-failure";
const CANONICAL_TARGET_DOMAIN: &str =
    "catchplate.response-observation-v2/canonical-upstream-target";
const STAGED_REQUEST_DOMAIN: &str =
    "catchplate.response-observation-v2/staged-target-request";
const STAGED_REQUEST_RETRIEVAL_DOMAIN: &str =
    "catchplate.response-observation-v2/staged-request-retrieval";
const REQUEST_OPERATION_SEMANTICS_DOMAIN: &str =
    "catchplate.response-observation-v2/request-operation-semantics";
const REQUEST_FRAMING_DOMAIN: &str =
    "catchplate.response-observation-v2/request-framing";
const CREDENTIAL_INJECTION_RESULT_DOMAIN: &str =
    "catchplate.response-observation-v2/credential-injection-result";
const POLICY_CREDENTIAL_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/policy-credential-binding";
const DISPATCH_AUTHORIZATION_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/dispatch-authorization-binding";
const PROVIDER_IDEMPOTENCY_PROFILE_DOMAIN: &str =
    "catchplate.response-observation-v2/provider-idempotency-profile";
const IDEMPOTENCY_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/provider-idempotency-binding";
const RECOVERY_KEY_DOMAIN: &str =
    "catchplate.response-observation-v2/ambiguous-outcome-recovery-key";
const READ_RETRY_BINDING_DOMAIN: &str =
    "catchplate.response-observation-v2/read-retry-binding";
const UPSTREAM_OBSERVATION_DOMAIN: &str =
    "catchplate.response-observation-v2/upstream-observation";
const UPSTREAM_RESPONSE_RETRIEVAL_DOMAIN: &str =
    "catchplate.response-observation-v2/upstream-response-retrieval";
const RESPONSE_POLICY_PROFILE_DOMAIN: &str =
    "catchplate.response-observation-v2/response-policy-profile";
const RESPONSE_POLICY_VALIDATION_DOMAIN: &str =
    "catchplate.response-observation-v2/response-policy-validation";
const FINAL_ENVELOPE_DOMAIN: &str =
    "catchplate.response-observation-v2/finalized-envelope";
const RETRIEVAL_ID_DOMAIN: &str =
    "catchplate.response-observation-v2/retrieval-identity";
const EVIDENCE_ENVELOPE_DOMAIN: &str =
    "catchplate.response-observation-v2/evidence-envelope";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub code: &'static str,
    pub path: &'static str,
    pub message: &'static str,
}

impl ContractError {
    const fn new(
        code: &'static str,
        path: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            path,
            message,
        }
    }
}

pub type ContractResult<T> = Result<T, ContractError>;

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseObservationProofV2 {
    pub api_version: String,
    pub kind: String,
    pub finalized_envelope: FinalizedEnvelopeV2,
    pub attestation: AttestationState,
    pub publication: PublicationState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedEnvelopeV2 {
    pub body: ResponseObservationEnvelopeBodyV2,
    pub identity: FinalizedEnvelopeIdentity,
    pub persistence_evidence: SignedEvidence<PersistenceEvidencePayload>,
    pub finalization_checkpoint_evidence:
        SignedEvidence<FinalizationCheckpointEvidencePayload>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseObservationEnvelopeBodyV2 {
    pub api_version: String,
    pub kind: String,
    pub attempt_id: String,
    pub issued_at_epoch_ms: u64,
    pub runtime: BootRuntimeIdentity,
    pub nonce: NonceBinding,
    pub policy: PolicyBinding,
    pub route_semantic_profile_evidence:
        SignedEvidence<RouteSemanticProfileEvidencePayload>,
    pub authorization: AuthorizationState,
    pub credential: CredentialState,
    pub credential_authority_side_effect: CredentialAuthoritySideEffect,
    pub credential_authority_evidence:
        Vec<SignedEvidence<CredentialAuthorityEvidencePayload>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_state_machine:
        Option<CredentialAuthorityStateMachineSummary>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub local_reconciliation_continuity_evidence:
        Option<SignedEvidence<LocalReconciliationContinuityEvidencePayload>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub local_reconciliation_ledger_witness_evidence:
        Option<SignedEvidence<LocalReconciliationLedgerWitness>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub local_reconciliation_genesis_absence_evidence:
        Option<SignedEvidence<LocalReconciliationGenesisAbsenceEvidencePayload>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub local_reconciliation_recovery_evidence:
        Option<SignedEvidence<LocalReconciliationRecoveryEvidencePayload>>,
    pub route_semantics: RouteSemantics,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub durable_recovery_seal_evidence:
        Option<SignedEvidence<DurableRecoverySealPayload>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub staged_target_request: Option<StagedTargetRequest>,
    pub target_egress: TargetEgressState,
    pub upstream_observation: UpstreamObservationState,
    pub lifecycle: Vec<LifecycleTransition>,
    pub authority: ObservationAuthority,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub reserve_evidence: Option<SignedEvidence<ReserveEvidencePayload>>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub dispatch_evidence: Option<SignedEvidence<DispatchEvidencePayload>>,
    pub terminal_evidence: SignedEvidence<TerminalEvidencePayload>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub custody_authority_evidence:
        Option<SignedEvidence<CustodyAuthorityEvidencePayload>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootRuntimeIdentity {
    pub boot_id: String,
    pub runtime_instance_id: String,
    pub runtime_measurement_sha256: String,
    pub release_sha256: String,
    pub data_plane_binary_sha256: String,
    pub rollback_state_epoch: u64,
    pub rollback_state_head_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NonceBinding {
    pub client_nonce: String,
    pub nonce_sha256: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyPrerequisites {
    pub authority_plan: AuthorityPrerequisitePlan,
    pub idempotency: PolicyIdempotencyPrerequisite,
    pub response_validation: PolicyResponseValidationPrerequisite,
    pub prerequisites_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyCredentialIdentity {
    pub source: PolicyCredentialSource,
    pub provider_id: String,
    pub account_id: String,
    pub credential_ref: String,
    pub credential_version: u64,
    pub credential_generation: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub local_acquisition_uncertain_side_effect:
        Option<LocalAcquisitionUncertainSideEffect>,
    pub credential_binding_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyCredentialSource {
    AuthorityPlan,
    LocalCredential,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityPlanMode {
    None,
    Required,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPrerequisitePlan {
    pub mode: AuthorityPlanMode,
    pub primary_steps: Vec<AuthorityPrerequisiteStep>,
    pub cleanup_steps: Vec<AuthorityPrerequisiteStep>,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPrerequisiteStep {
    pub sequence: u8,
    pub authority_id: String,
    pub operation: CredentialAuthorityOperation,
    pub constraint: AuthorityPrerequisiteConstraint,
    pub prerequisite_sha256: String,
    pub step_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "family",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorityPrerequisiteConstraint {
    Grant {
        grant_id: String,
        approval_id: String,
        reservation_id: String,
        maximum_use_count: u64,
        webauthn_required: bool,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        webauthn_approval: Option<WebAuthnApprovalIdentity>,
    },
    QuotaBudget {
        counter_id: String,
        budget_id: String,
        window_start_epoch_ms: u64,
        window_end_epoch_ms: u64,
        reservation_id: String,
        reservation_expires_at_epoch_ms: u64,
        units: u64,
        weight_basis_sha256: String,
    },
    Credential {
        provider_id: String,
        account_id: String,
        credential_ref: String,
        credential_version: u64,
        credential_generation: u64,
        lease_id: String,
        lease_release_id: String,
        authorization_receipt_id: String,
        expires_at_epoch_ms: u64,
        credential_injection_template_sha256: String,
    },
    Oauth {
        provider_authority_id: String,
        subject_id: String,
        account_id: String,
        client_id: String,
        app_id: String,
        credential_ref: String,
        credential_version: u64,
        granted_scope_root_sha256: String,
        prior_token_generation: u64,
        new_token_generation: u64,
        output_generation_rule: OauthOutputGenerationRule,
        credential_binding_sha256: String,
        request_sha256: String,
        operation_sha256: String,
        authorization_binding_sha256: String,
        prior_state_sha256: String,
        provider_request_id: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        provider_idempotency_key_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "requirement",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyIdempotencyPrerequisite {
    Required {
        provider_profile: ProviderIdempotencyProfile,
    },
    NotRequired,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "requirement",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyResponseValidationPrerequisite {
    Required {
        profile: ResponsePolicyProfile,
    },
    NotRequired,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "decision",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyBinding {
    Denied {
        policy_sha256: String,
        snapshot_epoch: u64,
        request_sha256: String,
        operation_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        principal_id: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        route_id: Option<String>,
        reason: PolicyDenialReason,
    },
    Allowed {
        policy_sha256: String,
        snapshot_epoch: u64,
        request_sha256: String,
        operation_sha256: String,
        principal_id: String,
        route_id: String,
        credential_mode: PolicyCredentialMode,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_identity: Option<PolicyCredentialIdentity>,
        valid_from_epoch_ms: u64,
        valid_until_epoch_ms: u64,
        prerequisites: PolicyPrerequisites,
    },
}

impl PolicyBinding {
    fn policy_sha256(&self) -> &str {
        match self {
            Self::Denied { policy_sha256, .. } | Self::Allowed { policy_sha256, .. } => {
                policy_sha256
            }
        }
    }

    fn request_sha256(&self) -> &str {
        match self {
            Self::Denied { request_sha256, .. } | Self::Allowed { request_sha256, .. } => {
                request_sha256
            }
        }
    }

    fn operation_sha256(&self) -> &str {
        match self {
            Self::Denied {
                operation_sha256, ..
            }
            | Self::Allowed {
                operation_sha256, ..
            } => operation_sha256,
        }
    }

    fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    fn snapshot_epoch(&self) -> u64 {
        match self {
            Self::Denied { snapshot_epoch, .. }
            | Self::Allowed { snapshot_epoch, .. } => *snapshot_epoch,
        }
    }

    fn route_id(&self) -> Option<&str> {
        match self {
            Self::Denied { route_id, .. } => route_id.as_deref(),
            Self::Allowed { route_id, .. } => Some(route_id.as_str()),
        }
    }

    fn credential_mode(&self) -> Option<PolicyCredentialMode> {
        match self {
            Self::Denied { .. } => None,
            Self::Allowed {
                credential_mode, ..
            } => Some(*credential_mode),
        }
    }

    fn credential_identity(&self) -> Option<&PolicyCredentialIdentity> {
        match self {
            Self::Denied { .. } => None,
            Self::Allowed {
                credential_identity,
                ..
            } => credential_identity.as_ref(),
        }
    }

    fn prerequisites(&self) -> Option<&PolicyPrerequisites> {
        match self {
            Self::Denied { .. } => None,
            Self::Allowed { prerequisites, .. } => Some(prerequisites),
        }
    }

    fn validity_window(&self) -> Option<(u64, u64)> {
        match self {
            Self::Denied { .. } => None,
            Self::Allowed {
                valid_from_epoch_ms,
                valid_until_epoch_ms,
                ..
            } => Some((*valid_from_epoch_ms, *valid_until_epoch_ms)),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyDenialReason {
    UnknownPrincipal,
    UnknownRoute,
    MethodDenied,
    EndpointDenied,
    ConstraintDenied,
    IdempotencyUnavailable,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyCredentialMode {
    Required,
    NotRequiredReadOnly,
    NotRequiredCredentialless,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorizationState {
    DeniedBeforeReserve {
        terminal_evidence_sha256: String,
    },
    ReservedCancelled {
        reserve_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    DispatchCancelled {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    DispatchCompleted {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    DispatchResponseRejected {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    DispatchExactResponseUnsupported {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    WriteDispatchTransitionUnknown {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
    ReadDispatchTransitionUnknown {
        reserve_evidence_sha256: String,
        dispatch_evidence_sha256: String,
        terminal_evidence_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialState {
    NotEvaluated {
        reason: CredentialNotEvaluatedReason,
    },
    NotRequired {
        exception: CredentialException,
    },
    AcquisitionFailed {
        credential_binding_sha256: String,
        failure: CredentialAcquisitionFailure,
    },
    AcquisitionOutcomeUnknown {
        credential_binding_sha256: String,
        recovery_binding_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation: Option<LocalAcquisitionReconciliation>,
    },
    AcquiredNotInjected {
        credential_binding_sha256: String,
        reason: CredentialNotInjectedReason,
    },
    InjectionFailed {
        credential_binding_sha256: String,
        failure: CredentialFailure,
        attempted_request: AttemptedStagedRequest,
    },
    InjectionOutcomeUnknown {
        credential_binding_sha256: String,
        recovery_binding_sha256: String,
        attempted_request: AttemptedStagedRequest,
    },
    Injected {
        credential_binding_sha256: String,
        staged_request_sha256: String,
        injection_result_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AttemptedStagedRequest {
    Produced {
        credential_binding_sha256: String,
        staged_request_sha256: String,
        injection_result_sha256: String,
    },
    NotProduced {
        credential_binding_sha256: String,
        reason: AttemptedRequestNotProducedReason,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptedRequestNotProducedReason {
    RejectedBeforeImmutableBytes,
    AuthorityOutcomeUnknownBeforeImmutableBytes,
}

impl CredentialState {
    fn binding_sha256(&self) -> Option<&str> {
        match self {
            Self::AcquisitionFailed {
                credential_binding_sha256,
                ..
            }
            | Self::AcquisitionOutcomeUnknown {
                credential_binding_sha256,
                ..
            }
            | Self::AcquiredNotInjected {
                credential_binding_sha256,
                ..
            }
            | Self::InjectionFailed {
                credential_binding_sha256,
                ..
            }
            | Self::InjectionOutcomeUnknown {
                credential_binding_sha256,
                ..
            }
            | Self::Injected {
                credential_binding_sha256,
                ..
            } => Some(credential_binding_sha256),
            Self::NotEvaluated { .. } | Self::NotRequired { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialNotEvaluatedReason {
    PolicyDenied,
    AuthorizationDenied,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialException {
    ReadOnlyNoCredential,
    CredentiallessReadOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFailure {
    LeaseUnavailable,
    LeaseDecryptionFailed,
    CredentialExpired,
    AuthorityDenied,
    AuthorityUnavailable,
    InjectionRejected,
    BindingMismatch,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "source",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialAcquisitionFailure {
    LocalCredential {
        reason: LocalAcquisitionFailure,
    },
    CredentialAuthority {
        failure: CredentialAuthorityFailure,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAcquisitionFailure {
    Missing,
    Expired,
    Unreadable,
    DecryptionFailed,
    UnsealFailed,
    StorageUnavailable,
    Invalid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalAcquisitionReconciliation {
    pub record_id: String,
    pub record_sha256: String,
    pub record_byte_length: u64,
    pub retrieval_id: String,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub continuity_evidence_sha256: String,
    pub continuity_evidence_byte_length: u64,
    pub continuity_evidence_retrieval_id: String,
    pub continuity_persistence_receipt_sha256: String,
    pub continuity_retrieval_proof_sha256: String,
    pub ledger_witness_sha256: String,
    pub ledger_witness_byte_length: u64,
    pub ledger_witness_retrieval_id: String,
    pub ledger_witness_persistence_receipt_sha256: String,
    pub ledger_witness_retrieval_proof_sha256: String,
    pub predecessor_proof_sha256: String,
    pub store_transition_sha256: String,
    pub quorum_certificate_sha256: String,
    pub transparency_log_proof_sha256: String,
    pub recovery_evidence_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalAcquisitionReconciliationRecord {
    pub api_version: String,
    pub kind: String,
    pub attempt_id: String,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub credential_binding_sha256: String,
    pub provider_id: String,
    pub account_id: String,
    pub credential_ref: String,
    pub credential_version: u64,
    pub credential_generation: u64,
    pub status: LocalAcquisitionReconciliationStatus,
    pub uncertain_side_effect: LocalAcquisitionUncertainSideEffect,
    pub created_at_epoch_ms: u64,
    pub deadline_epoch_ms: u64,
    pub rollback_state_epoch: u64,
    pub rollback_head_sha256: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub ledger_id: String,
    pub ledger_sequence: u64,
    pub ledger_checkpoint_epoch: u64,
    pub ledger_checkpoint_sha256: String,
    pub linearizable_store_id: String,
    pub linearizable_store_cluster_id: String,
    pub store_transaction_id: String,
    pub store_term: u64,
    pub store_log_index: u64,
    pub store_fencing_token: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_sha256: Option<String>,
    pub predecessor_rollback_head_sha256: String,
    pub predecessor_ledger_checkpoint_sha256: String,
    pub custody_authority_key_id: String,
    pub custody_authority_key_material_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAcquisitionReconciliationStatus {
    Unresolved,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAcquisitionUncertainSideEffect {
    LeaseAcquisition,
    UnsealCounterAdvance,
    StorageGenerationTransition,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationQuorumMemberSignature {
    pub member_key_id: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub store_transaction_id: String,
    pub store_transition_sha256: String,
    pub store_term: u64,
    pub store_log_index: u64,
    pub store_fencing_token: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationQuorumCertificate {
    pub linearizable_store_id: String,
    pub linearizable_store_cluster_id: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub store_transaction_id: String,
    pub store_transition_sha256: String,
    pub store_term: u64,
    pub store_log_index: u64,
    pub store_fencing_token: u64,
    pub quorum_threshold: u16,
    pub members: Vec<LocalReconciliationQuorumMemberSignature>,
    pub certificate_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationTransparencyLogProof {
    pub transparency_log_id: String,
    pub transparency_operator_key_id: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub store_transaction_id: String,
    pub store_transition_sha256: String,
    pub quorum_certificate_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub leaf_sha256: String,
    pub leaf_index: u64,
    pub anchor_checkpoint_root_sha256: String,
    pub anchor_checkpoint_revision: u64,
    pub anchor_checkpoint_tree_size: u64,
    pub current_checkpoint_root_sha256: String,
    pub current_checkpoint_revision: u64,
    pub current_checkpoint_tree_size: u64,
    pub inclusion_path_sha256: Vec<String>,
    pub consistency_path_sha256: Vec<String>,
    pub conflicting_successor_absence_proof_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub signed_at_epoch_ms: u64,
    pub checkpoint_signature: String,
    pub proof_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationLedgerWitness {
    pub api_version: String,
    pub kind: String,
    pub attempt_id: String,
    pub current_record_id: String,
    pub current_record_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_sha256: Option<String>,
    pub genesis_absence: bool,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub ledger_id: String,
    pub predecessor_ledger_sequence: u64,
    pub current_ledger_sequence: u64,
    pub predecessor_checkpoint_sha256: String,
    pub current_checkpoint_sha256: String,
    pub checkpoint_epoch: u64,
    pub linearizable_store_id: String,
    pub linearizable_store_cluster_id: String,
    pub store_transaction_id: String,
    pub predecessor_store_term: u64,
    pub predecessor_store_log_index: u64,
    pub predecessor_store_fencing_token: u64,
    pub current_store_term: u64,
    pub current_store_log_index: u64,
    pub current_store_fencing_token: u64,
    pub cas_expected_predecessor_sha256: String,
    pub cas_observed_predecessor_sha256: String,
    pub cas_successor_sha256: String,
    pub store_transition_sha256: String,
    pub quorum_certificate: LocalReconciliationQuorumCertificate,
    pub transparency_log_proof: LocalReconciliationTransparencyLogProof,
    pub witnessed_at_epoch_ms: u64,
    pub custody_authority_key_id: String,
    pub custody_authority_key_material_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LocalReconciliationPredecessorProof {
    Predecessor {
        record_id: String,
        record_sha256: String,
        record_byte_length: u64,
        retrieval_id: String,
        persistence_receipt_sha256: String,
        retrieval_proof_sha256: String,
        recovery_evidence_sha256: String,
        recovery_evidence_byte_length: u64,
        recovery_evidence_retrieval_id: String,
        recovery_evidence_persistence_receipt_sha256: String,
        recovery_evidence_retrieval_proof_sha256: String,
        rollback_head_sha256: String,
        ledger_sequence: u64,
        ledger_checkpoint_epoch: u64,
        ledger_checkpoint_sha256: String,
    },
    Genesis {
        genesis_absence_evidence_sha256: String,
        genesis_absence_evidence_byte_length: u64,
        genesis_absence_evidence_retrieval_id: String,
        genesis_absence_persistence_receipt_sha256: String,
        genesis_absence_retrieval_proof_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationContinuityEvidencePayload {
    pub attempt_id: String,
    pub current_record_id: String,
    pub current_record_sha256: String,
    pub current_record_byte_length: u64,
    pub current_record_retrieval_id: String,
    pub current_persistence_receipt_sha256: String,
    pub current_retrieval_proof_sha256: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub ledger_id: String,
    pub ledger_sequence: u64,
    pub ledger_checkpoint_epoch: u64,
    pub ledger_checkpoint_sha256: String,
    pub linearizable_store_id: String,
    pub linearizable_store_cluster_id: String,
    pub store_transaction_id: String,
    pub store_term: u64,
    pub store_log_index: u64,
    pub store_fencing_token: u64,
    pub store_transition_sha256: String,
    pub quorum_certificate_sha256: String,
    pub transparency_log_proof_sha256: String,
    pub predecessor: LocalReconciliationPredecessorProof,
    pub ledger_witness_evidence_sha256: String,
    pub ledger_witness_byte_length: u64,
    pub ledger_witness_retrieval_id: String,
    pub ledger_witness_persistence_receipt_sha256: String,
    pub ledger_witness_retrieval_proof_sha256: String,
    pub custody_authority_evidence_sha256: String,
    pub custody_authority_key_id: String,
    pub custody_authority_key_material_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub signed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationGenesisAbsenceEvidencePayload {
    pub attempt_id: String,
    pub current_record_id: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    pub ledger_id: String,
    pub first_ledger_sequence: u64,
    pub prior_record_count: u64,
    pub predecessor_checkpoint_sha256: String,
    pub current_checkpoint_sha256: String,
    pub checkpoint_epoch: u64,
    pub custody_authority_key_id: String,
    pub custody_authority_key_material_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub signed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialNotInjectedReason {
    AuthorizationCancelled,
    StagingFailed,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialAuthoritySideEffect {
    NotAttempted {
        reason: CredentialAuthorityNotAttemptedReason,
    },
    DefinitelyFailed {
        authority_id: String,
        operation: CredentialAuthorityOperation,
        effect_binding_sha256: String,
        terminal_record_sha256: String,
        final_record_sha256: String,
        evidence_root_sha256: String,
        state_machine_summary_sha256: String,
        failure: CredentialAuthorityFailure,
    },
    Completed {
        authority_id: String,
        operation: CredentialAuthorityOperation,
        effect_binding_sha256: String,
        terminal_record_sha256: String,
        final_record_sha256: String,
        evidence_root_sha256: String,
        state_machine_summary_sha256: String,
    },
    OutcomeUnknown {
        authority_id: String,
        operation: CredentialAuthorityOperation,
        effect_binding_sha256: String,
        terminal_record_sha256: String,
        final_record_sha256: String,
        evidence_root_sha256: String,
        state_machine_summary_sha256: String,
        recovery_binding_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthorityNotAttemptedReason {
    PolicyDenied,
    AuthorizationDenied,
    CredentialNotRequired,
    LocalCredentialOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthorityOperation {
    ReserveGrant,
    ConsumeGrant,
    ReserveQuota,
    ConsumeQuota,
    CancelQuotaReservation,
    AcquireCredentialLease,
    AuthorizeCredentialDecryption,
    AuthorizeCredentialInjection,
    RefreshOauthToken,
    ExchangeOauthToken,
    MintToken,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthorityFailure {
    DefinitelyRejected,
    DefinitelyUnavailableBeforeRequest,
    InvalidResponse,
    BindingMismatch,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GrantAuthorityAction {
    Reserve,
    Consume,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebAuthnApprovalIdentity {
    pub approval_id: String,
    pub assertion_id: String,
    pub credential_id_sha256: String,
    pub authenticator_data_sha256: String,
    pub client_data_json_sha256: String,
    pub challenge_sha256: String,
    pub assertion_consumption_id: String,
    pub assertion_consumption_sha256: String,
    pub rp_id: String,
    pub origin_sha256: String,
    pub valid_from_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantAuthorityRequest {
    pub action: GrantAuthorityAction,
    pub grant_id: String,
    pub approval_id: String,
    pub policy_sha256: String,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub reservation_id: String,
    pub prior_use_count: u64,
    pub new_use_count: u64,
    pub maximum_use_count: u64,
    pub prior_use_state_sha256: String,
    pub new_use_state_sha256: String,
    pub webauthn_required: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub webauthn_approval: Option<WebAuthnApprovalIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GrantAuthorityResult {
    Succeeded {
        transition_receipt_id: String,
        transition_receipt_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        reservation_expires_at_epoch_ms: Option<u64>,
    },
    DefinitelyFailed {
        failure: CredentialAuthorityFailure,
        failure_receipt_id: String,
        failure_receipt_sha256: String,
    },
    TransitionUnknown {
        recovery: DurableAuthorityRecovery,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaBudgetAction {
    Reserve,
    Consume,
    Cancel,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaBudgetRequest {
    pub action: QuotaBudgetAction,
    pub counter_id: String,
    pub budget_id: String,
    pub window_start_epoch_ms: u64,
    pub window_end_epoch_ms: u64,
    pub reservation_id: String,
    pub reservation_expires_at_epoch_ms: u64,
    pub units: u64,
    pub weight_basis_sha256: String,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub prior_sequence: u64,
    pub new_sequence: u64,
    pub prior_state_sha256: String,
    pub new_state_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaBudgetTransition {
    Reserved,
    Consumed,
    Cancelled,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QuotaBudgetResult {
    Succeeded {
        transition: QuotaBudgetTransition,
        transition_receipt_id: String,
        transition_receipt_sha256: String,
    },
    DefinitelyFailed {
        failure: CredentialAuthorityFailure,
        failure_receipt_id: String,
        failure_receipt_sha256: String,
    },
    TransitionUnknown {
        recovery: DurableAuthorityRecovery,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAccessAction {
    AcquireLease,
    AuthorizeDecryption,
    AuthorizeInjection,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialAccessRequest {
    pub action: CredentialAccessAction,
    pub provider_id: String,
    pub account_id: String,
    pub credential_ref: String,
    pub credential_version: u64,
    pub credential_generation: u64,
    pub recipient_runtime_measurement_sha256: String,
    pub recipient_runtime_instance_id: String,
    pub lease_id: String,
    pub lease_release_id: String,
    pub authorization_receipt_id: String,
    pub expires_at_epoch_ms: u64,
    pub credential_injection_template_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub staged_request_sha256: Option<String>,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub prior_state_sha256: String,
    pub new_state_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialAccessResult {
    Succeeded {
        access_receipt_id: String,
        access_receipt_sha256: String,
        sealed_lease_attachment_sha256: String,
    },
    DefinitelyFailed {
        failure: CredentialAuthorityFailure,
        failure_receipt_id: String,
        failure_receipt_sha256: String,
    },
    TransitionUnknown {
        recovery: DurableAuthorityRecovery,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OauthTokenAction {
    Refresh,
    Exchange,
    Mint,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OauthOutputGenerationRule {
    AdvanceExactlyOneOnSuccessPreserveOnFailureOrUnknown,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OauthEffectiveStateCommitment<'a> {
    action: OauthTokenAction,
    provider_authority_id: &'a str,
    subject_id: &'a str,
    account_id: &'a str,
    client_id: &'a str,
    app_id: &'a str,
    credential_ref: &'a str,
    credential_version: u64,
    granted_scope_root_sha256: &'a str,
    prior_token_generation: u64,
    proposed_generation: u64,
    effective_generation: u64,
    request_sha256: &'a str,
    operation_sha256: &'a str,
    authorization_binding_sha256: &'a str,
    prior_state_sha256: &'a str,
    provider_request_id: &'a str,
    provider_idempotency_key_sha256: Option<&'a str>,
    issued_credential_receipt_sha256: &'a str,
    encrypted_attachment_sha256: &'a str,
    provider_response_receipt_sha256: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OauthTokenRequest {
    pub action: OauthTokenAction,
    pub provider_authority_id: String,
    pub subject_id: String,
    pub account_id: String,
    pub client_id: String,
    pub app_id: String,
    pub credential_ref: String,
    pub credential_version: u64,
    pub granted_scope_root_sha256: String,
    pub prior_token_generation: u64,
    pub new_token_generation: u64,
    pub output_generation_rule: OauthOutputGenerationRule,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub prior_state_sha256: String,
    pub new_state_sha256: String,
    pub provider_request_id: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_idempotency_key_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OauthTokenResult {
    Succeeded {
        proposed_generation: u64,
        effective_generation: u64,
        issued_credential_receipt_id: String,
        issued_credential_receipt_sha256: String,
        encrypted_attachment_sha256: String,
        provider_response_receipt_sha256: String,
    },
    DefinitelyFailed {
        proposed_generation: u64,
        effective_generation: u64,
        failure: CredentialAuthorityFailure,
        provider_failure_id: String,
        failure_receipt_sha256: String,
    },
    TransitionUnknown {
        proposed_generation: u64,
        effective_generation: u64,
        recovery: DurableAuthorityRecovery,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableAuthorityRecovery {
    pub recovery_binding_sha256: String,
    pub durable_record_sha256: String,
    pub idempotency_key_sha256: String,
    pub last_known_state_sha256: String,
    pub transition_identity_sha256: String,
    pub reconcile_after_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "family",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialAuthorityOperationEvidence {
    Grant {
        request: GrantAuthorityRequest,
        result: GrantAuthorityResult,
    },
    QuotaBudget {
        request: QuotaBudgetRequest,
        result: QuotaBudgetResult,
    },
    CredentialAccess {
        request: CredentialAccessRequest,
        result: CredentialAccessResult,
    },
    OauthToken {
        request: OauthTokenRequest,
        result: OauthTokenResult,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteClassification {
    Rejected,
    WriteNotDispatchable,
    Write,
    ReadOnly,
    CredentiallessReadOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdempotencyClassification {
    NotApplicableDenied,
    RequiredUnavailable,
    RequiredNotEvaluated,
    RequiredSatisfied,
    NotRequired,
    ProviderEnforced,
    ReadOnlyException,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteSemanticProfileEvidencePayload {
    pub attempt_id: String,
    pub authorization_binding_sha256: String,
    pub policy_sha256: String,
    pub snapshot_epoch: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub route_id: Option<String>,
    pub operation_sha256: String,
    pub method: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub canonical_target: Option<CanonicalUpstreamTarget>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_profile_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_schema_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_idempotency_profile_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub response_policy_profile_sha256: Option<String>,
    pub route_classification: RouteClassification,
    pub idempotency_classification: IdempotencyClassification,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_mode: Option<PolicyCredentialMode>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_identity_sha256: Option<String>,
    pub semantic_profile_sha256: String,
    pub signed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialAuthorityEvidencePayload {
    pub attempt_id: String,
    pub authorization_binding_sha256: String,
    pub route_semantic_profile_sha256: String,
    pub authority_id: String,
    pub operation: CredentialAuthorityOperation,
    pub prerequisite_sha256: String,
    pub plan_step_sha256: String,
    pub sequence: u8,
    pub prior_execution_state_sha256: String,
    pub execution_state_sha256: String,
    pub effect_binding_sha256: String,
    pub operation_evidence: CredentialAuthorityOperationEvidence,
    pub operation_record_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_binding_sha256: Option<String>,
    pub completed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthorityTerminalOutcome {
    Completed,
    DefinitelyFailed,
    OutcomeUnknown,
    ExternalFailure,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialAuthorityStateMachineSummary {
    pub initial_state_sha256: String,
    pub final_state_sha256: String,
    pub plan_sha256: String,
    pub selected_path_sha256: String,
    pub consumed_plan_step_sha256: Vec<String>,
    pub evidence_root_sha256: String,
    pub terminal_outcome: CredentialAuthorityTerminalOutcome,
    pub terminal_record_sha256: String,
    pub final_record_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub external_failure_sha256: Option<String>,
    pub cleanup_record_sha256: Vec<String>,
    pub unresolved_reservation_sha256: Vec<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub dispatch_valid_from_epoch_ms: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub dispatch_valid_until_epoch_ms: Option<u64>,
    pub summary_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableRecoverySealPayload {
    pub attempt_id: String,
    pub authorization_binding_sha256: String,
    pub route_semantic_profile_sha256: String,
    pub idempotency_binding_sha256: String,
    pub recovery_key_sha256: String,
    pub durable_record_sha256: String,
    pub rollback_state_epoch: u64,
    pub armed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "routeClass",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RouteSemantics {
    Rejected {
        reason: RouteRejectionReason,
    },
    WriteNotDispatchable {
        provider_idempotency: WritePreDispatchIdempotency,
        reason: WriteNotDispatchableReason,
    },
    Write {
        provider_idempotency: ProviderIdempotencyBinding,
        ambiguous_outcome_recovery: AmbiguousOutcomeRecovery,
    },
    ReadOnly {
        exception: ReadOnlyRouteException,
        retry_recovery: ReadRetryRecovery,
    },
    CredentiallessReadOnly {
        exception: CredentiallessRouteException,
        retry_recovery: ReadRetryRecovery,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteRejectionReason {
    PolicyDeniedBeforeRouteAuthority,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WritePreDispatchIdempotency {
    RequiredUnavailable,
    RequiredNotEvaluated,
    RequiredSatisfied {
        key_sha256: String,
        locator_profile_sha256: String,
        binding_sha256: String,
    },
    NotRequired,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WriteNotDispatchableReason {
    ProviderIdempotencyUnavailable,
    ReservationDenied,
    CredentialFailure,
    CredentialAcquisitionOutcomeUnknown,
    CredentialAuthorityOutcomeUnknown,
    RecoveryAuthorityFailure,
    StagingFailed,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdempotencyBinding {
    pub enforcement: ProviderIdempotencyEnforcement,
    pub scope: IdempotencyScope,
    pub reuse_policy: IdempotencyReusePolicy,
    pub key_sha256: String,
    pub locator_profile_sha256: String,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdempotencyProfile {
    pub provider_id: String,
    pub locator: ProviderIdempotencyLocator,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "location",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderIdempotencyLocator {
    Header {
        header_name: String,
    },
    CanonicalFlatJsonStringBodyField {
        field_name: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponsePolicyProfile {
    pub validator_id: String,
    pub provider_id: String,
    pub provider_schema_sha256: String,
    pub restrictions_sha256: String,
    pub maximum_body_bytes: u64,
    pub require_complete_body: bool,
    pub chunk_extensions: ChunkExtensionPolicy,
    pub trailers: TrailerPolicy,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "policy",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ChunkExtensionPolicy {
    Forbidden,
    Allowed {
        maximum_extension_bytes: u64,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "policy",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TrailerPolicy {
    Forbidden,
    Allowed {
        maximum_trailer_bytes: u64,
        maximum_trailer_count: u32,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponsePolicyValidation {
    pub profile_sha256: String,
    pub exact_response_bytes_sha256: String,
    pub restrictions_sha256: String,
    pub decision: ResponsePolicyDecision,
    pub validation_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResponsePolicyDecision {
    Passed,
    Failed,
    NotEvaluatedIncompleteResponse,
    NotEvaluatedUnsupportedResponse,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderIdempotencyEnforcement {
    ProviderEnforced,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdempotencyScope {
    AttemptId,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdempotencyReusePolicy {
    ExactStagedRequestOnly,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmbiguousOutcomeRecovery {
    pub attempt_id: String,
    pub idempotency_binding_sha256: String,
    pub recovery_key_sha256: String,
    pub durable_record_sha256: String,
    pub state: RecoveryState,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryState {
    ArmedBeforeDispatch,
    PendingReconciliation,
    ResolvedFromProvider,
    NotNeededKnownOutcome,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadRetryRecovery {
    pub attempt_id: String,
    pub retry_binding_sha256: String,
    pub state: ReadRetryState,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReadRetryState {
    NotNeededKnownOutcome,
    SafeRetryAfterUnknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReadOnlyRouteException {
    NoProviderSideEffect,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentiallessRouteException {
    NoProviderCredentialAndNoSideEffect,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedTargetRequest {
    pub staging_sha256: String,
    pub exact_request_retrieval_id: String,
    pub credential_injection_template_sha256: String,
    pub injection: CredentialInjectionState,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_binding_sha256: Option<String>,
    pub injection_result_sha256: String,
    pub operation_semantics_sha256: String,
    pub request_framing_sha256: String,
    pub dispatch_authorization_binding_sha256: String,
    pub exact_request_bytes_sha256: String,
    pub exact_request_bytes_length: u64,
    pub method: String,
    pub wire_protocol: TargetWireProtocol,
    pub canonical_target: CanonicalUpstreamTarget,
    pub header_block_sha256: String,
    pub header_block_length: u64,
    pub header_count: u32,
    pub body_sha256: String,
    pub body_length: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub idempotency_key_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub idempotency_binding_sha256: Option<String>,
    pub prepared_at_epoch_ms: u64,
    pub preparation: TargetPreparation,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialInjectionState {
    Applied,
    NotRequired,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetScheme {
    Https,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetWireProtocol {
    Http11OriginForm,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalUpstreamTarget {
    pub scheme: TargetScheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub canonical_query: BTreeMap<String, String>,
    pub decode_semantics: TargetDecodeSemantics,
    pub target_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetDecodeSemantics {
    ExactlyOnceNoRedecode,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetPreparation {
    pub dns: DnsPreparationState,
    pub tls: TlsPreparationState,
    pub request_build: RequestBuildState,
    pub remaining_after_dispatch_authorization: RemainingPreparationState,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsPreparationState {
    ResolvedAndPinned,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsPreparationState {
    ConnectedAndAuthenticated,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RequestBuildState {
    ImmutableExactBytesFinal,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RemainingPreparationState {
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TargetEgressState {
    DefinitelyNotDispatched {
        reason: NotDispatchedReason,
        bytes_written: u64,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        staged_request_sha256: Option<String>,
    },
    Dispatched {
        dispatch_evidence_sha256: String,
        staged_request_sha256: String,
        write_state: ExactBytesWriteState,
        bytes_written: u64,
        dispatched_at_epoch_ms: u64,
    },
    WriteOutcomeUnknown {
        dispatch_evidence_sha256: String,
        staged_request_sha256: String,
        write_state: UnknownBytesWriteState,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        bytes_written_lower_bound: Option<u64>,
        unknown_at_epoch_ms: u64,
        recovery_binding_sha256: String,
    },
    ReadOutcomeUnknown {
        dispatch_evidence_sha256: String,
        staged_request_sha256: String,
        write_state: UnknownBytesWriteState,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        bytes_written_lower_bound: Option<u64>,
        unknown_at_epoch_ms: u64,
        retry_binding_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NotDispatchedReason {
    PolicyDenied,
    ReservationDenied,
    CredentialFailure,
    CredentialAcquisitionOutcomeUnknown,
    CredentialAuthorityOutcomeUnknown,
    RecoveryAuthorityFailure,
    StagingFailed,
    DispatchCancelledBeforeWrite,
    DeadlineExpiredBeforeWrite,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExactBytesWriteState {
    CompleteExactStagedBytes,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownBytesWriteState {
    PartialOrCompleteExactStagedBytes,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum UpstreamObservationState {
    NotApplicable {
        reason: UpstreamNotApplicableReason,
    },
    ObservedResponse {
        exact_response_retrieval_id: String,
        exact_response_bytes_sha256: String,
        exact_response_bytes_length: u64,
        wire_protocol: UpstreamResponseWireProtocol,
        informational_responses: Vec<InformationalResponseHead>,
        status_line_sha256: String,
        status_line_length: u64,
        status: u16,
        header_block_sha256: String,
        header_block_length: u64,
        header_count: u32,
        framing: UpstreamResponseFraming,
        completion: UpstreamResponseCompletion,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        declared_body_length: Option<u64>,
        physical_body_sha256: String,
        physical_body_length: u64,
        body_sha256: String,
        body_length: u64,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        trailer_block_sha256: Option<String>,
        trailer_block_length: u64,
        trailer_count: u32,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        close_completion_receipt_sha256: Option<String>,
        observed_bytes_sha256: String,
        response_policy_validation: ResponsePolicyValidation,
        observed_at_epoch_ms: u64,
        truth: ProviderTruth,
    },
    ExactResponseUnsupported {
        exact_response_retrieval_id: String,
        exact_response_bytes_sha256: String,
        exact_response_bytes_length: u64,
        wire_protocol: UpstreamResponseWireProtocol,
        completion: UpstreamResponseCompletion,
        protocol_validation_receipt_sha256: String,
        reason: ExactResponseUnsupportedReason,
        response_policy_decision: ResponsePolicyDecision,
        downstream_delivery: DownstreamDeliveryState,
        observed_at_epoch_ms: u64,
        truth: ProviderTruth,
    },
    WriteOutcomeUnknown {
        transition_unknown_evidence_sha256: String,
        recovery_binding_sha256: String,
        response_policy_decision: ResponsePolicyDecision,
        downstream_delivery: DownstreamDeliveryState,
        truth: ProviderTruth,
    },
    ReadOutcomeUnknown {
        transition_unknown_evidence_sha256: String,
        retry_binding_sha256: String,
        response_policy_decision: ResponsePolicyDecision,
        downstream_delivery: DownstreamDeliveryState,
        truth: ProviderTruth,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InformationalResponseHead {
    pub status_line_sha256: String,
    pub status_line_length: u64,
    pub status: u16,
    pub header_block_sha256: String,
    pub header_block_length: u64,
    pub header_count: u32,
}

impl UpstreamObservationState {
    fn digest(&self) -> ContractResult<String> {
        let canonical = canonical_jcs_bytes(self)?;
        domain_sha256(UPSTREAM_OBSERVATION_DOMAIN, &[canonical.as_slice()])
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamNotApplicableReason {
    DefinitelyNotDispatched,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamResponseWireProtocol {
    Http11,
    Http10,
    Http2,
    Http3,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamResponseFraming {
    ContentLength,
    Chunked,
    CloseDelimited,
    NoBody,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExactResponseUnsupportedReason {
    UnsupportedProtocol,
    UnsupportedTransferCoding,
    ProtocolUpgrade,
    UnsupportedHttp11Framing,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamResponseCompletion {
    Complete,
    Truncated,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DownstreamDeliveryState {
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderTruth {
    ObservedBytesOnly,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleTransition {
    pub sequence: u8,
    pub state: LifecycleState,
    pub at_epoch_ms: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub binding_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleState {
    Received,
    PolicyEvaluated,
    AuthorizationReserved,
    CredentialAuthorityComplete,
    TargetRequestStaged,
    DispatchAuthorized,
    TargetWriteStarted,
    TerminalCancelled,
    TerminalCompleted,
    TerminalResponseRejected,
    TerminalExactResponseUnsupported,
    TerminalTransitionUnknown,
}

impl LifecycleState {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::TerminalCancelled
                | Self::TerminalCompleted
                | Self::TerminalResponseRejected
                | Self::TerminalExactResponseUnsupported
                | Self::TerminalTransitionUnknown
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "source",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ObservationAuthority {
    GateAuthored {
        ceiling: GateAuthorityCeiling,
        provider_truth: ProviderTruth,
        downstream_delivery: DownstreamDeliveryClaim,
    },
    MeasuredCustody {
        ceiling: CustodyAuthorityCeiling,
        provider_truth: ProviderTruth,
        downstream_delivery: DownstreamDeliveryClaim,
        custody_authority_evidence_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GateAuthorityCeiling {
    GateObservedOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyAuthorityCeiling {
    CustodyOwnedEndToEnd,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DownstreamDeliveryClaim {
    NotClaimed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyCapability {
    LeaseDecryption,
    CredentialInjection,
    TargetTls,
    TargetEgress,
    ProofSigning,
    RollbackProtectedState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedEvidence<P> {
    pub api_version: String,
    pub evidence_type: EvidenceType,
    pub payload: P,
    pub payload_sha256: String,
    pub key_id: String,
    pub signature_domain: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub boot_runtime_identity: BootRuntimeIdentity,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_evidence_sha256: Option<String>,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceType {
    RouteSemanticProfile,
    Reserve,
    CredentialAuthority,
    DurableRecoverySeal,
    Dispatch,
    Terminal,
    CustodyAuthority,
    LocalReconciliationContinuity,
    LocalReconciliationLedgerWitness,
    LocalReconciliationGenesisAbsence,
    LocalReconciliationRecovery,
    Persistence,
    FinalizationCheckpoint,
    ArtifactTimeCheckpoint,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRole {
    RouteSemanticProfile,
    Reserve,
    CredentialAuthority,
    DurableRecoverySeal,
    Dispatch,
    Cancellation,
    Completion,
    ResponseRejection,
    ExactResponseUnsupported,
    WriteTransitionUnknown,
    ReadTransitionUnknown,
    CustodyAuthority,
    LocalReconciliationContinuity,
    LocalReconciliationLedgerWitness,
    LocalReconciliationGenesisAbsence,
    LocalReconciliationRecovery,
    Persistence,
    FinalizationCheckpoint,
    ArtifactTimeCheckpoint,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReserveEvidencePayload {
    pub attempt_id: String,
    pub nonce_sha256: String,
    pub policy_sha256: String,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub route_semantic_profile_sha256: String,
    pub authorization_binding_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_plan_sha256: Option<String>,
    pub reservation_id: String,
    pub reserved_at_epoch_ms: u64,
    pub reservation_deadline_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchEvidencePayload {
    pub attempt_id: String,
    pub policy_sha256: String,
    pub reserve_evidence_sha256: String,
    pub route_semantic_profile_sha256: String,
    pub authorization_binding_sha256: String,
    pub dispatch_authorization_binding_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_binding_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_evidence_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_evidence_root_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_state_machine_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub durable_recovery_seal_evidence_sha256: Option<String>,
    pub staged_request_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub idempotency_binding_sha256: Option<String>,
    pub authorized_at_epoch_ms: u64,
    pub revalidated_at_epoch_ms: u64,
    pub policy_snapshot_epoch: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub dispatch_deadline_epoch_ms: u64,
    pub all_preparation_complete: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "transition",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TerminalEvidencePayload {
    Cancelled {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        reserve_evidence_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        dispatch_evidence_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        dispatch_authorization_binding_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        staged_request_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_recovery_binding_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_recovery_evidence_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_recovery_authority_key_id: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_recovery_authority_key_material_sha256:
            Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_recovery_authority_trust_checkpoint_sha256:
            Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_recovery_authority_revocation_epoch: Option<u64>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_credential_ledger_namespace: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_pinned_genesis_state_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_predecessor_successor_key_sha256:
            Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_continuity_evidence_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_store_transition_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_quorum_certificate_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        local_reconciliation_transparency_log_proof_sha256: Option<String>,
        reason: CancellationReason,
        definitely_not_dispatched: bool,
        failure_observed_at_epoch_ms: u64,
        completed_at_epoch_ms: u64,
    },
    Completed {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        dispatch_authorization_binding_sha256: String,
        dispatch_evidence_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        staged_request_sha256: String,
        upstream_observation_sha256: String,
        completed_at_epoch_ms: u64,
    },
    ResponseRejected {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        dispatch_authorization_binding_sha256: String,
        dispatch_evidence_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        staged_request_sha256: String,
        upstream_observation_sha256: String,
        reason: ResponseRejectionReason,
        rejected_at_epoch_ms: u64,
    },
    ExactResponseUnsupported {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        dispatch_authorization_binding_sha256: String,
        dispatch_evidence_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        staged_request_sha256: String,
        upstream_observation_sha256: String,
        reason: ExactResponseUnsupportedReason,
        unsupported_at_epoch_ms: u64,
    },
    WriteTransitionUnknown {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        dispatch_authorization_binding_sha256: String,
        dispatch_evidence_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        durable_recovery_seal_evidence_sha256: String,
        staged_request_sha256: String,
        idempotency_binding_sha256: String,
        recovery_binding_sha256: String,
        unknown_at_epoch_ms: u64,
    },
    ReadTransitionUnknown {
        attempt_id: String,
        route_semantic_profile_sha256: String,
        authorization_binding_sha256: String,
        dispatch_authorization_binding_sha256: String,
        dispatch_evidence_sha256: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_evidence_root_sha256: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        credential_authority_state_machine_sha256: Option<String>,
        staged_request_sha256: String,
        retry_binding_sha256: String,
        unknown_at_epoch_ms: u64,
    },
}

impl TerminalEvidencePayload {
    fn attempt_id(&self) -> &str {
        match self {
            Self::Cancelled { attempt_id, .. }
            | Self::Completed { attempt_id, .. }
            | Self::ResponseRejected { attempt_id, .. }
            | Self::ExactResponseUnsupported { attempt_id, .. }
            | Self::WriteTransitionUnknown { attempt_id, .. }
            | Self::ReadTransitionUnknown { attempt_id, .. } => attempt_id,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CancellationReason {
    PolicyDenied,
    ReservationDenied,
    CredentialFailure,
    CredentialAcquisitionOutcomeUnknown,
    CredentialAuthorityOutcomeUnknown,
    RecoveryAuthorityFailure,
    StagingFailed,
    DispatchCancelledBeforeWrite,
    DeadlineExpiredBeforeWrite,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseRejectionReason {
    PolicyRejected,
    IncompleteResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyAuthorityEvidencePayload {
    pub attempt_id: String,
    pub policy_sha256: String,
    pub authorization_binding_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub dispatch_authorization_binding_sha256: Option<String>,
    pub runtime_measurement_sha256: String,
    pub rollback_state_epoch: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub staged_request_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_evidence_root_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_authority_state_machine_sha256: Option<String>,
    pub capabilities: Vec<CustodyCapability>,
    pub ownership_binding_sha256: String,
    pub measured_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistenceEvidencePayload {
    pub attempt_id: String,
    pub envelope_sha256: String,
    pub envelope_byte_length: u64,
    pub retrieval_id: String,
    pub terminal_evidence_sha256: String,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub persisted_at_epoch_ms: u64,
    pub immutable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalReconciliationRecoveryEvidencePayload {
    pub attempt_id: String,
    pub request_sha256: String,
    pub operation_sha256: String,
    pub authorization_binding_sha256: String,
    pub reserve_evidence_sha256: String,
    pub custody_authority_evidence_sha256: String,
    pub credential_binding_sha256: String,
    pub provider_id: String,
    pub account_id: String,
    pub credential_ref: String,
    pub credential_version: u64,
    pub credential_generation: u64,
    pub record_id: String,
    pub record_sha256: String,
    pub record_byte_length: u64,
    pub retrieval_id: String,
    pub status: LocalAcquisitionReconciliationStatus,
    pub uncertain_side_effect: LocalAcquisitionUncertainSideEffect,
    pub created_at_epoch_ms: u64,
    pub deadline_epoch_ms: u64,
    pub rollback_state_epoch: u64,
    pub rollback_head_sha256: String,
    pub credential_ledger_namespace: String,
    pub pinned_genesis_state_sha256: String,
    pub predecessor_successor_key_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub predecessor_record_sha256: Option<String>,
    pub predecessor_rollback_head_sha256: String,
    pub linearizable_store_id: String,
    pub linearizable_store_cluster_id: String,
    pub store_transaction_id: String,
    pub store_term: u64,
    pub store_log_index: u64,
    pub store_fencing_token: u64,
    pub custody_authority_key_id: String,
    pub custody_authority_key_material_sha256: String,
    pub recovery_authority_key_id: String,
    pub recovery_authority_key_material_sha256: String,
    pub recovery_authority_trust_checkpoint_sha256: String,
    pub recovery_authority_revocation_epoch: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub continuity_evidence_sha256: String,
    pub ledger_witness_evidence_sha256: String,
    pub predecessor_proof_sha256: String,
    pub store_transition_sha256: String,
    pub quorum_certificate_sha256: String,
    pub transparency_log_proof_sha256: String,
    pub signed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizationCheckpointEvidencePayload {
    pub attempt_id: String,
    pub retrieval_id: String,
    pub envelope_sha256: String,
    pub envelope_byte_length: u64,
    pub terminal_evidence_sha256: String,
    pub persistence_evidence_sha256: String,
    pub finalized_at_epoch_ms: u64,
    pub trusted_time_epoch_ms: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub historical_trust_policy_sha256: String,
    pub historical_key_set_root_sha256: String,
    pub historical_key_inclusion_proof_sha256: String,
    pub historical_non_revocation_proof_sha256: String,
    pub runtime_attestation_evidence_sha256: String,
    pub runtime_attestation_verifier_key_id: String,
    pub runtime_attestation_inclusion_proof_sha256: String,
    pub runtime_measurement_sha256: String,
    pub immutable_persistence_receipt_sha256: String,
    pub exact_retrieval_proof_sha256: String,
    pub archival_verification_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactTimeCheckpointEvidencePayload {
    pub attempt_id: String,
    pub retrieval_id: String,
    pub envelope_sha256: String,
    pub artifact_role: FinalizationArtifactRole,
    pub artifact_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub prerequisite_attestation_sha256: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub prerequisite_artifact_time_checkpoint_evidence_sha256:
        Option<String>,
    pub artifact_signing_key_id: String,
    pub finalized_at_epoch_ms: u64,
    pub artifact_at_epoch_ms: u64,
    pub trusted_time_epoch_ms: u64,
    pub artifact_key_expires_at_epoch_ms: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub historical_trust_policy_sha256: String,
    pub historical_key_set_root_sha256: String,
    pub historical_key_inclusion_proof_sha256: String,
    pub historical_non_revocation_proof_sha256: String,
    pub runtime_attestation_evidence_sha256: String,
    pub runtime_attestation_verifier_key_id: String,
    pub runtime_attestation_inclusion_proof_sha256: String,
    pub runtime_measurement_sha256: String,
    pub finalization_checkpoint_evidence_sha256: String,
    pub immutable_artifact_receipt_sha256: String,
    pub exact_artifact_retrieval_proof_sha256: String,
    pub signed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedEnvelopeIdentity {
    pub attempt_id: String,
    pub canonicalization: CanonicalizationProfile,
    pub envelope_sha256: String,
    pub envelope_byte_length: u64,
    pub retrieval_id: String,
    pub finalized_at_epoch_ms: u64,
    pub retrieval_contract: RetrievalContract,
    pub bytes_immutable: bool,
    pub replacement_prohibited: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum CanonicalizationProfile {
    #[serde(rename = "RFC8785-JCS/catchplate-integers-and-unique-keys/v1")]
    Rfc8785CatchplateV1,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RetrievalContract {
    ExactCanonicalEnvelopeBytes,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AttestationState {
    NotAttempted {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
    },
    Succeeded {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
        attestation_sha256: String,
        attested_at_epoch_ms: u64,
        artifact_time_checkpoint_evidence:
            SignedEvidence<ArtifactTimeCheckpointEvidencePayload>,
    },
    Failed {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
        failure: AttestationFailure,
        failed_at_epoch_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationFailure {
    SignerUnavailable,
    MeasurementUnavailable,
    QuoteRejected,
    PersistenceBindingMismatch,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PublicationState {
    NotAttempted {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
    },
    Published {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
        publication_receipt_sha256: String,
        published_at_epoch_ms: u64,
        artifact_time_checkpoint_evidence:
            SignedEvidence<ArtifactTimeCheckpointEvidencePayload>,
    },
    Failed {
        attempt_id: String,
        retrieval_id: String,
        envelope_sha256: String,
        failure: PublicationFailure,
        failed_at_epoch_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationFailure {
    AttestationUnavailable,
    PublisherUnavailable,
    PublisherRejected,
    ReceiptInvalid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndependentRuntimeAttestationClaim {
    pub runtime: BootRuntimeIdentity,
    pub attestation_evidence_sha256: String,
    pub verifier_key_id: String,
    pub verified_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationPurpose {
    LiveAuthorization,
    ArchivalVerification,
}

pub type RuntimeVerificationPurpose = VerificationPurpose;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoricalRuntimeAttestationInclusion {
    pub finalized_at_epoch_ms: u64,
    pub trusted_time_epoch_ms: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub historical_trust_policy_sha256: String,
    pub historical_key_set_root_sha256: String,
    pub historical_key_inclusion_proof_sha256: String,
    pub historical_non_revocation_proof_sha256: String,
    pub runtime_attestation_inclusion_proof_sha256: String,
}

#[derive(Debug)]
pub(crate) struct RuntimeAttestationVerificationPurpose<'a> {
    purpose: VerificationPurpose,
    historical_inclusion:
        Option<&'a HistoricalRuntimeAttestationInclusion>,
}

impl<'a> RuntimeAttestationVerificationPurpose<'a> {
    pub(crate) fn purpose(&self) -> VerificationPurpose {
        self.purpose
    }

    pub(crate) fn historical_inclusion(
        &self,
    ) -> Option<&HistoricalRuntimeAttestationInclusion> {
        self.historical_inclusion
    }
}

pub(crate) trait IndependentRuntimeAttestationVerifier {
    /// Verify the runtime claim against independent attestation evidence.
    ///
    /// Implementations MUST obtain their trust roots independently of the
    /// response-observation proof and scope acceptance to the supplied closed
    /// purpose. Returning true asserts measurement, boot, release, binary, and
    /// rollback-state bindings, not merely signature validity. For
    /// ARCHIVAL_VERIFICATION it must also independently retrieve and verify the
    /// supplied historical key-set, verifier-key inclusion, non-revocation,
    /// trusted-time, and runtime-attestation inclusion proofs as of the exact
    /// finalization checkpoint.
    fn verify_runtime_attestation(
        &self,
        purpose: &RuntimeAttestationVerificationPurpose<'_>,
        claim: &IndependentRuntimeAttestationClaim,
    ) -> bool;
}

/// Opaque proof that a runtime identity was accepted by an independent
/// attestation verifier. It cannot be deserialized or directly constructed.
#[derive(Debug)]
pub(crate) struct VerifiedRuntimeIdentity {
    identity: BootRuntimeIdentity,
    attestation_evidence_sha256: String,
    verifier_key_id: String,
    verified_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
    verification_purpose: VerificationPurpose,
    historical_inclusion: Option<HistoricalRuntimeAttestationInclusion>,
    _seal: VerifiedRuntimeSeal,
}

#[derive(Debug)]
struct VerifiedRuntimeSeal;

impl VerifiedRuntimeIdentity {
    pub(crate) fn identity(&self) -> &BootRuntimeIdentity {
        &self.identity
    }

    pub(crate) fn attestation_evidence_sha256(&self) -> &str {
        &self.attestation_evidence_sha256
    }

    pub(crate) fn verifier_key_id(&self) -> &str {
        &self.verifier_key_id
    }

    pub(crate) fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub(crate) fn historical_inclusion(
        &self,
    ) -> Option<&HistoricalRuntimeAttestationInclusion> {
        self.historical_inclusion.as_ref()
    }
}

pub(crate) fn verify_independently_attested_runtime<
    V: IndependentRuntimeAttestationVerifier,
>(
    claim: IndependentRuntimeAttestationClaim,
    trusted_now_epoch_ms: u64,
    verifier: &V,
) -> ContractResult<VerifiedRuntimeIdentity> {
    validate_safe_time(trusted_now_epoch_ms, "trustedNowEpochMs")?;
    validate_runtime(&claim.runtime)?;
    validate_digest(
        &claim.attestation_evidence_sha256,
        "runtimeAttestation.attestationEvidenceSha256",
    )?;
    validate_digest(
        &claim.verifier_key_id,
        "runtimeAttestation.verifierKeyId",
    )?;
    validate_safe_time(
        claim.verified_at_epoch_ms,
        "runtimeAttestation.verifiedAtEpochMs",
    )?;
    validate_safe_time(
        claim.expires_at_epoch_ms,
        "runtimeAttestation.expiresAtEpochMs",
    )?;
    if claim.expires_at_epoch_ms <= claim.verified_at_epoch_ms
        || claim.expires_at_epoch_ms - claim.verified_at_epoch_ms
            > MAX_RUNTIME_ATTESTATION_TTL_MS
        || claim.verified_at_epoch_ms
            > trusted_now_epoch_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || trusted_now_epoch_ms > claim.expires_at_epoch_ms
    {
        return Err(ContractError::new(
            "runtime_attestation_outside_validity_window",
            "runtimeAttestation",
            "independent runtime attestation is not fresh and bounded",
        ));
    }
    let purpose = RuntimeAttestationVerificationPurpose {
        purpose: VerificationPurpose::LiveAuthorization,
        historical_inclusion: None,
    };
    if !verifier.verify_runtime_attestation(&purpose, &claim) {
        return Err(ContractError::new(
            "runtime_attestation_unverified",
            "runtimeAttestation",
            "independent attestation verifier rejected the runtime identity",
        ));
    }
    Ok(VerifiedRuntimeIdentity {
        identity: claim.runtime,
        attestation_evidence_sha256: claim.attestation_evidence_sha256,
        verifier_key_id: claim.verifier_key_id,
        verified_at_epoch_ms: claim.verified_at_epoch_ms,
        expires_at_epoch_ms: claim.expires_at_epoch_ms,
        verification_purpose: VerificationPurpose::LiveAuthorization,
        historical_inclusion: None,
        _seal: VerifiedRuntimeSeal,
    })
}

pub(crate) fn verify_historically_attested_runtime<
    V: IndependentRuntimeAttestationVerifier,
>(
    claim: IndependentRuntimeAttestationClaim,
    inclusion: HistoricalRuntimeAttestationInclusion,
    trusted_delivery_time_epoch_ms: u64,
    verifier: &V,
) -> ContractResult<VerifiedRuntimeIdentity> {
    validate_safe_time(
        trusted_delivery_time_epoch_ms,
        "trustedDeliveryTimeEpochMs",
    )?;
    validate_runtime(&claim.runtime)?;
    for (value, path) in [
        (
            &claim.attestation_evidence_sha256,
            "runtimeAttestation.attestationEvidenceSha256",
        ),
        (
            &claim.verifier_key_id,
            "runtimeAttestation.verifierKeyId",
        ),
        (
            &inclusion.trust_checkpoint_sha256,
            "runtimeAttestation.historicalInclusion.trustCheckpointSha256",
        ),
        (
            &inclusion.historical_trust_policy_sha256,
            "runtimeAttestation.historicalInclusion.historicalTrustPolicySha256",
        ),
        (
            &inclusion.historical_key_set_root_sha256,
            "runtimeAttestation.historicalInclusion.historicalKeySetRootSha256",
        ),
        (
            &inclusion.historical_key_inclusion_proof_sha256,
            "runtimeAttestation.historicalInclusion.historicalKeyInclusionProofSha256",
        ),
        (
            &inclusion.historical_non_revocation_proof_sha256,
            "runtimeAttestation.historicalInclusion.historicalNonRevocationProofSha256",
        ),
        (
            &inclusion.runtime_attestation_inclusion_proof_sha256,
            "runtimeAttestation.historicalInclusion.inclusionProofSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path) in [
        (
            claim.verified_at_epoch_ms,
            "runtimeAttestation.verifiedAtEpochMs",
        ),
        (
            claim.expires_at_epoch_ms,
            "runtimeAttestation.expiresAtEpochMs",
        ),
        (
            inclusion.finalized_at_epoch_ms,
            "runtimeAttestation.historicalInclusion.finalizedAtEpochMs",
        ),
        (
            inclusion.trusted_time_epoch_ms,
            "runtimeAttestation.historicalInclusion.trustedTimeEpochMs",
        ),
    ] {
        validate_safe_time(value, path)?;
    }
    validate_safe_integer(
        inclusion.revocation_epoch,
        "runtimeAttestation.historicalInclusion.revocationEpoch",
    )?;
    if inclusion.revocation_epoch == 0
        || claim.expires_at_epoch_ms <= claim.verified_at_epoch_ms
        || claim.expires_at_epoch_ms - claim.verified_at_epoch_ms
            > MAX_RUNTIME_ATTESTATION_TTL_MS
        || inclusion.trusted_time_epoch_ms < claim.verified_at_epoch_ms
        || inclusion.trusted_time_epoch_ms > claim.expires_at_epoch_ms
        || inclusion.finalized_at_epoch_ms
            != inclusion.trusted_time_epoch_ms
        || trusted_delivery_time_epoch_ms
            < inclusion.finalized_at_epoch_ms
    {
        return Err(ContractError::new(
            "historical_runtime_attestation_invalid",
            "runtimeAttestation.historicalInclusion",
            "historical runtime attestation must be included, valid, and non-revoked at the exact signed finalization-time checkpoint",
        ));
    }
    let purpose = RuntimeAttestationVerificationPurpose {
        purpose: VerificationPurpose::ArchivalVerification,
        historical_inclusion: Some(&inclusion),
    };
    if !verifier.verify_runtime_attestation(&purpose, &claim) {
        return Err(ContractError::new(
            "historical_runtime_attestation_unverified",
            "runtimeAttestation",
            "independent verifier rejected historical runtime-attestation inclusion at finalization",
        ));
    }
    Ok(VerifiedRuntimeIdentity {
        identity: claim.runtime,
        attestation_evidence_sha256: claim.attestation_evidence_sha256,
        verifier_key_id: claim.verifier_key_id,
        verified_at_epoch_ms: claim.verified_at_epoch_ms,
        expires_at_epoch_ms: claim.expires_at_epoch_ms,
        verification_purpose: VerificationPurpose::ArchivalVerification,
        historical_inclusion: Some(inclusion),
        _seal: VerifiedRuntimeSeal,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinnedReconciliationQuorumMember {
    key_id: String,
    key_material_sha256: String,
}

impl PinnedReconciliationQuorumMember {
    pub(crate) fn new(
        key_id: String,
        key_material_sha256: String,
    ) -> ContractResult<Self> {
        validate_digest(
            &key_id,
            "reconciliationWitnessAuthority.quorumMembers.keyId",
        )?;
        validate_digest(
            &key_material_sha256,
            "reconciliationWitnessAuthority.quorumMembers.keyMaterialSha256",
        )?;
        Ok(Self {
            key_id,
            key_material_sha256,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn key_material_sha256(&self) -> &str {
        &self.key_material_sha256
    }
}

/// Independently provisioned reconciliation authority. None of these values
/// may be learned from the response-observation proof being verified.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinnedReconciliationWitnessAuthority {
    linearizable_store_id: String,
    linearizable_store_cluster_id: String,
    credential_ledger_namespace: String,
    pinned_genesis_state_sha256: String,
    genesis_predecessor_successor_key_sha256: String,
    quorum_threshold: u16,
    quorum_members: Vec<PinnedReconciliationQuorumMember>,
    transparency_log_id: String,
    transparency_operator_key_id: String,
    transparency_operator_key_material_sha256: String,
    recovery_authority_key_id: String,
    recovery_authority_key_material_sha256: String,
    anchor_checkpoint_root_sha256: String,
    anchor_checkpoint_revision: u64,
    anchor_checkpoint_tree_size: u64,
    current_checkpoint_root_sha256: String,
    current_checkpoint_revision: u64,
    current_checkpoint_tree_size: u64,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
}

impl PinnedReconciliationWitnessAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        linearizable_store_id: String,
        linearizable_store_cluster_id: String,
        credential_ledger_namespace: String,
        pinned_genesis_state_sha256: String,
        quorum_threshold: u16,
        mut quorum_members: Vec<PinnedReconciliationQuorumMember>,
        transparency_log_id: String,
        transparency_operator_key_id: String,
        transparency_operator_key_material_sha256: String,
        recovery_authority_key_id: String,
        recovery_authority_key_material_sha256: String,
        anchor_checkpoint_root_sha256: String,
        anchor_checkpoint_revision: u64,
        anchor_checkpoint_tree_size: u64,
        current_checkpoint_root_sha256: String,
        current_checkpoint_revision: u64,
        current_checkpoint_tree_size: u64,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
    ) -> ContractResult<Self> {
        for (value, path) in [
            (
                &linearizable_store_id,
                "reconciliationWitnessAuthority.linearizableStoreId",
            ),
            (
                &linearizable_store_cluster_id,
                "reconciliationWitnessAuthority.linearizableStoreClusterId",
            ),
            (
                &credential_ledger_namespace,
                "reconciliationWitnessAuthority.credentialLedgerNamespace",
            ),
            (
                &transparency_log_id,
                "reconciliationWitnessAuthority.transparencyLogId",
            ),
        ] {
            validate_identifier(value, path)?;
        }
        for (value, path) in [
            (
                &pinned_genesis_state_sha256,
                "reconciliationWitnessAuthority.pinnedGenesisStateSha256",
            ),
            (
                &transparency_operator_key_id,
                "reconciliationWitnessAuthority.transparencyOperatorKeyId",
            ),
            (
                &transparency_operator_key_material_sha256,
                "reconciliationWitnessAuthority.transparencyOperatorKeyMaterialSha256",
            ),
            (
                &recovery_authority_key_id,
                "reconciliationWitnessAuthority.recoveryAuthorityKeyId",
            ),
            (
                &recovery_authority_key_material_sha256,
                "reconciliationWitnessAuthority.recoveryAuthorityKeyMaterialSha256",
            ),
            (
                &anchor_checkpoint_root_sha256,
                "reconciliationWitnessAuthority.anchorCheckpointRootSha256",
            ),
            (
                &current_checkpoint_root_sha256,
                "reconciliationWitnessAuthority.currentCheckpointRootSha256",
            ),
            (
                &trust_checkpoint_sha256,
                "reconciliationWitnessAuthority.trustCheckpointSha256",
            ),
        ] {
            validate_digest(value, path)?;
        }
        for (value, path) in [
            (
                anchor_checkpoint_revision,
                "reconciliationWitnessAuthority.anchorCheckpointRevision",
            ),
            (
                anchor_checkpoint_tree_size,
                "reconciliationWitnessAuthority.anchorCheckpointTreeSize",
            ),
            (
                current_checkpoint_revision,
                "reconciliationWitnessAuthority.currentCheckpointRevision",
            ),
            (
                current_checkpoint_tree_size,
                "reconciliationWitnessAuthority.currentCheckpointTreeSize",
            ),
            (
                revocation_epoch,
                "reconciliationWitnessAuthority.revocationEpoch",
            ),
        ] {
            validate_safe_integer(value, path)?;
        }
        let genesis_conflict_key =
            LocalReconciliationConflictKeyCommitment {
                linearizable_store_id: linearizable_store_id.as_str(),
                linearizable_store_cluster_id:
                    linearizable_store_cluster_id.as_str(),
                credential_ledger_namespace:
                    credential_ledger_namespace.as_str(),
                predecessor_identity:
                    LOCAL_RECONCILIATION_GENESIS_MARKER,
            };
        let genesis_conflict_key_jcs =
            canonical_jcs_bytes(&genesis_conflict_key)?;
        let genesis_predecessor_successor_key_sha256 = domain_sha256(
            LOCAL_RECONCILIATION_PREDECESSOR_SUCCESSOR_KEY_DOMAIN,
            &[genesis_conflict_key_jcs.as_slice()],
        )?;
        let pinned_genesis_state =
            LocalReconciliationPinnedGenesisStateCommitment {
                linearizable_store_id: linearizable_store_id.as_str(),
                linearizable_store_cluster_id:
                    linearizable_store_cluster_id.as_str(),
                credential_ledger_namespace:
                    credential_ledger_namespace.as_str(),
                genesis_marker: LOCAL_RECONCILIATION_GENESIS_MARKER,
                predecessor_successor_key_sha256:
                    genesis_predecessor_successor_key_sha256.as_str(),
                ledger_sequence: 0,
                store_term: 0,
                store_log_index: 0,
                store_fencing_token: 0,
            };
        let pinned_genesis_state_jcs =
            canonical_jcs_bytes(&pinned_genesis_state)?;
        let expected_pinned_genesis_state_sha256 = domain_sha256(
            LOCAL_RECONCILIATION_PINNED_GENESIS_STATE_DOMAIN,
            &[pinned_genesis_state_jcs.as_slice()],
        )?;
        quorum_members.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let unique_member_ids: BTreeSet<&str> = quorum_members
            .iter()
            .map(|member| member.key_id.as_str())
            .collect();
        let unique_member_material: BTreeSet<&str> = quorum_members
            .iter()
            .map(|member| member.key_material_sha256.as_str())
            .collect();
        if quorum_members.is_empty()
            || pinned_genesis_state_sha256
                != expected_pinned_genesis_state_sha256
            || quorum_members.len() > MAX_LOCAL_RECONCILIATION_QUORUM_MEMBERS
            || usize::from(quorum_threshold) > quorum_members.len()
            || quorum_threshold == 0
            || unique_member_ids.len() != quorum_members.len()
            || unique_member_material.len() != quorum_members.len()
            || quorum_members.iter().any(|member| {
                member.key_id == transparency_operator_key_id
                    || member.key_material_sha256
                        == transparency_operator_key_material_sha256
                    || member.key_id == recovery_authority_key_id
                    || member.key_material_sha256
                        == recovery_authority_key_material_sha256
            })
            || recovery_authority_key_id == transparency_operator_key_id
            || recovery_authority_key_material_sha256
                == transparency_operator_key_material_sha256
            || anchor_checkpoint_revision == 0
            || anchor_checkpoint_tree_size == 0
            || current_checkpoint_revision < anchor_checkpoint_revision
            || current_checkpoint_tree_size < anchor_checkpoint_tree_size
            || (current_checkpoint_revision == anchor_checkpoint_revision)
                != (current_checkpoint_tree_size
                    == anchor_checkpoint_tree_size)
            || (current_checkpoint_revision == anchor_checkpoint_revision
                && current_checkpoint_root_sha256
                    != anchor_checkpoint_root_sha256)
            || revocation_epoch == 0
        {
            return Err(ContractError::new(
                "invalid_reconciliation_witness_authority_pin",
                "reconciliationWitnessAuthority",
                "external pin requires one canonical credential-ledger namespace and exact derived GENESIS state, a bounded unique quorum, separate transparency authority, positive checkpoints, and monotonic revision/tree state",
            ));
        }
        Ok(Self {
            linearizable_store_id,
            linearizable_store_cluster_id,
            credential_ledger_namespace,
            pinned_genesis_state_sha256,
            genesis_predecessor_successor_key_sha256,
            quorum_threshold,
            quorum_members,
            transparency_log_id,
            transparency_operator_key_id,
            transparency_operator_key_material_sha256,
            recovery_authority_key_id,
            recovery_authority_key_material_sha256,
            anchor_checkpoint_root_sha256,
            anchor_checkpoint_revision,
            anchor_checkpoint_tree_size,
            current_checkpoint_root_sha256,
            current_checkpoint_revision,
            current_checkpoint_tree_size,
            trust_checkpoint_sha256,
            revocation_epoch,
        })
    }

    fn quorum_member(
        &self,
        key_id: &str,
    ) -> Option<&PinnedReconciliationQuorumMember> {
        self.quorum_members
            .binary_search_by(|member| member.key_id.as_str().cmp(key_id))
            .ok()
            .map(|index| &self.quorum_members[index])
    }

    pub(crate) fn linearizable_store_id(&self) -> &str {
        &self.linearizable_store_id
    }

    pub(crate) fn linearizable_store_cluster_id(&self) -> &str {
        &self.linearizable_store_cluster_id
    }

    pub(crate) fn credential_ledger_namespace(&self) -> &str {
        &self.credential_ledger_namespace
    }

    pub(crate) fn pinned_genesis_state_sha256(&self) -> &str {
        &self.pinned_genesis_state_sha256
    }

    pub(crate) fn genesis_predecessor_successor_key_sha256(
        &self,
    ) -> &str {
        &self.genesis_predecessor_successor_key_sha256
    }

    pub(crate) fn quorum_threshold(&self) -> u16 {
        self.quorum_threshold
    }

    pub(crate) fn quorum_members(
        &self,
    ) -> &[PinnedReconciliationQuorumMember] {
        self.quorum_members.as_slice()
    }

    pub(crate) fn transparency_log_id(&self) -> &str {
        &self.transparency_log_id
    }

    pub(crate) fn transparency_operator_key_id(&self) -> &str {
        &self.transparency_operator_key_id
    }

    pub(crate) fn transparency_operator_key_material_sha256(
        &self,
    ) -> &str {
        &self.transparency_operator_key_material_sha256
    }

    pub(crate) fn recovery_authority_key_id(&self) -> &str {
        &self.recovery_authority_key_id
    }

    pub(crate) fn recovery_authority_key_material_sha256(&self) -> &str {
        &self.recovery_authority_key_material_sha256
    }

    pub(crate) fn anchor_checkpoint_root_sha256(&self) -> &str {
        &self.anchor_checkpoint_root_sha256
    }

    pub(crate) fn anchor_checkpoint_revision(&self) -> u64 {
        self.anchor_checkpoint_revision
    }

    pub(crate) fn anchor_checkpoint_tree_size(&self) -> u64 {
        self.anchor_checkpoint_tree_size
    }

    pub(crate) fn current_checkpoint_root_sha256(&self) -> &str {
        &self.current_checkpoint_root_sha256
    }

    pub(crate) fn current_checkpoint_revision(&self) -> u64 {
        self.current_checkpoint_revision
    }

    pub(crate) fn current_checkpoint_tree_size(&self) -> u64 {
        self.current_checkpoint_tree_size
    }

    pub(crate) fn trust_checkpoint_sha256(&self) -> &str {
        &self.trust_checkpoint_sha256
    }

    pub(crate) fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
}

#[derive(Debug)]
pub(crate) struct VerificationContext<'a> {
    purpose: VerificationPurpose,
    trusted_delivery_time_epoch_ms: u64,
    verification_reference_time_epoch_ms: u64,
    expected_runtime: &'a VerifiedRuntimeIdentity,
    current_trust_checkpoint_sha256: String,
    current_revocation_epoch: u64,
    archival_checkpoint: Option<FinalizationCheckpointEvidencePayload>,
    reconciliation_witness_authority:
        Option<PinnedReconciliationWitnessAuthority>,
}

impl<'a> VerificationContext<'a> {
    pub(crate) fn new(
        trusted_now_epoch_ms: u64,
        expected_runtime: &'a VerifiedRuntimeIdentity,
        current_trust_checkpoint_sha256: &'a str,
        current_revocation_epoch: u64,
    ) -> ContractResult<Self> {
        validate_safe_time(trusted_now_epoch_ms, "trustedNowEpochMs")?;
        validate_digest(
            current_trust_checkpoint_sha256,
            "verificationContext.currentTrustCheckpointSha256",
        )?;
        validate_safe_integer(
            current_revocation_epoch,
            "verificationContext.currentRevocationEpoch",
        )?;
        if current_revocation_epoch == 0 {
            return Err(ContractError::new(
                "invalid_revocation_epoch",
                "verificationContext.currentRevocationEpoch",
                "current revocation epoch must be positive",
            ));
        }
        if expected_runtime.verification_purpose()
            != VerificationPurpose::LiveAuthorization
        {
            return Err(ContractError::new(
                "live_context_requires_live_runtime",
                "verificationContext.expectedRuntime",
                "LIVE_AUTHORIZATION requires a currently verified runtime attestation",
            ));
        }
        if trusted_now_epoch_ms < expected_runtime.verified_at_epoch_ms
            || trusted_now_epoch_ms > expected_runtime.expires_at_epoch_ms
        {
            return Err(ContractError::new(
                "verified_runtime_expired",
                "verificationContext.expectedRuntime",
                "verified runtime is outside its independent attestation window",
            ));
        }
        Ok(Self {
            purpose: VerificationPurpose::LiveAuthorization,
            trusted_delivery_time_epoch_ms: trusted_now_epoch_ms,
            verification_reference_time_epoch_ms: trusted_now_epoch_ms,
            expected_runtime,
            current_trust_checkpoint_sha256:
                current_trust_checkpoint_sha256.to_owned(),
            current_revocation_epoch,
            archival_checkpoint: None,
            reconciliation_witness_authority: None,
        })
    }

    pub(crate) fn new_archival(
        trusted_delivery_time_epoch_ms: u64,
        expected_runtime: &'a VerifiedRuntimeIdentity,
        checkpoint: FinalizationCheckpointEvidencePayload,
    ) -> ContractResult<Self> {
        validate_safe_time(
            trusted_delivery_time_epoch_ms,
            "trustedDeliveryTimeEpochMs",
        )?;
        validate_finalization_checkpoint_payload(&checkpoint)?;
        let inclusion = expected_runtime.historical_inclusion().ok_or_else(|| {
            ContractError::new(
                "archival_runtime_not_historically_verified",
                "verificationContext.expectedRuntime",
                "ARCHIVAL_VERIFICATION requires a historically included runtime attestation",
            )
        })?;
        if expected_runtime.verification_purpose()
                != VerificationPurpose::ArchivalVerification
            || trusted_delivery_time_epoch_ms
                < checkpoint.finalized_at_epoch_ms
            || inclusion.finalized_at_epoch_ms
                != checkpoint.finalized_at_epoch_ms
            || inclusion.trusted_time_epoch_ms
                != checkpoint.trusted_time_epoch_ms
            || inclusion.trust_checkpoint_sha256
                != checkpoint.trust_checkpoint_sha256
            || inclusion.revocation_epoch != checkpoint.revocation_epoch
            || inclusion.historical_trust_policy_sha256
                != checkpoint.historical_trust_policy_sha256
            || inclusion.historical_key_set_root_sha256
                != checkpoint.historical_key_set_root_sha256
            || inclusion.historical_key_inclusion_proof_sha256
                != checkpoint.historical_key_inclusion_proof_sha256
            || inclusion.historical_non_revocation_proof_sha256
                != checkpoint.historical_non_revocation_proof_sha256
            || inclusion.runtime_attestation_inclusion_proof_sha256
                != checkpoint.runtime_attestation_inclusion_proof_sha256
        {
            return Err(ContractError::new(
                "archival_checkpoint_runtime_mismatch",
                "verificationContext",
                "archival context must exactly match the historically verified runtime and finalization checkpoint",
            ));
        }
        Ok(Self {
            purpose: VerificationPurpose::ArchivalVerification,
            trusted_delivery_time_epoch_ms,
            verification_reference_time_epoch_ms:
                checkpoint.trusted_time_epoch_ms,
            expected_runtime,
            current_trust_checkpoint_sha256:
                checkpoint.trust_checkpoint_sha256.clone(),
            current_revocation_epoch: checkpoint.revocation_epoch,
            archival_checkpoint: Some(checkpoint),
            reconciliation_witness_authority: None,
        })
    }

    pub(crate) fn with_reconciliation_witness_authority(
        mut self,
        authority: PinnedReconciliationWitnessAuthority,
    ) -> ContractResult<Self> {
        if authority.trust_checkpoint_sha256
                != self.current_trust_checkpoint_sha256
            || authority.revocation_epoch != self.current_revocation_epoch
        {
            return Err(ContractError::new(
                "reconciliation_witness_authority_checkpoint_mismatch",
                "verificationContext.reconciliationWitnessAuthority",
                "externally pinned reconciliation authority must use the exact effective trust checkpoint and revocation epoch",
            ));
        }
        self.reconciliation_witness_authority = Some(authority);
        Ok(self)
    }

    pub(crate) fn trusted_now_epoch_ms(&self) -> u64 {
        self.verification_reference_time_epoch_ms
    }

    pub(crate) fn trusted_delivery_time_epoch_ms(&self) -> u64 {
        self.trusted_delivery_time_epoch_ms
    }

    pub(crate) fn purpose(&self) -> VerificationPurpose {
        self.purpose
    }

    pub(crate) fn archival_checkpoint(
        &self,
    ) -> Option<&FinalizationCheckpointEvidencePayload> {
        self.archival_checkpoint.as_ref()
    }

    pub(crate) fn expected_runtime(&self) -> &VerifiedRuntimeIdentity {
        self.expected_runtime
    }

    pub(crate) fn current_trust_checkpoint_sha256(&self) -> &str {
        &self.current_trust_checkpoint_sha256
    }

    pub(crate) fn current_revocation_epoch(&self) -> u64 {
        self.current_revocation_epoch
    }

    fn reconciliation_witness_authority(
        &self,
    ) -> Option<&PinnedReconciliationWitnessAuthority> {
        self.reconciliation_witness_authority.as_ref()
    }
}

/// Internally constructed purpose passed to the signature trust capability.
/// It prevents a verifier from treating cryptographic validity as sufficient
/// when a key is not trusted for this exact role, domain, algorithm, and
/// independently attested runtime.
#[derive(Debug)]
pub(crate) struct EvidenceVerificationPurpose<'a> {
    verification_purpose: VerificationPurpose,
    evidence_type: EvidenceType,
    evidence_role: EvidenceRole,
    signature_domain: &'static str,
    payload_domain: &'static str,
    algorithm: SignatureAlgorithm,
    expected_runtime: &'a BootRuntimeIdentity,
    runtime_attestation_evidence_sha256: &'a str,
    runtime_attestation_verifier_key_id: &'a str,
    historical_checkpoint:
        Option<&'a FinalizationCheckpointEvidencePayload>,
    artifact_checkpoint:
        Option<&'a ArtifactTimeCheckpointEvidencePayload>,
    credential_authority_id: Option<&'a str>,
    credential_authority_operation: Option<CredentialAuthorityOperation>,
}

impl<'a> EvidenceVerificationPurpose<'a> {
    pub(crate) fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub(crate) fn evidence_type(&self) -> EvidenceType {
        self.evidence_type
    }

    pub(crate) fn evidence_role(&self) -> EvidenceRole {
        self.evidence_role
    }

    pub(crate) fn signature_domain(&self) -> &'static str {
        self.signature_domain
    }

    pub(crate) fn payload_domain(&self) -> &'static str {
        self.payload_domain
    }

    pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub(crate) fn expected_runtime(&self) -> &BootRuntimeIdentity {
        self.expected_runtime
    }

    pub(crate) fn runtime_attestation_evidence_sha256(&self) -> &str {
        self.runtime_attestation_evidence_sha256
    }

    pub(crate) fn runtime_attestation_verifier_key_id(&self) -> &str {
        self.runtime_attestation_verifier_key_id
    }

    pub(crate) fn historical_checkpoint(
        &self,
    ) -> Option<&FinalizationCheckpointEvidencePayload> {
        self.historical_checkpoint
    }

    pub(crate) fn artifact_checkpoint(
        &self,
    ) -> Option<&ArtifactTimeCheckpointEvidencePayload> {
        self.artifact_checkpoint
    }

    pub(crate) fn credential_authority_id(&self) -> Option<&str> {
        self.credential_authority_id
    }

    pub(crate) fn credential_authority_operation(
        &self,
    ) -> Option<CredentialAuthorityOperation> {
        self.credential_authority_operation
    }
}

#[derive(Debug)]
pub(crate) struct EvidenceSignatureVerification {
    accepted: bool,
    pinned_trust_policy_sha256: String,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
    key_material_sha256: String,
    historical_key_inclusion_verified: bool,
    historical_non_revocation_verified: bool,
    revoked_at_epoch_ms: Option<u64>,
    credential_authority_id: Option<String>,
    credential_authority_operation: Option<CredentialAuthorityOperation>,
}

impl EvidenceSignatureVerification {
    pub(crate) fn rejected(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
    ) -> Self {
        Self {
            accepted: false,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: false,
            historical_non_revocation_verified: false,
            revoked_at_epoch_ms: None,
            credential_authority_id: None,
            credential_authority_operation: None,
        }
    }

    pub(crate) fn accepted_role(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
    ) -> Self {
        Self {
            accepted: true,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: false,
            historical_non_revocation_verified: false,
            revoked_at_epoch_ms: None,
            credential_authority_id: None,
            credential_authority_operation: None,
        }
    }

    pub(crate) fn accepted_credential_authority(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
        authority_id: String,
        operation: CredentialAuthorityOperation,
    ) -> Self {
        Self {
            accepted: true,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: false,
            historical_non_revocation_verified: false,
            revoked_at_epoch_ms: None,
            credential_authority_id: Some(authority_id),
            credential_authority_operation: Some(operation),
        }
    }

    pub(crate) fn accepted_historical_role(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
    ) -> Self {
        Self {
            accepted: true,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: true,
            historical_non_revocation_verified: true,
            revoked_at_epoch_ms: None,
            credential_authority_id: None,
            credential_authority_operation: None,
        }
    }

    pub(crate) fn accepted_historical_role_at(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
        revoked_at_epoch_ms: Option<u64>,
    ) -> Self {
        Self {
            accepted: true,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: true,
            historical_non_revocation_verified: true,
            revoked_at_epoch_ms,
            credential_authority_id: None,
            credential_authority_operation: None,
        }
    }

    pub(crate) fn accepted_historical_credential_authority(
        pinned_trust_policy_sha256: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
        authority_id: String,
        operation: CredentialAuthorityOperation,
    ) -> Self {
        Self {
            accepted: true,
            pinned_trust_policy_sha256,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            historical_key_inclusion_verified: true,
            historical_non_revocation_verified: true,
            revoked_at_epoch_ms: None,
            credential_authority_id: Some(authority_id),
            credential_authority_operation: Some(operation),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReconciliationQuorumMemberVerificationPurpose<'a> {
    verification_purpose: VerificationPurpose,
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    store_transaction_id: &'a str,
    store_transition_sha256: &'a str,
    predecessor_record_id: Option<&'a str>,
    predecessor_record_sha256: Option<&'a str>,
    successor_record_id: &'a str,
    successor_record_sha256: &'a str,
    cas_expected_predecessor_sha256: &'a str,
    cas_observed_predecessor_sha256: &'a str,
    cas_successor_sha256: &'a str,
    store_term: u64,
    store_log_index: u64,
    store_fencing_token: u64,
    trust_checkpoint_sha256: &'a str,
    revocation_epoch: u64,
    historical_checkpoint:
        Option<&'a FinalizationCheckpointEvidencePayload>,
    expected_runtime: &'a BootRuntimeIdentity,
}

impl<'a> ReconciliationQuorumMemberVerificationPurpose<'a> {
    pub(crate) fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub(crate) fn linearizable_store_id(&self) -> &str {
        self.linearizable_store_id
    }

    pub(crate) fn linearizable_store_cluster_id(&self) -> &str {
        self.linearizable_store_cluster_id
    }

    pub(crate) fn credential_ledger_namespace(&self) -> &str {
        self.credential_ledger_namespace
    }

    pub(crate) fn pinned_genesis_state_sha256(&self) -> &str {
        self.pinned_genesis_state_sha256
    }

    pub(crate) fn predecessor_successor_key_sha256(&self) -> &str {
        self.predecessor_successor_key_sha256
    }

    pub(crate) fn store_transaction_id(&self) -> &str {
        self.store_transaction_id
    }

    pub(crate) fn store_transition_sha256(&self) -> &str {
        self.store_transition_sha256
    }

    pub(crate) fn predecessor_record_id(&self) -> Option<&str> {
        self.predecessor_record_id
    }

    pub(crate) fn predecessor_record_sha256(&self) -> Option<&str> {
        self.predecessor_record_sha256
    }

    pub(crate) fn successor_record_id(&self) -> &str {
        self.successor_record_id
    }

    pub(crate) fn successor_record_sha256(&self) -> &str {
        self.successor_record_sha256
    }

    pub(crate) fn cas_expected_predecessor_sha256(&self) -> &str {
        self.cas_expected_predecessor_sha256
    }

    pub(crate) fn cas_observed_predecessor_sha256(&self) -> &str {
        self.cas_observed_predecessor_sha256
    }

    pub(crate) fn cas_successor_sha256(&self) -> &str {
        self.cas_successor_sha256
    }

    pub(crate) fn store_term(&self) -> u64 {
        self.store_term
    }

    pub(crate) fn store_log_index(&self) -> u64 {
        self.store_log_index
    }

    pub(crate) fn store_fencing_token(&self) -> u64 {
        self.store_fencing_token
    }

    pub(crate) fn trust_checkpoint_sha256(&self) -> &str {
        self.trust_checkpoint_sha256
    }

    pub(crate) fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub(crate) fn historical_checkpoint(
        &self,
    ) -> Option<&FinalizationCheckpointEvidencePayload> {
        self.historical_checkpoint
    }

    pub(crate) fn expected_runtime(&self) -> &BootRuntimeIdentity {
        self.expected_runtime
    }
}

#[derive(Debug)]
pub(crate) struct ReconciliationQuorumMemberVerification {
    accepted: bool,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
    key_material_sha256: String,
    revoked_at_epoch_ms: Option<u64>,
}

impl ReconciliationQuorumMemberVerification {
    pub(crate) fn new(
        accepted: bool,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        key_material_sha256: String,
        revoked_at_epoch_ms: Option<u64>,
    ) -> Self {
        Self {
            accepted,
            trust_checkpoint_sha256,
            revocation_epoch,
            key_material_sha256,
            revoked_at_epoch_ms,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReconciliationTransparencyVerificationPurpose<'a> {
    verification_purpose: VerificationPurpose,
    proof: &'a LocalReconciliationTransparencyLogProof,
    predecessor_record_id: Option<&'a str>,
    predecessor_record_sha256: Option<&'a str>,
    successor_record_id: &'a str,
    successor_record_sha256: &'a str,
    externally_pinned_authority:
        &'a PinnedReconciliationWitnessAuthority,
    historical_checkpoint:
        Option<&'a FinalizationCheckpointEvidencePayload>,
    expected_runtime: &'a BootRuntimeIdentity,
}

impl<'a> ReconciliationTransparencyVerificationPurpose<'a> {
    pub(crate) fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub(crate) fn proof(&self) -> &LocalReconciliationTransparencyLogProof {
        self.proof
    }

    pub(crate) fn predecessor_record_id(&self) -> Option<&str> {
        self.predecessor_record_id
    }

    pub(crate) fn predecessor_record_sha256(&self) -> Option<&str> {
        self.predecessor_record_sha256
    }

    pub(crate) fn successor_record_id(&self) -> &str {
        self.successor_record_id
    }

    pub(crate) fn successor_record_sha256(&self) -> &str {
        self.successor_record_sha256
    }

    pub(crate) fn externally_pinned_authority(
        &self,
    ) -> &PinnedReconciliationWitnessAuthority {
        self.externally_pinned_authority
    }

    pub(crate) fn historical_checkpoint(
        &self,
    ) -> Option<&FinalizationCheckpointEvidencePayload> {
        self.historical_checkpoint
    }

    pub(crate) fn expected_runtime(&self) -> &BootRuntimeIdentity {
        self.expected_runtime
    }
}

#[derive(Debug)]
pub(crate) struct ReconciliationTransparencyVerification {
    accepted: bool,
    transparency_log_id: String,
    transparency_operator_key_material_sha256: String,
    store_transaction_id: String,
    store_transition_sha256: String,
    predecessor_successor_key_sha256: String,
    leaf_sha256: String,
    proof_sha256: String,
    checkpoint_root_sha256: String,
    checkpoint_revision: u64,
    checkpoint_tree_size: u64,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
    inclusion_verified: bool,
    consistency_verified: bool,
    conflicting_successor_detected: bool,
    revoked_at_epoch_ms: Option<u64>,
}

impl ReconciliationTransparencyVerification {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        accepted: bool,
        transparency_log_id: String,
        transparency_operator_key_material_sha256: String,
        store_transaction_id: String,
        store_transition_sha256: String,
        predecessor_successor_key_sha256: String,
        leaf_sha256: String,
        proof_sha256: String,
        checkpoint_root_sha256: String,
        checkpoint_revision: u64,
        checkpoint_tree_size: u64,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        inclusion_verified: bool,
        consistency_verified: bool,
        conflicting_successor_detected: bool,
        revoked_at_epoch_ms: Option<u64>,
    ) -> Self {
        Self {
            accepted,
            transparency_log_id,
            transparency_operator_key_material_sha256,
            store_transaction_id,
            store_transition_sha256,
            predecessor_successor_key_sha256,
            leaf_sha256,
            proof_sha256,
            checkpoint_root_sha256,
            checkpoint_revision,
            checkpoint_tree_size,
            trust_checkpoint_sha256,
            revocation_epoch,
            inclusion_verified,
            consistency_verified,
            conflicting_successor_detected,
            revoked_at_epoch_ms,
        }
    }
}

pub(crate) trait EvidenceSignatureVerifier {
    /// Verify a role-scoped signature over the fixed 32-byte digest of the
    /// incrementally hashed, domain-separated signing commitment.
    ///
    /// Implementations MUST reject a key that is not trusted for every field in
    /// `purpose`, even when the Ed25519 signature is otherwise valid. For
    /// CredentialAuthority evidence this includes the exact authorityId and
    /// operation; generic role-only or provider-wide acceptance is invalid
    /// unless pinned trust policy explicitly contains that exact pair. The
    /// returned checkpoint and revocation epoch must be the caller-pinned
    /// current values, and keyMaterialSha256 must identify the verified public
    /// key material independently of its keyId alias. For archival purpose the
    /// implementation must independently retrieve the checkpoint-identified
    /// historical trust policy and proofs and establish this exact keyId,
    /// material, role, authority scope, and non-revocation as of finalization.
    /// When `artifact_checkpoint` is present it must instead establish those
    /// facts, trusted time, runtime-attestation inclusion, and non-revocation
    /// as of that exact artifact timestamp and reject revocation at or before
    /// the timestamp.
    fn verify_role_scoped_ed25519(
        &self,
        purpose: &EvidenceVerificationPurpose<'_>,
        key_id: &str,
        message: &[u8],
        signature: &str,
    ) -> EvidenceSignatureVerification;

    /// Verify one independently pinned linearizable-store quorum member over
    /// the exact credential-ledger namespace, canonical genesis state,
    /// predecessor conflict key, predecessor-to-successor CAS tuple, and
    /// transaction ID.
    fn verify_reconciliation_quorum_member_ed25519(
        &self,
        purpose: &ReconciliationQuorumMemberVerificationPurpose<'_>,
        key_id: &str,
        message: &[u8],
        signature: &str,
    ) -> ReconciliationQuorumMemberVerification;

    /// Independently verify the separately administered append-only log's
    /// checkpoint signature, inclusion, consistency from the pinned anchor,
    /// and absence of another successor for the exact proof-independent
    /// store/cluster/credential-ledger predecessor key.
    fn verify_reconciliation_transparency_log(
        &self,
        purpose: &ReconciliationTransparencyVerificationPurpose<'_>,
        checkpoint_signing_message: &[u8],
        checkpoint_signature: &str,
    ) -> ReconciliationTransparencyVerification;
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FinalizationArtifactRole {
    EnvelopeAttestation,
    PublicationReceipt,
}

#[derive(Debug)]
pub(crate) struct FinalizationArtifactVerificationPurpose<'a> {
    verification_purpose: VerificationPurpose,
    role: FinalizationArtifactRole,
    artifact_sha256: &'a str,
    prerequisite_attestation_sha256: Option<&'a str>,
    attempt_id: &'a str,
    retrieval_id: &'a str,
    envelope_sha256: &'a str,
    occurred_at_epoch_ms: u64,
    expected_runtime: &'a BootRuntimeIdentity,
    runtime_attestation_evidence_sha256: &'a str,
    runtime_attestation_verifier_key_id: &'a str,
    finalization_checkpoint: &'a FinalizationCheckpointEvidencePayload,
    artifact_time_checkpoint: &'a ArtifactTimeCheckpointEvidencePayload,
    artifact_time_checkpoint_evidence_sha256: &'a str,
}

impl<'a> FinalizationArtifactVerificationPurpose<'a> {
    pub fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub fn role(&self) -> FinalizationArtifactRole {
        self.role
    }

    pub fn artifact_sha256(&self) -> &str {
        self.artifact_sha256
    }

    pub fn prerequisite_attestation_sha256(&self) -> Option<&str> {
        self.prerequisite_attestation_sha256
    }

    pub fn attempt_id(&self) -> &str {
        self.attempt_id
    }

    pub fn retrieval_id(&self) -> &str {
        self.retrieval_id
    }

    pub fn envelope_sha256(&self) -> &str {
        self.envelope_sha256
    }

    pub fn occurred_at_epoch_ms(&self) -> u64 {
        self.occurred_at_epoch_ms
    }

    pub fn expected_runtime(&self) -> &BootRuntimeIdentity {
        self.expected_runtime
    }

    pub fn runtime_attestation_evidence_sha256(&self) -> &str {
        self.runtime_attestation_evidence_sha256
    }

    pub fn runtime_attestation_verifier_key_id(&self) -> &str {
        self.runtime_attestation_verifier_key_id
    }

    pub fn finalization_checkpoint(
        &self,
    ) -> &FinalizationCheckpointEvidencePayload {
        self.finalization_checkpoint
    }

    pub fn artifact_time_checkpoint(
        &self,
    ) -> &ArtifactTimeCheckpointEvidencePayload {
        self.artifact_time_checkpoint
    }

    pub fn artifact_time_checkpoint_evidence_sha256(&self) -> &str {
        self.artifact_time_checkpoint_evidence_sha256
    }
}

#[derive(Debug)]
pub(crate) struct FinalizationArtifactVerification {
    accepted: bool,
    artifact_signing_key_id: String,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
    historical_trust_policy_sha256: String,
    historical_key_inclusion_verified: bool,
    historical_non_revocation_verified: bool,
    runtime_attestation_inclusion_verified: bool,
    immutable_artifact_retrieval_verified: bool,
    artifact_key_valid_at_timestamp: bool,
    revoked_at_epoch_ms: Option<u64>,
}

impl FinalizationArtifactVerification {
    pub(crate) fn rejected(
        artifact_signing_key_id: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        historical_trust_policy_sha256: String,
    ) -> Self {
        Self {
            accepted: false,
            artifact_signing_key_id,
            trust_checkpoint_sha256,
            revocation_epoch,
            historical_trust_policy_sha256,
            historical_key_inclusion_verified: false,
            historical_non_revocation_verified: false,
            runtime_attestation_inclusion_verified: false,
            immutable_artifact_retrieval_verified: false,
            artifact_key_valid_at_timestamp: false,
            revoked_at_epoch_ms: None,
        }
    }

    pub(crate) fn accepted_historical(
        artifact_signing_key_id: String,
        trust_checkpoint_sha256: String,
        revocation_epoch: u64,
        historical_trust_policy_sha256: String,
        revoked_at_epoch_ms: Option<u64>,
    ) -> Self {
        Self {
            accepted: true,
            artifact_signing_key_id,
            trust_checkpoint_sha256,
            revocation_epoch,
            historical_trust_policy_sha256,
            historical_key_inclusion_verified: true,
            historical_non_revocation_verified: true,
            runtime_attestation_inclusion_verified: true,
            immutable_artifact_retrieval_verified: true,
            artifact_key_valid_at_timestamp: true,
            revoked_at_epoch_ms,
        }
    }
}

pub(crate) trait FinalizationArtifactVerifier {
    /// Verify the exact attestation or publication artifact identified by the
    /// digest and all immutable envelope bindings in `purpose`. Archival
    /// acceptance authenticates history only and must never cause dispatch,
    /// publication, reconciliation, cleanup, or another state mutation.
    /// Implementations must use the required artifact-time checkpoint, not the
    /// finalization checkpoint alone, and independently verify the exact
    /// artifact key inclusion, non-revocation, trust policy, runtime-
    /// attestation inclusion, immutable receipt, and retrieval proof at the
    /// signed artifact timestamp.
    fn verify_finalization_artifact(
        &self,
        purpose: &FinalizationArtifactVerificationPurpose<'_>,
    ) -> FinalizationArtifactVerification;
}

#[derive(Debug)]
pub(crate) struct RetrievedEnvelopeBytes {
    pub attempt_id: String,
    pub retrieval_id: String,
    pub canonical_bytes: Vec<u8>,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub immutable: bool,
    pub replacement_prohibited: bool,
}

pub(crate) struct RetrievedStagedRequestBytes {
    pub retrieval_id: String,
    pub exact_request_bytes: Vec<u8>,
    pub wire_protocol: TargetWireProtocol,
    pub transport_scheme: TargetScheme,
    pub authenticated_peer_authority: String,
    pub immutable: bool,
    pub replacement_prohibited: bool,
}

pub(crate) struct RetrievedUpstreamResponseBytes {
    pub attempt_id: String,
    pub retrieval_id: String,
    pub staged_request_sha256: String,
    pub dispatch_evidence_sha256: String,
    pub exact_response_bytes: Vec<u8>,
    pub wire_protocol: UpstreamResponseWireProtocol,
    pub transport_scheme: TargetScheme,
    pub authenticated_peer_authority: String,
    pub completion: UpstreamResponseCompletion,
    pub protocol_validation_receipt_sha256: String,
    pub unsupported_reason: Option<ExactResponseUnsupportedReason>,
    pub authenticated_eof_receipt_sha256: Option<String>,
    pub immutable: bool,
    pub replacement_prohibited: bool,
}

pub(crate) struct RetrievedLocalReconciliationRecordBytes {
    pub retrieval_id: String,
    pub exact_record_bytes: Vec<u8>,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub immutable: bool,
    pub replacement_prohibited: bool,
}

pub(crate) struct RetrievedSignedLocalReconciliationEvidenceBytes {
    pub retrieval_id: String,
    pub exact_evidence_bytes: Vec<u8>,
    pub persistence_receipt_sha256: String,
    pub retrieval_proof_sha256: String,
    pub immutable: bool,
    pub replacement_prohibited: bool,
}

pub(crate) struct RetrievedLocalReconciliationContinuityBytes {
    pub current_record_id: String,
    pub continuity_evidence:
        RetrievedSignedLocalReconciliationEvidenceBytes,
    pub ledger_witness_evidence:
        RetrievedSignedLocalReconciliationEvidenceBytes,
    pub predecessor_record: Option<RetrievedLocalReconciliationRecordBytes>,
    pub predecessor_recovery_evidence:
        Option<RetrievedSignedLocalReconciliationEvidenceBytes>,
    pub genesis_absence_evidence:
        Option<RetrievedSignedLocalReconciliationEvidenceBytes>,
}

pub(crate) struct TrustedResponsePolicyValidation {
    pub profile_sha256: String,
    pub exact_response_bytes_sha256: String,
    pub restrictions_sha256: String,
    pub decision: ResponsePolicyDecision,
    pub validation_sha256: String,
}

struct VerifiedExactStagedRequest {
    staging_sha256: String,
    operation_semantics_sha256: String,
    dispatch_authorization_binding_sha256: String,
    idempotency_key_sha256: Option<String>,
}

struct VerifiedExactUpstreamResponse {
    exact_response_bytes_sha256: String,
    response_policy_validation_sha256: Option<String>,
    completion: UpstreamResponseCompletion,
    unsupported_reason: Option<ExactResponseUnsupportedReason>,
}

struct VerifiedLocalReconciliationRecord {
    record: LocalAcquisitionReconciliationRecord,
    record_id: String,
    record_sha256: String,
    record_byte_length: u64,
    retrieval_id: String,
    persistence_receipt_sha256: String,
    retrieval_proof_sha256: String,
}

struct VerifiedLocalReconciliationContinuity {
    continuity:
        VerifiedEvidence<LocalReconciliationContinuityEvidencePayload>,
    ledger_witness: VerifiedEvidence<LocalReconciliationLedgerWitness>,
    predecessor_record: Option<VerifiedLocalReconciliationRecord>,
    predecessor_recovery:
        Option<VerifiedEvidence<LocalReconciliationRecoveryEvidencePayload>>,
    genesis_absence:
        Option<VerifiedEvidence<LocalReconciliationGenesisAbsenceEvidencePayload>>,
    predecessor_proof_sha256: String,
    store_transition_sha256: String,
    quorum_certificate_sha256: String,
    transparency_log_proof_sha256: String,
    quorum_member_key_ids: BTreeSet<String>,
    quorum_member_key_material_sha256: BTreeSet<String>,
    transparency_operator_key_id: String,
    transparency_operator_key_material_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationPinnedGenesisStateCommitment<'a> {
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    genesis_marker: &'a str,
    predecessor_successor_key_sha256: &'a str,
    ledger_sequence: u64,
    store_term: u64,
    store_log_index: u64,
    store_fencing_token: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationConflictKeyCommitment<'a> {
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    predecessor_identity: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationStoreStateCommitment<'a> {
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    ledger_id: &'a str,
    record_id: Option<&'a str>,
    record_sha256: Option<&'a str>,
    ledger_sequence: u64,
    ledger_checkpoint_sha256: &'a str,
    rollback_head_sha256: &'a str,
    store_term: u64,
    store_log_index: u64,
    store_fencing_token: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationStoreTransitionCommitment<'a> {
    attempt_id: &'a str,
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    store_transaction_id: &'a str,
    ledger_id: &'a str,
    predecessor_record_id: Option<&'a str>,
    predecessor_record_sha256: Option<&'a str>,
    successor_record_id: &'a str,
    successor_record_sha256: &'a str,
    predecessor_ledger_sequence: u64,
    successor_ledger_sequence: u64,
    predecessor_checkpoint_sha256: &'a str,
    successor_checkpoint_sha256: &'a str,
    predecessor_store_term: u64,
    predecessor_store_log_index: u64,
    predecessor_store_fencing_token: u64,
    successor_store_term: u64,
    successor_store_log_index: u64,
    successor_store_fencing_token: u64,
    cas_expected_predecessor_sha256: &'a str,
    cas_observed_predecessor_sha256: &'a str,
    cas_successor_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationQuorumMemberSigningCommitment<'a, 'b> {
    member_key_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    transition: &'a LocalReconciliationStoreTransitionCommitment<'b>,
    store_transition_sha256: &'a str,
    store_transaction_id: &'a str,
    store_term: u64,
    store_log_index: u64,
    store_fencing_token: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationQuorumCertificateCommitment<'a> {
    linearizable_store_id: &'a str,
    linearizable_store_cluster_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    store_transaction_id: &'a str,
    store_transition_sha256: &'a str,
    store_term: u64,
    store_log_index: u64,
    store_fencing_token: u64,
    quorum_threshold: u16,
    members: &'a [LocalReconciliationQuorumMemberSignature],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationTransparencyLeafCommitment<'a> {
    transparency_log_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    store_transaction_id: &'a str,
    store_transition_sha256: &'a str,
    quorum_certificate_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationTransparencyCheckpointCommitment<'a> {
    transparency_log_id: &'a str,
    transparency_operator_key_id: &'a str,
    checkpoint_root_sha256: &'a str,
    checkpoint_revision: u64,
    checkpoint_tree_size: u64,
    trust_checkpoint_sha256: &'a str,
    revocation_epoch: u64,
    signed_at_epoch_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalReconciliationTransparencyProofCommitment<'a> {
    transparency_log_id: &'a str,
    transparency_operator_key_id: &'a str,
    credential_ledger_namespace: &'a str,
    pinned_genesis_state_sha256: &'a str,
    store_transaction_id: &'a str,
    store_transition_sha256: &'a str,
    quorum_certificate_sha256: &'a str,
    predecessor_successor_key_sha256: &'a str,
    leaf_sha256: &'a str,
    leaf_index: u64,
    anchor_checkpoint_root_sha256: &'a str,
    anchor_checkpoint_revision: u64,
    anchor_checkpoint_tree_size: u64,
    current_checkpoint_root_sha256: &'a str,
    current_checkpoint_revision: u64,
    current_checkpoint_tree_size: u64,
    inclusion_path_sha256: &'a [String],
    consistency_path_sha256: &'a [String],
    conflicting_successor_absence_proof_sha256: &'a str,
    trust_checkpoint_sha256: &'a str,
    revocation_epoch: u64,
    signed_at_epoch_ms: u64,
    checkpoint_signature: &'a str,
}

struct VerifiedLocalReconciliationStoreWitness {
    store_transition_sha256: String,
    quorum_certificate_sha256: String,
    transparency_log_proof_sha256: String,
    quorum_member_key_ids: BTreeSet<String>,
    quorum_member_key_material_sha256: BTreeSet<String>,
    transparency_operator_key_id: String,
    transparency_operator_key_material_sha256: String,
}

pub(crate) trait ExactBytePersistenceVerifier {
    /// Retrieve the immutable object through the trusted persistence boundary.
    ///
    /// Implementations must use `retrieval_id` as the lookup key and return the
    /// stored bytes and storage-enforced immutability state, not proof-body
    /// assertions.
    fn retrieve_exact_envelope(
        &self,
        retrieval_id: &str,
    ) -> ContractResult<RetrievedEnvelopeBytes>;

    /// Retrieve the immutable exact request bytes from the custody boundary.
    /// The Rust verifier independently hashes and parses those bytes and checks
    /// the custody-reported wire protocol, HTTPS transport, and authenticated
    /// peer authority; proof metadata is never a substitute for retrieval.
    fn retrieve_exact_staged_request(
        &self,
        retrieval_id: &str,
    ) -> ContractResult<RetrievedStagedRequestBytes>;

    /// Retrieve the immutable physical upstream response before any policy
    /// validation or attestation accepts claims derived from that response.
    fn retrieve_exact_upstream_response(
        &self,
        retrieval_id: &str,
    ) -> ContractResult<RetrievedUpstreamResponseBytes>;

    /// Retrieve the exact immutable canonical local reconciliation record and
    /// storage-generated persistence/retrieval proofs. The verifier decodes and
    /// canonicalizes the returned bytes itself; reference metadata in the proof
    /// is never accepted as record authority.
    fn retrieve_exact_local_reconciliation_record(
        &self,
        retrieval_id: &str,
    ) -> ContractResult<RetrievedLocalReconciliationRecordBytes>;

    /// Retrieve the immutable signed continuity graph for one current record.
    /// The returned closed branch contains either the exact predecessor record
    /// and its exact signed recovery evidence or the exact signed genesis
    /// absence evidence, plus the exact signed monotonic ledger witness.
    fn retrieve_exact_local_reconciliation_continuity(
        &self,
        current_record_id: &str,
        continuity_retrieval_id: &str,
        ledger_witness_retrieval_id: &str,
    ) -> ContractResult<RetrievedLocalReconciliationContinuityBytes>;

    /// Apply the trusted, provider-specific response validator to the exact
    /// retrieved physical response, final headers, exact trailers, and decoded
    /// entity bytes. The returned digest is independently reconstructed below
    /// and cannot be supplied by the response-observation producer.
    fn validate_exact_response_policy(
        &self,
        profile: &ResponsePolicyProfile,
        status: u16,
        exact_response_bytes: &[u8],
        header_block: &[u8],
        trailer_block: &[u8],
        body: &[u8],
        exact_response_bytes_sha256: &str,
        completion: UpstreamResponseCompletion,
    ) -> ContractResult<TrustedResponsePolicyValidation>;
}

mod sealed {
    pub trait EvidencePayload {}
}

trait EvidencePayload:
    sealed::EvidencePayload + Clone + Serialize + PartialEq + Eq
{
    const EVIDENCE_TYPE: EvidenceType;

    fn evidence_role(&self) -> EvidenceRole;
    fn payload_domain(&self) -> &'static str;
    fn signature_domain(&self) -> &'static str;
    fn attempt_id(&self) -> &str;
    fn action_epoch_ms(&self) -> u64;
    fn validate_payload(&self) -> ContractResult<()>;
    fn credential_authority_scope(
        &self,
    ) -> Option<(&str, CredentialAuthorityOperation)> {
        None
    }
}

macro_rules! evidence_payload {
    (
        $type:ty,
        $evidence_type:expr,
        $evidence_role:expr,
        $payload_domain:expr,
        $signature_domain:expr,
        $attempt_field:ident,
        $action:expr,
        $validate:expr
    ) => {
        impl sealed::EvidencePayload for $type {}
        impl EvidencePayload for $type {
            const EVIDENCE_TYPE: EvidenceType = $evidence_type;

            fn evidence_role(&self) -> EvidenceRole {
                $evidence_role
            }

            fn payload_domain(&self) -> &'static str {
                $payload_domain
            }

            fn signature_domain(&self) -> &'static str {
                $signature_domain
            }

            fn attempt_id(&self) -> &str {
                self.$attempt_field.as_str()
            }

            fn action_epoch_ms(&self) -> u64 {
                ($action)(self)
            }

            fn validate_payload(&self) -> ContractResult<()> {
                ($validate)(self)
            }
        }
    };
}

evidence_payload!(
    RouteSemanticProfileEvidencePayload,
    EvidenceType::RouteSemanticProfile,
    EvidenceRole::RouteSemanticProfile,
    "catchplate.response-observation-v2/route-semantic-profile-evidence-payload",
    "catchplate.response-observation-v2/route-semantic-profile-evidence-signature",
    attempt_id,
    |value: &RouteSemanticProfileEvidencePayload| value.signed_at_epoch_ms,
    validate_route_semantic_profile_payload
);

evidence_payload!(
    ReserveEvidencePayload,
    EvidenceType::Reserve,
    EvidenceRole::Reserve,
    "catchplate.response-observation-v2/reserve-payload",
    "catchplate.response-observation-v2/reserve-signature",
    attempt_id,
    |value: &ReserveEvidencePayload| value.reserved_at_epoch_ms,
    validate_reserve_payload
);

impl sealed::EvidencePayload for CredentialAuthorityEvidencePayload {}

impl EvidencePayload for CredentialAuthorityEvidencePayload {
    const EVIDENCE_TYPE: EvidenceType = EvidenceType::CredentialAuthority;

    fn evidence_role(&self) -> EvidenceRole {
        EvidenceRole::CredentialAuthority
    }

    fn payload_domain(&self) -> &'static str {
        "catchplate.response-observation-v2/credential-authority-payload"
    }

    fn signature_domain(&self) -> &'static str {
        "catchplate.response-observation-v2/credential-authority-signature"
    }

    fn attempt_id(&self) -> &str {
        self.attempt_id.as_str()
    }

    fn action_epoch_ms(&self) -> u64 {
        self.completed_at_epoch_ms
    }

    fn validate_payload(&self) -> ContractResult<()> {
        validate_credential_authority_evidence_payload(self)
    }

    fn credential_authority_scope(
        &self,
    ) -> Option<(&str, CredentialAuthorityOperation)> {
        Some((self.authority_id.as_str(), self.operation))
    }
}

evidence_payload!(
    DurableRecoverySealPayload,
    EvidenceType::DurableRecoverySeal,
    EvidenceRole::DurableRecoverySeal,
    "catchplate.response-observation-v2/durable-recovery-seal-payload",
    "catchplate.response-observation-v2/durable-recovery-seal-signature",
    attempt_id,
    |value: &DurableRecoverySealPayload| value.armed_at_epoch_ms,
    validate_durable_recovery_seal_payload
);

evidence_payload!(
    DispatchEvidencePayload,
    EvidenceType::Dispatch,
    EvidenceRole::Dispatch,
    "catchplate.response-observation-v2/dispatch-payload",
    "catchplate.response-observation-v2/dispatch-signature",
    attempt_id,
    |value: &DispatchEvidencePayload| value.authorized_at_epoch_ms,
    validate_dispatch_payload
);

impl sealed::EvidencePayload for TerminalEvidencePayload {}

impl EvidencePayload for TerminalEvidencePayload {
    const EVIDENCE_TYPE: EvidenceType = EvidenceType::Terminal;

    fn evidence_role(&self) -> EvidenceRole {
        match self {
            Self::Cancelled { .. } => EvidenceRole::Cancellation,
            Self::Completed { .. } => EvidenceRole::Completion,
            Self::ResponseRejected { .. } => EvidenceRole::ResponseRejection,
            Self::ExactResponseUnsupported { .. } => {
                EvidenceRole::ExactResponseUnsupported
            }
            Self::WriteTransitionUnknown { .. } => {
                EvidenceRole::WriteTransitionUnknown
            }
            Self::ReadTransitionUnknown { .. } => {
                EvidenceRole::ReadTransitionUnknown
            }
        }
    }
    fn payload_domain(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => {
                "catchplate.response-observation-v2/cancellation-payload"
            }
            Self::Completed { .. } => {
                "catchplate.response-observation-v2/completion-payload"
            }
            Self::ResponseRejected { .. } => {
                "catchplate.response-observation-v2/response-rejection-payload"
            }
            Self::ExactResponseUnsupported { .. } => {
                "catchplate.response-observation-v2/exact-response-unsupported-payload"
            }
            Self::WriteTransitionUnknown { .. } => {
                "catchplate.response-observation-v2/write-transition-unknown-payload"
            }
            Self::ReadTransitionUnknown { .. } => {
                "catchplate.response-observation-v2/read-transition-unknown-payload"
            }
        }
    }

    fn signature_domain(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => {
                "catchplate.response-observation-v2/cancellation-signature"
            }
            Self::Completed { .. } => {
                "catchplate.response-observation-v2/completion-signature"
            }
            Self::ResponseRejected { .. } => {
                "catchplate.response-observation-v2/response-rejection-signature"
            }
            Self::ExactResponseUnsupported { .. } => {
                "catchplate.response-observation-v2/exact-response-unsupported-signature"
            }
            Self::WriteTransitionUnknown { .. } => {
                "catchplate.response-observation-v2/write-transition-unknown-signature"
            }
            Self::ReadTransitionUnknown { .. } => {
                "catchplate.response-observation-v2/read-transition-unknown-signature"
            }
        }
    }

    fn attempt_id(&self) -> &str {
        TerminalEvidencePayload::attempt_id(self)
    }

    fn action_epoch_ms(&self) -> u64 {
        match self {
            Self::Cancelled {
                completed_at_epoch_ms,
                ..
            }
            | Self::Completed {
                completed_at_epoch_ms,
                ..
            } => *completed_at_epoch_ms,
            Self::ResponseRejected {
                rejected_at_epoch_ms,
                ..
            } => *rejected_at_epoch_ms,
            Self::ExactResponseUnsupported {
                unsupported_at_epoch_ms,
                ..
            } => *unsupported_at_epoch_ms,
            Self::WriteTransitionUnknown {
                unknown_at_epoch_ms,
                ..
            }
            | Self::ReadTransitionUnknown {
                unknown_at_epoch_ms,
                ..
            } => *unknown_at_epoch_ms,
        }
    }

    fn validate_payload(&self) -> ContractResult<()> {
        validate_terminal_payload(self)
    }
}

evidence_payload!(
    CustodyAuthorityEvidencePayload,
    EvidenceType::CustodyAuthority,
    EvidenceRole::CustodyAuthority,
    "catchplate.response-observation-v2/custody-authority-payload",
    "catchplate.response-observation-v2/custody-authority-signature",
    attempt_id,
    |value: &CustodyAuthorityEvidencePayload| value.measured_at_epoch_ms,
    validate_custody_authority_payload
);

evidence_payload!(
    LocalReconciliationContinuityEvidencePayload,
    EvidenceType::LocalReconciliationContinuity,
    EvidenceRole::LocalReconciliationContinuity,
    "catchplate.response-observation-v2/local-reconciliation-continuity-payload",
    "catchplate.response-observation-v2/local-reconciliation-continuity-signature",
    attempt_id,
    |value: &LocalReconciliationContinuityEvidencePayload| value.signed_at_epoch_ms,
    validate_local_reconciliation_continuity_payload
);

evidence_payload!(
    LocalReconciliationLedgerWitness,
    EvidenceType::LocalReconciliationLedgerWitness,
    EvidenceRole::LocalReconciliationLedgerWitness,
    "catchplate.response-observation-v2/local-reconciliation-ledger-witness-payload",
    "catchplate.response-observation-v2/local-reconciliation-ledger-witness-signature",
    attempt_id,
    |value: &LocalReconciliationLedgerWitness| value.witnessed_at_epoch_ms,
    validate_local_reconciliation_ledger_witness
);

evidence_payload!(
    LocalReconciliationGenesisAbsenceEvidencePayload,
    EvidenceType::LocalReconciliationGenesisAbsence,
    EvidenceRole::LocalReconciliationGenesisAbsence,
    "catchplate.response-observation-v2/local-reconciliation-genesis-absence-payload",
    "catchplate.response-observation-v2/local-reconciliation-genesis-absence-signature",
    attempt_id,
    |value: &LocalReconciliationGenesisAbsenceEvidencePayload| value.signed_at_epoch_ms,
    validate_local_reconciliation_genesis_absence_payload
);

evidence_payload!(
    LocalReconciliationRecoveryEvidencePayload,
    EvidenceType::LocalReconciliationRecovery,
    EvidenceRole::LocalReconciliationRecovery,
    "catchplate.response-observation-v2/local-reconciliation-recovery-payload",
    "catchplate.response-observation-v2/local-reconciliation-recovery-signature",
    attempt_id,
    |value: &LocalReconciliationRecoveryEvidencePayload| value.signed_at_epoch_ms,
    validate_local_reconciliation_recovery_payload
);

evidence_payload!(
    PersistenceEvidencePayload,
    EvidenceType::Persistence,
    EvidenceRole::Persistence,
    "catchplate.response-observation-v2/persistence-payload",
    "catchplate.response-observation-v2/persistence-signature",
    attempt_id,
    |value: &PersistenceEvidencePayload| value.persisted_at_epoch_ms,
    validate_persistence_payload
);

evidence_payload!(
    FinalizationCheckpointEvidencePayload,
    EvidenceType::FinalizationCheckpoint,
    EvidenceRole::FinalizationCheckpoint,
    "catchplate.response-observation-v2/finalization-checkpoint-payload",
    "catchplate.response-observation-v2/finalization-checkpoint-signature",
    attempt_id,
    |value: &FinalizationCheckpointEvidencePayload| value.finalized_at_epoch_ms,
    validate_finalization_checkpoint_payload
);

evidence_payload!(
    ArtifactTimeCheckpointEvidencePayload,
    EvidenceType::ArtifactTimeCheckpoint,
    EvidenceRole::ArtifactTimeCheckpoint,
    "catchplate.response-observation-v2/artifact-time-checkpoint-payload",
    "catchplate.response-observation-v2/artifact-time-checkpoint-signature",
    attempt_id,
    |value: &ArtifactTimeCheckpointEvidencePayload| value.signed_at_epoch_ms,
    validate_artifact_time_checkpoint_payload
);

/// A verified wrapper cannot be deserialized or directly constructed.
#[derive(Debug)]
struct VerifiedEvidence<P> {
    wire: SignedEvidence<P>,
    pinned_trust_policy_sha256: String,
    trust_checkpoint_sha256: String,
    revocation_epoch: u64,
    key_material_sha256: String,
    revoked_at_epoch_ms: Option<u64>,
    _seal: VerifiedSeal,
}

#[derive(Debug)]
struct VerifiedSeal;

/// Opaque proof that the supplied raw document was exact canonical JCS.
/// It is produced only by `decode_canonical_proof`.
#[derive(Debug)]
pub struct CanonicalResponseObservationProofV2 {
    wire: ResponseObservationProofV2,
    _seal: CanonicalWireSeal,
}

#[derive(Debug)]
struct CanonicalWireSeal;

impl CanonicalResponseObservationProofV2 {
    pub fn wire(&self) -> &ResponseObservationProofV2 {
        &self.wire
    }
}

impl<P> VerifiedEvidence<P> {
    pub fn wire(&self) -> &SignedEvidence<P> {
        &self.wire
    }

    fn key_material_sha256(&self) -> &str {
        &self.key_material_sha256
    }

    fn revoked_at_epoch_ms(&self) -> Option<u64> {
        self.revoked_at_epoch_ms
    }
}

/// A fully cross-validated proof. It exposes no dispatch, activation, or I/O API.
#[derive(Debug)]
pub(crate) struct VerifiedResponseObservationProofV2 {
    wire: ResponseObservationProofV2,
    verification_purpose: VerificationPurpose,
    live_authorization: Option<LiveAuthorizationSeal>,
    _seal: VerifiedSeal,
}

/// Opaque capability present only after LIVE_AUTHORIZATION verification.
/// Archival verification can authenticate history but cannot authorize any
/// dispatch, reconciliation, cleanup, or other lifecycle state mutation.
#[derive(Debug)]
pub(crate) struct LiveAuthorizationSeal {
    _seal: VerifiedSeal,
}

impl VerifiedResponseObservationProofV2 {
    pub(crate) fn wire(&self) -> &ResponseObservationProofV2 {
        &self.wire
    }

    pub(crate) fn verification_purpose(&self) -> VerificationPurpose {
        self.verification_purpose
    }

    pub(crate) fn live_authorization(
        &self,
    ) -> Option<&LiveAuthorizationSeal> {
        self.live_authorization.as_ref()
    }

    pub(crate) fn retrieval_identity(&self) -> &FinalizedEnvelopeIdentity {
        &self.wire.finalized_envelope.identity
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceSigningCommitment<'a, P> {
    api_version: &'a str,
    evidence_type: EvidenceType,
    payload: &'a P,
    payload_sha256: &'a str,
    key_id: &'a str,
    signature_domain: &'a str,
    signature_algorithm: SignatureAlgorithm,
    issued_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
    boot_runtime_identity: &'a BootRuntimeIdentity,
    predecessor_evidence_sha256: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
// The dispatch-authorization and idempotency bindings are intentionally
// excluded: both are derived from this canonical staged-request digest.
struct StagedRequestDigestCommitment<'a> {
    exact_request_retrieval_id: &'a str,
    credential_injection_template_sha256: &'a str,
    injection: CredentialInjectionState,
    credential_binding_sha256: Option<&'a str>,
    injection_result_sha256: &'a str,
    operation_semantics_sha256: &'a str,
    request_framing_sha256: &'a str,
    exact_request_bytes_sha256: &'a str,
    exact_request_bytes_length: u64,
    method: &'a str,
    wire_protocol: TargetWireProtocol,
    canonical_target: &'a CanonicalUpstreamTarget,
    header_block_sha256: &'a str,
    header_block_length: u64,
    header_count: u32,
    body_sha256: &'a str,
    body_length: u64,
    idempotency_key_sha256: Option<&'a str>,
    prepared_at_epoch_ms: u64,
    preparation: &'a TargetPreparation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteSemanticProfileCommitment<'a> {
    policy_sha256: &'a str,
    snapshot_epoch: u64,
    route_id: Option<&'a str>,
    operation_sha256: &'a str,
    method: &'a str,
    canonical_target: Option<&'a CanonicalUpstreamTarget>,
    provider_id: Option<&'a str>,
    provider_profile_sha256: Option<&'a str>,
    provider_schema_sha256: Option<&'a str>,
    provider_idempotency_profile_sha256: Option<&'a str>,
    response_policy_profile_sha256: Option<&'a str>,
    route_classification: RouteClassification,
    idempotency_classification: IdempotencyClassification,
    credential_mode: Option<PolicyCredentialMode>,
    credential_identity_sha256: Option<&'a str>,
}

pub(crate) fn validate_and_verify<
    E: EvidenceSignatureVerifier,
    A: FinalizationArtifactVerifier,
    P: ExactBytePersistenceVerifier,
>(
    proof: CanonicalResponseObservationProofV2,
    context: &VerificationContext<'_>,
    evidence_verifier: &E,
    artifact_verifier: &A,
    persistence_verifier: &P,
) -> ContractResult<VerifiedResponseObservationProofV2> {
    let proof = proof.wire;
    validate_safe_time(
        context.trusted_now_epoch_ms(),
        "context.trustedNowEpochMs",
    )?;
    validate_runtime(context.expected_runtime().identity())?;
    if proof.api_version != PROOF_API_VERSION || proof.kind != PROOF_KIND {
        return Err(ContractError::new(
            "wrong_contract",
            "$",
            "proof apiVersion or kind is not response-observation v2",
        ));
    }

    let finalized = &proof.finalized_envelope;
    validate_finalized_identity(finalized)?;
    let exact_staged_request = match finalized.body.staged_target_request.as_ref() {
        Some(staged) => Some(verify_exact_staged_request_bytes(
            staged,
            &finalized.body,
            persistence_verifier,
        )?),
        None => None,
    };
    let exact_upstream_response = match &finalized.body.upstream_observation {
        UpstreamObservationState::ObservedResponse { .. }
        | UpstreamObservationState::ExactResponseUnsupported { .. } => {
            Some(verify_exact_upstream_response_bytes(
                &finalized.body,
                persistence_verifier,
            )?)
        }
        _ => None,
    };
    let exact_local_reconciliation =
        verify_exact_local_reconciliation_record(
            &finalized.body,
            persistence_verifier,
        )?;
    let exact_local_reconciliation_continuity =
        verify_exact_local_reconciliation_continuity(
            &finalized.body,
            context,
            evidence_verifier,
            persistence_verifier,
            exact_local_reconciliation.as_ref(),
        )?;
    validate_envelope_body(
        &finalized.body,
        context,
        exact_staged_request.as_ref(),
        exact_upstream_response.as_ref(),
        exact_local_reconciliation.as_ref(),
    )?;
    verify_body_evidence(
        &finalized.body,
        context,
        evidence_verifier,
        exact_local_reconciliation.as_ref(),
        exact_local_reconciliation_continuity.as_ref(),
    )?;

    let persistence = verify_evidence(
        finalized.persistence_evidence.clone(),
        context,
        evidence_verifier,
    )?;
    validate_persistence_binding(finalized, persistence.wire())?;
    verify_exact_persisted_envelope(finalized, persistence_verifier)?;
    let finalization_checkpoint = verify_evidence(
        finalized.finalization_checkpoint_evidence.clone(),
        context,
        evidence_verifier,
    )?;
    validate_finalization_checkpoint_binding(
        finalized,
        persistence.wire(),
        &finalization_checkpoint,
        context,
    )?;
    validate_attestation_and_publication(
        &proof.attestation,
        &proof.publication,
        &finalized.identity,
        &finalized.body.runtime,
        &finalization_checkpoint,
        context,
        evidence_verifier,
        artifact_verifier,
    )?;

    Ok(VerifiedResponseObservationProofV2 {
        wire: proof,
        verification_purpose: context.purpose(),
        live_authorization: (context.purpose()
            == VerificationPurpose::LiveAuthorization)
            .then_some(LiveAuthorizationSeal {
                _seal: VerifiedSeal,
            }),
        _seal: VerifiedSeal,
    })
}

fn validate_envelope_body(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
    exact_staged_request: Option<&VerifiedExactStagedRequest>,
    exact_upstream_response: Option<&VerifiedExactUpstreamResponse>,
    exact_local_reconciliation: Option<&VerifiedLocalReconciliationRecord>,
) -> ContractResult<()> {
    if body.api_version != ENVELOPE_API_VERSION || body.kind != ENVELOPE_KIND {
        return Err(ContractError::new(
            "wrong_envelope_contract",
            "finalizedEnvelope.body",
            "envelope apiVersion or kind is not response-observation v2",
        ));
    }
    validate_attempt_id(&body.attempt_id)?;
    validate_safe_time(body.issued_at_epoch_ms, "body.issuedAtEpochMs")?;
    if body.issued_at_epoch_ms
        > context
            .trusted_now_epoch_ms()
            .saturating_add(MAX_CLOCK_SKEW_MS)
        || context
            .trusted_now_epoch_ms()
            .saturating_sub(body.issued_at_epoch_ms)
            > MAX_PROOF_AGE_MS
    {
        return Err(ContractError::new(
            "proof_outside_freshness_window",
            "finalizedEnvelope.body.issuedAtEpochMs",
            "proof issue time is outside the bounded verifier window",
        ));
    }
    validate_runtime(&body.runtime)?;
    if &body.runtime != context.expected_runtime().identity() {
        return Err(ContractError::new(
            "runtime_binding_mismatch",
            "finalizedEnvelope.body.runtime",
            "proof runtime does not match the verifier-pinned runtime",
        ));
    }
    validate_nonce(&body.nonce, context.trusted_now_epoch_ms())?;
    if body.nonce.issued_at_epoch_ms > body.issued_at_epoch_ms
        || body.issued_at_epoch_ms > body.nonce.expires_at_epoch_ms
    {
        return Err(ContractError::new(
            "nonce_envelope_ordering_mismatch",
            "finalizedEnvelope.body.issuedAtEpochMs",
            "nonce issuance must precede the envelope and envelope issuance must precede nonce expiry",
        ));
    }
    validate_policy(&body.policy)?;

    let semantic_profile = &body.route_semantic_profile_evidence.payload;
    let expected_semantic_profile =
        route_semantic_profile_digest(semantic_profile)?;
    require_equal_digest(
        &semantic_profile.semantic_profile_sha256,
        &expected_semantic_profile,
        "body.routeSemanticProfileEvidence.payload.semanticProfileSha256",
    )?;
    let expected_attempt = attempt_id(
        &body.nonce.nonce_sha256,
        body.policy.policy_sha256(),
        body.policy.request_sha256(),
        body.policy.operation_sha256(),
        &body.runtime.boot_id,
        &semantic_profile.semantic_profile_sha256,
    )?;
    if body.attempt_id != expected_attempt {
        return Err(ContractError::new(
            "attempt_binding_mismatch",
            "finalizedEnvelope.body.attemptId",
            "attemptId is not the unique nonce, policy, request, operation, and boot commitment",
        ));
    }
    let expected_authorization_binding = authorization_binding(
        &body.policy,
        &body.attempt_id,
        &semantic_profile.semantic_profile_sha256,
    )?;
    require_equal_digest(
        &semantic_profile.authorization_binding_sha256,
        &expected_authorization_binding,
        "body.routeSemanticProfileEvidence.payload.authorizationBindingSha256",
    )?;
    validate_route_semantic_profile_binding(body, &expected_authorization_binding)?;

    let staged_digest = match &body.staged_target_request {
        Some(staged) => {
            validate_staged_request(staged)?;
            Some(staged.staging_sha256.as_str())
        }
        None => None,
    };
    validate_route_semantics(
        &body.route_semantics,
        &body.attempt_id,
        staged_digest,
    )?;
    validate_route_classification(
        &body.route_semantics,
        semantic_profile,
        body.staged_target_request.as_ref(),
    )?;
    validate_staged_idempotency_binding(body)?;
    if matches!(&body.policy, PolicyBinding::Denied { .. })
        != matches!(&body.route_semantics, RouteSemantics::Rejected { .. })
    {
        return Err(ContractError::new(
            "policy_route_semantics_mismatch",
            "finalizedEnvelope.body.routeSemantics",
            "only a denied policy may use rejected route semantics, and every denied policy must",
        ));
    }
    validate_credential_and_side_effect(
        body,
        staged_digest,
        exact_local_reconciliation,
    )?;
    validate_exact_staged_request_binding(body, exact_staged_request)?;
    validate_target_and_upstream(
        body,
        staged_digest,
        exact_upstream_response,
    )?;
    validate_authorization_and_evidence(body, context)?;
    validate_lifecycle(body)?;
    validate_authority(body, context)?;
    Ok(())
}

fn validate_authorization_and_evidence(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
) -> ContractResult<()> {
    // Signature verification is performed by `verify_body_evidence`; this pass
    // only enforces the closed optional-field and digest-reference graph.
    let _ = context;

    let reserve_digest = body
        .reserve_evidence
        .as_ref()
        .map(|evidence| evidence.evidence_sha256.as_str());
    let dispatch_digest = body
        .dispatch_evidence
        .as_ref()
        .map(|evidence| evidence.evidence_sha256.as_str());
    let terminal_digest = body.terminal_evidence.evidence_sha256.as_str();
    if !body.policy.is_allowed()
        && !matches!(
            &body.authorization,
            AuthorizationState::DeniedBeforeReserve { .. }
        )
    {
        return Err(ContractError::new(
            "denied_policy_reserved_authority",
            "body.authorization",
            "a denied policy cannot reserve or dispatch authority",
        ));
    }

    match &body.authorization {
        AuthorizationState::DeniedBeforeReserve {
            terminal_evidence_sha256,
        } => {
            require_none(reserve_digest, "body.reserveEvidence")?;
            require_none(dispatch_digest, "body.dispatchEvidence")?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::Cancelled {
                    reserve_evidence_sha256: None,
                    dispatch_evidence_sha256: None,
                    ..
                }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::DefinitelyNotDispatched { .. }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "denied-before-reserve requires root cancellation and definitely no dispatch",
                ));
            }
        }
        AuthorizationState::ReservedCancelled {
            reserve_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_none(dispatch_digest, "body.dispatchEvidence")?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::Cancelled {
                    reserve_evidence_sha256: Some(_),
                    dispatch_evidence_sha256: None,
                    ..
                }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::DefinitelyNotDispatched { .. }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "reserved-cancelled requires reserve-bound cancellation and no dispatch",
                ));
            }
        }
        AuthorizationState::DispatchCancelled {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::Cancelled {
                    reserve_evidence_sha256: Some(_),
                    dispatch_evidence_sha256: Some(_),
                    ..
                }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::DefinitelyNotDispatched {
                    reason:
                        NotDispatchedReason::DispatchCancelledBeforeWrite
                        | NotDispatchedReason::DeadlineExpiredBeforeWrite,
                    ..
                }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "dispatch-cancelled requires chain-bound cancellation before any byte write",
                ));
            }
        }
        AuthorizationState::DispatchCompleted {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::Completed { .. }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::Dispatched { .. }
            ) || !matches!(
                &body.upstream_observation,
                UpstreamObservationState::ObservedResponse {
                    completion: UpstreamResponseCompletion::Complete,
                    ..
                }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "dispatch-completed requires completed evidence and observed upstream bytes",
                ));
            }
        }
        AuthorizationState::DispatchResponseRejected {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::ResponseRejected { .. }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::Dispatched { .. }
            ) || !matches!(
                &body.upstream_observation,
                UpstreamObservationState::ObservedResponse {
                    response_policy_validation:
                        ResponsePolicyValidation {
                            decision:
                                ResponsePolicyDecision::Failed
                                | ResponsePolicyDecision::NotEvaluatedIncompleteResponse,
                            ..
                        },
                    ..
                }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "dispatch-response-rejected requires exact observed response bytes and a non-passing response-policy decision",
                ));
            }
        }
        AuthorizationState::DispatchExactResponseUnsupported {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::ExactResponseUnsupported { .. }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::Dispatched { .. }
            ) || !matches!(
                &body.upstream_observation,
                UpstreamObservationState::ExactResponseUnsupported {
                    response_policy_decision:
                        ResponsePolicyDecision::NotEvaluatedUnsupportedResponse,
                    downstream_delivery: DownstreamDeliveryState::Unknown,
                    ..
                }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "dispatch-exact-response-unsupported requires exact immutable unsupported response evidence and a non-passing provider decision",
                ));
            }
        }
        AuthorizationState::WriteDispatchTransitionUnknown {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::WriteTransitionUnknown { .. }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::WriteOutcomeUnknown { .. }
            ) || !matches!(
                &body.upstream_observation,
                UpstreamObservationState::WriteOutcomeUnknown { .. }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "transition-unknown requires unknown evidence, target state, and upstream state",
                ));
            }
        }
        AuthorizationState::ReadDispatchTransitionUnknown {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            terminal_evidence_sha256,
        } => {
            require_equal_optional_digest(
                reserve_evidence_sha256,
                reserve_digest,
                "body.authorization.reserveEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                dispatch_digest,
                "body.authorization.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                terminal_evidence_sha256,
                terminal_digest,
                "body.authorization.terminalEvidenceSha256",
            )?;
            if !matches!(
                &body.terminal_evidence.payload,
                TerminalEvidencePayload::ReadTransitionUnknown { .. }
            ) || !matches!(
                &body.target_egress,
                TargetEgressState::ReadOutcomeUnknown { .. }
            ) || !matches!(
                &body.upstream_observation,
                UpstreamObservationState::ReadOutcomeUnknown { .. }
            ) {
                return Err(ContractError::new(
                    "authorization_terminal_mismatch",
                    "body.authorization",
                    "read-transition-unknown requires read-specific non-passing target and upstream uncertainty without write recovery authority",
                ));
            }
        }
    }
    validate_cancellation_reason_consistency(body)?;
    validate_recovery_state(body)?;
    Ok(())
}

fn validate_cancellation_reason_consistency(
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<()> {
    let (cancellation, no_dispatch) =
        match (&body.terminal_evidence.payload, &body.target_egress) {
            (
                TerminalEvidencePayload::Cancelled { reason, .. },
                TargetEgressState::DefinitelyNotDispatched {
                    reason: no_dispatch,
                    ..
                },
            ) => (*reason, *no_dispatch),
            _ => return Ok(()),
        };
    let expected_no_dispatch = match cancellation {
        CancellationReason::PolicyDenied => NotDispatchedReason::PolicyDenied,
        CancellationReason::ReservationDenied => {
            NotDispatchedReason::ReservationDenied
        }
        CancellationReason::CredentialFailure => {
            NotDispatchedReason::CredentialFailure
        }
        CancellationReason::CredentialAcquisitionOutcomeUnknown => {
            NotDispatchedReason::CredentialAcquisitionOutcomeUnknown
        }
        CancellationReason::CredentialAuthorityOutcomeUnknown => {
            NotDispatchedReason::CredentialAuthorityOutcomeUnknown
        }
        CancellationReason::RecoveryAuthorityFailure => {
            NotDispatchedReason::RecoveryAuthorityFailure
        }
        CancellationReason::StagingFailed => NotDispatchedReason::StagingFailed,
        CancellationReason::DispatchCancelledBeforeWrite => {
            NotDispatchedReason::DispatchCancelledBeforeWrite
        }
        CancellationReason::DeadlineExpiredBeforeWrite => {
            NotDispatchedReason::DeadlineExpiredBeforeWrite
        }
    };
    if no_dispatch != expected_no_dispatch {
        return Err(ContractError::new(
            "cancellation_reason_mismatch",
            "body.targetEgress.reason",
            "terminal cancellation and target no-dispatch reasons must be identical",
        ));
    }
    let status_valid = match &body.authorization {
        AuthorizationState::DeniedBeforeReserve { .. } => {
            if body.policy.is_allowed() {
                cancellation == CancellationReason::ReservationDenied
            } else {
                cancellation == CancellationReason::PolicyDenied
            }
        }
        AuthorizationState::ReservedCancelled { .. } => matches!(
            cancellation,
            CancellationReason::CredentialFailure
                | CancellationReason::CredentialAcquisitionOutcomeUnknown
                | CancellationReason::CredentialAuthorityOutcomeUnknown
                | CancellationReason::RecoveryAuthorityFailure
                | CancellationReason::StagingFailed
                | CancellationReason::DeadlineExpiredBeforeWrite
        ),
        AuthorizationState::DispatchCancelled { .. } => matches!(
            cancellation,
            CancellationReason::DispatchCancelledBeforeWrite
                | CancellationReason::DeadlineExpiredBeforeWrite
        ),
        AuthorizationState::DispatchCompleted { .. }
        | AuthorizationState::DispatchResponseRejected { .. }
        | AuthorizationState::DispatchExactResponseUnsupported { .. }
        | AuthorizationState::WriteDispatchTransitionUnknown { .. }
        | AuthorizationState::ReadDispatchTransitionUnknown { .. } => false,
    };
    if !status_valid {
        return Err(ContractError::new(
            "cancellation_authorization_mismatch",
            "body.terminalEvidence.payload.reason",
            "cancellation reason is impossible for the authorization stage",
        ));
    }
    Ok(())
}

fn validate_recovery_state(
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<()> {
    let write_outcome_unknown = matches!(
        &body.authorization,
        AuthorizationState::WriteDispatchTransitionUnknown { .. }
    );
    let read_outcome_unknown = matches!(
        &body.authorization,
        AuthorizationState::ReadDispatchTransitionUnknown { .. }
    );
    let outcome_known = matches!(
        &body.authorization,
        AuthorizationState::DispatchCompleted { .. }
            | AuthorizationState::DispatchResponseRejected { .. }
            | AuthorizationState::DispatchExactResponseUnsupported { .. }
    );
    match &body.route_semantics {
        RouteSemantics::Write {
            ambiguous_outcome_recovery,
            ..
        } => {
            let valid = if write_outcome_unknown {
                ambiguous_outcome_recovery.state
                    == RecoveryState::PendingReconciliation
            } else if outcome_known {
                matches!(
                    ambiguous_outcome_recovery.state,
                    RecoveryState::NotNeededKnownOutcome
                        | RecoveryState::ResolvedFromProvider
                )
            } else {
                ambiguous_outcome_recovery.state
                    == RecoveryState::ArmedBeforeDispatch
            };
            if !valid {
                return Err(ContractError::new(
                    "write_recovery_state_mismatch",
                    "body.routeSemantics.ambiguousOutcomeRecovery.state",
                    "write recovery state does not match the terminal dispatch outcome",
                ));
            }
        }
        RouteSemantics::ReadOnly { retry_recovery, .. }
        | RouteSemantics::CredentiallessReadOnly { retry_recovery, .. } => {
            let expected = if read_outcome_unknown {
                ReadRetryState::SafeRetryAfterUnknown
            } else {
                ReadRetryState::NotNeededKnownOutcome
            };
            if retry_recovery.state != expected {
                return Err(ContractError::new(
                    "read_recovery_state_mismatch",
                    "body.routeSemantics.retryRecovery.state",
                    "read retry state does not match the terminal dispatch outcome",
                ));
            }
        }
        RouteSemantics::Rejected { .. }
        | RouteSemantics::WriteNotDispatchable { .. } => {}
    }
    Ok(())
}

fn verify_body_evidence<V: EvidenceSignatureVerifier>(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
    verifier: &V,
    exact_local_reconciliation: Option<&VerifiedLocalReconciliationRecord>,
    exact_local_reconciliation_continuity:
        Option<&VerifiedLocalReconciliationContinuity>,
) -> ContractResult<()> {
    let semantic_profile = verify_evidence(
        body.route_semantic_profile_evidence.clone(),
        context,
        verifier,
    )?;
    let reserve = match body.reserve_evidence.clone() {
        Some(evidence) => Some(verify_evidence(evidence, context, verifier)?),
        None => None,
    };
    if body.credential_authority_evidence.len()
        > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(ContractError::new(
            "credential_authority_evidence_limit",
            "body.credentialAuthorityEvidence",
            "credential-authority evidence exceeds the closed work bound",
        ));
    }
    let mut credential_authority = Vec::with_capacity(
        body.credential_authority_evidence.len(),
    );
    for evidence in body.credential_authority_evidence.iter().cloned() {
        credential_authority.push(verify_evidence(evidence, context, verifier)?);
    }
    let recovery_seal = match body.durable_recovery_seal_evidence.clone() {
        Some(evidence) => Some(verify_evidence(evidence, context, verifier)?),
        None => None,
    };
    let dispatch = match body.dispatch_evidence.clone() {
        Some(evidence) => Some(verify_evidence(evidence, context, verifier)?),
        None => None,
    };
    let custody = match body.custody_authority_evidence.clone() {
        Some(evidence) => Some(verify_evidence(evidence, context, verifier)?),
        None => None,
    };
    let local_reconciliation_recovery =
        match body.local_reconciliation_recovery_evidence.clone() {
            Some(evidence) => {
                Some(verify_evidence(evidence, context, verifier)?)
            }
            None => None,
        };
    let local_reconciliation_continuity =
        exact_local_reconciliation_continuity
            .map(|value| &value.continuity);
    let local_reconciliation_ledger_witness =
        exact_local_reconciliation_continuity
            .map(|value| &value.ledger_witness);
    let local_reconciliation_genesis_absence =
        exact_local_reconciliation_continuity
            .and_then(|value| value.genesis_absence.as_ref());
    let terminal =
        verify_evidence(body.terminal_evidence.clone(), context, verifier)?;
    if let (Some(recovery), Some(dispatch)) =
        (recovery_seal.as_ref(), dispatch.as_ref())
    {
        if recovery.wire().key_id == dispatch.wire().key_id
            || recovery.key_material_sha256()
                == dispatch.key_material_sha256()
            || recovery.trust_checkpoint_sha256
                != dispatch.trust_checkpoint_sha256
            || recovery.revocation_epoch != dispatch.revocation_epoch
        {
            return Err(ContractError::new(
                "recovery_dispatch_key_separation_failed",
                "body.durableRecoverySealEvidence",
                "recovery and dispatch must use independently keyed role authorities verified at the same current trust and revocation checkpoint",
            ));
        }
    }

    for attempt in std::iter::once(
        semantic_profile.wire().payload.attempt_id.as_str(),
    )
        .chain(
            reserve
                .as_ref()
                .map(|value| value.wire().payload.attempt_id.as_str())
                .into_iter(),
        )
        .chain(
            credential_authority
                .iter()
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            recovery_seal
                .as_ref()
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            dispatch
                .as_ref()
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            custody
                .as_ref()
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            local_reconciliation_recovery
                .as_ref()
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            local_reconciliation_continuity
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            local_reconciliation_ledger_witness
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(
            local_reconciliation_genesis_absence
                .map(|value| value.wire().payload.attempt_id.as_str()),
        )
        .chain(std::iter::once(terminal.wire().payload.attempt_id()))
    {
        if attempt != body.attempt_id {
            return Err(ContractError::new(
                "attempt_binding_mismatch",
                "finalizedEnvelope.body",
                "every authority-bearing evidence payload must bind the one envelope attemptId",
            ));
        }
    }
    validate_evidence_body_time(semantic_profile.wire(), body)?;
    if let Some(value) = reserve.as_ref() {
        validate_evidence_body_time(value.wire(), body)?;
    }
    for value in &credential_authority {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = recovery_seal.as_ref() {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = dispatch.as_ref() {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = custody.as_ref() {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = local_reconciliation_recovery.as_ref() {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = local_reconciliation_continuity {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = local_reconciliation_ledger_witness {
        validate_evidence_body_time(value.wire(), body)?;
    }
    if let Some(value) = local_reconciliation_genesis_absence {
        validate_evidence_body_time(value.wire(), body)?;
    }
    validate_evidence_body_time(terminal.wire(), body)?;

    if semantic_profile.wire().predecessor_evidence_sha256.is_some() {
        return Err(ContractError::new(
            "invalid_evidence_predecessor",
            "body.routeSemanticProfileEvidence.predecessorEvidenceSha256",
            "the signed route semantic profile must be the evidence-chain root",
        ));
    }

    if let Some(reserve) = reserve.as_ref() {
        let payload = &reserve.wire().payload;
        if payload.reserved_at_epoch_ms
            < semantic_profile.wire().payload.signed_at_epoch_ms
            || payload.reserved_at_epoch_ms > body.issued_at_epoch_ms
        {
            return Err(ContractError::new(
                "reserve_after_envelope",
                "body.reserveEvidence.payload.reservedAtEpochMs",
                "reservation must follow signed route semantics and precede envelope issuance",
            ));
        }
        require_equal_digest(
            &payload.nonce_sha256,
            &body.nonce.nonce_sha256,
            "body.reserveEvidence.payload.nonceSha256",
        )?;
        require_equal_digest(
            &payload.policy_sha256,
            body.policy.policy_sha256(),
            "body.reserveEvidence.payload.policySha256",
        )?;
        require_equal_digest(
            &payload.request_sha256,
            body.policy.request_sha256(),
            "body.reserveEvidence.payload.requestSha256",
        )?;
        require_equal_digest(
            &payload.operation_sha256,
            body.policy.operation_sha256(),
            "body.reserveEvidence.payload.operationSha256",
        )?;
        require_equal_digest(
            &payload.route_semantic_profile_sha256,
            &semantic_profile.wire().payload.semantic_profile_sha256,
            "body.reserveEvidence.payload.routeSemanticProfileSha256",
        )?;
        require_equal_digest(
            &payload.authorization_binding_sha256,
            &semantic_profile.wire().payload.authorization_binding_sha256,
            "body.reserveEvidence.payload.authorizationBindingSha256",
        )?;
        require_equal_optional_digest(
            &semantic_profile.wire().evidence_sha256,
            reserve.wire().predecessor_evidence_sha256.as_deref(),
            "body.reserveEvidence.predecessorEvidenceSha256",
        )?;
    }

    let expected_authorization_binding =
        semantic_profile.wire().payload.authorization_binding_sha256.as_str();
    let semantic_profile_digest =
        semantic_profile.wire().payload.semantic_profile_sha256.as_str();
    let credential_authority_roots = verify_credential_authority_chain(
        body,
        reserve.as_ref(),
        &credential_authority,
        expected_authorization_binding,
        semantic_profile_digest,
    )?;
    verify_durable_recovery_seal(
        body,
        reserve.as_ref(),
        credential_authority.last(),
        recovery_seal.as_ref(),
        expected_authorization_binding,
        semantic_profile_digest,
    )?;
    verify_local_reconciliation_recovery_evidence(
        body,
        context,
        exact_local_reconciliation,
        reserve.as_ref(),
        custody.as_ref(),
        exact_local_reconciliation_continuity,
        local_reconciliation_recovery.as_ref(),
    )?;

    if let Some(dispatch) = dispatch.as_ref() {
        let reserve = reserve.as_ref().ok_or_else(|| {
            ContractError::new(
                "missing_reserve_evidence",
                "body.reserveEvidence",
                "dispatch evidence requires reserve evidence",
            )
        })?;
        let payload = &dispatch.wire().payload;
        if payload.authorized_at_epoch_ms < reserve.wire().payload.reserved_at_epoch_ms
            || recovery_seal.as_ref().is_some_and(|value| {
                payload.authorized_at_epoch_ms
                    < value.wire().payload.armed_at_epoch_ms
            })
            || credential_authority.last().is_some_and(|value| {
                payload.authorized_at_epoch_ms
                    < value.wire().payload.completed_at_epoch_ms
            })
            || payload.authorized_at_epoch_ms
                > reserve.wire().payload.reservation_deadline_epoch_ms
            || payload.authorized_at_epoch_ms > body.issued_at_epoch_ms
        {
            return Err(ContractError::new(
                "dispatch_outside_reservation",
                "body.dispatchEvidence.payload.authorizedAtEpochMs",
                "dispatch authority is outside the reservation and envelope timeline",
            ));
        }
        require_equal_digest(
            &payload.policy_sha256,
            body.policy.policy_sha256(),
            "body.dispatchEvidence.payload.policySha256",
        )?;
        require_equal_digest(
            &payload.route_semantic_profile_sha256,
            semantic_profile_digest,
            "body.dispatchEvidence.payload.routeSemanticProfileSha256",
        )?;
        require_equal_digest(
            &payload.authorization_binding_sha256,
            expected_authorization_binding,
            "body.dispatchEvidence.payload.authorizationBindingSha256",
        )?;
        validate_digest(
            &payload.dispatch_authorization_binding_sha256,
            "body.dispatchEvidence.payload.dispatchAuthorizationBindingSha256",
        )?;
        validate_digest(
            &payload.trust_checkpoint_sha256,
            "body.dispatchEvidence.payload.trustCheckpointSha256",
        )?;
        let (policy_valid_from, policy_valid_until) =
            body.policy.validity_window().ok_or_else(|| {
                ContractError::new(
                    "dispatch_without_allowed_policy",
                    "body.policy",
                    "dispatch requires one allowed policy validity window",
                )
            })?;
        if !matches!(
            body.policy.prerequisites().map(|value| &value.response_validation),
            Some(PolicyResponseValidationPrerequisite::Required { .. })
        ) {
            return Err(ContractError::new(
                "dispatch_without_response_validation",
                "body.policy.prerequisites.responseValidation",
                "every dispatched route requires one signed exact-byte provider response-validation profile",
            ));
        }
        if payload.revalidated_at_epoch_ms != payload.authorized_at_epoch_ms
            || payload.policy_snapshot_epoch != body.policy.snapshot_epoch()
            || payload.trust_checkpoint_sha256
                != context.current_trust_checkpoint_sha256()
            || payload.revocation_epoch != context.current_revocation_epoch()
            || payload.authorized_at_epoch_ms < policy_valid_from
            || payload.authorized_at_epoch_ms >= policy_valid_until
            || credential_authority_roots
                .dispatch_valid_from_epoch_ms
                .is_some_and(|from| payload.authorized_at_epoch_ms < from)
            || credential_authority_roots
                .dispatch_valid_until_epoch_ms
                .is_some_and(|until| payload.authorized_at_epoch_ms >= until)
        {
            return Err(ContractError::new(
                "dispatch_final_revalidation_failed",
                "body.dispatchEvidence.payload",
                "dispatch instant must revalidate policy freshness, authority expiries/windows, and the current trust/revocation checkpoint",
            ));
        }
        require_equal_digest(
            &payload.reserve_evidence_sha256,
            &reserve.wire().evidence_sha256,
            "body.dispatchEvidence.payload.reserveEvidenceSha256",
        )?;
        let expected_predecessor = recovery_seal
            .as_ref()
            .map(|value| value.wire().evidence_sha256.as_str())
            .or_else(|| {
                credential_authority
                    .last()
                    .map(|value| value.wire().evidence_sha256.as_str())
            })
            .unwrap_or(reserve.wire().evidence_sha256.as_str());
        require_equal_optional_digest(
            expected_predecessor,
            dispatch.wire().predecessor_evidence_sha256.as_deref(),
            "body.dispatchEvidence.predecessorEvidenceSha256",
        )?;
        if payload.credential_authority_evidence_sha256.as_deref()
            != credential_authority
                .last()
                .map(|value| value.wire().evidence_sha256.as_str())
        {
            return Err(ContractError::new(
                "credential_authority_binding_mismatch",
                "body.dispatchEvidence.payload.credentialAuthorityEvidenceSha256",
                "dispatch evidence does not bind the final credential-authority result",
            ));
        }
        if payload
            .credential_authority_evidence_root_sha256
            .as_deref()
            != credential_authority_roots
                .evidence_root_sha256
                .as_deref()
        {
            return Err(ContractError::new(
                "credential_authority_root_mismatch",
                "body.dispatchEvidence.payload.credentialAuthorityEvidenceRootSha256",
                "dispatch evidence must bind the aggregate root of every typed authority result",
            ));
        }
        if payload
            .credential_authority_state_machine_sha256
            .as_deref()
            != credential_authority_roots
                .state_machine_summary_sha256
                .as_deref()
        {
            return Err(ContractError::new(
                "credential_authority_state_machine_mismatch",
                "body.dispatchEvidence.payload.credentialAuthorityStateMachineSha256",
                "dispatch evidence must bind the verified causal authority state machine",
            ));
        }
        if payload.durable_recovery_seal_evidence_sha256.as_deref()
            != recovery_seal
                .as_ref()
                .map(|value| value.wire().evidence_sha256.as_str())
        {
            return Err(ContractError::new(
                "durable_recovery_seal_binding_mismatch",
                "body.dispatchEvidence.payload.durableRecoverySealEvidenceSha256",
                "dispatch evidence does not bind the required pre-dispatch recovery seal",
            ));
        }
        let staged = body.staged_target_request.as_ref().ok_or_else(|| {
            ContractError::new(
                "missing_staged_request",
                "body.stagedTargetRequest",
                "dispatch authorization requires immutable staged target bytes",
            )
        })?;
        require_equal_digest(
            &payload.staged_request_sha256,
            &staged.staging_sha256,
            "body.dispatchEvidence.payload.stagedRequestSha256",
        )?;
        require_equal_digest(
            &payload.dispatch_authorization_binding_sha256,
            &staged.dispatch_authorization_binding_sha256,
            "body.dispatchEvidence.payload.dispatchAuthorizationBindingSha256",
        )?;
        if staged.prepared_at_epoch_ms > payload.authorized_at_epoch_ms {
            return Err(ContractError::new(
                "dispatch_before_staging",
                "body.dispatchEvidence.payload.authorizedAtEpochMs",
                "dispatch authority cannot precede immutable request staging",
            ));
        }
        if payload.credential_binding_sha256.as_deref()
            != body.credential.binding_sha256()
        {
            return Err(ContractError::new(
                "credential_binding_mismatch",
                "body.dispatchEvidence.payload.credentialBindingSha256",
                "dispatch evidence credential binding does not match credential state",
            ));
        }
        let expected_idempotency = route_idempotency_digest(&body.route_semantics);
        if payload.idempotency_binding_sha256.as_deref() != expected_idempotency {
            return Err(ContractError::new(
                "idempotency_binding_mismatch",
                "body.dispatchEvidence.payload.idempotencyBindingSha256",
                "dispatch evidence does not match route idempotency semantics",
            ));
        }
        if let Some(write_started) = body
            .lifecycle
            .iter()
            .find(|item| item.state == LifecycleState::TargetWriteStarted)
            .map(|item| item.at_epoch_ms)
        {
            if write_started != payload.revalidated_at_epoch_ms
                || write_started > payload.dispatch_deadline_epoch_ms
            {
                return Err(ContractError::new(
                    "target_write_outside_dispatch_window",
                    "body.lifecycle",
                    "target byte writing must begin at the signed final revalidation instant and inside the dispatch deadline",
                ));
            }
        }
    }

    validate_terminal_evidence_graph(
        body,
        &semantic_profile,
        reserve.as_ref(),
        credential_authority.last(),
        recovery_seal.as_ref(),
        dispatch.as_ref(),
        exact_local_reconciliation_continuity,
        local_reconciliation_recovery.as_ref(),
        &terminal,
        credential_authority_roots.evidence_root_sha256.as_deref(),
        credential_authority_roots
            .state_machine_summary_sha256
            .as_deref(),
    )?;
    if let Some(custody) = custody.as_ref() {
        if custody.wire().predecessor_evidence_sha256.is_some() {
            return Err(ContractError::new(
                "invalid_evidence_predecessor",
                "body.custodyAuthorityEvidence.predecessorEvidenceSha256",
                "custody ownership evidence is an independent measured root",
            ));
        }
        require_equal_digest(
            &custody.wire().payload.authorization_binding_sha256,
            expected_authorization_binding,
            "body.custodyAuthorityEvidence.payload.authorizationBindingSha256",
        )?;
        let expected_staged = body
            .staged_target_request
            .as_ref()
            .map(|value| value.staging_sha256.as_str());
        let expected_dispatch_authorization = body
            .staged_target_request
            .as_ref()
            .map(|value| value.dispatch_authorization_binding_sha256.as_str());
        if custody.wire().payload.staged_request_sha256.as_deref()
            != expected_staged
            || custody
                .wire()
                .payload
                .dispatch_authorization_binding_sha256
                .as_deref()
                != expected_dispatch_authorization
        {
            return Err(ContractError::new(
                "custody_staged_authority_mismatch",
                "body.custodyAuthorityEvidence.payload",
                "measured custody must bind the exact staged request and its derived dispatch authorization",
            ));
        }
        if custody
            .wire()
            .payload
            .credential_authority_evidence_root_sha256
            .as_deref()
            != credential_authority_roots
                .evidence_root_sha256
                .as_deref()
        {
            return Err(ContractError::new(
                "credential_authority_root_mismatch",
                "body.custodyAuthorityEvidence.payload.credentialAuthorityEvidenceRootSha256",
                "measured custody authority must bind the exact aggregate authority-result root",
            ));
        }
        if custody
            .wire()
            .payload
            .credential_authority_state_machine_sha256
            .as_deref()
            != credential_authority_roots
                .state_machine_summary_sha256
                .as_deref()
        {
            return Err(ContractError::new(
                "credential_authority_state_machine_mismatch",
                "body.custodyAuthorityEvidence.payload.credentialAuthorityStateMachineSha256",
                "measured custody authority must bind the verified causal authority state machine",
            ));
        }
    }
    Ok(())
}

fn validate_evidence_body_time<P: EvidencePayload>(
    evidence: &SignedEvidence<P>,
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<()> {
    if evidence.issued_at_epoch_ms < body.nonce.issued_at_epoch_ms
        || evidence.issued_at_epoch_ms > body.issued_at_epoch_ms
        || evidence.payload.action_epoch_ms() < body.nonce.issued_at_epoch_ms
        || evidence.payload.action_epoch_ms() > body.issued_at_epoch_ms
        || evidence.payload.action_epoch_ms() > body.nonce.expires_at_epoch_ms
    {
        return Err(ContractError::new(
            "evidence_envelope_time_mismatch",
            "finalizedEnvelope.body",
            "evidence issuance and action times must remain inside the nonce and envelope timeline",
        ));
    }
    Ok(())
}

fn verify_credential_authority_chain(
    body: &ResponseObservationEnvelopeBodyV2,
    reserve: Option<&VerifiedEvidence<ReserveEvidencePayload>>,
    evidence: &[VerifiedEvidence<CredentialAuthorityEvidencePayload>],
    authorization_binding_sha256: &str,
    semantic_profile_sha256: &str,
) -> ContractResult<CredentialAuthorityRoots> {
    let mut roots = credential_authority_roots(evidence)?;
    let plan = body
        .policy
        .prerequisites()
        .map(|value| &value.authority_plan);
    let committed_plan_sha256 = plan.and_then(|value| {
        (value.mode == AuthorityPlanMode::Required)
            .then_some(value.plan_sha256.as_str())
    });
    let cancellation_failure = cancellation_failure_cause(body)?;
    roots.plan_sha256 = committed_plan_sha256.map(str::to_owned);
    if evidence.is_empty() {
        if !matches!(
            &body.credential_authority_side_effect,
            CredentialAuthoritySideEffect::NotAttempted { .. }
        ) {
            return Err(ContractError::new(
                "missing_credential_authority_evidence",
                "body.credentialAuthorityEvidence",
                "an attempted authority side effect requires independently signed evidence",
            ));
        }
        if reserve.is_some_and(|value| {
            value.wire().payload.credential_authority_plan_sha256.as_deref()
                != committed_plan_sha256
        }) {
            return Err(ContractError::new(
                "credential_authority_plan_reservation_mismatch",
                "body.reserveEvidence.payload.credentialAuthorityPlanSha256",
                "reserve evidence must bind the exact policy authority plan, including explicit no-plan",
            ));
        }
        if committed_plan_sha256.is_some() && reserve.is_some() {
            return Err(ContractError::new(
                "credential_authority_plan_without_evidence",
                "body.credentialAuthorityEvidence",
                "a started required authority plan must record its first committed success, failure, or unknown transition",
            ));
        }
        if body.credential_authority_state_machine.is_some() {
            return Err(ContractError::new(
                "unexpected_credential_authority_state_machine",
                "body.credentialAuthorityStateMachine",
                "an unattempted authority plan must use an explicit null state machine",
            ));
        }
        return Ok(roots);
    }
    let plan = plan
        .filter(|value| value.mode == AuthorityPlanMode::Required)
        .ok_or_else(|| {
            ContractError::new(
                "uncommitted_credential_authority_execution",
                "body.credentialAuthorityEvidence",
                "authority evidence is forbidden unless policy commits a required branch automaton",
            )
        })?;
    let reserve = reserve.ok_or_else(|| {
        ContractError::new(
            "credential_authority_without_reservation",
            "body.reserveEvidence",
            "credential-authority evidence requires a signed reservation predecessor",
        )
    })?;
    if reserve
        .wire()
        .payload
        .credential_authority_plan_sha256
        .as_deref()
        != Some(plan.plan_sha256.as_str())
    {
        return Err(ContractError::new(
            "credential_authority_plan_mismatch",
            "body.reserveEvidence.payload.credentialAuthorityPlanSha256",
            "reserve evidence must commit to the exact ordered typed authority requests before execution",
        ));
    }
    let plan_sha256 = plan.plan_sha256.clone();
    let initial_state_sha256 = domain_sha256(
        CREDENTIAL_AUTHORITY_INITIAL_STATE_DOMAIN,
        &[
            body.attempt_id.as_bytes(),
            authorization_binding_sha256.as_bytes(),
            semantic_profile_sha256.as_bytes(),
            reserve.wire().evidence_sha256.as_bytes(),
            plan_sha256.as_bytes(),
        ],
    )?;
    let mut execution_state_sha256 = initial_state_sha256.clone();
    let mut predecessor = reserve.wire().evidence_sha256.as_str();
    let mut previous_time = reserve.wire().payload.reserved_at_epoch_ms;
    let mut machine = CredentialAuthorityMachine::default();
    let mut terminal_index: Option<usize> = None;
    let mut external_terminal_index: Option<usize> = None;
    let mut external_failure_selected = false;
    let mut cleanup_record_sha256 = Vec::new();
    let mut consumed_plan_step_sha256 = Vec::with_capacity(evidence.len());
    let mut selected_path_leaves = Vec::with_capacity(evidence.len());
    let mut primary_index = 0usize;
    let mut cleanup_index = 0usize;
    for (index, item) in evidence.iter().enumerate() {
        let wire = item.wire();
        let payload = &wire.payload;
        require_equal_digest(
            &payload.authorization_binding_sha256,
            authorization_binding_sha256,
            "body.credentialAuthorityEvidence.payload.authorizationBindingSha256",
        )?;
        require_equal_digest(
            &payload.route_semantic_profile_sha256,
            semantic_profile_sha256,
            "body.credentialAuthorityEvidence.payload.routeSemanticProfileSha256",
        )?;
        validate_credential_authority_body_binding(body, payload)?;
        if usize::from(payload.sequence) != index + 1 {
            return Err(ContractError::new(
                "credential_authority_sequence_mismatch",
                "body.credentialAuthorityEvidence.payload.sequence",
                "authority records must use contiguous one-based sequence numbers",
            ));
        }
        require_equal_digest(
            &payload.prior_execution_state_sha256,
            &execution_state_sha256,
            "body.credentialAuthorityEvidence.payload.priorExecutionStateSha256",
        )?;
        require_equal_optional_digest(
            predecessor,
            wire.predecessor_evidence_sha256.as_deref(),
            "body.credentialAuthorityEvidence.predecessorEvidenceSha256",
        )?;
        if payload.completed_at_epoch_ms < previous_time {
            return Err(ContractError::new(
                "credential_authority_time_regression",
                "body.credentialAuthorityEvidence",
                "credential-authority effects must be signed in predecessor order",
            ));
        }
        let is_cleanup_candidate = matches!(
            &payload.operation_evidence,
            CredentialAuthorityOperationEvidence::QuotaBudget {
                request: QuotaBudgetRequest {
                    action: QuotaBudgetAction::Cancel,
                    ..
                },
                ..
            }
        );
        let opens_external_cleanup = terminal_index.is_none()
            && !external_failure_selected
            && is_cleanup_candidate
            && cancellation_failure.is_some();
        if opens_external_cleanup {
            let (failure_observed_at_epoch_ms, failure_sha256) =
                cancellation_failure.as_ref().ok_or_else(|| {
                    invalid_authority_transition(
                        "external cleanup lacks its signed cancellation failure cause",
                    )
                })?;
            if *failure_observed_at_epoch_ms < previous_time
                || payload.completed_at_epoch_ms
                    < *failure_observed_at_epoch_ms
            {
                return Err(invalid_authority_transition(
                    "external failure must follow the committed primary prefix and precede compensating cleanup",
                ));
            }
            external_terminal_index = index.checked_sub(1);
            if external_terminal_index.is_none() {
                return Err(invalid_authority_transition(
                    "external cleanup requires a successful committed primary reservation prefix",
                ));
            }
            selected_path_leaves.push(failure_sha256.clone());
            external_failure_selected = true;
        }
        if let (Some(authority_terminal_index), Some((failure_time, _))) =
            (terminal_index, cancellation_failure.as_ref())
        {
            let terminal_time = evidence[authority_terminal_index]
                .wire()
                .payload
                .completed_at_epoch_ms;
            if *failure_time < terminal_time
                || (is_cleanup_candidate
                    && payload.completed_at_epoch_ms < *failure_time)
            {
                return Err(invalid_authority_transition(
                    "signed cancellation failure must follow the original failed or unknown authority transition and precede cleanup",
                ));
            }
        }
        let branch_terminal =
            terminal_index.is_some() || external_failure_selected;
        let is_cleanup = branch_terminal && is_cleanup_candidate;
        if branch_terminal && !is_cleanup {
            return Err(ContractError::new(
                "credential_authority_operation_after_terminal",
                "body.credentialAuthorityEvidence",
                "only a causally valid quota cancellation may follow the original failed or unknown operation",
            ));
        }
        let expected_step = if is_cleanup {
            let relative_index = plan.cleanup_steps[cleanup_index..]
                .iter()
                .position(|step| {
                    step.step_sha256 == payload.plan_step_sha256
                })
                .ok_or_else(|| {
                    invalid_authority_transition(
                        "cleanup selected an uncommitted, duplicated, or reordered branch step",
                    )
                })?;
            cleanup_index = cleanup_index
                .checked_add(relative_index + 1)
                .ok_or_else(|| {
                    invalid_authority_transition(
                        "cleanup branch cursor overflowed",
                    )
                })?;
            plan.cleanup_steps.get(cleanup_index - 1)
        } else {
            plan.primary_steps.get(primary_index)
        }
        .ok_or_else(|| {
            invalid_authority_transition(
                "authority execution selected an operation outside the committed primary or cleanup branch",
            )
        })?;
        validate_authority_plan_step_execution(expected_step, payload)?;
        consumed_plan_step_sha256.push(expected_step.step_sha256.clone());
        let outcome = canonical_jcs_bytes(&payload.operation_evidence.outcome_kind())?;
        selected_path_leaves.push(domain_sha256(
            CREDENTIAL_AUTHORITY_SELECTED_PATH_DOMAIN,
            &[
                expected_step.step_sha256.as_bytes(),
                outcome.as_slice(),
                payload.operation_record_sha256.as_bytes(),
            ],
        )?);
        machine.apply(payload, is_cleanup)?;
        if is_cleanup {
            cleanup_record_sha256
                .push(payload.operation_record_sha256.clone());
        } else {
            primary_index += 1;
            if !payload.operation_evidence.is_succeeded() {
                terminal_index = Some(index);
            }
        }
        execution_state_sha256 = payload.execution_state_sha256.clone();
        predecessor = wire.evidence_sha256.as_str();
        previous_time = payload.completed_at_epoch_ms;
    }
    if terminal_index.is_none() && !external_failure_selected {
        if let Some((failure_observed_at_epoch_ms, failure_sha256)) =
            cancellation_failure.as_ref()
        {
            if *failure_observed_at_epoch_ms < previous_time {
                return Err(invalid_authority_transition(
                    "external failure cannot precede the committed primary prefix it terminates",
                ));
            }
            external_terminal_index = evidence.len().checked_sub(1);
            selected_path_leaves.push(failure_sha256.clone());
            external_failure_selected = true;
        }
    }
    if terminal_index.is_none()
        && !external_failure_selected
        && primary_index != plan.primary_steps.len()
    {
        return Err(invalid_authority_transition(
            "successful authority execution must consume the complete committed primary branch; a shorter path requires an explicit failed or unknown terminal record",
        ));
    }
    machine.validate_terminal_readiness(body, terminal_index)?;
    let (dispatch_valid_from_epoch_ms, dispatch_valid_until_epoch_ms) =
        machine.dispatch_validity_window();
    roots.dispatch_valid_from_epoch_ms = dispatch_valid_from_epoch_ms;
    roots.dispatch_valid_until_epoch_ms = dispatch_valid_until_epoch_ms;
    let unresolved_reservation_sha256 =
        machine.unresolved_reservation_sha256()?;
    let selected_path_frames = selected_path_leaves
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>();
    let selected_path_sha256 = domain_sha256(
        CREDENTIAL_AUTHORITY_SELECTED_PATH_DOMAIN,
        selected_path_frames.as_slice(),
    )?;
    let final_payload = &evidence.last().ok_or_else(|| {
        ContractError::new(
            "missing_credential_authority_evidence",
            "body.credentialAuthorityEvidence",
            "credential-authority chain unexpectedly became empty",
        )
    })?.wire().payload;
    let terminal_payload = &evidence[terminal_index
        .or(external_terminal_index)
        .unwrap_or(evidence.len() - 1)]
        .wire()
        .payload;
    let terminal_outcome = if external_failure_selected {
        CredentialAuthorityTerminalOutcome::ExternalFailure
    } else {
        match terminal_payload.operation_evidence.outcome_kind() {
            AuthorityOperationOutcome::Succeeded => {
                CredentialAuthorityTerminalOutcome::Completed
            }
            AuthorityOperationOutcome::DefinitelyFailed(_) => {
                CredentialAuthorityTerminalOutcome::DefinitelyFailed
            }
            AuthorityOperationOutcome::TransitionUnknown => {
                CredentialAuthorityTerminalOutcome::OutcomeUnknown
            }
        }
    };
    let external_failure_sha256 = if external_failure_selected {
        cancellation_failure
            .as_ref()
            .map(|value| value.1.as_str())
    } else {
        None
    };
    let state_machine =
        body.credential_authority_state_machine.as_ref().ok_or_else(|| {
            ContractError::new(
                "missing_credential_authority_state_machine",
                "body.credentialAuthorityStateMachine",
                "attempted authority effects require the exact signed execution-state summary",
            )
        })?;
    let expected_root =
        roots.evidence_root_sha256.clone().ok_or_else(|| {
        ContractError::new(
            "missing_credential_authority_root",
            "body.credentialAuthorityEvidence",
            "nonempty authority evidence must have an aggregate root",
        )
        })?;
    validate_credential_authority_state_machine_summary(
        state_machine,
        &initial_state_sha256,
        &execution_state_sha256,
        &plan_sha256,
        &selected_path_sha256,
        consumed_plan_step_sha256.as_slice(),
        &expected_root,
        terminal_outcome,
        &terminal_payload.operation_record_sha256,
        &final_payload.operation_record_sha256,
        external_failure_sha256,
        cleanup_record_sha256.as_slice(),
        unresolved_reservation_sha256.as_slice(),
        dispatch_valid_from_epoch_ms,
        dispatch_valid_until_epoch_ms,
    )?;
    roots.state_machine_summary_sha256 =
        Some(state_machine.summary_sha256.clone());
    validate_credential_authority_summary_binding(
        &body.credential_authority_side_effect,
        terminal_payload,
        final_payload,
        &expected_root,
        &state_machine.summary_sha256,
        body.credential.binding_sha256(),
    )?;
    Ok(roots)
}

fn cancellation_failure_cause(
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<Option<(u64, String)>> {
    let (
        reason,
        failure_observed_at_epoch_ms,
        completed_at_epoch_ms,
    ) = match (&body.authorization, &body.terminal_evidence.payload) {
        (
            AuthorizationState::ReservedCancelled { .. },
            TerminalEvidencePayload::Cancelled {
                reason,
                failure_observed_at_epoch_ms,
                completed_at_epoch_ms,
                ..
            },
        ) if matches!(
            reason,
            CancellationReason::CredentialFailure
                | CancellationReason::CredentialAcquisitionOutcomeUnknown
                | CancellationReason::CredentialAuthorityOutcomeUnknown
                | CancellationReason::RecoveryAuthorityFailure
                | CancellationReason::StagingFailed
                | CancellationReason::DeadlineExpiredBeforeWrite
        ) => (
            *reason,
            *failure_observed_at_epoch_ms,
            *completed_at_epoch_ms,
        ),
        _ => return Ok(None),
    };
    if failure_observed_at_epoch_ms > completed_at_epoch_ms {
        return Err(invalid_authority_transition(
            "signed cancellation failure cannot occur after terminal cancellation",
        ));
    }
    let reason_jcs = canonical_jcs_bytes(&reason)?;
    let failure_time = failure_observed_at_epoch_ms.to_be_bytes();
    let staged_request_sha256 = body
        .staged_target_request
        .as_ref()
        .map(|staged| staged.staging_sha256.as_str());
    let staged_jcs = canonical_jcs_bytes(&staged_request_sha256)?;
    let failure_sha256 = domain_sha256(
        CREDENTIAL_AUTHORITY_EXTERNAL_FAILURE_DOMAIN,
        &[
            body.attempt_id.as_bytes(),
            body.policy.request_sha256().as_bytes(),
            body.policy.operation_sha256().as_bytes(),
            reason_jcs.as_slice(),
            failure_time.as_slice(),
            staged_jcs.as_slice(),
        ],
    )?;
    Ok(Some((failure_observed_at_epoch_ms, failure_sha256)))
}

fn validate_credential_authority_body_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    payload: &CredentialAuthorityEvidencePayload,
) -> ContractResult<()> {
    match &payload.operation_evidence {
        CredentialAuthorityOperationEvidence::Grant { request, .. } => {
            require_equal_digest(
                &request.policy_sha256,
                body.policy.policy_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.policySha256",
            )?;
            require_equal_digest(
                &request.request_sha256,
                body.policy.request_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.requestSha256",
            )?;
            require_equal_digest(
                &request.operation_sha256,
                body.policy.operation_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.operationSha256",
            )?;
        }
        CredentialAuthorityOperationEvidence::CredentialAccess {
            request,
            ..
        } => {
            require_equal_digest(
                &request.request_sha256,
                body.policy.request_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.requestSha256",
            )?;
            require_equal_digest(
                &request.operation_sha256,
                body.policy.operation_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.operationSha256",
            )?;
            if body
                .route_semantic_profile_evidence
                .payload
                .provider_id
                .as_deref()
                != Some(request.provider_id.as_str())
            {
                return Err(ContractError::new(
                    "credential_provider_route_mismatch",
                    "body.credentialAuthorityEvidence.payload.operationEvidence.request.providerId",
                    "credential access provider must equal the signed route provider identity",
                ));
            }
            require_equal_digest(
                &request.recipient_runtime_measurement_sha256,
                &body.runtime.runtime_measurement_sha256,
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.recipientRuntimeMeasurementSha256",
            )?;
            if request.recipient_runtime_instance_id
                != body.runtime.runtime_instance_id
            {
                return Err(ContractError::new(
                    "credential_recipient_runtime_mismatch",
                    "body.credentialAuthorityEvidence.payload.operationEvidence.request.recipientRuntimeInstanceId",
                    "credential access must target the exact independently attested runtime instance",
                ));
            }
            if let Some(staged) = body.staged_target_request.as_ref() {
                require_equal_digest(
                    &request.credential_injection_template_sha256,
                    &staged.credential_injection_template_sha256,
                    "body.credentialAuthorityEvidence.payload.operationEvidence.request.credentialInjectionTemplateSha256",
                )?;
                if let Some(staged_request_sha256) =
                    request.staged_request_sha256.as_deref()
                {
                    require_equal_digest(
                        staged_request_sha256,
                        &staged.staging_sha256,
                        "body.credentialAuthorityEvidence.payload.operationEvidence.request.stagedRequestSha256",
                    )?;
                }
                if request.action
                    == CredentialAccessAction::AuthorizeInjection
                    && request.staged_request_sha256.is_none()
                {
                    return Err(ContractError::new(
                        "missing_injection_stage_binding",
                        "body.credentialAuthorityEvidence.payload.operationEvidence.request.stagedRequestSha256",
                        "an injection authority record after immutable staging must carry that exact staged-request commitment regardless of its outcome",
                    ));
                }
                let valid_order = match request.action {
                    CredentialAccessAction::AcquireLease
                    | CredentialAccessAction::AuthorizeDecryption => {
                        payload.completed_at_epoch_ms
                            <= staged.prepared_at_epoch_ms
                    }
                    CredentialAccessAction::AuthorizeInjection => {
                        payload.completed_at_epoch_ms
                            >= staged.prepared_at_epoch_ms
                    }
                };
                if !valid_order {
                    return Err(ContractError::new(
                        "credential_access_stage_order_mismatch",
                        "body.credentialAuthorityEvidence",
                        "lease/decryption must precede final staging and injection authorization must follow it",
                    ));
                }
            } else if request.staged_request_sha256.is_some() {
                return Err(ContractError::new(
                    "missing_staged_request_binding",
                    "body.stagedTargetRequest",
                    "an exact staged-request authority binding requires the same staged request in the envelope",
                ));
            }
        }
        CredentialAuthorityOperationEvidence::QuotaBudget {
            request,
            ..
        } => {
            require_equal_digest(
                &request.request_sha256,
                body.policy.request_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.requestSha256",
            )?;
            require_equal_digest(
                &request.operation_sha256,
                body.policy.operation_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.operationSha256",
            )?;
        }
        CredentialAuthorityOperationEvidence::OauthToken {
            request,
            ..
        } => {
            require_equal_digest(
                &request.request_sha256,
                body.policy.request_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.requestSha256",
            )?;
            require_equal_digest(
                &request.operation_sha256,
                body.policy.operation_sha256(),
                "body.credentialAuthorityEvidence.payload.operationEvidence.request.operationSha256",
            )?;
            if body
                .route_semantic_profile_evidence
                .payload
                .provider_id
                .as_deref()
                != Some(request.provider_authority_id.as_str())
            {
                return Err(ContractError::new(
                    "oauth_provider_route_mismatch",
                    "body.credentialAuthorityEvidence.payload.operationEvidence.request.providerAuthorityId",
                    "OAuth provider authority must equal the signed route provider identity",
                ));
            }
            let policy_identity =
                body.policy.credential_identity().ok_or_else(|| {
                    ContractError::new(
                        "missing_oauth_policy_credential",
                        "body.policy.credentialIdentity",
                        "every OAuth outcome requires the exact policy credential identity it attempts to produce",
                    )
                })?;
            if policy_identity.source != PolicyCredentialSource::AuthorityPlan
                || request.provider_authority_id != policy_identity.provider_id
                || request.account_id != policy_identity.account_id
                || request.credential_ref != policy_identity.credential_ref
                || request.credential_version
                    != policy_identity.credential_version
                || request.new_token_generation
                    != policy_identity.credential_generation
                || payload.credential_binding_sha256.as_deref()
                    != Some(
                        policy_identity
                            .credential_binding_sha256
                            .as_str(),
                    )
            {
                return Err(ContractError::new(
                    "oauth_policy_credential_mismatch",
                    "body.credentialAuthorityEvidence.payload.operationEvidence",
                    "successful, failed, and unknown OAuth outcomes must retain the exact policy provider, account, credential, version, proposed output generation, and credential binding",
                ));
            }
        }
    }
    Ok(())
}

fn validate_authority_plan_step_execution(
    step: &AuthorityPrerequisiteStep,
    payload: &CredentialAuthorityEvidencePayload,
) -> ContractResult<()> {
    if payload.authority_id != step.authority_id
        || payload.operation != step.operation
        || payload.prerequisite_sha256 != step.prerequisite_sha256
        || payload.plan_step_sha256 != step.step_sha256
    {
        return Err(invalid_authority_transition(
            "authority record identity, operation, prerequisite, or selected plan step is not the exact committed branch step",
        ));
    }
    let matches_constraint = match (
        &step.constraint,
        &payload.operation_evidence,
    ) {
        (
            AuthorityPrerequisiteConstraint::Grant {
                grant_id,
                approval_id,
                reservation_id,
                maximum_use_count,
                webauthn_required,
                webauthn_approval,
            },
            CredentialAuthorityOperationEvidence::Grant { request, .. },
        ) => {
            request.grant_id == *grant_id
                && request.approval_id == *approval_id
                && request.reservation_id == *reservation_id
                && request.maximum_use_count == *maximum_use_count
                && request.webauthn_required == *webauthn_required
                && request.webauthn_approval.as_ref()
                    == webauthn_approval.as_ref()
        }
        (
            AuthorityPrerequisiteConstraint::QuotaBudget {
                counter_id,
                budget_id,
                window_start_epoch_ms,
                window_end_epoch_ms,
                reservation_id,
                reservation_expires_at_epoch_ms,
                units,
                weight_basis_sha256,
            },
            CredentialAuthorityOperationEvidence::QuotaBudget {
                request, ..
            },
        ) => {
            request.counter_id == *counter_id
                && request.budget_id == *budget_id
                && request.window_start_epoch_ms == *window_start_epoch_ms
                && request.window_end_epoch_ms == *window_end_epoch_ms
                && request.reservation_id == *reservation_id
                && request.reservation_expires_at_epoch_ms
                    == *reservation_expires_at_epoch_ms
                && request.units == *units
                && request.weight_basis_sha256 == *weight_basis_sha256
        }
        (
            AuthorityPrerequisiteConstraint::Credential {
                provider_id,
                account_id,
                credential_ref,
                credential_version,
                credential_generation,
                lease_id,
                lease_release_id,
                authorization_receipt_id,
                expires_at_epoch_ms,
                credential_injection_template_sha256,
            },
            CredentialAuthorityOperationEvidence::CredentialAccess {
                request, ..
            },
        ) => {
            request.provider_id == *provider_id
                && request.account_id == *account_id
                && request.credential_ref == *credential_ref
                && request.credential_version == *credential_version
                && request.credential_generation == *credential_generation
                && request.lease_id == *lease_id
                && request.lease_release_id == *lease_release_id
                && request.authorization_receipt_id
                    == *authorization_receipt_id
                && request.expires_at_epoch_ms == *expires_at_epoch_ms
                && request.credential_injection_template_sha256
                    == *credential_injection_template_sha256
        }
        (
            AuthorityPrerequisiteConstraint::Oauth {
                provider_authority_id,
                subject_id,
                account_id,
                client_id,
                app_id,
                credential_ref,
                credential_version,
                granted_scope_root_sha256,
                prior_token_generation,
                new_token_generation,
                output_generation_rule,
                credential_binding_sha256,
                request_sha256,
                operation_sha256,
                authorization_binding_sha256,
                prior_state_sha256,
                provider_request_id,
                provider_idempotency_key_sha256,
            },
            CredentialAuthorityOperationEvidence::OauthToken {
                request, ..
            },
        ) => {
            request.provider_authority_id == *provider_authority_id
                && request.subject_id == *subject_id
                && request.account_id == *account_id
                && request.client_id == *client_id
                && request.app_id == *app_id
                && request.credential_ref == *credential_ref
                && request.credential_version == *credential_version
                && request.granted_scope_root_sha256
                    == *granted_scope_root_sha256
                && request.prior_token_generation == *prior_token_generation
                && request.new_token_generation == *new_token_generation
                && request.output_generation_rule == *output_generation_rule
                && payload.credential_binding_sha256.as_deref()
                    == Some(credential_binding_sha256.as_str())
                && request.request_sha256 == *request_sha256
                && request.operation_sha256 == *operation_sha256
                && request.authorization_binding_sha256
                    == *authorization_binding_sha256
                && request.prior_state_sha256 == *prior_state_sha256
                && request.provider_request_id == *provider_request_id
                && request.provider_idempotency_key_sha256.as_deref()
                    == provider_idempotency_key_sha256.as_deref()
        }
        _ => false,
    };
    if !matches_constraint {
        return Err(invalid_authority_transition(
            "authority request does not satisfy the exact policy-committed JIT, quota, credential, or OAuth prerequisite constraint",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CredentialAuthorityRoots {
    plan_sha256: Option<String>,
    evidence_root_sha256: Option<String>,
    state_machine_summary_sha256: Option<String>,
    dispatch_valid_from_epoch_ms: Option<u64>,
    dispatch_valid_until_epoch_ms: Option<u64>,
}

fn credential_authority_roots(
    evidence: &[VerifiedEvidence<CredentialAuthorityEvidencePayload>],
) -> ContractResult<CredentialAuthorityRoots> {
    if evidence.is_empty() {
        return Ok(CredentialAuthorityRoots {
            plan_sha256: None,
            evidence_root_sha256: None,
            state_machine_summary_sha256: None,
            dispatch_valid_from_epoch_ms: None,
            dispatch_valid_until_epoch_ms: None,
        });
    }
    let mut evidence_leaves = Vec::with_capacity(evidence.len());
    for (index, item) in evidence.iter().enumerate() {
        let payload = &item.wire().payload;
        let sequence = (index as u64).to_be_bytes();
        evidence_leaves.push(domain_sha256(
            CREDENTIAL_AUTHORITY_EVIDENCE_LEAF_DOMAIN,
            &[
                sequence.as_slice(),
                payload.operation_record_sha256.as_bytes(),
                item.wire().evidence_sha256.as_bytes(),
            ],
        )?);
    }
    let evidence_frames = evidence_leaves
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>();
    Ok(CredentialAuthorityRoots {
        plan_sha256: None,
        evidence_root_sha256: Some(domain_sha256(
            CREDENTIAL_AUTHORITY_EVIDENCE_ROOT_DOMAIN,
            evidence_frames.as_slice(),
        )?),
        state_machine_summary_sha256: None,
        dispatch_valid_from_epoch_ms: None,
        dispatch_valid_until_epoch_ms: None,
    })
}

#[derive(Default)]
struct CredentialAuthorityMachine {
    grant: Option<GrantLineage>,
    quotas: Vec<QuotaLineage>,
    quota_buckets: Vec<QuotaBucketLineage>,
    credential: Option<CredentialLineage>,
    oauth: Option<OauthLineage>,
    cleanup_attempted_reservations: BTreeSet<String>,
    uncertain_reservations: BTreeSet<String>,
    unresolved_reservations: BTreeSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GrantLineageState {
    Reserved,
    Consumed,
}

struct GrantLineage {
    authority_id: String,
    identity: GrantAuthorityRequest,
    expires_at_epoch_ms: u64,
    state: GrantLineageState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuotaLineageState {
    Reserved,
    Consumed,
    Cancelled,
}

struct QuotaLineage {
    authority_id: String,
    identity: QuotaBudgetRequest,
    state: QuotaLineageState,
}

struct QuotaBucketLineage {
    authority_id: String,
    counter_id: String,
    budget_id: String,
    window_start_epoch_ms: u64,
    window_end_epoch_ms: u64,
    sequence: u64,
    state_sha256: String,
    uncertain: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CredentialLineageState {
    LeaseAcquired,
    DecryptionAuthorized,
    InjectionAuthorized,
}

struct CredentialLineage {
    authority_id: String,
    identity: CredentialAccessRequest,
    credential_binding_sha256: String,
    state: CredentialLineageState,
}

struct OauthLineage {
    authority_id: String,
    identity: OauthTokenRequest,
    credential_binding_sha256: String,
}

impl CredentialAuthorityMachine {
    fn apply(
        &mut self,
        payload: &CredentialAuthorityEvidencePayload,
        cleanup_only: bool,
    ) -> ContractResult<()> {
        match &payload.operation_evidence {
            CredentialAuthorityOperationEvidence::Grant { request, result } => {
                if cleanup_only {
                    return Err(invalid_authority_transition(
                        "grant operations cannot follow a terminal outcome",
                    ));
                }
                match request.action {
                    GrantAuthorityAction::Reserve => {
                        if self.grant.is_some() {
                            return Err(invalid_authority_transition(
                                "grant reservation may occur exactly once",
                            ));
                        }
                        if let GrantAuthorityResult::Succeeded {
                            reservation_expires_at_epoch_ms:
                                Some(expires_at_epoch_ms),
                            ..
                        } = result
                        {
                            let expires_at_epoch_ms = request
                                .webauthn_approval
                                .as_ref()
                                .map(|approval| {
                                    approval
                                        .expires_at_epoch_ms
                                        .min(*expires_at_epoch_ms)
                                })
                                .unwrap_or(*expires_at_epoch_ms);
                            self.grant = Some(GrantLineage {
                                authority_id: payload.authority_id.clone(),
                                identity: request.clone(),
                                expires_at_epoch_ms,
                                state: GrantLineageState::Reserved,
                            });
                        }
                    }
                    GrantAuthorityAction::Consume => {
                        let lineage = self.grant.as_mut().ok_or_else(|| {
                            invalid_authority_transition(
                                "grant consumption requires a successful matching reservation",
                            )
                        })?;
                        if lineage.state != GrantLineageState::Reserved
                            || lineage.authority_id != payload.authority_id
                            || !same_grant_identity(&lineage.identity, request)
                            || request.prior_use_count
                                != lineage.identity.new_use_count
                            || request.prior_use_state_sha256
                                != lineage.identity.new_use_state_sha256
                        {
                            return Err(invalid_authority_transition(
                                "grant consume identity or predecessor state differs from its reservation",
                            ));
                        }
                        if matches!(result, GrantAuthorityResult::Succeeded { .. }) {
                            if payload.completed_at_epoch_ms
                                >= lineage.expires_at_epoch_ms
                            {
                                return Err(invalid_authority_transition(
                                    "grant consumption cannot succeed at or after the exact reservation expiry",
                                ));
                            }
                            lineage.identity = request.clone();
                            lineage.state = GrantLineageState::Consumed;
                        }
                    }
                }
                if matches!(
                    result,
                    GrantAuthorityResult::TransitionUnknown { .. }
                ) {
                    self.unresolved_reservations.insert(
                        unresolved_reservation_identity(
                            "grant",
                            &payload.authority_id,
                            &request.reservation_id,
                        )?,
                    );
                }
            }
            CredentialAuthorityOperationEvidence::QuotaBudget {
                request,
                result,
            } => {
                let bucket_index = self.quota_buckets.iter().position(
                    |bucket| {
                        same_quota_bucket(
                            bucket,
                            &payload.authority_id,
                            request,
                        )
                    },
                );
                if let Some(index) = bucket_index {
                    let bucket = &self.quota_buckets[index];
                    if bucket.uncertain
                        || request.prior_sequence != bucket.sequence
                        || request.prior_state_sha256
                            != bucket.state_sha256
                    {
                        return Err(invalid_authority_transition(
                            "quota operation must consume the one current state of its exact authority, counter, budget, and window bucket",
                        ));
                    }
                } else if request.action != QuotaBudgetAction::Reserve {
                    return Err(invalid_authority_transition(
                        "quota consume or cancel requires an established exact bucket state",
                    ));
                }
                match request.action {
                    QuotaBudgetAction::Reserve => {
                        if cleanup_only
                            || self.quotas.iter().any(|lineage| {
                                lineage.identity.reservation_id
                                    == request.reservation_id
                            })
                        {
                            return Err(invalid_authority_transition(
                                "quota reservation identity may be introduced exactly once before a terminal outcome",
                            ));
                        }
                        if matches!(
                            result,
                            QuotaBudgetResult::Succeeded { .. }
                        ) {
                            self.quotas.push(QuotaLineage {
                                authority_id: payload.authority_id.clone(),
                                identity: request.clone(),
                                state: QuotaLineageState::Reserved,
                            });
                        }
                    }
                    QuotaBudgetAction::Consume
                    | QuotaBudgetAction::Cancel => {
                        if cleanup_only
                            && self
                                .uncertain_reservations
                                .contains(&request.reservation_id)
                        {
                            return Err(invalid_authority_transition(
                                "a reservation with an unknown consume or cancel transition must be reconciled, not cancelled as if still reserved",
                            ));
                        }
                        if cleanup_only
                            && !self
                                .cleanup_attempted_reservations
                                .insert(request.reservation_id.clone())
                        {
                            return Err(invalid_authority_transition(
                                "each reservation permits at most one compensating cleanup attempt",
                            ));
                        }
                        let lineage = self
                            .quotas
                            .iter_mut()
                            .find(|lineage| {
                                lineage.identity.reservation_id
                                    == request.reservation_id
                            })
                            .ok_or_else(|| {
                                invalid_authority_transition(
                                    "quota consume or cancel requires its exact successful reservation",
                                )
                            })?;
                        if lineage.state != QuotaLineageState::Reserved
                            || lineage.authority_id
                                != payload.authority_id
                            || !same_quota_identity(
                                &lineage.identity,
                                request,
                            )
                        {
                            return Err(invalid_authority_transition(
                                "quota transition identity, weighted amount, or bucket differs from its reservation",
                            ));
                        }
                        if cleanup_only
                            && request.action
                                != QuotaBudgetAction::Cancel
                        {
                            return Err(invalid_authority_transition(
                                "only quota cancellation is a valid compensating cleanup",
                            ));
                        }
                        if matches!(
                            result,
                            QuotaBudgetResult::Succeeded { .. }
                        ) {
                            lineage.identity = request.clone();
                            lineage.state = match request.action {
                                QuotaBudgetAction::Consume => {
                                    QuotaLineageState::Consumed
                                }
                                QuotaBudgetAction::Cancel => {
                                    QuotaLineageState::Cancelled
                                }
                                QuotaBudgetAction::Reserve => {
                                    unreachable!()
                                }
                            };
                        } else if matches!(
                            result,
                            QuotaBudgetResult::TransitionUnknown {
                                ..
                            }
                        ) {
                            self.uncertain_reservations
                                .insert(request.reservation_id.clone());
                        }
                    }
                }
                match result {
                    QuotaBudgetResult::Succeeded { .. } => {
                        if let Some(index) = bucket_index {
                            let bucket = &mut self.quota_buckets[index];
                            bucket.sequence = request.new_sequence;
                            bucket.state_sha256 =
                                request.new_state_sha256.clone();
                        } else {
                            self.quota_buckets.push(QuotaBucketLineage {
                                authority_id: payload.authority_id.clone(),
                                counter_id: request.counter_id.clone(),
                                budget_id: request.budget_id.clone(),
                                window_start_epoch_ms:
                                    request.window_start_epoch_ms,
                                window_end_epoch_ms:
                                    request.window_end_epoch_ms,
                                sequence: request.new_sequence,
                                state_sha256:
                                    request.new_state_sha256.clone(),
                                uncertain: false,
                            });
                        }
                    }
                    QuotaBudgetResult::TransitionUnknown { .. } => {
                        if let Some(index) = bucket_index {
                            self.quota_buckets[index].uncertain = true;
                        }
                        self.unresolved_reservations.insert(
                            unresolved_reservation_identity(
                                "quota-budget",
                                &payload.authority_id,
                                &request.reservation_id,
                            )?,
                        );
                    }
                    QuotaBudgetResult::DefinitelyFailed { .. } => {}
                }
            }
            CredentialAuthorityOperationEvidence::CredentialAccess {
                request,
                result,
            } => {
                if cleanup_only {
                    return Err(invalid_authority_transition(
                        "credential operations cannot follow a terminal outcome",
                    ));
                }
                match request.action {
                    CredentialAccessAction::AcquireLease => {
                        if self.credential.is_some() {
                            return Err(invalid_authority_transition(
                                "credential lease may be acquired exactly once",
                            ));
                        }
                        if let Some(oauth) = self.oauth.as_ref() {
                            if oauth.authority_id != payload.authority_id
                                || !oauth_matches_credential(
                                    &oauth.identity,
                                    request,
                                )
                                || request.prior_state_sha256
                                    != oauth.identity.new_state_sha256
                                || payload
                                    .credential_binding_sha256
                                    .as_deref()
                                    != Some(
                                        oauth
                                            .credential_binding_sha256
                                            .as_str(),
                                    )
                            {
                                return Err(invalid_authority_transition(
                                    "credential lease identity must equal the exact OAuth-produced provider, account, credential, version, generation, and binding",
                                ));
                            }
                        }
                        if matches!(
                            result,
                            CredentialAccessResult::Succeeded { .. }
                        ) {
                            self.credential = Some(CredentialLineage {
                                authority_id: payload.authority_id.clone(),
                                identity: request.clone(),
                                credential_binding_sha256: payload
                                    .credential_binding_sha256
                                    .clone()
                                    .ok_or_else(|| {
                                        invalid_authority_transition(
                                            "successful lease acquisition requires one credential binding",
                                        )
                                    })?,
                                state: CredentialLineageState::LeaseAcquired,
                            });
                        }
                    }
                    CredentialAccessAction::AuthorizeDecryption
                    | CredentialAccessAction::AuthorizeInjection => {
                        let lineage =
                            self.credential.as_mut().ok_or_else(|| {
                                invalid_authority_transition(
                                    "credential authorization requires its exact successful lease",
                                )
                            })?;
                        let expected_state = match request.action {
                            CredentialAccessAction::AuthorizeDecryption => {
                                CredentialLineageState::LeaseAcquired
                            }
                            CredentialAccessAction::AuthorizeInjection => {
                                CredentialLineageState::DecryptionAuthorized
                            }
                            CredentialAccessAction::AcquireLease => {
                                unreachable!()
                            }
                        };
                        if lineage.state != expected_state
                            || lineage.authority_id != payload.authority_id
                            || !same_credential_identity(
                                &lineage.identity,
                                request,
                            )
                            || request.prior_state_sha256
                                != lineage.identity.new_state_sha256
                            || payload.credential_binding_sha256.as_deref()
                                != Some(
                                    lineage
                                        .credential_binding_sha256
                                        .as_str(),
                                )
                        {
                            return Err(invalid_authority_transition(
                                "credential operation identity, lease, release, generation, binding, or predecessor state is not continuous",
                            ));
                        }
                        if matches!(
                            result,
                            CredentialAccessResult::Succeeded { .. }
                        ) {
                            lineage.identity = request.clone();
                            lineage.state = match request.action {
                                CredentialAccessAction::AuthorizeDecryption => {
                                    CredentialLineageState::DecryptionAuthorized
                                }
                                CredentialAccessAction::AuthorizeInjection => {
                                    CredentialLineageState::InjectionAuthorized
                                }
                                CredentialAccessAction::AcquireLease => {
                                    unreachable!()
                                }
                            };
                        }
                    }
                }
            }
            CredentialAuthorityOperationEvidence::OauthToken {
                request,
                result,
            } => {
                if cleanup_only
                    || self.oauth.is_some()
                    || self.credential.is_some()
                {
                    return Err(invalid_authority_transition(
                        "one OAuth transition may precede credential lease acquisition",
                    ));
                }
                if matches!(result, OauthTokenResult::Succeeded { .. }) {
                    self.oauth = Some(OauthLineage {
                        authority_id: payload.authority_id.clone(),
                        identity: request.clone(),
                        credential_binding_sha256: payload
                            .credential_binding_sha256
                            .clone()
                            .ok_or_else(|| {
                                invalid_authority_transition(
                                    "successful OAuth transition requires its exact issued credential binding",
                                )
                            })?,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_terminal_readiness(
        &self,
        body: &ResponseObservationEnvelopeBodyV2,
        terminal_index: Option<usize>,
    ) -> ContractResult<()> {
        if let Some(lineage) = self.credential.as_ref() {
            if body.credential.binding_sha256()
                != Some(lineage.credential_binding_sha256.as_str())
            {
                return Err(invalid_authority_transition(
                    "envelope credential state must equal the one binding carried through the signed lease, decrypt, and injection lineage",
                ));
            }
        } else if let Some(oauth) = self.oauth.as_ref() {
            if body.credential.binding_sha256()
                != Some(oauth.credential_binding_sha256.as_str())
            {
                return Err(invalid_authority_transition(
                    "envelope credential state must equal the exact OAuth-issued credential binding",
                ));
            }
        }
        if terminal_index.is_some() && body.dispatch_evidence.is_some() {
            return Err(invalid_authority_transition(
                "a failed or unknown authority operation can never authorize dispatch",
            ));
        }
        if body.dispatch_evidence.is_none() {
            return Ok(());
        }
        if matches!(
            body.policy.credential_mode(),
            Some(PolicyCredentialMode::Required)
        ) && self
            .credential
            .as_ref()
            .is_none_or(|lineage| {
                lineage.state != CredentialLineageState::InjectionAuthorized
            })
        {
            return Err(invalid_authority_transition(
                "credential-required dispatch needs acquire, decrypt, and exact-request injection authorization in order",
            ));
        }
        if self.grant.as_ref().is_some_and(|lineage| {
            lineage.state != GrantLineageState::Consumed
        }) || self.quotas.iter().any(|lineage| {
            lineage.state != QuotaLineageState::Consumed
        }) {
            return Err(invalid_authority_transition(
                "dispatch requires every grant and weighted quota reservation to be consumed, never merely reserved or cancelled",
            ));
        }
        Ok(())
    }

    fn dispatch_validity_window(&self) -> (Option<u64>, Option<u64>) {
        let valid_from = self
            .quotas
            .iter()
            .map(|lineage| lineage.identity.window_start_epoch_ms)
            .max();
        let mut valid_until = self
            .grant
            .as_ref()
            .map(|lineage| lineage.expires_at_epoch_ms);
        if let Some(credential_expiry) = self
            .credential
            .as_ref()
            .map(|lineage| lineage.identity.expires_at_epoch_ms)
        {
            valid_until = Some(
                valid_until
                    .map(|current| current.min(credential_expiry))
                    .unwrap_or(credential_expiry),
            );
        }
        for quota_expiry in self
            .quotas
            .iter()
            .map(|lineage| {
                lineage
                    .identity
                    .window_end_epoch_ms
                    .min(lineage.identity.reservation_expires_at_epoch_ms)
            })
        {
            valid_until = Some(
                valid_until
                    .map(|current| current.min(quota_expiry))
                    .unwrap_or(quota_expiry),
            );
        }
        (valid_from, valid_until)
    }

    fn unresolved_reservation_sha256(
        &self,
    ) -> ContractResult<Vec<String>> {
        let mut unresolved = self.unresolved_reservations.clone();
        if let Some(lineage) = self.grant.as_ref() {
            if lineage.state == GrantLineageState::Reserved {
                unresolved.insert(unresolved_reservation_identity(
                    "grant",
                    &lineage.authority_id,
                    &lineage.identity.reservation_id,
                )?);
            }
        }
        for lineage in &self.quotas {
            if lineage.state == QuotaLineageState::Reserved {
                unresolved.insert(unresolved_reservation_identity(
                    "quota-budget",
                    &lineage.authority_id,
                    &lineage.identity.reservation_id,
                )?);
            }
        }
        Ok(unresolved.into_iter().collect())
    }
}

fn invalid_authority_transition(message: &'static str) -> ContractError {
    ContractError::new(
        "invalid_credential_authority_transition",
        "body.credentialAuthorityEvidence",
        message,
    )
}

fn same_grant_identity(
    left: &GrantAuthorityRequest,
    right: &GrantAuthorityRequest,
) -> bool {
    left.grant_id == right.grant_id
        && left.approval_id == right.approval_id
        && left.policy_sha256 == right.policy_sha256
        && left.request_sha256 == right.request_sha256
        && left.operation_sha256 == right.operation_sha256
        && left.authorization_binding_sha256
            == right.authorization_binding_sha256
        && left.reservation_id == right.reservation_id
        && left.maximum_use_count == right.maximum_use_count
        && left.webauthn_required == right.webauthn_required
        && left.webauthn_approval == right.webauthn_approval
}

fn same_quota_identity(
    left: &QuotaBudgetRequest,
    right: &QuotaBudgetRequest,
) -> bool {
    left.counter_id == right.counter_id
        && left.budget_id == right.budget_id
        && left.window_start_epoch_ms == right.window_start_epoch_ms
        && left.window_end_epoch_ms == right.window_end_epoch_ms
        && left.reservation_id == right.reservation_id
        && left.reservation_expires_at_epoch_ms
            == right.reservation_expires_at_epoch_ms
        && left.units == right.units
        && left.weight_basis_sha256 == right.weight_basis_sha256
        && left.request_sha256 == right.request_sha256
        && left.operation_sha256 == right.operation_sha256
        && left.authorization_binding_sha256
            == right.authorization_binding_sha256
}

fn same_quota_bucket(
    bucket: &QuotaBucketLineage,
    authority_id: &str,
    request: &QuotaBudgetRequest,
) -> bool {
    bucket.authority_id == authority_id
        && bucket.counter_id == request.counter_id
        && bucket.budget_id == request.budget_id
        && bucket.window_start_epoch_ms
            == request.window_start_epoch_ms
        && bucket.window_end_epoch_ms == request.window_end_epoch_ms
}

fn unresolved_reservation_identity(
    family: &str,
    authority_id: &str,
    reservation_id: &str,
) -> ContractResult<String> {
    domain_sha256(
        CREDENTIAL_AUTHORITY_UNRESOLVED_RESERVATION_DOMAIN,
        &[
            family.as_bytes(),
            authority_id.as_bytes(),
            reservation_id.as_bytes(),
        ],
    )
}

fn same_credential_identity(
    left: &CredentialAccessRequest,
    right: &CredentialAccessRequest,
) -> bool {
    left.provider_id == right.provider_id
        && left.account_id == right.account_id
        && left.credential_ref == right.credential_ref
        && left.credential_version == right.credential_version
        && left.credential_generation == right.credential_generation
        && left.recipient_runtime_measurement_sha256
            == right.recipient_runtime_measurement_sha256
        && left.recipient_runtime_instance_id
            == right.recipient_runtime_instance_id
        && left.lease_id == right.lease_id
        && left.lease_release_id == right.lease_release_id
        && left.authorization_receipt_id
            == right.authorization_receipt_id
        && left.expires_at_epoch_ms == right.expires_at_epoch_ms
        && left.credential_injection_template_sha256
            == right.credential_injection_template_sha256
        && left.request_sha256 == right.request_sha256
        && left.operation_sha256 == right.operation_sha256
        && left.authorization_binding_sha256
            == right.authorization_binding_sha256
}

fn oauth_matches_credential(
    oauth: &OauthTokenRequest,
    credential: &CredentialAccessRequest,
) -> bool {
    oauth.provider_authority_id == credential.provider_id
        && oauth.account_id == credential.account_id
        && oauth.credential_ref == credential.credential_ref
        && oauth.credential_version == credential.credential_version
        && oauth.new_token_generation == credential.credential_generation
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialAuthorityStateMachineCommitment<'a> {
    initial_state_sha256: &'a str,
    final_state_sha256: &'a str,
    plan_sha256: &'a str,
    selected_path_sha256: &'a str,
    consumed_plan_step_sha256: &'a [String],
    evidence_root_sha256: &'a str,
    terminal_outcome: CredentialAuthorityTerminalOutcome,
    terminal_record_sha256: &'a str,
    final_record_sha256: &'a str,
    external_failure_sha256: Option<&'a str>,
    cleanup_record_sha256: &'a [String],
    unresolved_reservation_sha256: &'a [String],
    dispatch_valid_from_epoch_ms: Option<u64>,
    dispatch_valid_until_epoch_ms: Option<u64>,
}

fn validate_credential_authority_state_machine_summary(
    summary: &CredentialAuthorityStateMachineSummary,
    initial_state_sha256: &str,
    final_state_sha256: &str,
    plan_sha256: &str,
    selected_path_sha256: &str,
    consumed_plan_step_sha256: &[String],
    evidence_root_sha256: &str,
    terminal_outcome: CredentialAuthorityTerminalOutcome,
    terminal_record_sha256: &str,
    final_record_sha256: &str,
    external_failure_sha256: Option<&str>,
    cleanup_record_sha256: &[String],
    unresolved_reservation_sha256: &[String],
    dispatch_valid_from_epoch_ms: Option<u64>,
    dispatch_valid_until_epoch_ms: Option<u64>,
) -> ContractResult<()> {
    for digest in [
        &summary.initial_state_sha256,
        &summary.final_state_sha256,
        &summary.plan_sha256,
        &summary.selected_path_sha256,
        &summary.evidence_root_sha256,
        &summary.terminal_record_sha256,
        &summary.final_record_sha256,
        &summary.summary_sha256,
    ] {
        validate_digest(digest, "credentialAuthorityStateMachine")?;
    }
    if let Some(digest) = summary.external_failure_sha256.as_deref() {
        validate_digest(
            digest,
            "credentialAuthorityStateMachine.externalFailureSha256",
        )?;
    }
    if summary.consumed_plan_step_sha256.len()
        > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(invalid_authority_transition(
            "selected plan path exceeds the authority evidence bound",
        ));
    }
    for digest in &summary.consumed_plan_step_sha256 {
        validate_digest(digest, "credentialAuthorityStateMachine.selectedPath")?;
    }
    for value in [
        summary.dispatch_valid_from_epoch_ms,
        summary.dispatch_valid_until_epoch_ms,
    ]
    .into_iter()
    .flatten()
    {
        validate_safe_time(value, "credentialAuthorityStateMachine.dispatchValidity")?;
    }
    if matches!(
        (
            summary.dispatch_valid_from_epoch_ms,
            summary.dispatch_valid_until_epoch_ms,
        ),
        (Some(from), Some(until)) if until <= from
    ) {
        return Err(invalid_authority_transition(
            "authority dispatch validity window is empty",
        ));
    }
    if summary.cleanup_record_sha256.len()
        > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(invalid_authority_transition(
            "cleanup record list exceeds the authority evidence bound",
        ));
    }
    for digest in &summary.cleanup_record_sha256 {
        validate_digest(digest, "credentialAuthorityStateMachine.cleanup")?;
    }
    if summary.unresolved_reservation_sha256.len()
        > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(invalid_authority_transition(
            "unresolved reservation list exceeds the authority evidence bound",
        ));
    }
    for digest in &summary.unresolved_reservation_sha256 {
        validate_digest(
            digest,
            "credentialAuthorityStateMachine.unresolvedReservation",
        )?;
    }
    if summary.initial_state_sha256 != initial_state_sha256
        || summary.final_state_sha256 != final_state_sha256
        || summary.plan_sha256 != plan_sha256
        || summary.selected_path_sha256 != selected_path_sha256
        || summary.consumed_plan_step_sha256
            != consumed_plan_step_sha256
        || summary.evidence_root_sha256 != evidence_root_sha256
        || summary.terminal_outcome != terminal_outcome
        || summary.terminal_record_sha256 != terminal_record_sha256
        || summary.final_record_sha256 != final_record_sha256
        || summary.external_failure_sha256.as_deref()
            != external_failure_sha256
        || summary.cleanup_record_sha256 != cleanup_record_sha256
        || summary.unresolved_reservation_sha256
            != unresolved_reservation_sha256
        || summary.dispatch_valid_from_epoch_ms
            != dispatch_valid_from_epoch_ms
        || summary.dispatch_valid_until_epoch_ms
            != dispatch_valid_until_epoch_ms
    {
        return Err(invalid_authority_transition(
            "state-machine summary does not equal the verified causal execution",
        ));
    }
    let commitment = CredentialAuthorityStateMachineCommitment {
        initial_state_sha256,
        final_state_sha256,
        plan_sha256,
        selected_path_sha256,
        consumed_plan_step_sha256,
        evidence_root_sha256,
        terminal_outcome,
        terminal_record_sha256,
        final_record_sha256,
        external_failure_sha256,
        cleanup_record_sha256,
        unresolved_reservation_sha256,
        dispatch_valid_from_epoch_ms,
        dispatch_valid_until_epoch_ms,
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected = domain_sha256(
        CREDENTIAL_AUTHORITY_STATE_MACHINE_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &summary.summary_sha256,
        &expected,
        "body.credentialAuthorityStateMachine.summarySha256",
    )
}

fn verify_durable_recovery_seal(
    body: &ResponseObservationEnvelopeBodyV2,
    reserve: Option<&VerifiedEvidence<ReserveEvidencePayload>>,
    final_credential_authority:
        Option<&VerifiedEvidence<CredentialAuthorityEvidencePayload>>,
    seal: Option<&VerifiedEvidence<DurableRecoverySealPayload>>,
    authorization_binding_sha256: &str,
    semantic_profile_sha256: &str,
) -> ContractResult<()> {
    let RouteSemantics::Write {
        provider_idempotency,
        ambiguous_outcome_recovery,
    } = &body.route_semantics
    else {
        if seal.is_some() {
            return Err(ContractError::new(
                "unexpected_durable_recovery_seal",
                "body.durableRecoverySealEvidence",
                "only dispatchable writes may carry a durable recovery seal",
            ));
        }
        return Ok(());
    };
    let seal = seal.ok_or_else(|| {
        ContractError::new(
            "missing_durable_recovery_seal",
            "body.durableRecoverySealEvidence",
            "every dispatchable write requires a separately signed rollback-protected recovery seal",
        )
    })?;
    let reserve = reserve.ok_or_else(|| {
        ContractError::new(
            "recovery_seal_without_reservation",
            "body.reserveEvidence",
            "a durable recovery seal requires a signed reservation",
        )
    })?;
    let payload = &seal.wire().payload;
    require_equal_digest(
        &payload.authorization_binding_sha256,
        authorization_binding_sha256,
        "body.durableRecoverySealEvidence.payload.authorizationBindingSha256",
    )?;
    require_equal_digest(
        &payload.route_semantic_profile_sha256,
        semantic_profile_sha256,
        "body.durableRecoverySealEvidence.payload.routeSemanticProfileSha256",
    )?;
    require_equal_digest(
        &payload.idempotency_binding_sha256,
        &provider_idempotency.binding_sha256,
        "body.durableRecoverySealEvidence.payload.idempotencyBindingSha256",
    )?;
    require_equal_digest(
        &payload.recovery_key_sha256,
        &ambiguous_outcome_recovery.recovery_key_sha256,
        "body.durableRecoverySealEvidence.payload.recoveryKeySha256",
    )?;
    require_equal_digest(
        &payload.durable_record_sha256,
        &ambiguous_outcome_recovery.durable_record_sha256,
        "body.durableRecoverySealEvidence.payload.durableRecordSha256",
    )?;
    if payload.rollback_state_epoch != body.runtime.rollback_state_epoch {
        return Err(ContractError::new(
            "recovery_rollback_epoch_mismatch",
            "body.durableRecoverySealEvidence.payload.rollbackStateEpoch",
            "durable recovery seal is not bound to the attested rollback-protected epoch",
        ));
    }
    let expected_predecessor = final_credential_authority
        .map(|value| value.wire().evidence_sha256.as_str())
        .unwrap_or(reserve.wire().evidence_sha256.as_str());
    require_equal_optional_digest(
        expected_predecessor,
        seal.wire().predecessor_evidence_sha256.as_deref(),
        "body.durableRecoverySealEvidence.predecessorEvidenceSha256",
    )?;
    let staged_at = body
        .staged_target_request
        .as_ref()
        .map(|value| value.prepared_at_epoch_ms)
        .unwrap_or(0);
    let authority_predecessor_time = final_credential_authority
        .map(|value| value.wire().payload.completed_at_epoch_ms)
        .unwrap_or(reserve.wire().payload.reserved_at_epoch_ms);
    if payload.armed_at_epoch_ms < staged_at
        || payload.armed_at_epoch_ms < authority_predecessor_time
    {
        return Err(ContractError::new(
            "recovery_seal_before_staging",
            "body.durableRecoverySealEvidence.payload.armedAtEpochMs",
            "recovery must be armed after exact request staging and before dispatch authority",
        ));
    }
    Ok(())
}

fn verify_local_reconciliation_recovery_evidence(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
    exact_reconciliation: Option<&VerifiedLocalReconciliationRecord>,
    reserve: Option<&VerifiedEvidence<ReserveEvidencePayload>>,
    custody: Option<&VerifiedEvidence<CustodyAuthorityEvidencePayload>>,
    continuity: Option<&VerifiedLocalReconciliationContinuity>,
    recovery: Option<
        &VerifiedEvidence<LocalReconciliationRecoveryEvidencePayload>,
    >,
) -> ContractResult<()> {
    let Some(exact) = exact_reconciliation else {
        if recovery.is_some() {
            return Err(ContractError::new(
                "unexpected_local_reconciliation_recovery_evidence",
                "body.localReconciliationRecoveryEvidence",
                "signed local recovery evidence is forbidden without a verifier-retrieved unresolved local reconciliation record",
            ));
        }
        return Ok(());
    };
    let reference = match &body.credential {
        CredentialState::AcquisitionOutcomeUnknown {
            local_reconciliation: Some(reference),
            ..
        } => reference,
        _ => {
            return Err(ContractError::new(
                "local_reconciliation_branch_mismatch",
                "body.credential",
                "retrieved local reconciliation evidence can only appear on the closed local acquisition-outcome-unknown branch",
            ))
        }
    };
    let custody = custody.ok_or_else(|| {
        ContractError::new(
            "missing_local_reconciliation_custody",
            "body.custodyAuthorityEvidence",
            "local reconciliation recovery requires separately verified custody authority",
        )
    })?;
    let reserve = reserve.ok_or_else(|| {
        ContractError::new(
            "missing_local_reconciliation_reserve",
            "body.reserveEvidence",
            "local acquisition reconciliation must remain causally bound to the exact reservation that preceded acquisition",
        )
    })?;
    let recovery = recovery.ok_or_else(|| {
        ContractError::new(
            "missing_local_reconciliation_recovery_evidence",
            "body.localReconciliationRecoveryEvidence",
            "local acquisition uncertainty requires separately signed recovery evidence over the retrieved exact record",
        )
    })?;
    let continuity = continuity.ok_or_else(|| {
        ContractError::new(
            "missing_local_reconciliation_continuity",
            "body.localReconciliationContinuityEvidence",
            "local acquisition uncertainty requires exact predecessor/genesis continuity and the externally pinned store quorum/transparency witness",
        )
    })?;
    let pin = context
        .reconciliation_witness_authority()
        .ok_or_else(|| {
            ContractError::new(
                "missing_reconciliation_witness_authority_pin",
                "verificationContext.reconciliationWitnessAuthority",
                "local reconciliation recovery requires proof-independent store, credential-ledger, GENESIS, witness, and recovery-authority pins",
            )
        })?;
    let payload = &recovery.wire().payload;
    let record = &exact.record;
    let continuity_payload = &continuity.continuity.wire().payload;
    let witness_payload = &continuity.ledger_witness.wire().payload;
    let continuity_predecessor_valid = match (
        &continuity_payload.predecessor,
        continuity.genesis_absence.as_ref(),
    ) {
        (LocalReconciliationPredecessorProof::Predecessor { .. }, None) => {
            continuity
                .continuity
                .wire()
                .predecessor_evidence_sha256
                .as_deref()
                == Some(custody.wire().evidence_sha256.as_str())
                && continuity.predecessor_record.is_some()
                && continuity.predecessor_recovery.is_some()
        }
        (LocalReconciliationPredecessorProof::Genesis { .. }, Some(genesis)) => {
            genesis.wire().predecessor_evidence_sha256.as_deref()
                == Some(custody.wire().evidence_sha256.as_str())
                && continuity
                    .continuity
                    .wire()
                    .predecessor_evidence_sha256
                    .as_deref()
                    == Some(genesis.wire().evidence_sha256.as_str())
                && continuity.predecessor_record.is_none()
                && continuity.predecessor_recovery.is_none()
        }
        _ => false,
    };
    let (failure_observed_at_epoch_ms, completed_at_epoch_ms) =
        match &body.terminal_evidence.payload {
            TerminalEvidencePayload::Cancelled {
                failure_observed_at_epoch_ms,
                completed_at_epoch_ms,
                ..
            } => (*failure_observed_at_epoch_ms, *completed_at_epoch_ms),
            _ => {
                return Err(ContractError::new(
                    "local_reconciliation_without_cancellation",
                    "body.terminalEvidence.payload",
                    "signed local reconciliation recovery evidence requires the closed cancellation terminal",
                ))
            }
        };
    if reference.recovery_evidence_sha256
            != recovery.wire().evidence_sha256
        || !continuity_predecessor_valid
        || recovery.wire().predecessor_evidence_sha256.as_deref()
            != Some(
                continuity
                    .ledger_witness
                    .wire()
                    .evidence_sha256
                    .as_str(),
            )
        || recovery.wire().key_id != pin.recovery_authority_key_id()
        || recovery.key_material_sha256()
            != pin.recovery_authority_key_material_sha256()
        || recovery.wire().key_id == custody.wire().key_id
        || recovery.key_material_sha256() == custody.key_material_sha256()
        || recovery.revoked_at_epoch_ms().is_some_and(|revoked_at| {
            revoked_at <= context.trusted_now_epoch_ms()
        })
        || payload.recovery_authority_key_id
            != pin.recovery_authority_key_id()
        || payload.recovery_authority_key_material_sha256
            != pin.recovery_authority_key_material_sha256()
        || payload.recovery_authority_trust_checkpoint_sha256
            != pin.trust_checkpoint_sha256()
        || payload.recovery_authority_revocation_epoch
            != pin.revocation_epoch()
        || payload.custody_authority_key_id != custody.wire().key_id
        || payload.custody_authority_key_material_sha256
            != custody.key_material_sha256()
        || record.custody_authority_key_id != custody.wire().key_id
        || record.custody_authority_key_material_sha256
            != custody.key_material_sha256()
        || continuity.continuity.wire().key_id
            != custody.wire().key_id
        || continuity.continuity.key_material_sha256()
            != custody.key_material_sha256()
        || continuity.ledger_witness.wire().key_id
            != continuity.transparency_operator_key_id
        || continuity.ledger_witness.key_material_sha256()
            != continuity.transparency_operator_key_material_sha256
        || continuity.transparency_operator_key_id
            == custody.wire().key_id
        || continuity.transparency_operator_key_id
            == recovery.wire().key_id
        || continuity.transparency_operator_key_material_sha256
            == custody.key_material_sha256()
        || continuity.transparency_operator_key_material_sha256
            == recovery.key_material_sha256()
        || continuity
            .quorum_member_key_ids
            .contains(custody.wire().key_id.as_str())
        || continuity
            .quorum_member_key_ids
            .contains(recovery.wire().key_id.as_str())
        || continuity
            .quorum_member_key_material_sha256
            .contains(custody.key_material_sha256())
        || continuity
            .quorum_member_key_material_sha256
            .contains(recovery.key_material_sha256())
        || continuity_payload.custody_authority_evidence_sha256
            != custody.wire().evidence_sha256
        || continuity_payload.custody_authority_key_id
            != custody.wire().key_id
        || continuity_payload.custody_authority_key_material_sha256
            != custody.key_material_sha256()
        || witness_payload.custody_authority_key_id
            != custody.wire().key_id
        || witness_payload.custody_authority_key_material_sha256
            != custody.key_material_sha256()
        || continuity_payload.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || continuity_payload.revocation_epoch
            != context.current_revocation_epoch()
        || witness_payload.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || witness_payload.revocation_epoch
            != context.current_revocation_epoch()
        || payload.attempt_id != record.attempt_id
        || payload.request_sha256 != record.request_sha256
        || payload.operation_sha256 != record.operation_sha256
        || payload.authorization_binding_sha256
            != record.authorization_binding_sha256
        || payload.reserve_evidence_sha256
            != reserve.wire().evidence_sha256
        || payload.custody_authority_evidence_sha256
            != custody.wire().evidence_sha256
        || payload.credential_binding_sha256
            != record.credential_binding_sha256
        || payload.provider_id != record.provider_id
        || payload.account_id != record.account_id
        || payload.credential_ref != record.credential_ref
        || payload.credential_version != record.credential_version
        || payload.credential_generation != record.credential_generation
        || payload.record_id != exact.record_id
        || payload.record_sha256 != exact.record_sha256
        || payload.record_byte_length != exact.record_byte_length
        || payload.retrieval_id != exact.retrieval_id
        || payload.status != record.status
        || payload.uncertain_side_effect != record.uncertain_side_effect
        || payload.created_at_epoch_ms != record.created_at_epoch_ms
        || payload.deadline_epoch_ms != record.deadline_epoch_ms
        || payload.rollback_state_epoch != record.rollback_state_epoch
        || payload.rollback_head_sha256 != record.rollback_head_sha256
        || payload.credential_ledger_namespace
            != pin.credential_ledger_namespace()
        || payload.credential_ledger_namespace
            != record.credential_ledger_namespace
        || payload.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256()
        || payload.pinned_genesis_state_sha256
            != record.pinned_genesis_state_sha256
        || payload.predecessor_successor_key_sha256
            != record.predecessor_successor_key_sha256
        || payload.predecessor_successor_key_sha256
            != continuity_payload.predecessor_successor_key_sha256
        || payload.predecessor_record_id != record.predecessor_record_id
        || payload.predecessor_record_sha256
            != record.predecessor_record_sha256
        || payload.predecessor_rollback_head_sha256
            != record.predecessor_rollback_head_sha256
        || payload.linearizable_store_id
            != record.linearizable_store_id
        || payload.linearizable_store_cluster_id
            != record.linearizable_store_cluster_id
        || payload.store_transaction_id != record.store_transaction_id
        || payload.store_term != record.store_term
        || payload.store_log_index != record.store_log_index
        || payload.store_fencing_token != record.store_fencing_token
        || payload.persistence_receipt_sha256
            != exact.persistence_receipt_sha256
        || payload.retrieval_proof_sha256 != exact.retrieval_proof_sha256
        || payload.continuity_evidence_sha256
            != continuity.continuity.wire().evidence_sha256
        || payload.ledger_witness_evidence_sha256
            != continuity.ledger_witness.wire().evidence_sha256
        || payload.predecessor_proof_sha256
            != continuity.predecessor_proof_sha256
        || payload.store_transition_sha256
            != continuity.store_transition_sha256
        || payload.quorum_certificate_sha256
            != continuity.quorum_certificate_sha256
        || payload.transparency_log_proof_sha256
            != continuity.transparency_log_proof_sha256
        || reference.continuity_evidence_sha256
            != continuity.continuity.wire().evidence_sha256
        || reference.ledger_witness_sha256
            != continuity.ledger_witness.wire().evidence_sha256
        || reference.predecessor_proof_sha256
            != continuity.predecessor_proof_sha256
        || reference.store_transition_sha256
            != continuity.store_transition_sha256
        || reference.quorum_certificate_sha256
            != continuity.quorum_certificate_sha256
        || reference.transparency_log_proof_sha256
            != continuity.transparency_log_proof_sha256
        || payload.trust_checkpoint_sha256
            != record.trust_checkpoint_sha256
        || payload.revocation_epoch != record.revocation_epoch
        || payload.trust_checkpoint_sha256
            != recovery.trust_checkpoint_sha256
        || payload.revocation_epoch != recovery.revocation_epoch
        || payload.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || payload.revocation_epoch != context.current_revocation_epoch()
        || payload.recovery_authority_trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || payload.recovery_authority_revocation_epoch
            != context.current_revocation_epoch()
        || custody.trust_checkpoint_sha256
            != recovery.trust_checkpoint_sha256
        || custody.revocation_epoch != recovery.revocation_epoch
        || custody.wire().payload.rollback_state_epoch
            != record.rollback_state_epoch
        || custody.wire().payload.measured_at_epoch_ms
            > continuity.continuity.wire().payload.signed_at_epoch_ms
        || continuity
            .ledger_witness
            .wire()
            .payload
            .witnessed_at_epoch_ms
            > payload.signed_at_epoch_ms
        || payload.signed_at_epoch_ms < failure_observed_at_epoch_ms
        || payload.signed_at_epoch_ms > completed_at_epoch_ms
        || payload.signed_at_epoch_ms >= payload.deadline_epoch_ms
    {
        return Err(ContractError::new(
            "local_reconciliation_recovery_binding_mismatch",
            "body.localReconciliationRecoveryEvidence",
            "signed recovery evidence must exactly bind the independently pinned credential-ledger namespace, GENESIS state, predecessor conflict key, retrieved bytes, unresolved side effect and timeline, immutable storage proofs, exact custody identity, and a distinct current non-revoked recovery authority",
        ));
    }
    Ok(())
}

fn validate_terminal_evidence_graph(
    body: &ResponseObservationEnvelopeBodyV2,
    semantic_profile:
        &VerifiedEvidence<RouteSemanticProfileEvidencePayload>,
    reserve: Option<&VerifiedEvidence<ReserveEvidencePayload>>,
    final_credential_authority:
        Option<&VerifiedEvidence<CredentialAuthorityEvidencePayload>>,
    recovery_seal: Option<&VerifiedEvidence<DurableRecoverySealPayload>>,
    dispatch: Option<&VerifiedEvidence<DispatchEvidencePayload>>,
    local_reconciliation_continuity:
        Option<&VerifiedLocalReconciliationContinuity>,
    local_reconciliation_recovery:
        Option<&VerifiedEvidence<LocalReconciliationRecoveryEvidencePayload>>,
    terminal: &VerifiedEvidence<TerminalEvidencePayload>,
    credential_authority_evidence_root_sha256: Option<&str>,
    credential_authority_state_machine_sha256: Option<&str>,
) -> ContractResult<()> {
    let wire = terminal.wire();
    if wire.payload.action_epoch_ms() > body.issued_at_epoch_ms {
        return Err(ContractError::new(
            "terminal_after_envelope",
            "body.terminalEvidence.payload",
            "terminal action cannot occur after envelope issuance",
        ));
    }
    let (terminal_profile, terminal_authorization) = match &wire.payload {
        TerminalEvidencePayload::Cancelled {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        }
        | TerminalEvidencePayload::Completed {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        }
        | TerminalEvidencePayload::ResponseRejected {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        }
        | TerminalEvidencePayload::ExactResponseUnsupported {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        }
        | TerminalEvidencePayload::WriteTransitionUnknown {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        }
        | TerminalEvidencePayload::ReadTransitionUnknown {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            ..
        } => (
            route_semantic_profile_sha256,
            authorization_binding_sha256,
        ),
    };
    require_equal_digest(
        terminal_profile,
        &semantic_profile.wire().payload.semantic_profile_sha256,
        "body.terminalEvidence.payload.routeSemanticProfileSha256",
    )?;
    require_equal_digest(
        terminal_authorization,
        &semantic_profile.wire().payload.authorization_binding_sha256,
        "body.terminalEvidence.payload.authorizationBindingSha256",
    )?;
    match &wire.payload {
        TerminalEvidencePayload::Cancelled {
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            dispatch_authorization_binding_sha256,
            staged_request_sha256,
            local_reconciliation_recovery_evidence_sha256,
            local_reconciliation_recovery_authority_key_id,
            local_reconciliation_recovery_authority_key_material_sha256,
            local_reconciliation_recovery_authority_trust_checkpoint_sha256,
            local_reconciliation_recovery_authority_revocation_epoch,
            local_reconciliation_credential_ledger_namespace,
            local_reconciliation_pinned_genesis_state_sha256,
            local_reconciliation_predecessor_successor_key_sha256,
            local_reconciliation_continuity_evidence_sha256,
            local_reconciliation_store_transition_sha256,
            local_reconciliation_quorum_certificate_sha256,
            local_reconciliation_transparency_log_proof_sha256,
            definitely_not_dispatched,
            failure_observed_at_epoch_ms,
            completed_at_epoch_ms,
            ..
        } => {
            if !*definitely_not_dispatched {
                return Err(ContractError::new(
                    "contradictory_terminal_claim",
                    "body.terminalEvidence.payload.definitelyNotDispatched",
                    "cancellation must prove definitely-not-dispatched",
                ));
            }
            if reserve_evidence_sha256.as_deref()
                != reserve.map(|value| value.wire().evidence_sha256.as_str())
                || dispatch_evidence_sha256.as_deref()
                    != dispatch.map(|value| value.wire().evidence_sha256.as_str())
            {
                return Err(ContractError::new(
                    "terminal_evidence_graph_mismatch",
                    "body.terminalEvidence.payload",
                    "cancellation evidence does not bind the exact reserve and dispatch chain",
                ));
            }
            if terminal_root.as_deref()
                != credential_authority_evidence_root_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_root_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityEvidenceRootSha256",
                    "terminal cancellation must bind the aggregate authority-result root",
                ));
            }
            if terminal_state_machine.as_deref()
                != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_state_machine_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityStateMachineSha256",
                    "terminal cancellation must bind the verified causal authority state machine",
                ));
            }
            if local_reconciliation_recovery_evidence_sha256.as_deref()
                != local_reconciliation_recovery
                    .map(|value| value.wire().evidence_sha256.as_str())
            {
                return Err(ContractError::new(
                    "local_reconciliation_recovery_terminal_mismatch",
                    "body.terminalEvidence.payload.localReconciliationRecoveryEvidenceSha256",
                    "cancellation must bind exactly the separately signed local reconciliation recovery evidence and every other cancellation must carry null",
                ));
            }
            if local_reconciliation_recovery_authority_key_id.as_deref()
                    != local_reconciliation_recovery
                        .map(|value| value.wire().key_id.as_str())
                || local_reconciliation_recovery_authority_key_material_sha256
                    .as_deref()
                    != local_reconciliation_recovery
                        .map(|value| value.key_material_sha256())
                || local_reconciliation_recovery_authority_trust_checkpoint_sha256
                    .as_deref()
                    != local_reconciliation_recovery.map(|value| {
                        value.trust_checkpoint_sha256.as_str()
                    })
                || *local_reconciliation_recovery_authority_revocation_epoch
                    != local_reconciliation_recovery
                        .map(|value| value.revocation_epoch)
            {
                return Err(ContractError::new(
                    "local_reconciliation_recovery_authority_terminal_mismatch",
                    "body.terminalEvidence.payload",
                    "cancellation must bind the exact verified independently pinned recovery key id, public-key material, trust checkpoint, and revocation epoch; every other cancellation must carry null",
                ));
            }
            if local_reconciliation_continuity_evidence_sha256.as_deref()
                != local_reconciliation_continuity
                    .map(|value| {
                        value.continuity.wire().evidence_sha256.as_str()
                    })
            {
                return Err(ContractError::new(
                    "local_reconciliation_continuity_terminal_mismatch",
                    "body.terminalEvidence.payload.localReconciliationContinuityEvidenceSha256",
                    "cancellation must bind the exact signed predecessor/genesis continuity evidence and every other cancellation must carry null",
                ));
            }
            if local_reconciliation_credential_ledger_namespace.as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value
                            .continuity
                            .wire()
                            .payload
                            .credential_ledger_namespace
                            .as_str()
                    })
                || local_reconciliation_pinned_genesis_state_sha256
                    .as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value
                            .continuity
                            .wire()
                            .payload
                            .pinned_genesis_state_sha256
                            .as_str()
                    })
                || local_reconciliation_predecessor_successor_key_sha256
                    .as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value
                            .continuity
                            .wire()
                            .payload
                            .predecessor_successor_key_sha256
                            .as_str()
                    })
            {
                return Err(ContractError::new(
                    "local_reconciliation_namespace_terminal_mismatch",
                    "body.terminalEvidence.payload",
                    "cancellation must bind the exact proof-independent credential-ledger namespace, pinned GENESIS state, and predecessor conflict key verified by continuity; every other cancellation must carry null",
                ));
            }
            if local_reconciliation_store_transition_sha256.as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value.store_transition_sha256.as_str()
                    })
                || local_reconciliation_quorum_certificate_sha256.as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value.quorum_certificate_sha256.as_str()
                    })
                || local_reconciliation_transparency_log_proof_sha256
                    .as_deref()
                    != local_reconciliation_continuity.map(|value| {
                        value.transparency_log_proof_sha256.as_str()
                    })
            {
                return Err(ContractError::new(
                    "local_reconciliation_store_witness_terminal_mismatch",
                    "body.terminalEvidence.payload",
                    "cancellation must bind the verifier-derived CAS transition, quorum certificate, and externally anchored transparency proof, with null on every other branch",
                ));
            }
            if staged_request_sha256.as_deref()
                != body
                    .staged_target_request
                    .as_ref()
                    .map(|value| value.staging_sha256.as_str())
                || dispatch_authorization_binding_sha256.as_deref()
                    != body.staged_target_request.as_ref().map(|value| {
                        value.dispatch_authorization_binding_sha256.as_str()
                    })
            {
                return Err(ContractError::new(
                    "cancelled_staged_request_binding_mismatch",
                    "body.terminalEvidence.payload",
                    "pre-dispatch cancellation must retain the exact staged request and derived dispatch authority when immutable bytes were produced",
                ));
            }
            let expected_predecessor = local_reconciliation_recovery
                .map(|value| value.wire().evidence_sha256.as_str())
                .or_else(|| {
                    dispatch
                        .map(|value| value.wire().evidence_sha256.as_str())
                })
                .or_else(|| {
                    recovery_seal
                        .map(|value| value.wire().evidence_sha256.as_str())
                })
                .or_else(|| {
                    final_credential_authority
                        .map(|value| value.wire().evidence_sha256.as_str())
                })
                .or_else(|| {
                    reserve.map(|value| value.wire().evidence_sha256.as_str())
                })
                .or(Some(semantic_profile.wire().evidence_sha256.as_str()));
            if wire.predecessor_evidence_sha256.as_deref() != expected_predecessor {
                return Err(ContractError::new(
                    "invalid_evidence_predecessor",
                    "body.terminalEvidence.predecessorEvidenceSha256",
                    "cancellation predecessor is not the last authorization evidence",
                ));
            }
            let predecessor_time = local_reconciliation_recovery
                .map(|value| value.wire().payload.signed_at_epoch_ms)
                .or_else(|| {
                    dispatch
                        .map(|value| value.wire().payload.authorized_at_epoch_ms)
                })
                .or_else(|| {
                    recovery_seal
                        .map(|value| value.wire().payload.armed_at_epoch_ms)
                })
                .or_else(|| {
                    final_credential_authority
                        .map(|value| value.wire().payload.completed_at_epoch_ms)
                })
                .or_else(|| {
                    reserve.map(|value| value.wire().payload.reserved_at_epoch_ms)
                })
                .unwrap_or(
                    semantic_profile.wire().payload.signed_at_epoch_ms,
                );
            let predecessor_time = body
                .staged_target_request
                .as_ref()
                .map(|staged| predecessor_time.max(staged.prepared_at_epoch_ms))
                .unwrap_or(predecessor_time);
            let failure_floor = dispatch
                .map(|value| value.wire().payload.authorized_at_epoch_ms)
                .or_else(|| {
                    recovery_seal
                        .map(|value| value.wire().payload.armed_at_epoch_ms)
                })
                .or_else(|| {
                    reserve.map(|value| {
                        value.wire().payload.reserved_at_epoch_ms
                    })
                })
                .unwrap_or(
                    semantic_profile.wire().payload.signed_at_epoch_ms,
                );
            let failure_floor = body
                .staged_target_request
                .as_ref()
                .map(|staged| {
                    failure_floor.max(staged.prepared_at_epoch_ms)
                })
                .unwrap_or(failure_floor);
            if *failure_observed_at_epoch_ms < failure_floor
                || *failure_observed_at_epoch_ms > *completed_at_epoch_ms
                || *completed_at_epoch_ms < predecessor_time
            {
                return Err(ContractError::new(
                    "cancellation_before_predecessor",
                    "body.terminalEvidence.payload",
                    "failure observation must follow the signed request preparation floor and terminal cancellation must follow both that failure and its final authorization or cleanup predecessor",
                ));
            }
        }
        TerminalEvidencePayload::Completed {
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            staged_request_sha256,
            upstream_observation_sha256,
            completed_at_epoch_ms,
            ..
        } => {
            if terminal_root.as_deref()
                != credential_authority_evidence_root_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_root_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityEvidenceRootSha256",
                    "terminal completion must bind the aggregate authority-result root",
                ));
            }
            if terminal_state_machine.as_deref()
                != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_state_machine_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityStateMachineSha256",
                    "terminal completion must bind the verified causal authority state machine",
                ));
            }
            let dispatch = dispatch.ok_or_else(|| {
                ContractError::new(
                    "missing_dispatch_evidence",
                    "body.dispatchEvidence",
                    "completion requires dispatch evidence",
                )
            })?;
            require_equal_digest(
                dispatch_evidence_sha256,
                &dispatch.wire().evidence_sha256,
                "body.terminalEvidence.payload.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                &dispatch.wire().evidence_sha256,
                wire.predecessor_evidence_sha256.as_deref(),
                "body.terminalEvidence.predecessorEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "completion requires staged target bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.terminalEvidence.payload.stagedRequestSha256",
            )?;
            require_equal_digest(
                dispatch_authorization_binding_sha256,
                &staged.dispatch_authorization_binding_sha256,
                "body.terminalEvidence.payload.dispatchAuthorizationBindingSha256",
            )?;
            require_equal_digest(
                upstream_observation_sha256,
                &body.upstream_observation.digest()?,
                "body.terminalEvidence.payload.upstreamObservationSha256",
            )?;
            let observed_at = match &body.upstream_observation {
                UpstreamObservationState::ObservedResponse {
                    observed_at_epoch_ms,
                    completion: UpstreamResponseCompletion::Complete,
                    response_policy_validation:
                        ResponsePolicyValidation {
                            decision: ResponsePolicyDecision::Passed,
                            ..
                        },
                    ..
                } => *observed_at_epoch_ms,
                _ => {
                    return Err(ContractError::new(
                        "completion_without_passing_exact_response",
                        "body.upstreamObservation",
                        "completed terminal state requires a complete exact response that passes the signed provider response restrictions",
                    ));
                }
            };
            if *completed_at_epoch_ms < observed_at {
                return Err(ContractError::new(
                    "completion_before_observation",
                    "body.terminalEvidence.payload.completedAtEpochMs",
                    "completion cannot precede the observed upstream bytes it commits",
                ));
            }
        }
        TerminalEvidencePayload::ResponseRejected {
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            staged_request_sha256,
            upstream_observation_sha256,
            reason,
            rejected_at_epoch_ms,
            ..
        } => {
            if terminal_root.as_deref()
                != credential_authority_evidence_root_sha256
                || terminal_state_machine.as_deref()
                    != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "response_rejection_authority_mismatch",
                    "body.terminalEvidence.payload",
                    "response rejection must preserve the exact authority evidence root and state-machine summary",
                ));
            }
            let dispatch = dispatch.ok_or_else(|| {
                ContractError::new(
                    "missing_dispatch_evidence",
                    "body.dispatchEvidence",
                    "response rejection requires dispatch evidence",
                )
            })?;
            require_equal_digest(
                dispatch_evidence_sha256,
                &dispatch.wire().evidence_sha256,
                "body.terminalEvidence.payload.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                &dispatch.wire().evidence_sha256,
                wire.predecessor_evidence_sha256.as_deref(),
                "body.terminalEvidence.predecessorEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "response rejection requires exact staged request bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.terminalEvidence.payload.stagedRequestSha256",
            )?;
            require_equal_digest(
                dispatch_authorization_binding_sha256,
                &staged.dispatch_authorization_binding_sha256,
                "body.terminalEvidence.payload.dispatchAuthorizationBindingSha256",
            )?;
            require_equal_digest(
                upstream_observation_sha256,
                &body.upstream_observation.digest()?,
                "body.terminalEvidence.payload.upstreamObservationSha256",
            )?;
            let observed_at = match (&body.upstream_observation, reason) {
                (
                    UpstreamObservationState::ObservedResponse {
                        observed_at_epoch_ms,
                        completion: UpstreamResponseCompletion::Complete,
                        response_policy_validation:
                            ResponsePolicyValidation {
                                decision: ResponsePolicyDecision::Failed,
                                ..
                            },
                        ..
                    },
                    ResponseRejectionReason::PolicyRejected,
                )
                | (
                    UpstreamObservationState::ObservedResponse {
                        observed_at_epoch_ms,
                        completion: UpstreamResponseCompletion::Truncated,
                        response_policy_validation:
                            ResponsePolicyValidation {
                                decision:
                                    ResponsePolicyDecision::NotEvaluatedIncompleteResponse,
                                ..
                            },
                        ..
                    },
                    ResponseRejectionReason::IncompleteResponse,
                ) => *observed_at_epoch_ms,
                _ => {
                    return Err(ContractError::new(
                        "response_rejection_reason_mismatch",
                        "body.terminalEvidence.payload.reason",
                        "response rejection must distinguish a complete policy failure from an incomplete exact response capture",
                    ));
                }
            };
            if *rejected_at_epoch_ms < observed_at {
                return Err(ContractError::new(
                    "response_rejection_before_observation",
                    "body.terminalEvidence.payload.rejectedAtEpochMs",
                    "response rejection cannot precede the exact upstream bytes it commits",
                ));
            }
        }
        TerminalEvidencePayload::ExactResponseUnsupported {
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            staged_request_sha256,
            upstream_observation_sha256,
            reason,
            unsupported_at_epoch_ms,
            ..
        } => {
            if terminal_root.as_deref()
                != credential_authority_evidence_root_sha256
                || terminal_state_machine.as_deref()
                    != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "unsupported_response_authority_mismatch",
                    "body.terminalEvidence.payload",
                    "unsupported response terminal must preserve the exact authority evidence root and state-machine summary",
                ));
            }
            let dispatch = dispatch.ok_or_else(|| {
                ContractError::new(
                    "missing_dispatch_evidence",
                    "body.dispatchEvidence",
                    "unsupported exact response requires dispatch evidence",
                )
            })?;
            require_equal_digest(
                dispatch_evidence_sha256,
                &dispatch.wire().evidence_sha256,
                "body.terminalEvidence.payload.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                &dispatch.wire().evidence_sha256,
                wire.predecessor_evidence_sha256.as_deref(),
                "body.terminalEvidence.predecessorEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "unsupported exact response requires exact staged request bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.terminalEvidence.payload.stagedRequestSha256",
            )?;
            require_equal_digest(
                dispatch_authorization_binding_sha256,
                &staged.dispatch_authorization_binding_sha256,
                "body.terminalEvidence.payload.dispatchAuthorizationBindingSha256",
            )?;
            require_equal_digest(
                upstream_observation_sha256,
                &body.upstream_observation.digest()?,
                "body.terminalEvidence.payload.upstreamObservationSha256",
            )?;
            let observed_at = match &body.upstream_observation {
                UpstreamObservationState::ExactResponseUnsupported {
                    reason: observed_reason,
                    response_policy_decision:
                        ResponsePolicyDecision::NotEvaluatedUnsupportedResponse,
                    downstream_delivery: DownstreamDeliveryState::Unknown,
                    observed_at_epoch_ms,
                    ..
                } if observed_reason == reason => *observed_at_epoch_ms,
                _ => {
                    return Err(ContractError::new(
                        "unsupported_response_terminal_mismatch",
                        "body.terminalEvidence.payload",
                        "unsupported terminal must bind the exact trusted unsupported response reason and non-passing observation",
                    ))
                }
            };
            if *unsupported_at_epoch_ms < observed_at {
                return Err(ContractError::new(
                    "unsupported_terminal_before_observation",
                    "body.terminalEvidence.payload.unsupportedAtEpochMs",
                    "unsupported terminal cannot precede exact response observation",
                ));
            }
        }
        TerminalEvidencePayload::WriteTransitionUnknown {
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            durable_recovery_seal_evidence_sha256,
            staged_request_sha256,
            idempotency_binding_sha256,
            recovery_binding_sha256,
            unknown_at_epoch_ms,
            ..
        } => {
            if terminal_root.as_deref()
                != credential_authority_evidence_root_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_root_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityEvidenceRootSha256",
                    "terminal unknown state must bind the aggregate authority-result root",
                ));
            }
            if terminal_state_machine.as_deref()
                != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "credential_authority_state_machine_mismatch",
                    "body.terminalEvidence.payload.credentialAuthorityStateMachineSha256",
                    "terminal unknown state must bind the verified causal authority state machine",
                ));
            }
            let dispatch = dispatch.ok_or_else(|| {
                ContractError::new(
                    "missing_dispatch_evidence",
                    "body.dispatchEvidence",
                    "transition-unknown requires dispatch evidence",
                )
            })?;
            require_equal_digest(
                dispatch_evidence_sha256,
                &dispatch.wire().evidence_sha256,
                "body.terminalEvidence.payload.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                &dispatch.wire().evidence_sha256,
                wire.predecessor_evidence_sha256.as_deref(),
                "body.terminalEvidence.predecessorEvidenceSha256",
            )?;
            let recovery_seal = recovery_seal.ok_or_else(|| {
                ContractError::new(
                    "missing_durable_recovery_seal",
                    "body.durableRecoverySealEvidence",
                    "unknown write transition requires the pre-dispatch durable recovery seal",
                )
            })?;
            require_equal_digest(
                durable_recovery_seal_evidence_sha256,
                &recovery_seal.wire().evidence_sha256,
                "body.terminalEvidence.payload.durableRecoverySealEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "transition-unknown requires staged target bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.terminalEvidence.payload.stagedRequestSha256",
            )?;
            require_equal_digest(
                dispatch_authorization_binding_sha256,
                &staged.dispatch_authorization_binding_sha256,
                "body.terminalEvidence.payload.dispatchAuthorizationBindingSha256",
            )?;
            require_equal_digest(
                idempotency_binding_sha256,
                route_idempotency_digest(&body.route_semantics).ok_or_else(
                    || {
                        ContractError::new(
                            "idempotency_binding_mismatch",
                            "body.terminalEvidence.payload.idempotencyBindingSha256",
                            "write transition uncertainty requires exact provider idempotency authority",
                        )
                    },
                )?,
                "body.terminalEvidence.payload.idempotencyBindingSha256",
            )?;
            require_equal_digest(
                recovery_binding_sha256,
                route_recovery_binding(&body.route_semantics)?,
                "body.terminalEvidence.payload.recoveryBindingSha256",
            )?;
            let target_unknown_at = match &body.target_egress {
                TargetEgressState::WriteOutcomeUnknown {
                    unknown_at_epoch_ms,
                    ..
                } => *unknown_at_epoch_ms,
                _ => 0,
            };
            if *unknown_at_epoch_ms != target_unknown_at {
                return Err(ContractError::new(
                    "unknown_transition_time_mismatch",
                    "body.terminalEvidence.payload.unknownAtEpochMs",
                    "terminal unknown time must equal the target-egress transition time",
                ));
            }
        }
        TerminalEvidencePayload::ReadTransitionUnknown {
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256: terminal_root,
            credential_authority_state_machine_sha256:
                terminal_state_machine,
            staged_request_sha256,
            retry_binding_sha256,
            unknown_at_epoch_ms,
            ..
        } => {
            if recovery_seal.is_some()
                || terminal_root.as_deref()
                    != credential_authority_evidence_root_sha256
                || terminal_state_machine.as_deref()
                    != credential_authority_state_machine_sha256
            {
                return Err(ContractError::new(
                    "read_unknown_authority_mismatch",
                    "body.terminalEvidence.payload",
                    "read uncertainty forbids a write recovery seal and must preserve exact authority roots",
                ));
            }
            let dispatch = dispatch.ok_or_else(|| {
                ContractError::new(
                    "missing_dispatch_evidence",
                    "body.dispatchEvidence",
                    "read transition uncertainty requires dispatch evidence",
                )
            })?;
            require_equal_digest(
                dispatch_evidence_sha256,
                &dispatch.wire().evidence_sha256,
                "body.terminalEvidence.payload.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                &dispatch.wire().evidence_sha256,
                wire.predecessor_evidence_sha256.as_deref(),
                "body.terminalEvidence.predecessorEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "read transition uncertainty requires exact staged bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.terminalEvidence.payload.stagedRequestSha256",
            )?;
            require_equal_digest(
                dispatch_authorization_binding_sha256,
                &staged.dispatch_authorization_binding_sha256,
                "body.terminalEvidence.payload.dispatchAuthorizationBindingSha256",
            )?;
            require_equal_digest(
                retry_binding_sha256,
                route_read_retry_binding(&body.route_semantics)?,
                "body.terminalEvidence.payload.retryBindingSha256",
            )?;
            let target_unknown_at = match &body.target_egress {
                TargetEgressState::ReadOutcomeUnknown {
                    unknown_at_epoch_ms,
                    ..
                } => *unknown_at_epoch_ms,
                _ => 0,
            };
            if *unknown_at_epoch_ms != target_unknown_at {
                return Err(ContractError::new(
                    "unknown_transition_time_mismatch",
                    "body.terminalEvidence.payload.unknownAtEpochMs",
                    "read terminal uncertainty time must equal target-egress uncertainty time",
                ));
            }
        }
    }
    Ok(())
}

fn verify_evidence<P: EvidencePayload, V: EvidenceSignatureVerifier>(
    wire: SignedEvidence<P>,
    context: &VerificationContext<'_>,
    verifier: &V,
) -> ContractResult<VerifiedEvidence<P>> {
    let evidence_role = wire.payload.evidence_role();
    let payload_domain = wire.payload.payload_domain();
    let signature_domain = wire.payload.signature_domain();
    if wire.api_version != EVIDENCE_API_VERSION
        || wire.evidence_type != P::EVIDENCE_TYPE
        || wire.signature_domain != signature_domain
        || wire.signature_algorithm != SignatureAlgorithm::Ed25519
    {
        return Err(ContractError::new(
            "wrong_evidence_contract",
            "evidence",
            "evidence version, type, signature domain, or algorithm is invalid",
        ));
    }
    wire.payload.validate_payload()?;
    validate_attempt_id(wire.payload.attempt_id())?;
    validate_digest(&wire.payload_sha256, "evidence.payloadSha256")?;
    validate_digest(&wire.key_id, "evidence.keyId")?;
    validate_signature(&wire.signature)?;
    validate_safe_time(wire.issued_at_epoch_ms, "evidence.issuedAtEpochMs")?;
    validate_safe_time(wire.expires_at_epoch_ms, "evidence.expiresAtEpochMs")?;
    if wire.expires_at_epoch_ms <= wire.issued_at_epoch_ms
        || wire.expires_at_epoch_ms - wire.issued_at_epoch_ms > MAX_EVIDENCE_TTL_MS
        || wire.issued_at_epoch_ms
            > context
                .trusted_now_epoch_ms()
                .saturating_add(MAX_CLOCK_SKEW_MS)
        || context.trusted_now_epoch_ms() > wire.expires_at_epoch_ms
        || wire.payload.action_epoch_ms() < wire.issued_at_epoch_ms
        || wire.payload.action_epoch_ms() > wire.expires_at_epoch_ms
        || wire.payload.action_epoch_ms()
            > context
                .trusted_now_epoch_ms()
                .saturating_add(MAX_CLOCK_SKEW_MS)
    {
        return Err(ContractError::new(
            "evidence_outside_validity_window",
            "evidence",
            "evidence issue, action, expiry, or verifier time is inconsistent",
        ));
    }
    validate_runtime(&wire.boot_runtime_identity)?;
    if &wire.boot_runtime_identity != context.expected_runtime().identity() {
        return Err(ContractError::new(
            "runtime_binding_mismatch",
            "evidence.bootRuntimeIdentity",
            "evidence runtime does not match the verifier-pinned runtime",
        ));
    }
    if let Some(predecessor) = wire.predecessor_evidence_sha256.as_deref() {
        validate_digest(predecessor, "evidence.predecessorEvidenceSha256")?;
    }
    validate_digest(&wire.evidence_sha256, "evidence.evidenceSha256")?;

    let payload_jcs = canonical_jcs_bytes(&wire.payload)?;
    let expected_payload =
        domain_sha256(payload_domain, &[payload_jcs.as_slice()])?;
    if wire.payload_sha256 != expected_payload {
        return Err(ContractError::new(
            "payload_digest_mismatch",
            "evidence.payloadSha256",
            "evidence payload digest does not match canonical typed payload",
        ));
    }

    let commitment = EvidenceSigningCommitment {
        api_version: &wire.api_version,
        evidence_type: wire.evidence_type,
        payload: &wire.payload,
        payload_sha256: &wire.payload_sha256,
        key_id: &wire.key_id,
        signature_domain: &wire.signature_domain,
        signature_algorithm: wire.signature_algorithm,
        issued_at_epoch_ms: wire.issued_at_epoch_ms,
        expires_at_epoch_ms: wire.expires_at_epoch_ms,
        boot_runtime_identity: &wire.boot_runtime_identity,
        predecessor_evidence_sha256: wire.predecessor_evidence_sha256.as_deref(),
    };
    let commitment_jcs = canonical_jcs_bytes(&commitment)?;
    let signing_message =
        domain_sha256_bytes(signature_domain, &[commitment_jcs.as_slice()])?;
    // Construct this only after the wire role, domain, and algorithm have been
    // checked against the sealed payload implementation above.
    let verified_runtime = context.expected_runtime();
    let credential_scope = wire.payload.credential_authority_scope();
    if (evidence_role == EvidenceRole::CredentialAuthority)
        != credential_scope.is_some()
    {
        return Err(ContractError::new(
            "credential_authority_scope_missing",
            "evidence.payload",
            "credential-authority evidence must expose exactly one authorityId and operation scope, and other evidence must expose none",
        ));
    }
    let purpose = EvidenceVerificationPurpose {
        verification_purpose: context.purpose(),
        evidence_type: P::EVIDENCE_TYPE,
        evidence_role,
        signature_domain,
        payload_domain,
        algorithm: SignatureAlgorithm::Ed25519,
        expected_runtime: verified_runtime.identity(),
        runtime_attestation_evidence_sha256: verified_runtime
            .attestation_evidence_sha256(),
        runtime_attestation_verifier_key_id: verified_runtime.verifier_key_id(),
        historical_checkpoint: context.archival_checkpoint(),
        artifact_checkpoint: None,
        credential_authority_id: credential_scope.map(|scope| scope.0),
        credential_authority_operation: credential_scope.map(|scope| scope.1),
    };
    let signature_verification = verifier.verify_role_scoped_ed25519(
        &purpose,
        &wire.key_id,
        signing_message.as_slice(),
        &wire.signature,
    );
    validate_digest(
        &signature_verification.pinned_trust_policy_sha256,
        "evidence.pinnedTrustPolicySha256",
    )?;
    validate_digest(
        &signature_verification.trust_checkpoint_sha256,
        "evidence.trustCheckpointSha256",
    )?;
    validate_digest(
        &signature_verification.key_material_sha256,
        "evidence.keyMaterialSha256",
    )?;
    validate_safe_integer(
        signature_verification.revocation_epoch,
        "evidence.revocationEpoch",
    )?;
    if let Some(revoked_at_epoch_ms) =
        signature_verification.revoked_at_epoch_ms
    {
        validate_safe_time(
            revoked_at_epoch_ms,
            "evidence.revokedAtEpochMs",
        )?;
    }
    let verified_scope = signature_verification
        .credential_authority_id
        .as_deref()
        .zip(signature_verification.credential_authority_operation);
    let historical_authority_valid =
        context.purpose() == VerificationPurpose::LiveAuthorization
            || (context.archival_checkpoint().is_some()
                && signature_verification
                    .historical_key_inclusion_verified
                && signature_verification
                    .historical_non_revocation_verified
                && context.archival_checkpoint().is_some_and(|checkpoint| {
                    signature_verification.pinned_trust_policy_sha256
                        == checkpoint.historical_trust_policy_sha256
                }));
    if !signature_verification.accepted
        || !historical_authority_valid
        || signature_verification.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || signature_verification.revocation_epoch
            != context.current_revocation_epoch()
        || verified_scope != credential_scope
    {
        return Err(ContractError::new(
            "evidence_signature_invalid",
            "evidence.signature",
            "evidence signature or pinned trust policy is not valid for the exact role, authorityId, operation, and preimage",
        ));
    }
    let expected_evidence = domain_sha256(
        EVIDENCE_ENVELOPE_DOMAIN,
        &[signing_message.as_slice(), wire.signature.as_bytes()],
    )?;
    if wire.evidence_sha256 != expected_evidence {
        return Err(ContractError::new(
            "evidence_digest_mismatch",
            "evidence.evidenceSha256",
            "evidence digest does not identify the exact signed envelope",
        ));
    }
    Ok(VerifiedEvidence {
        wire,
        pinned_trust_policy_sha256:
            signature_verification.pinned_trust_policy_sha256,
        trust_checkpoint_sha256:
            signature_verification.trust_checkpoint_sha256,
        revocation_epoch: signature_verification.revocation_epoch,
        key_material_sha256: signature_verification.key_material_sha256,
        revoked_at_epoch_ms:
            signature_verification.revoked_at_epoch_ms,
        _seal: VerifiedSeal,
    })
}

fn validate_finalized_identity(finalized: &FinalizedEnvelopeV2) -> ContractResult<()> {
    let identity = &finalized.identity;
    validate_attempt_id(&identity.attempt_id)?;
    if identity.attempt_id != finalized.body.attempt_id {
        return Err(ContractError::new(
            "attempt_binding_mismatch",
            "finalizedEnvelope.identity.attemptId",
            "final envelope identity must bind the body attemptId",
        ));
    }
    validate_digest(
        &identity.envelope_sha256,
        "finalizedEnvelope.identity.envelopeSha256",
    )?;
    validate_digest(
        &identity.retrieval_id,
        "finalizedEnvelope.identity.retrievalId",
    )?;
    validate_safe_time(
        identity.finalized_at_epoch_ms,
        "finalizedEnvelope.identity.finalizedAtEpochMs",
    )?;
    if identity.finalized_at_epoch_ms < finalized.body.issued_at_epoch_ms
        || identity.envelope_byte_length == 0
        || identity.envelope_byte_length > MAX_PROOF_BYTES as u64
        || !identity.bytes_immutable
        || !identity.replacement_prohibited
        || identity.canonicalization
            != CanonicalizationProfile::Rfc8785CatchplateV1
        || identity.retrieval_contract
            != RetrievalContract::ExactCanonicalEnvelopeBytes
    {
        return Err(ContractError::new(
            "invalid_finalization",
            "finalizedEnvelope.identity",
            "finalized identity does not establish immutable exact-byte retrieval",
        ));
    }
    let body_jcs = canonical_jcs_bytes(&finalized.body)?;
    let body_length = u64::try_from(body_jcs.len()).map_err(|_| {
        ContractError::new(
            "length_overflow",
            "finalizedEnvelope.identity.envelopeByteLength",
            "canonical envelope length cannot be represented",
        )
    })?;
    let body_digest = domain_sha256(FINAL_ENVELOPE_DOMAIN, &[body_jcs.as_slice()])?;
    if identity.envelope_byte_length != body_length
        || identity.envelope_sha256 != body_digest
    {
        return Err(ContractError::new(
            "finalized_envelope_identity_mismatch",
            "finalizedEnvelope.identity",
            "finalized identity does not identify the exact canonical envelope bytes",
        ));
    }
    let expected_retrieval = retrieval_id(&identity.attempt_id, &body_digest)?;
    if identity.retrieval_id != expected_retrieval {
        return Err(ContractError::new(
            "retrieval_identity_mismatch",
            "finalizedEnvelope.identity.retrievalId",
            "retrieval identity is not bound to the one attempt and envelope digest",
        ));
    }
    Ok(())
}

fn validate_persistence_binding(
    finalized: &FinalizedEnvelopeV2,
    evidence: &SignedEvidence<PersistenceEvidencePayload>,
) -> ContractResult<()> {
    let identity = &finalized.identity;
    let payload = &evidence.payload;
    if payload.attempt_id != identity.attempt_id
        || payload.envelope_sha256 != identity.envelope_sha256
        || payload.envelope_byte_length != identity.envelope_byte_length
        || payload.retrieval_id != identity.retrieval_id
        || payload.terminal_evidence_sha256
            != finalized.body.terminal_evidence.evidence_sha256
        || payload.persisted_at_epoch_ms != identity.finalized_at_epoch_ms
        || !payload.immutable
        || evidence.predecessor_evidence_sha256.as_deref()
            != Some(finalized.body.terminal_evidence.evidence_sha256.as_str())
    {
        return Err(ContractError::new(
            "persistence_binding_mismatch",
            "finalizedEnvelope.persistenceEvidence",
            "persistence evidence does not bind the exact immutable finalized envelope",
        ));
    }
    Ok(())
}

fn verify_exact_persisted_envelope<P: ExactBytePersistenceVerifier>(
    finalized: &FinalizedEnvelopeV2,
    verifier: &P,
) -> ContractResult<()> {
    let identity = &finalized.identity;
    let retrieved = verifier.retrieve_exact_envelope(&identity.retrieval_id)?;
    if retrieved.attempt_id != identity.attempt_id
        || retrieved.retrieval_id != identity.retrieval_id
        || retrieved.persistence_receipt_sha256
            != finalized
                .persistence_evidence
                .payload
                .persistence_receipt_sha256
        || retrieved.retrieval_proof_sha256
            != finalized
                .persistence_evidence
                .payload
                .retrieval_proof_sha256
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.canonical_bytes.is_empty()
        || retrieved.canonical_bytes.len() > MAX_PROOF_BYTES
    {
        return Err(ContractError::new(
            "retrieved_envelope_authority_mismatch",
            "finalizedEnvelope.identity",
            "trusted retrieval did not return the immutable object for the exact attempt",
        ));
    }
    validate_digest(
        &retrieved.persistence_receipt_sha256,
        "finalizedEnvelope.persistenceEvidence.payload.persistenceReceiptSha256",
    )?;
    validate_digest(
        &retrieved.retrieval_proof_sha256,
        "finalizedEnvelope.persistenceEvidence.payload.retrievalProofSha256",
    )?;
    let expected = canonical_jcs_bytes(&finalized.body)?;
    if retrieved.canonical_bytes != expected {
        return Err(ContractError::new(
            "retrieved_envelope_bytes_mismatch",
            "finalizedEnvelope.identity.retrievalId",
            "retrieved bytes are not the exact canonical finalized envelope bytes",
        ));
    }
    let retrieved_length = u64::try_from(retrieved.canonical_bytes.len()).map_err(|_| {
        ContractError::new(
            "length_overflow",
            "finalizedEnvelope.identity.envelopeByteLength",
            "retrieved canonical envelope length cannot be represented",
        )
    })?;
    let retrieved_digest =
        domain_sha256(FINAL_ENVELOPE_DOMAIN, &[retrieved.canonical_bytes.as_slice()])?;
    if retrieved_length != identity.envelope_byte_length
        || retrieved_digest != identity.envelope_sha256
    {
        return Err(ContractError::new(
            "retrieved_envelope_identity_mismatch",
            "finalizedEnvelope.identity",
            "trusted retrieval bytes do not match the immutable digest and byte length",
        ));
    }
    Ok(())
}

fn validate_finalization_checkpoint_binding(
    finalized: &FinalizedEnvelopeV2,
    persistence: &SignedEvidence<PersistenceEvidencePayload>,
    checkpoint:
        &VerifiedEvidence<FinalizationCheckpointEvidencePayload>,
    context: &VerificationContext<'_>,
) -> ContractResult<()> {
    let identity = &finalized.identity;
    let wire = checkpoint.wire();
    let payload = &wire.payload;
    if payload.attempt_id != identity.attempt_id
        || payload.retrieval_id != identity.retrieval_id
        || payload.envelope_sha256 != identity.envelope_sha256
        || payload.envelope_byte_length != identity.envelope_byte_length
        || payload.terminal_evidence_sha256
            != finalized.body.terminal_evidence.evidence_sha256
        || payload.persistence_evidence_sha256
            != persistence.evidence_sha256
        || payload.finalized_at_epoch_ms != identity.finalized_at_epoch_ms
        || payload.trusted_time_epoch_ms != identity.finalized_at_epoch_ms
        || payload.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || payload.revocation_epoch != context.current_revocation_epoch()
        || payload.historical_trust_policy_sha256
            != checkpoint.pinned_trust_policy_sha256
        || payload.runtime_attestation_evidence_sha256
            != context
                .expected_runtime()
                .attestation_evidence_sha256()
        || payload.runtime_attestation_verifier_key_id
            != context.expected_runtime().verifier_key_id()
        || payload.runtime_measurement_sha256
            != finalized.body.runtime.runtime_measurement_sha256
        || payload.immutable_persistence_receipt_sha256
            != persistence.payload.persistence_receipt_sha256
        || payload.exact_retrieval_proof_sha256
            != persistence.payload.retrieval_proof_sha256
        || wire.predecessor_evidence_sha256.as_deref()
            != Some(persistence.evidence_sha256.as_str())
    {
        return Err(ContractError::new(
            "finalization_checkpoint_binding_mismatch",
            "finalizedEnvelope.finalizationCheckpointEvidence",
            "signed finalization checkpoint must bind the exact persisted envelope, terminal and persistence evidence, trusted finalization time, historical trust/revocation proofs, runtime attestation, and immutable retrieval evidence",
        ));
    }
    match context.purpose() {
        VerificationPurpose::LiveAuthorization => {
            if identity.finalized_at_epoch_ms
                    > context.trusted_delivery_time_epoch_ms()
                || context
                    .trusted_delivery_time_epoch_ms()
                    .saturating_sub(identity.finalized_at_epoch_ms)
                    > MAX_PROOF_AGE_MS
            {
                return Err(ContractError::new(
                    "live_finalization_not_fresh",
                    "finalizedEnvelope.identity.finalizedAtEpochMs",
                    "LIVE_AUTHORIZATION requires a current bounded finalization and current trust/revocation checkpoint",
                ));
            }
        }
        VerificationPurpose::ArchivalVerification => {
            if context.archival_checkpoint() != Some(payload) {
                return Err(ContractError::new(
                    "archival_checkpoint_not_exact",
                    "finalizedEnvelope.finalizationCheckpointEvidence.payload",
                    "ARCHIVAL_VERIFICATION context must equal the separately signed finalization checkpoint byte-for-byte",
                ));
            }
        }
    }
    Ok(())
}

fn validate_attestation_and_publication<
    E: EvidenceSignatureVerifier,
    A: FinalizationArtifactVerifier,
>(
    attestation: &AttestationState,
    publication: &PublicationState,
    identity: &FinalizedEnvelopeIdentity,
    runtime: &BootRuntimeIdentity,
    finalization_checkpoint:
        &VerifiedEvidence<FinalizationCheckpointEvidencePayload>,
    context: &VerificationContext<'_>,
    evidence_verifier: &E,
    artifact_verifier: &A,
) -> ContractResult<()> {
    let trusted_now_epoch_ms = context.trusted_delivery_time_epoch_ms();
    let (
        att_attempt,
        att_retrieval,
        att_envelope,
        att_time,
        attestation_artifact,
        attestation_checkpoint,
    ) =
        match attestation {
            AttestationState::NotAttempted {
                attempt_id,
                retrieval_id,
                envelope_sha256,
            } => (
                attempt_id,
                retrieval_id,
                envelope_sha256,
                None,
                None,
                None,
            ),
            AttestationState::Succeeded {
                attempt_id,
                retrieval_id,
                envelope_sha256,
                attestation_sha256,
                attested_at_epoch_ms,
                artifact_time_checkpoint_evidence,
            } => {
                validate_digest(
                    attestation_sha256,
                    "attestation.attestationSha256",
                )?;
                (
                    attempt_id,
                    retrieval_id,
                    envelope_sha256,
                    Some(*attested_at_epoch_ms),
                    Some(attestation_sha256.as_str()),
                    Some(artifact_time_checkpoint_evidence),
                )
            }
            AttestationState::Failed {
                attempt_id,
                retrieval_id,
                envelope_sha256,
                failed_at_epoch_ms,
                ..
            } => (
                attempt_id,
                retrieval_id,
                envelope_sha256,
                Some(*failed_at_epoch_ms),
                None,
                None,
            ),
        };
    require_publication_identity(
        att_attempt,
        att_retrieval,
        att_envelope,
        identity,
        "attestation",
    )?;
    if let Some(time) = att_time {
        validate_post_finalization_time(
            time,
            identity.finalized_at_epoch_ms,
            trusted_now_epoch_ms,
            "attestation",
        )?;
    }
    if let (Some(time), Some(artifact_sha256), Some(checkpoint_wire)) =
        (
            att_time,
            attestation_artifact,
            attestation_checkpoint,
        )
    {
        let checkpoint = verify_artifact_time_checkpoint_evidence(
            checkpoint_wire.clone(),
            FinalizationArtifactRole::EnvelopeAttestation,
            artifact_sha256,
            None,
            None,
            time,
            identity,
            runtime,
            finalization_checkpoint,
            context,
            evidence_verifier,
        )?;
        let purpose = FinalizationArtifactVerificationPurpose {
            verification_purpose: context.purpose(),
            role: FinalizationArtifactRole::EnvelopeAttestation,
            artifact_sha256,
            prerequisite_attestation_sha256: None,
            attempt_id: &identity.attempt_id,
            retrieval_id: &identity.retrieval_id,
            envelope_sha256: &identity.envelope_sha256,
            occurred_at_epoch_ms: time,
            expected_runtime: context.expected_runtime().identity(),
            runtime_attestation_evidence_sha256: context
                .expected_runtime()
                .attestation_evidence_sha256(),
            runtime_attestation_verifier_key_id: context
                .expected_runtime()
                .verifier_key_id(),
            finalization_checkpoint:
                &finalization_checkpoint.wire().payload,
            artifact_time_checkpoint: &checkpoint.wire().payload,
            artifact_time_checkpoint_evidence_sha256:
                &checkpoint.wire().evidence_sha256,
        };
        validate_finalization_artifact_verification(
            artifact_verifier.verify_finalization_artifact(&purpose),
            &checkpoint.wire().payload,
            "attestation",
        )?;
    } else if attestation_artifact.is_some()
        || attestation_checkpoint.is_some()
    {
        return Err(ContractError::new(
            "attestation_artifact_checkpoint_missing",
            "attestation",
            "successful attestation requires one non-null artifact-time checkpoint and other branches forbid it",
        ));
    }

    let (
        pub_attempt,
        pub_retrieval,
        pub_envelope,
        pub_time,
        published,
        publication_artifact,
        publication_checkpoint,
    ) = match publication {
        PublicationState::NotAttempted {
            attempt_id,
            retrieval_id,
            envelope_sha256,
        } => (
            attempt_id,
            retrieval_id,
            envelope_sha256,
            None,
            false,
            None,
            None,
        ),
        PublicationState::Published {
            attempt_id,
            retrieval_id,
            envelope_sha256,
            publication_receipt_sha256,
            published_at_epoch_ms,
            artifact_time_checkpoint_evidence,
        } => {
            validate_digest(
                publication_receipt_sha256,
                "publication.publicationReceiptSha256",
            )?;
            (
                attempt_id,
                retrieval_id,
                envelope_sha256,
                Some(*published_at_epoch_ms),
                true,
                Some(publication_receipt_sha256.as_str()),
                Some(artifact_time_checkpoint_evidence),
            )
        }
        PublicationState::Failed {
            attempt_id,
            retrieval_id,
            envelope_sha256,
            failed_at_epoch_ms,
            ..
        } => (
            attempt_id,
            retrieval_id,
            envelope_sha256,
            Some(*failed_at_epoch_ms),
            false,
            None,
            None,
        ),
    };
    require_publication_identity(
        pub_attempt,
        pub_retrieval,
        pub_envelope,
        identity,
        "publication",
    )?;
    if let Some(time) = pub_time {
        validate_post_finalization_time(
            time,
            identity.finalized_at_epoch_ms,
            trusted_now_epoch_ms,
            "publication",
        )?;
        if let Some(attested) = att_time {
            if time < attested {
                return Err(ContractError::new(
                    "publication_before_attestation",
                    "publication",
                    "publication cannot precede its attestation attempt",
                ));
            }
        }
    }
    if published && attestation_artifact.is_none() {
        return Err(ContractError::new(
            "publication_without_attestation",
            "publication",
            "published state requires successful attestation of the same envelope",
        ));
    }
    if let (
        Some(time),
        Some(artifact_sha256),
        Some(checkpoint_wire),
    ) = (
        pub_time,
        publication_artifact,
        publication_checkpoint,
    ) {
        let checkpoint = verify_artifact_time_checkpoint_evidence(
            checkpoint_wire.clone(),
            FinalizationArtifactRole::PublicationReceipt,
            artifact_sha256,
            attestation_artifact,
            attestation_checkpoint
                .map(|value| value.evidence_sha256.as_str()),
            time,
            identity,
            runtime,
            finalization_checkpoint,
            context,
            evidence_verifier,
        )?;
        let purpose = FinalizationArtifactVerificationPurpose {
            verification_purpose: context.purpose(),
            role: FinalizationArtifactRole::PublicationReceipt,
            artifact_sha256,
            prerequisite_attestation_sha256: attestation_artifact,
            attempt_id: &identity.attempt_id,
            retrieval_id: &identity.retrieval_id,
            envelope_sha256: &identity.envelope_sha256,
            occurred_at_epoch_ms: time,
            expected_runtime: context.expected_runtime().identity(),
            runtime_attestation_evidence_sha256: context
                .expected_runtime()
                .attestation_evidence_sha256(),
            runtime_attestation_verifier_key_id: context
                .expected_runtime()
                .verifier_key_id(),
            finalization_checkpoint:
                &finalization_checkpoint.wire().payload,
            artifact_time_checkpoint: &checkpoint.wire().payload,
            artifact_time_checkpoint_evidence_sha256:
                &checkpoint.wire().evidence_sha256,
        };
        validate_finalization_artifact_verification(
            artifact_verifier.verify_finalization_artifact(&purpose),
            &checkpoint.wire().payload,
            "publication",
        )?;
    } else if publication_artifact.is_some()
        || publication_checkpoint.is_some()
    {
        return Err(ContractError::new(
            "publication_artifact_checkpoint_missing",
            "publication",
            "published receipt requires one non-null artifact-time checkpoint and other branches forbid it",
        ));
    }
    if matches!(attestation, AttestationState::NotAttempted { .. })
        && !matches!(publication, PublicationState::NotAttempted { .. })
    {
        return Err(ContractError::new(
            "publication_without_attestation_attempt",
            "publication",
            "publication cannot be attempted before attestation",
        ));
    }
    let _ = published;
    Ok(())
}

fn validate_finalization_artifact_verification(
    verification: FinalizationArtifactVerification,
    checkpoint: &ArtifactTimeCheckpointEvidencePayload,
    path: &'static str,
) -> ContractResult<()> {
    validate_digest(
        &verification.artifact_signing_key_id,
        "artifactVerification.artifactSigningKeyId",
    )?;
    validate_digest(
        &verification.trust_checkpoint_sha256,
        "artifactVerification.trustCheckpointSha256",
    )?;
    validate_digest(
        &verification.historical_trust_policy_sha256,
        "artifactVerification.historicalTrustPolicySha256",
    )?;
    validate_safe_integer(
        verification.revocation_epoch,
        "artifactVerification.revocationEpoch",
    )?;
    if let Some(revoked_at_epoch_ms) = verification.revoked_at_epoch_ms {
        validate_safe_time(
            revoked_at_epoch_ms,
            "artifactVerification.revokedAtEpochMs",
        )?;
    }
    if !verification.accepted
        || verification.artifact_signing_key_id
            != checkpoint.artifact_signing_key_id
        || verification.trust_checkpoint_sha256
            != checkpoint.trust_checkpoint_sha256
        || verification.revocation_epoch != checkpoint.revocation_epoch
        || verification.historical_trust_policy_sha256
            != checkpoint.historical_trust_policy_sha256
        || !verification.historical_key_inclusion_verified
        || !verification.historical_non_revocation_verified
        || !verification.runtime_attestation_inclusion_verified
        || !verification.immutable_artifact_retrieval_verified
        || !verification.artifact_key_valid_at_timestamp
        || verification
            .revoked_at_epoch_ms
            .is_some_and(|revoked_at| {
                revoked_at <= checkpoint.artifact_at_epoch_ms
            })
    {
        return Err(ContractError::new(
            "finalization_artifact_historical_authority_invalid",
            path,
            "artifact verification must prove the exact artifact key, trust policy, runtime inclusion, and non-revocation at the artifact timestamp; revocation at or before that timestamp is fatal",
        ));
    }
    Ok(())
}

fn verify_artifact_time_checkpoint_evidence<
    V: EvidenceSignatureVerifier,
>(
    wire: SignedEvidence<ArtifactTimeCheckpointEvidencePayload>,
    expected_role: FinalizationArtifactRole,
    expected_artifact_sha256: &str,
    expected_prerequisite_attestation_sha256: Option<&str>,
    expected_prerequisite_artifact_time_checkpoint_evidence_sha256:
        Option<&str>,
    expected_artifact_at_epoch_ms: u64,
    identity: &FinalizedEnvelopeIdentity,
    runtime: &BootRuntimeIdentity,
    finalization_checkpoint:
        &VerifiedEvidence<FinalizationCheckpointEvidencePayload>,
    context: &VerificationContext<'_>,
    verifier: &V,
) -> ContractResult<
    VerifiedEvidence<ArtifactTimeCheckpointEvidencePayload>,
> {
    let payload = &wire.payload;
    if wire.api_version != EVIDENCE_API_VERSION
        || wire.evidence_type != EvidenceType::ArtifactTimeCheckpoint
        || wire.signature_domain
            != "catchplate.response-observation-v2/artifact-time-checkpoint-signature"
        || wire.signature_algorithm != SignatureAlgorithm::Ed25519
    {
        return Err(ContractError::new(
            "wrong_artifact_time_checkpoint_contract",
            "artifactTimeCheckpointEvidence",
            "artifact-time checkpoint version, type, domain, or algorithm is invalid",
        ));
    }
    validate_artifact_time_checkpoint_payload(payload)?;
    validate_digest(
        &wire.payload_sha256,
        "artifactTimeCheckpointEvidence.payloadSha256",
    )?;
    validate_digest(
        &wire.key_id,
        "artifactTimeCheckpointEvidence.keyId",
    )?;
    validate_signature(&wire.signature)?;
    validate_digest(
        &wire.evidence_sha256,
        "artifactTimeCheckpointEvidence.evidenceSha256",
    )?;
    validate_safe_time(
        wire.issued_at_epoch_ms,
        "artifactTimeCheckpointEvidence.issuedAtEpochMs",
    )?;
    validate_safe_time(
        wire.expires_at_epoch_ms,
        "artifactTimeCheckpointEvidence.expiresAtEpochMs",
    )?;
    if payload.attempt_id != identity.attempt_id
        || payload.retrieval_id != identity.retrieval_id
        || payload.envelope_sha256 != identity.envelope_sha256
        || payload.artifact_role != expected_role
        || payload.artifact_sha256 != expected_artifact_sha256
        || payload.prerequisite_attestation_sha256.as_deref()
            != expected_prerequisite_attestation_sha256
        || payload
            .prerequisite_artifact_time_checkpoint_evidence_sha256
            .as_deref()
            != expected_prerequisite_artifact_time_checkpoint_evidence_sha256
        || payload.finalized_at_epoch_ms != identity.finalized_at_epoch_ms
        || payload.artifact_at_epoch_ms != expected_artifact_at_epoch_ms
        || payload.finalization_checkpoint_evidence_sha256
            != finalization_checkpoint.wire().evidence_sha256
        || payload.runtime_attestation_evidence_sha256
            != context
                .expected_runtime()
                .attestation_evidence_sha256()
        || payload.runtime_attestation_verifier_key_id
            != context.expected_runtime().verifier_key_id()
        || payload.runtime_measurement_sha256
            != runtime.runtime_measurement_sha256
        || wire.boot_runtime_identity != *runtime
        || wire.predecessor_evidence_sha256.as_deref()
            != Some(
                finalization_checkpoint
                    .wire()
                    .evidence_sha256
                    .as_str(),
            )
        || wire.issued_at_epoch_ms > payload.artifact_at_epoch_ms
        || payload.artifact_at_epoch_ms >= wire.expires_at_epoch_ms
        || wire.expires_at_epoch_ms <= wire.issued_at_epoch_ms
        || wire.expires_at_epoch_ms - wire.issued_at_epoch_ms
            > MAX_EVIDENCE_TTL_MS
        || payload.artifact_at_epoch_ms
            > context.trusted_delivery_time_epoch_ms()
    {
        return Err(ContractError::new(
            "artifact_time_checkpoint_binding_mismatch",
            "artifactTimeCheckpointEvidence",
            "artifact-time checkpoint must bind the exact finalized object, artifact role/digest/time, prerequisite, runtime inclusion, finalization checkpoint, and bounded signature window",
        ));
    }
    let payload_jcs = canonical_jcs_bytes(payload)?;
    let expected_payload = domain_sha256(
        "catchplate.response-observation-v2/artifact-time-checkpoint-payload",
        &[payload_jcs.as_slice()],
    )?;
    if wire.payload_sha256 != expected_payload {
        return Err(ContractError::new(
            "artifact_time_checkpoint_payload_digest_mismatch",
            "artifactTimeCheckpointEvidence.payloadSha256",
            "artifact-time checkpoint payload digest does not match canonical typed bytes",
        ));
    }
    let commitment = EvidenceSigningCommitment {
        api_version: &wire.api_version,
        evidence_type: wire.evidence_type,
        payload,
        payload_sha256: &wire.payload_sha256,
        key_id: &wire.key_id,
        signature_domain: &wire.signature_domain,
        signature_algorithm: wire.signature_algorithm,
        issued_at_epoch_ms: wire.issued_at_epoch_ms,
        expires_at_epoch_ms: wire.expires_at_epoch_ms,
        boot_runtime_identity: &wire.boot_runtime_identity,
        predecessor_evidence_sha256:
            wire.predecessor_evidence_sha256.as_deref(),
    };
    let commitment_jcs = canonical_jcs_bytes(&commitment)?;
    let signing_message = domain_sha256_bytes(
        "catchplate.response-observation-v2/artifact-time-checkpoint-signature",
        &[commitment_jcs.as_slice()],
    )?;
    let purpose = EvidenceVerificationPurpose {
        verification_purpose: VerificationPurpose::ArchivalVerification,
        evidence_type: EvidenceType::ArtifactTimeCheckpoint,
        evidence_role: EvidenceRole::ArtifactTimeCheckpoint,
        signature_domain:
            "catchplate.response-observation-v2/artifact-time-checkpoint-signature",
        payload_domain:
            "catchplate.response-observation-v2/artifact-time-checkpoint-payload",
        algorithm: SignatureAlgorithm::Ed25519,
        expected_runtime: runtime,
        runtime_attestation_evidence_sha256:
            &payload.runtime_attestation_evidence_sha256,
        runtime_attestation_verifier_key_id:
            &payload.runtime_attestation_verifier_key_id,
        historical_checkpoint:
            Some(&finalization_checkpoint.wire().payload),
        artifact_checkpoint: Some(payload),
        credential_authority_id: None,
        credential_authority_operation: None,
    };
    let signature_verification = verifier.verify_role_scoped_ed25519(
        &purpose,
        &wire.key_id,
        signing_message.as_slice(),
        &wire.signature,
    );
    validate_digest(
        &signature_verification.pinned_trust_policy_sha256,
        "artifactTimeCheckpointEvidence.pinnedTrustPolicySha256",
    )?;
    validate_digest(
        &signature_verification.trust_checkpoint_sha256,
        "artifactTimeCheckpointEvidence.trustCheckpointSha256",
    )?;
    validate_digest(
        &signature_verification.key_material_sha256,
        "artifactTimeCheckpointEvidence.keyMaterialSha256",
    )?;
    validate_safe_integer(
        signature_verification.revocation_epoch,
        "artifactTimeCheckpointEvidence.revocationEpoch",
    )?;
    if let Some(revoked_at_epoch_ms) =
        signature_verification.revoked_at_epoch_ms
    {
        validate_safe_time(
            revoked_at_epoch_ms,
            "artifactTimeCheckpointEvidence.revokedAtEpochMs",
        )?;
    }
    if !signature_verification.accepted
        || !signature_verification.historical_key_inclusion_verified
        || !signature_verification.historical_non_revocation_verified
        || signature_verification.pinned_trust_policy_sha256
            != payload.historical_trust_policy_sha256
        || signature_verification.trust_checkpoint_sha256
            != payload.trust_checkpoint_sha256
        || signature_verification.revocation_epoch
            != payload.revocation_epoch
        || signature_verification
            .revoked_at_epoch_ms
            .is_some_and(|revoked_at| {
                revoked_at <= payload.artifact_at_epoch_ms
            })
        || signature_verification.credential_authority_id.is_some()
        || signature_verification
            .credential_authority_operation
            .is_some()
    {
        return Err(ContractError::new(
            "artifact_time_checkpoint_historical_signature_invalid",
            "artifactTimeCheckpointEvidence.signature",
            "checkpoint signer must be historically included and non-revoked under the exact artifact-time trust policy; revocation at or before artifact time is fatal",
        ));
    }
    let expected_evidence = domain_sha256(
        EVIDENCE_ENVELOPE_DOMAIN,
        &[signing_message.as_slice(), wire.signature.as_bytes()],
    )?;
    if wire.evidence_sha256 != expected_evidence {
        return Err(ContractError::new(
            "artifact_time_checkpoint_evidence_digest_mismatch",
            "artifactTimeCheckpointEvidence.evidenceSha256",
            "artifact-time checkpoint digest does not identify the exact signed envelope",
        ));
    }
    Ok(VerifiedEvidence {
        wire,
        pinned_trust_policy_sha256:
            signature_verification.pinned_trust_policy_sha256,
        trust_checkpoint_sha256:
            signature_verification.trust_checkpoint_sha256,
        revocation_epoch: signature_verification.revocation_epoch,
        key_material_sha256: signature_verification.key_material_sha256,
        revoked_at_epoch_ms: signature_verification.revoked_at_epoch_ms,
        _seal: VerifiedSeal,
    })
}

fn validate_nonce(nonce: &NonceBinding, trusted_now_epoch_ms: u64) -> ContractResult<()> {
    validate_base64url_32(&nonce.client_nonce, "body.nonce.clientNonce")?;
    validate_digest(&nonce.nonce_sha256, "body.nonce.nonceSha256")?;
    validate_safe_time(nonce.issued_at_epoch_ms, "body.nonce.issuedAtEpochMs")?;
    validate_safe_time(nonce.expires_at_epoch_ms, "body.nonce.expiresAtEpochMs")?;
    if nonce.expires_at_epoch_ms <= nonce.issued_at_epoch_ms
        || nonce.expires_at_epoch_ms - nonce.issued_at_epoch_ms > MAX_PROOF_AGE_MS
        || nonce.issued_at_epoch_ms
            > trusted_now_epoch_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || trusted_now_epoch_ms > nonce.expires_at_epoch_ms
    {
        return Err(ContractError::new(
            "nonce_outside_validity_window",
            "body.nonce",
            "nonce issue, expiry, or verifier time is inconsistent",
        ));
    }
    let expected = domain_sha256(NONCE_DIGEST_DOMAIN, &[nonce.client_nonce.as_bytes()])?;
    require_equal_digest(
        &nonce.nonce_sha256,
        &expected,
        "body.nonce.nonceSha256",
    )
}

fn validate_policy(policy: &PolicyBinding) -> ContractResult<()> {
    match policy {
        PolicyBinding::Denied {
            policy_sha256,
            snapshot_epoch,
            request_sha256,
            operation_sha256,
            principal_id,
            route_id,
            ..
        } => {
            validate_policy_common(
                policy_sha256,
                *snapshot_epoch,
                request_sha256,
                operation_sha256,
            )?;
            if let Some(value) = principal_id {
                validate_identifier(value, "body.policy.principalId")?;
            }
            if let Some(value) = route_id {
                validate_identifier(value, "body.policy.routeId")?;
            }
        }
        PolicyBinding::Allowed {
            policy_sha256,
            snapshot_epoch,
            request_sha256,
            operation_sha256,
            principal_id,
            route_id,
            credential_mode,
            credential_identity,
            valid_from_epoch_ms,
            valid_until_epoch_ms,
            prerequisites,
            ..
        } => {
            validate_policy_common(
                policy_sha256,
                *snapshot_epoch,
                request_sha256,
                operation_sha256,
            )?;
            validate_identifier(principal_id, "body.policy.principalId")?;
            validate_identifier(route_id, "body.policy.routeId")?;
            validate_safe_time(
                *valid_from_epoch_ms,
                "body.policy.validFromEpochMs",
            )?;
            validate_safe_time(
                *valid_until_epoch_ms,
                "body.policy.validUntilEpochMs",
            )?;
            if valid_until_epoch_ms <= valid_from_epoch_ms
                || valid_until_epoch_ms - valid_from_epoch_ms
                    > MAX_EVIDENCE_TTL_MS
            {
                return Err(ContractError::new(
                    "invalid_policy_validity_window",
                    "body.policy",
                    "allowed policy freshness must use one positive bounded validity window",
                ));
            }
            validate_policy_prerequisites(prerequisites)?;
            validate_policy_credential_identity(
                *credential_mode,
                credential_identity.as_ref(),
                &prerequisites.authority_plan,
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyCredentialIdentityCommitment<'a> {
    provider_id: &'a str,
    account_id: &'a str,
    credential_ref: &'a str,
    credential_version: u64,
    credential_generation: u64,
    local_acquisition_uncertain_side_effect:
        Option<&'a LocalAcquisitionUncertainSideEffect>,
}

fn validate_policy_credential_identity(
    mode: PolicyCredentialMode,
    identity: Option<&PolicyCredentialIdentity>,
    authority_plan: &AuthorityPrerequisitePlan,
) -> ContractResult<()> {
    let identity = match (mode, identity) {
        (PolicyCredentialMode::Required, Some(identity)) => identity,
        (
            PolicyCredentialMode::NotRequiredReadOnly
            | PolicyCredentialMode::NotRequiredCredentialless,
            None,
        ) => return Ok(()),
        _ => {
            return Err(ContractError::new(
                "policy_credential_identity_shape",
                "body.policy.credentialIdentity",
                "required credential policy needs one exact identity; no-credential policy forbids one",
            ))
        }
    };
    for (value, path) in [
        (&identity.provider_id, "body.policy.credentialIdentity.providerId"),
        (&identity.account_id, "body.policy.credentialIdentity.accountId"),
        (
            &identity.credential_ref,
            "body.policy.credentialIdentity.credentialRef",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    validate_safe_integer(
        identity.credential_version,
        "body.policy.credentialIdentity.credentialVersion",
    )?;
    validate_safe_integer(
        identity.credential_generation,
        "body.policy.credentialIdentity.credentialGeneration",
    )?;
    validate_digest(
        &identity.credential_binding_sha256,
        "body.policy.credentialIdentity.credentialBindingSha256",
    )?;
    if identity.credential_version == 0 || identity.credential_generation == 0 {
        return Err(ContractError::new(
            "policy_credential_identity_version",
            "body.policy.credentialIdentity",
            "credential version and generation must be positive",
        ));
    }
    let commitment = PolicyCredentialIdentityCommitment {
        provider_id: &identity.provider_id,
        account_id: &identity.account_id,
        credential_ref: &identity.credential_ref,
        credential_version: identity.credential_version,
        credential_generation: identity.credential_generation,
        local_acquisition_uncertain_side_effect: identity
            .local_acquisition_uncertain_side_effect
            .as_ref(),
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected = domain_sha256(
        POLICY_CREDENTIAL_BINDING_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &identity.credential_binding_sha256,
        &expected,
        "body.policy.credentialIdentity.credentialBindingSha256",
    )?;

    let credential_constraints: Vec<&AuthorityPrerequisiteConstraint> = authority_plan
        .primary_steps
        .iter()
        .chain(authority_plan.cleanup_steps.iter())
        .filter_map(|step| match &step.constraint {
            constraint @ AuthorityPrerequisiteConstraint::Credential { .. } => {
                Some(constraint)
            }
            _ => None,
        })
        .collect();
    let oauth_constraints: Vec<&AuthorityPrerequisiteConstraint> = authority_plan
        .primary_steps
        .iter()
        .chain(authority_plan.cleanup_steps.iter())
        .filter_map(|step| match &step.constraint {
            constraint @ AuthorityPrerequisiteConstraint::Oauth { .. } => {
                Some(constraint)
            }
            _ => None,
        })
        .collect();
    match identity.source {
        PolicyCredentialSource::LocalCredential
            if authority_plan.mode == AuthorityPlanMode::None
                && authority_plan.primary_steps.is_empty()
                && authority_plan.cleanup_steps.is_empty() => {}
        PolicyCredentialSource::AuthorityPlan
            if authority_plan.mode == AuthorityPlanMode::Required
                && identity
                    .local_acquisition_uncertain_side_effect
                    .is_none()
                && !credential_constraints.is_empty()
                && credential_constraints.iter().all(|constraint| {
                    matches!(
                        constraint,
                        AuthorityPrerequisiteConstraint::Credential {
                            provider_id,
                            account_id,
                            credential_ref,
                            credential_version,
                            credential_generation,
                            ..
                        } if provider_id == &identity.provider_id
                            && account_id == &identity.account_id
                            && credential_ref == &identity.credential_ref
                            && credential_version == &identity.credential_version
                            && credential_generation == &identity.credential_generation
                    )
                })
                && oauth_constraints.iter().all(|constraint| {
                    matches!(
                        constraint,
                        AuthorityPrerequisiteConstraint::Oauth {
                            provider_authority_id,
                            account_id,
                            credential_ref,
                            credential_version,
                            new_token_generation,
                            credential_binding_sha256,
                            ..
                        } if provider_authority_id == &identity.provider_id
                            && account_id == &identity.account_id
                            && credential_ref == &identity.credential_ref
                            && credential_version == &identity.credential_version
                            && new_token_generation == &identity.credential_generation
                            && credential_binding_sha256
                                == &identity.credential_binding_sha256
                    )
                }) => {}
        _ => {
            return Err(ContractError::new(
                "policy_credential_source_mismatch",
                "body.policy.credentialIdentity.source",
                "credential source must be either a local identity with an explicit empty authority plan or exact matching credential and OAuth prerequisites",
            ))
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityPrerequisiteStepCommitment<'a> {
    sequence: u8,
    authority_id: &'a str,
    operation: CredentialAuthorityOperation,
    constraint: &'a AuthorityPrerequisiteConstraint,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityPlanCommitment<'a> {
    mode: AuthorityPlanMode,
    primary_step_sha256: &'a [String],
    cleanup_step_sha256: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyPrerequisitesCommitment<'a> {
    authority_plan_sha256: &'a str,
    idempotency: &'a PolicyIdempotencyPrerequisite,
    response_validation: &'a PolicyResponseValidationPrerequisite,
}

fn validate_policy_prerequisites(
    prerequisites: &PolicyPrerequisites,
) -> ContractResult<()> {
    validate_authority_prerequisite_plan(&prerequisites.authority_plan)?;
    match &prerequisites.idempotency {
        PolicyIdempotencyPrerequisite::Required { provider_profile } => {
            validate_provider_idempotency_profile(provider_profile)?;
        }
        PolicyIdempotencyPrerequisite::NotRequired => {}
    }
    match &prerequisites.response_validation {
        PolicyResponseValidationPrerequisite::Required { profile } => {
            validate_response_policy_profile(profile)?;
        }
        PolicyResponseValidationPrerequisite::NotRequired => {}
    }
    validate_digest(
        &prerequisites.prerequisites_sha256,
        "body.policy.prerequisites.prerequisitesSha256",
    )?;
    let commitment = PolicyPrerequisitesCommitment {
        authority_plan_sha256: &prerequisites.authority_plan.plan_sha256,
        idempotency: &prerequisites.idempotency,
        response_validation: &prerequisites.response_validation,
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected = domain_sha256(
        AUTHORIZATION_BINDING_DOMAIN,
        &[b"policy-prerequisites", canonical.as_slice()],
    )?;
    require_equal_digest(
        &prerequisites.prerequisites_sha256,
        &expected,
        "body.policy.prerequisites.prerequisitesSha256",
    )
}

fn validate_authority_prerequisite_plan(
    plan: &AuthorityPrerequisitePlan,
) -> ContractResult<()> {
    if plan.mode == AuthorityPlanMode::None
        && (!plan.primary_steps.is_empty()
            || !plan.cleanup_steps.is_empty())
    {
        return Err(ContractError::new(
            "authority_plan_none_has_steps",
            "body.policy.prerequisites.authorityPlan",
            "mode none requires both primarySteps and cleanupSteps to be exactly empty",
        ));
    }
    if plan.primary_steps.len() + plan.cleanup_steps.len()
        > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(ContractError::new(
            "authority_plan_too_large",
            "body.policy.prerequisites.authorityPlan",
            "primary and cleanup branches exceed the closed authority evidence bound",
        ));
    }
    let shape_valid = match plan.mode {
        AuthorityPlanMode::None => true,
        AuthorityPlanMode::Required => !plan.primary_steps.is_empty(),
    };
    if !shape_valid {
        return Err(ContractError::new(
            "invalid_authority_plan_shape",
            "body.policy.prerequisites.authorityPlan",
            "none requires no steps and required requires a nonempty primary branch",
        ));
    }
    let mut primary_step_sha256 = Vec::with_capacity(plan.primary_steps.len());
    let mut cleanup_step_sha256 = Vec::with_capacity(plan.cleanup_steps.len());
    for (index, step) in plan.primary_steps.iter().enumerate() {
        validate_authority_prerequisite_step(step, index + 1, false)?;
        primary_step_sha256.push(step.step_sha256.clone());
    }
    for (index, step) in plan.cleanup_steps.iter().enumerate() {
        validate_authority_prerequisite_step(
            step,
            plan.primary_steps.len() + index + 1,
            true,
        )?;
        cleanup_step_sha256.push(step.step_sha256.clone());
    }
    validate_authority_plan_order(plan)?;
    validate_digest(
        &plan.plan_sha256,
        "body.policy.prerequisites.authorityPlan.planSha256",
    )?;
    let commitment = AuthorityPlanCommitment {
        mode: plan.mode,
        primary_step_sha256: primary_step_sha256.as_slice(),
        cleanup_step_sha256: cleanup_step_sha256.as_slice(),
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected = domain_sha256(
        CREDENTIAL_AUTHORITY_PLAN_ROOT_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &plan.plan_sha256,
        &expected,
        "body.policy.prerequisites.authorityPlan.planSha256",
    )
}

fn validate_authority_prerequisite_step(
    step: &AuthorityPrerequisiteStep,
    expected_sequence: usize,
    cleanup: bool,
) -> ContractResult<()> {
    if usize::from(step.sequence) != expected_sequence {
        return Err(ContractError::new(
            "authority_plan_sequence_mismatch",
            "body.policy.prerequisites.authorityPlan",
            "plan steps must use one contiguous sequence across primary and cleanup branches",
        ));
    }
    validate_identifier(
        &step.authority_id,
        "body.policy.prerequisites.authorityPlan.authorityId",
    )?;
    validate_authority_prerequisite_constraint(&step.constraint)?;
    if !authority_constraint_matches_operation(&step.constraint, step.operation)
        || cleanup
            != (step.operation
                == CredentialAuthorityOperation::CancelQuotaReservation)
    {
        return Err(ContractError::new(
            "authority_plan_operation_mismatch",
            "body.policy.prerequisites.authorityPlan",
            "primary constraints must match their operation and only committed quota cancellation may occupy cleanup capacity",
        ));
    }
    let constraint = canonical_jcs_bytes(&step.constraint)?;
    let expected_prerequisite = domain_sha256(
        CREDENTIAL_AUTHORITY_PLAN_STEP_DOMAIN,
        &[b"constraint", constraint.as_slice()],
    )?;
    require_equal_digest(
        &step.prerequisite_sha256,
        &expected_prerequisite,
        "body.policy.prerequisites.authorityPlan.prerequisiteSha256",
    )?;
    let commitment = AuthorityPrerequisiteStepCommitment {
        sequence: step.sequence,
        authority_id: &step.authority_id,
        operation: step.operation,
        constraint: &step.constraint,
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected_step = domain_sha256(
        CREDENTIAL_AUTHORITY_PLAN_STEP_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &step.step_sha256,
        &expected_step,
        "body.policy.prerequisites.authorityPlan.stepSha256",
    )
}

fn validate_authority_prerequisite_constraint(
    constraint: &AuthorityPrerequisiteConstraint,
) -> ContractResult<()> {
    match constraint {
        AuthorityPrerequisiteConstraint::Grant {
            grant_id,
            approval_id,
            reservation_id,
            maximum_use_count,
            webauthn_required,
            webauthn_approval,
        } => {
            validate_identifier(grant_id, "authorityPlan.grantId")?;
            validate_identifier(approval_id, "authorityPlan.approvalId")?;
            validate_identifier(reservation_id, "authorityPlan.reservationId")?;
            validate_safe_integer(*maximum_use_count, "authorityPlan.maximumUseCount")?;
            if *maximum_use_count == 0
                || (*webauthn_required != webauthn_approval.is_some())
            {
                return Err(ContractError::new(
                    "invalid_grant_prerequisite",
                    "body.policy.prerequisites.authorityPlan",
                    "grant prerequisites require a positive use limit and the complete exact WebAuthn identity when WebAuthn is required",
                ));
            }
            if let Some(approval) = webauthn_approval {
                validate_webauthn_approval_identity(approval)?;
                if approval.approval_id != *approval_id {
                    return Err(ContractError::new(
                        "grant_prerequisite_approval_mismatch",
                        "body.policy.prerequisites.authorityPlan",
                        "WebAuthn approval identity must equal the exact grant approval",
                    ));
                }
            }
        }
        AuthorityPrerequisiteConstraint::QuotaBudget {
            counter_id,
            budget_id,
            window_start_epoch_ms,
            window_end_epoch_ms,
            reservation_id,
            reservation_expires_at_epoch_ms,
            units,
            weight_basis_sha256,
        } => {
            validate_identifier(counter_id, "authorityPlan.counterId")?;
            validate_identifier(budget_id, "authorityPlan.budgetId")?;
            validate_identifier(reservation_id, "authorityPlan.reservationId")?;
            for value in [
                *window_start_epoch_ms,
                *window_end_epoch_ms,
                *reservation_expires_at_epoch_ms,
            ] {
                validate_safe_time(value, "authorityPlan.quotaWindow")?;
            }
            validate_safe_integer(*units, "authorityPlan.units")?;
            validate_digest(weight_basis_sha256, "authorityPlan.weightBasisSha256")?;
            if *units == 0
                || window_end_epoch_ms <= window_start_epoch_ms
                || reservation_expires_at_epoch_ms <= window_start_epoch_ms
                || reservation_expires_at_epoch_ms > window_end_epoch_ms
            {
                return Err(ContractError::new(
                    "invalid_quota_prerequisite",
                    "body.policy.prerequisites.authorityPlan",
                    "quota prerequisite requires positive units and one exact valid reservation/window interval",
                ));
            }
        }
        AuthorityPrerequisiteConstraint::Credential {
            provider_id,
            account_id,
            credential_ref,
            credential_version,
            credential_generation,
            lease_id,
            lease_release_id,
            authorization_receipt_id,
            expires_at_epoch_ms,
            credential_injection_template_sha256,
        } => {
            for value in [
                provider_id,
                account_id,
                credential_ref,
                lease_id,
                lease_release_id,
                authorization_receipt_id,
            ] {
                validate_identifier(value, "authorityPlan.credential")?;
            }
            validate_safe_integer(*credential_version, "authorityPlan.credentialVersion")?;
            validate_safe_integer(*credential_generation, "authorityPlan.credentialGeneration")?;
            validate_safe_time(*expires_at_epoch_ms, "authorityPlan.expiresAtEpochMs")?;
            validate_digest(
                credential_injection_template_sha256,
                "authorityPlan.credentialInjectionTemplateSha256",
            )?;
            if *credential_version == 0
                || *credential_generation == 0
                || *expires_at_epoch_ms == 0
            {
                return Err(ContractError::new(
                    "invalid_credential_prerequisite",
                    "body.policy.prerequisites.authorityPlan",
                    "credential version and generation must be positive",
                ));
            }
        }
        AuthorityPrerequisiteConstraint::Oauth {
            provider_authority_id,
            subject_id,
            account_id,
            client_id,
            app_id,
            credential_ref,
            credential_version,
            granted_scope_root_sha256,
            prior_token_generation,
            new_token_generation,
            output_generation_rule,
            credential_binding_sha256,
            request_sha256,
            operation_sha256,
            authorization_binding_sha256,
            prior_state_sha256,
            provider_request_id,
            provider_idempotency_key_sha256,
        } => {
            for value in [
                provider_authority_id,
                subject_id,
                account_id,
                client_id,
                app_id,
                credential_ref,
                provider_request_id,
            ] {
                validate_identifier(value, "authorityPlan.oauth")?;
            }
            validate_safe_integer(*credential_version, "authorityPlan.credentialVersion")?;
            validate_safe_integer(*prior_token_generation, "authorityPlan.priorTokenGeneration")?;
            validate_safe_integer(*new_token_generation, "authorityPlan.newTokenGeneration")?;
            for (value, path) in [
                (
                    granted_scope_root_sha256,
                    "authorityPlan.grantedScopeRootSha256",
                ),
                (
                    credential_binding_sha256,
                    "authorityPlan.credentialBindingSha256",
                ),
                (request_sha256, "authorityPlan.requestSha256"),
                (operation_sha256, "authorityPlan.operationSha256"),
                (
                    authorization_binding_sha256,
                    "authorityPlan.authorizationBindingSha256",
                ),
                (prior_state_sha256, "authorityPlan.priorStateSha256"),
            ] {
                validate_digest(value, path)?;
            }
            if let Some(value) = provider_idempotency_key_sha256 {
                validate_digest(value, "authorityPlan.providerIdempotencyKeySha256")?;
            }
            if *credential_version == 0
                || *output_generation_rule
                    != OauthOutputGenerationRule::AdvanceExactlyOneOnSuccessPreserveOnFailureOrUnknown
                || prior_token_generation.checked_add(1)
                    != Some(*new_token_generation)
            {
                return Err(ContractError::new(
                    "invalid_oauth_prerequisite",
                    "body.policy.prerequisites.authorityPlan",
                    "OAuth prerequisite requires a positive credential version and an exact one-generation proposed output with preserve-on-failure-or-unknown semantics",
                ));
            }
        }
    }
    Ok(())
}

fn authority_constraint_matches_operation(
    constraint: &AuthorityPrerequisiteConstraint,
    operation: CredentialAuthorityOperation,
) -> bool {
    matches!(
        (constraint, operation),
        (
            AuthorityPrerequisiteConstraint::Grant { .. },
            CredentialAuthorityOperation::ReserveGrant
                | CredentialAuthorityOperation::ConsumeGrant
        ) | (
            AuthorityPrerequisiteConstraint::QuotaBudget { .. },
            CredentialAuthorityOperation::ReserveQuota
                | CredentialAuthorityOperation::ConsumeQuota
                | CredentialAuthorityOperation::CancelQuotaReservation
        ) | (
            AuthorityPrerequisiteConstraint::Credential { .. },
            CredentialAuthorityOperation::AcquireCredentialLease
                | CredentialAuthorityOperation::AuthorizeCredentialDecryption
                | CredentialAuthorityOperation::AuthorizeCredentialInjection
        ) | (
            AuthorityPrerequisiteConstraint::Oauth { .. },
            CredentialAuthorityOperation::RefreshOauthToken
                | CredentialAuthorityOperation::ExchangeOauthToken
                | CredentialAuthorityOperation::MintToken
        )
    )
}

fn validate_authority_plan_order(
    plan: &AuthorityPrerequisitePlan,
) -> ContractResult<()> {
    let position = |operation| {
        plan.primary_steps
            .iter()
            .position(|step| step.operation == operation)
    };
    let ordered = |before, after| match (position(before), position(after)) {
        (Some(left), Some(right)) => left < right,
        (_, None) => true,
        (None, Some(_)) => false,
    };
    let has_credential_authority = position(
        CredentialAuthorityOperation::AuthorizeCredentialDecryption,
    )
    .is_some()
        || position(
            CredentialAuthorityOperation::AuthorizeCredentialInjection,
        )
        .is_some();
    let oauth_position = plan.primary_steps.iter().position(|step| {
        matches!(
            step.operation,
            CredentialAuthorityOperation::RefreshOauthToken
                | CredentialAuthorityOperation::ExchangeOauthToken
                | CredentialAuthorityOperation::MintToken
        )
    });
    let lease_position =
        position(CredentialAuthorityOperation::AcquireCredentialLease);
    let grant_consume_position =
        position(CredentialAuthorityOperation::ConsumeGrant);
    let first_credential_position = plan.primary_steps.iter().position(|step| {
        matches!(
            step.operation,
            CredentialAuthorityOperation::AcquireCredentialLease
                | CredentialAuthorityOperation::AuthorizeCredentialDecryption
                | CredentialAuthorityOperation::AuthorizeCredentialInjection
        )
    });
    if !ordered(
        CredentialAuthorityOperation::ReserveGrant,
        CredentialAuthorityOperation::ConsumeGrant,
    ) || !ordered(
        CredentialAuthorityOperation::ReserveQuota,
        CredentialAuthorityOperation::ConsumeQuota,
    ) || !ordered(
        CredentialAuthorityOperation::AcquireCredentialLease,
        CredentialAuthorityOperation::AuthorizeCredentialDecryption,
    ) || !ordered(
        CredentialAuthorityOperation::AuthorizeCredentialDecryption,
        CredentialAuthorityOperation::AuthorizeCredentialInjection,
    ) || (has_credential_authority
        && position(CredentialAuthorityOperation::ConsumeGrant).is_none())
        || matches!(
            (grant_consume_position, first_credential_position),
            (Some(grant), Some(credential)) if grant >= credential
        )
        || matches!((oauth_position, lease_position), (Some(oauth), Some(lease)) if oauth >= lease)
    {
        return Err(ContractError::new(
            "invalid_authority_plan_order",
            "body.policy.prerequisites.authorityPlan",
            "the committed success branch must order JIT/WebAuthn before credential authority, reserve before consume, OAuth before its lease, and decrypt before injection",
        ));
    }
    for (reserve_index, reserve) in plan
        .primary_steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.operation == CredentialAuthorityOperation::ReserveQuota
        })
    {
        let matching_consume = plan.primary_steps.iter().enumerate().filter(
            |(index, step)| {
                *index > reserve_index
                    && step.operation
                        == CredentialAuthorityOperation::ConsumeQuota
                    && step.authority_id == reserve.authority_id
                    && step.constraint == reserve.constraint
            },
        ).count();
        let matching_cleanup = plan.cleanup_steps.iter().filter(|step| {
            step.operation
                == CredentialAuthorityOperation::CancelQuotaReservation
                && step.authority_id == reserve.authority_id
                && step.constraint == reserve.constraint
        }).count();
        if matching_consume != 1 || matching_cleanup != 1 {
            return Err(ContractError::new(
                "incomplete_quota_plan_branches",
                "body.policy.prerequisites.authorityPlan",
                "every exact quota reservation requires one later matching consume step and one committed matching cleanup cancellation slot",
            ));
        }
    }
    for step in plan.primary_steps.iter().filter(|step| {
        step.operation == CredentialAuthorityOperation::ConsumeQuota
    }) {
        if !plan.primary_steps.iter().any(|candidate| {
            candidate.sequence < step.sequence
                && candidate.operation
                    == CredentialAuthorityOperation::ReserveQuota
                && candidate.authority_id == step.authority_id
                && candidate.constraint == step.constraint
        }) {
            return Err(ContractError::new(
                "orphan_quota_consume",
                "body.policy.prerequisites.authorityPlan",
                "quota consumption requires one earlier exact matching reservation",
            ));
        }
    }
    for cleanup in &plan.cleanup_steps {
        if !plan.primary_steps.iter().any(|candidate| {
            candidate.operation == CredentialAuthorityOperation::ReserveQuota
                && candidate.authority_id == cleanup.authority_id
                && candidate.constraint == cleanup.constraint
        }) {
            return Err(ContractError::new(
                "orphan_quota_cleanup",
                "body.policy.prerequisites.authorityPlan.cleanupSteps",
                "cleanup capacity may only cancel an exact reservation committed on the primary branch",
            ));
        }
    }
    Ok(())
}

fn validate_provider_idempotency_profile(
    profile: &ProviderIdempotencyProfile,
) -> ContractResult<()> {
    validate_identifier(&profile.provider_id, "providerIdempotencyProfile.providerId")?;
    match &profile.locator {
        ProviderIdempotencyLocator::Header { header_name } => {
            if !is_canonical_header_name(header_name.as_bytes()) {
                return Err(ContractError::new(
                    "invalid_idempotency_header_locator",
                    "providerIdempotencyProfile.locator.headerName",
                    "idempotency header locator must be one canonical lowercase HTTP field name",
                ));
            }
        }
        ProviderIdempotencyLocator::CanonicalFlatJsonStringBodyField {
            field_name,
        } => {
            validate_identifier(
                field_name,
                "providerIdempotencyProfile.locator.fieldName",
            )?;
        }
    }
    validate_digest(&profile.profile_sha256, "providerIdempotencyProfile.profileSha256")?;
    let canonical = canonical_jcs_bytes(&(
        profile.provider_id.as_str(),
        &profile.locator,
    ))?;
    let expected = domain_sha256(
        PROVIDER_IDEMPOTENCY_PROFILE_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &profile.profile_sha256,
        &expected,
        "providerIdempotencyProfile.profileSha256",
    )
}

fn validate_response_policy_profile(
    profile: &ResponsePolicyProfile,
) -> ContractResult<()> {
    validate_identifier(&profile.validator_id, "responsePolicyProfile.validatorId")?;
    validate_identifier(&profile.provider_id, "responsePolicyProfile.providerId")?;
    validate_digest(
        &profile.provider_schema_sha256,
        "responsePolicyProfile.providerSchemaSha256",
    )?;
    validate_digest(
        &profile.restrictions_sha256,
        "responsePolicyProfile.restrictionsSha256",
    )?;
    validate_safe_integer(
        profile.maximum_body_bytes,
        "responsePolicyProfile.maximumBodyBytes",
    )?;
    if profile.maximum_body_bytes > MAX_RESPONSE_ENTITY_BYTES {
        return Err(ContractError::new(
            "response_policy_body_limit",
            "responsePolicyProfile.maximumBodyBytes",
            "response policy body limit exceeds the immutable response bound",
        ));
    }
    match &profile.chunk_extensions {
        ChunkExtensionPolicy::Forbidden => {}
        ChunkExtensionPolicy::Allowed {
            maximum_extension_bytes,
        } => {
            validate_safe_integer(
                *maximum_extension_bytes,
                "responsePolicyProfile.chunkExtensions.maximumExtensionBytes",
            )?;
            if *maximum_extension_bytes == 0
                || *maximum_extension_bytes > MAX_RESPONSE_CHUNK_FRAMING_BYTES
            {
                return Err(ContractError::new(
                    "response_chunk_extension_limit",
                    "responsePolicyProfile.chunkExtensions.maximumExtensionBytes",
                    "allowed chunk extensions require one positive bound within the physical framing budget",
                ));
            }
        }
    }
    match &profile.trailers {
        TrailerPolicy::Forbidden => {}
        TrailerPolicy::Allowed {
            maximum_trailer_bytes,
            maximum_trailer_count,
        } => {
            validate_safe_integer(
                *maximum_trailer_bytes,
                "responsePolicyProfile.trailers.maximumTrailerBytes",
            )?;
            if *maximum_trailer_bytes < 2
                || *maximum_trailer_bytes > MAX_RESPONSE_TRAILER_BYTES
                || *maximum_trailer_count == 0
                || *maximum_trailer_count > MAX_HEADER_COUNT
            {
                return Err(ContractError::new(
                    "response_trailer_limit",
                    "responsePolicyProfile.trailers",
                    "allowed trailers require positive byte and count bounds within the physical response budget",
                ));
            }
        }
    }
    validate_digest(&profile.profile_sha256, "responsePolicyProfile.profileSha256")?;
    let canonical = canonical_jcs_bytes(&(
        profile.validator_id.as_str(),
        profile.provider_id.as_str(),
        profile.provider_schema_sha256.as_str(),
        profile.restrictions_sha256.as_str(),
        profile.maximum_body_bytes,
        profile.require_complete_body,
        &profile.chunk_extensions,
        &profile.trailers,
    ))?;
    let expected = domain_sha256(
        RESPONSE_POLICY_PROFILE_DOMAIN,
        &[canonical.as_slice()],
    )?;
    require_equal_digest(
        &profile.profile_sha256,
        &expected,
        "responsePolicyProfile.profileSha256",
    )
}

fn validate_route_semantic_profile_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    authorization_binding_sha256: &str,
) -> ContractResult<()> {
    let profile = &body.route_semantic_profile_evidence.payload;
    if profile.attempt_id != body.attempt_id
        || profile.policy_sha256 != body.policy.policy_sha256()
        || profile.snapshot_epoch != body.policy.snapshot_epoch()
        || profile.route_id.as_deref() != body.policy.route_id()
        || profile.operation_sha256 != body.policy.operation_sha256()
        || profile.credential_mode != body.policy.credential_mode()
        || profile.credential_identity_sha256.as_deref()
            != body
                .policy
                .credential_identity()
                .map(|identity| identity.credential_binding_sha256.as_str())
    {
        return Err(ContractError::new(
            "route_semantic_profile_policy_mismatch",
            "body.routeSemanticProfileEvidence.payload",
            "signed route semantics do not exactly bind the policy snapshot, route, operation, credential mode, and concrete credential generation",
        ));
    }
    require_equal_digest(
        &profile.authorization_binding_sha256,
        authorization_binding_sha256,
        "body.routeSemanticProfileEvidence.payload.authorizationBindingSha256",
    )?;
    if let Some(target) = profile.canonical_target.as_ref() {
        validate_canonical_target(target)?;
    }
    if let Some(staged) = body.staged_target_request.as_ref() {
        if profile.method != staged.method
            || profile.canonical_target.as_ref()
                != Some(&staged.canonical_target)
        {
            return Err(ContractError::new(
                "route_semantic_profile_target_mismatch",
                "body.routeSemanticProfileEvidence.payload",
                "signed route method and canonical target must equal the values derived from immutable staged bytes",
            ));
        }
    }
    let expected_idempotency_profile = body
        .policy
        .prerequisites()
        .and_then(|value| match &value.idempotency {
            PolicyIdempotencyPrerequisite::Required { provider_profile } => {
                Some(provider_profile.profile_sha256.as_str())
            }
            PolicyIdempotencyPrerequisite::NotRequired => None,
        });
    let expected_response_profile = body
        .policy
        .prerequisites()
        .and_then(|value| match &value.response_validation {
            PolicyResponseValidationPrerequisite::Required { profile } => {
                Some(profile.profile_sha256.as_str())
            }
            PolicyResponseValidationPrerequisite::NotRequired => None,
        });
    if profile.provider_idempotency_profile_sha256.as_deref()
        != expected_idempotency_profile
        || profile.response_policy_profile_sha256.as_deref()
            != expected_response_profile
    {
        return Err(ContractError::new(
            "route_semantic_profile_prerequisite_mismatch",
            "body.routeSemanticProfileEvidence.payload",
            "signed route semantics must bind the exact policy idempotency and response-validation profiles",
        ));
    }
    if let Some(PolicyResponseValidationPrerequisite::Required {
        profile: response_profile,
    }) = body
        .policy
        .prerequisites()
        .map(|value| &value.response_validation)
    {
        if profile.provider_id.as_deref()
            != Some(response_profile.provider_id.as_str())
            || profile.provider_schema_sha256.as_deref()
                != Some(response_profile.provider_schema_sha256.as_str())
        {
            return Err(ContractError::new(
                "route_response_provider_profile_mismatch",
                "body.routeSemanticProfileEvidence.payload",
                "the signed response validator profile must identify the exact route provider and provider schema",
            ));
        }
    }
    Ok(())
}

fn validate_route_classification(
    route: &RouteSemantics,
    profile: &RouteSemanticProfileEvidencePayload,
    staged: Option<&StagedTargetRequest>,
) -> ContractResult<()> {
    let (route_classification, idempotency_classification) = match route {
        RouteSemantics::Rejected { .. } => (
            RouteClassification::Rejected,
            IdempotencyClassification::NotApplicableDenied,
        ),
        RouteSemantics::WriteNotDispatchable {
            provider_idempotency,
            ..
        } => (
            RouteClassification::WriteNotDispatchable,
            match provider_idempotency {
                WritePreDispatchIdempotency::RequiredUnavailable => {
                    IdempotencyClassification::RequiredUnavailable
                }
                WritePreDispatchIdempotency::RequiredNotEvaluated => {
                    IdempotencyClassification::RequiredNotEvaluated
                }
                WritePreDispatchIdempotency::RequiredSatisfied { .. } => {
                    IdempotencyClassification::RequiredSatisfied
                }
                WritePreDispatchIdempotency::NotRequired => {
                    IdempotencyClassification::NotRequired
                }
            },
        ),
        RouteSemantics::Write { .. } => (
            RouteClassification::Write,
            IdempotencyClassification::ProviderEnforced,
        ),
        RouteSemantics::ReadOnly { .. } => (
            RouteClassification::ReadOnly,
            IdempotencyClassification::ReadOnlyException,
        ),
        RouteSemantics::CredentiallessReadOnly { .. } => (
            RouteClassification::CredentiallessReadOnly,
            IdempotencyClassification::ReadOnlyException,
        ),
    };
    if profile.route_classification != route_classification
        || profile.idempotency_classification != idempotency_classification
    {
        return Err(ContractError::new(
            "route_semantic_classification_mismatch",
            "body.routeSemanticProfileEvidence.payload",
            "body route labels differ from the independently signed provider semantic profile",
        ));
    }
    let provider_complete = profile.provider_id.is_some()
        && profile.provider_profile_sha256.is_some()
        && profile.provider_schema_sha256.is_some();
    if route_classification == RouteClassification::Rejected {
        if profile.provider_id.is_some()
            || profile.provider_profile_sha256.is_some()
            || profile.provider_schema_sha256.is_some()
            || profile.provider_idempotency_profile_sha256.is_some()
            || profile.response_policy_profile_sha256.is_some()
            || profile.credential_identity_sha256.is_some()
        {
            return Err(ContractError::new(
                "rejected_route_provider_authority",
                "body.routeSemanticProfileEvidence.payload",
                "a route rejected before provider authority must use explicit null provider bindings",
            ));
        }
        if profile.canonical_target.is_some() {
            return Err(ContractError::new(
                "rejected_route_target_authority",
                "body.routeSemanticProfileEvidence.payload.canonicalTarget",
                "a route rejected before provider authority must not carry an upstream target",
            ));
        }
    } else if !provider_complete {
        return Err(ContractError::new(
            "missing_provider_semantic_identity",
            "body.routeSemanticProfileEvidence.payload",
            "every known route requires exact provider profile and schema identities",
        ));
    } else if profile.canonical_target.is_none() {
        return Err(ContractError::new(
            "missing_canonical_target",
            "body.routeSemanticProfileEvidence.payload.canonicalTarget",
            "every known route requires a signed canonical upstream target",
        ));
    }
    if let Some(staged) = staged {
        if staged.method != profile.method {
            return Err(ContractError::new(
                "staged_method_semantic_mismatch",
                "body.stagedTargetRequest.method",
                "staged request method differs from the signed route semantic profile",
            ));
        }
    }
    Ok(())
}

fn route_semantic_profile_digest(
    profile: &RouteSemanticProfileEvidencePayload,
) -> ContractResult<String> {
    let commitment = RouteSemanticProfileCommitment {
        policy_sha256: &profile.policy_sha256,
        snapshot_epoch: profile.snapshot_epoch,
        route_id: profile.route_id.as_deref(),
        operation_sha256: &profile.operation_sha256,
        method: &profile.method,
        canonical_target: profile.canonical_target.as_ref(),
        provider_id: profile.provider_id.as_deref(),
        provider_profile_sha256: profile.provider_profile_sha256.as_deref(),
        provider_schema_sha256: profile.provider_schema_sha256.as_deref(),
        provider_idempotency_profile_sha256: profile
            .provider_idempotency_profile_sha256
            .as_deref(),
        response_policy_profile_sha256: profile
            .response_policy_profile_sha256
            .as_deref(),
        route_classification: profile.route_classification,
        idempotency_classification: profile.idempotency_classification,
        credential_mode: profile.credential_mode,
        credential_identity_sha256: profile
            .credential_identity_sha256
            .as_deref(),
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    domain_sha256(ROUTE_SEMANTIC_PROFILE_DOMAIN, &[canonical.as_slice()])
}

fn authorization_binding(
    policy: &PolicyBinding,
    attempt_id_value: &str,
    semantic_profile_sha256: &str,
) -> ContractResult<String> {
    validate_attempt_id(attempt_id_value)?;
    validate_digest(
        semantic_profile_sha256,
        "routeSemanticProfileSha256",
    )?;
    let canonical_policy = canonical_jcs_bytes(policy)?;
    domain_sha256(
        AUTHORIZATION_BINDING_DOMAIN,
        &[
            canonical_policy.as_slice(),
            attempt_id_value.as_bytes(),
            semantic_profile_sha256.as_bytes(),
        ],
    )
}

fn validate_policy_common(
    policy_sha256: &str,
    snapshot_epoch: u64,
    request_sha256: &str,
    operation_sha256: &str,
) -> ContractResult<()> {
    validate_digest(policy_sha256, "body.policy.policySha256")?;
    validate_digest(request_sha256, "body.policy.requestSha256")?;
    validate_digest(operation_sha256, "body.policy.operationSha256")?;
    validate_safe_integer(snapshot_epoch, "body.policy.snapshotEpoch")?;
    if snapshot_epoch == 0 {
        return Err(ContractError::new(
            "invalid_snapshot_epoch",
            "body.policy.snapshotEpoch",
            "policy snapshot epoch must be positive",
        ));
    }
    Ok(())
}

fn validate_staged_request(staged: &StagedTargetRequest) -> ContractResult<()> {
    validate_digest(&staged.staging_sha256, "body.stagedTargetRequest.stagingSha256")?;
    validate_digest(
        &staged.exact_request_retrieval_id,
        "body.stagedTargetRequest.exactRequestRetrievalId",
    )?;
    validate_digest(
        &staged.credential_injection_template_sha256,
        "body.stagedTargetRequest.credentialInjectionTemplateSha256",
    )?;
    for (value, path) in [
        (
            &staged.injection_result_sha256,
            "body.stagedTargetRequest.injectionResultSha256",
        ),
        (
            &staged.operation_semantics_sha256,
            "body.stagedTargetRequest.operationSemanticsSha256",
        ),
        (
            &staged.request_framing_sha256,
            "body.stagedTargetRequest.requestFramingSha256",
        ),
        (
            &staged.dispatch_authorization_binding_sha256,
            "body.stagedTargetRequest.dispatchAuthorizationBindingSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    if let Some(value) = staged.credential_binding_sha256.as_deref() {
        validate_digest(
            value,
            "body.stagedTargetRequest.credentialBindingSha256",
        )?;
    }
    if matches!(staged.injection, CredentialInjectionState::Applied)
        != staged.credential_binding_sha256.is_some()
    {
        return Err(ContractError::new(
            "invalid_staged_injection_shape",
            "body.stagedTargetRequest",
            "applied injection requires one credential binding and not-required injection forbids one",
        ));
    }
    validate_digest(
        &staged.exact_request_bytes_sha256,
        "body.stagedTargetRequest.exactRequestBytesSha256",
    )?;
    let expected_retrieval_id = domain_sha256(
        STAGED_REQUEST_RETRIEVAL_DOMAIN,
        &[staged.exact_request_bytes_sha256.as_bytes()],
    )?;
    require_equal_digest(
        &staged.exact_request_retrieval_id,
        &expected_retrieval_id,
        "body.stagedTargetRequest.exactRequestRetrievalId",
    )?;
    validate_digest(
        &staged.header_block_sha256,
        "body.stagedTargetRequest.headerBlockSha256",
    )?;
    validate_digest(&staged.body_sha256, "body.stagedTargetRequest.bodySha256")?;
    if let Some(value) = staged.idempotency_key_sha256.as_deref() {
        validate_digest(
            value,
            "body.stagedTargetRequest.idempotencyKeySha256",
        )?;
    }
    if let Some(value) = staged.idempotency_binding_sha256.as_deref() {
        validate_digest(
            value,
            "body.stagedTargetRequest.idempotencyBindingSha256",
        )?;
    }
    validate_http_method(&staged.method)?;
    validate_canonical_target(&staged.canonical_target)?;
    validate_safe_time(
        staged.prepared_at_epoch_ms,
        "body.stagedTargetRequest.preparedAtEpochMs",
    )?;
    if staged.exact_request_bytes_length == 0
        || staged.exact_request_bytes_length > MAX_REQUEST_BYTES
        || staged.header_block_length > MAX_HEADER_BYTES
        || staged.header_count > MAX_HEADER_COUNT
        || staged.body_length > MAX_REQUEST_BYTES
        || staged
            .header_block_length
            .saturating_add(staged.body_length)
            > staged.exact_request_bytes_length
    {
        return Err(ContractError::new(
            "staged_request_bounds_invalid",
            "body.stagedTargetRequest",
            "staged request lengths or counts exceed the closed contract",
        ));
    }
    let commitment = StagedRequestDigestCommitment {
        exact_request_retrieval_id: &staged.exact_request_retrieval_id,
        credential_injection_template_sha256:
            &staged.credential_injection_template_sha256,
        injection: staged.injection,
        credential_binding_sha256: staged.credential_binding_sha256.as_deref(),
        injection_result_sha256: &staged.injection_result_sha256,
        operation_semantics_sha256: &staged.operation_semantics_sha256,
        request_framing_sha256: &staged.request_framing_sha256,
        exact_request_bytes_sha256: &staged.exact_request_bytes_sha256,
        exact_request_bytes_length: staged.exact_request_bytes_length,
        method: &staged.method,
        wire_protocol: staged.wire_protocol,
        canonical_target: &staged.canonical_target,
        header_block_sha256: &staged.header_block_sha256,
        header_block_length: staged.header_block_length,
        header_count: staged.header_count,
        body_sha256: &staged.body_sha256,
        body_length: staged.body_length,
        idempotency_key_sha256: staged.idempotency_key_sha256.as_deref(),
        prepared_at_epoch_ms: staged.prepared_at_epoch_ms,
        preparation: &staged.preparation,
    };
    let jcs = canonical_jcs_bytes(&commitment)?;
    let expected = domain_sha256(STAGED_REQUEST_DOMAIN, &[jcs.as_slice()])?;
    require_equal_digest(
        &staged.staging_sha256,
        &expected,
        "body.stagedTargetRequest.stagingSha256",
    )
}

fn verify_exact_staged_request_bytes<P: ExactBytePersistenceVerifier>(
    staged: &StagedTargetRequest,
    envelope: &ResponseObservationEnvelopeBodyV2,
    persistence: &P,
) -> ContractResult<VerifiedExactStagedRequest> {
    validate_staged_request(staged)?;
    let retrieved = persistence
        .retrieve_exact_staged_request(&staged.exact_request_retrieval_id)?;
    let expected_authority =
        canonical_target_authority(&staged.canonical_target)?;
    if retrieved.retrieval_id != staged.exact_request_retrieval_id
        || retrieved.wire_protocol != staged.wire_protocol
        || retrieved.transport_scheme != staged.canonical_target.scheme
        || retrieved.authenticated_peer_authority.as_str()
            != expected_authority.as_str()
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_request_bytes.is_empty()
        || retrieved.exact_request_bytes.len() as u64
            != staged.exact_request_bytes_length
        || retrieved.exact_request_bytes.len() > MAX_REQUEST_BYTES as usize
    {
        return Err(ContractError::new(
            "staged_request_retrieval_mismatch",
            "body.stagedTargetRequest.exactRequestRetrievalId",
            "trusted retrieval must return the exact immutable bounded request, wire protocol, HTTPS transport, and authenticated peer authority",
        ));
    }
    require_equal_digest(
        &staged.exact_request_bytes_sha256,
        &raw_sha256(&retrieved.exact_request_bytes),
        "body.stagedTargetRequest.exactRequestBytesSha256",
    )?;
    let path_and_query = canonical_path_and_query(&staged.canonical_target)?;
    let request_line = format!(
        "{} {} HTTP/1.1\r\n",
        staged.method, path_and_query
    );
    let request = retrieved.exact_request_bytes.as_slice();
    if !request.starts_with(request_line.as_bytes()) {
        return Err(ContractError::new(
            "exact_request_line_mismatch",
            "body.stagedTargetRequest",
            "exact request bytes must begin with the canonical method, origin-form target, and HTTP/1.1 request line",
        ));
    }
    let header_start = request_line.len();
    let header_length = usize::try_from(staged.header_block_length).map_err(|_| {
        ContractError::new(
            "staged_request_bounds_invalid",
            "body.stagedTargetRequest.headerBlockLength",
            "header length cannot be represented",
        )
    })?;
    let body_length = usize::try_from(staged.body_length).map_err(|_| {
        ContractError::new(
            "staged_request_bounds_invalid",
            "body.stagedTargetRequest.bodyLength",
            "body length cannot be represented",
        )
    })?;
    let header_end = header_start.checked_add(header_length).ok_or_else(|| {
        ContractError::new(
            "staged_request_bounds_invalid",
            "body.stagedTargetRequest",
            "request segment lengths overflow",
        )
    })?;
    let body_end = header_end.checked_add(body_length).ok_or_else(|| {
        ContractError::new(
            "staged_request_bounds_invalid",
            "body.stagedTargetRequest",
            "request segment lengths overflow",
        )
    })?;
    if body_end != request.len() {
        return Err(ContractError::new(
            "exact_request_segment_mismatch",
            "body.stagedTargetRequest",
            "request line, header block, and body lengths must exactly partition immutable request bytes",
        ));
    }
    let header_block = &request[header_start..header_end];
    let body = &request[header_end..body_end];
    require_equal_digest(
        &staged.header_block_sha256,
        &raw_sha256(header_block),
        "body.stagedTargetRequest.headerBlockSha256",
    )?;
    require_equal_digest(
        &staged.body_sha256,
        &raw_sha256(body),
        "body.stagedTargetRequest.bodySha256",
    )?;
    validate_exact_header_block(
        header_block,
        staged.header_count,
        &expected_authority,
        staged.body_length,
    )?;
    let expected_operation_semantics = request_operation_semantics_digest(
        &staged.method,
        &staged.canonical_target,
        body,
    )?;
    require_equal_digest(
        &staged.operation_semantics_sha256,
        &expected_operation_semantics,
        "body.stagedTargetRequest.operationSemanticsSha256",
    )?;
    let expected_framing = request_framing_digest(
        request_line.as_bytes(),
        header_block,
        body,
    )?;
    require_equal_digest(
        &staged.request_framing_sha256,
        &expected_framing,
        "body.stagedTargetRequest.requestFramingSha256",
    )?;
    let expected_injection_result = credential_injection_result_digest(
        staged.injection,
        &staged.credential_injection_template_sha256,
        staged.credential_binding_sha256.as_deref(),
        header_block,
        body,
    )?;
    require_equal_digest(
        &staged.injection_result_sha256,
        &expected_injection_result,
        "body.stagedTargetRequest.injectionResultSha256",
    )?;
    let derived_idempotency_key_sha256 =
        derive_provider_idempotency_key(envelope, header_block, body)?;
    if staged.idempotency_key_sha256 != derived_idempotency_key_sha256 {
        return Err(ContractError::new(
            "staged_idempotency_key_mismatch",
            "body.stagedTargetRequest.idempotencyKeySha256",
            "staged idempotency key must be derived from the exact provider-located immutable request field",
        ));
    }
    let dispatch_authorization_binding_sha256 =
        dispatch_authorization_binding(envelope, staged)?;
    require_equal_digest(
        &staged.dispatch_authorization_binding_sha256,
        &dispatch_authorization_binding_sha256,
        "body.stagedTargetRequest.dispatchAuthorizationBindingSha256",
    )?;
    Ok(VerifiedExactStagedRequest {
        staging_sha256: staged.staging_sha256.clone(),
        operation_semantics_sha256: expected_operation_semantics,
        dispatch_authorization_binding_sha256,
        idempotency_key_sha256: derived_idempotency_key_sha256,
    })
}

fn validate_exact_header_block(
    header_block: &[u8],
    expected_count: u32,
    expected_authority: &str,
    expected_body_length: u64,
) -> ContractResult<()> {
    if header_block.len() < 4
        || !header_block.ends_with(b"\r\n\r\n")
        || header_block[..header_block.len() - 4]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
    {
        return Err(ContractError::new(
            "noncanonical_header_block",
            "body.stagedTargetRequest",
            "header block must contain one terminal CRLF pair and no embedded header terminator",
        ));
    }
    let mut remaining = &header_block[..header_block.len() - 2];
    let mut count = 0u32;
    let mut host_count = 0u8;
    let mut content_length_count = 0u8;
    let mut seen_header_names = BTreeSet::new();
    while !remaining.is_empty() {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                ContractError::new(
                    "noncanonical_header_block",
                    "body.stagedTargetRequest",
                    "every exact header line must end in CRLF",
                )
            })?;
        let line = &remaining[..line_end];
        remaining = &remaining[line_end + 2..];
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ContractError::new(
                "noncanonical_header_line",
                "body.stagedTargetRequest",
                "every exact header line must have a canonical lowercase field name",
            )
        })?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty()
            || !is_canonical_header_name(name)
            || !value.starts_with(b" ")
            || value.len() < 2
            || value[1] == b' '
            || value.last() == Some(&b' ')
            || value[1..]
                .iter()
                .any(|byte| *byte < 0x21 || *byte > 0x7e)
        {
            return Err(ContractError::new(
                "noncanonical_header_line",
                "body.stagedTargetRequest",
                "headers must use lowercase token names and exactly one space before a visible ASCII value",
            ));
        }
        if !seen_header_names.insert(name) {
            return Err(ContractError::new(
                "duplicate_header_name",
                "body.stagedTargetRequest",
                "canonical staged requests permit each lowercase header name exactly once",
            ));
        }
        if name == b"host" {
            host_count = host_count.saturating_add(1);
            if &value[1..] != expected_authority.as_bytes() {
                return Err(ContractError::new(
                    "exact_host_target_mismatch",
                    "body.stagedTargetRequest",
                    "the exact Host field must equal the signed canonical authority",
                ));
            }
        }
        if name == b"transfer-encoding" {
            return Err(ContractError::new(
                "ambiguous_request_framing",
                "body.stagedTargetRequest",
                "immutable staged requests must not use Transfer-Encoding",
            ));
        }
        if name == b"content-length" {
            content_length_count =
                content_length_count.saturating_add(1);
            let digits = &value[1..];
            let canonical_decimal = !digits.is_empty()
                && digits.iter().all(|byte| byte.is_ascii_digit())
                && (digits.len() == 1 || digits[0] != b'0');
            let parsed = std::str::from_utf8(digits)
                .ok()
                .and_then(|value| value.parse::<u64>().ok());
            if !canonical_decimal
                || parsed != Some(expected_body_length)
            {
                return Err(ContractError::new(
                    "ambiguous_request_framing",
                    "body.stagedTargetRequest",
                    "Content-Length must be one canonical decimal exactly equal to the committed body length",
                ));
            }
        }
        count = count.saturating_add(1);
        if count > MAX_HEADER_COUNT {
            return Err(ContractError::new(
                "header_count_limit",
                "body.stagedTargetRequest.headerCount",
                "exact header count exceeds the closed bound",
            ));
        }
    }
    if count != expected_count
        || host_count != 1
        || content_length_count > 1
        || (expected_body_length > 0 && content_length_count != 1)
    {
        return Err(ContractError::new(
            "exact_header_identity_mismatch",
            "body.stagedTargetRequest",
            "exact headers require one Host, at most one matching Content-Length, no transfer coding, and complete single-message framing",
        ));
    }
    Ok(())
}

fn is_canonical_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
                        | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn request_operation_semantics_digest(
    method: &str,
    target: &CanonicalUpstreamTarget,
    exact_body: &[u8],
) -> ContractResult<String> {
    domain_sha256(
        REQUEST_OPERATION_SEMANTICS_DOMAIN,
        &[
            method.as_bytes(),
            target.target_sha256.as_bytes(),
            exact_body,
        ],
    )
}

fn request_framing_digest(
    request_line: &[u8],
    header_block: &[u8],
    body: &[u8],
) -> ContractResult<String> {
    let body_length = (body.len() as u64).to_be_bytes();
    domain_sha256(
        REQUEST_FRAMING_DOMAIN,
        &[
            request_line,
            header_block,
            body_length.as_slice(),
        ],
    )
}

fn credential_injection_result_digest(
    injection: CredentialInjectionState,
    template_sha256: &str,
    credential_binding_sha256: Option<&str>,
    header_block: &[u8],
    body: &[u8],
) -> ContractResult<String> {
    let injection_jcs = canonical_jcs_bytes(&injection)?;
    let credential_jcs = canonical_jcs_bytes(&credential_binding_sha256)?;
    domain_sha256(
        CREDENTIAL_INJECTION_RESULT_DOMAIN,
        &[
            injection_jcs.as_slice(),
            template_sha256.as_bytes(),
            credential_jcs.as_slice(),
            header_block,
            body,
        ],
    )
}

fn dispatch_authorization_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    staged: &StagedTargetRequest,
) -> ContractResult<String> {
    let policy_jcs = canonical_jcs_bytes(&body.policy)?;
    domain_sha256(
        DISPATCH_AUTHORIZATION_BINDING_DOMAIN,
        &[
            policy_jcs.as_slice(),
            body.attempt_id.as_bytes(),
            body.route_semantic_profile_evidence
                .payload
                .semantic_profile_sha256
                .as_bytes(),
            staged.staging_sha256.as_bytes(),
            staged.operation_semantics_sha256.as_bytes(),
            staged.request_framing_sha256.as_bytes(),
            staged.injection_result_sha256.as_bytes(),
        ],
    )
}

fn exact_header_value<'a>(
    header_block: &'a [u8],
    expected_name: &[u8],
) -> ContractResult<Option<&'a [u8]>> {
    let mut remaining = &header_block[..header_block.len() - 2];
    let mut found = None;
    while !remaining.is_empty() {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                ContractError::new(
                    "noncanonical_header_block",
                    "body.stagedTargetRequest",
                    "exact idempotency extraction requires canonical CRLF header lines",
                )
            })?;
        let line = &remaining[..line_end];
        remaining = &remaining[line_end + 2..];
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ContractError::new(
                "noncanonical_header_line",
                "body.stagedTargetRequest",
                "exact idempotency extraction requires a canonical header separator",
            )
        })?;
        if &line[..colon] == expected_name {
            if found.is_some() {
                return Err(ContractError::new(
                    "duplicate_idempotency_field",
                    "body.stagedTargetRequest",
                    "provider idempotency field appears more than once",
                ));
            }
            found = Some(&line[colon + 2..]);
        }
    }
    Ok(found)
}

fn canonical_flat_json_string_field(
    body: &[u8],
    expected_field: &[u8],
) -> ContractResult<Option<Vec<u8>>> {
    if body.len() < 2 || body.first() != Some(&b'{') || body.last() != Some(&b'}') {
        return Err(ContractError::new(
            "noncanonical_idempotency_body",
            "body.stagedTargetRequest",
            "body-field idempotency extraction requires one canonical flat JSON string map",
        ));
    }
    if body == b"{}" {
        return Ok(None);
    }
    let mut index = 1usize;
    let mut previous_key: Option<&[u8]> = None;
    let mut found = None;
    while index < body.len() - 1 {
        if body.get(index) != Some(&b'"') {
            return Err(ContractError::new(
                "noncanonical_idempotency_body",
                "body.stagedTargetRequest",
                "canonical flat JSON keys must begin with a quote",
            ));
        }
        index += 1;
        let key_start = index;
        while body.get(index).is_some_and(|byte| *byte != b'"') {
            let byte = body[index];
            if !(0x21..=0x7e).contains(&byte) || byte == b'\\' {
                return Err(ContractError::new(
                    "noncanonical_idempotency_body",
                    "body.stagedTargetRequest",
                    "canonical flat JSON idempotency fields forbid escapes and non-visible ASCII",
                ));
            }
            index += 1;
        }
        let key = &body[key_start..index];
        if key.is_empty()
            || previous_key.is_some_and(|previous| previous >= key)
            || body.get(index..index + 2) != Some(b"\":")
            || body.get(index + 2) != Some(&b'"')
        {
            return Err(ContractError::new(
                "noncanonical_idempotency_body",
                "body.stagedTargetRequest",
                "canonical flat JSON keys must be unique, byte-sorted, and followed by one string value",
            ));
        }
        index += 3;
        let value_start = index;
        while body.get(index).is_some_and(|byte| *byte != b'"') {
            let byte = body[index];
            if !(0x21..=0x7e).contains(&byte) || byte == b'\\' {
                return Err(ContractError::new(
                    "noncanonical_idempotency_body",
                    "body.stagedTargetRequest",
                    "canonical flat JSON string values forbid escapes and non-visible ASCII",
                ));
            }
            index += 1;
        }
        if body.get(index) != Some(&b'"') {
            return Err(ContractError::new(
                "noncanonical_idempotency_body",
                "body.stagedTargetRequest",
                "canonical flat JSON string value is unterminated",
            ));
        }
        if key == expected_field {
            if found.is_some() {
                return Err(ContractError::new(
                    "duplicate_idempotency_field",
                    "body.stagedTargetRequest",
                    "provider body idempotency field appears more than once",
                ));
            }
            found = Some(body[value_start..index].to_vec());
        }
        previous_key = Some(key);
        index += 1;
        match body.get(index) {
            Some(b',') => index += 1,
            Some(b'}') if index == body.len() - 1 => break,
            _ => {
                return Err(ContractError::new(
                    "noncanonical_idempotency_body",
                    "body.stagedTargetRequest",
                    "canonical flat JSON fields require one comma and no whitespace",
                ));
            }
        }
    }
    Ok(found)
}

fn derive_provider_idempotency_key(
    envelope: &ResponseObservationEnvelopeBodyV2,
    header_block: &[u8],
    body: &[u8],
) -> ContractResult<Option<String>> {
    let prerequisite = envelope
        .policy
        .prerequisites()
        .map(|value| &value.idempotency);
    let profile = match prerequisite {
        Some(PolicyIdempotencyPrerequisite::Required { provider_profile }) => {
            provider_profile
        }
        Some(PolicyIdempotencyPrerequisite::NotRequired) | None => {
            return Ok(None);
        }
    };
    validate_provider_idempotency_profile(profile)?;
    if envelope
        .route_semantic_profile_evidence
        .payload
        .provider_id
        .as_deref()
        != Some(profile.provider_id.as_str())
        || envelope
            .route_semantic_profile_evidence
            .payload
            .provider_idempotency_profile_sha256
            .as_deref()
            != Some(profile.profile_sha256.as_str())
    {
        return Err(ContractError::new(
            "idempotency_provider_profile_mismatch",
            "body.policy.prerequisites.idempotency",
            "provider-specific idempotency locator must identify the signed route provider",
        ));
    }
    let value = match &profile.locator {
        ProviderIdempotencyLocator::Header { header_name } => {
            exact_header_value(header_block, header_name.as_bytes())?
                .map(|value| value.to_vec())
        }
        ProviderIdempotencyLocator::CanonicalFlatJsonStringBodyField {
            field_name,
        } => canonical_flat_json_string_field(body, field_name.as_bytes())?,
    };
    let value = match value {
        Some(value) => value,
        None
            if matches!(
                &envelope.route_semantics,
                RouteSemantics::WriteNotDispatchable {
                    reason:
                        WriteNotDispatchableReason::ProviderIdempotencyUnavailable,
                    ..
                }
            ) =>
        {
            return Ok(None);
        }
        None => {
            return Err(ContractError::new(
                "missing_provider_idempotency_field",
                "body.stagedTargetRequest",
                "required provider idempotency field is absent from exact immutable request bytes",
            ));
        }
    };
    if value.is_empty()
        || value.len() > 512
        || value.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return Err(ContractError::new(
            "noncanonical_provider_idempotency_key",
            "body.stagedTargetRequest",
            "provider idempotency key must be one nonempty bounded visible-ASCII exact value",
        ));
    }
    Ok(Some(raw_sha256(value.as_slice())))
}

fn validate_exact_staged_request_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    exact: Option<&VerifiedExactStagedRequest>,
) -> ContractResult<()> {
    let staged = body.staged_target_request.as_ref();
    if staged.is_some() != exact.is_some() {
        return Err(ContractError::new(
            "exact_staged_request_presence_mismatch",
            "body.stagedTargetRequest",
            "every staged request and only a staged request requires exact immutable retrieval",
        ));
    }
    let (staged, exact) = match (staged, exact) {
        (Some(staged), Some(exact)) => (staged, exact),
        (None, None) => return Ok(()),
        _ => unreachable!(),
    };
    if exact.staging_sha256 != staged.staging_sha256
        || exact.operation_semantics_sha256
            != staged.operation_semantics_sha256
        || exact.dispatch_authorization_binding_sha256
            != staged.dispatch_authorization_binding_sha256
        || exact.idempotency_key_sha256 != staged.idempotency_key_sha256
        || body.policy.request_sha256() != staged.staging_sha256
        || body.policy.operation_sha256()
            != staged.operation_semantics_sha256
    {
        return Err(ContractError::new(
            "exact_staged_request_policy_mismatch",
            "body.stagedTargetRequest",
            "policy request, operation, dispatch authority, and staged metadata must equal values reconstructed from exact immutable request bytes",
        ));
    }
    Ok(())
}

fn raw_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

fn validate_route_semantics(
    route: &RouteSemantics,
    attempt_id_value: &str,
    staged_digest: Option<&str>,
) -> ContractResult<()> {
    match route {
        RouteSemantics::Rejected { .. } => {
            if staged_digest.is_some() {
                return Err(ContractError::new(
                    "rejected_route_staged",
                    "body.stagedTargetRequest",
                    "a route rejected before authority cannot stage target bytes",
                ));
            }
        }
        RouteSemantics::WriteNotDispatchable {
            provider_idempotency,
            reason,
        } => {
            if staged_digest.is_some()
                && matches!(
                    reason,
                    WriteNotDispatchableReason::ReservationDenied
                        | WriteNotDispatchableReason::StagingFailed
                )
            {
                return Err(ContractError::new(
                    "nondispatchable_write_staged",
                    "body.stagedTargetRequest",
                    "reservation denial and failure before immutable staging cannot carry staged bytes; later failures must retain them when produced",
                ));
            }
            if let WritePreDispatchIdempotency::RequiredSatisfied {
                key_sha256,
                locator_profile_sha256,
                binding_sha256,
            } = provider_idempotency
            {
                for value in [
                    key_sha256,
                    locator_profile_sha256,
                    binding_sha256,
                ] {
                    validate_digest(
                        value,
                        "body.routeSemantics.providerIdempotency",
                    )?;
                }
                if staged_digest.is_none() {
                    return Err(ContractError::new(
                        "idempotency_authority_without_exact_request",
                        "body.routeSemantics.providerIdempotency",
                        "required-satisfied idempotency authority requires the exact staged request from which the verifier derives the key",
                    ));
                }
            }
            if *reason
                == WriteNotDispatchableReason::ProviderIdempotencyUnavailable
                && (!matches!(
                    provider_idempotency,
                    WritePreDispatchIdempotency::RequiredUnavailable
                ) || staged_digest.is_none())
            {
                return Err(ContractError::new(
                    "write_nondispatchable_idempotency_mismatch",
                    "body.routeSemantics",
                    "provider-idempotency-unavailable requires RequiredUnavailable proven against produced exact staged bytes",
                ));
            }
            if matches!(
                provider_idempotency,
                WritePreDispatchIdempotency::RequiredUnavailable
            ) && (*reason
                != WriteNotDispatchableReason::ProviderIdempotencyUnavailable
                || staged_digest.is_none())
            {
                return Err(ContractError::new(
                    "write_required_unavailable_without_exact_proof",
                    "body.routeSemantics.providerIdempotency",
                    "RequiredUnavailable is valid only when canonical exact staged bytes prove the signed required locator absent; duplicate or noncanonical requests fail closed before staging",
                ));
            }
            if matches!(
                provider_idempotency,
                WritePreDispatchIdempotency::RequiredNotEvaluated
            ) && (staged_digest.is_some()
                || *reason
                    == WriteNotDispatchableReason::ProviderIdempotencyUnavailable)
            {
                return Err(ContractError::new(
                    "write_required_not_evaluated_with_staged_request",
                    "body.routeSemantics.providerIdempotency",
                    "RequiredNotEvaluated is valid only for a pre-staging failure where no exact request existed to inspect",
                ));
            }
        }
        RouteSemantics::Write {
            provider_idempotency,
            ambiguous_outcome_recovery,
        } => {
            validate_digest(
                &provider_idempotency.key_sha256,
                "body.routeSemantics.providerIdempotency.keySha256",
            )?;
            validate_digest(
                &provider_idempotency.binding_sha256,
                "body.routeSemantics.providerIdempotency.bindingSha256",
            )?;
            validate_digest(
                &provider_idempotency.locator_profile_sha256,
                "body.routeSemantics.providerIdempotency.locatorProfileSha256",
            )?;
            let staged = staged_digest.ok_or_else(|| {
                ContractError::new(
                    "write_route_not_staged",
                    "body.stagedTargetRequest",
                    "write routes require staged exact bytes before any dispatch authority",
                )
            })?;
            let expected_binding = idempotency_binding(
                attempt_id_value,
                &provider_idempotency.key_sha256,
                staged,
            )?;
            require_equal_digest(
                &provider_idempotency.binding_sha256,
                &expected_binding,
                "body.routeSemantics.providerIdempotency.bindingSha256",
            )?;
            if ambiguous_outcome_recovery.attempt_id != attempt_id_value
                || ambiguous_outcome_recovery.idempotency_binding_sha256
                    != provider_idempotency.binding_sha256
            {
                return Err(ContractError::new(
                    "recovery_binding_mismatch",
                    "body.routeSemantics.ambiguousOutcomeRecovery",
                    "durable recovery must bind the one attemptId and provider idempotency key",
                ));
            }
            validate_digest(
                &ambiguous_outcome_recovery.durable_record_sha256,
                "body.routeSemantics.ambiguousOutcomeRecovery.durableRecordSha256",
            )?;
            validate_digest(
                &ambiguous_outcome_recovery.recovery_key_sha256,
                "body.routeSemantics.ambiguousOutcomeRecovery.recoveryKeySha256",
            )?;
            let expected_recovery = recovery_key(
                attempt_id_value,
                &provider_idempotency.binding_sha256,
            )?;
            require_equal_digest(
                &ambiguous_outcome_recovery.recovery_key_sha256,
                &expected_recovery,
                "body.routeSemantics.ambiguousOutcomeRecovery.recoveryKeySha256",
            )?;
        }
        RouteSemantics::ReadOnly { retry_recovery, .. } => {
            validate_read_retry_recovery(
                retry_recovery,
                attempt_id_value,
                b"read-only",
            )?;
        }
        RouteSemantics::CredentiallessReadOnly { retry_recovery, .. } => {
            validate_read_retry_recovery(
                retry_recovery,
                attempt_id_value,
                b"credentialless-read-only",
            )?;
        }
    }
    Ok(())
}

fn validate_read_retry_recovery(
    recovery: &ReadRetryRecovery,
    attempt_id_value: &str,
    route_class: &[u8],
) -> ContractResult<()> {
    if recovery.attempt_id != attempt_id_value {
        return Err(ContractError::new(
            "read_retry_attempt_mismatch",
            "body.routeSemantics.retryRecovery.attemptId",
            "read retry recovery must bind the one attemptId",
        ));
    }
    validate_digest(
        &recovery.retry_binding_sha256,
        "body.routeSemantics.retryRecovery.retryBindingSha256",
    )?;
    let expected = domain_sha256(
        READ_RETRY_BINDING_DOMAIN,
        &[attempt_id_value.as_bytes(), route_class],
    )?;
    require_equal_digest(
        &recovery.retry_binding_sha256,
        &expected,
        "body.routeSemantics.retryRecovery.retryBindingSha256",
    )
}

fn validate_staged_idempotency_binding(
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<()> {
    let staged = body.staged_target_request.as_ref();
    let expected_profile = body
        .policy
        .prerequisites()
        .and_then(|prerequisites| match &prerequisites.idempotency {
            PolicyIdempotencyPrerequisite::Required { provider_profile } => {
                Some(provider_profile.profile_sha256.as_str())
            }
            PolicyIdempotencyPrerequisite::NotRequired => None,
        });
    match (&body.route_semantics, &body.policy) {
        (
            RouteSemantics::Write { .. },
            PolicyBinding::Allowed {
                prerequisites:
                    PolicyPrerequisites {
                        idempotency: PolicyIdempotencyPrerequisite::Required { .. },
                        ..
                    },
                ..
            },
        )
        | (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency:
                    WritePreDispatchIdempotency::RequiredSatisfied { .. }
                    | WritePreDispatchIdempotency::RequiredUnavailable
                    | WritePreDispatchIdempotency::RequiredNotEvaluated,
                ..
            },
            PolicyBinding::Allowed {
                prerequisites:
                    PolicyPrerequisites {
                        idempotency: PolicyIdempotencyPrerequisite::Required { .. },
                        ..
                    },
                ..
            },
        )
        | (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency: WritePreDispatchIdempotency::NotRequired,
                ..
            },
            PolicyBinding::Allowed {
                prerequisites:
                    PolicyPrerequisites {
                        idempotency: PolicyIdempotencyPrerequisite::NotRequired,
                        ..
                    },
                ..
            },
        )
        | (
            RouteSemantics::ReadOnly { .. }
            | RouteSemantics::CredentiallessReadOnly { .. },
            PolicyBinding::Allowed {
                prerequisites:
                    PolicyPrerequisites {
                        idempotency: PolicyIdempotencyPrerequisite::NotRequired,
                        ..
                    },
                ..
            },
        )
        | (RouteSemantics::Rejected { .. }, PolicyBinding::Denied { .. }) => {}
        _ => {
            return Err(ContractError::new(
                "policy_route_idempotency_mismatch",
                "body.policy.prerequisites.idempotency",
                "policy idempotency prerequisite and exact route class must select one closed matching state",
            ))
        }
    }
    match (&body.route_semantics, staged) {
        (
            RouteSemantics::Write {
                provider_idempotency,
                ..
            },
            Some(staged),
        ) => {
            let expected_binding = idempotency_binding(
                &body.attempt_id,
                &provider_idempotency.key_sha256,
                &staged.staging_sha256,
            )?;
            if staged.idempotency_key_sha256.as_deref()
                != Some(provider_idempotency.key_sha256.as_str())
                || staged.idempotency_binding_sha256.as_deref()
                    != Some(provider_idempotency.binding_sha256.as_str())
                || provider_idempotency.binding_sha256 != expected_binding
                || expected_profile
                    != Some(
                        provider_idempotency
                            .locator_profile_sha256
                            .as_str(),
                    )
            {
                return Err(ContractError::new(
                    "provider_idempotency_exact_binding_mismatch",
                    "body.routeSemantics.providerIdempotency",
                    "write idempotency key, locator profile, and binding must be verifier-derived from the exact immutable staged request",
                ));
            }
            Ok(())
        }
        (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency:
                    WritePreDispatchIdempotency::RequiredSatisfied {
                        key_sha256,
                        locator_profile_sha256,
                        binding_sha256,
                    },
                ..
            },
            Some(staged),
        ) => {
            let expected_binding = idempotency_binding(
                &body.attempt_id,
                key_sha256,
                &staged.staging_sha256,
            )?;
            if staged.idempotency_key_sha256.as_deref()
                != Some(key_sha256.as_str())
                || staged.idempotency_binding_sha256.as_deref()
                    != Some(binding_sha256.as_str())
                || binding_sha256 != &expected_binding
                || expected_profile != Some(locator_profile_sha256.as_str())
            {
                return Err(ContractError::new(
                    "predispatch_idempotency_exact_binding_mismatch",
                    "body.routeSemantics.providerIdempotency",
                    "pre-dispatch required-satisfied idempotency must be verifier-derived from exact immutable staged bytes",
                ));
            }
            Ok(())
        }
        (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency: WritePreDispatchIdempotency::RequiredUnavailable,
                reason: WriteNotDispatchableReason::ProviderIdempotencyUnavailable,
            },
            Some(staged),
        ) => {
            if staged.idempotency_key_sha256.is_some()
                || staged.idempotency_binding_sha256.is_some()
                || expected_profile.is_none()
            {
                return Err(ContractError::new(
                    "predispatch_idempotency_unavailable_proof_mismatch",
                    "body.routeSemantics.providerIdempotency",
                    "required-unavailable must be verifier-derived as no valid provider key from exact immutable staged bytes under the signed required locator profile",
                ));
            }
            Ok(())
        }
        (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency: WritePreDispatchIdempotency::RequiredNotEvaluated,
                ..
            },
            None,
        ) => Ok(()),
        (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency: WritePreDispatchIdempotency::RequiredUnavailable,
                ..
            },
            None,
        )
        | (
            RouteSemantics::WriteNotDispatchable {
                provider_idempotency: WritePreDispatchIdempotency::RequiredNotEvaluated,
                ..
            },
            Some(_),
        ) => Err(ContractError::new(
            "predispatch_idempotency_evidence_state_mismatch",
            "body.routeSemantics.providerIdempotency",
            "required-unavailable requires exact staged bytes, while required-not-evaluated requires an explicit no-staged-request state",
        )),
        (
            RouteSemantics::ReadOnly { .. }
            | RouteSemantics::CredentiallessReadOnly { .. },
            Some(staged),
        ) if staged.idempotency_binding_sha256.is_some()
            || staged.idempotency_key_sha256.is_some() =>
        {
            Err(ContractError::new(
                "unexpected_read_idempotency_binding",
                "body.stagedTargetRequest.idempotencyBindingSha256",
                "read exceptions cannot carry a write-provider idempotency authority",
            ))
        }
        (_, Some(staged))
            if matches!(
                body
                    .policy
                    .prerequisites()
                    .map(|value| &value.idempotency),
                Some(PolicyIdempotencyPrerequisite::NotRequired)
            ) && (staged.idempotency_binding_sha256.is_some()
                || staged.idempotency_key_sha256.is_some()) =>
        {
            Err(ContractError::new(
                "unexpected_provider_idempotency",
                "body.stagedTargetRequest",
                "policy-explicit not-required idempotency forbids staged key or binding authority",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_credential_and_side_effect(
    body: &ResponseObservationEnvelopeBodyV2,
    staged_digest: Option<&str>,
    exact_local_reconciliation: Option<&VerifiedLocalReconciliationRecord>,
) -> ContractResult<()> {
    if let Some(binding) = body.credential.binding_sha256() {
        validate_digest(binding, "body.credential.credentialBindingSha256")?;
    }
    if let CredentialState::AcquisitionOutcomeUnknown {
        recovery_binding_sha256,
        ..
    }
    | CredentialState::InjectionOutcomeUnknown {
        recovery_binding_sha256,
        ..
    } = &body.credential {
        validate_digest(
            recovery_binding_sha256,
            "body.credential.recoveryBindingSha256",
        )?;
    }
    let policy_credential_identity = body.policy.credential_identity();
    if let Some(identity) = policy_credential_identity {
        if body.route_semantic_profile_evidence.payload.provider_id.as_deref()
                != Some(identity.provider_id.as_str())
            || body.credential.binding_sha256().is_some_and(|binding| {
                binding != identity.credential_binding_sha256.as_str()
            })
            || (body.credential.binding_sha256().is_none()
                && !matches!(&body.credential, CredentialState::NotEvaluated { .. }))
        {
            return Err(ContractError::new(
                "policy_credential_binding_mismatch",
                "body.credential.credentialBindingSha256",
                "every credential-bearing outcome and signed route provider must equal the policy-committed provider, account, credential, version, and generation binding",
            ));
        }
    } else if body.credential.binding_sha256().is_some() {
        return Err(ContractError::new(
            "unexpected_credential_binding",
            "body.credential.credentialBindingSha256",
            "a policy without credential authority cannot carry a credential binding",
        ));
    }
    match (policy_credential_identity, &body.credential) {
        (
            Some(PolicyCredentialIdentity {
                source: PolicyCredentialSource::LocalCredential,
                ..
            }),
            CredentialState::AcquisitionFailed {
                failure:
                    CredentialAcquisitionFailure::LocalCredential { .. },
                ..
            },
        )
        | (
            Some(PolicyCredentialIdentity {
                source: PolicyCredentialSource::AuthorityPlan,
                ..
            }),
            CredentialState::AcquisitionFailed {
                failure:
                    CredentialAcquisitionFailure::CredentialAuthority { .. },
                ..
            },
        ) => {}
        (
            Some(PolicyCredentialIdentity { .. }),
            CredentialState::AcquisitionFailed { .. },
        ) => {
            return Err(ContractError::new(
                "credential_acquisition_failure_source_mismatch",
                "body.credential.failure",
                "local acquisition failures and credential-authority failures are closed, disjoint classes selected by the exact policy credential source",
            ))
        }
        (
            Some(PolicyCredentialIdentity {
                source: PolicyCredentialSource::LocalCredential,
                ..
            }),
            CredentialState::AcquisitionOutcomeUnknown {
                local_reconciliation: Some(_),
                ..
            },
        )
        | (
            Some(PolicyCredentialIdentity {
                source: PolicyCredentialSource::AuthorityPlan,
                ..
            }),
            CredentialState::AcquisitionOutcomeUnknown {
                local_reconciliation: None,
                ..
            },
        ) => {}
        (
            Some(PolicyCredentialIdentity { .. }),
            CredentialState::AcquisitionOutcomeUnknown { .. },
        ) => {
            return Err(ContractError::new(
                "credential_acquisition_reconciliation_source_mismatch",
                "body.credential.localReconciliation",
                "local acquisition uncertainty requires its durable reconciliation record and credential-authority uncertainty forbids one",
            ))
        }
        _ => {}
    }
    let expected_terminal_recovery = match &body.credential {
        CredentialState::AcquisitionOutcomeUnknown {
            recovery_binding_sha256,
            ..
        } => Some(recovery_binding_sha256.as_str()),
        _ => None,
    };
    match (&body.terminal_evidence.payload, expected_terminal_recovery) {
        (
            TerminalEvidencePayload::Cancelled {
                credential_recovery_binding_sha256,
                ..
            },
            expected,
        ) if credential_recovery_binding_sha256.as_deref() == expected => {}
        (TerminalEvidencePayload::Cancelled { .. }, _)
        | (_, Some(_)) => {
            return Err(ContractError::new(
                "terminal_credential_recovery_binding_mismatch",
                "body.terminalEvidence.payload.credentialRecoveryBindingSha256",
                "the signed cancellation terminal must carry exactly the credential recovery binding for an unknown acquisition and null for every other credential state",
            ))
        }
        _ => {}
    }
    match (&body.policy, &body.credential, &body.route_semantics) {
        (
            PolicyBinding::Denied { .. },
            CredentialState::NotEvaluated {
                reason: CredentialNotEvaluatedReason::PolicyDenied,
            },
            RouteSemantics::Rejected { .. },
        ) => {}
        (
            PolicyBinding::Allowed { .. },
            CredentialState::NotEvaluated {
                reason: CredentialNotEvaluatedReason::AuthorizationDenied,
            },
            _,
        ) => {}
        (
            PolicyBinding::Allowed {
                credential_mode: PolicyCredentialMode::Required,
                ..
            },
            CredentialState::AcquisitionFailed { .. }
            | CredentialState::AcquisitionOutcomeUnknown { .. }
            | CredentialState::AcquiredNotInjected { .. }
            | CredentialState::InjectionFailed { .. }
            | CredentialState::InjectionOutcomeUnknown { .. }
            | CredentialState::Injected { .. },
            _,
        ) => {}
        (
            PolicyBinding::Allowed {
                credential_mode: PolicyCredentialMode::NotRequiredReadOnly,
                ..
            },
            CredentialState::NotRequired {
                exception: CredentialException::ReadOnlyNoCredential,
            },
            RouteSemantics::ReadOnly { .. },
        ) => {}
        (
            PolicyBinding::Allowed {
                credential_mode: PolicyCredentialMode::NotRequiredCredentialless,
                ..
            },
            CredentialState::NotRequired {
                exception: CredentialException::CredentiallessReadOnly,
            },
            RouteSemantics::CredentiallessReadOnly { .. },
        ) => {}
        _ => {
            return Err(ContractError::new(
                "credential_policy_mismatch",
                "body.credential",
                "credential state does not match policy credential mode and route exception",
            ))
        }
    }
    if let CredentialState::Injected {
        staged_request_sha256,
        injection_result_sha256,
        credential_binding_sha256,
        ..
    } = &body.credential
    {
        require_equal_optional_digest(
            staged_request_sha256,
            staged_digest,
            "body.credential.stagedRequestSha256",
        )?;
        let staged = body.staged_target_request.as_ref().ok_or_else(|| {
            ContractError::new(
                "missing_staged_request",
                "body.stagedTargetRequest",
                "injected credential state requires exact immutable staged bytes",
            )
        })?;
        if staged.injection != CredentialInjectionState::Applied
            || staged.credential_binding_sha256.as_deref()
                != Some(credential_binding_sha256.as_str())
            || staged.injection_result_sha256 != *injection_result_sha256
        {
            return Err(ContractError::new(
                "credential_injection_exact_binding_mismatch",
                "body.credential",
                "injected state must bind the exact staged credential and verifier-derived physical injection result",
            ));
        }
    }
    if let CredentialState::InjectionFailed {
        credential_binding_sha256,
        attempted_request,
        ..
    }
    | CredentialState::InjectionOutcomeUnknown {
        credential_binding_sha256,
        attempted_request,
        ..
    } = &body.credential {
        validate_attempted_staged_request(
            attempted_request,
            body.staged_target_request.as_ref(),
            credential_binding_sha256,
        )?;
    }
    if matches!(
        &body.credential,
        CredentialState::NotEvaluated { .. }
            | CredentialState::AcquisitionFailed { .. }
            | CredentialState::AcquisitionOutcomeUnknown { .. }
            | CredentialState::AcquiredNotInjected { .. }
    ) && (body.dispatch_evidence.is_some() || body.staged_target_request.is_some())
    {
        return Err(ContractError::new(
            "credential_state_dispatchable",
            "body.credential",
            "non-injected credential state cannot stage bytes or receive dispatch authority",
        ));
    }

    match &body.credential_authority_side_effect {
        CredentialAuthoritySideEffect::NotAttempted { reason } => {
            let valid = matches!(
                (reason, &body.policy, &body.credential),
                (
                    CredentialAuthorityNotAttemptedReason::PolicyDenied,
                    PolicyBinding::Denied { .. },
                    CredentialState::NotEvaluated { .. }
                ) | (
                    CredentialAuthorityNotAttemptedReason::AuthorizationDenied,
                    PolicyBinding::Allowed { .. },
                    CredentialState::NotEvaluated {
                        reason: CredentialNotEvaluatedReason::AuthorizationDenied
                    }
                ) | (
                    CredentialAuthorityNotAttemptedReason::CredentialNotRequired,
                    PolicyBinding::Allowed { .. },
                    CredentialState::NotRequired { .. }
                ) | (
                    CredentialAuthorityNotAttemptedReason::LocalCredentialOnly,
                    PolicyBinding::Allowed {
                        credential_identity:
                            Some(PolicyCredentialIdentity {
                                source: PolicyCredentialSource::LocalCredential,
                                ..
                            }),
                        ..
                    },
                    CredentialState::AcquisitionFailed { .. }
                        | CredentialState::AcquisitionOutcomeUnknown { .. }
                        | CredentialState::AcquiredNotInjected { .. }
                        | CredentialState::InjectionFailed { .. }
                        | CredentialState::InjectionOutcomeUnknown { .. }
                        | CredentialState::Injected { .. }
                )
            );
            if !valid {
                return Err(ContractError::new(
                    "credential_authority_state_mismatch",
                    "body.credentialAuthoritySideEffect",
                    "not-attempted authority reason contradicts policy or credential state",
                ));
            }
            if *reason
                == CredentialAuthorityNotAttemptedReason::LocalCredentialOnly
            {
                validate_local_credential_terminal(
                    body,
                    exact_local_reconciliation,
                )?;
            }
        }
        CredentialAuthoritySideEffect::DefinitelyFailed {
            authority_id,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256,
            state_machine_summary_sha256,
            ..
        }
        | CredentialAuthoritySideEffect::Completed {
            authority_id,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256,
            state_machine_summary_sha256,
            ..
        } => {
            validate_identifier(
                authority_id,
                "body.credentialAuthoritySideEffect.authorityId",
            )?;
            validate_digest(
                effect_binding_sha256,
                "body.credentialAuthoritySideEffect.effectBindingSha256",
            )?;
            validate_digest(
                terminal_record_sha256,
                "body.credentialAuthoritySideEffect.terminalRecordSha256",
            )?;
            validate_digest(
                final_record_sha256,
                "body.credentialAuthoritySideEffect.finalRecordSha256",
            )?;
            validate_digest(
                evidence_root_sha256,
                "body.credentialAuthoritySideEffect.evidenceRootSha256",
            )?;
            validate_digest(
                state_machine_summary_sha256,
                "body.credentialAuthoritySideEffect.stateMachineSummarySha256",
            )?;
            match &body.credential_authority_side_effect {
                CredentialAuthoritySideEffect::Completed {
                    operation,
                    ..
                } if operation_may_produce_credential(*operation)
                    && !matches!(
                        &body.credential,
                        CredentialState::AcquiredNotInjected { .. }
                            | CredentialState::InjectionFailed { .. }
                            | CredentialState::Injected { .. }
                    ) =>
                {
                    return Err(ContractError::new(
                        "credential_authority_state_mismatch",
                        "body.credentialAuthoritySideEffect",
                        "completed credential-producing authority requires an acquired credential state",
                    ));
                }
                CredentialAuthoritySideEffect::DefinitelyFailed {
                    operation,
                    failure,
                    ..
                } if operation_may_produce_credential(*operation)
                    && !matches!(
                        &body.credential,
                        CredentialState::AcquisitionFailed {
                            failure:
                                CredentialAcquisitionFailure::CredentialAuthority {
                                    failure: credential_failure,
                                },
                            ..
                        } if credential_failure == failure
                    ) =>
                {
                    return Err(ContractError::new(
                        "credential_authority_state_mismatch",
                        "body.credentialAuthoritySideEffect",
                        "definite credential-producing authority failure requires definite credential acquisition failure",
                    ));
                }
                _ => {}
            }
            if body.reserve_evidence.is_none() {
                return Err(ContractError::new(
                    "credential_authority_without_reservation",
                    "body.reserveEvidence",
                    "credential-authority activity requires prior authorization reservation",
                ));
            }
        }
        CredentialAuthoritySideEffect::OutcomeUnknown {
            authority_id,
            operation,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256,
            state_machine_summary_sha256,
            recovery_binding_sha256,
            ..
        } => {
            validate_identifier(
                authority_id,
                "body.credentialAuthoritySideEffect.authorityId",
            )?;
            validate_digest(
                effect_binding_sha256,
                "body.credentialAuthoritySideEffect.effectBindingSha256",
            )?;
            validate_digest(
                terminal_record_sha256,
                "body.credentialAuthoritySideEffect.terminalRecordSha256",
            )?;
            validate_digest(
                final_record_sha256,
                "body.credentialAuthoritySideEffect.finalRecordSha256",
            )?;
            validate_digest(
                evidence_root_sha256,
                "body.credentialAuthoritySideEffect.evidenceRootSha256",
            )?;
            validate_digest(
                state_machine_summary_sha256,
                "body.credentialAuthoritySideEffect.stateMachineSummarySha256",
            )?;
            validate_digest(
                recovery_binding_sha256,
                "body.credentialAuthoritySideEffect.recoveryBindingSha256",
            )?;
            if operation_may_produce_credential(*operation)
                && !matches!(
                    &body.credential,
                    CredentialState::AcquisitionOutcomeUnknown {
                        recovery_binding_sha256: credential_recovery,
                        local_reconciliation: None,
                        ..
                    } if credential_recovery == recovery_binding_sha256
                )
            {
                return Err(ContractError::new(
                    "credential_authority_state_mismatch",
                    "body.credentialAuthoritySideEffect",
                    "unknown credential-producing authority outcome requires the same credential recovery binding",
                ));
            }
            if !matches!(
                &body.target_egress,
                TargetEgressState::DefinitelyNotDispatched {
                    reason: NotDispatchedReason::CredentialAuthorityOutcomeUnknown,
                    ..
                }
            ) {
                return Err(ContractError::new(
                    "credential_authority_ambiguity_leaked_to_target",
                    "body.targetEgress",
                    "unknown credential-authority side effect must prevent target dispatch",
                ));
            }
            if body.reserve_evidence.is_none() {
                return Err(ContractError::new(
                    "credential_authority_without_reservation",
                    "body.reserveEvidence",
                    "credential-authority activity requires prior authorization reservation",
                ));
            }
        }
    }
    Ok(())
}

fn validate_attempted_staged_request(
    attempted: &AttemptedStagedRequest,
    staged: Option<&StagedTargetRequest>,
    expected_credential_binding_sha256: &str,
) -> ContractResult<()> {
    match (attempted, staged) {
        (
            AttemptedStagedRequest::Produced {
                credential_binding_sha256,
                staged_request_sha256,
                injection_result_sha256,
            },
            Some(staged),
        ) => {
            validate_digest(
                credential_binding_sha256,
                "body.credential.attemptedRequest.credentialBindingSha256",
            )?;
            validate_digest(
                staged_request_sha256,
                "body.credential.attemptedRequest.stagedRequestSha256",
            )?;
            validate_digest(
                injection_result_sha256,
                "body.credential.attemptedRequest.injectionResultSha256",
            )?;
            if credential_binding_sha256 != expected_credential_binding_sha256
                || staged.credential_binding_sha256.as_deref()
                    != Some(expected_credential_binding_sha256)
                || staged.injection != CredentialInjectionState::Applied
                || staged_request_sha256 != &staged.staging_sha256
                || injection_result_sha256 != &staged.injection_result_sha256
            {
                return Err(ContractError::new(
                    "attempted_staged_request_mismatch",
                    "body.credential.attemptedRequest",
                    "failed or unknown injection must retain one exact policy credential binding through attempted bytes, staged bytes, and the credential-bound injection result",
                ));
            }
            Ok(())
        }
        (
            AttemptedStagedRequest::NotProduced {
                credential_binding_sha256,
                ..
            },
            None,
        ) => {
            validate_digest(
                credential_binding_sha256,
                "body.credential.attemptedRequest.credentialBindingSha256",
            )?;
            if credential_binding_sha256 != expected_credential_binding_sha256 {
                return Err(ContractError::new(
                    "attempted_credential_binding_mismatch",
                    "body.credential.attemptedRequest.credentialBindingSha256",
                    "explicit not-produced state must retain the same policy credential identity attempted by injection",
                ));
            }
            Ok(())
        }
        _ => Err(ContractError::new(
            "attempted_staged_request_presence_mismatch",
            "body.credential.attemptedRequest",
            "injection outcome must truthfully select exact produced bytes or explicit not-produced state",
        )),
    }
}

fn validate_local_credential_terminal(
    body: &ResponseObservationEnvelopeBodyV2,
    exact_reconciliation: Option<&VerifiedLocalReconciliationRecord>,
) -> ContractResult<()> {
    if !body.credential_authority_evidence.is_empty()
        || body.credential_authority_state_machine.is_some()
    {
        return Err(ContractError::new(
            "local_credential_authority_evidence",
            "body.credentialAuthorityEvidence",
            "local-credential-only acquisition cannot carry authority steps or an authority state machine",
        ));
    }
    let (expected_cancellation, expected_no_dispatch) =
        match &body.credential {
            CredentialState::AcquisitionFailed {
                failure:
                    CredentialAcquisitionFailure::LocalCredential { .. },
                ..
            } => (
                    CancellationReason::CredentialFailure,
                    NotDispatchedReason::CredentialFailure,
                ),
            CredentialState::AcquisitionOutcomeUnknown {
                credential_binding_sha256,
                recovery_binding_sha256,
                local_reconciliation:
                    Some(local_reconciliation),
            } => {
                validate_local_acquisition_reconciliation(
                    body,
                    local_reconciliation,
                    exact_reconciliation.ok_or_else(|| {
                        ContractError::new(
                            "missing_exact_local_reconciliation",
                            "body.credential.localReconciliation",
                            "local acquisition uncertainty requires trusted retrieval of the exact immutable reconciliation record",
                        )
                    })?,
                )?;
                let expected_recovery =
                    local_credential_recovery_binding(
                        body,
                        credential_binding_sha256,
                        local_reconciliation,
                    )?;
                require_equal_digest(
                    recovery_binding_sha256,
                    &expected_recovery,
                    "body.credential.recoveryBindingSha256",
                )?;
                (
                    CancellationReason::CredentialAcquisitionOutcomeUnknown,
                    NotDispatchedReason::CredentialAcquisitionOutcomeUnknown,
                )
            }
            CredentialState::AcquisitionFailed { .. }
            | CredentialState::AcquisitionOutcomeUnknown { .. } => {
                return Err(ContractError::new(
                    "invalid_local_acquisition_terminal",
                    "body.credential",
                    "local credential acquisition requires either a closed local failure cause or a durable unresolved side-effect reconciliation record",
                ))
            }
            _ => return Ok(()),
        };
    if matches!(
        &body.credential,
        CredentialState::AcquisitionFailed {
            failure:
                CredentialAcquisitionFailure::LocalCredential { .. },
            ..
        }
    ) && (exact_reconciliation.is_some()
        || body.local_reconciliation_recovery_evidence.is_some()
        || body.local_reconciliation_continuity_evidence.is_some()
        || body
            .local_reconciliation_ledger_witness_evidence
            .is_some()
        || body
            .local_reconciliation_genesis_absence_evidence
            .is_some())
    {
        return Err(ContractError::new(
            "unexpected_local_reconciliation",
            "body.localReconciliationRecoveryEvidence",
            "a definite local acquisition failure cannot carry an unresolved reconciliation record or recovery evidence",
        ));
    }
    if !matches!(
        &body.authorization,
        AuthorizationState::ReservedCancelled { .. }
    ) || !matches!(
        &body.terminal_evidence.payload,
        TerminalEvidencePayload::Cancelled {
            reason,
            definitely_not_dispatched: true,
            ..
        } if *reason == expected_cancellation
    ) || !matches!(
        &body.target_egress,
        TargetEgressState::DefinitelyNotDispatched {
            reason,
            bytes_written: 0,
            staged_request_sha256: None,
        } if *reason == expected_no_dispatch
    ) {
        return Err(ContractError::new(
            "local_credential_terminal_mismatch",
            "body",
            "local credential acquisition failure or uncertainty requires its exact reserved cancellation, zero-byte no-dispatch reason, and no staged request",
        ));
    }
    if let RouteSemantics::WriteNotDispatchable { reason, .. } =
        &body.route_semantics
    {
        let expected_route_reason = match &body.credential {
            CredentialState::AcquisitionFailed {
                failure:
                    CredentialAcquisitionFailure::LocalCredential { .. },
                ..
            } => {
                WriteNotDispatchableReason::CredentialFailure
            }
            CredentialState::AcquisitionOutcomeUnknown { .. } => {
                WriteNotDispatchableReason::CredentialAcquisitionOutcomeUnknown
            }
            _ => unreachable!(),
        };
        if *reason != expected_route_reason {
            return Err(ContractError::new(
                "local_credential_route_reason_mismatch",
                "body.routeSemantics.reason",
                "local credential acquisition terminal must use the same definite or unknown route reason",
            ));
        }
    }
    Ok(())
}

fn local_credential_recovery_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    credential_binding_sha256: &str,
    reconciliation: &LocalAcquisitionReconciliation,
) -> ContractResult<String> {
    let reconciliation_commitment = canonical_jcs_bytes(reconciliation)?;
    domain_sha256(
        LOCAL_CREDENTIAL_RECOVERY_BINDING_DOMAIN,
        &[
            body.attempt_id.as_bytes(),
            credential_binding_sha256.as_bytes(),
            body.policy.request_sha256().as_bytes(),
            body.policy.operation_sha256().as_bytes(),
            body.route_semantic_profile_evidence
                .payload
                .authorization_binding_sha256
                .as_bytes(),
            reconciliation_commitment.as_slice(),
        ],
    )
}

fn validate_local_acquisition_reconciliation(
    body: &ResponseObservationEnvelopeBodyV2,
    reference: &LocalAcquisitionReconciliation,
    reconciliation: &VerifiedLocalReconciliationRecord,
) -> ContractResult<()> {
    let record = &reconciliation.record;
    let policy_side_effect =
        body.policy.credential_identity().and_then(|identity| {
            if identity.source == PolicyCredentialSource::LocalCredential {
                identity.local_acquisition_uncertain_side_effect
            } else {
                None
            }
        });
    if policy_side_effect != Some(record.uncertain_side_effect) {
        return Err(ContractError::new(
            "local_reconciliation_side_effect_not_permitted",
            "localReconciliationRecord.uncertainSideEffect",
            "local acquisition uncertainty is valid only for the exact durable side effect committed by policy; a side-effect-free acquisition must be a definite failure",
        ));
    }
    if reference.record_id != reconciliation.record_id
        || reference.record_sha256 != reconciliation.record_sha256
        || reference.record_byte_length != reconciliation.record_byte_length
        || reference.retrieval_id != reconciliation.retrieval_id
        || reference.persistence_receipt_sha256
            != reconciliation.persistence_receipt_sha256
        || reference.retrieval_proof_sha256
            != reconciliation.retrieval_proof_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_reference_mismatch",
            "body.credential.localReconciliation",
            "proof references must equal the verifier-retrieved exact record, recomputed digest and length, and trusted persistence/retrieval evidence",
        ));
    }
    let (failure_observed_at_epoch_ms, completed_at_epoch_ms) =
        match &body.terminal_evidence.payload {
            TerminalEvidencePayload::Cancelled {
                failure_observed_at_epoch_ms,
                completed_at_epoch_ms,
                ..
            } => (*failure_observed_at_epoch_ms, *completed_at_epoch_ms),
            _ => {
                return Err(ContractError::new(
                    "local_reconciliation_without_cancellation",
                    "body.terminalEvidence.payload",
                    "an unresolved local acquisition side effect requires a signed cancellation terminal",
                ))
            }
        };
    if record.rollback_state_epoch != body.runtime.rollback_state_epoch
        || record.rollback_head_sha256
            != body.runtime.rollback_state_head_sha256
        || record.created_at_epoch_ms > failure_observed_at_epoch_ms
        || failure_observed_at_epoch_ms > completed_at_epoch_ms
        || record.deadline_epoch_ms <= completed_at_epoch_ms
        || record
            .deadline_epoch_ms
            .saturating_sub(record.created_at_epoch_ms)
            > MAX_LOCAL_RECONCILIATION_DELAY_MS
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_window",
            "body.credential.localReconciliation",
            "local reconciliation must bind the current rollback epoch and head, predate the unknown terminal, remain unresolved past completion, and use the closed bounded deadline",
        ));
    }
    let custody = body.custody_authority_evidence.as_ref().ok_or_else(|| {
        ContractError::new(
            "missing_local_reconciliation_custody",
            "body.custodyAuthorityEvidence",
            "unknown local acquisition side effects require current signed custody authority evidence",
        )
    })?;
    if record.custody_authority_key_id != custody.key_id
        || record.rollback_state_epoch
            != custody.payload.rollback_state_epoch
        || record.rollback_state_epoch
            != custody.boot_runtime_identity.rollback_state_epoch
        || record.rollback_head_sha256
            != custody
                .boot_runtime_identity
                .rollback_state_head_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_custody_mismatch",
            "body.credential.localReconciliation",
            "the durable reconciliation record must bind the exact current custody key, signed custody evidence, and independently attested rollback-protected runtime epoch and head",
        ));
    }
    let identity = body.policy.credential_identity().ok_or_else(|| {
        ContractError::new(
            "local_reconciliation_without_policy_credential",
            "body.policy.credentialIdentity",
            "local reconciliation requires one exact policy credential identity",
        )
    })?;
    if record.attempt_id != body.attempt_id
        || record.request_sha256 != body.policy.request_sha256()
        || record.operation_sha256 != body.policy.operation_sha256()
        || record.authorization_binding_sha256
            != body
                .route_semantic_profile_evidence
                .payload
                .authorization_binding_sha256
        || record.credential_binding_sha256
            != identity.credential_binding_sha256
        || record.provider_id != identity.provider_id
        || record.account_id != identity.account_id
        || record.credential_ref != identity.credential_ref
        || record.credential_version != identity.credential_version
        || record.credential_generation != identity.credential_generation
    {
        return Err(ContractError::new(
            "local_reconciliation_subject_mismatch",
            "localReconciliationRecord",
            "retrieved reconciliation bytes do not bind the exact attempt, request, operation, authorization, and policy credential tuple",
        ));
    }
    Ok(())
}

fn verify_exact_local_reconciliation_record<
    P: ExactBytePersistenceVerifier,
>(
    body: &ResponseObservationEnvelopeBodyV2,
    persistence: &P,
) -> ContractResult<Option<VerifiedLocalReconciliationRecord>> {
    let reference = match &body.credential {
        CredentialState::AcquisitionOutcomeUnknown {
            local_reconciliation: Some(reference),
            ..
        } => reference,
        _ => return Ok(None),
    };
    for (value, path) in [
        (
            &reference.record_id,
            "body.credential.localReconciliation.recordId",
        ),
        (
            &reference.record_sha256,
            "body.credential.localReconciliation.recordSha256",
        ),
        (
            &reference.retrieval_id,
            "body.credential.localReconciliation.retrievalId",
        ),
        (
            &reference.persistence_receipt_sha256,
            "body.credential.localReconciliation.persistenceReceiptSha256",
        ),
        (
            &reference.retrieval_proof_sha256,
            "body.credential.localReconciliation.retrievalProofSha256",
        ),
        (
            &reference.recovery_evidence_sha256,
            "body.credential.localReconciliation.recoveryEvidenceSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_safe_integer(
        reference.record_byte_length,
        "body.credential.localReconciliation.recordByteLength",
    )?;
    let retrieved = persistence
        .retrieve_exact_local_reconciliation_record(&reference.retrieval_id)?;
    if retrieved.retrieval_id != reference.retrieval_id
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_record_bytes.is_empty()
        || retrieved.exact_record_bytes.len()
            > MAX_LOCAL_RECONCILIATION_RECORD_BYTES
        || retrieved.persistence_receipt_sha256
            != reference.persistence_receipt_sha256
        || retrieved.retrieval_proof_sha256
            != reference.retrieval_proof_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_retrieval_mismatch",
            "body.credential.localReconciliation",
            "trusted retrieval must return the exact immutable bounded record and storage-generated persistence/retrieval evidence for the referenced object",
        ));
    }
    validate_digest(
        &retrieved.persistence_receipt_sha256,
        "localReconciliationRetrieval.persistenceReceiptSha256",
    )?;
    validate_digest(
        &retrieved.retrieval_proof_sha256,
        "localReconciliationRetrieval.retrievalProofSha256",
    )?;
    let record_byte_length =
        u64::try_from(retrieved.exact_record_bytes.len()).map_err(|_| {
            ContractError::new(
                "length_overflow",
                "body.credential.localReconciliation.recordByteLength",
                "retrieved reconciliation record length cannot be represented",
            )
        })?;
    if record_byte_length != reference.record_byte_length {
        return Err(ContractError::new(
            "local_reconciliation_length_mismatch",
            "body.credential.localReconciliation.recordByteLength",
            "asserted record length does not equal trusted exact-byte retrieval",
        ));
    }
    let record =
        decode_canonical_local_reconciliation_record(
            &retrieved.exact_record_bytes,
        )?;
    validate_local_reconciliation_record(&record)?;
    let record_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_RECORD_DOMAIN,
        &[retrieved.exact_record_bytes.as_slice()],
    )?;
    let record_id = local_reconciliation_record_id(
        &record.attempt_id,
        &record_sha256,
        record_byte_length,
    )?;
    let retrieval_id = local_reconciliation_retrieval_id(
        &record_id,
        &record_sha256,
        record_byte_length,
    )?;
    if record_sha256 != reference.record_sha256
        || record_id != reference.record_id
        || retrieval_id != reference.retrieval_id
    {
        return Err(ContractError::new(
            "local_reconciliation_identity_mismatch",
            "body.credential.localReconciliation",
            "record id, retrieval id, digest, and length must be independently derived from the exact canonical retrieved bytes",
        ));
    }
    Ok(Some(VerifiedLocalReconciliationRecord {
        record,
        record_id,
        record_sha256,
        record_byte_length,
        retrieval_id,
        persistence_receipt_sha256:
            retrieved.persistence_receipt_sha256,
        retrieval_proof_sha256: retrieved.retrieval_proof_sha256,
    }))
}

fn verify_exact_local_reconciliation_continuity<
    V: EvidenceSignatureVerifier,
    P: ExactBytePersistenceVerifier,
>(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
    evidence_verifier: &V,
    persistence: &P,
    current: Option<&VerifiedLocalReconciliationRecord>,
) -> ContractResult<Option<VerifiedLocalReconciliationContinuity>> {
    let reference = match &body.credential {
        CredentialState::AcquisitionOutcomeUnknown {
            local_reconciliation: Some(reference),
            ..
        } => reference,
        _ => {
            if body.local_reconciliation_continuity_evidence.is_some()
                || body
                    .local_reconciliation_ledger_witness_evidence
                    .is_some()
                || body
                    .local_reconciliation_genesis_absence_evidence
                    .is_some()
            {
                return Err(ContractError::new(
                    "unexpected_local_reconciliation_continuity",
                    "finalizedEnvelope.body",
                    "continuity, witness, and genesis evidence are forbidden outside local acquisition uncertainty",
                ));
            }
            return Ok(None);
        }
    };
    let current = current.ok_or_else(|| {
        ContractError::new(
            "missing_exact_local_reconciliation_record",
            "body.credential.localReconciliation",
            "continuity verification requires the exact current record first",
        )
    })?;
    let pin = context
        .reconciliation_witness_authority()
        .ok_or_else(|| {
            ContractError::new(
                "missing_reconciliation_witness_authority_pin",
                "verificationContext.reconciliationWitnessAuthority",
                "local acquisition uncertainty requires one proof-independent store, cluster, credential-ledger namespace, and exact GENESIS state pin",
            )
        })?;
    let continuity_wire = body
        .local_reconciliation_continuity_evidence
        .clone()
        .ok_or_else(|| {
            ContractError::new(
                "missing_local_reconciliation_continuity",
                "body.localReconciliationContinuityEvidence",
                "local acquisition uncertainty requires signed continuity evidence",
            )
        })?;
    let witness_wire = body
        .local_reconciliation_ledger_witness_evidence
        .clone()
        .ok_or_else(|| {
            ContractError::new(
                "missing_local_reconciliation_ledger_witness",
                "body.localReconciliationLedgerWitnessEvidence",
                "local acquisition uncertainty requires the exact signed store quorum/transparency witness",
            )
        })?;
    for (value, path) in [
        (
            &reference.continuity_evidence_sha256,
            "body.credential.localReconciliation.continuityEvidenceSha256",
        ),
        (
            &reference.continuity_evidence_retrieval_id,
            "body.credential.localReconciliation.continuityEvidenceRetrievalId",
        ),
        (
            &reference.continuity_persistence_receipt_sha256,
            "body.credential.localReconciliation.continuityPersistenceReceiptSha256",
        ),
        (
            &reference.continuity_retrieval_proof_sha256,
            "body.credential.localReconciliation.continuityRetrievalProofSha256",
        ),
        (
            &reference.ledger_witness_sha256,
            "body.credential.localReconciliation.ledgerWitnessSha256",
        ),
        (
            &reference.ledger_witness_retrieval_id,
            "body.credential.localReconciliation.ledgerWitnessRetrievalId",
        ),
        (
            &reference.ledger_witness_persistence_receipt_sha256,
            "body.credential.localReconciliation.ledgerWitnessPersistenceReceiptSha256",
        ),
        (
            &reference.ledger_witness_retrieval_proof_sha256,
            "body.credential.localReconciliation.ledgerWitnessRetrievalProofSha256",
        ),
        (
            &reference.predecessor_proof_sha256,
            "body.credential.localReconciliation.predecessorProofSha256",
        ),
        (
            &reference.store_transition_sha256,
            "body.credential.localReconciliation.storeTransitionSha256",
        ),
        (
            &reference.quorum_certificate_sha256,
            "body.credential.localReconciliation.quorumCertificateSha256",
        ),
        (
            &reference.transparency_log_proof_sha256,
            "body.credential.localReconciliation.transparencyLogProofSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path, maximum) in [
        (
            reference.continuity_evidence_byte_length,
            "body.credential.localReconciliation.continuityEvidenceByteLength",
            MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES as u64,
        ),
        (
            reference.ledger_witness_byte_length,
            "body.credential.localReconciliation.ledgerWitnessByteLength",
            MAX_LOCAL_RECONCILIATION_WITNESS_BYTES as u64,
        ),
    ] {
        validate_safe_integer(value, path)?;
        if value == 0 || value > maximum {
            return Err(ContractError::new(
                "local_reconciliation_evidence_size_out_of_bounds",
                path,
                "exact signed reconciliation evidence is empty or exceeds its closed byte bound",
            ));
        }
    }
    let retrieved = persistence.retrieve_exact_local_reconciliation_continuity(
        &reference.record_id,
        &reference.continuity_evidence_retrieval_id,
        &reference.ledger_witness_retrieval_id,
    )?;
    if retrieved.current_record_id != current.record_id {
        return Err(ContractError::new(
            "local_reconciliation_continuity_subject_mismatch",
            "localReconciliationContinuityRetrieval.currentRecordId",
            "trusted continuity retrieval returned a different current record",
        ));
    }
    let continuity_length = validate_retrieved_local_reconciliation_evidence(
        &retrieved.continuity_evidence,
        &reference.continuity_evidence_retrieval_id,
        &reference.continuity_persistence_receipt_sha256,
        &reference.continuity_retrieval_proof_sha256,
        MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES,
        "localReconciliationContinuityRetrieval.continuityEvidence",
    )?;
    let continuity_exact = canonical_jcs_bytes(&continuity_wire)?;
    if retrieved.continuity_evidence.exact_evidence_bytes
            != continuity_exact
        || continuity_length != reference.continuity_evidence_byte_length
        || continuity_wire.evidence_sha256
            != reference.continuity_evidence_sha256
        || local_reconciliation_evidence_retrieval_id(
            LOCAL_RECONCILIATION_CONTINUITY_RETRIEVAL_ID_DOMAIN,
            &current.record_id,
            &continuity_wire.evidence_sha256,
            continuity_length,
        )? != reference.continuity_evidence_retrieval_id
    {
        return Err(ContractError::new(
            "local_reconciliation_continuity_exact_bytes_mismatch",
            "body.localReconciliationContinuityEvidence",
            "continuity evidence must equal the exact immutable retrieved bytes and derived digest/length/retrieval identity",
        ));
    }
    let continuity =
        verify_evidence(continuity_wire, context, evidence_verifier)?;

    let witness_length = validate_retrieved_local_reconciliation_evidence(
        &retrieved.ledger_witness_evidence,
        &reference.ledger_witness_retrieval_id,
        &reference.ledger_witness_persistence_receipt_sha256,
        &reference.ledger_witness_retrieval_proof_sha256,
        MAX_LOCAL_RECONCILIATION_WITNESS_BYTES,
        "localReconciliationContinuityRetrieval.ledgerWitnessEvidence",
    )?;
    let witness_exact = canonical_jcs_bytes(&witness_wire)?;
    if retrieved.ledger_witness_evidence.exact_evidence_bytes != witness_exact
        || witness_length != reference.ledger_witness_byte_length
        || witness_wire.evidence_sha256 != reference.ledger_witness_sha256
        || local_reconciliation_evidence_retrieval_id(
            LOCAL_RECONCILIATION_LEDGER_WITNESS_RETRIEVAL_ID_DOMAIN,
            &current.record_id,
            &witness_wire.evidence_sha256,
            witness_length,
        )? != reference.ledger_witness_retrieval_id
    {
        return Err(ContractError::new(
            "local_reconciliation_witness_exact_bytes_mismatch",
            "body.localReconciliationLedgerWitnessEvidence",
            "ledger witness must equal the exact immutable retrieved bytes and derived digest/length/retrieval identity",
        ));
    }
    let ledger_witness =
        verify_evidence(witness_wire, context, evidence_verifier)?;

    let continuity_payload = &continuity.wire().payload;
    let witness_payload = &ledger_witness.wire().payload;
    if continuity_payload.attempt_id != body.attempt_id
        || continuity_payload.current_record_id != current.record_id
        || continuity_payload.current_record_sha256 != current.record_sha256
        || continuity_payload.current_record_byte_length
            != current.record_byte_length
        || continuity_payload.current_record_retrieval_id
            != current.retrieval_id
        || continuity_payload.current_persistence_receipt_sha256
            != current.persistence_receipt_sha256
        || continuity_payload.current_retrieval_proof_sha256
            != current.retrieval_proof_sha256
        || continuity_payload.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || continuity_payload.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || continuity_payload.predecessor_successor_key_sha256
            != current.record.predecessor_successor_key_sha256
        || continuity_payload.ledger_id != current.record.ledger_id
        || continuity_payload.ledger_sequence
            != current.record.ledger_sequence
        || continuity_payload.ledger_checkpoint_epoch
            != current.record.ledger_checkpoint_epoch
        || continuity_payload.ledger_checkpoint_sha256
            != current.record.ledger_checkpoint_sha256
        || continuity_payload.linearizable_store_id
            != current.record.linearizable_store_id
        || continuity_payload.linearizable_store_cluster_id
            != current.record.linearizable_store_cluster_id
        || continuity_payload.store_transaction_id
            != current.record.store_transaction_id
        || continuity_payload.store_term != current.record.store_term
        || continuity_payload.store_log_index
            != current.record.store_log_index
        || continuity_payload.store_fencing_token
            != current.record.store_fencing_token
        || continuity_payload.ledger_witness_evidence_sha256
            != ledger_witness.wire().evidence_sha256
        || continuity_payload.ledger_witness_byte_length != witness_length
        || continuity_payload.ledger_witness_retrieval_id
            != reference.ledger_witness_retrieval_id
        || continuity_payload.ledger_witness_persistence_receipt_sha256
            != reference.ledger_witness_persistence_receipt_sha256
        || continuity_payload.ledger_witness_retrieval_proof_sha256
            != reference.ledger_witness_retrieval_proof_sha256
        || continuity_payload.custody_authority_key_id
            != current.record.custody_authority_key_id
        || continuity_payload.custody_authority_key_material_sha256
            != current.record.custody_authority_key_material_sha256
        || continuity.wire().key_id
            != continuity_payload.custody_authority_key_id
        || continuity.key_material_sha256()
            != continuity_payload.custody_authority_key_material_sha256
        || witness_payload.attempt_id != body.attempt_id
        || witness_payload.current_record_id != current.record_id
        || witness_payload.current_record_sha256 != current.record_sha256
        || witness_payload.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || witness_payload.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || witness_payload.predecessor_successor_key_sha256
            != current.record.predecessor_successor_key_sha256
        || witness_payload.ledger_id != current.record.ledger_id
        || witness_payload.current_ledger_sequence
            != current.record.ledger_sequence
        || witness_payload.current_checkpoint_sha256
            != current.record.ledger_checkpoint_sha256
        || witness_payload.checkpoint_epoch
            != current.record.ledger_checkpoint_epoch
        || witness_payload.linearizable_store_id
            != current.record.linearizable_store_id
        || witness_payload.linearizable_store_cluster_id
            != current.record.linearizable_store_cluster_id
        || witness_payload.store_transaction_id
            != current.record.store_transaction_id
        || witness_payload.current_store_term != current.record.store_term
        || witness_payload.current_store_log_index
            != current.record.store_log_index
        || witness_payload.current_store_fencing_token
            != current.record.store_fencing_token
        || continuity_payload.store_transition_sha256
            != witness_payload.store_transition_sha256
        || continuity_payload.quorum_certificate_sha256
            != witness_payload.quorum_certificate.certificate_sha256
        || continuity_payload.transparency_log_proof_sha256
            != witness_payload.transparency_log_proof.proof_sha256
        || witness_payload.custody_authority_key_id
            != continuity_payload.custody_authority_key_id
        || witness_payload.custody_authority_key_material_sha256
            != continuity_payload.custody_authority_key_material_sha256
        || witness_payload.trust_checkpoint_sha256
            != continuity_payload.trust_checkpoint_sha256
        || witness_payload.revocation_epoch
            != continuity_payload.revocation_epoch
        || ledger_witness
            .wire()
            .predecessor_evidence_sha256
            .as_deref()
            != Some(continuity.wire().evidence_sha256.as_str())
        || witness_payload.witnessed_at_epoch_ms
            < continuity_payload.signed_at_epoch_ms
        || continuity_payload.signed_at_epoch_ms
            < current.record.created_at_epoch_ms
        || witness_payload.witnessed_at_epoch_ms
            >= current.record.deadline_epoch_ms
    {
        return Err(ContractError::new(
            "local_reconciliation_continuity_binding_mismatch",
            "body.localReconciliationContinuityEvidence",
            "continuity and witness must bind the exact current record, proof-independent credential-ledger namespace and genesis state, predecessor conflict key, immutable receipts, monotonic ledger checkpoint, custody subject, and causal evidence order",
        ));
    }

    let (
        predecessor_record,
        predecessor_recovery,
        genesis_absence,
        predecessor_proof_sha256,
    ) = match &continuity_payload.predecessor {
        LocalReconciliationPredecessorProof::Predecessor {
            record_id,
            record_sha256,
            record_byte_length,
            retrieval_id,
            persistence_receipt_sha256,
            retrieval_proof_sha256,
            recovery_evidence_sha256,
            recovery_evidence_byte_length,
            recovery_evidence_retrieval_id,
            recovery_evidence_persistence_receipt_sha256,
            recovery_evidence_retrieval_proof_sha256,
            rollback_head_sha256,
            ledger_sequence,
            ledger_checkpoint_epoch,
            ledger_checkpoint_sha256,
        } => {
            if body
                .local_reconciliation_genesis_absence_evidence
                .is_some()
                || retrieved.genesis_absence_evidence.is_some()
            {
                return Err(ContractError::new(
                    "local_reconciliation_predecessor_genesis_overlap",
                    "body.localReconciliationGenesisAbsenceEvidence",
                    "predecessor continuity forbids genesis absence evidence",
                ));
            }
            let predecessor_bytes =
                retrieved.predecessor_record.as_ref().ok_or_else(|| {
                    ContractError::new(
                        "missing_exact_local_reconciliation_predecessor",
                        "localReconciliationContinuityRetrieval.predecessorRecord",
                        "predecessor branch requires exact immutable predecessor record retrieval",
                    )
                })?;
            let predecessor = verify_retrieved_local_reconciliation_record(
                predecessor_bytes,
                record_id,
                record_sha256,
                *record_byte_length,
                retrieval_id,
                persistence_receipt_sha256,
                retrieval_proof_sha256,
            )?;
            let predecessor_conflict_key =
                LocalReconciliationConflictKeyCommitment {
                    linearizable_store_id: pin.linearizable_store_id(),
                    linearizable_store_cluster_id:
                        pin.linearizable_store_cluster_id(),
                    credential_ledger_namespace:
                        pin.credential_ledger_namespace(),
                    predecessor_identity: predecessor
                        .record
                        .predecessor_record_id
                        .as_deref()
                        .unwrap_or(LOCAL_RECONCILIATION_GENESIS_MARKER),
                };
            let predecessor_conflict_key_jcs =
                canonical_jcs_bytes(&predecessor_conflict_key)?;
            let predecessor_conflict_key_sha256 = domain_sha256(
                LOCAL_RECONCILIATION_PREDECESSOR_SUCCESSOR_KEY_DOMAIN,
                &[predecessor_conflict_key_jcs.as_slice()],
            )?;
            if predecessor.record.predecessor_successor_key_sha256
                != predecessor_conflict_key_sha256
            {
                return Err(ContractError::new(
                    "predecessor_conflict_key_mismatch",
                    "localReconciliationContinuityRetrieval.predecessorRecord",
                    "retrieved predecessor record conflict key must be verifier-derived from the pinned store, cluster, credential-ledger namespace, and its exact predecessor record ID or fixed GENESIS marker",
                ));
            }
            let predecessor_recovery_bytes = retrieved
                .predecessor_recovery_evidence
                .as_ref()
                .ok_or_else(|| {
                    ContractError::new(
                        "missing_exact_predecessor_recovery_evidence",
                        "localReconciliationContinuityRetrieval.predecessorRecoveryEvidence",
                        "predecessor branch requires exact immutable signed predecessor recovery evidence",
                    )
                })?;
            let predecessor_recovery_length =
                validate_retrieved_local_reconciliation_evidence(
                    predecessor_recovery_bytes,
                    recovery_evidence_retrieval_id,
                    recovery_evidence_persistence_receipt_sha256,
                    recovery_evidence_retrieval_proof_sha256,
                    MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES,
                    "localReconciliationContinuityRetrieval.predecessorRecoveryEvidence",
                )?;
            if predecessor_recovery_length != *recovery_evidence_byte_length
                || local_reconciliation_evidence_retrieval_id(
                    LOCAL_RECONCILIATION_PREDECESSOR_EVIDENCE_RETRIEVAL_ID_DOMAIN,
                    &predecessor.record_id,
                    recovery_evidence_sha256,
                    predecessor_recovery_length,
                )? != *recovery_evidence_retrieval_id
            {
                return Err(ContractError::new(
                    "predecessor_recovery_identity_mismatch",
                    "localReconciliationContinuity.payload.predecessor",
                    "predecessor signed recovery evidence length and retrieval identity must be independently derived",
                ));
            }
            let predecessor_recovery_wire: SignedEvidence<
                LocalReconciliationRecoveryEvidencePayload,
            > = decode_canonical_signed_reconciliation_evidence(
                &predecessor_recovery_bytes.exact_evidence_bytes,
                MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES,
                "localReconciliationContinuityRetrieval.predecessorRecoveryEvidence",
            )?;
            if predecessor_recovery_wire.evidence_sha256
                    != *recovery_evidence_sha256
                || predecessor_recovery_wire.payload.attempt_id
                    != predecessor.record.attempt_id
                || predecessor_recovery_wire.payload.request_sha256
                    != predecessor.record.request_sha256
                || predecessor_recovery_wire.payload.operation_sha256
                    != predecessor.record.operation_sha256
                || predecessor_recovery_wire
                    .payload
                    .authorization_binding_sha256
                    != predecessor.record.authorization_binding_sha256
                || predecessor_recovery_wire
                    .payload
                    .credential_binding_sha256
                    != predecessor.record.credential_binding_sha256
                || predecessor_recovery_wire.payload.provider_id
                    != predecessor.record.provider_id
                || predecessor_recovery_wire.payload.account_id
                    != predecessor.record.account_id
                || predecessor_recovery_wire.payload.credential_ref
                    != predecessor.record.credential_ref
                || predecessor_recovery_wire.payload.credential_version
                    != predecessor.record.credential_version
                || predecessor_recovery_wire.payload.credential_generation
                    != predecessor.record.credential_generation
                || predecessor_recovery_wire.payload.record_id
                    != predecessor.record_id
                || predecessor_recovery_wire.payload.record_sha256
                    != predecessor.record_sha256
                || predecessor_recovery_wire.payload.record_byte_length
                    != predecessor.record_byte_length
                || predecessor_recovery_wire.payload.retrieval_id
                    != predecessor.retrieval_id
                || predecessor_recovery_wire
                    .payload
                    .persistence_receipt_sha256
                    != predecessor.persistence_receipt_sha256
                || predecessor_recovery_wire.payload.retrieval_proof_sha256
                    != predecessor.retrieval_proof_sha256
                || predecessor_recovery_wire.payload.status
                    != predecessor.record.status
                || predecessor_recovery_wire.payload.uncertain_side_effect
                    != predecessor.record.uncertain_side_effect
                || predecessor_recovery_wire.payload.created_at_epoch_ms
                    != predecessor.record.created_at_epoch_ms
                || predecessor_recovery_wire.payload.deadline_epoch_ms
                    != predecessor.record.deadline_epoch_ms
                || predecessor_recovery_wire.payload.rollback_state_epoch
                    != predecessor.record.rollback_state_epoch
                || predecessor_recovery_wire.payload.rollback_head_sha256
                    != predecessor.record.rollback_head_sha256
                || predecessor_recovery_wire
                    .payload
                    .credential_ledger_namespace
                    != predecessor.record.credential_ledger_namespace
                || predecessor_recovery_wire
                    .payload
                    .pinned_genesis_state_sha256
                    != predecessor.record.pinned_genesis_state_sha256
                || predecessor_recovery_wire
                    .payload
                    .predecessor_successor_key_sha256
                    != predecessor
                        .record
                        .predecessor_successor_key_sha256
                || predecessor_recovery_wire.payload.predecessor_record_id
                    != predecessor.record.predecessor_record_id
                || predecessor_recovery_wire
                    .payload
                    .predecessor_record_sha256
                    != predecessor.record.predecessor_record_sha256
                || predecessor_recovery_wire
                    .payload
                    .predecessor_rollback_head_sha256
                    != predecessor.record.predecessor_rollback_head_sha256
                || predecessor_recovery_wire
                    .payload
                    .linearizable_store_id
                    != predecessor.record.linearizable_store_id
                || predecessor_recovery_wire
                    .payload
                    .linearizable_store_cluster_id
                    != predecessor.record.linearizable_store_cluster_id
                || predecessor_recovery_wire.payload.store_transaction_id
                    != predecessor.record.store_transaction_id
                || predecessor_recovery_wire.payload.store_term
                    != predecessor.record.store_term
                || predecessor_recovery_wire.payload.store_log_index
                    != predecessor.record.store_log_index
                || predecessor_recovery_wire.payload.store_fencing_token
                    != predecessor.record.store_fencing_token
                || predecessor_recovery_wire
                    .payload
                    .custody_authority_key_id
                    != predecessor.record.custody_authority_key_id
                || predecessor_recovery_wire
                    .payload
                    .custody_authority_key_material_sha256
                    != predecessor
                        .record
                        .custody_authority_key_material_sha256
                || predecessor_recovery_wire.payload.trust_checkpoint_sha256
                    != predecessor.record.trust_checkpoint_sha256
                || predecessor_recovery_wire.payload.revocation_epoch
                    != predecessor.record.revocation_epoch
            {
                return Err(ContractError::new(
                    "predecessor_recovery_binding_mismatch",
                    "localReconciliationContinuityRetrieval.predecessorRecoveryEvidence",
                    "exact signed predecessor recovery evidence must bind the exact retrieved predecessor record and storage proofs",
                ));
            }
            let predecessor_recovery = verify_evidence(
                predecessor_recovery_wire,
                context,
                evidence_verifier,
            )?;
            if predecessor_recovery.wire().key_id
                    != pin.recovery_authority_key_id()
                || predecessor_recovery.key_material_sha256()
                    != pin.recovery_authority_key_material_sha256()
                || predecessor_recovery.wire().key_id
                    == predecessor.record.custody_authority_key_id
                || predecessor_recovery.key_material_sha256()
                    == predecessor
                        .record
                        .custody_authority_key_material_sha256
                || predecessor_recovery
                    .revoked_at_epoch_ms()
                    .is_some_and(|revoked_at| {
                        revoked_at <= context.trusted_now_epoch_ms()
                    })
                || predecessor_recovery
                    .wire()
                    .payload
                    .recovery_authority_key_id
                    != pin.recovery_authority_key_id()
                || predecessor_recovery
                    .wire()
                    .payload
                    .recovery_authority_key_material_sha256
                    != pin.recovery_authority_key_material_sha256()
                || predecessor_recovery
                    .wire()
                    .payload
                    .recovery_authority_trust_checkpoint_sha256
                    != context.current_trust_checkpoint_sha256()
                || predecessor_recovery
                    .wire()
                    .payload
                    .recovery_authority_revocation_epoch
                    != context.current_revocation_epoch()
                || predecessor.record.credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || predecessor.record.ledger_id
                    != pin.credential_ledger_namespace
                || predecessor.record.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || predecessor_recovery
                    .wire()
                    .payload
                    .credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || predecessor_recovery
                    .wire()
                    .payload
                    .pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || current.record.predecessor_record_id.as_deref()
                    != Some(predecessor.record_id.as_str())
                || current.record.predecessor_record_sha256.as_deref()
                    != Some(predecessor.record_sha256.as_str())
                || current.record.predecessor_rollback_head_sha256
                    != predecessor.record.rollback_head_sha256
                || current.record.predecessor_ledger_checkpoint_sha256
                    != predecessor.record.ledger_checkpoint_sha256
                || current.record.ledger_id != predecessor.record.ledger_id
                || current.record.linearizable_store_id
                    != predecessor.record.linearizable_store_id
                || current.record.linearizable_store_cluster_id
                    != predecessor.record.linearizable_store_cluster_id
                || current.record.store_transaction_id
                    == predecessor.record.store_transaction_id
                || current.record.credential_binding_sha256
                    != predecessor.record.credential_binding_sha256
                || current.record.provider_id != predecessor.record.provider_id
                || current.record.account_id != predecessor.record.account_id
                || current.record.credential_ref
                    != predecessor.record.credential_ref
                || current.record.credential_version
                    != predecessor.record.credential_version
                || current.record.credential_generation
                    != predecessor.record.credential_generation
                || predecessor.record.ledger_sequence != *ledger_sequence
                || predecessor.record.ledger_checkpoint_epoch
                    != *ledger_checkpoint_epoch
                || predecessor.record.ledger_checkpoint_sha256
                    != *ledger_checkpoint_sha256
                || predecessor.record.rollback_head_sha256
                    != *rollback_head_sha256
                || predecessor.record.ledger_sequence.checked_add(1)
                    != Some(current.record.ledger_sequence)
                || predecessor.record.ledger_checkpoint_epoch
                    >= current.record.ledger_checkpoint_epoch
                || witness_payload.genesis_absence
                || witness_payload.predecessor_record_id.as_deref()
                    != Some(predecessor.record_id.as_str())
                || witness_payload.predecessor_record_sha256.as_deref()
                    != Some(predecessor.record_sha256.as_str())
                || witness_payload.predecessor_ledger_sequence
                    != predecessor.record.ledger_sequence
                || witness_payload.predecessor_checkpoint_sha256
                    != predecessor.record.ledger_checkpoint_sha256
                || witness_payload.predecessor_store_term
                    != predecessor.record.store_term
                || witness_payload.predecessor_store_log_index
                    != predecessor.record.store_log_index
                || witness_payload.predecessor_store_fencing_token
                    != predecessor.record.store_fencing_token
            {
                return Err(ContractError::new(
                    "local_reconciliation_predecessor_continuity_mismatch",
                    "localReconciliationContinuity.payload.predecessor",
                    "exact predecessor record, signed recovery evidence, rollback head, ledger sequence, checkpoint, and store witness must form one immediate non-forking chain",
                ));
            }
            (
                Some(predecessor),
                Some(predecessor_recovery),
                None,
                recovery_evidence_sha256.clone(),
            )
        }
        LocalReconciliationPredecessorProof::Genesis {
            genesis_absence_evidence_sha256,
            genesis_absence_evidence_byte_length,
            genesis_absence_evidence_retrieval_id,
            genesis_absence_persistence_receipt_sha256,
            genesis_absence_retrieval_proof_sha256,
        } => {
            if retrieved.predecessor_record.is_some()
                || retrieved.predecessor_recovery_evidence.is_some()
            {
                return Err(ContractError::new(
                    "local_reconciliation_genesis_predecessor_overlap",
                    "localReconciliationContinuityRetrieval",
                    "genesis branch forbids predecessor record and recovery evidence",
                ));
            }
            let genesis_wire = body
                .local_reconciliation_genesis_absence_evidence
                .clone()
                .ok_or_else(|| {
                    ContractError::new(
                        "missing_local_reconciliation_genesis_absence",
                        "body.localReconciliationGenesisAbsenceEvidence",
                        "genesis continuity requires separately signed absence evidence",
                    )
                })?;
            let genesis_bytes = retrieved
                .genesis_absence_evidence
                .as_ref()
                .ok_or_else(|| {
                    ContractError::new(
                        "missing_exact_local_reconciliation_genesis_absence",
                        "localReconciliationContinuityRetrieval.genesisAbsenceEvidence",
                        "genesis branch requires exact immutable signed absence evidence retrieval",
                    )
                })?;
            let genesis_length =
                validate_retrieved_local_reconciliation_evidence(
                    genesis_bytes,
                    genesis_absence_evidence_retrieval_id,
                    genesis_absence_persistence_receipt_sha256,
                    genesis_absence_retrieval_proof_sha256,
                    MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES,
                    "localReconciliationContinuityRetrieval.genesisAbsenceEvidence",
                )?;
            if canonical_jcs_bytes(&genesis_wire)?
                    != genesis_bytes.exact_evidence_bytes
                || genesis_length != *genesis_absence_evidence_byte_length
                || genesis_wire.evidence_sha256
                    != *genesis_absence_evidence_sha256
                || local_reconciliation_evidence_retrieval_id(
                    LOCAL_RECONCILIATION_GENESIS_EVIDENCE_RETRIEVAL_ID_DOMAIN,
                    &current.record_id,
                    genesis_absence_evidence_sha256,
                    genesis_length,
                )? != *genesis_absence_evidence_retrieval_id
            {
                return Err(ContractError::new(
                    "local_reconciliation_genesis_exact_bytes_mismatch",
                    "body.localReconciliationGenesisAbsenceEvidence",
                    "signed genesis absence must equal exact immutable retrieved bytes and its independently derived identity",
                ));
            }
            let genesis =
                verify_evidence(genesis_wire, context, evidence_verifier)?;
            let genesis_payload = &genesis.wire().payload;
            if current.record.predecessor_record_id.is_some()
                || current.record.predecessor_record_sha256.is_some()
                || current.record.ledger_sequence != 1
                || current.record.credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || current.record.ledger_id
                    != pin.credential_ledger_namespace
                || current.record.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || current.record.predecessor_successor_key_sha256
                    != pin.genesis_predecessor_successor_key_sha256
                || witness_payload.predecessor_record_id.is_some()
                || witness_payload.predecessor_record_sha256.is_some()
                || !witness_payload.genesis_absence
                || witness_payload.predecessor_ledger_sequence != 0
                || witness_payload.credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || witness_payload.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || witness_payload.predecessor_successor_key_sha256
                    != pin.genesis_predecessor_successor_key_sha256
                || genesis_payload.attempt_id != body.attempt_id
                || genesis_payload.current_record_id != current.record_id
                || genesis_payload.credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || genesis_payload.ledger_id
                    != pin.credential_ledger_namespace
                || genesis_payload.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || genesis_payload.predecessor_successor_key_sha256
                    != pin.genesis_predecessor_successor_key_sha256
                || continuity_payload.credential_ledger_namespace
                    != pin.credential_ledger_namespace
                || continuity_payload.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
                || continuity_payload.predecessor_successor_key_sha256
                    != pin.genesis_predecessor_successor_key_sha256
                || genesis_payload.current_checkpoint_sha256
                    != current.record.ledger_checkpoint_sha256
                || genesis_payload.checkpoint_epoch
                    != current.record.ledger_checkpoint_epoch
                || genesis_payload.predecessor_checkpoint_sha256
                    != current.record.predecessor_ledger_checkpoint_sha256
                || witness_payload.predecessor_checkpoint_sha256
                    != genesis_payload.predecessor_checkpoint_sha256
                || genesis.wire().key_id
                    != continuity_payload.custody_authority_key_id
                || genesis.key_material_sha256()
                    != continuity_payload
                        .custody_authority_key_material_sha256
                || genesis_payload.custody_authority_key_id
                    != continuity_payload.custody_authority_key_id
                || genesis_payload.custody_authority_key_material_sha256
                    != continuity_payload
                        .custody_authority_key_material_sha256
                || genesis_payload.trust_checkpoint_sha256
                    != continuity_payload.trust_checkpoint_sha256
                || genesis_payload.revocation_epoch
                    != continuity_payload.revocation_epoch
                || continuity
                    .wire()
                    .predecessor_evidence_sha256
                    .as_deref()
                    != Some(genesis.wire().evidence_sha256.as_str())
            {
                return Err(ContractError::new(
                    "local_reconciliation_genesis_continuity_mismatch",
                    "body.localReconciliationGenesisAbsenceEvidence",
                    "genesis absence, current record, continuity, CAS witness, and checkpoint must use the one externally pinned credential-ledger namespace, exact GENESIS state, and fixed GENESIS conflict key",
                ));
            }
            (
                None,
                None,
                Some(genesis),
                genesis_absence_evidence_sha256.clone(),
            )
        }
    };
    if reference.predecessor_proof_sha256 != predecessor_proof_sha256 {
        return Err(ContractError::new(
            "local_reconciliation_predecessor_proof_mismatch",
            "body.credential.localReconciliation.predecessorProofSha256",
            "credential recovery descriptor must bind the exact predecessor recovery evidence or signed genesis absence evidence",
        ));
    }
    let store_witness = verify_local_reconciliation_store_witness(
        context,
        evidence_verifier,
        current,
        predecessor_record.as_ref(),
        &continuity,
        &ledger_witness,
    )?;
    if reference.store_transition_sha256
            != store_witness.store_transition_sha256
        || reference.quorum_certificate_sha256
            != store_witness.quorum_certificate_sha256
        || reference.transparency_log_proof_sha256
            != store_witness.transparency_log_proof_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_store_witness_reference_mismatch",
            "body.credential.localReconciliation",
            "credential recovery descriptor must bind the verifier-derived CAS transition, quorum certificate, and externally anchored transparency proof",
        ));
    }
    Ok(Some(VerifiedLocalReconciliationContinuity {
        continuity,
        ledger_witness,
        predecessor_record,
        predecessor_recovery,
        genesis_absence,
        predecessor_proof_sha256,
        store_transition_sha256:
            store_witness.store_transition_sha256,
        quorum_certificate_sha256:
            store_witness.quorum_certificate_sha256,
        transparency_log_proof_sha256:
            store_witness.transparency_log_proof_sha256,
        quorum_member_key_ids:
            store_witness.quorum_member_key_ids,
        quorum_member_key_material_sha256:
            store_witness.quorum_member_key_material_sha256,
        transparency_operator_key_id:
            store_witness.transparency_operator_key_id,
        transparency_operator_key_material_sha256:
            store_witness.transparency_operator_key_material_sha256,
    }))
}

fn verify_local_reconciliation_store_witness<
    V: EvidenceSignatureVerifier,
>(
    context: &VerificationContext<'_>,
    verifier: &V,
    current: &VerifiedLocalReconciliationRecord,
    predecessor: Option<&VerifiedLocalReconciliationRecord>,
    continuity: &VerifiedEvidence<LocalReconciliationContinuityEvidencePayload>,
    witness: &VerifiedEvidence<LocalReconciliationLedgerWitness>,
) -> ContractResult<VerifiedLocalReconciliationStoreWitness> {
    let pin = context
        .reconciliation_witness_authority()
        .ok_or_else(|| {
            ContractError::new(
                "missing_reconciliation_witness_authority_pin",
                "verificationContext.reconciliationWitnessAuthority",
                "local acquisition uncertainty requires a proof-independent linearizable-store and transparency-log authority pin",
            )
        })?;
    let payload = &witness.wire().payload;
    let continuity_payload = &continuity.wire().payload;
    let (
        predecessor_record_id,
        predecessor_record_sha256,
        predecessor_ledger_sequence,
        predecessor_checkpoint_sha256,
        predecessor_rollback_head_sha256,
        predecessor_store_term,
        predecessor_store_log_index,
        predecessor_store_fencing_token,
    ) = match predecessor {
        Some(predecessor) => (
            Some(predecessor.record_id.as_str()),
            Some(predecessor.record_sha256.as_str()),
            predecessor.record.ledger_sequence,
            predecessor.record.ledger_checkpoint_sha256.as_str(),
            predecessor.record.rollback_head_sha256.as_str(),
            predecessor.record.store_term,
            predecessor.record.store_log_index,
            predecessor.record.store_fencing_token,
        ),
        None => (
            None,
            None,
            0,
            current
                .record
                .predecessor_ledger_checkpoint_sha256
                .as_str(),
            current
                .record
                .predecessor_rollback_head_sha256
                .as_str(),
            0,
            0,
            0,
        ),
    };
    let predecessor_identity = predecessor_record_id
        .unwrap_or(LOCAL_RECONCILIATION_GENESIS_MARKER);
    let conflict_key_commitment =
        LocalReconciliationConflictKeyCommitment {
            linearizable_store_id: pin.linearizable_store_id(),
            linearizable_store_cluster_id:
                pin.linearizable_store_cluster_id(),
            credential_ledger_namespace:
                pin.credential_ledger_namespace(),
            predecessor_identity,
        };
    let conflict_key_jcs = canonical_jcs_bytes(&conflict_key_commitment)?;
    let predecessor_successor_key_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_PREDECESSOR_SUCCESSOR_KEY_DOMAIN,
        &[conflict_key_jcs.as_slice()],
    )?;
    if current.record.linearizable_store_id != pin.linearizable_store_id
        || current.record.linearizable_store_cluster_id
            != pin.linearizable_store_cluster_id
        || current.record.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || current.record.ledger_id != pin.credential_ledger_namespace
        || current.record.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || current.record.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || predecessor.is_some_and(|value| {
            value.record.credential_ledger_namespace
                != pin.credential_ledger_namespace
                || value.record.ledger_id
                    != pin.credential_ledger_namespace
                || value.record.pinned_genesis_state_sha256
                    != pin.pinned_genesis_state_sha256
        })
        || payload.linearizable_store_id != pin.linearizable_store_id
        || payload.linearizable_store_cluster_id
            != pin.linearizable_store_cluster_id
        || payload.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || payload.ledger_id != pin.credential_ledger_namespace
        || payload.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || payload.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || continuity_payload.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || continuity_payload.ledger_id
            != pin.credential_ledger_namespace
        || continuity_payload.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || continuity_payload.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || (predecessor.is_none()
            && predecessor_successor_key_sha256
                != pin.genesis_predecessor_successor_key_sha256)
        || payload.predecessor_store_term != predecessor_store_term
        || payload.predecessor_store_log_index
            != predecessor_store_log_index
        || payload.predecessor_store_fencing_token
            != predecessor_store_fencing_token
        || payload.current_store_term != current.record.store_term
        || payload.current_store_log_index != current.record.store_log_index
        || payload.current_store_fencing_token
            != current.record.store_fencing_token
        || current.record.store_log_index
            <= predecessor_store_log_index
        || current.record.store_fencing_token
            <= predecessor_store_fencing_token
        || current.record.store_term < predecessor_store_term
    {
        return Err(ContractError::new(
            "local_reconciliation_store_pin_or_monotonicity_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload",
            "witness must use the one externally pinned store, cluster, credential-ledger namespace, exact GENESIS state or predecessor record conflict key, and strictly advance log index and fencing token without regressing term",
        ));
    }

    let expected_predecessor_sha256 = match predecessor {
        Some(predecessor) => {
            let predecessor_state =
                LocalReconciliationStoreStateCommitment {
                    linearizable_store_id:
                        pin.linearizable_store_id(),
                    linearizable_store_cluster_id:
                        pin.linearizable_store_cluster_id(),
                    credential_ledger_namespace:
                        pin.credential_ledger_namespace(),
                    pinned_genesis_state_sha256:
                        pin.pinned_genesis_state_sha256(),
                    predecessor_successor_key_sha256: predecessor
                        .record
                        .predecessor_successor_key_sha256
                        .as_str(),
                    ledger_id: pin.credential_ledger_namespace(),
                    record_id: predecessor_record_id,
                    record_sha256: predecessor_record_sha256,
                    ledger_sequence: predecessor_ledger_sequence,
                    ledger_checkpoint_sha256:
                        predecessor_checkpoint_sha256,
                    rollback_head_sha256:
                        predecessor_rollback_head_sha256,
                    store_term: predecessor_store_term,
                    store_log_index: predecessor_store_log_index,
                    store_fencing_token:
                        predecessor_store_fencing_token,
                };
            let predecessor_state_jcs =
                canonical_jcs_bytes(&predecessor_state)?;
            domain_sha256(
                LOCAL_RECONCILIATION_STORE_STATE_DOMAIN,
                &[predecessor_state_jcs.as_slice()],
            )?
        }
        None => pin.pinned_genesis_state_sha256().to_string(),
    };
    let successor_state = LocalReconciliationStoreStateCommitment {
        linearizable_store_id: pin.linearizable_store_id(),
        linearizable_store_cluster_id:
            pin.linearizable_store_cluster_id(),
        credential_ledger_namespace:
            pin.credential_ledger_namespace(),
        pinned_genesis_state_sha256:
            pin.pinned_genesis_state_sha256(),
        predecessor_successor_key_sha256:
            predecessor_successor_key_sha256.as_str(),
        ledger_id: pin.credential_ledger_namespace(),
        record_id: Some(current.record_id.as_str()),
        record_sha256: Some(current.record_sha256.as_str()),
        ledger_sequence: current.record.ledger_sequence,
        ledger_checkpoint_sha256:
            current.record.ledger_checkpoint_sha256.as_str(),
        rollback_head_sha256: current.record.rollback_head_sha256.as_str(),
        store_term: current.record.store_term,
        store_log_index: current.record.store_log_index,
        store_fencing_token: current.record.store_fencing_token,
    };
    let successor_state_jcs = canonical_jcs_bytes(&successor_state)?;
    let expected_successor_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_STORE_STATE_DOMAIN,
        &[successor_state_jcs.as_slice()],
    )?;
    if payload.cas_expected_predecessor_sha256
            != expected_predecessor_sha256
        || payload.cas_observed_predecessor_sha256
            != expected_predecessor_sha256
        || payload.cas_successor_sha256 != expected_successor_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_cas_state_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload",
            "CAS expected and observed predecessor must equal the verifier-derived predecessor state and successor must equal the exact retrieved current state",
        ));
    }

    let transition = LocalReconciliationStoreTransitionCommitment {
        attempt_id: current.record.attempt_id.as_str(),
        linearizable_store_id: pin.linearizable_store_id(),
        linearizable_store_cluster_id:
            pin.linearizable_store_cluster_id(),
        credential_ledger_namespace:
            pin.credential_ledger_namespace(),
        pinned_genesis_state_sha256:
            pin.pinned_genesis_state_sha256(),
        predecessor_successor_key_sha256:
            predecessor_successor_key_sha256.as_str(),
        store_transaction_id:
            current.record.store_transaction_id.as_str(),
        ledger_id: pin.credential_ledger_namespace(),
        predecessor_record_id,
        predecessor_record_sha256,
        successor_record_id: current.record_id.as_str(),
        successor_record_sha256: current.record_sha256.as_str(),
        predecessor_ledger_sequence,
        successor_ledger_sequence: current.record.ledger_sequence,
        predecessor_checkpoint_sha256,
        successor_checkpoint_sha256:
            current.record.ledger_checkpoint_sha256.as_str(),
        predecessor_store_term,
        predecessor_store_log_index,
        predecessor_store_fencing_token,
        successor_store_term: current.record.store_term,
        successor_store_log_index: current.record.store_log_index,
        successor_store_fencing_token: current.record.store_fencing_token,
        cas_expected_predecessor_sha256:
            expected_predecessor_sha256.as_str(),
        cas_observed_predecessor_sha256:
            expected_predecessor_sha256.as_str(),
        cas_successor_sha256: expected_successor_sha256.as_str(),
    };
    let transition_jcs = canonical_jcs_bytes(&transition)?;
    let store_transition_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_STORE_TRANSITION_DOMAIN,
        &[transition_jcs.as_slice()],
    )?;
    if payload.store_transition_sha256 != store_transition_sha256
        || continuity_payload.store_transition_sha256
            != store_transition_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_store_transition_digest_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload.storeTransitionSha256",
            "store transition digest must be recomputed from the full exact predecessor-to-successor CAS tuple",
        ));
    }

    let certificate = &payload.quorum_certificate;
    if certificate.linearizable_store_id
            != current.record.linearizable_store_id
        || certificate.linearizable_store_cluster_id
            != current.record.linearizable_store_cluster_id
        || certificate.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || certificate.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || certificate.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || certificate.store_transaction_id
            != current.record.store_transaction_id
        || certificate.store_transition_sha256
            != store_transition_sha256
        || certificate.store_term != current.record.store_term
        || certificate.store_log_index != current.record.store_log_index
        || certificate.store_fencing_token
            != current.record.store_fencing_token
        || certificate.quorum_threshold != pin.quorum_threshold
    {
        return Err(ContractError::new(
            "local_reconciliation_quorum_tuple_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload.quorumCertificate",
            "quorum certificate must repeat the exact pinned store, transaction, transition, term, log index, fencing token, and threshold",
        ));
    }
    let certificate_commitment =
        LocalReconciliationQuorumCertificateCommitment {
            linearizable_store_id:
                certificate.linearizable_store_id.as_str(),
            linearizable_store_cluster_id:
                certificate.linearizable_store_cluster_id.as_str(),
            credential_ledger_namespace:
                certificate.credential_ledger_namespace.as_str(),
            pinned_genesis_state_sha256:
                certificate.pinned_genesis_state_sha256.as_str(),
            predecessor_successor_key_sha256: certificate
                .predecessor_successor_key_sha256
                .as_str(),
            store_transaction_id:
                certificate.store_transaction_id.as_str(),
            store_transition_sha256:
                certificate.store_transition_sha256.as_str(),
            store_term: certificate.store_term,
            store_log_index: certificate.store_log_index,
            store_fencing_token: certificate.store_fencing_token,
            quorum_threshold: certificate.quorum_threshold,
            members: certificate.members.as_slice(),
        };
    let certificate_jcs =
        canonical_jcs_bytes(&certificate_commitment)?;
    let quorum_certificate_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_QUORUM_CERTIFICATE_DOMAIN,
        &[certificate_jcs.as_slice()],
    )?;
    if certificate.certificate_sha256 != quorum_certificate_sha256
        || continuity_payload.quorum_certificate_sha256
            != quorum_certificate_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_quorum_certificate_digest_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload.quorumCertificate.certificateSha256",
            "quorum certificate digest must be recomputed over the exact ordered member signatures and full store tuple",
        ));
    }

    let quorum_purpose = ReconciliationQuorumMemberVerificationPurpose {
        verification_purpose: context.purpose(),
        linearizable_store_id:
            current.record.linearizable_store_id.as_str(),
        linearizable_store_cluster_id:
            current.record.linearizable_store_cluster_id.as_str(),
        credential_ledger_namespace:
            pin.credential_ledger_namespace(),
        pinned_genesis_state_sha256:
            pin.pinned_genesis_state_sha256(),
        predecessor_successor_key_sha256:
            predecessor_successor_key_sha256.as_str(),
        store_transaction_id:
            current.record.store_transaction_id.as_str(),
        store_transition_sha256: store_transition_sha256.as_str(),
        predecessor_record_id,
        predecessor_record_sha256,
        successor_record_id: current.record_id.as_str(),
        successor_record_sha256: current.record_sha256.as_str(),
        cas_expected_predecessor_sha256:
            expected_predecessor_sha256.as_str(),
        cas_observed_predecessor_sha256:
            expected_predecessor_sha256.as_str(),
        cas_successor_sha256: expected_successor_sha256.as_str(),
        store_term: current.record.store_term,
        store_log_index: current.record.store_log_index,
        store_fencing_token: current.record.store_fencing_token,
        trust_checkpoint_sha256:
            context.current_trust_checkpoint_sha256(),
        revocation_epoch: context.current_revocation_epoch(),
        historical_checkpoint: context.archival_checkpoint(),
        expected_runtime: context.expected_runtime().identity(),
    };
    let mut quorum_member_key_ids = BTreeSet::new();
    let mut quorum_member_key_material_sha256 = BTreeSet::new();
    for member in &certificate.members {
        let pinned_member =
            pin.quorum_member(&member.member_key_id).ok_or_else(|| {
                ContractError::new(
                    "unpinned_reconciliation_quorum_member",
                    "body.localReconciliationLedgerWitnessEvidence.payload.quorumCertificate.members",
                    "every quorum signer must be an independently pinned member of this exact linearizable store",
                )
            })?;
        let signing_commitment =
            LocalReconciliationQuorumMemberSigningCommitment {
                member_key_id: member.member_key_id.as_str(),
                credential_ledger_namespace:
                    pin.credential_ledger_namespace(),
                pinned_genesis_state_sha256:
                    pin.pinned_genesis_state_sha256(),
                predecessor_successor_key_sha256:
                    predecessor_successor_key_sha256.as_str(),
                transition: &transition,
                store_transition_sha256:
                    store_transition_sha256.as_str(),
                store_transaction_id:
                    current.record.store_transaction_id.as_str(),
                store_term: current.record.store_term,
                store_log_index: current.record.store_log_index,
                store_fencing_token:
                    current.record.store_fencing_token,
            };
        let signing_jcs = canonical_jcs_bytes(&signing_commitment)?;
        let signing_message = domain_sha256_bytes(
            LOCAL_RECONCILIATION_QUORUM_MEMBER_SIGNATURE_DOMAIN,
            &[signing_jcs.as_slice()],
        )?;
        let verification =
            verifier.verify_reconciliation_quorum_member_ed25519(
                &quorum_purpose,
                &member.member_key_id,
                signing_message.as_slice(),
                &member.signature,
            );
        validate_digest(
            &verification.trust_checkpoint_sha256,
            "reconciliationQuorumMember.trustCheckpointSha256",
        )?;
        validate_digest(
            &verification.key_material_sha256,
            "reconciliationQuorumMember.keyMaterialSha256",
        )?;
        validate_safe_integer(
            verification.revocation_epoch,
            "reconciliationQuorumMember.revocationEpoch",
        )?;
        if let Some(revoked_at_epoch_ms) =
            verification.revoked_at_epoch_ms
        {
            validate_safe_time(
                revoked_at_epoch_ms,
                "reconciliationQuorumMember.revokedAtEpochMs",
            )?;
        }
        let revocation_invalid = match context.purpose() {
            VerificationPurpose::LiveAuthorization => {
                verification.revoked_at_epoch_ms.is_some()
            }
            VerificationPurpose::ArchivalVerification => verification
                .revoked_at_epoch_ms
                .is_some_and(|revoked_at| {
                    revoked_at <= payload.witnessed_at_epoch_ms
                }),
        };
        if !verification.accepted
            || revocation_invalid
            || member.credential_ledger_namespace
                != pin.credential_ledger_namespace
            || member.pinned_genesis_state_sha256
                != pin.pinned_genesis_state_sha256
            || member.predecessor_successor_key_sha256
                != predecessor_successor_key_sha256
            || verification.trust_checkpoint_sha256
                != context.current_trust_checkpoint_sha256()
            || verification.revocation_epoch
                != context.current_revocation_epoch()
            || verification.key_material_sha256
                != pinned_member.key_material_sha256
            || member.member_key_id == current.record.custody_authority_key_id
            || member.member_key_id == witness.wire().key_id
            || verification.key_material_sha256
                == continuity.key_material_sha256()
            || verification.key_material_sha256
                == witness.key_material_sha256()
            || !quorum_member_key_ids
                .insert(member.member_key_id.clone())
            || !quorum_member_key_material_sha256
                .insert(verification.key_material_sha256)
        {
            return Err(ContractError::new(
                "local_reconciliation_quorum_signature_invalid",
                "body.localReconciliationLedgerWitnessEvidence.payload.quorumCertificate.members",
                "quorum signature must be current, non-revoked, uniquely pinned, over the exact full CAS tuple, and authority-separated from custody and transparency",
            ));
        }
    }
    if quorum_member_key_ids.len()
        < usize::from(pin.quorum_threshold)
    {
        return Err(ContractError::new(
            "local_reconciliation_quorum_not_met",
            "body.localReconciliationLedgerWitnessEvidence.payload.quorumCertificate",
            "verified distinct pinned quorum signatures do not meet the externally configured threshold",
        ));
    }

    let transparency = &payload.transparency_log_proof;
    let leaf_commitment = LocalReconciliationTransparencyLeafCommitment {
        transparency_log_id: transparency.transparency_log_id.as_str(),
        credential_ledger_namespace:
            pin.credential_ledger_namespace(),
        pinned_genesis_state_sha256:
            pin.pinned_genesis_state_sha256(),
        store_transaction_id:
            current.record.store_transaction_id.as_str(),
        store_transition_sha256: store_transition_sha256.as_str(),
        quorum_certificate_sha256:
            quorum_certificate_sha256.as_str(),
        predecessor_successor_key_sha256:
            predecessor_successor_key_sha256.as_str(),
    };
    let leaf_jcs = canonical_jcs_bytes(&leaf_commitment)?;
    let leaf_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_TRANSPARENCY_LEAF_DOMAIN,
        &[leaf_jcs.as_slice()],
    )?;
    if transparency.transparency_log_id != pin.transparency_log_id
        || transparency.transparency_operator_key_id
            != pin.transparency_operator_key_id
        || transparency.credential_ledger_namespace
            != pin.credential_ledger_namespace
        || transparency.pinned_genesis_state_sha256
            != pin.pinned_genesis_state_sha256
        || witness.wire().key_id != pin.transparency_operator_key_id
        || witness.key_material_sha256()
            != pin.transparency_operator_key_material_sha256
        || witness.wire().key_id == current.record.custody_authority_key_id
        || witness.key_material_sha256()
            == continuity.key_material_sha256()
        || transparency.store_transaction_id
            != current.record.store_transaction_id
        || transparency.store_transition_sha256
            != store_transition_sha256
        || transparency.quorum_certificate_sha256
            != quorum_certificate_sha256
        || transparency.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || transparency.leaf_sha256 != leaf_sha256
        || transparency.anchor_checkpoint_root_sha256
            != pin.anchor_checkpoint_root_sha256
        || transparency.anchor_checkpoint_revision
            != pin.anchor_checkpoint_revision
        || transparency.anchor_checkpoint_tree_size
            != pin.anchor_checkpoint_tree_size
        || transparency.current_checkpoint_root_sha256
            != pin.current_checkpoint_root_sha256
        || transparency.current_checkpoint_revision
            != pin.current_checkpoint_revision
        || transparency.current_checkpoint_tree_size
            != pin.current_checkpoint_tree_size
        || transparency.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || transparency.revocation_epoch
            != context.current_revocation_epoch()
        || transparency.signed_at_epoch_ms != payload.witnessed_at_epoch_ms
    {
        return Err(ContractError::new(
            "local_reconciliation_transparency_pin_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload.transparencyLogProof",
            "transparency proof, signer, leaf, anchor, current checkpoint, trust, and revocation state must equal independently pinned and verifier-derived values",
        ));
    }
    let proof_commitment =
        LocalReconciliationTransparencyProofCommitment {
            transparency_log_id: transparency.transparency_log_id.as_str(),
            transparency_operator_key_id:
                transparency.transparency_operator_key_id.as_str(),
            credential_ledger_namespace:
                transparency.credential_ledger_namespace.as_str(),
            pinned_genesis_state_sha256:
                transparency.pinned_genesis_state_sha256.as_str(),
            store_transaction_id:
                transparency.store_transaction_id.as_str(),
            store_transition_sha256:
                transparency.store_transition_sha256.as_str(),
            quorum_certificate_sha256:
                transparency.quorum_certificate_sha256.as_str(),
            predecessor_successor_key_sha256:
                transparency.predecessor_successor_key_sha256.as_str(),
            leaf_sha256: transparency.leaf_sha256.as_str(),
            leaf_index: transparency.leaf_index,
            anchor_checkpoint_root_sha256:
                transparency.anchor_checkpoint_root_sha256.as_str(),
            anchor_checkpoint_revision:
                transparency.anchor_checkpoint_revision,
            anchor_checkpoint_tree_size:
                transparency.anchor_checkpoint_tree_size,
            current_checkpoint_root_sha256:
                transparency.current_checkpoint_root_sha256.as_str(),
            current_checkpoint_revision:
                transparency.current_checkpoint_revision,
            current_checkpoint_tree_size:
                transparency.current_checkpoint_tree_size,
            inclusion_path_sha256:
                transparency.inclusion_path_sha256.as_slice(),
            consistency_path_sha256:
                transparency.consistency_path_sha256.as_slice(),
            conflicting_successor_absence_proof_sha256: transparency
                .conflicting_successor_absence_proof_sha256
                .as_str(),
            trust_checkpoint_sha256:
                transparency.trust_checkpoint_sha256.as_str(),
            revocation_epoch: transparency.revocation_epoch,
            signed_at_epoch_ms: transparency.signed_at_epoch_ms,
            checkpoint_signature:
                transparency.checkpoint_signature.as_str(),
        };
    let proof_jcs = canonical_jcs_bytes(&proof_commitment)?;
    let transparency_log_proof_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_TRANSPARENCY_PROOF_DOMAIN,
        &[proof_jcs.as_slice()],
    )?;
    if transparency.proof_sha256 != transparency_log_proof_sha256
        || continuity_payload.transparency_log_proof_sha256
            != transparency_log_proof_sha256
    {
        return Err(ContractError::new(
            "local_reconciliation_transparency_proof_digest_mismatch",
            "body.localReconciliationLedgerWitnessEvidence.payload.transparencyLogProof.proofSha256",
            "transparency proof digest must be recomputed over the full inclusion, consistency, conflict-absence, checkpoint, and signature tuple",
        ));
    }
    let checkpoint_commitment =
        LocalReconciliationTransparencyCheckpointCommitment {
            transparency_log_id: transparency.transparency_log_id.as_str(),
            transparency_operator_key_id:
                transparency.transparency_operator_key_id.as_str(),
            checkpoint_root_sha256:
                transparency.current_checkpoint_root_sha256.as_str(),
            checkpoint_revision:
                transparency.current_checkpoint_revision,
            checkpoint_tree_size:
                transparency.current_checkpoint_tree_size,
            trust_checkpoint_sha256:
                transparency.trust_checkpoint_sha256.as_str(),
            revocation_epoch: transparency.revocation_epoch,
            signed_at_epoch_ms: transparency.signed_at_epoch_ms,
        };
    let checkpoint_jcs = canonical_jcs_bytes(&checkpoint_commitment)?;
    let checkpoint_signing_message = domain_sha256_bytes(
        LOCAL_RECONCILIATION_TRANSPARENCY_CHECKPOINT_DOMAIN,
        &[checkpoint_jcs.as_slice()],
    )?;
    let transparency_purpose =
        ReconciliationTransparencyVerificationPurpose {
            verification_purpose: context.purpose(),
            proof: transparency,
            predecessor_record_id,
            predecessor_record_sha256,
            successor_record_id: current.record_id.as_str(),
            successor_record_sha256: current.record_sha256.as_str(),
            externally_pinned_authority: pin,
            historical_checkpoint: context.archival_checkpoint(),
            expected_runtime: context.expected_runtime().identity(),
        };
    let transparency_verification =
        verifier.verify_reconciliation_transparency_log(
            &transparency_purpose,
            checkpoint_signing_message.as_slice(),
            &transparency.checkpoint_signature,
        );
    for (value, path) in [
        (
            &transparency_verification
                .transparency_operator_key_material_sha256,
            "reconciliationTransparency.keyMaterialSha256",
        ),
        (
            &transparency_verification.store_transaction_id,
            "reconciliationTransparency.storeTransactionId",
        ),
        (
            &transparency_verification.store_transition_sha256,
            "reconciliationTransparency.storeTransitionSha256",
        ),
        (
            &transparency_verification.predecessor_successor_key_sha256,
            "reconciliationTransparency.predecessorSuccessorKeySha256",
        ),
        (
            &transparency_verification.leaf_sha256,
            "reconciliationTransparency.leafSha256",
        ),
        (
            &transparency_verification.proof_sha256,
            "reconciliationTransparency.proofSha256",
        ),
        (
            &transparency_verification.checkpoint_root_sha256,
            "reconciliationTransparency.checkpointRootSha256",
        ),
        (
            &transparency_verification.trust_checkpoint_sha256,
            "reconciliationTransparency.trustCheckpointSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_identifier(
        &transparency_verification.transparency_log_id,
        "reconciliationTransparency.transparencyLogId",
    )?;
    for (value, path) in [
        (
            transparency_verification.checkpoint_revision,
            "reconciliationTransparency.checkpointRevision",
        ),
        (
            transparency_verification.checkpoint_tree_size,
            "reconciliationTransparency.checkpointTreeSize",
        ),
        (
            transparency_verification.revocation_epoch,
            "reconciliationTransparency.revocationEpoch",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    if let Some(revoked_at_epoch_ms) =
        transparency_verification.revoked_at_epoch_ms
    {
        validate_safe_time(
            revoked_at_epoch_ms,
            "reconciliationTransparency.revokedAtEpochMs",
        )?;
    }
    let transparency_revocation_invalid = match context.purpose() {
        VerificationPurpose::LiveAuthorization => {
            transparency_verification.revoked_at_epoch_ms.is_some()
        }
        VerificationPurpose::ArchivalVerification => transparency_verification
            .revoked_at_epoch_ms
            .is_some_and(|revoked_at| {
                revoked_at <= transparency.signed_at_epoch_ms
            }),
    };
    if !transparency_verification.accepted
        || !transparency_verification.inclusion_verified
        || !transparency_verification.consistency_verified
        || transparency_verification.conflicting_successor_detected
        || transparency_revocation_invalid
        || transparency_verification.transparency_log_id
            != pin.transparency_log_id
        || transparency_verification
            .transparency_operator_key_material_sha256
            != pin.transparency_operator_key_material_sha256
        || transparency_verification.store_transaction_id
            != current.record.store_transaction_id
        || transparency_verification.store_transition_sha256
            != store_transition_sha256
        || transparency_verification.predecessor_successor_key_sha256
            != predecessor_successor_key_sha256
        || transparency_verification.leaf_sha256 != leaf_sha256
        || transparency_verification.proof_sha256
            != transparency_log_proof_sha256
        || transparency_verification.checkpoint_root_sha256
            != pin.current_checkpoint_root_sha256
        || transparency_verification.checkpoint_revision
            != pin.current_checkpoint_revision
        || transparency_verification.checkpoint_tree_size
            != pin.current_checkpoint_tree_size
        || transparency_verification.trust_checkpoint_sha256
            != context.current_trust_checkpoint_sha256()
        || transparency_verification.revocation_epoch
            != context.current_revocation_epoch()
    {
        return Err(ContractError::new(
            "local_reconciliation_transparency_verification_failed",
            "body.localReconciliationLedgerWitnessEvidence.payload.transparencyLogProof",
            "separate transparency authority must verify the exact current pinned checkpoint signature, leaf inclusion, append-only consistency, non-revocation, and absence of a conflicting successor",
        ));
    }

    Ok(VerifiedLocalReconciliationStoreWitness {
        store_transition_sha256,
        quorum_certificate_sha256,
        transparency_log_proof_sha256,
        quorum_member_key_ids,
        quorum_member_key_material_sha256,
        transparency_operator_key_id:
            pin.transparency_operator_key_id.clone(),
        transparency_operator_key_material_sha256:
            pin.transparency_operator_key_material_sha256.clone(),
    })
}

fn validate_retrieved_local_reconciliation_evidence(
    retrieved: &RetrievedSignedLocalReconciliationEvidenceBytes,
    expected_retrieval_id: &str,
    expected_persistence_receipt_sha256: &str,
    expected_retrieval_proof_sha256: &str,
    maximum_bytes: usize,
    path: &'static str,
) -> ContractResult<u64> {
    if retrieved.retrieval_id != expected_retrieval_id
        || retrieved.persistence_receipt_sha256
            != expected_persistence_receipt_sha256
        || retrieved.retrieval_proof_sha256
            != expected_retrieval_proof_sha256
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_evidence_bytes.is_empty()
        || retrieved.exact_evidence_bytes.len() > maximum_bytes
    {
        return Err(ContractError::new(
            "local_reconciliation_evidence_retrieval_mismatch",
            path,
            "trusted retrieval must return exact bounded immutable evidence bytes and matching storage-generated persistence/retrieval proofs",
        ));
    }
    validate_digest(&retrieved.retrieval_id, path)?;
    validate_digest(&retrieved.persistence_receipt_sha256, path)?;
    validate_digest(&retrieved.retrieval_proof_sha256, path)?;
    u64::try_from(retrieved.exact_evidence_bytes.len()).map_err(|_| {
        ContractError::new(
            "length_overflow",
            path,
            "retrieved evidence length cannot be represented",
        )
    })
}

fn verify_retrieved_local_reconciliation_record(
    retrieved: &RetrievedLocalReconciliationRecordBytes,
    expected_record_id: &str,
    expected_record_sha256: &str,
    expected_record_byte_length: u64,
    expected_retrieval_id: &str,
    expected_persistence_receipt_sha256: &str,
    expected_retrieval_proof_sha256: &str,
) -> ContractResult<VerifiedLocalReconciliationRecord> {
    if retrieved.retrieval_id != expected_retrieval_id
        || retrieved.persistence_receipt_sha256
            != expected_persistence_receipt_sha256
        || retrieved.retrieval_proof_sha256
            != expected_retrieval_proof_sha256
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_record_bytes.is_empty()
        || retrieved.exact_record_bytes.len()
            > MAX_LOCAL_RECONCILIATION_RECORD_BYTES
    {
        return Err(ContractError::new(
            "local_reconciliation_predecessor_retrieval_mismatch",
            "localReconciliationContinuityRetrieval.predecessorRecord",
            "trusted predecessor retrieval must return exact bounded immutable record bytes and matching storage proofs",
        ));
    }
    let record_byte_length =
        u64::try_from(retrieved.exact_record_bytes.len()).map_err(|_| {
            ContractError::new(
                "length_overflow",
                "localReconciliationContinuityRetrieval.predecessorRecord",
                "predecessor record length cannot be represented",
            )
        })?;
    let record =
        decode_canonical_local_reconciliation_record(
            &retrieved.exact_record_bytes,
        )?;
    validate_local_reconciliation_record(&record)?;
    let record_sha256 = domain_sha256(
        LOCAL_RECONCILIATION_RECORD_DOMAIN,
        &[retrieved.exact_record_bytes.as_slice()],
    )?;
    let record_id = local_reconciliation_record_id(
        &record.attempt_id,
        &record_sha256,
        record_byte_length,
    )?;
    let retrieval_id = local_reconciliation_retrieval_id(
        &record_id,
        &record_sha256,
        record_byte_length,
    )?;
    if record_id != expected_record_id
        || record_sha256 != expected_record_sha256
        || record_byte_length != expected_record_byte_length
        || retrieval_id != expected_retrieval_id
    {
        return Err(ContractError::new(
            "local_reconciliation_predecessor_identity_mismatch",
            "localReconciliationContinuityRetrieval.predecessorRecord",
            "predecessor record ID, digest, length, and retrieval ID must be independently reconstructed from exact canonical bytes",
        ));
    }
    Ok(VerifiedLocalReconciliationRecord {
        record,
        record_id,
        record_sha256,
        record_byte_length,
        retrieval_id,
        persistence_receipt_sha256:
            retrieved.persistence_receipt_sha256.clone(),
        retrieval_proof_sha256: retrieved.retrieval_proof_sha256.clone(),
    })
}

fn decode_canonical_signed_reconciliation_evidence<P>(
    bytes: &[u8],
    maximum_bytes: usize,
    path: &'static str,
) -> ContractResult<SignedEvidence<P>>
where
    P: EvidencePayload + for<'de> Deserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(ContractError::new(
            "signed_reconciliation_evidence_size_out_of_bounds",
            path,
            "signed reconciliation evidence is empty or exceeds its closed byte bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let evidence =
        SignedEvidence::<P>::deserialize(&mut deserializer).map_err(|_| {
            ContractError::new(
                "invalid_signed_reconciliation_evidence",
                path,
                "retrieved bytes violate the closed signed evidence contract",
            )
        })?;
    deserializer.end().map_err(|_| {
        ContractError::new(
            "signed_reconciliation_evidence_trailing_json",
            path,
            "retrieved signed evidence contains trailing JSON data",
        )
    })?;
    if canonical_jcs_bytes(&evidence)? != bytes {
        return Err(ContractError::new(
            "noncanonical_signed_reconciliation_evidence",
            path,
            "retrieved signed evidence is not its exact canonical JCS representation",
        ));
    }
    Ok(evidence)
}

fn local_reconciliation_evidence_retrieval_id(
    domain: &'static str,
    record_id: &str,
    evidence_sha256: &str,
    evidence_byte_length: u64,
) -> ContractResult<String> {
    validate_digest(record_id, "localReconciliationEvidence.recordId")?;
    validate_digest(
        evidence_sha256,
        "localReconciliationEvidence.evidenceSha256",
    )?;
    validate_safe_integer(
        evidence_byte_length,
        "localReconciliationEvidence.evidenceByteLength",
    )?;
    let length = evidence_byte_length.to_string();
    domain_sha256(
        domain,
        &[
            record_id.as_bytes(),
            evidence_sha256.as_bytes(),
            length.as_bytes(),
        ],
    )
}

fn decode_canonical_local_reconciliation_record(
    bytes: &[u8],
) -> ContractResult<LocalAcquisitionReconciliationRecord> {
    if bytes.is_empty()
        || bytes.len() > MAX_LOCAL_RECONCILIATION_RECORD_BYTES
    {
        return Err(ContractError::new(
            "local_reconciliation_record_size_out_of_bounds",
            "localReconciliationRecord",
            "reconciliation record is empty or exceeds the 64 KiB exact-byte bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let record = LocalAcquisitionReconciliationRecord::deserialize(
        &mut deserializer,
    )
    .map_err(|_| {
        ContractError::new(
            "invalid_local_reconciliation_record",
            "localReconciliationRecord",
            "retrieved bytes violate the closed reconciliation record contract",
        )
    })?;
    deserializer.end().map_err(|_| {
        ContractError::new(
            "local_reconciliation_trailing_json",
            "localReconciliationRecord",
            "retrieved reconciliation record contains trailing JSON data",
        )
    })?;
    if canonical_jcs_bytes(&record)? != bytes {
        return Err(ContractError::new(
            "noncanonical_local_reconciliation_record",
            "localReconciliationRecord",
            "retrieved reconciliation bytes are not the exact canonical JCS representation",
        ));
    }
    Ok(record)
}

fn validate_local_reconciliation_record(
    record: &LocalAcquisitionReconciliationRecord,
) -> ContractResult<()> {
    if record.api_version != LOCAL_RECONCILIATION_API_VERSION
        || record.kind != LOCAL_RECONCILIATION_KIND
    {
        return Err(ContractError::new(
            "wrong_local_reconciliation_contract",
            "localReconciliationRecord",
            "retrieved record apiVersion or kind is not local credential reconciliation v2",
        ));
    }
    validate_attempt_id(&record.attempt_id)?;
    for (value, path) in [
        (&record.request_sha256, "localReconciliationRecord.requestSha256"),
        (
            &record.operation_sha256,
            "localReconciliationRecord.operationSha256",
        ),
        (
            &record.authorization_binding_sha256,
            "localReconciliationRecord.authorizationBindingSha256",
        ),
        (
            &record.credential_binding_sha256,
            "localReconciliationRecord.credentialBindingSha256",
        ),
        (
            &record.pinned_genesis_state_sha256,
            "localReconciliationRecord.pinnedGenesisStateSha256",
        ),
        (
            &record.predecessor_successor_key_sha256,
            "localReconciliationRecord.predecessorSuccessorKeySha256",
        ),
        (
            &record.rollback_head_sha256,
            "localReconciliationRecord.rollbackHeadSha256",
        ),
        (
            &record.predecessor_rollback_head_sha256,
            "localReconciliationRecord.predecessorRollbackHeadSha256",
        ),
        (
            &record.ledger_checkpoint_sha256,
            "localReconciliationRecord.ledgerCheckpointSha256",
        ),
        (
            &record.predecessor_ledger_checkpoint_sha256,
            "localReconciliationRecord.predecessorLedgerCheckpointSha256",
        ),
        (
            &record.custody_authority_key_id,
            "localReconciliationRecord.custodyAuthorityKeyId",
        ),
        (
            &record.custody_authority_key_material_sha256,
            "localReconciliationRecord.custodyAuthorityKeyMaterialSha256",
        ),
        (
            &record.trust_checkpoint_sha256,
            "localReconciliationRecord.trustCheckpointSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_identifier(
        &record.credential_ledger_namespace,
        "localReconciliationRecord.credentialLedgerNamespace",
    )?;
    for (value, path) in [
        (&record.provider_id, "localReconciliationRecord.providerId"),
        (&record.account_id, "localReconciliationRecord.accountId"),
        (
            &record.credential_ref,
            "localReconciliationRecord.credentialRef",
        ),
        (
            &record.ledger_id,
            "localReconciliationRecord.ledgerId",
        ),
        (
            &record.linearizable_store_id,
            "localReconciliationRecord.linearizableStoreId",
        ),
        (
            &record.linearizable_store_cluster_id,
            "localReconciliationRecord.linearizableStoreClusterId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    validate_digest(
        &record.store_transaction_id,
        "localReconciliationRecord.storeTransactionId",
    )?;
    for (value, path) in [
        (
            record.credential_version,
            "localReconciliationRecord.credentialVersion",
        ),
        (
            record.credential_generation,
            "localReconciliationRecord.credentialGeneration",
        ),
        (
            record.rollback_state_epoch,
            "localReconciliationRecord.rollbackStateEpoch",
        ),
        (
            record.ledger_sequence,
            "localReconciliationRecord.ledgerSequence",
        ),
        (
            record.ledger_checkpoint_epoch,
            "localReconciliationRecord.ledgerCheckpointEpoch",
        ),
        (
            record.store_term,
            "localReconciliationRecord.storeTerm",
        ),
        (
            record.store_log_index,
            "localReconciliationRecord.storeLogIndex",
        ),
        (
            record.store_fencing_token,
            "localReconciliationRecord.storeFencingToken",
        ),
        (
            record.revocation_epoch,
            "localReconciliationRecord.revocationEpoch",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    validate_safe_time(
        record.created_at_epoch_ms,
        "localReconciliationRecord.createdAtEpochMs",
    )?;
    validate_safe_time(
        record.deadline_epoch_ms,
        "localReconciliationRecord.deadlineEpochMs",
    )?;
    if record.credential_version == 0
        || record.credential_generation == 0
        || record.rollback_state_epoch == 0
        || record.ledger_sequence == 0
        || record.ledger_checkpoint_epoch == 0
        || record.store_term == 0
        || record.store_log_index == 0
        || record.store_fencing_token == 0
        || record.revocation_epoch == 0
        || record.deadline_epoch_ms <= record.created_at_epoch_ms
        || record.deadline_epoch_ms - record.created_at_epoch_ms
            > MAX_LOCAL_RECONCILIATION_DELAY_MS
        || record.predecessor_record_id.is_some()
            != record.predecessor_record_sha256.is_some()
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_record_state",
            "localReconciliationRecord",
            "record requires positive credential, rollback, and revocation versions, a bounded unresolved deadline, and an all-or-none predecessor record identity",
        ));
    }
    for (value, path) in [
        (
            record.predecessor_record_id.as_deref(),
            "localReconciliationRecord.predecessorRecordId",
        ),
        (
            record.predecessor_record_sha256.as_deref(),
            "localReconciliationRecord.predecessorRecordSha256",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, path)?;
        }
    }
    Ok(())
}

fn local_reconciliation_record_id(
    attempt_id_value: &str,
    record_sha256: &str,
    record_byte_length: u64,
) -> ContractResult<String> {
    validate_attempt_id(attempt_id_value)?;
    validate_digest(record_sha256, "localReconciliationRecord.recordSha256")?;
    validate_safe_integer(
        record_byte_length,
        "localReconciliationRecord.recordByteLength",
    )?;
    let length = record_byte_length.to_string();
    domain_sha256(
        LOCAL_RECONCILIATION_RECORD_ID_DOMAIN,
        &[
            attempt_id_value.as_bytes(),
            record_sha256.as_bytes(),
            length.as_bytes(),
        ],
    )
}

fn local_reconciliation_retrieval_id(
    record_id: &str,
    record_sha256: &str,
    record_byte_length: u64,
) -> ContractResult<String> {
    validate_digest(record_id, "localReconciliationRecord.recordId")?;
    validate_digest(record_sha256, "localReconciliationRecord.recordSha256")?;
    validate_safe_integer(
        record_byte_length,
        "localReconciliationRecord.recordByteLength",
    )?;
    let length = record_byte_length.to_string();
    domain_sha256(
        LOCAL_RECONCILIATION_RETRIEVAL_ID_DOMAIN,
        &[
            record_id.as_bytes(),
            record_sha256.as_bytes(),
            length.as_bytes(),
        ],
    )
}

fn verify_exact_upstream_response_bytes<P: ExactBytePersistenceVerifier>(
    body: &ResponseObservationEnvelopeBodyV2,
    persistence: &P,
) -> ContractResult<VerifiedExactUpstreamResponse> {
    match &body.upstream_observation {
        UpstreamObservationState::ObservedResponse {
            exact_response_retrieval_id,
            exact_response_bytes_sha256,
            exact_response_bytes_length,
            wire_protocol,
            informational_responses,
            status_line_sha256,
            status_line_length,
            status,
            header_block_sha256,
            header_block_length,
            header_count,
            framing,
            completion,
            declared_body_length,
            physical_body_sha256,
            physical_body_length,
            body_sha256,
            body_length,
            trailer_block_sha256,
            trailer_block_length,
            trailer_count,
            close_completion_receipt_sha256,
            observed_bytes_sha256,
            response_policy_validation,
            ..
        } => verify_supported_http11_response(
            body,
            persistence,
            exact_response_retrieval_id,
            exact_response_bytes_sha256,
            *exact_response_bytes_length,
            *wire_protocol,
            informational_responses,
            status_line_sha256,
            *status_line_length,
            *status,
            header_block_sha256,
            *header_block_length,
            *header_count,
            *framing,
            *completion,
            *declared_body_length,
            physical_body_sha256,
            *physical_body_length,
            body_sha256,
            *body_length,
            trailer_block_sha256.as_deref(),
            *trailer_block_length,
            *trailer_count,
            close_completion_receipt_sha256.as_deref(),
            observed_bytes_sha256,
            response_policy_validation,
        ),
        UpstreamObservationState::ExactResponseUnsupported {
            exact_response_retrieval_id,
            exact_response_bytes_sha256,
            exact_response_bytes_length,
            wire_protocol,
            completion,
            protocol_validation_receipt_sha256,
            reason,
            response_policy_decision,
            downstream_delivery,
            ..
        } => verify_exact_unsupported_response(
            body,
            persistence,
            exact_response_retrieval_id,
            exact_response_bytes_sha256,
            *exact_response_bytes_length,
            *wire_protocol,
            *completion,
            protocol_validation_receipt_sha256,
            *reason,
            *response_policy_decision,
            *downstream_delivery,
        ),
        _ => {
            Err(ContractError::new(
                "missing_observed_response",
                "body.upstreamObservation",
                "exact response retrieval is valid only for observed or exact-response-unsupported state",
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_supported_http11_response<P: ExactBytePersistenceVerifier>(
    body: &ResponseObservationEnvelopeBodyV2,
    persistence: &P,
    retrieval_id: &str,
    exact_response_bytes_sha256: &str,
    exact_response_bytes_length: u64,
    wire_protocol: UpstreamResponseWireProtocol,
    informational_responses: &[InformationalResponseHead],
    status_line_sha256: &str,
    status_line_length: u64,
    status: u16,
    header_block_sha256: &str,
    header_block_length: u64,
    header_count: u32,
    framing: UpstreamResponseFraming,
    completion: UpstreamResponseCompletion,
    declared_body_length: Option<u64>,
    physical_body_sha256: &str,
    physical_body_length: u64,
    body_sha256: &str,
    body_length: u64,
    trailer_block_sha256: Option<&str>,
    trailer_block_length: u64,
    trailer_count: u32,
    close_completion_receipt_sha256: Option<&str>,
    observed_bytes_sha256: &str,
    response_policy_validation: &ResponsePolicyValidation,
) -> ContractResult<VerifiedExactUpstreamResponse> {
    if wire_protocol != UpstreamResponseWireProtocol::Http11 {
        return Err(ContractError::new(
            "unsupported_response_protocol_in_observed_state",
            "body.upstreamObservation.wireProtocol",
            "observed-response accepts only independently reconstructed HTTP/1.1; other valid protocols require exact-response-unsupported",
        ));
    }
    let staged = body.staged_target_request.as_ref().ok_or_else(|| {
        ContractError::new(
            "missing_staged_request",
            "body.stagedTargetRequest",
            "an observed response requires the exact staged request that produced it",
        )
    })?;
    let dispatch = body.dispatch_evidence.as_ref().ok_or_else(|| {
        ContractError::new(
            "missing_dispatch_evidence",
            "body.dispatchEvidence",
            "an observed response requires the exact dispatch evidence that produced it",
        )
    })?;
    let expected_authority =
        canonical_target_authority(&staged.canonical_target)?;
    if let Some(declared_body_length) = declared_body_length {
        validate_safe_integer(
            declared_body_length,
            "body.upstreamObservation.declaredBodyLength",
        )?;
    }
    if informational_responses.len() > MAX_INFORMATIONAL_RESPONSES
        || status_line_length == 0
        || status_line_length > MAX_HEADER_BYTES
        || header_block_length > MAX_HEADER_BYTES
        || header_count > MAX_HEADER_COUNT
        || physical_body_length > MAX_RESPONSE_PHYSICAL_BODY_BYTES
        || body_length > MAX_RESPONSE_ENTITY_BYTES
        || trailer_block_length > MAX_RESPONSE_TRAILER_BYTES
        || trailer_count > MAX_HEADER_COUNT
        || exact_response_bytes_length > MAX_PHYSICAL_RESPONSE_BYTES
    {
        return Err(ContractError::new(
            "response_component_bounds_invalid",
            "body.upstreamObservation",
            "response head chain, physical framing, trailers, or decoded entity exceeds its coherent closed bound",
        ));
    }
    for value in [
        retrieval_id,
        exact_response_bytes_sha256,
        status_line_sha256,
        header_block_sha256,
        physical_body_sha256,
        body_sha256,
        observed_bytes_sha256,
    ] {
        validate_digest(value, "body.upstreamObservation")?;
    }
    if let Some(value) = trailer_block_sha256 {
        validate_digest(value, "body.upstreamObservation.trailerBlockSha256")?;
    }
    if let Some(value) = close_completion_receipt_sha256 {
        validate_digest(
            value,
            "body.upstreamObservation.closeCompletionReceiptSha256",
        )?;
    }
    let wire_protocol_jcs = canonical_jcs_bytes(&wire_protocol)?;
    let completion_jcs = canonical_jcs_bytes(&completion)?;
    let expected_retrieval_id = domain_sha256(
        UPSTREAM_RESPONSE_RETRIEVAL_DOMAIN,
        &[
            body.attempt_id.as_bytes(),
            staged.staging_sha256.as_bytes(),
            dispatch.evidence_sha256.as_bytes(),
            expected_authority.as_bytes(),
            wire_protocol_jcs.as_slice(),
            completion_jcs.as_slice(),
            exact_response_bytes_sha256.as_bytes(),
        ],
    )?;
    require_equal_digest(
        retrieval_id,
        &expected_retrieval_id,
        "body.upstreamObservation.exactResponseRetrievalId",
    )?;
    let retrieved = persistence.retrieve_exact_upstream_response(retrieval_id)?;
    if retrieved.attempt_id != body.attempt_id
        || retrieved.retrieval_id != retrieval_id
        || retrieved.staged_request_sha256 != staged.staging_sha256
        || retrieved.dispatch_evidence_sha256 != dispatch.evidence_sha256
        || retrieved.wire_protocol != wire_protocol
        || retrieved.transport_scheme != staged.canonical_target.scheme
        || retrieved.authenticated_peer_authority != expected_authority
        || retrieved.completion != completion
        || retrieved.unsupported_reason.is_some()
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_response_bytes.len() as u64
            != exact_response_bytes_length
        || retrieved.exact_response_bytes.len()
            > MAX_PHYSICAL_RESPONSE_BYTES as usize
        || exact_response_bytes_length == 0
    {
        return Err(ContractError::new(
            "upstream_response_retrieval_mismatch",
            "body.upstreamObservation.exactResponseRetrievalId",
            "trusted retrieval must return the exact immutable bounded physical upstream response",
        ));
    }
    validate_digest(
        &retrieved.protocol_validation_receipt_sha256,
        "retrievedUpstreamResponse.protocolValidationReceiptSha256",
    )?;
    let exact_response = retrieved.exact_response_bytes.as_slice();
    let exact_digest = raw_sha256(exact_response);
    require_equal_digest(
        exact_response_bytes_sha256,
        &exact_digest,
        "body.upstreamObservation.exactResponseBytesSha256",
    )?;
    require_equal_digest(
        observed_bytes_sha256,
        &exact_digest,
        "body.upstreamObservation.observedBytesSha256",
    )?;
    let mut offset = 0usize;
    let mut head_chain_length = 0u64;
    for informational in informational_responses {
        validate_digest(
            &informational.status_line_sha256,
            "body.upstreamObservation.informationalResponses.statusLineSha256",
        )?;
        validate_digest(
            &informational.header_block_sha256,
            "body.upstreamObservation.informationalResponses.headerBlockSha256",
        )?;
        if informational.status_line_length == 0
            || informational.status_line_length > MAX_HEADER_BYTES
            || informational.header_block_length < 2
            || informational.header_block_length > MAX_HEADER_BYTES
            || informational.header_count > MAX_HEADER_COUNT
        {
            return Err(ContractError::new(
                "informational_response_bounds_invalid",
                "body.upstreamObservation.informationalResponses",
                "informational response head exceeds the closed status, header, or count bound",
            ));
        }
        let status_length = usize::try_from(informational.status_line_length)
            .map_err(|_| response_bounds_error())?;
        let header_length = usize::try_from(informational.header_block_length)
            .map_err(|_| response_bounds_error())?;
        let status_end = offset
            .checked_add(status_length)
            .ok_or_else(response_bounds_error)?;
        let header_end = status_end
            .checked_add(header_length)
            .ok_or_else(response_bounds_error)?;
        if header_end > exact_response.len() {
            return Err(response_segment_error());
        }
        let informational_status_line = &exact_response[offset..status_end];
        let informational_headers = &exact_response[status_end..header_end];
        require_equal_digest(
            &informational.status_line_sha256,
            &raw_sha256(informational_status_line),
            "body.upstreamObservation.informationalResponses.statusLineSha256",
        )?;
        require_equal_digest(
            &informational.header_block_sha256,
            &raw_sha256(informational_headers),
            "body.upstreamObservation.informationalResponses.headerBlockSha256",
        )?;
        validate_exact_status_line(
            informational_status_line,
            informational.status,
            ResponseStatusClass::Informational,
        )?;
        let semantics = parse_exact_response_header_block(
            informational_headers,
            informational.header_count,
        )?;
        if semantics.content_length.is_some()
            || semantics.transfer_encoding_chunked
            || !semantics.declared_trailer_names.is_empty()
        {
            return Err(ContractError::new(
                "informational_response_framing",
                "body.upstreamObservation.informationalResponses",
                "informational response heads cannot carry message framing or trailer declarations",
            ));
        }
        offset = header_end;
        head_chain_length = head_chain_length
            .checked_add(informational.status_line_length)
            .and_then(|value| value.checked_add(informational.header_block_length))
            .ok_or_else(response_bounds_error)?;
    }
    let status_line_length = usize::try_from(status_line_length).map_err(|_| {
        ContractError::new(
            "response_bounds_invalid",
            "body.upstreamObservation.statusLineLength",
            "status-line length cannot be represented",
        )
    })?;
    let header_block_length =
        usize::try_from(header_block_length).map_err(|_| {
            ContractError::new(
                "response_bounds_invalid",
                "body.upstreamObservation.headerBlockLength",
                "header length cannot be represented",
            )
        })?;
    let physical_body_length_usize =
        usize::try_from(physical_body_length).map_err(|_| {
        ContractError::new(
            "response_bounds_invalid",
            "body.upstreamObservation.physicalBodyLength",
            "physical body length cannot be represented",
        )
    })?;
    let status_end = offset
        .checked_add(status_line_length)
        .ok_or_else(response_bounds_error)?;
    let header_end = status_end
        .checked_add(header_block_length)
        .ok_or_else(response_bounds_error)?;
    let response_end = header_end
        .checked_add(physical_body_length_usize)
        .ok_or_else(response_bounds_error)?;
    if response_end != exact_response.len()
        || status_line_length < 15
        || header_block_length < 2
        || head_chain_length
            .saturating_add(status_line_length as u64)
            .saturating_add(header_block_length as u64)
            > MAX_RESPONSE_HEAD_CHAIN_BYTES
    {
        return Err(response_segment_error());
    }
    let status_line = &exact_response[offset..status_end];
    let header_block = &exact_response[status_end..header_end];
    let physical_body = &exact_response[header_end..response_end];
    require_equal_digest(
        status_line_sha256,
        &raw_sha256(status_line),
        "body.upstreamObservation.statusLineSha256",
    )?;
    require_equal_digest(
        header_block_sha256,
        &raw_sha256(header_block),
        "body.upstreamObservation.headerBlockSha256",
    )?;
    require_equal_digest(
        physical_body_sha256,
        &raw_sha256(physical_body),
        "body.upstreamObservation.physicalBodySha256",
    )?;
    validate_exact_status_line(status_line, status, ResponseStatusClass::Final)?;
    let header_semantics =
        parse_exact_response_header_block(header_block, header_count)?;
    if staged.method == "CONNECT" && (200..=299).contains(&status) {
        return Err(ContractError::new(
            "unsupported_connect_tunnel",
            "body.upstreamObservation",
            "successful CONNECT switches protocol and requires exact-response-unsupported",
        ));
    }
    let profile = required_response_policy_profile(body)?;
    validate_response_policy_profile(profile)?;
    let parsed_body = reconstruct_response_body(
        physical_body,
        &header_semantics,
        framing,
        completion,
        declared_body_length,
        &staged.method,
        status,
        profile,
        retrieved.authenticated_eof_receipt_sha256.as_deref(),
        close_completion_receipt_sha256,
    )?;
    if parsed_body.entity_body.len() as u64 != body_length
        || parsed_body.trailer_block.len() as u64 != trailer_block_length
        || parsed_body.trailer_count != trailer_count
        || parsed_body.entity_body.len() as u64 > MAX_RESPONSE_ENTITY_BYTES
    {
        return Err(ContractError::new(
            "response_decoding_metadata_mismatch",
            "body.upstreamObservation",
            "decoded entity body and exact trailer metadata must equal reconstruction from physical framing",
        ));
    }
    require_equal_digest(
        body_sha256,
        &raw_sha256(&parsed_body.entity_body),
        "body.upstreamObservation.bodySha256",
    )?;
    match (
        trailer_block_sha256,
        parsed_body.trailer_block.is_empty(),
    ) {
        (Some(expected), false) => require_equal_digest(
            expected,
            &raw_sha256(parsed_body.trailer_block),
            "body.upstreamObservation.trailerBlockSha256",
        )?,
        (None, true) => {}
        _ => {
            return Err(ContractError::new(
                "response_trailer_metadata_mismatch",
                "body.upstreamObservation.trailerBlockSha256",
                "only chunked responses carry an exact trailer block commitment, including the empty terminal CRLF",
            ))
        }
    }
    let route_profile = &body.route_semantic_profile_evidence.payload;
    if route_profile.provider_id.as_deref()
        != Some(profile.provider_id.as_str())
        || route_profile.provider_schema_sha256.as_deref()
            != Some(profile.provider_schema_sha256.as_str())
        || route_profile.response_policy_profile_sha256.as_deref()
            != Some(profile.profile_sha256.as_str())
    {
        return Err(ContractError::new(
            "response_validator_route_mismatch",
            "body.policy.prerequisites.responseValidation",
            "exact-byte response validation may invoke only the provider, schema, and profile committed by the signed route semantics",
        ));
    }
    if body_length > profile.maximum_body_bytes {
        return Err(ContractError::new(
            "response_policy_capture_requirement_failed",
            "body.upstreamObservation",
            "response exceeds the signed policy body bound",
        ));
    }
    let trusted = persistence.validate_exact_response_policy(
        profile,
        status,
        exact_response,
        header_block,
        parsed_body.trailer_block,
        &parsed_body.entity_body,
        exact_response_bytes_sha256,
        completion,
    )?;
    let expected_validation = response_policy_validation_digest(
        &trusted.profile_sha256,
        &trusted.exact_response_bytes_sha256,
        &trusted.restrictions_sha256,
        trusted.decision,
    )?;
    if trusted.profile_sha256 != profile.profile_sha256
        || trusted.exact_response_bytes_sha256 != exact_response_bytes_sha256
        || trusted.restrictions_sha256 != profile.restrictions_sha256
        || trusted.validation_sha256 != expected_validation
        || response_policy_validation.profile_sha256 != trusted.profile_sha256
        || response_policy_validation.exact_response_bytes_sha256
            != trusted.exact_response_bytes_sha256
        || response_policy_validation.restrictions_sha256
            != trusted.restrictions_sha256
        || response_policy_validation.decision != trusted.decision
        || response_policy_validation.validation_sha256
            != trusted.validation_sha256
        || !matches!(
            (completion, trusted.decision),
            (
                UpstreamResponseCompletion::Complete,
                ResponsePolicyDecision::Passed | ResponsePolicyDecision::Failed
            ) | (
                UpstreamResponseCompletion::Truncated,
                ResponsePolicyDecision::NotEvaluatedIncompleteResponse
            )
        )
    {
        return Err(ContractError::new(
            "response_policy_validation_mismatch",
            "body.upstreamObservation.responsePolicyValidation",
            "response-policy result must be produced by the trusted provider validator over the exact retrieved response bytes and signed restrictions",
        ));
    }
    Ok(VerifiedExactUpstreamResponse {
        exact_response_bytes_sha256: exact_digest,
        response_policy_validation_sha256: Some(expected_validation),
        completion,
        unsupported_reason: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_exact_unsupported_response<P: ExactBytePersistenceVerifier>(
    body: &ResponseObservationEnvelopeBodyV2,
    persistence: &P,
    retrieval_id: &str,
    exact_response_bytes_sha256: &str,
    exact_response_bytes_length: u64,
    wire_protocol: UpstreamResponseWireProtocol,
    completion: UpstreamResponseCompletion,
    protocol_validation_receipt_sha256: &str,
    reason: ExactResponseUnsupportedReason,
    response_policy_decision: ResponsePolicyDecision,
    downstream_delivery: DownstreamDeliveryState,
) -> ContractResult<VerifiedExactUpstreamResponse> {
    if response_policy_decision
        != ResponsePolicyDecision::NotEvaluatedUnsupportedResponse
        || downstream_delivery != DownstreamDeliveryState::Unknown
    {
        return Err(ContractError::new(
            "unsupported_response_passing_claim",
            "body.upstreamObservation",
            "valid but unsupported exact responses must remain non-passing with downstream delivery unknown",
        ));
    }
    if (wire_protocol == UpstreamResponseWireProtocol::Http11)
        != !matches!(reason, ExactResponseUnsupportedReason::UnsupportedProtocol)
    {
        return Err(ContractError::new(
            "unsupported_response_reason_mismatch",
            "body.upstreamObservation.reason",
            "unsupported-protocol is reserved for non-HTTP/1.1 retrievals; HTTP/1.1 must name its unsupported framing or upgrade reason",
        ));
    }
    for value in [
        retrieval_id,
        exact_response_bytes_sha256,
        protocol_validation_receipt_sha256,
    ] {
        validate_digest(value, "body.upstreamObservation")?;
    }
    let staged = body.staged_target_request.as_ref().ok_or_else(|| {
        ContractError::new(
            "missing_staged_request",
            "body.stagedTargetRequest",
            "an unsupported exact response still requires its exact staged request",
        )
    })?;
    let dispatch = body.dispatch_evidence.as_ref().ok_or_else(|| {
        ContractError::new(
            "missing_dispatch_evidence",
            "body.dispatchEvidence",
            "an unsupported exact response still requires dispatch evidence",
        )
    })?;
    let expected_authority = canonical_target_authority(&staged.canonical_target)?;
    let wire_protocol_jcs = canonical_jcs_bytes(&wire_protocol)?;
    let completion_jcs = canonical_jcs_bytes(&completion)?;
    let expected_retrieval_id = domain_sha256(
        UPSTREAM_RESPONSE_RETRIEVAL_DOMAIN,
        &[
            body.attempt_id.as_bytes(),
            staged.staging_sha256.as_bytes(),
            dispatch.evidence_sha256.as_bytes(),
            expected_authority.as_bytes(),
            wire_protocol_jcs.as_slice(),
            completion_jcs.as_slice(),
            exact_response_bytes_sha256.as_bytes(),
        ],
    )?;
    require_equal_digest(
        retrieval_id,
        &expected_retrieval_id,
        "body.upstreamObservation.exactResponseRetrievalId",
    )?;
    let retrieved = persistence.retrieve_exact_upstream_response(retrieval_id)?;
    if retrieved.attempt_id != body.attempt_id
        || retrieved.retrieval_id != retrieval_id
        || retrieved.staged_request_sha256 != staged.staging_sha256
        || retrieved.dispatch_evidence_sha256 != dispatch.evidence_sha256
        || retrieved.wire_protocol != wire_protocol
        || retrieved.transport_scheme != staged.canonical_target.scheme
        || retrieved.authenticated_peer_authority != expected_authority
        || retrieved.completion != completion
        || retrieved.unsupported_reason != Some(reason)
        || retrieved.protocol_validation_receipt_sha256
            != protocol_validation_receipt_sha256
        || !retrieved.immutable
        || !retrieved.replacement_prohibited
        || retrieved.exact_response_bytes.is_empty()
        || retrieved.exact_response_bytes.len() as u64
            != exact_response_bytes_length
        || exact_response_bytes_length > MAX_PHYSICAL_RESPONSE_BYTES
    {
        return Err(ContractError::new(
            "unsupported_response_retrieval_mismatch",
            "body.upstreamObservation.exactResponseRetrievalId",
            "trusted immutable retrieval must attest the exact valid-but-unsupported protocol/framing, completion truth, and physical bytes",
        ));
    }
    let exact_digest = raw_sha256(&retrieved.exact_response_bytes);
    require_equal_digest(
        exact_response_bytes_sha256,
        &exact_digest,
        "body.upstreamObservation.exactResponseBytesSha256",
    )?;
    Ok(VerifiedExactUpstreamResponse {
        exact_response_bytes_sha256: exact_digest,
        response_policy_validation_sha256: None,
        completion,
        unsupported_reason: Some(reason),
    })
}

fn required_response_policy_profile(
    body: &ResponseObservationEnvelopeBodyV2,
) -> ContractResult<&ResponsePolicyProfile> {
    body.policy
        .prerequisites()
        .and_then(|value| match &value.response_validation {
            PolicyResponseValidationPrerequisite::Required { profile } => {
                Some(profile)
            }
            PolicyResponseValidationPrerequisite::NotRequired => None,
        })
        .ok_or_else(|| {
            ContractError::new(
                "missing_response_policy_prerequisite",
                "body.policy.prerequisites.responseValidation",
                "an observed upstream response requires one exact provider response-validation profile",
            )
        })
}

fn response_policy_validation_digest(
    profile_sha256: &str,
    exact_response_bytes_sha256: &str,
    restrictions_sha256: &str,
    decision: ResponsePolicyDecision,
) -> ContractResult<String> {
    let decision_jcs = canonical_jcs_bytes(&decision)?;
    domain_sha256(
        RESPONSE_POLICY_VALIDATION_DOMAIN,
        &[
            profile_sha256.as_bytes(),
            exact_response_bytes_sha256.as_bytes(),
            restrictions_sha256.as_bytes(),
            decision_jcs.as_slice(),
        ],
    )
}

#[derive(Clone, Copy)]
enum ResponseStatusClass {
    Informational,
    Final,
}

fn validate_exact_status_line(
    status_line: &[u8],
    expected_status: u16,
    expected_class: ResponseStatusClass,
) -> ContractResult<()> {
    let reason_phrase = status_line
        .get(13..status_line.len().saturating_sub(2))
        .unwrap_or_default();
    if !status_line.starts_with(b"HTTP/1.1 ")
        || !status_line.ends_with(b"\r\n")
        || status_line.len() < 15
        || status_line.get(12) != Some(&b' ')
        || status_line[9..12]
            .iter()
            .any(|byte| !byte.is_ascii_digit())
        || reason_phrase
            .iter()
            .any(|byte| {
                *byte != b'\t'
                    && !(0x20..=0x7e).contains(byte)
                    && !(0x80..=0xff).contains(byte)
            })
    {
        return Err(ContractError::new(
            "noncanonical_response_status_line",
            "body.upstreamObservation",
            "response status line must be exact HTTP/1.1 with an optional bounded HTTP reason phrase, including the empty phrase",
        ));
    }
    let parsed = std::str::from_utf8(&status_line[9..12])
        .ok()
        .and_then(|value| value.parse::<u16>().ok());
    let valid_class = match expected_class {
        ResponseStatusClass::Informational => {
            (100..=199).contains(&expected_status) && expected_status != 101
        }
        ResponseStatusClass::Final => (200..=599).contains(&expected_status),
    };
    if parsed != Some(expected_status) || !valid_class {
        return Err(ContractError::new(
            "response_status_mismatch",
            "body.upstreamObservation.status",
            "response status metadata must equal the exact physical status line",
        ));
    }
    Ok(())
}

struct ResponseHeaderSemantics {
    content_length: Option<u64>,
    transfer_encoding_chunked: bool,
    declared_trailer_names: BTreeSet<Vec<u8>>,
}

fn parse_exact_response_header_block(
    header_block: &[u8],
    expected_count: u32,
) -> ContractResult<ResponseHeaderSemantics> {
    if header_block.len() < 2
        || !header_block.ends_with(b"\r\n")
        || (header_block.len() > 2
            && !header_block.ends_with(b"\r\n\r\n"))
        || (header_block.len() > 4
            && header_block[..header_block.len() - 4]
                .windows(4)
                .any(|window| window == b"\r\n\r\n"))
    {
        return Err(ContractError::new(
            "noncanonical_response_header_block",
            "body.upstreamObservation",
            "physical response header block must have one terminal CRLF separator",
        ));
    }
    let mut remaining = &header_block[..header_block.len() - 2];
    let mut count = 0u32;
    let mut content_length = None;
    let mut content_length_seen = false;
    let mut transfer_encoding_chunked = false;
    let mut transfer_encoding_seen = false;
    let mut declared_trailer_names = BTreeSet::new();
    let mut trailer_declaration_seen = false;
    while !remaining.is_empty() {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                ContractError::new(
                    "noncanonical_response_header_block",
                    "body.upstreamObservation",
                    "every physical response header must end in CRLF",
                )
            })?;
        let line = &remaining[..line_end];
        remaining = &remaining[line_end + 2..];
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ContractError::new(
                "noncanonical_response_header",
                "body.upstreamObservation",
                "response header lacks a canonical separator",
            )
        })?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if !is_physical_response_header_name(name)
            || value.iter().any(|byte| {
                (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f
            })
        {
            return Err(ContractError::new(
                "noncanonical_response_header",
                "body.upstreamObservation",
                "physical response headers require bounded HTTP token names, no obs-fold, and no control bytes outside horizontal tab",
            ));
        }
        let semantic_value = trim_http_ows(value);
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if transfer_encoding_seen {
                return Err(ContractError::new(
                    "duplicate_response_transfer_encoding",
                    "body.upstreamObservation",
                    "response permits exactly one Transfer-Encoding field",
                ));
            }
            transfer_encoding_seen = true;
            if !semantic_value.eq_ignore_ascii_case(b"chunked")
                || semantic_value.contains(&b',')
            {
                return Err(ContractError::new(
                    "unsupported_response_transfer_coding",
                    "body.upstreamObservation",
                    "observed-response supports only one terminal chunked transfer coding; other valid codings require exact-response-unsupported",
                ));
            }
            transfer_encoding_chunked = true;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length_seen {
                return Err(ContractError::new(
                    "duplicate_response_content_length",
                    "body.upstreamObservation",
                    "response permits exactly one canonical Content-Length",
                ));
            }
            content_length_seen = true;
            let digits = semantic_value;
            if digits.is_empty()
                || digits.iter().any(|byte| !byte.is_ascii_digit())
                || (digits.len() > 1 && digits[0] == b'0')
            {
                return Err(ContractError::new(
                    "noncanonical_response_content_length",
                    "body.upstreamObservation",
                    "response Content-Length must be canonical decimal",
                ));
            }
            content_length = std::str::from_utf8(digits)
                .ok()
                .and_then(|value| value.parse::<u64>().ok());
            if content_length.is_none() {
                return Err(ContractError::new(
                    "response_content_length_overflow",
                    "body.upstreamObservation",
                    "response Content-Length exceeds the supported exact framing range",
                ));
            }
        }
        if name.eq_ignore_ascii_case(b"trailer") {
            if trailer_declaration_seen {
                return Err(ContractError::new(
                    "duplicate_response_trailer_declaration",
                    "body.upstreamObservation",
                    "response permits one bounded Trailer declaration",
                ));
            }
            trailer_declaration_seen = true;
            declared_trailer_names =
                parse_comma_separated_header_names(semantic_value)?;
        }
        count = count.saturating_add(1);
        if count > MAX_HEADER_COUNT {
            return Err(ContractError::new(
                "response_header_count_limit",
                "body.upstreamObservation.headerCount",
                "physical response header count exceeds the closed bound",
            ));
        }
    }
    if count != expected_count {
        return Err(ContractError::new(
            "response_header_count_mismatch",
            "body.upstreamObservation.headerCount",
            "response header count does not match exact physical headers",
        ));
    }
    if content_length_seen && transfer_encoding_seen {
        return Err(ContractError::new(
            "ambiguous_response_framing",
            "body.upstreamObservation",
            "Transfer-Encoding and Content-Length cannot coexist",
        ));
    }
    Ok(ResponseHeaderSemantics {
        content_length,
        transfer_encoding_chunked,
        declared_trailer_names,
    })
}

struct ReconstructedResponseBody<'a> {
    entity_body: Vec<u8>,
    trailer_block: &'a [u8],
    trailer_count: u32,
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_response_body<'a>(
    physical_body: &'a [u8],
    headers: &ResponseHeaderSemantics,
    framing: UpstreamResponseFraming,
    completion: UpstreamResponseCompletion,
    declared_body_length: Option<u64>,
    request_method: &str,
    response_status: u16,
    profile: &ResponsePolicyProfile,
    retrieved_eof_receipt_sha256: Option<&str>,
    claimed_eof_receipt_sha256: Option<&str>,
) -> ContractResult<ReconstructedResponseBody<'a>> {
    let no_body_semantics =
        request_method == "HEAD" || response_status == 204 || response_status == 304;
    match framing {
        UpstreamResponseFraming::NoBody => {
            let content_length_allowed =
                request_method == "HEAD" || response_status == 304;
            let transfer_encoding_allowed = content_length_allowed;
            let declared_length_matches = if headers.transfer_encoding_chunked {
                declared_body_length.is_none() && headers.content_length.is_none()
            } else {
                headers.content_length == declared_body_length
            };
            let trailer_declaration_allowed =
                headers.declared_trailer_names.is_empty()
                    || (headers.transfer_encoding_chunked
                        && content_length_allowed
                        && matches!(
                            &profile.trailers,
                            TrailerPolicy::Allowed {
                                maximum_trailer_count,
                                ..
                            } if headers.declared_trailer_names.len()
                                <= *maximum_trailer_count as usize
                        ));
            if completion != UpstreamResponseCompletion::Complete
                || !no_body_semantics
                || !physical_body.is_empty()
                || (headers.transfer_encoding_chunked
                    && !transfer_encoding_allowed)
                || (!content_length_allowed && headers.content_length.is_some())
                || !declared_length_matches
                || !trailer_declaration_allowed
                || retrieved_eof_receipt_sha256.is_some()
                || claimed_eof_receipt_sha256.is_some()
            {
                return Err(response_framing_error());
            }
            Ok(ReconstructedResponseBody {
                entity_body: Vec::new(),
                trailer_block: &[],
                trailer_count: 0,
            })
        }
        UpstreamResponseFraming::ContentLength => {
            let declared = headers.content_length.ok_or_else(response_framing_error)?;
            let complete = physical_body.len() as u64 == declared;
            if no_body_semantics
                || headers.transfer_encoding_chunked
                || headers.content_length != declared_body_length
                || !headers.declared_trailer_names.is_empty()
                || (completion == UpstreamResponseCompletion::Complete && !complete)
                || (completion == UpstreamResponseCompletion::Truncated
                    && physical_body.len() as u64 >= declared)
                || retrieved_eof_receipt_sha256.is_some()
                || claimed_eof_receipt_sha256.is_some()
            {
                return Err(response_framing_error());
            }
            Ok(ReconstructedResponseBody {
                entity_body: physical_body.to_vec(),
                trailer_block: &[],
                trailer_count: 0,
            })
        }
        UpstreamResponseFraming::CloseDelimited => {
            if no_body_semantics
                || headers.content_length.is_some()
                || headers.transfer_encoding_chunked
                || declared_body_length.is_some()
                || !headers.declared_trailer_names.is_empty()
            {
                return Err(response_framing_error());
            }
            match completion {
                UpstreamResponseCompletion::Complete => {
                    let claimed =
                        claimed_eof_receipt_sha256.ok_or_else(response_framing_error)?;
                    validate_digest(
                        claimed,
                        "body.upstreamObservation.closeCompletionReceiptSha256",
                    )?;
                    if retrieved_eof_receipt_sha256 != Some(claimed) {
                        return Err(ContractError::new(
                            "close_completion_receipt_mismatch",
                            "body.upstreamObservation.closeCompletionReceiptSha256",
                            "complete close-delimited response requires the trusted authenticated EOF receipt",
                        ));
                    }
                }
                UpstreamResponseCompletion::Truncated => {
                    if retrieved_eof_receipt_sha256.is_some()
                        || claimed_eof_receipt_sha256.is_some()
                    {
                        return Err(response_framing_error());
                    }
                }
            }
            Ok(ReconstructedResponseBody {
                entity_body: physical_body.to_vec(),
                trailer_block: &[],
                trailer_count: 0,
            })
        }
        UpstreamResponseFraming::Chunked => {
            if no_body_semantics
                || headers.content_length.is_some()
                || !headers.transfer_encoding_chunked
                || declared_body_length.is_some()
                || retrieved_eof_receipt_sha256.is_some()
                || claimed_eof_receipt_sha256.is_some()
            {
                return Err(response_framing_error());
            }
            parse_chunked_response_body(
                physical_body,
                completion,
                &headers.declared_trailer_names,
                profile,
            )
        }
    }
}

fn parse_chunked_response_body<'a>(
    raw: &'a [u8],
    completion: UpstreamResponseCompletion,
    declared_trailer_names: &BTreeSet<Vec<u8>>,
    profile: &ResponsePolicyProfile,
) -> ContractResult<ReconstructedResponseBody<'a>> {
    let mut position = 0usize;
    let mut entity_body = Vec::new();
    let mut chunk_count = 0u32;
    let mut extension_bytes = 0u64;
    loop {
        let line_end = match raw[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            Some(relative) => position + relative,
            None if completion == UpstreamResponseCompletion::Truncated => {
                validate_incomplete_chunk_line_prefix(
                    &raw[position..],
                    &profile.chunk_extensions,
                )?;
                enforce_chunk_framing_overhead(
                    raw.len() as u64,
                    entity_body.len() as u64,
                    0,
                )?;
                return Ok(ReconstructedResponseBody {
                    entity_body,
                    trailer_block: &[],
                    trailer_count: 0,
                })
            }
            None => return Err(invalid_chunk_error()),
        };
        let line = &raw[position..line_end];
        if line.is_empty() || line.len() > MAX_CHUNK_LINE_BYTES {
            return Err(invalid_chunk_error());
        }
        let size_end = line
            .iter()
            .position(|byte| !byte.is_ascii_hexdigit())
            .unwrap_or(line.len());
        let size_bytes = &line[..size_end];
        if size_bytes.is_empty()
            || size_bytes.len() > 16
        {
            return Err(invalid_chunk_error());
        }
        let size = std::str::from_utf8(size_bytes)
            .ok()
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(invalid_chunk_error)?;
        let extensions = &line[size_end..];
        if !extensions.is_empty() {
            validate_chunk_extensions(extensions, &profile.chunk_extensions)?;
            extension_bytes = extension_bytes
                .checked_add(extensions.len() as u64)
                .ok_or_else(invalid_chunk_error)?;
            let maximum = match &profile.chunk_extensions {
                ChunkExtensionPolicy::Forbidden => 0,
                ChunkExtensionPolicy::Allowed {
                    maximum_extension_bytes,
                } => *maximum_extension_bytes,
            };
            if extension_bytes > maximum {
                return Err(invalid_chunk_error());
            }
        }
        position = line_end + 2;
        if size == 0 {
            let trailer_start = position;
            let trailer_end = match locate_trailer_block_end(raw, trailer_start) {
                Some(value) => value,
                None if completion == UpstreamResponseCompletion::Truncated => {
                    enforce_chunk_framing_overhead(
                        raw.len() as u64,
                        entity_body.len() as u64,
                        0,
                    )?;
                    return Ok(ReconstructedResponseBody {
                        entity_body,
                        trailer_block: &[],
                        trailer_count: 0,
                    })
                }
                None => return Err(invalid_chunk_error()),
            };
            if trailer_end != raw.len()
                || completion != UpstreamResponseCompletion::Complete
            {
                return Err(response_framing_error());
            }
            let trailer_block = &raw[trailer_start..trailer_end];
            let trailer_count = validate_trailer_block(
                trailer_block,
                declared_trailer_names,
                &profile.trailers,
            )?;
            enforce_chunk_framing_overhead(
                raw.len() as u64,
                entity_body.len() as u64,
                trailer_block.len() as u64,
            )?;
            return Ok(ReconstructedResponseBody {
                entity_body,
                trailer_block,
                trailer_count,
            });
        }
        chunk_count = chunk_count.saturating_add(1);
        if chunk_count > MAX_CHUNK_COUNT
            || size > MAX_RESPONSE_ENTITY_BYTES
            || entity_body.len() as u64 + size > MAX_RESPONSE_ENTITY_BYTES
        {
            return Err(invalid_chunk_error());
        }
        let size = usize::try_from(size).map_err(|_| invalid_chunk_error())?;
        let available = raw.len().saturating_sub(position);
        if available < size {
            if completion != UpstreamResponseCompletion::Truncated {
                return Err(invalid_chunk_error());
            }
            entity_body.extend_from_slice(&raw[position..]);
            enforce_chunk_framing_overhead(
                raw.len() as u64,
                entity_body.len() as u64,
                0,
            )?;
            return Ok(ReconstructedResponseBody {
                entity_body,
                trailer_block: &[],
                trailer_count: 0,
            });
        }
        entity_body.extend_from_slice(&raw[position..position + size]);
        position += size;
        if raw.len().saturating_sub(position) < 2 {
            if completion == UpstreamResponseCompletion::Truncated {
                enforce_chunk_framing_overhead(
                    raw.len() as u64,
                    entity_body.len() as u64,
                    0,
                )?;
                return Ok(ReconstructedResponseBody {
                    entity_body,
                    trailer_block: &[],
                    trailer_count: 0,
                });
            }
            return Err(invalid_chunk_error());
        }
        if &raw[position..position + 2] != b"\r\n" {
            return Err(invalid_chunk_error());
        }
        position += 2;
    }
}

fn validate_incomplete_chunk_line_prefix(
    line: &[u8],
    policy: &ChunkExtensionPolicy,
) -> ContractResult<()> {
    if line.is_empty() {
        return Ok(());
    }
    if line.len() > MAX_CHUNK_LINE_BYTES {
        return Err(invalid_chunk_error());
    }
    let size_end = line
        .iter()
        .position(|byte| !byte.is_ascii_hexdigit())
        .unwrap_or(line.len());
    let size_bytes = &line[..size_end];
    if size_bytes.is_empty()
        || size_bytes.len() > 16
    {
        return Err(invalid_chunk_error());
    }
    let extensions = &line[size_end..];
    if extensions.is_empty() {
        return Ok(());
    }
    let maximum = match policy {
        ChunkExtensionPolicy::Forbidden => return Err(invalid_chunk_error()),
        ChunkExtensionPolicy::Allowed {
            maximum_extension_bytes,
        } => *maximum_extension_bytes,
    };
    if extensions.len() as u64 > maximum {
        return Err(invalid_chunk_error());
    }
    validate_chunk_extensions_syntax(extensions, true)
}

fn validate_chunk_extensions_syntax(
    extensions: &[u8],
    allow_incomplete: bool,
) -> ContractResult<()> {
    let mut position = 0usize;
    let mut parsed_extension = false;
    while position < extensions.len() {
        while position < extensions.len()
            && matches!(extensions[position], b' ' | b'\t')
        {
            position += 1;
        }
        if position == extensions.len() {
            return if allow_incomplete || parsed_extension {
                Ok(())
            } else {
                Err(invalid_chunk_error())
            };
        }
        if extensions[position] != b';' {
            return Err(invalid_chunk_error());
        }
        position += 1;
        while position < extensions.len()
            && matches!(extensions[position], b' ' | b'\t')
        {
            position += 1;
        }
        if position == extensions.len() {
            return if allow_incomplete {
                Ok(())
            } else {
                Err(invalid_chunk_error())
            };
        }
        let name_start = position;
        while position < extensions.len() && is_http_token_byte(extensions[position]) {
            position += 1;
        }
        if position == name_start {
            return Err(invalid_chunk_error());
        }
        parsed_extension = true;
        if position == extensions.len() {
            return Ok(());
        }
        while position < extensions.len()
            && matches!(extensions[position], b' ' | b'\t')
        {
            position += 1;
        }
        if position == extensions.len() {
            return if allow_incomplete {
                Ok(())
            } else {
                Err(invalid_chunk_error())
            };
        }
        match extensions[position] {
            b';' => continue,
            b'=' => {
                position += 1;
                while position < extensions.len()
                    && matches!(extensions[position], b' ' | b'\t')
                {
                    position += 1;
                }
                if position == extensions.len() {
                    return if allow_incomplete {
                        Ok(())
                    } else {
                        Err(invalid_chunk_error())
                    };
                }
                if extensions[position] == b'"' {
                    position += 1;
                    let mut closed = false;
                    while position < extensions.len() {
                        match extensions[position] {
                            b'"' => {
                                position += 1;
                                closed = true;
                                break;
                            }
                            b'\\' => {
                                position += 1;
                                if position == extensions.len() {
                                    return if allow_incomplete {
                                        Ok(())
                                    } else {
                                        Err(invalid_chunk_error())
                                    };
                                }
                                if extensions[position] != b'\t'
                                    && !(0x20..=0x7e)
                                        .contains(&extensions[position])
                                    && !(0x80..=0xff)
                                        .contains(&extensions[position])
                                {
                                    return Err(invalid_chunk_error());
                                }
                                position += 1;
                            }
                            byte
                                if byte == b'\t'
                                    || byte == b' '
                                    || (0x21..=0x7e).contains(&byte)
                                    || (0x80..=0xff).contains(&byte) =>
                            {
                                position += 1;
                            }
                            _ => return Err(invalid_chunk_error()),
                        }
                    }
                    if !closed {
                        return if allow_incomplete {
                            Ok(())
                        } else {
                            Err(invalid_chunk_error())
                        };
                    }
                } else {
                    let value_start = position;
                    while position < extensions.len()
                        && is_http_token_byte(extensions[position])
                    {
                        position += 1;
                    }
                    if position == extensions.len() {
                        return Ok(());
                    }
                    if position == value_start {
                        return Err(invalid_chunk_error());
                    }
                }
                if position == extensions.len() {
                    return Ok(());
                }
                while position < extensions.len()
                    && matches!(extensions[position], b' ' | b'\t')
                {
                    position += 1;
                }
                if position == extensions.len() {
                    return if allow_incomplete {
                        Ok(())
                    } else {
                        Err(invalid_chunk_error())
                    };
                }
                if extensions[position] != b';' {
                    return Err(invalid_chunk_error());
                }
            }
            _ => return Err(invalid_chunk_error()),
        }
    }
    Ok(())
}

fn validate_chunk_extensions(
    extensions: &[u8],
    policy: &ChunkExtensionPolicy,
) -> ContractResult<()> {
    let maximum = match policy {
        ChunkExtensionPolicy::Forbidden => {
            return Err(ContractError::new(
                "chunk_extensions_forbidden",
                "body.upstreamObservation",
                "signed response profile forbids chunk extensions",
            ))
        }
        ChunkExtensionPolicy::Allowed {
            maximum_extension_bytes,
        } => *maximum_extension_bytes,
    };
    if extensions.len() as u64 > maximum {
        return Err(invalid_chunk_error());
    }
    validate_chunk_extensions_syntax(extensions, false)
}

fn locate_trailer_block_end(raw: &[u8], start: usize) -> Option<usize> {
    let mut position = start;
    loop {
        let relative = raw[position..]
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let line_end = position + relative;
        if line_end == position {
            return Some(line_end + 2);
        }
        position = line_end + 2;
    }
}

fn validate_trailer_block(
    trailer_block: &[u8],
    declared_names: &BTreeSet<Vec<u8>>,
    policy: &TrailerPolicy,
) -> ContractResult<u32> {
    if trailer_block.is_empty()
        || !trailer_block.ends_with(b"\r\n")
        || trailer_block.len() as u64 > MAX_RESPONSE_TRAILER_BYTES
    {
        return Err(invalid_trailer_error());
    }
    let mut position = 0usize;
    let mut count = 0u32;
    let mut actual_names = BTreeSet::new();
    while position < trailer_block.len() - 2 {
        let relative = trailer_block[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(invalid_trailer_error)?;
        let line_end = position + relative;
        let line = &trailer_block[position..line_end];
        if line.is_empty() {
            return Err(invalid_trailer_error());
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(invalid_trailer_error)?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if !is_physical_response_header_name(name)
            || value.iter().any(|byte| {
                (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f
            })
            || is_forbidden_trailer_name(name)
        {
            return Err(invalid_trailer_error());
        }
        let canonical_name: Vec<u8> =
            name.iter().map(|byte| byte.to_ascii_lowercase()).collect();
        if !actual_names.insert(canonical_name) {
            return Err(invalid_trailer_error());
        }
        count = count.saturating_add(1);
        position = line_end + 2;
    }
    match policy {
        TrailerPolicy::Forbidden
            if count == 0 && declared_names.is_empty() => {}
        TrailerPolicy::Allowed {
            maximum_trailer_bytes,
            maximum_trailer_count,
        } if trailer_block.len() as u64 <= *maximum_trailer_bytes
            && count <= *maximum_trailer_count
            && &actual_names == declared_names => {}
        _ => return Err(invalid_trailer_error()),
    }
    Ok(count)
}

fn parse_comma_separated_header_names(
    value: &[u8],
) -> ContractResult<BTreeSet<Vec<u8>>> {
    let mut names = BTreeSet::new();
    for raw_name in value.split(|byte| *byte == b',') {
        let name = trim_http_ows(raw_name);
        if !is_physical_response_header_name(name)
            || is_forbidden_trailer_name(name)
        {
            return Err(invalid_trailer_error());
        }
        let canonical_name: Vec<u8> =
            name.iter().map(|byte| byte.to_ascii_lowercase()).collect();
        if !names.insert(canonical_name) {
            return Err(invalid_trailer_error());
        }
    }
    if names.is_empty() {
        return Err(invalid_trailer_error());
    }
    Ok(names)
}

fn is_forbidden_trailer_name(name: &[u8]) -> bool {
    [
        b"transfer-encoding".as_slice(),
        b"content-length".as_slice(),
        b"host".as_slice(),
        b"trailer".as_slice(),
        b"authorization".as_slice(),
        b"proxy-authorization".as_slice(),
        b"cookie".as_slice(),
        b"set-cookie".as_slice(),
    ]
    .iter()
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

fn enforce_chunk_framing_overhead(
    physical_length: u64,
    entity_length: u64,
    trailer_length: u64,
) -> ContractResult<()> {
    let overhead = physical_length
        .checked_sub(entity_length)
        .and_then(|value| value.checked_sub(trailer_length))
        .ok_or_else(invalid_chunk_error)?;
    if overhead > MAX_RESPONSE_CHUNK_FRAMING_BYTES {
        return Err(ContractError::new(
            "chunk_framing_limit",
            "body.upstreamObservation.physicalBodyLength",
            "raw chunk framing exceeds the closed overhead budget",
        ));
    }
    Ok(())
}

fn is_physical_response_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
                        | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
                | b'*' | b'+' | b'-' | b'.' | b'^'
                | b'_' | b'`' | b'|' | b'~'
        )
}

fn trim_http_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn response_bounds_error() -> ContractError {
    ContractError::new(
        "response_bounds_invalid",
        "body.upstreamObservation",
        "response segment length overflows or exceeds the closed bound",
    )
}

fn response_segment_error() -> ContractError {
    ContractError::new(
        "exact_response_segment_mismatch",
        "body.upstreamObservation",
        "informational heads, final head, and physical body must exactly partition immutable response bytes",
    )
}

fn response_framing_error() -> ContractError {
    ContractError::new(
        "response_framing_mismatch",
        "body.upstreamObservation",
        "response framing headers, physical bytes, decoded entity, completion, or EOF authority contradict one another",
    )
}

fn invalid_chunk_error() -> ContractError {
    ContractError::new(
        "invalid_chunked_response",
        "body.upstreamObservation",
        "chunked response contains invalid, ambiguous, unsupported, or out-of-bound raw chunk framing",
    )
}

fn invalid_trailer_error() -> ContractError {
    ContractError::new(
        "invalid_response_trailers",
        "body.upstreamObservation",
        "response trailers are invalid, undeclared, forbidden, duplicate, or outside the signed profile bound",
    )
}

fn validate_target_and_upstream(
    body: &ResponseObservationEnvelopeBodyV2,
    staged_digest: Option<&str>,
    exact_response: Option<&VerifiedExactUpstreamResponse>,
) -> ContractResult<()> {
    match (&body.target_egress, &body.upstream_observation) {
        (
            TargetEgressState::DefinitelyNotDispatched {
                bytes_written,
                staged_request_sha256,
                ..
            },
            UpstreamObservationState::NotApplicable { .. },
        ) => {
            if *bytes_written != 0
                || staged_request_sha256.as_deref() != staged_digest
            {
                return Err(ContractError::new(
                    "contradictory_no_dispatch_claim",
                    "body.targetEgress",
                    "definitely-not-dispatched requires zero bytes and exact optional stage binding",
                ));
            }
        }
        (
            TargetEgressState::Dispatched {
                dispatch_evidence_sha256,
                staged_request_sha256,
                bytes_written,
                dispatched_at_epoch_ms,
                ..
            },
            UpstreamObservationState::ObservedResponse {
                status,
                header_block_length,
                header_count,
                body_length,
                completion,
                response_policy_validation,
                observed_at_epoch_ms,
                ..
            },
        ) => {
            validate_digest(
                dispatch_evidence_sha256,
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                body.dispatch_evidence
                    .as_ref()
                    .map(|value| value.evidence_sha256.as_str()),
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "dispatched target egress requires staged exact bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.targetEgress.stagedRequestSha256",
            )?;
            if *bytes_written != staged.exact_request_bytes_length {
                return Err(ContractError::new(
                    "incomplete_staged_write",
                    "body.targetEgress.bytesWritten",
                    "known dispatch requires writing the exact complete staged bytes",
                ));
            }
            validate_safe_time(*dispatched_at_epoch_ms, "body.targetEgress.dispatchedAtEpochMs")?;
            if !(200..=599).contains(status)
                || *header_block_length > MAX_HEADER_BYTES
                || *header_count > MAX_HEADER_COUNT
                || *body_length > MAX_RESPONSE_ENTITY_BYTES
                || *dispatched_at_epoch_ms > body.issued_at_epoch_ms
                || body.dispatch_evidence.as_ref().is_none_or(|evidence| {
                    *dispatched_at_epoch_ms
                        < evidence.payload.authorized_at_epoch_ms
                })
                || *observed_at_epoch_ms < *dispatched_at_epoch_ms
                || *observed_at_epoch_ms > body.issued_at_epoch_ms
            {
                return Err(ContractError::new(
                    "invalid_upstream_observation",
                    "body.upstreamObservation",
                    "upstream status, bounds, or observation time is invalid",
                ));
            }
            let exact = exact_response.ok_or_else(|| {
                ContractError::new(
                    "missing_exact_upstream_response",
                    "body.upstreamObservation",
                    "observed response requires exact immutable retrieval before policy validation",
                )
            })?;
            if exact.completion != *completion
                || exact.response_policy_validation_sha256.as_deref()
                    != Some(response_policy_validation.validation_sha256.as_str())
                || exact.exact_response_bytes_sha256
                    != response_policy_validation.exact_response_bytes_sha256
                || exact.unsupported_reason.is_some()
            {
                return Err(ContractError::new(
                    "exact_upstream_response_binding_mismatch",
                    "body.upstreamObservation",
                    "observed response metadata and policy result must equal exact immutable reconstruction",
                ));
            }
        }
        (
            TargetEgressState::Dispatched {
                dispatch_evidence_sha256,
                staged_request_sha256,
                bytes_written,
                dispatched_at_epoch_ms,
                ..
            },
            UpstreamObservationState::ExactResponseUnsupported {
                exact_response_bytes_sha256,
                completion,
                reason,
                response_policy_decision,
                downstream_delivery,
                observed_at_epoch_ms,
                ..
            },
        ) => {
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                body.dispatch_evidence
                    .as_ref()
                    .map(|value| value.evidence_sha256.as_str()),
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "unsupported exact response requires the staged request that was dispatched",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.targetEgress.stagedRequestSha256",
            )?;
            let exact = exact_response.ok_or_else(|| {
                ContractError::new(
                    "missing_exact_unsupported_response",
                    "body.upstreamObservation",
                    "unsupported response requires trusted immutable exact-byte retrieval",
                )
            })?;
            if *bytes_written != staged.exact_request_bytes_length
                || *response_policy_decision
                    != ResponsePolicyDecision::NotEvaluatedUnsupportedResponse
                || *downstream_delivery != DownstreamDeliveryState::Unknown
                || exact.completion != *completion
                || exact.unsupported_reason != Some(*reason)
                || exact.response_policy_validation_sha256.is_some()
                || exact.exact_response_bytes_sha256
                    != exact_response_bytes_sha256.as_str()
                || *dispatched_at_epoch_ms > body.issued_at_epoch_ms
                || body.dispatch_evidence.as_ref().is_none_or(|evidence| {
                    *dispatched_at_epoch_ms
                        < evidence.payload.authorized_at_epoch_ms
                })
                || *observed_at_epoch_ms < *dispatched_at_epoch_ms
                || *observed_at_epoch_ms > body.issued_at_epoch_ms
            {
                return Err(ContractError::new(
                    "invalid_exact_unsupported_response",
                    "body.upstreamObservation",
                    "unsupported exact response must preserve complete dispatch, trusted protocol/framing reason, provider completion, exact bytes, and non-passing delivery truth",
                ));
            }
            validate_safe_time(
                *dispatched_at_epoch_ms,
                "body.targetEgress.dispatchedAtEpochMs",
            )?;
            validate_safe_time(
                *observed_at_epoch_ms,
                "body.upstreamObservation.observedAtEpochMs",
            )?;
        }
        (
            TargetEgressState::WriteOutcomeUnknown {
                dispatch_evidence_sha256,
                staged_request_sha256,
                bytes_written_lower_bound,
                unknown_at_epoch_ms,
                recovery_binding_sha256,
                ..
            },
            UpstreamObservationState::WriteOutcomeUnknown {
                transition_unknown_evidence_sha256,
                recovery_binding_sha256: upstream_recovery,
                response_policy_decision,
                downstream_delivery,
                ..
            },
        ) => {
            validate_digest(
                dispatch_evidence_sha256,
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            validate_digest(
                transition_unknown_evidence_sha256,
                "body.upstreamObservation.transitionUnknownEvidenceSha256",
            )?;
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                body.dispatch_evidence
                    .as_ref()
                    .map(|value| value.evidence_sha256.as_str()),
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                transition_unknown_evidence_sha256,
                &body.terminal_evidence.evidence_sha256,
                "body.upstreamObservation.transitionUnknownEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "unknown target outcome requires staged exact bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.targetEgress.stagedRequestSha256",
            )?;
            if bytes_written_lower_bound
                .is_some_and(|value| value > staged.exact_request_bytes_length)
            {
                return Err(ContractError::new(
                    "invalid_unknown_write_count",
                    "body.targetEgress.bytesWrittenLowerBound",
                    "unknown write lower bound, when known, cannot exceed exact staged bytes",
                ));
            }
            if *response_policy_decision
                != ResponsePolicyDecision::NotEvaluatedIncompleteResponse
                || *downstream_delivery != DownstreamDeliveryState::Unknown
            {
                return Err(ContractError::new(
                    "unknown_write_passing_claim",
                    "body.upstreamObservation",
                    "unknown write outcome must remain non-passing with downstream delivery unknown",
                ));
            }
            validate_safe_time(*unknown_at_epoch_ms, "body.targetEgress.unknownAtEpochMs")?;
            if *unknown_at_epoch_ms > body.issued_at_epoch_ms {
                return Err(ContractError::new(
                    "future_unknown_transition",
                    "body.targetEgress.unknownAtEpochMs",
                    "unknown transition cannot occur after envelope issuance",
                ));
            }
            if body.dispatch_evidence.as_ref().is_none_or(|evidence| {
                *unknown_at_epoch_ms < evidence.payload.authorized_at_epoch_ms
            }) {
                return Err(ContractError::new(
                    "unknown_before_dispatch_authority",
                    "body.targetEgress.unknownAtEpochMs",
                    "unknown write transition cannot precede signed dispatch authority",
                ));
            }
            require_equal_digest(
                recovery_binding_sha256,
                upstream_recovery,
                "body.upstreamObservation.recoveryBindingSha256",
            )?;
            require_equal_digest(
                recovery_binding_sha256,
                route_recovery_binding(&body.route_semantics)?,
                "body.targetEgress.recoveryBindingSha256",
            )?;
        }
        (
            TargetEgressState::ReadOutcomeUnknown {
                dispatch_evidence_sha256,
                staged_request_sha256,
                bytes_written_lower_bound,
                unknown_at_epoch_ms,
                retry_binding_sha256,
                ..
            },
            UpstreamObservationState::ReadOutcomeUnknown {
                transition_unknown_evidence_sha256,
                retry_binding_sha256: upstream_retry,
                response_policy_decision,
                downstream_delivery,
                ..
            },
        ) => {
            require_equal_optional_digest(
                dispatch_evidence_sha256,
                body.dispatch_evidence
                    .as_ref()
                    .map(|value| value.evidence_sha256.as_str()),
                "body.targetEgress.dispatchEvidenceSha256",
            )?;
            require_equal_digest(
                transition_unknown_evidence_sha256,
                &body.terminal_evidence.evidence_sha256,
                "body.upstreamObservation.transitionUnknownEvidenceSha256",
            )?;
            let staged = body.staged_target_request.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_staged_request",
                    "body.stagedTargetRequest",
                    "unknown read outcome requires exact staged bytes",
                )
            })?;
            require_equal_digest(
                staged_request_sha256,
                &staged.staging_sha256,
                "body.targetEgress.stagedRequestSha256",
            )?;
            if bytes_written_lower_bound
                .is_some_and(|value| value > staged.exact_request_bytes_length)
                || *unknown_at_epoch_ms > body.issued_at_epoch_ms
                || *response_policy_decision
                    != ResponsePolicyDecision::NotEvaluatedIncompleteResponse
                || *downstream_delivery != DownstreamDeliveryState::Unknown
            {
                return Err(ContractError::new(
                    "invalid_unknown_read_state",
                    "body.targetEgress",
                    "unknown read must have a bounded optional write lower bound and remain non-passing with delivery unknown",
                ));
            }
            validate_safe_time(
                *unknown_at_epoch_ms,
                "body.targetEgress.unknownAtEpochMs",
            )?;
            if body.dispatch_evidence.as_ref().is_none_or(|evidence| {
                *unknown_at_epoch_ms < evidence.payload.authorized_at_epoch_ms
            }) {
                return Err(ContractError::new(
                    "unknown_before_dispatch_authority",
                    "body.targetEgress.unknownAtEpochMs",
                    "unknown read transition cannot precede signed dispatch authority",
                ));
            }
            require_equal_digest(
                retry_binding_sha256,
                upstream_retry,
                "body.upstreamObservation.retryBindingSha256",
            )?;
            require_equal_digest(
                retry_binding_sha256,
                route_read_retry_binding(&body.route_semantics)?,
                "body.targetEgress.retryBindingSha256",
            )?;
        }
        _ => {
            return Err(ContractError::new(
                "target_upstream_state_mismatch",
                "body",
                "target egress and upstream observation states contradict one another",
            ))
        }
    }
    if !matches!(
        &body.upstream_observation,
        UpstreamObservationState::ObservedResponse { .. }
            | UpstreamObservationState::ExactResponseUnsupported { .. }
    ) && exact_response.is_some()
    {
        return Err(ContractError::new(
            "unexpected_exact_upstream_response",
            "body.upstreamObservation",
            "only observed-response or exact-response-unsupported may carry exact retrieved response authority",
        ));
    }
    Ok(())
}

fn validate_lifecycle(body: &ResponseObservationEnvelopeBodyV2) -> ContractResult<()> {
    if body.lifecycle.len() < 3
        || body.lifecycle.len() > MAX_LIFECYCLE_TRANSITIONS
        || body.lifecycle.first().map(|item| item.state)
            != Some(LifecycleState::Received)
        || body.lifecycle.get(1).map(|item| item.state)
            != Some(LifecycleState::PolicyEvaluated)
        || !body
            .lifecycle
            .last()
            .is_some_and(|item| item.state.is_terminal())
    {
        return Err(ContractError::new(
            "invalid_lifecycle_shape",
            "body.lifecycle",
            "lifecycle must begin received/policy-evaluated and end in one terminal state",
        ));
    }
    let mut previous_time = 0;
    for (index, item) in body.lifecycle.iter().enumerate() {
        validate_safe_time(item.at_epoch_ms, "body.lifecycle.atEpochMs")?;
        if usize::from(item.sequence) != index + 1
            || item.at_epoch_ms < previous_time
            || item.at_epoch_ms > body.issued_at_epoch_ms
        {
            return Err(ContractError::new(
                "non_monotonic_lifecycle",
                "body.lifecycle",
                "lifecycle sequence or timestamps are not monotonic and bounded",
            ));
        }
        previous_time = item.at_epoch_ms;
        let expected_binding = lifecycle_binding(body, item.state);
        if item.binding_sha256.as_deref() != expected_binding {
            return Err(ContractError::new(
                "lifecycle_binding_mismatch",
                "body.lifecycle",
                "lifecycle transition does not bind its required immutable evidence",
            ));
        }
        if let Some(next) = body.lifecycle.get(index + 1) {
            if !valid_lifecycle_edge(item.state, next.state) {
                return Err(ContractError::new(
                    "invalid_lifecycle_transition",
                    "body.lifecycle",
                    "lifecycle contains a non-monotonic or impossible transition",
                ));
            }
        }
    }
    let expected_terminal = match body.authorization {
        AuthorizationState::DeniedBeforeReserve { .. }
        | AuthorizationState::ReservedCancelled { .. }
        | AuthorizationState::DispatchCancelled { .. } => LifecycleState::TerminalCancelled,
        AuthorizationState::DispatchCompleted { .. } => LifecycleState::TerminalCompleted,
        AuthorizationState::DispatchResponseRejected { .. } => {
            LifecycleState::TerminalResponseRejected
        }
        AuthorizationState::DispatchExactResponseUnsupported { .. } => {
            LifecycleState::TerminalExactResponseUnsupported
        }
        AuthorizationState::WriteDispatchTransitionUnknown { .. }
        | AuthorizationState::ReadDispatchTransitionUnknown { .. } => {
            LifecycleState::TerminalTransitionUnknown
        }
    };
    if body.lifecycle.last().map(|item| item.state) != Some(expected_terminal) {
        return Err(ContractError::new(
            "terminal_lifecycle_mismatch",
            "body.lifecycle",
            "terminal lifecycle state does not match authorization state",
        ));
    }
    Ok(())
}

fn lifecycle_binding(
    body: &ResponseObservationEnvelopeBodyV2,
    state: LifecycleState,
) -> Option<&str> {
    match state {
        LifecycleState::Received | LifecycleState::PolicyEvaluated => None,
        LifecycleState::AuthorizationReserved => body
            .reserve_evidence
            .as_ref()
            .map(|value| value.evidence_sha256.as_str()),
        LifecycleState::CredentialAuthorityComplete => body
            .credential_authority_evidence
            .last()
            .map(|value| value.evidence_sha256.as_str()),
        LifecycleState::TargetRequestStaged => body
            .staged_target_request
            .as_ref()
            .map(|value| value.staging_sha256.as_str()),
        LifecycleState::DispatchAuthorized
        | LifecycleState::TargetWriteStarted => body
            .dispatch_evidence
            .as_ref()
            .map(|value| value.evidence_sha256.as_str()),
        LifecycleState::TerminalCancelled
        | LifecycleState::TerminalCompleted
        | LifecycleState::TerminalResponseRejected
        | LifecycleState::TerminalExactResponseUnsupported
        | LifecycleState::TerminalTransitionUnknown => {
            Some(body.terminal_evidence.evidence_sha256.as_str())
        }
    }
}

fn valid_lifecycle_edge(from: LifecycleState, to: LifecycleState) -> bool {
    use LifecycleState::*;
    matches!(
        (from, to),
        (Received, PolicyEvaluated)
            | (PolicyEvaluated, AuthorizationReserved)
            | (PolicyEvaluated, TerminalCancelled)
            | (AuthorizationReserved, CredentialAuthorityComplete)
            | (AuthorizationReserved, TargetRequestStaged)
            | (AuthorizationReserved, TerminalCancelled)
            | (CredentialAuthorityComplete, TargetRequestStaged)
            | (CredentialAuthorityComplete, TerminalCancelled)
            | (TargetRequestStaged, DispatchAuthorized)
            | (TargetRequestStaged, TerminalCancelled)
            | (DispatchAuthorized, TargetWriteStarted)
            | (DispatchAuthorized, TerminalCancelled)
            | (TargetWriteStarted, TerminalCompleted)
            | (TargetWriteStarted, TerminalResponseRejected)
            | (TargetWriteStarted, TerminalExactResponseUnsupported)
            | (TargetWriteStarted, TerminalTransitionUnknown)
    )
}

fn validate_authority(
    body: &ResponseObservationEnvelopeBodyV2,
    context: &VerificationContext<'_>,
) -> ContractResult<()> {
    match &body.authority {
        ObservationAuthority::GateAuthored { .. } => {
            if body.custody_authority_evidence.is_some() {
                return Err(ContractError::new(
                    "unexpected_custody_authority",
                    "body.custodyAuthorityEvidence",
                    "gate-authored authority cannot carry an unused higher-authority proof",
                ));
            }
        }
        ObservationAuthority::MeasuredCustody {
            custody_authority_evidence_sha256,
            ..
        } => {
            let evidence = body.custody_authority_evidence.as_ref().ok_or_else(|| {
                ContractError::new(
                    "missing_custody_authority_evidence",
                    "body.custodyAuthorityEvidence",
                    "elevated authority requires measured custody evidence",
                )
            })?;
            require_equal_digest(
                custody_authority_evidence_sha256,
                &evidence.evidence_sha256,
                "body.authority.custodyAuthorityEvidenceSha256",
            )?;
            let payload = &evidence.payload;
            if payload.attempt_id != body.attempt_id
                || payload.policy_sha256 != body.policy.policy_sha256()
                || payload.runtime_measurement_sha256
                    != context
                        .expected_runtime()
                        .identity()
                        .runtime_measurement_sha256
                || payload.rollback_state_epoch
                    != context
                        .expected_runtime()
                        .identity()
                        .rollback_state_epoch
                || payload.staged_request_sha256.as_deref()
                    != body
                        .staged_target_request
                        .as_ref()
                        .map(|value| value.staging_sha256.as_str())
                || !has_exact_custody_capabilities(&payload.capabilities)
            {
                return Err(ContractError::new(
                    "custody_authority_binding_mismatch",
                    "body.custodyAuthorityEvidence.payload",
                    "higher authority lacks the exact measured end-to-end custody ownership set",
                ));
            }
        }
    }
    Ok(())
}

fn has_exact_custody_capabilities(capabilities: &[CustodyCapability]) -> bool {
    if capabilities.len() != 6 {
        return false;
    }
    let set: BTreeSet<u8> = capabilities
        .iter()
        .map(|capability| match capability {
            CustodyCapability::LeaseDecryption => 0,
            CustodyCapability::CredentialInjection => 1,
            CustodyCapability::TargetTls => 2,
            CustodyCapability::TargetEgress => 3,
            CustodyCapability::ProofSigning => 4,
            CustodyCapability::RollbackProtectedState => 5,
        })
        .collect();
    set == BTreeSet::from([0, 1, 2, 3, 4, 5])
}

fn validate_route_semantic_profile_payload(
    payload: &RouteSemanticProfileEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (
            &payload.authorization_binding_sha256,
            "routeSemanticProfile.payload.authorizationBindingSha256",
        ),
        (
            &payload.policy_sha256,
            "routeSemanticProfile.payload.policySha256",
        ),
        (
            &payload.operation_sha256,
            "routeSemanticProfile.payload.operationSha256",
        ),
        (
            &payload.semantic_profile_sha256,
            "routeSemanticProfile.payload.semanticProfileSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_safe_integer(
        payload.snapshot_epoch,
        "routeSemanticProfile.payload.snapshotEpoch",
    )?;
    if payload.snapshot_epoch == 0 {
        return Err(ContractError::new(
            "invalid_snapshot_epoch",
            "routeSemanticProfile.payload.snapshotEpoch",
            "route semantic profile snapshot epoch must be positive",
        ));
    }
    if let Some(value) = payload.route_id.as_deref() {
        validate_identifier(value, "routeSemanticProfile.payload.routeId")?;
    }
    validate_http_method(&payload.method)?;
    if let Some(target) = payload.canonical_target.as_ref() {
        validate_canonical_target(target)?;
    }
    if let Some(value) = payload.provider_id.as_deref() {
        validate_identifier(value, "routeSemanticProfile.payload.providerId")?;
    }
    for (value, path) in [
        (
            payload.provider_profile_sha256.as_deref(),
            "routeSemanticProfile.payload.providerProfileSha256",
        ),
        (
            payload.provider_schema_sha256.as_deref(),
            "routeSemanticProfile.payload.providerSchemaSha256",
        ),
        (
            payload.credential_identity_sha256.as_deref(),
            "routeSemanticProfile.payload.credentialIdentitySha256",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, path)?;
        }
    }
    validate_safe_time(
        payload.signed_at_epoch_ms,
        "routeSemanticProfile.payload.signedAtEpochMs",
    )?;
    let expected = route_semantic_profile_digest(payload)?;
    require_equal_digest(
        &payload.semantic_profile_sha256,
        &expected,
        "routeSemanticProfile.payload.semanticProfileSha256",
    )
}

fn validate_credential_authority_evidence_payload(
    payload: &CredentialAuthorityEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    validate_identifier(
        &payload.authority_id,
        "credentialAuthority.payload.authorityId",
    )?;
    for (value, path) in [
        (
            &payload.authorization_binding_sha256,
            "credentialAuthority.payload.authorizationBindingSha256",
        ),
        (
            &payload.route_semantic_profile_sha256,
            "credentialAuthority.payload.routeSemanticProfileSha256",
        ),
        (
            &payload.prerequisite_sha256,
            "credentialAuthority.payload.prerequisiteSha256",
        ),
        (
            &payload.plan_step_sha256,
            "credentialAuthority.payload.planStepSha256",
        ),
        (
            &payload.prior_execution_state_sha256,
            "credentialAuthority.payload.priorExecutionStateSha256",
        ),
        (
            &payload.execution_state_sha256,
            "credentialAuthority.payload.executionStateSha256",
        ),
        (
            &payload.effect_binding_sha256,
            "credentialAuthority.payload.effectBindingSha256",
        ),
        (
            &payload.operation_record_sha256,
            "credentialAuthority.payload.operationRecordSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    if payload.sequence == 0
        || usize::from(payload.sequence)
            > MAX_CREDENTIAL_AUTHORITY_OPERATIONS
    {
        return Err(ContractError::new(
            "credential_authority_sequence_invalid",
            "credentialAuthority.payload.sequence",
            "authority sequence must be a positive bounded one-based index",
        ));
    }
    if let Some(value) = payload.credential_binding_sha256.as_deref() {
        validate_digest(
            value,
            "credentialAuthority.payload.credentialBindingSha256",
        )?;
    }
    if payload.operation != payload.operation_evidence.operation() {
        return Err(ContractError::new(
            "credential_authority_operation_mismatch",
            "credentialAuthority.payload.operation",
            "the signer-scoped operation must exactly match the closed typed operation record",
        ));
    }
    validate_credential_authority_operation_evidence(
        &payload.operation_evidence,
        &payload.authority_id,
        &payload.authorization_binding_sha256,
        payload.completed_at_epoch_ms,
    )?;
    let operation_record = credential_authority_record_binding(payload)?;
    require_equal_digest(
        &payload.operation_record_sha256,
        &operation_record,
        "credentialAuthority.payload.operationRecordSha256",
    )?;
    let expected_execution_state = credential_authority_execution_state(
        &payload.prior_execution_state_sha256,
        &payload.operation_record_sha256,
    )?;
    require_equal_digest(
        &payload.execution_state_sha256,
        &expected_execution_state,
        "credentialAuthority.payload.executionStateSha256",
    )?;
    let expected_effect = credential_authority_effect_binding(payload)?;
    require_equal_digest(
        &payload.effect_binding_sha256,
        &expected_effect,
        "credentialAuthority.payload.effectBindingSha256",
    )?;
    let requires_credential_binding =
        payload.operation_evidence.requires_credential_binding();
    if requires_credential_binding != payload.credential_binding_sha256.is_some()
    {
        return Err(ContractError::new(
            "credential_authority_result_shape_mismatch",
            "credentialAuthority.payload.credentialBindingSha256",
            "successful credential access and every OAuth outcome must carry the exact policy credential binding; all other authority outcomes must omit it",
        ));
    }
    validate_safe_time(
        payload.completed_at_epoch_ms,
        "credentialAuthority.payload.completedAtEpochMs",
    )
}

impl CredentialAuthorityOperationEvidence {
    fn operation(&self) -> CredentialAuthorityOperation {
        match self {
            Self::Grant { request, .. } => match request.action {
                GrantAuthorityAction::Reserve => {
                    CredentialAuthorityOperation::ReserveGrant
                }
                GrantAuthorityAction::Consume => {
                    CredentialAuthorityOperation::ConsumeGrant
                }
            },
            Self::QuotaBudget { request, .. } => match request.action {
                QuotaBudgetAction::Reserve => {
                    CredentialAuthorityOperation::ReserveQuota
                }
                QuotaBudgetAction::Consume => {
                    CredentialAuthorityOperation::ConsumeQuota
                }
                QuotaBudgetAction::Cancel => {
                    CredentialAuthorityOperation::CancelQuotaReservation
                }
            },
            Self::CredentialAccess { request, .. } => match request.action {
                CredentialAccessAction::AcquireLease => {
                    CredentialAuthorityOperation::AcquireCredentialLease
                }
                CredentialAccessAction::AuthorizeDecryption => {
                    CredentialAuthorityOperation::AuthorizeCredentialDecryption
                }
                CredentialAccessAction::AuthorizeInjection => {
                    CredentialAuthorityOperation::AuthorizeCredentialInjection
                }
            },
            Self::OauthToken { request, .. } => match request.action {
                OauthTokenAction::Refresh => {
                    CredentialAuthorityOperation::RefreshOauthToken
                }
                OauthTokenAction::Exchange => {
                    CredentialAuthorityOperation::ExchangeOauthToken
                }
                OauthTokenAction::Mint => CredentialAuthorityOperation::MintToken,
            },
        }
    }

    fn request_jcs(&self) -> ContractResult<Vec<u8>> {
        match self {
            Self::Grant { request, .. } => {
                canonical_jcs_bytes(&("grant", request))
            }
            Self::QuotaBudget { request, .. } => {
                canonical_jcs_bytes(&("quota-budget", request))
            }
            Self::CredentialAccess { request, .. } => {
                canonical_jcs_bytes(&("credential-access", request))
            }
            Self::OauthToken { request, .. } => {
                canonical_jcs_bytes(&("oauth-token", request))
            }
        }
    }

    fn is_succeeded(&self) -> bool {
        matches!(
            self,
            Self::Grant {
                result: GrantAuthorityResult::Succeeded { .. },
                ..
            } | Self::QuotaBudget {
                result: QuotaBudgetResult::Succeeded { .. },
                ..
            } | Self::CredentialAccess {
                result: CredentialAccessResult::Succeeded { .. },
                ..
            } | Self::OauthToken {
                result: OauthTokenResult::Succeeded { .. },
                ..
            }
        )
    }

    fn outcome_kind(&self) -> AuthorityOperationOutcome {
        if self.is_succeeded() {
            AuthorityOperationOutcome::Succeeded
        } else if let Some(failure) = self.definite_failure() {
            AuthorityOperationOutcome::DefinitelyFailed(failure)
        } else {
            AuthorityOperationOutcome::TransitionUnknown
        }
    }

    fn succeeded_with_credential(&self) -> bool {
        matches!(
            self,
            Self::CredentialAccess {
                result: CredentialAccessResult::Succeeded { .. },
                ..
            } | Self::OauthToken {
                result: OauthTokenResult::Succeeded { .. },
                ..
            }
        )
    }

    fn requires_credential_binding(&self) -> bool {
        self.succeeded_with_credential()
            || matches!(self, Self::OauthToken { .. })
    }

    fn definite_failure(&self) -> Option<CredentialAuthorityFailure> {
        match self {
            Self::Grant {
                result: GrantAuthorityResult::DefinitelyFailed { failure, .. },
                ..
            }
            | Self::QuotaBudget {
                result: QuotaBudgetResult::DefinitelyFailed { failure, .. },
                ..
            }
            | Self::CredentialAccess {
                result: CredentialAccessResult::DefinitelyFailed {
                    failure, ..
                },
                ..
            }
            | Self::OauthToken {
                result: OauthTokenResult::DefinitelyFailed { failure, .. },
                ..
            } => Some(*failure),
            _ => None,
        }
    }

    fn recovery_binding_sha256(&self) -> Option<&str> {
        match self {
            Self::Grant {
                result: GrantAuthorityResult::TransitionUnknown { recovery },
                ..
            }
            | Self::QuotaBudget {
                result: QuotaBudgetResult::TransitionUnknown { recovery },
                ..
            }
            | Self::CredentialAccess {
                result: CredentialAccessResult::TransitionUnknown { recovery },
                ..
            }
            | Self::OauthToken {
                result:
                    OauthTokenResult::TransitionUnknown {
                        recovery, ..
                    },
                ..
            } => Some(recovery.recovery_binding_sha256.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
enum AuthorityOperationOutcome {
    Succeeded,
    DefinitelyFailed(CredentialAuthorityFailure),
    TransitionUnknown,
}

fn validate_credential_authority_operation_evidence(
    evidence: &CredentialAuthorityOperationEvidence,
    authority_id: &str,
    authorization_binding_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    match evidence {
        CredentialAuthorityOperationEvidence::Grant { request, result } => {
            validate_grant_authority(
                request,
                result,
                authorization_binding_sha256,
                completed_at_epoch_ms,
            )
        }
        CredentialAuthorityOperationEvidence::QuotaBudget {
            request,
            result,
        } => validate_quota_budget(
            request,
            result,
            authorization_binding_sha256,
            completed_at_epoch_ms,
        ),
        CredentialAuthorityOperationEvidence::CredentialAccess {
            request,
            result,
        } => validate_credential_access(
            request,
            result,
            authorization_binding_sha256,
            completed_at_epoch_ms,
        ),
        CredentialAuthorityOperationEvidence::OauthToken {
            request,
            result,
        } => validate_oauth_token(
            request,
            result,
            authority_id,
            authorization_binding_sha256,
            completed_at_epoch_ms,
        ),
    }
}

fn validate_webauthn_approval_identity(
    approval: &WebAuthnApprovalIdentity,
) -> ContractResult<()> {
    for value in [
        &approval.approval_id,
        &approval.assertion_id,
        &approval.assertion_consumption_id,
        &approval.rp_id,
    ] {
        validate_identifier(value, "credentialAuthority.grant.webauthnApproval")?;
    }
    for digest in [
        &approval.credential_id_sha256,
        &approval.authenticator_data_sha256,
        &approval.client_data_json_sha256,
        &approval.challenge_sha256,
        &approval.assertion_consumption_sha256,
        &approval.origin_sha256,
    ] {
        validate_digest(digest, "credentialAuthority.grant.webauthnApproval")?;
    }
    validate_safe_time(
        approval.valid_from_epoch_ms,
        "credentialAuthority.grant.webauthnApproval.validFromEpochMs",
    )?;
    validate_safe_time(
        approval.expires_at_epoch_ms,
        "credentialAuthority.grant.webauthnApproval.expiresAtEpochMs",
    )?;
    if approval.expires_at_epoch_ms <= approval.valid_from_epoch_ms
        || approval.expires_at_epoch_ms - approval.valid_from_epoch_ms
            > MAX_EVIDENCE_TTL_MS
    {
        return Err(ContractError::new(
            "invalid_webauthn_approval_window",
            "credentialAuthority.grant.webauthnApproval",
            "WebAuthn/JIT approval must carry one positive bounded validity interval",
        ));
    }
    Ok(())
}

fn validate_grant_authority(
    request: &GrantAuthorityRequest,
    result: &GrantAuthorityResult,
    authorization_binding_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    for (value, path) in [
        (&request.grant_id, "credentialAuthority.grant.grantId"),
        (&request.approval_id, "credentialAuthority.grant.approvalId"),
        (
            &request.reservation_id,
            "credentialAuthority.grant.reservationId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    for (value, path) in [
        (&request.policy_sha256, "credentialAuthority.grant.policySha256"),
        (
            &request.request_sha256,
            "credentialAuthority.grant.requestSha256",
        ),
        (
            &request.operation_sha256,
            "credentialAuthority.grant.operationSha256",
        ),
        (
            &request.authorization_binding_sha256,
            "credentialAuthority.grant.authorizationBindingSha256",
        ),
        (
            &request.prior_use_state_sha256,
            "credentialAuthority.grant.priorUseStateSha256",
        ),
        (
            &request.new_use_state_sha256,
            "credentialAuthority.grant.newUseStateSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    require_equal_digest(
        &request.authorization_binding_sha256,
        authorization_binding_sha256,
        "credentialAuthority.grant.authorizationBindingSha256",
    )?;
    for (value, path) in [
        (request.prior_use_count, "credentialAuthority.grant.priorUseCount"),
        (request.new_use_count, "credentialAuthority.grant.newUseCount"),
        (
            request.maximum_use_count,
            "credentialAuthority.grant.maximumUseCount",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    if request.maximum_use_count == 0
        || request.prior_use_count > request.maximum_use_count
        || request.new_use_count > request.maximum_use_count
    {
        return Err(ContractError::new(
            "invalid_grant_use_transition",
            "credentialAuthority.grant",
            "grant counters must remain inside the positive configured use limit",
        ));
    }
    match (&request.webauthn_approval, request.webauthn_required) {
        (Some(approval), true) => {
            validate_webauthn_approval_identity(approval)?;
            if approval.approval_id != request.approval_id
                || completed_at_epoch_ms < approval.valid_from_epoch_ms
                || completed_at_epoch_ms >= approval.expires_at_epoch_ms
            {
                return Err(ContractError::new(
                    "webauthn_approval_binding_mismatch",
                    "credentialAuthority.grant.webauthnApproval",
                    "the WebAuthn assertion must identify the exact grant approval and be consumed inside its signed JIT validity interval",
                ));
            }
        }
        (None, false) => {}
        _ => {
            return Err(ContractError::new(
                "webauthn_requirement_mismatch",
                "credentialAuthority.grant.webauthnApproval",
                "required WebAuthn evidence must be present and optional evidence must be absent",
            ));
        }
    }
    match result {
        GrantAuthorityResult::Succeeded {
            transition_receipt_id,
            transition_receipt_sha256,
            reservation_expires_at_epoch_ms,
        } => {
            validate_identifier(
                transition_receipt_id,
                "credentialAuthority.grant.transitionReceiptId",
            )?;
            validate_digest(
                transition_receipt_sha256,
                "credentialAuthority.grant.transitionReceiptSha256",
            )?;
            let valid_counter = match request.action {
                GrantAuthorityAction::Reserve => {
                    request.new_use_count == request.prior_use_count
                }
                GrantAuthorityAction::Consume => request
                    .prior_use_count
                    .checked_add(1)
                    .is_some_and(|next| request.new_use_count == next),
            };
            if !valid_counter
                || request.prior_use_state_sha256
                    == request.new_use_state_sha256
            {
                return Err(ContractError::new(
                    "invalid_grant_use_transition",
                    "credentialAuthority.grant",
                    "successful grant reservation or consume must make its exact permitted monotonic transition",
                ));
            }
            if let Some(expires_at) = reservation_expires_at_epoch_ms {
                validate_safe_time(
                    *expires_at,
                    "credentialAuthority.grant.reservationExpiresAtEpochMs",
                )?;
                if request.action != GrantAuthorityAction::Reserve
                    || *expires_at <= completed_at_epoch_ms
                {
                    return Err(ContractError::new(
                        "invalid_grant_reservation_expiry",
                        "credentialAuthority.grant.reservationExpiresAtEpochMs",
                        "only a successful reservation may carry a future expiry",
                    ));
                }
            } else if request.action == GrantAuthorityAction::Reserve {
                return Err(ContractError::new(
                    "missing_grant_reservation_expiry",
                    "credentialAuthority.grant.reservationExpiresAtEpochMs",
                    "successful grant reservation requires a bounded expiry",
                ));
            }
        }
        GrantAuthorityResult::DefinitelyFailed {
            failure_receipt_id,
            failure_receipt_sha256,
            ..
        } => {
            validate_failure_receipt(
                failure_receipt_id,
                failure_receipt_sha256,
                "credentialAuthority.grant",
            )?;
            require_unchanged_transition(
                request.prior_use_count,
                request.new_use_count,
                &request.prior_use_state_sha256,
                &request.new_use_state_sha256,
                "credentialAuthority.grant",
            )?;
        }
        GrantAuthorityResult::TransitionUnknown { recovery } => {
            let transition_identity =
                credential_authority_transition_identity("grant", request)?;
            validate_durable_authority_recovery(
                recovery,
                &transition_identity,
                &request.prior_use_state_sha256,
                completed_at_epoch_ms,
            )?;
            require_unchanged_transition(
                request.prior_use_count,
                request.new_use_count,
                &request.prior_use_state_sha256,
                &request.new_use_state_sha256,
                "credentialAuthority.grant",
            )?;
        }
    }
    Ok(())
}

fn validate_quota_budget(
    request: &QuotaBudgetRequest,
    result: &QuotaBudgetResult,
    authorization_binding_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    for (value, path) in [
        (&request.counter_id, "credentialAuthority.quota.counterId"),
        (&request.budget_id, "credentialAuthority.quota.budgetId"),
        (
            &request.reservation_id,
            "credentialAuthority.quota.reservationId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    validate_safe_time(
        request.window_start_epoch_ms,
        "credentialAuthority.quota.windowStartEpochMs",
    )?;
    validate_safe_time(
        request.window_end_epoch_ms,
        "credentialAuthority.quota.windowEndEpochMs",
    )?;
    validate_safe_time(
        request.reservation_expires_at_epoch_ms,
        "credentialAuthority.quota.reservationExpiresAtEpochMs",
    )?;
    validate_safe_integer(request.units, "credentialAuthority.quota.units")?;
    validate_safe_integer(
        request.prior_sequence,
        "credentialAuthority.quota.priorSequence",
    )?;
    validate_safe_integer(
        request.new_sequence,
        "credentialAuthority.quota.newSequence",
    )?;
    validate_digest(
        &request.prior_state_sha256,
        "credentialAuthority.quota.priorStateSha256",
    )?;
    validate_digest(
        &request.new_state_sha256,
        "credentialAuthority.quota.newStateSha256",
    )?;
    for (value, path) in [
        (
            &request.weight_basis_sha256,
            "credentialAuthority.quota.weightBasisSha256",
        ),
        (
            &request.request_sha256,
            "credentialAuthority.quota.requestSha256",
        ),
        (
            &request.operation_sha256,
            "credentialAuthority.quota.operationSha256",
        ),
        (
            &request.authorization_binding_sha256,
            "credentialAuthority.quota.authorizationBindingSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    require_equal_digest(
        &request.authorization_binding_sha256,
        authorization_binding_sha256,
        "credentialAuthority.quota.authorizationBindingSha256",
    )?;
    if request.window_end_epoch_ms <= request.window_start_epoch_ms
        || request.reservation_expires_at_epoch_ms
            <= request.window_start_epoch_ms
        || request.reservation_expires_at_epoch_ms
            > request.window_end_epoch_ms
        || request.units == 0
    {
        return Err(ContractError::new(
            "invalid_quota_window",
            "credentialAuthority.quota",
            "quota/budget evidence requires a positive bounded window and unit count",
        ));
    }
    if matches!(result, QuotaBudgetResult::Succeeded { .. })
        && request.action != QuotaBudgetAction::Cancel
        && (completed_at_epoch_ms < request.window_start_epoch_ms
            || completed_at_epoch_ms >= request.window_end_epoch_ms
            || completed_at_epoch_ms
                >= request.reservation_expires_at_epoch_ms)
    {
        return Err(ContractError::new(
            "quota_transition_outside_window",
            "credentialAuthority.quota",
            "quota reserve and consume effects must complete inside their exact signed bucket window",
        ));
    }
    match result {
        QuotaBudgetResult::Succeeded {
            transition,
            transition_receipt_id,
            transition_receipt_sha256,
        } => {
            validate_identifier(
                transition_receipt_id,
                "credentialAuthority.quota.transitionReceiptId",
            )?;
            validate_digest(
                transition_receipt_sha256,
                "credentialAuthority.quota.transitionReceiptSha256",
            )?;
            let expected = match request.action {
                QuotaBudgetAction::Reserve => QuotaBudgetTransition::Reserved,
                QuotaBudgetAction::Consume => QuotaBudgetTransition::Consumed,
                QuotaBudgetAction::Cancel => QuotaBudgetTransition::Cancelled,
            };
            if *transition != expected
                || request
                    .prior_sequence
                    .checked_add(1)
                    .is_none_or(|next| request.new_sequence != next)
                || request.prior_state_sha256 == request.new_state_sha256
            {
                return Err(ContractError::new(
                    "invalid_quota_transition",
                    "credentialAuthority.quota",
                    "successful quota evidence must identify the exact action and one monotonic state advance",
                ));
            }
        }
        QuotaBudgetResult::DefinitelyFailed {
            failure_receipt_id,
            failure_receipt_sha256,
            ..
        } => {
            validate_failure_receipt(
                failure_receipt_id,
                failure_receipt_sha256,
                "credentialAuthority.quota",
            )?;
            require_unchanged_transition(
                request.prior_sequence,
                request.new_sequence,
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.quota",
            )?;
        }
        QuotaBudgetResult::TransitionUnknown { recovery } => {
            let transition_identity = credential_authority_transition_identity(
                "quota-budget",
                request,
            )?;
            validate_durable_authority_recovery(
                recovery,
                &transition_identity,
                &request.prior_state_sha256,
                completed_at_epoch_ms,
            )?;
            require_unchanged_transition(
                request.prior_sequence,
                request.new_sequence,
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.quota",
            )?;
        }
    }
    Ok(())
}

fn validate_credential_access(
    request: &CredentialAccessRequest,
    result: &CredentialAccessResult,
    authorization_binding_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    for (value, path) in [
        (
            &request.provider_id,
            "credentialAuthority.credentialAccess.providerId",
        ),
        (
            &request.account_id,
            "credentialAuthority.credentialAccess.accountId",
        ),
        (
            &request.credential_ref,
            "credentialAuthority.credentialAccess.credentialRef",
        ),
        (
            &request.recipient_runtime_instance_id,
            "credentialAuthority.credentialAccess.recipientRuntimeInstanceId",
        ),
        (
            &request.lease_id,
            "credentialAuthority.credentialAccess.leaseId",
        ),
        (
            &request.lease_release_id,
            "credentialAuthority.credentialAccess.leaseReleaseId",
        ),
        (
            &request.authorization_receipt_id,
            "credentialAuthority.credentialAccess.authorizationReceiptId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    validate_safe_integer(
        request.credential_version,
        "credentialAuthority.credentialAccess.credentialVersion",
    )?;
    validate_safe_integer(
        request.credential_generation,
        "credentialAuthority.credentialAccess.credentialGeneration",
    )?;
    if request.credential_version == 0 || request.credential_generation == 0 {
        return Err(ContractError::new(
            "invalid_credential_version",
            "credentialAuthority.credentialAccess.credentialVersion",
            "credential version and generation must be positive",
        ));
    }
    validate_safe_time(
        request.expires_at_epoch_ms,
        "credentialAuthority.credentialAccess.expiresAtEpochMs",
    )?;
    if request.expires_at_epoch_ms <= completed_at_epoch_ms {
        return Err(ContractError::new(
            "expired_credential_access",
            "credentialAuthority.credentialAccess.expiresAtEpochMs",
            "credential access authority must expire after its signed completion",
        ));
    }
    for (value, path) in [
        (
            &request.recipient_runtime_measurement_sha256,
            "credentialAuthority.credentialAccess.recipientRuntimeMeasurementSha256",
        ),
        (
            &request.credential_injection_template_sha256,
            "credentialAuthority.credentialAccess.credentialInjectionTemplateSha256",
        ),
        (
            &request.request_sha256,
            "credentialAuthority.credentialAccess.requestSha256",
        ),
        (
            &request.operation_sha256,
            "credentialAuthority.credentialAccess.operationSha256",
        ),
        (
            &request.authorization_binding_sha256,
            "credentialAuthority.credentialAccess.authorizationBindingSha256",
        ),
        (
            &request.prior_state_sha256,
            "credentialAuthority.credentialAccess.priorStateSha256",
        ),
        (
            &request.new_state_sha256,
            "credentialAuthority.credentialAccess.newStateSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    if let Some(value) = request.staged_request_sha256.as_deref() {
        validate_digest(
            value,
            "credentialAuthority.credentialAccess.stagedRequestSha256",
        )?;
    }
    require_equal_digest(
        &request.authorization_binding_sha256,
        authorization_binding_sha256,
        "credentialAuthority.credentialAccess.authorizationBindingSha256",
    )?;
    let succeeded =
        matches!(result, CredentialAccessResult::Succeeded { .. });
    let valid_stage_shape = match request.action {
        CredentialAccessAction::AcquireLease
        | CredentialAccessAction::AuthorizeDecryption => {
            request.staged_request_sha256.is_none()
        }
        CredentialAccessAction::AuthorizeInjection => {
            !succeeded || request.staged_request_sha256.is_some()
        }
    };
    if !valid_stage_shape {
        return Err(ContractError::new(
            "credential_access_stage_order_mismatch",
            "credentialAuthority.credentialAccess.stagedRequestSha256",
            "lease/decryption are template-bound pre-stage operations; successful injection requires final staged bytes and failed or unknown injection may truthfully retain produced bytes",
        ));
    }
    match result {
        CredentialAccessResult::Succeeded {
            access_receipt_id,
            access_receipt_sha256,
            sealed_lease_attachment_sha256,
        } => {
            validate_identifier(
                access_receipt_id,
                "credentialAuthority.credentialAccess.accessReceiptId",
            )?;
            validate_digest(
                access_receipt_sha256,
                "credentialAuthority.credentialAccess.accessReceiptSha256",
            )?;
            validate_digest(
                sealed_lease_attachment_sha256,
                "credentialAuthority.credentialAccess.sealedLeaseAttachmentSha256",
            )?;
            if request.prior_state_sha256 == request.new_state_sha256 {
                return Err(ContractError::new(
                    "credential_access_state_not_advanced",
                    "credentialAuthority.credentialAccess",
                    "successful lease/decrypt/injection authority must advance the committed state",
                ));
            }
        }
        CredentialAccessResult::DefinitelyFailed {
            failure_receipt_id,
            failure_receipt_sha256,
            ..
        } => {
            validate_failure_receipt(
                failure_receipt_id,
                failure_receipt_sha256,
                "credentialAuthority.credentialAccess",
            )?;
            require_equal_digest(
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.credentialAccess.newStateSha256",
            )?;
        }
        CredentialAccessResult::TransitionUnknown { recovery } => {
            let transition_identity = credential_authority_transition_identity(
                "credential-access",
                request,
            )?;
            validate_durable_authority_recovery(
                recovery,
                &transition_identity,
                &request.prior_state_sha256,
                completed_at_epoch_ms,
            )?;
            require_equal_digest(
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.credentialAccess.newStateSha256",
            )?;
        }
    }
    Ok(())
}

fn validate_oauth_token(
    request: &OauthTokenRequest,
    result: &OauthTokenResult,
    authority_id: &str,
    authorization_binding_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    for (value, path) in [
        (
            &request.provider_authority_id,
            "credentialAuthority.oauth.providerAuthorityId",
        ),
        (&request.subject_id, "credentialAuthority.oauth.subjectId"),
        (&request.account_id, "credentialAuthority.oauth.accountId"),
        (&request.client_id, "credentialAuthority.oauth.clientId"),
        (&request.app_id, "credentialAuthority.oauth.appId"),
        (
            &request.credential_ref,
            "credentialAuthority.oauth.credentialRef",
        ),
        (
            &request.provider_request_id,
            "credentialAuthority.oauth.providerRequestId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    if request.provider_authority_id != authority_id {
        return Err(ContractError::new(
            "provider_authority_binding_mismatch",
            "credentialAuthority.oauth.providerAuthorityId",
            "OAuth evidence provider authority must equal the signer-scoped authorityId",
        ));
    }
    for (value, path) in [
        (
            &request.granted_scope_root_sha256,
            "credentialAuthority.oauth.grantedScopeRootSha256",
        ),
        (
            &request.request_sha256,
            "credentialAuthority.oauth.requestSha256",
        ),
        (
            &request.operation_sha256,
            "credentialAuthority.oauth.operationSha256",
        ),
        (
            &request.authorization_binding_sha256,
            "credentialAuthority.oauth.authorizationBindingSha256",
        ),
        (
            &request.prior_state_sha256,
            "credentialAuthority.oauth.priorStateSha256",
        ),
        (
            &request.new_state_sha256,
            "credentialAuthority.oauth.newStateSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    require_equal_digest(
        &request.authorization_binding_sha256,
        authorization_binding_sha256,
        "credentialAuthority.oauth.authorizationBindingSha256",
    )?;
    for (value, path) in [
        (
            request.credential_version,
            "credentialAuthority.oauth.credentialVersion",
        ),
        (
            request.prior_token_generation,
            "credentialAuthority.oauth.priorTokenGeneration",
        ),
        (
            request.new_token_generation,
            "credentialAuthority.oauth.newTokenGeneration",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    if request.credential_version == 0
        || request.output_generation_rule
            != OauthOutputGenerationRule::AdvanceExactlyOneOnSuccessPreserveOnFailureOrUnknown
        || request.prior_token_generation.checked_add(1)
            != Some(request.new_token_generation)
    {
        return Err(ContractError::new(
            "invalid_token_generation",
            "credentialAuthority.oauth",
            "OAuth request requires a positive credential version and exactly one proposed output generation under the closed preserve-on-failure-or-unknown rule",
        ));
    }
    if let Some(value) = request.provider_idempotency_key_sha256.as_deref() {
        validate_digest(
            value,
            "credentialAuthority.oauth.providerIdempotencyKeySha256",
        )?;
    }
    let (proposed_generation, effective_generation) = match result {
        OauthTokenResult::Succeeded {
            proposed_generation,
            effective_generation,
            ..
        }
        | OauthTokenResult::DefinitelyFailed {
            proposed_generation,
            effective_generation,
            ..
        }
        | OauthTokenResult::TransitionUnknown {
            proposed_generation,
            effective_generation,
            ..
        } => (*proposed_generation, *effective_generation),
    };
    validate_safe_integer(
        proposed_generation,
        "credentialAuthority.oauth.result.proposedGeneration",
    )?;
    validate_safe_integer(
        effective_generation,
        "credentialAuthority.oauth.result.effectiveGeneration",
    )?;
    if proposed_generation != request.new_token_generation
        || proposed_generation
            != request.prior_token_generation.saturating_add(1)
    {
        return Err(ContractError::new(
            "oauth_proposed_generation_mismatch",
            "credentialAuthority.oauth.result.proposedGeneration",
            "the signed OAuth result proposal must equal the request proposal and exactly prior generation plus one",
        ));
    }
    match result {
        OauthTokenResult::Succeeded {
            proposed_generation,
            effective_generation,
            issued_credential_receipt_id,
            issued_credential_receipt_sha256,
            encrypted_attachment_sha256,
            provider_response_receipt_sha256,
        } => {
            validate_identifier(
                issued_credential_receipt_id,
                "credentialAuthority.oauth.issuedCredentialReceiptId",
            )?;
            for digest in [
                issued_credential_receipt_sha256,
                encrypted_attachment_sha256,
                provider_response_receipt_sha256,
            ] {
                validate_digest(digest, "credentialAuthority.oauth.result")?;
            }
            if effective_generation != proposed_generation
                || *effective_generation != request.new_token_generation
                || request.prior_state_sha256 == request.new_state_sha256
            {
                return Err(ContractError::new(
                    "invalid_oauth_generation_transition",
                    "credentialAuthority.oauth",
                    "successful OAuth authority must commit exactly the proposed next generation and advance the effective state digest once",
                ));
            }
            let commitment = OauthEffectiveStateCommitment {
                action: request.action,
                provider_authority_id: &request.provider_authority_id,
                subject_id: &request.subject_id,
                account_id: &request.account_id,
                client_id: &request.client_id,
                app_id: &request.app_id,
                credential_ref: &request.credential_ref,
                credential_version: request.credential_version,
                granted_scope_root_sha256:
                    &request.granted_scope_root_sha256,
                prior_token_generation: request.prior_token_generation,
                proposed_generation: *proposed_generation,
                effective_generation: *effective_generation,
                request_sha256: &request.request_sha256,
                operation_sha256: &request.operation_sha256,
                authorization_binding_sha256:
                    &request.authorization_binding_sha256,
                prior_state_sha256: &request.prior_state_sha256,
                provider_request_id: &request.provider_request_id,
                provider_idempotency_key_sha256: request
                    .provider_idempotency_key_sha256
                    .as_deref(),
                issued_credential_receipt_sha256,
                encrypted_attachment_sha256,
                provider_response_receipt_sha256,
            };
            let state_commitment = canonical_jcs_bytes(&commitment)?;
            let expected_effective_state = domain_sha256(
                OAUTH_EFFECTIVE_STATE_DOMAIN,
                &[state_commitment.as_slice()],
            )?;
            require_equal_digest(
                &request.new_state_sha256,
                &expected_effective_state,
                "credentialAuthority.oauth.newStateSha256",
            )?;
        }
        OauthTokenResult::DefinitelyFailed {
            effective_generation,
            provider_failure_id,
            failure_receipt_sha256,
            ..
        } => {
            validate_identifier(
                provider_failure_id,
                "credentialAuthority.oauth.providerFailureId",
            )?;
            validate_digest(
                failure_receipt_sha256,
                "credentialAuthority.oauth.failureReceiptSha256",
            )?;
            if *effective_generation != request.prior_token_generation {
                return Err(ContractError::new(
                    "oauth_effective_generation_mismatch",
                    "credentialAuthority.oauth.result.effectiveGeneration",
                    "definite OAuth failure must retain the prior effective generation",
                ));
            }
            require_equal_digest(
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.oauth.newStateSha256",
            )?;
        }
        OauthTokenResult::TransitionUnknown {
            effective_generation,
            recovery,
            ..
        } => {
            if *effective_generation != request.prior_token_generation {
                return Err(ContractError::new(
                    "oauth_effective_generation_mismatch",
                    "credentialAuthority.oauth.result.effectiveGeneration",
                    "unknown OAuth transition must retain the prior effective generation until durable reconciliation commits a result",
                ));
            }
            let transition_identity = credential_authority_transition_identity(
                "oauth-token",
                request,
            )?;
            validate_durable_authority_recovery(
                recovery,
                &transition_identity,
                &request.prior_state_sha256,
                completed_at_epoch_ms,
            )?;
            require_equal_digest(
                &request.prior_state_sha256,
                &request.new_state_sha256,
                "credentialAuthority.oauth.newStateSha256",
            )?;
            if request.provider_idempotency_key_sha256.as_deref()
                != Some(recovery.idempotency_key_sha256.as_str())
            {
                return Err(ContractError::new(
                    "oauth_unknown_recovery_mismatch",
                    "credentialAuthority.oauth.providerIdempotencyKeySha256",
                    "unknown OAuth transitions require the exact provider idempotency key in durable recovery",
                ));
            }
        }
    }
    Ok(())
}

fn validate_durable_authority_recovery(
    recovery: &DurableAuthorityRecovery,
    expected_transition_identity_sha256: &str,
    expected_last_known_state_sha256: &str,
    completed_at_epoch_ms: u64,
) -> ContractResult<()> {
    for digest in [
        &recovery.recovery_binding_sha256,
        &recovery.durable_record_sha256,
        &recovery.idempotency_key_sha256,
        &recovery.last_known_state_sha256,
        &recovery.transition_identity_sha256,
    ] {
        validate_digest(digest, "credentialAuthority.recovery")?;
    }
    require_equal_digest(
        &recovery.transition_identity_sha256,
        expected_transition_identity_sha256,
        "credentialAuthority.recovery.transitionIdentitySha256",
    )?;
    require_equal_digest(
        &recovery.last_known_state_sha256,
        expected_last_known_state_sha256,
        "credentialAuthority.recovery.lastKnownStateSha256",
    )?;
    validate_safe_time(
        recovery.reconcile_after_epoch_ms,
        "credentialAuthority.recovery.reconcileAfterEpochMs",
    )?;
    if recovery.reconcile_after_epoch_ms <= completed_at_epoch_ms {
        return Err(ContractError::new(
            "invalid_reconciliation_deadline",
            "credentialAuthority.recovery.reconcileAfterEpochMs",
            "durable reconciliation must be scheduled after the signed ambiguous operation completion",
        ));
    }
    let reconcile_time =
        canonical_jcs_bytes(&recovery.reconcile_after_epoch_ms)?;
    let expected_recovery = domain_sha256(
        CREDENTIAL_AUTHORITY_RECOVERY_BINDING_DOMAIN,
        &[
            recovery.transition_identity_sha256.as_bytes(),
            recovery.durable_record_sha256.as_bytes(),
            recovery.idempotency_key_sha256.as_bytes(),
            recovery.last_known_state_sha256.as_bytes(),
            reconcile_time.as_slice(),
        ],
    )?;
    require_equal_digest(
        &recovery.recovery_binding_sha256,
        &expected_recovery,
        "credentialAuthority.recovery.recoveryBindingSha256",
    )
}

fn credential_authority_transition_identity<T: Serialize>(
    family: &'static str,
    request: &T,
) -> ContractResult<String> {
    let request = canonical_jcs_bytes(request)?;
    domain_sha256(
        CREDENTIAL_AUTHORITY_TRANSITION_ID_DOMAIN,
        &[family.as_bytes(), request.as_slice()],
    )
}

fn validate_failure_receipt(
    receipt_id: &str,
    receipt_sha256: &str,
    path: &'static str,
) -> ContractResult<()> {
    validate_identifier(receipt_id, path)?;
    validate_digest(receipt_sha256, path)
}

fn require_unchanged_transition(
    prior_sequence: u64,
    new_sequence: u64,
    prior_state_sha256: &str,
    new_state_sha256: &str,
    path: &'static str,
) -> ContractResult<()> {
    if prior_sequence != new_sequence
        || prior_state_sha256 != new_state_sha256
    {
        return Err(ContractError::new(
            "non_success_state_advanced",
            path,
            "definite failure or transition-unknown may not assert a completed monotonic state advance",
        ));
    }
    Ok(())
}

fn validate_durable_recovery_seal_payload(
    payload: &DurableRecoverySealPayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (
            &payload.authorization_binding_sha256,
            "durableRecoverySeal.payload.authorizationBindingSha256",
        ),
        (
            &payload.route_semantic_profile_sha256,
            "durableRecoverySeal.payload.routeSemanticProfileSha256",
        ),
        (
            &payload.idempotency_binding_sha256,
            "durableRecoverySeal.payload.idempotencyBindingSha256",
        ),
        (
            &payload.recovery_key_sha256,
            "durableRecoverySeal.payload.recoveryKeySha256",
        ),
        (
            &payload.durable_record_sha256,
            "durableRecoverySeal.payload.durableRecordSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_safe_integer(
        payload.rollback_state_epoch,
        "durableRecoverySeal.payload.rollbackStateEpoch",
    )?;
    validate_safe_time(
        payload.armed_at_epoch_ms,
        "durableRecoverySeal.payload.armedAtEpochMs",
    )
}

fn credential_authority_effect_binding(
    payload: &CredentialAuthorityEvidencePayload,
) -> ContractResult<String> {
    let operation = canonical_jcs_bytes(&payload.operation)?;
    let request = payload.operation_evidence.request_jcs()?;
    let sequence = [payload.sequence];
    domain_sha256(
        CREDENTIAL_AUTHORITY_EFFECT_DOMAIN,
        &[
            payload.attempt_id.as_bytes(),
            payload.authorization_binding_sha256.as_bytes(),
            payload.route_semantic_profile_sha256.as_bytes(),
            payload.authority_id.as_bytes(),
            operation.as_slice(),
            request.as_slice(),
            sequence.as_slice(),
            payload.prior_execution_state_sha256.as_bytes(),
            payload.execution_state_sha256.as_bytes(),
        ],
    )
}

fn credential_authority_record_binding(
    payload: &CredentialAuthorityEvidencePayload,
) -> ContractResult<String> {
    let operation = canonical_jcs_bytes(&payload.operation)?;
    let evidence = canonical_jcs_bytes(&payload.operation_evidence)?;
    let credential =
        canonical_jcs_bytes(&payload.credential_binding_sha256.as_deref())?;
    let sequence = [payload.sequence];
    domain_sha256(
        CREDENTIAL_AUTHORITY_RECORD_DOMAIN,
        &[
            payload.attempt_id.as_bytes(),
            payload.authority_id.as_bytes(),
            operation.as_slice(),
            payload.prerequisite_sha256.as_bytes(),
            payload.plan_step_sha256.as_bytes(),
            sequence.as_slice(),
            payload.prior_execution_state_sha256.as_bytes(),
            evidence.as_slice(),
            credential.as_slice(),
        ],
    )
}

fn credential_authority_execution_state(
    prior_execution_state_sha256: &str,
    operation_record_sha256: &str,
) -> ContractResult<String> {
    domain_sha256(
        CREDENTIAL_AUTHORITY_EXECUTION_STATE_DOMAIN,
        &[
            prior_execution_state_sha256.as_bytes(),
            operation_record_sha256.as_bytes(),
        ],
    )
}

fn validate_credential_authority_summary_binding(
    summary: &CredentialAuthoritySideEffect,
    terminal_evidence: &CredentialAuthorityEvidencePayload,
    final_evidence: &CredentialAuthorityEvidencePayload,
    evidence_root_sha256: &str,
    state_machine_summary_sha256: &str,
    credential_binding_sha256: Option<&str>,
) -> ContractResult<()> {
    let matches = match summary {
        CredentialAuthoritySideEffect::Completed {
            authority_id,
            operation,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256: summary_root,
            state_machine_summary_sha256: summary_state_machine,
        } => {
            authority_id == &terminal_evidence.authority_id
                && operation == &terminal_evidence.operation
                && effect_binding_sha256
                    == &terminal_evidence.effect_binding_sha256
                && terminal_record_sha256
                    == &terminal_evidence.operation_record_sha256
                && final_record_sha256
                    == &final_evidence.operation_record_sha256
                && summary_root == evidence_root_sha256
                && summary_state_machine
                    == state_machine_summary_sha256
                && terminal_evidence.operation_evidence.is_succeeded()
                && (!terminal_evidence
                    .operation_evidence
                    .succeeded_with_credential()
                    || terminal_evidence
                        .credential_binding_sha256
                        .as_deref()
                        == credential_binding_sha256)
        }
        CredentialAuthoritySideEffect::DefinitelyFailed {
            authority_id,
            operation,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256: summary_root,
            state_machine_summary_sha256: summary_state_machine,
            failure,
        } => {
            authority_id == &terminal_evidence.authority_id
                && operation == &terminal_evidence.operation
                && effect_binding_sha256
                    == &terminal_evidence.effect_binding_sha256
                && terminal_record_sha256
                    == &terminal_evidence.operation_record_sha256
                && final_record_sha256
                    == &final_evidence.operation_record_sha256
                && summary_root == evidence_root_sha256
                && summary_state_machine
                    == state_machine_summary_sha256
                && terminal_evidence
                    .operation_evidence
                    .definite_failure()
                    == Some(*failure)
                && if matches!(
                    &terminal_evidence.operation_evidence,
                    CredentialAuthorityOperationEvidence::OauthToken { .. }
                ) {
                    terminal_evidence.credential_binding_sha256.as_deref()
                        == credential_binding_sha256
                } else {
                    terminal_evidence.credential_binding_sha256.is_none()
                }
        }
        CredentialAuthoritySideEffect::OutcomeUnknown {
            authority_id,
            operation,
            effect_binding_sha256,
            terminal_record_sha256,
            final_record_sha256,
            evidence_root_sha256: summary_root,
            state_machine_summary_sha256: summary_state_machine,
            recovery_binding_sha256,
        } => {
            authority_id == &terminal_evidence.authority_id
                && operation == &terminal_evidence.operation
                && effect_binding_sha256
                    == &terminal_evidence.effect_binding_sha256
                && terminal_record_sha256
                    == &terminal_evidence.operation_record_sha256
                && final_record_sha256
                    == &final_evidence.operation_record_sha256
                && summary_root == evidence_root_sha256
                && summary_state_machine
                    == state_machine_summary_sha256
                && terminal_evidence
                    .operation_evidence
                    .recovery_binding_sha256()
                    == Some(recovery_binding_sha256.as_str())
                && if matches!(
                    &terminal_evidence.operation_evidence,
                    CredentialAuthorityOperationEvidence::OauthToken { .. }
                ) {
                    terminal_evidence.credential_binding_sha256.as_deref()
                        == credential_binding_sha256
                } else {
                    terminal_evidence.credential_binding_sha256.is_none()
                }
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(ContractError::new(
            "credential_authority_summary_mismatch",
            "body.credentialAuthoritySideEffect",
            "credential-authority summary does not match the final signed operation, effect, result, and credential binding",
        ))
    }
}

fn operation_may_produce_credential(
    operation: CredentialAuthorityOperation,
) -> bool {
    matches!(
        operation,
        CredentialAuthorityOperation::AcquireCredentialLease
            | CredentialAuthorityOperation::AuthorizeCredentialDecryption
            | CredentialAuthorityOperation::AuthorizeCredentialInjection
            | CredentialAuthorityOperation::RefreshOauthToken
            | CredentialAuthorityOperation::ExchangeOauthToken
            | CredentialAuthorityOperation::MintToken
    )
}

fn validate_reserve_payload(payload: &ReserveEvidencePayload) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (&payload.nonce_sha256, "reserve.payload.nonceSha256"),
        (&payload.policy_sha256, "reserve.payload.policySha256"),
        (&payload.request_sha256, "reserve.payload.requestSha256"),
        (
            &payload.operation_sha256,
            "reserve.payload.operationSha256",
        ),
        (
            &payload.route_semantic_profile_sha256,
            "reserve.payload.routeSemanticProfileSha256",
        ),
        (
            &payload.authorization_binding_sha256,
            "reserve.payload.authorizationBindingSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    if let Some(value) = payload.credential_authority_plan_sha256.as_deref() {
        validate_digest(
            value,
            "reserve.payload.credentialAuthorityPlanSha256",
        )?;
    }
    validate_identifier(&payload.reservation_id, "reserve.payload.reservationId")?;
    validate_safe_time(payload.reserved_at_epoch_ms, "reserve.payload.reservedAtEpochMs")?;
    validate_safe_time(
        payload.reservation_deadline_epoch_ms,
        "reserve.payload.reservationDeadlineEpochMs",
    )?;
    if payload.reservation_deadline_epoch_ms <= payload.reserved_at_epoch_ms
        || payload.reservation_deadline_epoch_ms - payload.reserved_at_epoch_ms
            > MAX_EVIDENCE_TTL_MS
    {
        return Err(ContractError::new(
            "invalid_reservation_deadline",
            "reserve.payload.reservationDeadlineEpochMs",
            "reservation deadline is not positive and bounded",
        ));
    }
    Ok(())
}

fn validate_dispatch_payload(payload: &DispatchEvidencePayload) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (&payload.policy_sha256, "dispatch.payload.policySha256"),
        (
            &payload.reserve_evidence_sha256,
            "dispatch.payload.reserveEvidenceSha256",
        ),
        (
            &payload.route_semantic_profile_sha256,
            "dispatch.payload.routeSemanticProfileSha256",
        ),
        (
            &payload.authorization_binding_sha256,
            "dispatch.payload.authorizationBindingSha256",
        ),
        (
            &payload.dispatch_authorization_binding_sha256,
            "dispatch.payload.dispatchAuthorizationBindingSha256",
        ),
        (
            &payload.trust_checkpoint_sha256,
            "dispatch.payload.trustCheckpointSha256",
        ),
        (
            &payload.staged_request_sha256,
            "dispatch.payload.stagedRequestSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path) in [
        (
            payload.credential_binding_sha256.as_deref(),
            "dispatch.payload.credentialBindingSha256",
        ),
        (
            payload.idempotency_binding_sha256.as_deref(),
            "dispatch.payload.idempotencyBindingSha256",
        ),
        (
            payload.credential_authority_evidence_sha256.as_deref(),
            "dispatch.payload.credentialAuthorityEvidenceSha256",
        ),
        (
            payload
                .credential_authority_evidence_root_sha256
                .as_deref(),
            "dispatch.payload.credentialAuthorityEvidenceRootSha256",
        ),
        (
            payload
                .credential_authority_state_machine_sha256
                .as_deref(),
            "dispatch.payload.credentialAuthorityStateMachineSha256",
        ),
        (
            payload.durable_recovery_seal_evidence_sha256.as_deref(),
            "dispatch.payload.durableRecoverySealEvidenceSha256",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, path)?;
        }
    }
    validate_safe_time(
        payload.authorized_at_epoch_ms,
        "dispatch.payload.authorizedAtEpochMs",
    )?;
    validate_safe_time(
        payload.revalidated_at_epoch_ms,
        "dispatch.payload.revalidatedAtEpochMs",
    )?;
    validate_safe_integer(
        payload.policy_snapshot_epoch,
        "dispatch.payload.policySnapshotEpoch",
    )?;
    validate_safe_integer(
        payload.revocation_epoch,
        "dispatch.payload.revocationEpoch",
    )?;
    validate_safe_time(
        payload.dispatch_deadline_epoch_ms,
        "dispatch.payload.dispatchDeadlineEpochMs",
    )?;
    if !payload.all_preparation_complete
        || payload.revalidated_at_epoch_ms != payload.authorized_at_epoch_ms
        || payload.policy_snapshot_epoch == 0
        || payload.revocation_epoch == 0
        || payload.dispatch_deadline_epoch_ms <= payload.authorized_at_epoch_ms
        || payload.dispatch_deadline_epoch_ms - payload.authorized_at_epoch_ms
            > MAX_EVIDENCE_TTL_MS
    {
        return Err(ContractError::new(
            "invalid_dispatch_authority",
            "dispatch.payload",
            "dispatch requires completed preparation and a positive bounded deadline",
        ));
    }
    Ok(())
}

fn validate_terminal_payload(payload: &TerminalEvidencePayload) -> ContractResult<()> {
    validate_attempt_id(payload.attempt_id())?;
    match payload {
        TerminalEvidencePayload::Cancelled {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            reserve_evidence_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            dispatch_authorization_binding_sha256,
            staged_request_sha256,
            credential_recovery_binding_sha256,
            local_reconciliation_recovery_evidence_sha256,
            local_reconciliation_recovery_authority_key_id,
            local_reconciliation_recovery_authority_key_material_sha256,
            local_reconciliation_recovery_authority_trust_checkpoint_sha256,
            local_reconciliation_recovery_authority_revocation_epoch,
            local_reconciliation_credential_ledger_namespace,
            local_reconciliation_pinned_genesis_state_sha256,
            local_reconciliation_predecessor_successor_key_sha256,
            local_reconciliation_continuity_evidence_sha256,
            local_reconciliation_store_transition_sha256,
            local_reconciliation_quorum_certificate_sha256,
            local_reconciliation_transparency_log_proof_sha256,
            definitely_not_dispatched,
            failure_observed_at_epoch_ms,
            completed_at_epoch_ms,
            ..
        } => {
            validate_digest(
                route_semantic_profile_sha256,
                "terminal.payload.routeSemanticProfileSha256",
            )?;
            validate_digest(
                authorization_binding_sha256,
                "terminal.payload.authorizationBindingSha256",
            )?;
            for value in [
                reserve_evidence_sha256.as_deref(),
                dispatch_evidence_sha256.as_deref(),
                credential_authority_evidence_root_sha256.as_deref(),
                credential_authority_state_machine_sha256.as_deref(),
                dispatch_authorization_binding_sha256.as_deref(),
                staged_request_sha256.as_deref(),
                credential_recovery_binding_sha256.as_deref(),
                local_reconciliation_recovery_evidence_sha256.as_deref(),
                local_reconciliation_recovery_authority_key_id.as_deref(),
                local_reconciliation_recovery_authority_key_material_sha256
                    .as_deref(),
                local_reconciliation_recovery_authority_trust_checkpoint_sha256
                    .as_deref(),
                local_reconciliation_pinned_genesis_state_sha256.as_deref(),
                local_reconciliation_predecessor_successor_key_sha256
                    .as_deref(),
                local_reconciliation_continuity_evidence_sha256.as_deref(),
                local_reconciliation_store_transition_sha256.as_deref(),
                local_reconciliation_quorum_certificate_sha256.as_deref(),
                local_reconciliation_transparency_log_proof_sha256.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_digest(value, "terminal.payload")?;
            }
            if let Some(namespace) =
                local_reconciliation_credential_ledger_namespace.as_deref()
            {
                validate_identifier(
                    namespace,
                    "terminal.payload.localReconciliationCredentialLedgerNamespace",
                )?;
            }
            if let Some(revocation_epoch) =
                local_reconciliation_recovery_authority_revocation_epoch
            {
                validate_safe_integer(
                    *revocation_epoch,
                    "terminal.payload.localReconciliationRecoveryAuthorityRevocationEpoch",
                )?;
                if *revocation_epoch == 0 {
                    return Err(ContractError::new(
                        "invalid_terminal_recovery_authority_revocation_epoch",
                        "terminal.payload.localReconciliationRecoveryAuthorityRevocationEpoch",
                        "present recovery-authority revocation epoch must be positive",
                    ));
                }
            }
            if dispatch_evidence_sha256.is_some()
                && reserve_evidence_sha256.is_none()
            {
                return Err(ContractError::new(
                    "terminal_chain_gap",
                    "terminal.payload",
                    "dispatch cancellation cannot omit reserve evidence",
                ));
            }
            if !*definitely_not_dispatched {
                return Err(ContractError::new(
                    "invalid_cancellation_claim",
                    "terminal.payload.definitelyNotDispatched",
                    "cancelled terminal state must be definitely not dispatched",
                ));
            }
            validate_safe_time(
                *failure_observed_at_epoch_ms,
                "terminal.payload.failureObservedAtEpochMs",
            )?;
            validate_safe_time(*completed_at_epoch_ms, "terminal.payload.completedAtEpochMs")?;
            if failure_observed_at_epoch_ms > completed_at_epoch_ms {
                return Err(ContractError::new(
                    "invalid_cancellation_timeline",
                    "terminal.payload",
                    "failure observation cannot occur after terminal cancellation",
                ));
            }
        }
        TerminalEvidencePayload::ResponseRejected {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            staged_request_sha256,
            upstream_observation_sha256,
            rejected_at_epoch_ms,
            ..
        } => {
            for value in [
                route_semantic_profile_sha256,
                authorization_binding_sha256,
                dispatch_authorization_binding_sha256,
                dispatch_evidence_sha256,
                staged_request_sha256,
                upstream_observation_sha256,
            ] {
                validate_digest(value, "terminal.payload")?;
            }
            for value in [
                credential_authority_evidence_root_sha256.as_deref(),
                credential_authority_state_machine_sha256.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_digest(value, "terminal.payload")?;
            }
            validate_safe_time(
                *rejected_at_epoch_ms,
                "terminal.payload.rejectedAtEpochMs",
            )?;
        }
        TerminalEvidencePayload::ExactResponseUnsupported {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            staged_request_sha256,
            upstream_observation_sha256,
            unsupported_at_epoch_ms,
            ..
        } => {
            for value in [
                route_semantic_profile_sha256,
                authorization_binding_sha256,
                dispatch_authorization_binding_sha256,
                dispatch_evidence_sha256,
                staged_request_sha256,
                upstream_observation_sha256,
            ] {
                validate_digest(value, "terminal.payload")?;
            }
            for value in [
                credential_authority_evidence_root_sha256.as_deref(),
                credential_authority_state_machine_sha256.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_digest(value, "terminal.payload")?;
            }
            validate_safe_time(
                *unsupported_at_epoch_ms,
                "terminal.payload.unsupportedAtEpochMs",
            )?;
        }
        TerminalEvidencePayload::Completed {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            staged_request_sha256,
            upstream_observation_sha256,
            completed_at_epoch_ms,
            ..
        } => {
            for value in [
                route_semantic_profile_sha256,
                authorization_binding_sha256,
                dispatch_authorization_binding_sha256,
                dispatch_evidence_sha256,
                staged_request_sha256,
                upstream_observation_sha256,
            ] {
                validate_digest(value, "terminal.payload")?;
            }
            if let Some(value) =
                credential_authority_evidence_root_sha256.as_deref()
            {
                validate_digest(
                    value,
                    "terminal.payload.credentialAuthorityEvidenceRootSha256",
                )?;
            }
            if let Some(value) =
                credential_authority_state_machine_sha256.as_deref()
            {
                validate_digest(
                    value,
                    "terminal.payload.credentialAuthorityStateMachineSha256",
                )?;
            }
            validate_safe_time(*completed_at_epoch_ms, "terminal.payload.completedAtEpochMs")?;
        }
        TerminalEvidencePayload::WriteTransitionUnknown {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            durable_recovery_seal_evidence_sha256,
            staged_request_sha256,
            idempotency_binding_sha256,
            recovery_binding_sha256,
            unknown_at_epoch_ms,
            ..
        } => {
            validate_digest(
                route_semantic_profile_sha256,
                "terminal.payload.routeSemanticProfileSha256",
            )?;
            validate_digest(
                authorization_binding_sha256,
                "terminal.payload.authorizationBindingSha256",
            )?;
            validate_digest(
                dispatch_authorization_binding_sha256,
                "terminal.payload.dispatchAuthorizationBindingSha256",
            )?;
            validate_digest(dispatch_evidence_sha256, "terminal.payload.dispatchEvidenceSha256")?;
            if let Some(value) =
                credential_authority_evidence_root_sha256.as_deref()
            {
                validate_digest(
                    value,
                    "terminal.payload.credentialAuthorityEvidenceRootSha256",
                )?;
            }
            if let Some(value) =
                credential_authority_state_machine_sha256.as_deref()
            {
                validate_digest(
                    value,
                    "terminal.payload.credentialAuthorityStateMachineSha256",
                )?;
            }
            validate_digest(
                durable_recovery_seal_evidence_sha256,
                "terminal.payload.durableRecoverySealEvidenceSha256",
            )?;
            validate_digest(staged_request_sha256, "terminal.payload.stagedRequestSha256")?;
            validate_digest(
                idempotency_binding_sha256,
                "terminal.payload.idempotencyBindingSha256",
            )?;
            validate_digest(recovery_binding_sha256, "terminal.payload.recoveryBindingSha256")?;
            validate_safe_time(*unknown_at_epoch_ms, "terminal.payload.unknownAtEpochMs")?;
        }
        TerminalEvidencePayload::ReadTransitionUnknown {
            route_semantic_profile_sha256,
            authorization_binding_sha256,
            dispatch_authorization_binding_sha256,
            dispatch_evidence_sha256,
            credential_authority_evidence_root_sha256,
            credential_authority_state_machine_sha256,
            staged_request_sha256,
            retry_binding_sha256,
            unknown_at_epoch_ms,
            ..
        } => {
            for value in [
                route_semantic_profile_sha256,
                authorization_binding_sha256,
                dispatch_authorization_binding_sha256,
                dispatch_evidence_sha256,
                staged_request_sha256,
                retry_binding_sha256,
            ] {
                validate_digest(value, "terminal.payload")?;
            }
            for value in [
                credential_authority_evidence_root_sha256.as_deref(),
                credential_authority_state_machine_sha256.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_digest(value, "terminal.payload")?;
            }
            validate_safe_time(
                *unknown_at_epoch_ms,
                "terminal.payload.unknownAtEpochMs",
            )?;
        }
    }
    Ok(())
}

fn validate_custody_authority_payload(
    payload: &CustodyAuthorityEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    validate_digest(&payload.policy_sha256, "custody.payload.policySha256")?;
    validate_digest(
        &payload.authorization_binding_sha256,
        "custody.payload.authorizationBindingSha256",
    )?;
    if let Some(value) = payload
        .dispatch_authorization_binding_sha256
        .as_deref()
    {
        validate_digest(
            value,
            "custody.payload.dispatchAuthorizationBindingSha256",
        )?;
    }
    validate_digest(
        &payload.runtime_measurement_sha256,
        "custody.payload.runtimeMeasurementSha256",
    )?;
    if let Some(value) = payload.staged_request_sha256.as_deref() {
        validate_digest(value, "custody.payload.stagedRequestSha256")?;
    }
    if let Some(value) = payload
        .credential_authority_evidence_root_sha256
        .as_deref()
    {
        validate_digest(
            value,
            "custody.payload.credentialAuthorityEvidenceRootSha256",
        )?;
    }
    if let Some(value) = payload
        .credential_authority_state_machine_sha256
        .as_deref()
    {
        validate_digest(
            value,
            "custody.payload.credentialAuthorityStateMachineSha256",
        )?;
    }
    validate_digest(
        &payload.ownership_binding_sha256,
        "custody.payload.ownershipBindingSha256",
    )?;
    validate_safe_integer(
        payload.rollback_state_epoch,
        "custody.payload.rollbackStateEpoch",
    )?;
    validate_safe_time(payload.measured_at_epoch_ms, "custody.payload.measuredAtEpochMs")?;
    if !has_exact_custody_capabilities(&payload.capabilities) {
        return Err(ContractError::new(
            "incomplete_custody_capabilities",
            "custody.payload.capabilities",
            "custody authority must bind all six distinct measured capabilities",
        ));
    }
    Ok(())
}

fn validate_local_reconciliation_recovery_payload(
    payload: &LocalReconciliationRecoveryEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    validate_identifier(
        &payload.credential_ledger_namespace,
        "localReconciliationRecovery.payload.credentialLedgerNamespace",
    )?;
    for (value, path) in [
        (
            &payload.request_sha256,
            "localReconciliationRecovery.payload.requestSha256",
        ),
        (
            &payload.operation_sha256,
            "localReconciliationRecovery.payload.operationSha256",
        ),
        (
            &payload.authorization_binding_sha256,
            "localReconciliationRecovery.payload.authorizationBindingSha256",
        ),
        (
            &payload.reserve_evidence_sha256,
            "localReconciliationRecovery.payload.reserveEvidenceSha256",
        ),
        (
            &payload.custody_authority_evidence_sha256,
            "localReconciliationRecovery.payload.custodyAuthorityEvidenceSha256",
        ),
        (
            &payload.credential_binding_sha256,
            "localReconciliationRecovery.payload.credentialBindingSha256",
        ),
        (
            &payload.record_id,
            "localReconciliationRecovery.payload.recordId",
        ),
        (
            &payload.record_sha256,
            "localReconciliationRecovery.payload.recordSha256",
        ),
        (
            &payload.retrieval_id,
            "localReconciliationRecovery.payload.retrievalId",
        ),
        (
            &payload.pinned_genesis_state_sha256,
            "localReconciliationRecovery.payload.pinnedGenesisStateSha256",
        ),
        (
            &payload.predecessor_successor_key_sha256,
            "localReconciliationRecovery.payload.predecessorSuccessorKeySha256",
        ),
        (
            &payload.rollback_head_sha256,
            "localReconciliationRecovery.payload.rollbackHeadSha256",
        ),
        (
            &payload.predecessor_rollback_head_sha256,
            "localReconciliationRecovery.payload.predecessorRollbackHeadSha256",
        ),
        (
            &payload.store_transaction_id,
            "localReconciliationRecovery.payload.storeTransactionId",
        ),
        (
            &payload.custody_authority_key_id,
            "localReconciliationRecovery.payload.custodyAuthorityKeyId",
        ),
        (
            &payload.custody_authority_key_material_sha256,
            "localReconciliationRecovery.payload.custodyAuthorityKeyMaterialSha256",
        ),
        (
            &payload.recovery_authority_key_id,
            "localReconciliationRecovery.payload.recoveryAuthorityKeyId",
        ),
        (
            &payload.recovery_authority_key_material_sha256,
            "localReconciliationRecovery.payload.recoveryAuthorityKeyMaterialSha256",
        ),
        (
            &payload.recovery_authority_trust_checkpoint_sha256,
            "localReconciliationRecovery.payload.recoveryAuthorityTrustCheckpointSha256",
        ),
        (
            &payload.trust_checkpoint_sha256,
            "localReconciliationRecovery.payload.trustCheckpointSha256",
        ),
        (
            &payload.persistence_receipt_sha256,
            "localReconciliationRecovery.payload.persistenceReceiptSha256",
        ),
        (
            &payload.retrieval_proof_sha256,
            "localReconciliationRecovery.payload.retrievalProofSha256",
        ),
        (
            &payload.continuity_evidence_sha256,
            "localReconciliationRecovery.payload.continuityEvidenceSha256",
        ),
        (
            &payload.ledger_witness_evidence_sha256,
            "localReconciliationRecovery.payload.ledgerWitnessEvidenceSha256",
        ),
        (
            &payload.predecessor_proof_sha256,
            "localReconciliationRecovery.payload.predecessorProofSha256",
        ),
        (
            &payload.store_transition_sha256,
            "localReconciliationRecovery.payload.storeTransitionSha256",
        ),
        (
            &payload.quorum_certificate_sha256,
            "localReconciliationRecovery.payload.quorumCertificateSha256",
        ),
        (
            &payload.transparency_log_proof_sha256,
            "localReconciliationRecovery.payload.transparencyLogProofSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path) in [
        (
            &payload.provider_id,
            "localReconciliationRecovery.payload.providerId",
        ),
        (
            &payload.account_id,
            "localReconciliationRecovery.payload.accountId",
        ),
        (
            &payload.credential_ref,
            "localReconciliationRecovery.payload.credentialRef",
        ),
        (
            &payload.linearizable_store_id,
            "localReconciliationRecovery.payload.linearizableStoreId",
        ),
        (
            &payload.linearizable_store_cluster_id,
            "localReconciliationRecovery.payload.linearizableStoreClusterId",
        ),
    ] {
        validate_identifier(value, path)?;
    }
    for (value, path) in [
        (
            payload.credential_version,
            "localReconciliationRecovery.payload.credentialVersion",
        ),
        (
            payload.credential_generation,
            "localReconciliationRecovery.payload.credentialGeneration",
        ),
        (
            payload.record_byte_length,
            "localReconciliationRecovery.payload.recordByteLength",
        ),
        (
            payload.rollback_state_epoch,
            "localReconciliationRecovery.payload.rollbackStateEpoch",
        ),
        (
            payload.store_term,
            "localReconciliationRecovery.payload.storeTerm",
        ),
        (
            payload.store_log_index,
            "localReconciliationRecovery.payload.storeLogIndex",
        ),
        (
            payload.store_fencing_token,
            "localReconciliationRecovery.payload.storeFencingToken",
        ),
        (
            payload.revocation_epoch,
            "localReconciliationRecovery.payload.revocationEpoch",
        ),
        (
            payload.recovery_authority_revocation_epoch,
            "localReconciliationRecovery.payload.recoveryAuthorityRevocationEpoch",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    for (value, path) in [
        (
            payload.created_at_epoch_ms,
            "localReconciliationRecovery.payload.createdAtEpochMs",
        ),
        (
            payload.deadline_epoch_ms,
            "localReconciliationRecovery.payload.deadlineEpochMs",
        ),
        (
            payload.signed_at_epoch_ms,
            "localReconciliationRecovery.payload.signedAtEpochMs",
        ),
    ] {
        validate_safe_time(value, path)?;
    }
    for (value, path) in [
        (
            payload.predecessor_record_id.as_deref(),
            "localReconciliationRecovery.payload.predecessorRecordId",
        ),
        (
            payload.predecessor_record_sha256.as_deref(),
            "localReconciliationRecovery.payload.predecessorRecordSha256",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, path)?;
        }
    }
    if payload.credential_version == 0
        || payload.credential_generation == 0
        || payload.record_byte_length == 0
        || payload.record_byte_length
            > MAX_LOCAL_RECONCILIATION_RECORD_BYTES as u64
        || payload.rollback_state_epoch == 0
        || payload.store_term == 0
        || payload.store_log_index == 0
        || payload.store_fencing_token == 0
        || payload.revocation_epoch == 0
        || payload.recovery_authority_revocation_epoch == 0
        || payload.recovery_authority_key_id
            == payload.custody_authority_key_id
        || payload.recovery_authority_key_material_sha256
            == payload.custody_authority_key_material_sha256
        || payload.deadline_epoch_ms <= payload.created_at_epoch_ms
        || payload.deadline_epoch_ms - payload.created_at_epoch_ms
            > MAX_LOCAL_RECONCILIATION_DELAY_MS
        || payload.signed_at_epoch_ms < payload.created_at_epoch_ms
        || payload.signed_at_epoch_ms >= payload.deadline_epoch_ms
        || payload.predecessor_record_id.is_some()
            != payload.predecessor_record_sha256.is_some()
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_recovery_payload",
            "localReconciliationRecovery.payload",
            "signed recovery requires a bounded exact record, positive generations and rollback/revocation state, unresolved deadline, and an all-or-none predecessor record identity",
        ));
    }
    Ok(())
}

fn validate_local_reconciliation_continuity_payload(
    payload: &LocalReconciliationContinuityEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    validate_identifier(
        &payload.credential_ledger_namespace,
        "localReconciliationContinuity.payload.credentialLedgerNamespace",
    )?;
    for (value, path) in [
        (
            &payload.current_record_id,
            "localReconciliationContinuity.payload.currentRecordId",
        ),
        (
            &payload.pinned_genesis_state_sha256,
            "localReconciliationContinuity.payload.pinnedGenesisStateSha256",
        ),
        (
            &payload.predecessor_successor_key_sha256,
            "localReconciliationContinuity.payload.predecessorSuccessorKeySha256",
        ),
        (
            &payload.current_record_sha256,
            "localReconciliationContinuity.payload.currentRecordSha256",
        ),
        (
            &payload.current_record_retrieval_id,
            "localReconciliationContinuity.payload.currentRecordRetrievalId",
        ),
        (
            &payload.current_persistence_receipt_sha256,
            "localReconciliationContinuity.payload.currentPersistenceReceiptSha256",
        ),
        (
            &payload.current_retrieval_proof_sha256,
            "localReconciliationContinuity.payload.currentRetrievalProofSha256",
        ),
        (
            &payload.ledger_checkpoint_sha256,
            "localReconciliationContinuity.payload.ledgerCheckpointSha256",
        ),
        (
            &payload.store_transaction_id,
            "localReconciliationContinuity.payload.storeTransactionId",
        ),
        (
            &payload.store_transition_sha256,
            "localReconciliationContinuity.payload.storeTransitionSha256",
        ),
        (
            &payload.quorum_certificate_sha256,
            "localReconciliationContinuity.payload.quorumCertificateSha256",
        ),
        (
            &payload.transparency_log_proof_sha256,
            "localReconciliationContinuity.payload.transparencyLogProofSha256",
        ),
        (
            &payload.ledger_witness_evidence_sha256,
            "localReconciliationContinuity.payload.ledgerWitnessEvidenceSha256",
        ),
        (
            &payload.ledger_witness_retrieval_id,
            "localReconciliationContinuity.payload.ledgerWitnessRetrievalId",
        ),
        (
            &payload.ledger_witness_persistence_receipt_sha256,
            "localReconciliationContinuity.payload.ledgerWitnessPersistenceReceiptSha256",
        ),
        (
            &payload.ledger_witness_retrieval_proof_sha256,
            "localReconciliationContinuity.payload.ledgerWitnessRetrievalProofSha256",
        ),
        (
            &payload.custody_authority_evidence_sha256,
            "localReconciliationContinuity.payload.custodyAuthorityEvidenceSha256",
        ),
        (
            &payload.custody_authority_key_id,
            "localReconciliationContinuity.payload.custodyAuthorityKeyId",
        ),
        (
            &payload.custody_authority_key_material_sha256,
            "localReconciliationContinuity.payload.custodyAuthorityKeyMaterialSha256",
        ),
        (
            &payload.trust_checkpoint_sha256,
            "localReconciliationContinuity.payload.trustCheckpointSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_identifier(
        &payload.ledger_id,
        "localReconciliationContinuity.payload.ledgerId",
    )?;
    validate_identifier(
        &payload.linearizable_store_id,
        "localReconciliationContinuity.payload.linearizableStoreId",
    )?;
    validate_identifier(
        &payload.linearizable_store_cluster_id,
        "localReconciliationContinuity.payload.linearizableStoreClusterId",
    )?;
    for (value, path) in [
        (
            payload.current_record_byte_length,
            "localReconciliationContinuity.payload.currentRecordByteLength",
        ),
        (
            payload.ledger_sequence,
            "localReconciliationContinuity.payload.ledgerSequence",
        ),
        (
            payload.ledger_checkpoint_epoch,
            "localReconciliationContinuity.payload.ledgerCheckpointEpoch",
        ),
        (
            payload.store_term,
            "localReconciliationContinuity.payload.storeTerm",
        ),
        (
            payload.store_log_index,
            "localReconciliationContinuity.payload.storeLogIndex",
        ),
        (
            payload.store_fencing_token,
            "localReconciliationContinuity.payload.storeFencingToken",
        ),
        (
            payload.ledger_witness_byte_length,
            "localReconciliationContinuity.payload.ledgerWitnessByteLength",
        ),
        (
            payload.revocation_epoch,
            "localReconciliationContinuity.payload.revocationEpoch",
        ),
    ] {
        validate_safe_integer(value, path)?;
    }
    validate_safe_time(
        payload.signed_at_epoch_ms,
        "localReconciliationContinuity.payload.signedAtEpochMs",
    )?;
    if payload.current_record_byte_length == 0
        || payload.current_record_byte_length
            > MAX_LOCAL_RECONCILIATION_RECORD_BYTES as u64
        || payload.ledger_sequence == 0
        || payload.ledger_checkpoint_epoch == 0
        || payload.store_term == 0
        || payload.store_log_index == 0
        || payload.store_fencing_token == 0
        || payload.ledger_witness_byte_length == 0
        || payload.ledger_witness_byte_length
            > MAX_LOCAL_RECONCILIATION_WITNESS_BYTES as u64
        || payload.revocation_epoch == 0
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_continuity_payload",
            "localReconciliationContinuity.payload",
            "continuity evidence requires bounded exact records and witness bytes plus positive ledger, checkpoint, and revocation state",
        ));
    }
    match &payload.predecessor {
        LocalReconciliationPredecessorProof::Predecessor {
            record_id,
            record_sha256,
            record_byte_length,
            retrieval_id,
            persistence_receipt_sha256,
            retrieval_proof_sha256,
            recovery_evidence_sha256,
            recovery_evidence_byte_length,
            recovery_evidence_retrieval_id,
            recovery_evidence_persistence_receipt_sha256,
            recovery_evidence_retrieval_proof_sha256,
            rollback_head_sha256,
            ledger_sequence,
            ledger_checkpoint_epoch,
            ledger_checkpoint_sha256,
        } => {
            for (value, path) in [
                (record_id, "localReconciliationContinuity.payload.predecessor.recordId"),
                (record_sha256, "localReconciliationContinuity.payload.predecessor.recordSha256"),
                (retrieval_id, "localReconciliationContinuity.payload.predecessor.retrievalId"),
                (persistence_receipt_sha256, "localReconciliationContinuity.payload.predecessor.persistenceReceiptSha256"),
                (retrieval_proof_sha256, "localReconciliationContinuity.payload.predecessor.retrievalProofSha256"),
                (recovery_evidence_sha256, "localReconciliationContinuity.payload.predecessor.recoveryEvidenceSha256"),
                (recovery_evidence_retrieval_id, "localReconciliationContinuity.payload.predecessor.recoveryEvidenceRetrievalId"),
                (recovery_evidence_persistence_receipt_sha256, "localReconciliationContinuity.payload.predecessor.recoveryEvidencePersistenceReceiptSha256"),
                (recovery_evidence_retrieval_proof_sha256, "localReconciliationContinuity.payload.predecessor.recoveryEvidenceRetrievalProofSha256"),
                (rollback_head_sha256, "localReconciliationContinuity.payload.predecessor.rollbackHeadSha256"),
                (ledger_checkpoint_sha256, "localReconciliationContinuity.payload.predecessor.ledgerCheckpointSha256"),
            ] {
                validate_digest(value, path)?;
            }
            for (value, path) in [
                (*record_byte_length, "localReconciliationContinuity.payload.predecessor.recordByteLength"),
                (*recovery_evidence_byte_length, "localReconciliationContinuity.payload.predecessor.recoveryEvidenceByteLength"),
                (*ledger_sequence, "localReconciliationContinuity.payload.predecessor.ledgerSequence"),
                (*ledger_checkpoint_epoch, "localReconciliationContinuity.payload.predecessor.ledgerCheckpointEpoch"),
            ] {
                validate_safe_integer(value, path)?;
            }
            if *record_byte_length == 0
                || *record_byte_length
                    > MAX_LOCAL_RECONCILIATION_RECORD_BYTES as u64
                || *recovery_evidence_byte_length == 0
                || *recovery_evidence_byte_length
                    > MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES as u64
                || *ledger_sequence == 0
                || *ledger_checkpoint_epoch == 0
                || (*ledger_sequence).checked_add(1)
                    != Some(payload.ledger_sequence)
                || *ledger_checkpoint_epoch
                    >= payload.ledger_checkpoint_epoch
            {
                return Err(ContractError::new(
                    "invalid_local_reconciliation_predecessor",
                    "localReconciliationContinuity.payload.predecessor",
                    "predecessor evidence must be bounded and immediately precede a strictly newer ledger checkpoint",
                ));
            }
        }
        LocalReconciliationPredecessorProof::Genesis {
            genesis_absence_evidence_sha256,
            genesis_absence_evidence_byte_length,
            genesis_absence_evidence_retrieval_id,
            genesis_absence_persistence_receipt_sha256,
            genesis_absence_retrieval_proof_sha256,
        } => {
            for (value, path) in [
                (genesis_absence_evidence_sha256, "localReconciliationContinuity.payload.genesis.genesisAbsenceEvidenceSha256"),
                (genesis_absence_evidence_retrieval_id, "localReconciliationContinuity.payload.genesis.genesisAbsenceEvidenceRetrievalId"),
                (genesis_absence_persistence_receipt_sha256, "localReconciliationContinuity.payload.genesis.genesisAbsencePersistenceReceiptSha256"),
                (genesis_absence_retrieval_proof_sha256, "localReconciliationContinuity.payload.genesis.genesisAbsenceRetrievalProofSha256"),
            ] {
                validate_digest(value, path)?;
            }
            validate_safe_integer(
                *genesis_absence_evidence_byte_length,
                "localReconciliationContinuity.payload.genesis.genesisAbsenceEvidenceByteLength",
            )?;
            if payload.ledger_sequence != 1
                || *genesis_absence_evidence_byte_length == 0
                || *genesis_absence_evidence_byte_length
                    > MAX_LOCAL_RECONCILIATION_CONTINUITY_BYTES as u64
            {
                return Err(ContractError::new(
                    "invalid_local_reconciliation_genesis_reference",
                    "localReconciliationContinuity.payload.genesis",
                    "genesis requires ledger sequence one and bounded exact signed absence evidence",
                ));
            }
        }
    }
    Ok(())
}

fn validate_local_reconciliation_ledger_witness(
    payload: &LocalReconciliationLedgerWitness,
) -> ContractResult<()> {
    if payload.api_version
            != LOCAL_RECONCILIATION_LEDGER_WITNESS_API_VERSION
        || payload.kind != LOCAL_RECONCILIATION_LEDGER_WITNESS_KIND
    {
        return Err(ContractError::new(
            "wrong_local_reconciliation_ledger_witness_contract",
            "localReconciliationLedgerWitness",
            "ledger witness apiVersion or kind is not the closed v2 contract",
        ));
    }
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (&payload.current_record_id, "localReconciliationLedgerWitness.currentRecordId"),
        (&payload.current_record_sha256, "localReconciliationLedgerWitness.currentRecordSha256"),
        (&payload.pinned_genesis_state_sha256, "localReconciliationLedgerWitness.pinnedGenesisStateSha256"),
        (&payload.predecessor_successor_key_sha256, "localReconciliationLedgerWitness.predecessorSuccessorKeySha256"),
        (&payload.predecessor_checkpoint_sha256, "localReconciliationLedgerWitness.predecessorCheckpointSha256"),
        (&payload.current_checkpoint_sha256, "localReconciliationLedgerWitness.currentCheckpointSha256"),
        (&payload.store_transaction_id, "localReconciliationLedgerWitness.storeTransactionId"),
        (&payload.cas_expected_predecessor_sha256, "localReconciliationLedgerWitness.casExpectedPredecessorSha256"),
        (&payload.cas_observed_predecessor_sha256, "localReconciliationLedgerWitness.casObservedPredecessorSha256"),
        (&payload.cas_successor_sha256, "localReconciliationLedgerWitness.casSuccessorSha256"),
        (&payload.store_transition_sha256, "localReconciliationLedgerWitness.storeTransitionSha256"),
        (&payload.custody_authority_key_id, "localReconciliationLedgerWitness.custodyAuthorityKeyId"),
        (&payload.custody_authority_key_material_sha256, "localReconciliationLedgerWitness.custodyAuthorityKeyMaterialSha256"),
        (&payload.trust_checkpoint_sha256, "localReconciliationLedgerWitness.trustCheckpointSha256"),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path) in [
        (&payload.credential_ledger_namespace, "localReconciliationLedgerWitness.credentialLedgerNamespace"),
        (&payload.ledger_id, "localReconciliationLedgerWitness.ledgerId"),
        (&payload.linearizable_store_id, "localReconciliationLedgerWitness.linearizableStoreId"),
        (&payload.linearizable_store_cluster_id, "localReconciliationLedgerWitness.linearizableStoreClusterId"),
    ] {
        validate_identifier(value, path)?;
    }
    for (value, path) in [
        (payload.predecessor_ledger_sequence, "localReconciliationLedgerWitness.predecessorLedgerSequence"),
        (payload.current_ledger_sequence, "localReconciliationLedgerWitness.currentLedgerSequence"),
        (payload.checkpoint_epoch, "localReconciliationLedgerWitness.checkpointEpoch"),
        (payload.predecessor_store_term, "localReconciliationLedgerWitness.predecessorStoreTerm"),
        (payload.predecessor_store_log_index, "localReconciliationLedgerWitness.predecessorStoreLogIndex"),
        (payload.predecessor_store_fencing_token, "localReconciliationLedgerWitness.predecessorStoreFencingToken"),
        (payload.current_store_term, "localReconciliationLedgerWitness.currentStoreTerm"),
        (payload.current_store_log_index, "localReconciliationLedgerWitness.currentStoreLogIndex"),
        (payload.current_store_fencing_token, "localReconciliationLedgerWitness.currentStoreFencingToken"),
        (payload.revocation_epoch, "localReconciliationLedgerWitness.revocationEpoch"),
    ] {
        validate_safe_integer(value, path)?;
    }
    validate_safe_time(
        payload.witnessed_at_epoch_ms,
        "localReconciliationLedgerWitness.witnessedAtEpochMs",
    )?;
    for (value, path) in [
        (payload.predecessor_record_id.as_deref(), "localReconciliationLedgerWitness.predecessorRecordId"),
        (payload.predecessor_record_sha256.as_deref(), "localReconciliationLedgerWitness.predecessorRecordSha256"),
    ] {
        if let Some(value) = value {
            validate_digest(value, path)?;
        }
    }
    let predecessor_present = payload.predecessor_record_id.is_some()
        && payload.predecessor_record_sha256.is_some();
    if payload.predecessor_record_id.is_some()
            != payload.predecessor_record_sha256.is_some()
        || payload.genesis_absence == predecessor_present
        || payload.current_ledger_sequence == 0
        || payload.predecessor_ledger_sequence.checked_add(1)
            != Some(payload.current_ledger_sequence)
        || payload.checkpoint_epoch == 0
        || payload.current_store_term == 0
        || payload.current_store_log_index == 0
        || payload.current_store_fencing_token == 0
        || payload.current_store_term < payload.predecessor_store_term
        || payload.current_store_log_index
            <= payload.predecessor_store_log_index
        || payload.current_store_fencing_token
            <= payload.predecessor_store_fencing_token
        || payload.revocation_epoch == 0
        || (payload.genesis_absence
            && (payload.predecessor_ledger_sequence != 0
                || payload.predecessor_store_term != 0
                || payload.predecessor_store_log_index != 0
                || payload.predecessor_store_fencing_token != 0))
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_ledger_witness",
            "localReconciliationLedgerWitness",
            "witness must carry a closed predecessor/genesis branch and strictly monotonic term, log index, fencing token, ledger sequence, and checkpoint state",
        ));
    }
    validate_local_reconciliation_quorum_certificate(
        &payload.quorum_certificate,
    )?;
    validate_local_reconciliation_transparency_log_proof(
        &payload.transparency_log_proof,
    )?;
    Ok(())
}

fn validate_local_reconciliation_quorum_certificate(
    certificate: &LocalReconciliationQuorumCertificate,
) -> ContractResult<()> {
    for (value, path) in [
        (&certificate.linearizable_store_id, "localReconciliationLedgerWitness.quorumCertificate.linearizableStoreId"),
        (&certificate.linearizable_store_cluster_id, "localReconciliationLedgerWitness.quorumCertificate.linearizableStoreClusterId"),
        (&certificate.credential_ledger_namespace, "localReconciliationLedgerWitness.quorumCertificate.credentialLedgerNamespace"),
    ] {
        validate_identifier(value, path)?;
    }
    for (value, path) in [
        (&certificate.pinned_genesis_state_sha256, "localReconciliationLedgerWitness.quorumCertificate.pinnedGenesisStateSha256"),
        (&certificate.predecessor_successor_key_sha256, "localReconciliationLedgerWitness.quorumCertificate.predecessorSuccessorKeySha256"),
        (&certificate.store_transaction_id, "localReconciliationLedgerWitness.quorumCertificate.storeTransactionId"),
        (&certificate.store_transition_sha256, "localReconciliationLedgerWitness.quorumCertificate.storeTransitionSha256"),
        (&certificate.certificate_sha256, "localReconciliationLedgerWitness.quorumCertificate.certificateSha256"),
    ] {
        validate_digest(value, path)?;
    }
    for (value, path) in [
        (certificate.store_term, "localReconciliationLedgerWitness.quorumCertificate.storeTerm"),
        (certificate.store_log_index, "localReconciliationLedgerWitness.quorumCertificate.storeLogIndex"),
        (certificate.store_fencing_token, "localReconciliationLedgerWitness.quorumCertificate.storeFencingToken"),
    ] {
        validate_safe_integer(value, path)?;
    }
    if certificate.store_term == 0
        || certificate.store_log_index == 0
        || certificate.store_fencing_token == 0
        || certificate.quorum_threshold == 0
        || certificate.members.len()
            < usize::from(certificate.quorum_threshold)
        || certificate.members.len()
            > MAX_LOCAL_RECONCILIATION_QUORUM_MEMBERS
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_quorum_certificate",
            "localReconciliationLedgerWitness.quorumCertificate",
            "quorum certificate requires positive store coordinates and a bounded threshold number of member signatures",
        ));
    }
    let mut previous_key_id: Option<&str> = None;
    for member in &certificate.members {
        for (value, path) in [
            (&member.member_key_id, "localReconciliationLedgerWitness.quorumCertificate.members.memberKeyId"),
            (&member.pinned_genesis_state_sha256, "localReconciliationLedgerWitness.quorumCertificate.members.pinnedGenesisStateSha256"),
            (&member.predecessor_successor_key_sha256, "localReconciliationLedgerWitness.quorumCertificate.members.predecessorSuccessorKeySha256"),
            (&member.store_transaction_id, "localReconciliationLedgerWitness.quorumCertificate.members.storeTransactionId"),
            (&member.store_transition_sha256, "localReconciliationLedgerWitness.quorumCertificate.members.storeTransitionSha256"),
        ] {
            validate_digest(value, path)?;
        }
        validate_identifier(
            &member.credential_ledger_namespace,
            "localReconciliationLedgerWitness.quorumCertificate.members.credentialLedgerNamespace",
        )?;
        validate_signature(&member.signature)?;
        for (value, path) in [
            (member.store_term, "localReconciliationLedgerWitness.quorumCertificate.members.storeTerm"),
            (member.store_log_index, "localReconciliationLedgerWitness.quorumCertificate.members.storeLogIndex"),
            (member.store_fencing_token, "localReconciliationLedgerWitness.quorumCertificate.members.storeFencingToken"),
        ] {
            validate_safe_integer(value, path)?;
        }
        if previous_key_id.is_some_and(|previous| previous >= member.member_key_id.as_str())
            || member.credential_ledger_namespace
                != certificate.credential_ledger_namespace
            || member.pinned_genesis_state_sha256
                != certificate.pinned_genesis_state_sha256
            || member.predecessor_successor_key_sha256
                != certificate.predecessor_successor_key_sha256
            || member.store_transaction_id != certificate.store_transaction_id
            || member.store_transition_sha256
                != certificate.store_transition_sha256
            || member.store_term != certificate.store_term
            || member.store_log_index != certificate.store_log_index
            || member.store_fencing_token != certificate.store_fencing_token
        {
            return Err(ContractError::new(
                "invalid_local_reconciliation_quorum_member",
                "localReconciliationLedgerWitness.quorumCertificate.members",
                "quorum members must be strictly key-sorted, unique, and repeat the exact pinned credential-ledger namespace, genesis state, predecessor conflict key, transaction, transition, term, log index, and fencing token",
            ));
        }
        previous_key_id = Some(member.member_key_id.as_str());
    }
    Ok(())
}

fn validate_local_reconciliation_transparency_log_proof(
    proof: &LocalReconciliationTransparencyLogProof,
) -> ContractResult<()> {
    validate_identifier(
        &proof.transparency_log_id,
        "localReconciliationLedgerWitness.transparencyLogProof.transparencyLogId",
    )?;
    validate_identifier(
        &proof.credential_ledger_namespace,
        "localReconciliationLedgerWitness.transparencyLogProof.credentialLedgerNamespace",
    )?;
    for (value, path) in [
        (&proof.transparency_operator_key_id, "localReconciliationLedgerWitness.transparencyLogProof.transparencyOperatorKeyId"),
        (&proof.pinned_genesis_state_sha256, "localReconciliationLedgerWitness.transparencyLogProof.pinnedGenesisStateSha256"),
        (&proof.store_transaction_id, "localReconciliationLedgerWitness.transparencyLogProof.storeTransactionId"),
        (&proof.store_transition_sha256, "localReconciliationLedgerWitness.transparencyLogProof.storeTransitionSha256"),
        (&proof.quorum_certificate_sha256, "localReconciliationLedgerWitness.transparencyLogProof.quorumCertificateSha256"),
        (&proof.predecessor_successor_key_sha256, "localReconciliationLedgerWitness.transparencyLogProof.predecessorSuccessorKeySha256"),
        (&proof.leaf_sha256, "localReconciliationLedgerWitness.transparencyLogProof.leafSha256"),
        (&proof.anchor_checkpoint_root_sha256, "localReconciliationLedgerWitness.transparencyLogProof.anchorCheckpointRootSha256"),
        (&proof.current_checkpoint_root_sha256, "localReconciliationLedgerWitness.transparencyLogProof.currentCheckpointRootSha256"),
        (&proof.conflicting_successor_absence_proof_sha256, "localReconciliationLedgerWitness.transparencyLogProof.conflictingSuccessorAbsenceProofSha256"),
        (&proof.trust_checkpoint_sha256, "localReconciliationLedgerWitness.transparencyLogProof.trustCheckpointSha256"),
        (&proof.proof_sha256, "localReconciliationLedgerWitness.transparencyLogProof.proofSha256"),
    ] {
        validate_digest(value, path)?;
    }
    validate_signature(&proof.checkpoint_signature)?;
    for path_digest in proof
        .inclusion_path_sha256
        .iter()
        .chain(proof.consistency_path_sha256.iter())
    {
        validate_digest(
            path_digest,
            "localReconciliationLedgerWitness.transparencyLogProof.pathSha256",
        )?;
    }
    for (value, path) in [
        (proof.leaf_index, "localReconciliationLedgerWitness.transparencyLogProof.leafIndex"),
        (proof.anchor_checkpoint_revision, "localReconciliationLedgerWitness.transparencyLogProof.anchorCheckpointRevision"),
        (proof.anchor_checkpoint_tree_size, "localReconciliationLedgerWitness.transparencyLogProof.anchorCheckpointTreeSize"),
        (proof.current_checkpoint_revision, "localReconciliationLedgerWitness.transparencyLogProof.currentCheckpointRevision"),
        (proof.current_checkpoint_tree_size, "localReconciliationLedgerWitness.transparencyLogProof.currentCheckpointTreeSize"),
        (proof.revocation_epoch, "localReconciliationLedgerWitness.transparencyLogProof.revocationEpoch"),
    ] {
        validate_safe_integer(value, path)?;
    }
    validate_safe_time(
        proof.signed_at_epoch_ms,
        "localReconciliationLedgerWitness.transparencyLogProof.signedAtEpochMs",
    )?;
    let unchanged_checkpoint =
        proof.current_checkpoint_revision == proof.anchor_checkpoint_revision
            && proof.current_checkpoint_tree_size
                == proof.anchor_checkpoint_tree_size
            && proof.current_checkpoint_root_sha256
                == proof.anchor_checkpoint_root_sha256;
    if proof.anchor_checkpoint_revision == 0
        || proof.anchor_checkpoint_tree_size == 0
        || proof.current_checkpoint_revision
            < proof.anchor_checkpoint_revision
        || proof.current_checkpoint_tree_size
            < proof.anchor_checkpoint_tree_size
        || (proof.current_checkpoint_revision
            == proof.anchor_checkpoint_revision)
            != (proof.current_checkpoint_tree_size
                == proof.anchor_checkpoint_tree_size)
        || (proof.current_checkpoint_revision
                == proof.anchor_checkpoint_revision
            && proof.current_checkpoint_root_sha256
                != proof.anchor_checkpoint_root_sha256)
        || proof.leaf_index >= proof.current_checkpoint_tree_size
        || proof.revocation_epoch == 0
        || proof.inclusion_path_sha256.len()
            > MAX_LOCAL_RECONCILIATION_MERKLE_PATH
        || proof.consistency_path_sha256.len()
            > MAX_LOCAL_RECONCILIATION_MERKLE_PATH
        || (unchanged_checkpoint && !proof.consistency_path_sha256.is_empty())
        || (!unchanged_checkpoint && proof.consistency_path_sha256.is_empty())
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_transparency_proof",
            "localReconciliationLedgerWitness.transparencyLogProof",
            "transparency proof requires bounded inclusion/consistency paths, a contained leaf, positive trust state, and monotonic externally anchored checkpoints",
        ));
    }
    Ok(())
}

fn validate_local_reconciliation_genesis_absence_payload(
    payload: &LocalReconciliationGenesisAbsenceEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (&payload.current_record_id, "localReconciliationGenesisAbsence.payload.currentRecordId"),
        (&payload.pinned_genesis_state_sha256, "localReconciliationGenesisAbsence.payload.pinnedGenesisStateSha256"),
        (&payload.predecessor_successor_key_sha256, "localReconciliationGenesisAbsence.payload.predecessorSuccessorKeySha256"),
        (&payload.predecessor_checkpoint_sha256, "localReconciliationGenesisAbsence.payload.predecessorCheckpointSha256"),
        (&payload.current_checkpoint_sha256, "localReconciliationGenesisAbsence.payload.currentCheckpointSha256"),
        (&payload.custody_authority_key_id, "localReconciliationGenesisAbsence.payload.custodyAuthorityKeyId"),
        (&payload.custody_authority_key_material_sha256, "localReconciliationGenesisAbsence.payload.custodyAuthorityKeyMaterialSha256"),
        (&payload.trust_checkpoint_sha256, "localReconciliationGenesisAbsence.payload.trustCheckpointSha256"),
    ] {
        validate_digest(value, path)?;
    }
    validate_identifier(
        &payload.credential_ledger_namespace,
        "localReconciliationGenesisAbsence.payload.credentialLedgerNamespace",
    )?;
    validate_identifier(
        &payload.ledger_id,
        "localReconciliationGenesisAbsence.payload.ledgerId",
    )?;
    for (value, path) in [
        (payload.first_ledger_sequence, "localReconciliationGenesisAbsence.payload.firstLedgerSequence"),
        (payload.prior_record_count, "localReconciliationGenesisAbsence.payload.priorRecordCount"),
        (payload.checkpoint_epoch, "localReconciliationGenesisAbsence.payload.checkpointEpoch"),
        (payload.revocation_epoch, "localReconciliationGenesisAbsence.payload.revocationEpoch"),
    ] {
        validate_safe_integer(value, path)?;
    }
    validate_safe_time(
        payload.signed_at_epoch_ms,
        "localReconciliationGenesisAbsence.payload.signedAtEpochMs",
    )?;
    if payload.first_ledger_sequence != 1
        || payload.prior_record_count != 0
        || payload.checkpoint_epoch == 0
        || payload.revocation_epoch == 0
    {
        return Err(ContractError::new(
            "invalid_local_reconciliation_genesis_absence",
            "localReconciliationGenesisAbsence.payload",
            "signed genesis absence must prove zero prior records and ledger sequence one at a positive checkpoint",
        ));
    }
    Ok(())
}

fn validate_persistence_payload(payload: &PersistenceEvidencePayload) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    validate_digest(&payload.envelope_sha256, "persistence.payload.envelopeSha256")?;
    validate_digest(&payload.retrieval_id, "persistence.payload.retrievalId")?;
    validate_digest(
        &payload.terminal_evidence_sha256,
        "persistence.payload.terminalEvidenceSha256",
    )?;
    validate_digest(
        &payload.persistence_receipt_sha256,
        "persistence.payload.persistenceReceiptSha256",
    )?;
    validate_digest(
        &payload.retrieval_proof_sha256,
        "persistence.payload.retrievalProofSha256",
    )?;
    validate_safe_integer(
        payload.envelope_byte_length,
        "persistence.payload.envelopeByteLength",
    )?;
    validate_safe_time(
        payload.persisted_at_epoch_ms,
        "persistence.payload.persistedAtEpochMs",
    )?;
    if payload.envelope_byte_length == 0
        || payload.envelope_byte_length > MAX_PROOF_BYTES as u64
        || !payload.immutable
    {
        return Err(ContractError::new(
            "invalid_persistence_claim",
            "persistence.payload",
            "persistence must identify nonempty immutable envelope bytes",
        ));
    }
    Ok(())
}

fn validate_finalization_checkpoint_payload(
    payload: &FinalizationCheckpointEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (
            &payload.retrieval_id,
            "finalizationCheckpoint.payload.retrievalId",
        ),
        (
            &payload.envelope_sha256,
            "finalizationCheckpoint.payload.envelopeSha256",
        ),
        (
            &payload.terminal_evidence_sha256,
            "finalizationCheckpoint.payload.terminalEvidenceSha256",
        ),
        (
            &payload.persistence_evidence_sha256,
            "finalizationCheckpoint.payload.persistenceEvidenceSha256",
        ),
        (
            &payload.trust_checkpoint_sha256,
            "finalizationCheckpoint.payload.trustCheckpointSha256",
        ),
        (
            &payload.historical_trust_policy_sha256,
            "finalizationCheckpoint.payload.historicalTrustPolicySha256",
        ),
        (
            &payload.historical_key_set_root_sha256,
            "finalizationCheckpoint.payload.historicalKeySetRootSha256",
        ),
        (
            &payload.historical_key_inclusion_proof_sha256,
            "finalizationCheckpoint.payload.historicalKeyInclusionProofSha256",
        ),
        (
            &payload.historical_non_revocation_proof_sha256,
            "finalizationCheckpoint.payload.historicalNonRevocationProofSha256",
        ),
        (
            &payload.runtime_attestation_evidence_sha256,
            "finalizationCheckpoint.payload.runtimeAttestationEvidenceSha256",
        ),
        (
            &payload.runtime_attestation_verifier_key_id,
            "finalizationCheckpoint.payload.runtimeAttestationVerifierKeyId",
        ),
        (
            &payload.runtime_attestation_inclusion_proof_sha256,
            "finalizationCheckpoint.payload.runtimeAttestationInclusionProofSha256",
        ),
        (
            &payload.runtime_measurement_sha256,
            "finalizationCheckpoint.payload.runtimeMeasurementSha256",
        ),
        (
            &payload.immutable_persistence_receipt_sha256,
            "finalizationCheckpoint.payload.immutablePersistenceReceiptSha256",
        ),
        (
            &payload.exact_retrieval_proof_sha256,
            "finalizationCheckpoint.payload.exactRetrievalProofSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_safe_integer(
        payload.envelope_byte_length,
        "finalizationCheckpoint.payload.envelopeByteLength",
    )?;
    validate_safe_integer(
        payload.revocation_epoch,
        "finalizationCheckpoint.payload.revocationEpoch",
    )?;
    validate_safe_time(
        payload.finalized_at_epoch_ms,
        "finalizationCheckpoint.payload.finalizedAtEpochMs",
    )?;
    validate_safe_time(
        payload.trusted_time_epoch_ms,
        "finalizationCheckpoint.payload.trustedTimeEpochMs",
    )?;
    if payload.envelope_byte_length == 0
        || payload.envelope_byte_length > MAX_PROOF_BYTES as u64
        || payload.revocation_epoch == 0
        || payload.finalized_at_epoch_ms != payload.trusted_time_epoch_ms
        || !payload.archival_verification_enabled
    {
        return Err(ContractError::new(
            "invalid_finalization_checkpoint",
            "finalizationCheckpoint.payload",
            "checkpoint requires bounded finalized exact bytes, one trusted finalization instant, a positive revocation epoch, and explicit archival verification support",
        ));
    }
    Ok(())
}

fn validate_artifact_time_checkpoint_payload(
    payload: &ArtifactTimeCheckpointEvidencePayload,
) -> ContractResult<()> {
    validate_attempt_id(&payload.attempt_id)?;
    for (value, path) in [
        (&payload.retrieval_id, "artifactTimeCheckpoint.payload.retrievalId"),
        (&payload.envelope_sha256, "artifactTimeCheckpoint.payload.envelopeSha256"),
        (&payload.artifact_sha256, "artifactTimeCheckpoint.payload.artifactSha256"),
        (&payload.artifact_signing_key_id, "artifactTimeCheckpoint.payload.artifactSigningKeyId"),
        (&payload.trust_checkpoint_sha256, "artifactTimeCheckpoint.payload.trustCheckpointSha256"),
        (&payload.historical_trust_policy_sha256, "artifactTimeCheckpoint.payload.historicalTrustPolicySha256"),
        (&payload.historical_key_set_root_sha256, "artifactTimeCheckpoint.payload.historicalKeySetRootSha256"),
        (&payload.historical_key_inclusion_proof_sha256, "artifactTimeCheckpoint.payload.historicalKeyInclusionProofSha256"),
        (&payload.historical_non_revocation_proof_sha256, "artifactTimeCheckpoint.payload.historicalNonRevocationProofSha256"),
        (&payload.runtime_attestation_evidence_sha256, "artifactTimeCheckpoint.payload.runtimeAttestationEvidenceSha256"),
        (&payload.runtime_attestation_verifier_key_id, "artifactTimeCheckpoint.payload.runtimeAttestationVerifierKeyId"),
        (&payload.runtime_attestation_inclusion_proof_sha256, "artifactTimeCheckpoint.payload.runtimeAttestationInclusionProofSha256"),
        (&payload.runtime_measurement_sha256, "artifactTimeCheckpoint.payload.runtimeMeasurementSha256"),
        (&payload.finalization_checkpoint_evidence_sha256, "artifactTimeCheckpoint.payload.finalizationCheckpointEvidenceSha256"),
        (&payload.immutable_artifact_receipt_sha256, "artifactTimeCheckpoint.payload.immutableArtifactReceiptSha256"),
        (&payload.exact_artifact_retrieval_proof_sha256, "artifactTimeCheckpoint.payload.exactArtifactRetrievalProofSha256"),
    ] {
        validate_digest(value, path)?;
    }
    if let Some(value) = payload.prerequisite_attestation_sha256.as_deref() {
        validate_digest(
            value,
            "artifactTimeCheckpoint.payload.prerequisiteAttestationSha256",
        )?;
    }
    if let Some(value) = payload
        .prerequisite_artifact_time_checkpoint_evidence_sha256
        .as_deref()
    {
        validate_digest(
            value,
            "artifactTimeCheckpoint.payload.prerequisiteArtifactTimeCheckpointEvidenceSha256",
        )?;
    }
    for (value, path) in [
        (payload.finalized_at_epoch_ms, "artifactTimeCheckpoint.payload.finalizedAtEpochMs"),
        (payload.artifact_at_epoch_ms, "artifactTimeCheckpoint.payload.artifactAtEpochMs"),
        (payload.trusted_time_epoch_ms, "artifactTimeCheckpoint.payload.trustedTimeEpochMs"),
        (payload.artifact_key_expires_at_epoch_ms, "artifactTimeCheckpoint.payload.artifactKeyExpiresAtEpochMs"),
        (payload.signed_at_epoch_ms, "artifactTimeCheckpoint.payload.signedAtEpochMs"),
    ] {
        validate_safe_time(value, path)?;
    }
    validate_safe_integer(
        payload.revocation_epoch,
        "artifactTimeCheckpoint.payload.revocationEpoch",
    )?;
    let prerequisite_valid = match payload.artifact_role {
        FinalizationArtifactRole::EnvelopeAttestation => {
            payload.prerequisite_attestation_sha256.is_none()
                && payload
                    .prerequisite_artifact_time_checkpoint_evidence_sha256
                    .is_none()
        }
        FinalizationArtifactRole::PublicationReceipt => {
            payload.prerequisite_attestation_sha256.is_some()
                && payload
                    .prerequisite_artifact_time_checkpoint_evidence_sha256
                    .is_some()
        }
    };
    if !prerequisite_valid
        || payload.finalized_at_epoch_ms > payload.artifact_at_epoch_ms
        || payload.artifact_at_epoch_ms != payload.trusted_time_epoch_ms
        || payload.artifact_at_epoch_ms != payload.signed_at_epoch_ms
        || payload.artifact_at_epoch_ms
            >= payload.artifact_key_expires_at_epoch_ms
        || payload.revocation_epoch == 0
    {
        return Err(ContractError::new(
            "invalid_artifact_time_checkpoint",
            "artifactTimeCheckpoint.payload",
            "artifact checkpoint must be role-complete and prove finalization <= exact trusted artifact time < signing-key expiry at a positive revocation epoch",
        ));
    }
    Ok(())
}

fn validate_runtime(runtime: &BootRuntimeIdentity) -> ContractResult<()> {
    validate_identifier(&runtime.runtime_instance_id, "runtime.runtimeInstanceId")?;
    for (value, path) in [
        (&runtime.boot_id, "runtime.bootId"),
        (
            &runtime.runtime_measurement_sha256,
            "runtime.runtimeMeasurementSha256",
        ),
        (&runtime.release_sha256, "runtime.releaseSha256"),
        (
            &runtime.data_plane_binary_sha256,
            "runtime.dataPlaneBinarySha256",
        ),
        (
            &runtime.rollback_state_head_sha256,
            "runtime.rollbackStateHeadSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    validate_safe_integer(runtime.rollback_state_epoch, "runtime.rollbackStateEpoch")
}

fn route_idempotency_digest(route: &RouteSemantics) -> Option<&str> {
    match route {
        RouteSemantics::Write {
            provider_idempotency,
            ..
        } => Some(provider_idempotency.binding_sha256.as_str()),
        RouteSemantics::Rejected { .. }
        | RouteSemantics::WriteNotDispatchable { .. }
        | RouteSemantics::ReadOnly { .. }
        | RouteSemantics::CredentiallessReadOnly { .. } => None,
    }
}

fn route_recovery_binding(route: &RouteSemantics) -> ContractResult<&str> {
    match route {
        RouteSemantics::Write {
            ambiguous_outcome_recovery,
            ..
        } => Ok(ambiguous_outcome_recovery.durable_record_sha256.as_str()),
        RouteSemantics::Rejected { .. }
        | RouteSemantics::WriteNotDispatchable { .. } => {
            Err(ContractError::new(
                "ambiguous_outcome_without_recovery",
                "body.routeSemantics",
                "ambiguous target outcomes require a typed route recovery binding",
            ))
        }
        RouteSemantics::ReadOnly { .. }
        | RouteSemantics::CredentiallessReadOnly { .. } => Err(
            ContractError::new(
                "write_recovery_used_for_read",
                "body.routeSemantics",
                "read uncertainty must use the read-specific retry binding",
            ),
        ),
    }
}

fn route_read_retry_binding(route: &RouteSemantics) -> ContractResult<&str> {
    match route {
        RouteSemantics::ReadOnly { retry_recovery, .. }
        | RouteSemantics::CredentiallessReadOnly { retry_recovery, .. } => {
            Ok(retry_recovery.retry_binding_sha256.as_str())
        }
        _ => Err(ContractError::new(
            "read_uncertainty_without_retry_policy",
            "body.routeSemantics",
            "read transition uncertainty requires a read-specific signed retry policy",
        )),
    }
}

pub fn attempt_id(
    nonce_sha256: &str,
    policy_sha256: &str,
    request_sha256: &str,
    operation_sha256: &str,
    boot_id: &str,
    route_semantic_profile_sha256: &str,
) -> ContractResult<String> {
    for (value, path) in [
        (nonce_sha256, "nonceSha256"),
        (policy_sha256, "policySha256"),
        (request_sha256, "requestSha256"),
        (operation_sha256, "operationSha256"),
        (boot_id, "bootId"),
        (
            route_semantic_profile_sha256,
            "routeSemanticProfileSha256",
        ),
    ] {
        validate_digest(value, path)?;
    }
    domain_sha256(
        ATTEMPT_ID_DOMAIN,
        &[
            nonce_sha256.as_bytes(),
            policy_sha256.as_bytes(),
            request_sha256.as_bytes(),
            operation_sha256.as_bytes(),
            boot_id.as_bytes(),
            route_semantic_profile_sha256.as_bytes(),
        ],
    )
}

pub fn idempotency_binding(
    attempt_id_value: &str,
    key_sha256: &str,
    staged_request_sha256: &str,
) -> ContractResult<String> {
    validate_attempt_id(attempt_id_value)?;
    validate_digest(key_sha256, "keySha256")?;
    validate_digest(staged_request_sha256, "stagedRequestSha256")?;
    domain_sha256(
        IDEMPOTENCY_BINDING_DOMAIN,
        &[
            attempt_id_value.as_bytes(),
            key_sha256.as_bytes(),
            staged_request_sha256.as_bytes(),
        ],
    )
}

pub fn recovery_key(
    attempt_id_value: &str,
    idempotency_binding_sha256: &str,
) -> ContractResult<String> {
    validate_attempt_id(attempt_id_value)?;
    validate_digest(
        idempotency_binding_sha256,
        "idempotencyBindingSha256",
    )?;
    domain_sha256(
        RECOVERY_KEY_DOMAIN,
        &[
            attempt_id_value.as_bytes(),
            idempotency_binding_sha256.as_bytes(),
        ],
    )
}

pub fn retrieval_id(
    attempt_id_value: &str,
    envelope_sha256: &str,
) -> ContractResult<String> {
    validate_attempt_id(attempt_id_value)?;
    validate_digest(envelope_sha256, "envelopeSha256")?;
    domain_sha256(
        RETRIEVAL_ID_DOMAIN,
        &[attempt_id_value.as_bytes(), envelope_sha256.as_bytes()],
    )
}

/// Build the normative SHA-256 preimage:
///
/// `MAGIC || u16be(domain_len) || domain || u16be(frame_count) ||
///  repeated(u64be(frame_len) || frame)`.
///
/// Domain names are nonempty printable ASCII. Frame boundaries are therefore
/// unambiguous and no digest can be reinterpreted in another contract domain.
pub fn domain_separated_preimage(
    domain: &str,
    frames: &[&[u8]],
) -> ContractResult<Vec<u8>> {
    let (domain_len, frame_count, aggregate_bytes) =
        validate_digest_frames(domain, frames)?;
    let capacity = PREIMAGE_MAGIC
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(domain.len()))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(aggregate_bytes))
        .ok_or_else(|| {
            ContractError::new(
                "invalid_digest_preimage",
                "digest",
                "diagnostic preimage length overflows",
            )
        })?;
    if capacity > MAX_EXPORTED_PREIMAGE_BYTES {
        return Err(ContractError::new(
            "diagnostic_preimage_too_large",
            "digest",
            "materialized preimages are limited to 64 KiB; production digests stream incrementally",
        ));
    }
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(PREIMAGE_MAGIC);
    output.extend_from_slice(&domain_len.to_be_bytes());
    output.extend_from_slice(domain.as_bytes());
    output.extend_from_slice(&frame_count.to_be_bytes());
    for frame in frames {
        let length = u64::try_from(frame.len()).map_err(|_| {
            ContractError::new(
                "invalid_digest_preimage",
                "digest.frames",
                "frame length cannot be represented",
            )
        })?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(frame);
    }
    Ok(output)
}

fn validate_digest_frames(
    domain: &str,
    frames: &[&[u8]],
) -> ContractResult<(u16, u16, usize)> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
        || !domain
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
        || frames.len() > MAX_DIGEST_FRAMES
        || frames
            .iter()
            .any(|frame| frame.len() > MAX_DIGEST_FRAME_BYTES)
    {
        return Err(ContractError::new(
            "invalid_digest_preimage",
            "digest",
            "domain or frame bounds violate the v2 digest contract",
        ));
    }
    let domain_len = u16::try_from(domain.len()).map_err(|_| {
        ContractError::new(
            "invalid_digest_preimage",
            "digest.domain",
            "domain length cannot be represented",
        )
    })?;
    let frame_count = u16::try_from(frames.len()).map_err(|_| {
        ContractError::new(
            "invalid_digest_preimage",
            "digest.frames",
            "frame count cannot be represented",
        )
    })?;
    let mut aggregate_bytes = 0usize;
    for frame in frames {
        aggregate_bytes = aggregate_bytes
            .checked_add(8)
            .and_then(|value| value.checked_add(frame.len()))
            .ok_or_else(|| {
                ContractError::new(
                    "invalid_digest_preimage",
                    "digest.frames",
                    "aggregate frame work overflows",
                )
            })?;
    }
    if aggregate_bytes > MAX_DIGEST_AGGREGATE_BYTES {
        return Err(ContractError::new(
            "digest_work_limit_exceeded",
            "digest.frames",
            "aggregate framed digest work exceeds the 4 MiB contract bound",
        ));
    }
    Ok((domain_len, frame_count, aggregate_bytes))
}

fn domain_sha256_bytes(
    domain: &str,
    frames: &[&[u8]],
) -> ContractResult<[u8; 32]> {
    let (domain_len, frame_count, _) =
        validate_digest_frames(domain, frames)?;
    let mut hasher = Sha256::new();
    hasher.update(PREIMAGE_MAGIC);
    hasher.update(domain_len.to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(frame_count.to_be_bytes());
    for frame in frames {
        let length = u64::try_from(frame.len()).map_err(|_| {
            ContractError::new(
                "invalid_digest_preimage",
                "digest.frames",
                "frame length cannot be represented",
            )
        })?;
        hasher.update(length.to_be_bytes());
        hasher.update(frame);
    }
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

pub fn domain_sha256(domain: &str, frames: &[&[u8]]) -> ContractResult<String> {
    let digest = domain_sha256_bytes(domain, frames)?;
    Ok(format!("sha256:{}", hex::encode(digest)))
}

/// Canonicalize a typed value using the Catchplate RFC 8785 profile.
///
/// Raw input must first be decoded with duplicate-member rejection. This
/// function intentionally rejects all floating-point values and integers above
/// 2^53-1. It performs UTF-16 object-key ordering as required by JCS and emits
/// compact UTF-8 JSON.
pub fn canonical_jcs_bytes<T: Serialize>(value: &T) -> ContractResult<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| {
        ContractError::new(
            "jcs_serialization_failed",
            "canonicalization",
            "typed value cannot be represented as JSON",
        )
    })?;
    let mut output = Vec::new();
    append_jcs(&value, &mut output)?;
    Ok(output)
}

/// Decode one exact canonical v2 proof document.
///
/// Derived struct deserializers reject duplicate and unknown members. The
/// byte-for-byte JCS comparison rejects alternate whitespace, key order,
/// number spelling, and string escaping before any evidence is trusted.
pub fn decode_canonical_proof(
    bytes: &[u8],
) -> ContractResult<CanonicalResponseObservationProofV2> {
    if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
        return Err(ContractError::new(
            "proof_size_out_of_bounds",
            "$",
            "proof document is empty or exceeds the 2 MiB source-contract bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let proof = ResponseObservationProofV2::deserialize(&mut deserializer)
        .map_err(|_| {
            ContractError::new(
                "invalid_typed_proof",
                "$",
                "proof is invalid JSON or violates the closed typed wire contract",
            )
        })?;
    deserializer.end().map_err(|_| {
        ContractError::new(
            "trailing_json_data",
            "$",
            "proof contains trailing JSON data",
        )
    })?;
    let canonical = canonical_jcs_bytes(&proof)?;
    if canonical != bytes {
        return Err(ContractError::new(
            "noncanonical_jcs",
            "$",
            "proof bytes are not the exact Catchplate RFC 8785 JCS encoding",
        ));
    }
    Ok(CanonicalResponseObservationProofV2 {
        wire: proof,
        _seal: CanonicalWireSeal,
    })
}

fn append_jcs(value: &Value, output: &mut Vec<u8>) -> ContractResult<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                validate_safe_integer(value, "canonicalization.integer")?;
                output.extend_from_slice(value.to_string().as_bytes());
            } else {
                return Err(ContractError::new(
                    "noncanonical_number",
                    "canonicalization",
                    "v2 JCS permits only nonnegative integers through 2^53-1",
                ));
            }
        }
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|_| {
                ContractError::new(
                    "jcs_string_failed",
                    "canonicalization",
                    "string cannot be encoded as canonical JSON",
                )
            })?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                append_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                let key = serde_json::to_string(key).map_err(|_| {
                    ContractError::new(
                        "jcs_key_failed",
                        "canonicalization",
                        "object key cannot be encoded as canonical JSON",
                    )
                })?;
                output.extend_from_slice(key.as_bytes());
                output.push(b':');
                append_jcs(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn validate_digest(value: &str, path: &'static str) -> ContractResult<()> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "invalid_sha256",
            path,
            "value must be a lowercase sha256-prefixed digest",
        ))
    }
}

fn validate_attempt_id(value: &str) -> ContractResult<()> {
    validate_digest(value, "attemptId")
}

fn validate_signature(value: &str) -> ContractResult<()> {
    let encoded = value.strip_prefix("ed25519:").ok_or_else(|| {
        ContractError::new(
            "invalid_signature",
            "evidence.signature",
            "signature must use the ed25519 base64url encoding",
        )
    })?;
    if encoded.len() != 86
        || !encoded.bytes().all(is_base64url)
        || !matches!(
            encoded.as_bytes().last().copied(),
            Some(b'A' | b'Q' | b'g' | b'w')
        )
    {
        return Err(ContractError::new(
            "invalid_signature",
            "evidence.signature",
            "signature is not a canonical 64-byte Ed25519 base64url value",
        ));
    }
    Ok(())
}

fn validate_base64url_32(value: &str, path: &'static str) -> ContractResult<()> {
    if value.len() == 43
        && value.bytes().all(is_base64url)
        && matches!(
            value.as_bytes().last().copied(),
            Some(
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        )
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "invalid_nonce",
            path,
            "nonce must be canonical unpadded base64url for exactly 32 bytes",
        ))
    }
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn validate_identifier(value: &str, path: &'static str) -> ContractResult<()> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-'))
            })
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "invalid_identifier",
            path,
            "identifier is empty, non-ASCII, malformed, or over 128 bytes",
        ))
    }
}

fn validate_http_method(value: &str) -> ContractResult<()> {
    if !value.is_empty()
        && value.len() <= 16
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(
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
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "invalid_http_method",
            "body.stagedTargetRequest.method",
            "HTTP method is not a bounded uppercase token",
        ))
    }
}

fn validate_canonical_target(
    target: &CanonicalUpstreamTarget,
) -> ContractResult<()> {
    validate_digest(
        &target.target_sha256,
        "canonicalTarget.targetSha256",
    )?;
    validate_canonical_host(&target.host)?;
    if target.port == 0 {
        return Err(ContractError::new(
            "invalid_target_port",
            "canonicalTarget.port",
            "canonical target port must be in 1..=65535",
        ));
    }
    canonical_target_authority(target)?;
    validate_canonical_path(&target.path)?;
    validate_canonical_query(&target.canonical_query)?;
    let commitment = CanonicalTargetCommitment {
        scheme: target.scheme,
        host: &target.host,
        port: target.port,
        path: &target.path,
        canonical_query: &target.canonical_query,
        decode_semantics: target.decode_semantics,
    };
    let canonical = canonical_jcs_bytes(&commitment)?;
    let expected =
        domain_sha256(CANONICAL_TARGET_DOMAIN, &[canonical.as_slice()])?;
    require_equal_digest(
        &target.target_sha256,
        &expected,
        "canonicalTarget.targetSha256",
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalTargetCommitment<'a> {
    scheme: TargetScheme,
    host: &'a str,
    port: u16,
    path: &'a str,
    canonical_query: &'a BTreeMap<String, String>,
    decode_semantics: TargetDecodeSemantics,
}

fn canonical_target_authority(
    target: &CanonicalUpstreamTarget,
) -> ContractResult<String> {
    let authority = if target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    if authority.len() > MAX_CANONICAL_AUTHORITY_BYTES {
        return Err(ContractError::new(
            "noncanonical_target_authority",
            "canonicalTarget",
            "derived authority exceeds the closed host and port bound",
        ));
    }
    Ok(authority)
}

fn validate_canonical_host(host: &str) -> ContractResult<()> {
    let labels = host.split('.').collect::<Vec<_>>();
    let dns_shape = !host.is_empty()
        && host.len() <= 253
        && host == host.to_ascii_lowercase()
        && !host.ends_with('.')
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-')
        });
    if !dns_shape {
        return Err(ContractError::new(
            "noncanonical_target_host",
            "canonicalTarget.host",
            "host must be lowercase ASCII DNS form without userinfo, brackets, a trailing dot, empty labels, or noncanonical label boundaries",
        ));
    }
    let numeric_labels = labels
        .iter()
        .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    let legacy_numeric_shape = labels.len() <= 4
        && labels
            .iter()
            .all(|label| is_legacy_ipv4_number_token(label));
    if numeric_labels {
        let canonical_ipv4 = labels.len() == 4 && labels.iter().all(|label| {
            (label.len() == 1 || !label.starts_with('0'))
                && label
                    .parse::<u16>()
                    .is_ok_and(|octet| octet <= 255)
        });
        if !canonical_ipv4 {
            return Err(ContractError::new(
                "noncanonical_target_ipv4",
                "canonicalTarget.host",
                "numeric hosts must use canonical four-octet IPv4 without leading zeros",
            ));
        }
    }
    if legacy_numeric_shape && !numeric_labels {
        return Err(ContractError::new(
            "legacy_numeric_ipv4_forbidden",
            "canonicalTarget.host",
            "hexadecimal, octal, shortened, single-integer, and mixed numeric IPv4 spellings are forbidden",
        ));
    }
    Ok(())
}

fn is_legacy_ipv4_number_token(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.len() > 2
        && label.starts_with("0x")
        && label[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return true;
    }
    label.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_canonical_path(path: &str) -> ContractResult<()> {
    if !path.starts_with('/')
        || path.len() > MAX_CANONICAL_PATH_BYTES
        || !path.is_ascii()
        || path.contains('?')
        || path.contains('#')
        || path.contains("//")
        || !validate_percent_encoded_component(path.as_bytes(), b"/:@!$&'()*+,;=-._~")
    {
        return Err(ContractError::new(
            "noncanonical_target_path",
            "canonicalTarget.path",
            "path must be bounded canonical ASCII origin-form with uppercase necessary percent escapes and no query or fragment delimiter",
        ));
    }
    if path.split('/').any(|segment| segment == "." || segment == "..") {
        return Err(ContractError::new(
            "ambiguous_target_path",
            "canonicalTarget.path",
            "dot path segments are forbidden",
        ));
    }
    Ok(())
}

fn validate_canonical_query(
    query: &BTreeMap<String, String>,
) -> ContractResult<()> {
    if query.len() > MAX_QUERY_PARAMETERS {
        return Err(ContractError::new(
            "canonical_query_limit",
            "canonicalTarget.canonicalQuery",
            "canonical query exceeds the closed parameter bound",
        ));
    }
    for (name, value) in query {
        if name.is_empty()
            || name.len() > MAX_QUERY_NAME_BYTES
            || value.len() > MAX_QUERY_VALUE_BYTES
            || !validate_percent_encoded_component(
                name.as_bytes(),
                b"!$'()*,-._~/:@?",
            )
            || !validate_percent_encoded_component(
                value.as_bytes(),
                b"!$'()*,-._~/:@?",
            )
        {
            return Err(ContractError::new(
                "noncanonical_query_component",
                "canonicalTarget.canonicalQuery",
                "query names and values must use canonical ASCII percent encoding and cannot contain raw separators",
            ));
        }
    }
    Ok(())
}

fn validate_percent_encoded_component(bytes: &[u8], allowed: &[u8]) -> bool {
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
                || bytes[index + 1].is_ascii_lowercase()
                || bytes[index + 2].is_ascii_lowercase()
            {
                return false;
            }
            let decoded = (hex_value(bytes[index + 1]) << 4)
                | hex_value(bytes[index + 2]);
            if decoded.is_ascii_alphanumeric()
                || allowed.contains(&decoded)
                || decoded <= 0x20
                || decoded == 0x7f
                || matches!(
                    decoded,
                    b'%' | b'/' | b'\\' | b'?' | b'#'
                        | b'&' | b'=' | b';' | b'+'
                )
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || allowed.contains(&byte)) {
            return false;
        }
        index += 1;
    }
    true
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn canonical_path_and_query(
    target: &CanonicalUpstreamTarget,
) -> ContractResult<String> {
    let mut value = String::with_capacity(target.path.len());
    value.push_str(&target.path);
    if !target.canonical_query.is_empty() {
        value.push('?');
        for (index, (name, parameter_value)) in
            target.canonical_query.iter().enumerate()
        {
            if index > 0 {
                value.push('&');
            }
            value.push_str(name);
            value.push('=');
            value.push_str(parameter_value);
            if value.len() > MAX_PATH_AND_QUERY_BYTES {
                return Err(ContractError::new(
                    "canonical_target_too_long",
                    "canonicalTarget",
                    "serialized canonical path and query exceeds the closed bound",
                ));
            }
        }
    }
    Ok(value)
}

fn validate_safe_time(value: u64, path: &'static str) -> ContractResult<()> {
    validate_safe_integer(value, path)?;
    if value == 0 {
        return Err(ContractError::new(
            "invalid_timestamp",
            path,
            "timestamp must be positive",
        ));
    }
    Ok(())
}

fn validate_safe_integer(value: u64, path: &'static str) -> ContractResult<()> {
    if value <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(ContractError::new(
            "integer_out_of_range",
            path,
            "integer exceeds the Catchplate JCS interoperable bound",
        ))
    }
}

fn require_none(value: Option<&str>, path: &'static str) -> ContractResult<()> {
    if value.is_none() {
        Ok(())
    } else {
        Err(ContractError::new(
            "unexpected_field_state",
            path,
            "field must be null or absent for this closed state",
        ))
    }
}

fn require_equal_digest(
    actual: &str,
    expected: &str,
    path: &'static str,
) -> ContractResult<()> {
    validate_digest(actual, path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ContractError::new(
            "digest_binding_mismatch",
            path,
            "digest does not match the uniquely bound value",
        ))
    }
}

fn require_equal_optional_digest(
    expected: &str,
    actual: Option<&str>,
    path: &'static str,
) -> ContractResult<()> {
    match actual {
        Some(actual) => require_equal_digest(actual, expected, path),
        None => Err(ContractError::new(
            "missing_digest_binding",
            path,
            "required digest binding is null",
        )),
    }
}

fn require_publication_identity(
    attempt_id_value: &str,
    retrieval_id_value: &str,
    envelope_sha256: &str,
    identity: &FinalizedEnvelopeIdentity,
    path: &'static str,
) -> ContractResult<()> {
    if attempt_id_value == identity.attempt_id
        && retrieval_id_value == identity.retrieval_id
        && envelope_sha256 == identity.envelope_sha256
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "finalized_identity_replacement",
            path,
            "attestation or publication references a different attempt, retrieval ID, or envelope",
        ))
    }
}

fn validate_post_finalization_time(
    value: u64,
    finalized_at: u64,
    trusted_now: u64,
    path: &'static str,
) -> ContractResult<()> {
    validate_safe_time(value, path)?;
    if value < finalized_at || value > trusted_now.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err(ContractError::new(
            "invalid_post_finalization_time",
            path,
            "event time precedes finalization or exceeds trusted clock skew",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct JcsFixture {
        z: u64,
        a: &'static str,
    }

    struct AcceptingIndependentAttestation;

    impl IndependentRuntimeAttestationVerifier for AcceptingIndependentAttestation {
        fn verify_runtime_attestation(
            &self,
            purpose: &RuntimeAttestationVerificationPurpose<'_>,
            _claim: &IndependentRuntimeAttestationClaim,
        ) -> bool {
            purpose.purpose() == RuntimeVerificationPurpose::LiveAuthorization
        }
    }

    #[test]
    fn jcs_orders_object_members_and_rejects_unsafe_integers() {
        let encoded = canonical_jcs_bytes(&JcsFixture { z: 2, a: "one" })
            .expect("canonical typed fixture");
        assert_eq!(encoded, br#"{"a":"one","z":2}"#);
        assert!(canonical_jcs_bytes(&(MAX_SAFE_INTEGER + 1)).is_err());
    }

    #[test]
    fn domain_frames_prevent_concatenation_and_cross_domain_aliases() {
        let split = domain_sha256("test/a", &[b"ab", b"c"]).expect("split");
        let joined = domain_sha256("test/a", &[b"a", b"bc"]).expect("joined");
        let other = domain_sha256("test/b", &[b"ab", b"c"]).expect("other");
        assert_ne!(split, joined);
        assert_ne!(split, other);
    }

    #[test]
    fn attempt_identity_binds_every_authority_dimension() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let first =
            attempt_id(digest, digest, digest, digest, digest, digest)
                .expect("attempt");
        let changed =
            attempt_id(digest, digest, digest, other, digest, digest)
                .expect("changed");
        assert_ne!(first, changed);
    }

    #[test]
    fn lifecycle_rejects_skipping_from_policy_to_write() {
        assert!(!valid_lifecycle_edge(
            LifecycleState::PolicyEvaluated,
            LifecycleState::TargetWriteStarted,
        ));
        assert!(valid_lifecycle_edge(
            LifecycleState::TargetRequestStaged,
            LifecycleState::DispatchAuthorized,
        ));
    }

    #[test]
    fn higher_authority_requires_exact_distinct_capability_set() {
        assert!(has_exact_custody_capabilities(&[
            CustodyCapability::LeaseDecryption,
            CustodyCapability::CredentialInjection,
            CustodyCapability::TargetTls,
            CustodyCapability::TargetEgress,
            CustodyCapability::ProofSigning,
            CustodyCapability::RollbackProtectedState,
        ]));
        assert!(!has_exact_custody_capabilities(&[
            CustodyCapability::LeaseDecryption,
            CustodyCapability::CredentialInjection,
            CustodyCapability::TargetTls,
            CustodyCapability::TargetEgress,
            CustodyCapability::ProofSigning,
            CustodyCapability::ProofSigning,
        ]));
    }

    #[test]
    fn verification_context_requires_opaque_attested_runtime() {
        let digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let claim = IndependentRuntimeAttestationClaim {
            runtime: BootRuntimeIdentity {
                boot_id: digest.to_string(),
                runtime_instance_id: "runtime-1".to_string(),
                runtime_measurement_sha256: digest.to_string(),
                release_sha256: digest.to_string(),
                data_plane_binary_sha256: digest.to_string(),
                rollback_state_epoch: 1,
                rollback_state_head_sha256: digest.to_string(),
            },
            attestation_evidence_sha256: digest.to_string(),
            verifier_key_id: digest.to_string(),
            verified_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 10_000,
        };
        let verified = verify_independently_attested_runtime(
            claim,
            2_000,
            &AcceptingIndependentAttestation,
        )
        .expect("independently verified runtime");
        let context = VerificationContext::new(
            2_000,
            &verified,
            digest,
            1,
        )
        .expect("sealed context");
        assert_eq!(
            context.expected_runtime().identity().runtime_instance_id,
            "runtime-1"
        );
    }

    #[test]
    fn terminal_roles_have_distinct_trust_domains() {
        let digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cancelled = TerminalEvidencePayload::Cancelled {
            attempt_id: digest.to_string(),
            route_semantic_profile_sha256: digest.to_string(),
            authorization_binding_sha256: digest.to_string(),
            reserve_evidence_sha256: None,
            dispatch_evidence_sha256: None,
            credential_authority_evidence_root_sha256: None,
            credential_authority_state_machine_sha256: None,
            dispatch_authorization_binding_sha256: None,
            staged_request_sha256: None,
            credential_recovery_binding_sha256: None,
            local_reconciliation_recovery_evidence_sha256: None,
            local_reconciliation_recovery_authority_key_id: None,
            local_reconciliation_recovery_authority_key_material_sha256: None,
            local_reconciliation_recovery_authority_trust_checkpoint_sha256: None,
            local_reconciliation_recovery_authority_revocation_epoch: None,
            local_reconciliation_credential_ledger_namespace: None,
            local_reconciliation_pinned_genesis_state_sha256: None,
            local_reconciliation_predecessor_successor_key_sha256: None,
            local_reconciliation_continuity_evidence_sha256: None,
            local_reconciliation_store_transition_sha256: None,
            local_reconciliation_quorum_certificate_sha256: None,
            local_reconciliation_transparency_log_proof_sha256: None,
            reason: CancellationReason::PolicyDenied,
            definitely_not_dispatched: true,
            failure_observed_at_epoch_ms: 1,
            completed_at_epoch_ms: 1,
        };
        let completed = TerminalEvidencePayload::Completed {
            attempt_id: digest.to_string(),
            route_semantic_profile_sha256: digest.to_string(),
            authorization_binding_sha256: digest.to_string(),
            dispatch_authorization_binding_sha256: digest.to_string(),
            dispatch_evidence_sha256: digest.to_string(),
            credential_authority_evidence_root_sha256: None,
            credential_authority_state_machine_sha256: None,
            staged_request_sha256: digest.to_string(),
            upstream_observation_sha256: digest.to_string(),
            completed_at_epoch_ms: 1,
        };
        assert_ne!(cancelled.evidence_role(), completed.evidence_role());
        assert_ne!(cancelled.payload_domain(), completed.payload_domain());
        assert_ne!(
            cancelled.signature_domain(),
            completed.signature_domain()
        );
    }
}
