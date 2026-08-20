use ed25519_dalek::pkcs8::{
    DecodePublicKey, EncodePublicKey,
};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const REQUEST_CONTRACT_VERSION: u16 = 11;
pub const RECEIPT_CONTRACT_VERSION: u16 = 12;
pub const CONTROLLER_RUNTIME_PROTOCOL_V12: &str =
    "serverware/controller-runtime/v12";
pub const CONTROLLER_EXECUTOR_PROTOCOL_V12: &str =
    "serverware/controller-plan-invocation/v12";
pub const CONTROLLER_LIFECYCLE_PROTOCOL_V12: &str =
    "serverware/controller-lifecycle/v12";
pub const TRUSTED_HOST_PROFILE: &str =
    "TrustedHostNoTee/userspace-digest/no-IMA-appraisal";

pub type Digest = [u8; 32];

pub const EXECUTOR_INVOCATION_PAYLOAD_FD_INDEX_V12: u8 = 0;
pub const EXECUTOR_SOURCE_INPUT_FD_INDEX_V12: u8 = 1;
pub const EXECUTOR_LANE_PROXY_FD_INDEX_V12: u8 = 2;
pub const EXECUTOR_INVOCATION_FD_COUNT_V12: u8 = 3;

pub fn sha256(bytes: &[u8]) -> Digest {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogicalLane {
    Build,
    Unit,
    Integration,
    E2e,
    Attestation,
}

impl LogicalLane {
    pub const ORDERED: [Self; 5] = [
        Self::Build,
        Self::Unit,
        Self::Integration,
        Self::E2e,
        Self::Attestation,
    ];

    pub fn permits_build(self) -> bool {
        self == Self::Build
    }

    pub fn requires_service_endpoints(self) -> bool {
        matches!(self, Self::Integration | Self::E2e)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LanePhase {
    Prepare,
    Body,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Accepted,
    SourceSealed,
    Building,
    ArtifactSealed,
    Testing,
    Attesting,
    Destroying,
    Destroyed,
    ReceiptPrepared,
    ReceiptAuthenticated,
    ReceiptLogged,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalVerdict {
    Pass,
    Fail,
    Unknown,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestBindingV11 {
    pub request_id: String,
    pub replay_identity: String,
    pub boot_id_sha256: Digest,
    pub request_id_replay_sha256: Digest,
    pub nonce_replay_sha256: Digest,
    pub exact_request_sha256: Digest,
    pub request_envelope_sha256: Digest,
    pub requester_key_authorization_sha256: Digest,
    pub requester_key_revocation_highwater: u64,
    pub accepted_at_unix_ms: u64,
    pub deadline_boottime_ns: u64,
}

impl RequestBindingV11 {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.is_empty()
            || self.replay_identity.is_empty()
            || self.boot_id_sha256 == [0; 32]
            || self.request_id_replay_sha256 == [0; 32]
            || self.nonce_replay_sha256 == [0; 32]
            || self.exact_request_sha256 == [0; 32]
            || self.request_envelope_sha256 == [0; 32]
            || self.requester_key_authorization_sha256 == [0; 32]
            || self.accepted_at_unix_ms == 0
            || self.deadline_boottime_ns == 0
        {
            return Err(ControllerV12Error::Invalid(
                "request v11 binding is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowSelectionV12 {
    FullWorkflow,
    Build,
    UnitNoBuild,
    IntegrationNoBuild,
    E2eNoBuild,
    AttestationNoBuild,
}

impl WorkflowSelectionV12 {
    pub fn selected_lane(self) -> Option<LogicalLane> {
        match self {
            Self::FullWorkflow => None,
            Self::Build => Some(LogicalLane::Build),
            Self::UnitNoBuild => Some(LogicalLane::Unit),
            Self::IntegrationNoBuild => Some(LogicalLane::Integration),
            Self::E2eNoBuild => Some(LogicalLane::E2e),
            Self::AttestationNoBuild => Some(LogicalLane::Attestation),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcceptanceStateV12 {
    Accepted,
    Executing,
    Terminal,
    Finalized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceRecordV12 {
    pub protocol: String,
    pub state: AcceptanceStateV12,
    pub request: RequestBindingV11,
    pub workflow_id: String,
    pub selection: WorkflowSelectionV12,
    pub exact_request_base64url: String,
    pub exact_preallocation_frame_base64url: String,
    pub request_admission_sha256: Digest,
    pub controller_configuration_sha256: Digest,
    pub configuration_generation_sha256: Digest,
    pub executor_invocation_sha256: Option<Digest>,
    pub terminal_evidence_sha256: Option<Digest>,
    pub exact_receipt_sha256: Option<Digest>,
    pub record_sha256: Digest,
}

impl AcceptanceRecordV12 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        if self.protocol != CONTROLLER_RUNTIME_PROTOCOL_V12
            || self.workflow_id.is_empty()
            || self.exact_request_base64url.is_empty()
            || self.exact_preallocation_frame_base64url.is_empty()
            || self.request_admission_sha256 == [0; 32]
            || self.controller_configuration_sha256 == [0; 32]
            || self.configuration_generation_sha256 == [0; 32]
            || self.record_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Invalid(
                "controller acceptance record is incomplete",
            ));
        }
        match self.state {
            AcceptanceStateV12::Accepted => {
                if self.executor_invocation_sha256.is_some()
                    || self.terminal_evidence_sha256.is_some()
                    || self.exact_receipt_sha256.is_some()
                {
                    return Err(ControllerV12Error::Rejected(
                        "ACCEPTED record contains later-stage evidence",
                    ));
                }
            }
            AcceptanceStateV12::Executing => {
                if self.executor_invocation_sha256.is_none()
                    || self.terminal_evidence_sha256.is_some()
                    || self.exact_receipt_sha256.is_some()
                {
                    return Err(ControllerV12Error::Rejected(
                        "EXECUTING record has an invalid stage projection",
                    ));
                }
            }
            AcceptanceStateV12::Terminal => {
                if self.executor_invocation_sha256.is_none()
                    || self.terminal_evidence_sha256.is_none()
                    || self.exact_receipt_sha256.is_some()
                {
                    return Err(ControllerV12Error::Rejected(
                        "TERMINAL record has an invalid stage projection",
                    ));
                }
            }
            AcceptanceStateV12::Finalized => {
                if self.executor_invocation_sha256.is_none()
                    || self.terminal_evidence_sha256.is_none()
                    || self.exact_receipt_sha256.is_none()
                {
                    return Err(ControllerV12Error::Rejected(
                        "FINALIZED record lacks exact terminal evidence or receipt",
                    ));
                }
            }
        }
        let mut projection = self.clone();
        projection.record_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&projection).map_err(|_| {
            ControllerV12Error::Invalid(
                "controller acceptance record cannot be serialized",
            )
        })?;
        if sha256(&canonical) != self.record_sha256 {
            return Err(ControllerV12Error::Rejected(
                "controller acceptance record digest is not canonical",
            ));
        }
        Ok(())
    }

    pub fn seal(mut self) -> Result<Self> {
        self.record_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&self).map_err(|_| {
            ControllerV12Error::Invalid(
                "controller acceptance record cannot be serialized",
            )
        })?;
        self.record_sha256 = sha256(&canonical);
        self.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorFdLayoutV12 {
    pub invocation_payload_fd_index: u8,
    pub source_input_fd_index: u8,
    pub lane_proxy_fd_index: u8,
    pub total_fd_count: u8,
}

impl ExecutorFdLayoutV12 {
    pub fn canonical() -> Self {
        Self {
            invocation_payload_fd_index:
                EXECUTOR_INVOCATION_PAYLOAD_FD_INDEX_V12,
            source_input_fd_index: EXECUTOR_SOURCE_INPUT_FD_INDEX_V12,
            lane_proxy_fd_index: EXECUTOR_LANE_PROXY_FD_INDEX_V12,
            total_fd_count: EXECUTOR_INVOCATION_FD_COUNT_V12,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::canonical() {
            return Err(ControllerV12Error::Rejected(
                "executor descriptor layout is not the fixed v12 SCM_RIGHTS layout",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorLaneProxyBindingV12 {
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub peer_identity_sha256: Digest,
    pub capability_sha256: Digest,
}

impl ExecutorLaneProxyBindingV12 {
    pub fn validate(&self) -> Result<()> {
        if self.peer_uid == 0
            || self.peer_pid == 0
            || self.peer_identity_sha256 == [0; 32]
            || self.capability_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "lane proxy binding is absent, privileged, or incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorManifestTrustKeyV12 {
    pub key_id: String,
    pub public_key: [u8; 32],
}

impl ExecutorManifestTrustKeyV12 {
    pub fn validate(&self) -> Result<()> {
        if self.key_id.is_empty()
            || self.key_id.len() > 128
            || self.public_key == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "executor manifest trust key is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControllerWorkflowInvocationV12 {
    pub protocol: String,
    pub invocation_id: String,
    pub workflow_id: String,
    pub selection: WorkflowSelectionV12,
    pub request: RequestBindingV11,
    pub request_v11: Value,
    pub exact_request_base64url: String,
    pub exact_preallocation_frame_base64url: String,
    pub request_admission_sha256: Digest,
    pub acceptance_record_sha256: Digest,
    pub controller_configuration_sha256: Digest,
    pub configuration_generation_sha256: Digest,
    pub workflow_manifest_sha256: Digest,
    pub deadline_profile_sha256: Digest,
    pub source_ingress_descriptor_sha256: Digest,
    pub source_publication_sha256: Digest,
    pub source_cas_root: String,
    pub artifact_cas_root: String,
    pub oci_cas_root: String,
    pub logical_plan: Value,
    pub source_manifest: Value,
    pub source_publication_control: Value,
    pub artifact_publication_control: Value,
    pub fd_layout: ExecutorFdLayoutV12,
    pub lane_proxy: ExecutorLaneProxyBindingV12,
    pub manifest_trust_keys: Vec<ExecutorManifestTrustKeyV12>,
    pub readiness_fixture: Value,
    pub readiness_trust_key: ExecutorManifestTrustKeyV12,
    pub readiness_deadline_boottime_ns: u64,
    pub execution_deadline_boottime_ns: u64,
    pub cleanup_deadline_boottime_ns: u64,
    pub receipt_deadline_boottime_ns: u64,
    pub logical_lane_count: u8,
    pub host_docker_socket_exposed: bool,
    pub repository_body_docker_authority: bool,
    pub integration_endpoints_only: bool,
    pub e2e_endpoints_only: bool,
    pub invocation_sha256: Digest,
}

impl ControllerWorkflowInvocationV12 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.fd_layout.validate()?;
        self.lane_proxy.validate()?;
        self.readiness_trust_key.validate()?;
        let mut manifest_key_ids = BTreeSet::new();
        if self.manifest_trust_keys.is_empty()
            || self.manifest_trust_keys.len() > 32
            || self.manifest_trust_keys.iter().any(|key| {
                key.validate().is_err()
                    || !manifest_key_ids.insert(key.key_id.as_str())
            })
        {
            return Err(ControllerV12Error::Rejected(
                "executor manifest trust set is empty, duplicated, or invalid",
            ));
        }
        if self.protocol != CONTROLLER_EXECUTOR_PROTOCOL_V12
            || self.invocation_id.is_empty()
            || self.workflow_id.is_empty()
            || self.exact_request_base64url.is_empty()
            || self.exact_preallocation_frame_base64url.is_empty()
            || self.request_admission_sha256 == [0; 32]
            || self.acceptance_record_sha256 == [0; 32]
            || self.controller_configuration_sha256 == [0; 32]
            || self.configuration_generation_sha256 == [0; 32]
            || self.workflow_manifest_sha256 == [0; 32]
            || self.deadline_profile_sha256 == [0; 32]
            || self.source_ingress_descriptor_sha256 == [0; 32]
            || self.source_publication_sha256 == [0; 32]
            || self.source_cas_root.is_empty()
            || self.artifact_cas_root.is_empty()
            || self.oci_cas_root.is_empty()
            || !self.logical_plan.is_object()
            || !self.source_manifest.is_object()
            || !self.source_publication_control.is_object()
            || !self.artifact_publication_control.is_object()
            || !self.readiness_fixture.is_object()
            || self.readiness_deadline_boottime_ns == 0
            || self.readiness_deadline_boottime_ns
                > self.execution_deadline_boottime_ns
            || self.execution_deadline_boottime_ns
                != self.request.deadline_boottime_ns
            || self.cleanup_deadline_boottime_ns
                <= self.execution_deadline_boottime_ns
            || self.receipt_deadline_boottime_ns
                <= self.cleanup_deadline_boottime_ns
            || self.logical_lane_count != LogicalLane::ORDERED.len() as u8
            || self.host_docker_socket_exposed
            || self.repository_body_docker_authority
            || !self.integration_endpoints_only
            || !self.e2e_endpoints_only
            || self.invocation_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "controller workflow invocation violates the v12 trust boundary",
            ));
        }
        let mut projection = self.clone();
        projection.invocation_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&projection).map_err(|_| {
            ControllerV12Error::Invalid(
                "controller workflow invocation cannot be serialized",
            )
        })?;
        if sha256(&canonical) != self.invocation_sha256 {
            return Err(ControllerV12Error::Rejected(
                "controller workflow invocation digest is not canonical",
            ));
        }
        Ok(())
    }

    pub fn seal(mut self) -> Result<Self> {
        self.invocation_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&self).map_err(|_| {
            ControllerV12Error::Invalid(
                "controller workflow invocation cannot be serialized",
            )
        })?;
        self.invocation_sha256 = sha256(&canonical);
        self.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorTerminalEvidenceV12 {
    pub protocol: String,
    pub invocation_sha256: Digest,
    pub request_sha256: Digest,
    pub terminal_evidence_root_sha256: Digest,
    pub terminal_state_root_sha256: Digest,
    pub execution_result_sha256: Digest,
    pub source: SourceSeal,
    pub artifacts: Option<ArtifactSeal>,
    pub lanes: Vec<LaneEvidence>,
    pub verdict: TerminalVerdict,
    pub failure_code: Option<String>,
    pub executor_exact_evidence_base64url: String,
    pub executor_exact_evidence_sha256: Digest,
    pub completed_at_boottime_ns: u64,
    pub evidence_sha256: Digest,
}

impl ExecutorTerminalEvidenceV12 {
    pub fn validate_for(
        &self,
        invocation: &ControllerWorkflowInvocationV12,
    ) -> Result<()> {
        self.source.validate()?;
        if self.protocol != CONTROLLER_EXECUTOR_PROTOCOL_V12
            || self.invocation_sha256 != invocation.invocation_sha256
            || self.request_sha256 != invocation.request.exact_request_sha256
            || self.terminal_evidence_root_sha256 == [0; 32]
            || self.terminal_state_root_sha256 == [0; 32]
            || self.execution_result_sha256 == [0; 32]
            || self.executor_exact_evidence_base64url.is_empty()
            || self.executor_exact_evidence_sha256 == [0; 32]
            || self.completed_at_boottime_ns == 0
            || self.completed_at_boottime_ns
                > invocation.cleanup_deadline_boottime_ns
            || self.evidence_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "executor evidence is incomplete or not invocation-bound",
            ));
        }
        let expected_lanes: Vec<LogicalLane> = match invocation.selection {
            WorkflowSelectionV12::FullWorkflow => {
                LogicalLane::ORDERED.to_vec()
            }
            selection => vec![selection.selected_lane().ok_or(
                ControllerV12Error::Rejected(
                    "fixed workflow selection has no logical lane",
                ),
            )?],
        };
        let lanes_match_verdict = if self.verdict == TerminalVerdict::Pass {
            self.lanes
                .iter()
                .map(|lane| lane.lane)
                .eq(expected_lanes.iter().copied())
        } else {
            self.lanes
                .iter()
                .map(|lane| lane.lane)
                .eq(expected_lanes.iter().copied().take(self.lanes.len()))
        };
        if self.lanes.len() > expected_lanes.len()
            || !lanes_match_verdict
            || (self.verdict == TerminalVerdict::Pass
                && (self.lanes.len() != expected_lanes.len()
                    || self.lanes.iter().any(|lane| lane.exit_code != 0)
                    || self.artifacts.is_none()
                    || self.failure_code.is_some()))
            || (self.verdict != TerminalVerdict::Pass
                && self.failure_code.is_none())
        {
            return Err(ControllerV12Error::Rejected(
                "executor terminal verdict disagrees with ordered lane evidence",
            ));
        }
        if let Some(artifacts) = &self.artifacts {
            artifacts.validate_for_source(&self.source)?;
        }
        let mut projection = self.clone();
        projection.evidence_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&projection).map_err(|_| {
            ControllerV12Error::Invalid(
                "executor terminal evidence cannot be serialized",
            )
        })?;
        if sha256(&canonical) != self.evidence_sha256 {
            return Err(ControllerV12Error::Rejected(
                "executor terminal evidence digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleCleanupRequestV12 {
    pub protocol: String,
    pub operation: String,
    pub invocation_sha256: Digest,
    pub request_sha256: Digest,
    pub plan_id: Digest,
    pub configuration_generation_sha256: Digest,
    pub executor_evidence_sha256: Option<Digest>,
    pub reason_code: String,
    pub boot_id_sha256: Digest,
    pub cleanup_deadline_boottime_ns: u64,
    pub idempotency_key_sha256: Digest,
    pub controller_signer_spki_sha256: Digest,
    pub controller_signer_public_key_spki_der: Vec<u8>,
    pub controller_signature: Vec<u8>,
    pub request_sha256_canonical: Digest,
}

impl LifecycleCleanupRequestV12 {
    pub fn validate(&self) -> Result<()> {
        if self.protocol != CONTROLLER_LIFECYCLE_PROTOCOL_V12
            || self.operation != "DESTROY_AND_RECONCILE"
            || self.invocation_sha256 == [0; 32]
            || self.request_sha256 == [0; 32]
            || self.plan_id == [0; 32]
            || self.configuration_generation_sha256 == [0; 32]
            || self.executor_evidence_sha256 == Some([0; 32])
            || self.reason_code.is_empty()
            || self.boot_id_sha256 == [0; 32]
            || self.cleanup_deadline_boottime_ns == 0
            || self.idempotency_key_sha256 == [0; 32]
            || self.controller_signer_spki_sha256 == [0; 32]
            || self.controller_signer_public_key_spki_der.is_empty()
            || self.controller_signer_public_key_spki_der.len() > 1024
            || self.controller_signature.len() != 64
            || self.request_sha256_canonical == [0; 32]
        {
            return Err(ControllerV12Error::Invalid(
                "lifecycle cleanup request is incomplete",
            ));
        }
        let mut projection = self.clone();
        projection.request_sha256_canonical = [0; 32];
        let canonical = serde_json::to_vec(&projection).map_err(|_| {
            ControllerV12Error::Invalid(
                "lifecycle cleanup request cannot be serialized",
            )
        })?;
        if sha256(&canonical) != self.request_sha256_canonical {
            return Err(ControllerV12Error::Rejected(
                "lifecycle cleanup request digest is not canonical",
            ));
        }
        if sha256(&self.controller_signer_public_key_spki_der)
            != self.controller_signer_spki_sha256
        {
            return Err(ControllerV12Error::Rejected(
                "lifecycle cleanup controller SPKI digest is invalid",
            ));
        }
        let verifying_key = VerifyingKey::from_public_key_der(
            &self.controller_signer_public_key_spki_der,
        )
        .map_err(|_| {
            ControllerV12Error::Rejected(
                "lifecycle cleanup controller public key is invalid",
            )
        })?;
        let signature: [u8; 64] = self
            .controller_signature
            .as_slice()
            .try_into()
            .map_err(|_| {
                ControllerV12Error::Rejected(
                    "lifecycle cleanup controller signature length is invalid",
                )
            })?;
        let mut signature_projection = self.clone();
        signature_projection.controller_signature.clear();
        signature_projection.request_sha256_canonical = [0; 32];
        let projection =
            serde_json::to_vec(&signature_projection).map_err(|_| {
                ControllerV12Error::Invalid(
                    "lifecycle cleanup signature projection cannot be serialized",
                )
            })?;
        verifying_key
            .verify(
                &[
                    b"serverware/controller-lifecycle-cleanup-authority/v12\0"
                        .as_slice(),
                    projection.as_slice(),
                ]
                .concat(),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| {
                ControllerV12Error::Rejected(
                    "lifecycle cleanup controller signature is invalid",
                )
            })?;
        Ok(())
    }

    pub fn seal(
        mut self,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let public_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ControllerV12Error::Invalid(
                    "lifecycle cleanup controller public key cannot be encoded",
                )
            })?;
        self.controller_signer_public_key_spki_der =
            public_der.as_bytes().to_vec();
        self.controller_signer_spki_sha256 =
            sha256(&self.controller_signer_public_key_spki_der);
        self.controller_signature.clear();
        self.request_sha256_canonical = [0; 32];
        let signature_projection =
            serde_json::to_vec(&self).map_err(|_| {
                ControllerV12Error::Invalid(
                    "lifecycle cleanup request cannot be serialized",
                )
            })?;
        self.controller_signature = signing_key
            .sign(
                &[
                    b"serverware/controller-lifecycle-cleanup-authority/v12\0"
                        .as_slice(),
                    signature_projection.as_slice(),
                ]
                .concat(),
            )
            .to_bytes()
            .to_vec();
        let canonical = serde_json::to_vec(&self).map_err(|_| {
            ControllerV12Error::Invalid(
                "lifecycle cleanup request cannot be serialized",
            )
        })?;
        self.request_sha256_canonical = sha256(&canonical);
        self.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleCleanupResponseV12 {
    pub protocol: String,
    pub operation: String,
    pub disposition: String,
    pub request_sha256_canonical: Digest,
    pub destruction: DestructionEvidence,
    pub exact_plan_terminal_aggregate: Vec<u8>,
    pub plan_terminal_aggregate_sha256: Digest,
    pub exact_privileged_response: Vec<u8>,
    pub privileged_response_sha256: Digest,
    pub response_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanScopedTerminalAggregateV12 {
    protocol: String,
    plan_id: Digest,
    request_sha256_canonical: Digest,
    idempotency_key_sha256: Digest,
    observed_terminal_sha256: Digest,
    exact_receipt_sha256s: Vec<Digest>,
    exact_terminal_receipts: Vec<Vec<u8>>,
    root_signer_spki_sha256: Digest,
    root_signer_public_key_spki_der: Vec<u8>,
    root_signature: Vec<u8>,
    aggregate_sha256: Digest,
}

impl LifecycleCleanupResponseV12 {
    pub fn validate_for(
        &self,
        request: &LifecycleCleanupRequestV12,
    ) -> Result<()> {
        if self.protocol != CONTROLLER_LIFECYCLE_PROTOCOL_V12
            || self.operation != "DESTROY_AND_RECONCILE"
            || self.disposition != "DESTROYED"
            || self.request_sha256_canonical
                != request.request_sha256_canonical
            || self.exact_plan_terminal_aggregate.is_empty()
            || self.exact_plan_terminal_aggregate.len()
                > 4 * 1024 * 1024
            || sha256(&self.exact_plan_terminal_aggregate)
                != self.plan_terminal_aggregate_sha256
            || self.plan_terminal_aggregate_sha256 == [0; 32]
            || self.exact_privileged_response.is_empty()
            || self.exact_privileged_response.len()
                > 4 * 1024 * 1024
            || sha256(&self.exact_privileged_response)
                != self.privileged_response_sha256
            || self.privileged_response_sha256 == [0; 32]
            || self.response_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "lifecycle cleanup response is not exact-request-bound",
            ));
        }
        self.destruction
            .validate(request.request_sha256, true)?;
        let aggregate: PlanScopedTerminalAggregateV12 =
            serde_json::from_slice(
                &self.exact_plan_terminal_aggregate,
            )
            .map_err(|_| {
                ControllerV12Error::Invalid(
                    "plan terminal aggregate is not valid JSON",
                )
            })?;
        if serde_json::to_vec(&aggregate).map_err(|_| {
            ControllerV12Error::Invalid(
                "plan terminal aggregate cannot be serialized",
            )
        })? != self.exact_plan_terminal_aggregate
            || aggregate.protocol
                != "serverware/private-dind-plan-aggregate-terminal/v12"
            || aggregate.plan_id != request.plan_id
            || aggregate.request_sha256_canonical
                != request.request_sha256_canonical
            || aggregate.idempotency_key_sha256
                != request.idempotency_key_sha256
            || aggregate.observed_terminal_sha256 == [0; 32]
            || aggregate.exact_receipt_sha256s.len()
                != aggregate.exact_terminal_receipts.len()
            || aggregate
                .exact_receipt_sha256s
                .iter()
                .zip(&aggregate.exact_terminal_receipts)
                .any(|(digest, exact)| {
                    exact.is_empty() || sha256(exact) != *digest
                })
            || aggregate.root_signer_spki_sha256 == [0; 32]
            || aggregate.root_signer_public_key_spki_der.is_empty()
            || aggregate.root_signature.len() != 64
            || aggregate.aggregate_sha256
                != self.destruction.cleanup_terminal_sha256
        {
            return Err(ControllerV12Error::Rejected(
                "plan terminal aggregate lost exact cleanup binding",
            ));
        }
        let mut aggregate_projection = aggregate.clone();
        aggregate_projection.aggregate_sha256 = [0; 32];
        if sha256(
            &serde_json::to_vec(&aggregate_projection).map_err(|_| {
                ControllerV12Error::Invalid(
                    "plan terminal aggregate cannot be serialized",
                )
            })?,
        ) != aggregate.aggregate_sha256
        {
            return Err(ControllerV12Error::Rejected(
                "plan terminal aggregate digest is not canonical",
            ));
        }
        let mut projection = self.clone();
        projection.response_sha256 = [0; 32];
        let canonical = serde_json::to_vec(&projection).map_err(|_| {
            ControllerV12Error::Invalid(
                "lifecycle cleanup response cannot be serialized",
            )
        })?;
        if sha256(&canonical) != self.response_sha256 {
            return Err(ControllerV12Error::Rejected(
                "lifecycle cleanup response digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSeal {
    pub snapshot_id: String,
    pub manifest_sha256: Digest,
    pub canonical_bundle_sha256: Digest,
    pub source_root_sha256: Digest,
    pub immutable_object_sha256: Digest,
}

impl SourceSeal {
    pub fn validate(&self) -> Result<()> {
        if self.snapshot_id.is_empty()
            || self.manifest_sha256 == [0; 32]
            || self.canonical_bundle_sha256 == [0; 32]
            || self.source_root_sha256 == [0; 32]
            || self.immutable_object_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Invalid("source seal is incomplete"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactSeal {
    pub artifact_set_id: String,
    pub source_manifest_sha256: Digest,
    pub filesystem_manifest_sha256: Digest,
    pub oci_manifest_sha256: Digest,
    pub exact_oci_digests: BTreeSet<String>,
    pub immutable_object_sha256: Digest,
}

impl ArtifactSeal {
    pub fn validate_for_source(&self, source: &SourceSeal) -> Result<()> {
        if self.artifact_set_id.is_empty()
            || self.source_manifest_sha256 != source.manifest_sha256
            || self.filesystem_manifest_sha256 == [0; 32]
            || self.oci_manifest_sha256 == [0; 32]
            || self.exact_oci_digests.is_empty()
            || self.exact_oci_digests.iter().any(|value| {
                !value.starts_with("sha256:")
                    || value.len() != "sha256:".len() + 64
                    || !value["sha256:".len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            || self.immutable_object_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "artifact seal is not bound to the exact source and OCI set",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneRequest {
    pub lane: LogicalLane,
    pub phase: LanePhase,
    pub request_binding_sha256: Digest,
    pub source_seal: SourceSeal,
    pub artifact_seal: Option<ArtifactSeal>,
    pub runner_image_digest: String,
    pub plan_manifest_sha256: Digest,
    pub deadline_boottime_ns: u64,
    pub service_endpoint_set_sha256: Option<Digest>,
}

impl LaneRequest {
    pub fn validate(&self) -> Result<()> {
        self.source_seal.validate()?;
        if self.request_binding_sha256 == [0; 32]
            || self.runner_image_digest.len() != "sha256:".len() + 64
            || !self.runner_image_digest.starts_with("sha256:")
            || self.plan_manifest_sha256 == [0; 32]
            || self.deadline_boottime_ns == 0
        {
            return Err(ControllerV12Error::Invalid(
                "logical lane request is incomplete",
            ));
        }
        match self.lane {
            LogicalLane::Build if self.artifact_seal.is_some() => {
                return Err(ControllerV12Error::Rejected(
                    "build lane cannot consume an existing artifact seal",
                ));
            }
            LogicalLane::Build => {}
            _ => {
                let artifact = self.artifact_seal.as_ref().ok_or(
                    ControllerV12Error::Rejected(
                        "no-build lane requires the committed build artifact seal",
                    ),
                )?;
                artifact.validate_for_source(&self.source_seal)?;
            }
        }
        if self.lane.requires_service_endpoints()
            != self.service_endpoint_set_sha256.is_some()
        {
            return Err(ControllerV12Error::Rejected(
                "service endpoints are present outside integration/e2e or absent within them",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneEvidence {
    pub lane: LogicalLane,
    pub phase: LanePhase,
    pub request_sha256: Digest,
    pub runner_identity_sha256: Digest,
    pub docker_transcript_sha256: Digest,
    pub runtime_evidence_sha256: Digest,
    pub cleanup_intent_sha256: Digest,
    pub terminal_sha256: Digest,
    pub exit_code: i32,
    pub artifact_seal: Option<ArtifactSeal>,
}

impl LaneEvidence {
    pub fn validate_for(&self, request: &LaneRequest) -> Result<()> {
        if self.lane != request.lane
            || self.phase != request.phase
            || self.request_sha256 == [0; 32]
            || self.runner_identity_sha256 == [0; 32]
            || self.docker_transcript_sha256 == [0; 32]
            || self.runtime_evidence_sha256 == [0; 32]
            || self.cleanup_intent_sha256 == [0; 32]
            || self.terminal_sha256 == [0; 32]
        {
            return Err(ControllerV12Error::Rejected(
                "lane evidence lost its exact request or runtime binding",
            ));
        }
        if request.lane == LogicalLane::Build {
            let artifact = self.artifact_seal.as_ref().ok_or(
                ControllerV12Error::Rejected(
                    "successful build evidence lacks an artifact seal",
                ),
            )?;
            artifact.validate_for_source(&request.source_seal)?;
        } else if self.artifact_seal.is_some() {
            return Err(ControllerV12Error::Rejected(
                "no-build lane attempted to replace the build artifact seal",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestructionEvidence {
    pub request_binding_sha256: Digest,
    pub lane_generation_sha256: Digest,
    pub acceptance_revoked_sha256: Digest,
    pub cgroup_kill_sha256: Digest,
    pub cgroup_empty_sha256: Digest,
    pub dind_destroyed_sha256: Digest,
    pub network_destroyed_sha256: Digest,
    pub mounts_destroyed_sha256: Digest,
    pub sockets_destroyed_sha256: Digest,
    pub cleanup_terminal_sha256: Digest,
}

impl DestructionEvidence {
    pub fn is_complete(&self) -> bool {
        let values = [
            self.lane_generation_sha256,
            self.acceptance_revoked_sha256,
            self.cgroup_kill_sha256,
            self.cgroup_empty_sha256,
            self.dind_destroyed_sha256,
            self.network_destroyed_sha256,
            self.mounts_destroyed_sha256,
            self.sockets_destroyed_sha256,
            self.cleanup_terminal_sha256,
        ];
        values.iter().all(|value| *value != [0; 32])
    }

    pub fn validate(
        &self,
        request_binding_sha256: Digest,
        require_complete: bool,
    ) -> Result<()> {
        if self.request_binding_sha256 != request_binding_sha256
            || self.cleanup_terminal_sha256 == [0; 32]
            || (require_complete && !self.is_complete())
        {
            return Err(ControllerV12Error::Rejected(
                "destruction evidence is incomplete or belongs to another request",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptEvidenceV12 {
    pub request: RequestBindingV11,
    pub source: SourceSeal,
    pub artifacts: Option<ArtifactSeal>,
    pub lanes: Vec<LaneEvidence>,
    pub destruction: DestructionEvidence,
    pub verdict: TerminalVerdict,
    pub failure_code: Option<String>,
    pub evidence_root_sha256: Digest,
}

impl ReceiptEvidenceV12 {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.source.validate()?;
        self.destruction
            .validate(
                self.request.exact_request_sha256,
                self.verdict == TerminalVerdict::Pass,
            )?;
        if self.lanes.len() > LogicalLane::ORDERED.len() {
            return Err(ControllerV12Error::Rejected(
                "receipt contains too many logical lane records",
            ));
        }
        for (index, lane) in self.lanes.iter().enumerate() {
            if lane.lane != LogicalLane::ORDERED[index]
                || lane.phase != LanePhase::Body
            {
                return Err(ControllerV12Error::Rejected(
                    "receipt lane evidence is not the exact ordered body sequence",
                ));
            }
        }
        if self.verdict == TerminalVerdict::Pass
            && (self.lanes.len() != LogicalLane::ORDERED.len()
                || self.lanes.iter().any(|lane| lane.exit_code != 0)
                || self.artifacts.is_none()
                || !self.destruction.is_complete()
                || self.failure_code.is_some())
        {
            return Err(ControllerV12Error::Rejected(
                "PASS requires all five successful lanes, artifacts, and no failure",
            ));
        }
        if self.verdict != TerminalVerdict::Pass && self.failure_code.is_none() {
            return Err(ControllerV12Error::Rejected(
                "non-PASS receipt requires a stable failure code",
            ));
        }
        let canonical = serde_json::to_vec(&(
            &self.request,
            &self.source,
            &self.artifacts,
            &self.lanes,
            &self.destruction,
            self.verdict,
            &self.failure_code,
        ))
        .map_err(|_| ControllerV12Error::Invalid(
            "receipt evidence cannot be serialized",
        ))?;
        if sha256(&canonical) != self.evidence_root_sha256 {
            return Err(ControllerV12Error::Rejected(
                "receipt evidence root differs from the complete evidence projection",
            ));
        }
        Ok(())
    }
}

pub trait SourceCas {
    fn seal_source(
        &self,
        request: &RequestBindingV11,
        deadline_boottime_ns: u64,
    ) -> Result<SourceSeal>;
}

pub trait LogicalLaneExecutor {
    fn execute_phase(&self, request: &LaneRequest) -> Result<LaneEvidence>;
    fn destroy(
        &self,
        request: &RequestBindingV11,
        deadline_boottime_ns: u64,
    ) -> Result<DestructionEvidence>;
}

pub trait ReceiptPipeline {
    type FinalReceipt;

    fn prepare_authenticate_log_and_finalize(
        &self,
        evidence: &ReceiptEvidenceV12,
        deadline_boottime_ns: u64,
    ) -> Result<Self::FinalReceipt>;
}

pub trait BootTimeClock {
    fn now_boottime_ns(&self) -> Result<u64>;
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxBootTimeClock;

#[cfg(target_os = "linux")]
impl BootTimeClock for LinuxBootTimeClock {
    fn now_boottime_ns(&self) -> Result<u64> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
            return Err(ControllerV12Error::Io(
                std::io::Error::last_os_error(),
            ));
        }
        if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
            return Err(ControllerV12Error::Invalid(
                "CLOCK_BOOTTIME returned an invalid value",
            ));
        }
        let seconds = u64::try_from(value.tv_sec).map_err(|_| {
            ControllerV12Error::Invalid("CLOCK_BOOTTIME seconds overflow")
        })?;
        let nanos = u64::try_from(value.tv_nsec).map_err(|_| {
            ControllerV12Error::Invalid("CLOCK_BOOTTIME nanoseconds overflow")
        })?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|total| total.checked_add(nanos))
            .ok_or(ControllerV12Error::Invalid(
                "CLOCK_BOOTTIME nanosecond value overflow",
            ))
    }
}

pub struct ControllerCoordinator<S, E, R, C> {
    source_cas: S,
    executor: E,
    receipts: R,
    clock: C,
    runner_image_digest: String,
    plan_manifest_sha256: Digest,
    cleanup_reserve_ns: u64,
    receipt_reserve_ns: u64,
}

impl<S, E, R, C> ControllerCoordinator<S, E, R, C>
where
    S: SourceCas,
    E: LogicalLaneExecutor,
    R: ReceiptPipeline,
    C: BootTimeClock,
{
    pub fn new(
        source_cas: S,
        executor: E,
        receipts: R,
        clock: C,
        runner_image_digest: String,
        plan_manifest_sha256: Digest,
        cleanup_reserve_ns: u64,
        receipt_reserve_ns: u64,
    ) -> Result<Self> {
        if !runner_image_digest.starts_with("sha256:")
            || runner_image_digest.len() != "sha256:".len() + 64
            || plan_manifest_sha256 == [0; 32]
            || cleanup_reserve_ns == 0
            || receipt_reserve_ns == 0
        {
            return Err(ControllerV12Error::Invalid(
                "controller coordinator configuration is incomplete",
            ));
        }
        Ok(Self {
            source_cas,
            executor,
            receipts,
            clock,
            runner_image_digest,
            plan_manifest_sha256,
            cleanup_reserve_ns,
            receipt_reserve_ns,
        })
    }

    pub fn execute(
        &self,
        request: RequestBindingV11,
        service_endpoint_set_sha256: Option<Digest>,
    ) -> Result<R::FinalReceipt> {
        request.validate()?;
        if self.clock.now_boottime_ns()? >= request.deadline_boottime_ns {
            return Err(ControllerV12Error::Rejected(
                "request expired before source sealing",
            ));
        }
        let source = self
            .source_cas
            .seal_source(&request, request.deadline_boottime_ns)?;
        source.validate()?;
        let mut lanes = Vec::with_capacity(LogicalLane::ORDERED.len());
        let mut artifact: Option<ArtifactSeal> = None;
        let mut terminal = TerminalVerdict::Pass;
        let mut failure_code: Option<String> = None;

        for lane in LogicalLane::ORDERED {
            if self.clock.now_boottime_ns()? >= request.deadline_boottime_ns {
                terminal = TerminalVerdict::Unknown;
                failure_code = Some(format!("LANE_{lane:?}_DEADLINE_EXPIRED"));
                break;
            }
            let endpoints = if lane.requires_service_endpoints() {
                service_endpoint_set_sha256
            } else {
                None
            };
            if lane.requires_service_endpoints() && endpoints.is_none() {
                terminal = TerminalVerdict::Rejected;
                failure_code = Some("SERVICE_ENDPOINT_SET_MISSING".to_owned());
                break;
            }

            let prepare = LaneRequest {
                lane,
                phase: LanePhase::Prepare,
                request_binding_sha256: request.exact_request_sha256,
                source_seal: source.clone(),
                artifact_seal: artifact.clone(),
                runner_image_digest: self.runner_image_digest.clone(),
                plan_manifest_sha256: self.plan_manifest_sha256,
                deadline_boottime_ns: request.deadline_boottime_ns,
                service_endpoint_set_sha256: endpoints,
            };
            prepare.validate()?;
            if let Err(error) = self.executor.execute_phase(&prepare) {
                terminal = error.verdict();
                failure_code = Some(error.code().to_owned());
                break;
            }
            if self.clock.now_boottime_ns()? >= request.deadline_boottime_ns {
                terminal = TerminalVerdict::Unknown;
                failure_code = Some(format!(
                    "LANE_{lane:?}_PREPARE_DEADLINE_EXPIRED"
                ));
                break;
            }

            let body = LaneRequest {
                phase: LanePhase::Body,
                ..prepare
            };
            let evidence = match self.executor.execute_phase(&body) {
                Ok(evidence) => evidence,
                Err(error) => {
                    terminal = error.verdict();
                    failure_code = Some(error.code().to_owned());
                    break;
                }
            };
            evidence.validate_for(&body)?;
            if evidence.exit_code != 0 {
                terminal = TerminalVerdict::Fail;
                failure_code = Some(format!("LANE_{lane:?}_FAILED"));
                lanes.push(evidence);
                break;
            }
            if lane == LogicalLane::Build {
                artifact = evidence.artifact_seal.clone();
            }
            lanes.push(evidence);
        }

        let cleanup_deadline = request
            .deadline_boottime_ns
            .checked_add(self.cleanup_reserve_ns)
            .ok_or(ControllerV12Error::Invalid(
                "cleanup deadline overflow",
            ))?;
        let destruction = match self.executor.destroy(&request, cleanup_deadline) {
            Ok(evidence) => {
                evidence.validate(request.exact_request_sha256, true)?;
                evidence
            }
            Err(error) => {
                terminal = TerminalVerdict::Unknown;
                failure_code = Some(format!("CLEANUP_UNPROVED:{}", error.code()));
                DestructionEvidence {
                    request_binding_sha256: request.exact_request_sha256,
                    lane_generation_sha256: [0; 32],
                    acceptance_revoked_sha256: [0; 32],
                    cgroup_kill_sha256: [0; 32],
                    cgroup_empty_sha256: [0; 32],
                    dind_destroyed_sha256: [0; 32],
                    network_destroyed_sha256: [0; 32],
                    mounts_destroyed_sha256: [0; 32],
                    sockets_destroyed_sha256: [0; 32],
                    cleanup_terminal_sha256: sha256(error.to_string().as_bytes()),
                }
            }
        };

        let mut evidence = ReceiptEvidenceV12 {
            request,
            source,
            artifacts: artifact,
            lanes,
            destruction,
            verdict: terminal,
            failure_code,
            evidence_root_sha256: [0; 32],
        };
        let canonical = serde_json::to_vec(&(
            &evidence.request,
            &evidence.source,
            &evidence.artifacts,
            &evidence.lanes,
            &evidence.destruction,
            evidence.verdict,
            &evidence.failure_code,
        ))
        .map_err(|_| ControllerV12Error::Invalid(
            "receipt evidence cannot be serialized",
        ))?;
        evidence.evidence_root_sha256 = sha256(&canonical);
        evidence.validate()?;
        let receipt_deadline = cleanup_deadline
            .checked_add(self.receipt_reserve_ns)
            .ok_or(ControllerV12Error::Invalid(
                "receipt deadline overflow",
            ))?;
        self.receipts
            .prepare_authenticate_log_and_finalize(&evidence, receipt_deadline)
    }
}

#[derive(Debug)]
pub enum ControllerV12Error {
    Invalid(&'static str),
    Rejected(&'static str),
    Failed(&'static str),
    Unknown(&'static str),
    Io(std::io::Error),
}

impl ControllerV12Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "INVALID",
            Self::Rejected(_) => "REJECTED",
            Self::Failed(_) => "FAILED",
            Self::Unknown(_) => "UNKNOWN",
            Self::Io(_) => "IO_UNKNOWN",
        }
    }

    pub fn verdict(&self) -> TerminalVerdict {
        match self {
            Self::Invalid(_) | Self::Rejected(_) => TerminalVerdict::Rejected,
            Self::Failed(_) => TerminalVerdict::Fail,
            Self::Unknown(_) | Self::Io(_) => {
                TerminalVerdict::Unknown
            }
        }
    }
}

impl fmt::Display for ControllerV12Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid: {message}"),
            Self::Rejected(message) => write!(formatter, "rejected: {message}"),
            Self::Failed(message) => write!(formatter, "failed: {message}"),
            Self::Unknown(message) => write!(formatter, "unknown: {message}"),
            Self::Io(error) => write!(formatter, "I/O failed: {error}"),
        }
    }
}

impl std::error::Error for ControllerV12Error {}

impl From<std::io::Error> for ControllerV12Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, ControllerV12Error>;
