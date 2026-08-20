//! Closed wire and durable-state contract for policy-custody settlement.
//!
//! HSM and settlement-store consumption are independently durable and signed.
//! This protocol does not claim distributed atomicity between those endpoints.

use super::boottime::{BoottimeDeadline, BoottimeDomain};
use super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub(super) const POLICY_CUSTODY_PROTOCOL_VERSION: &str =
    "serverware.policyCustodyProtocol/v3";
pub(super) const POLICY_CUSTODY_SETTLEMENT_VERSION: &str =
    "serverware.policyCustodySettlement/v3";
pub(super) const POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION: &str =
    "serverware.policyCustodyCleanupAuthorization/v3";
pub(super) const POLICY_CUSTODY_KEY_AUTHORIZATION_VERSION: &str =
    "serverware.policyCustodyCurrentKeyAuthorization/v3";
pub(super) const POLICY_CUSTODY_DURABLE_CONSUME_EVIDENCE_VERSION: &str =
    "serverware.policyCustodyIndependentDurableConsumeEvidence/v3";
pub(super) const POLICY_CUSTODY_WATCHDOG_REGISTRATION_VERSION: &str =
    "serverware.policyCustodyWatchdogRegistration/v3";
pub(super) const POLICY_CUSTODY_WATCHDOG_OWNERSHIP_VERSION: &str =
    "serverware.policyCustodyWatchdogOwnership/v3";
pub(super) const MAX_ENDPOINT_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_SETTLEMENT_CHAIN_STATES: usize = 4;
pub(super) const MAX_TRUST_ANCESTRY_STEPS: usize = 4096;

const ZERO_SHA256: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PROCESS_IDENTITY_DOMAIN: &[u8] =
    b"serverware.policyCustodyEndpointProcessIdentity/v3";
const PIDFD_STAT_IDENTITY_DOMAIN: &[u8] =
    b"serverware.policyCustodyPidfdStatIdentity/v3";
const KEY_AUTHORIZATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyCurrentKeyAuthorization/v3";
const SETTLEMENT_STATE_DOMAIN: &[u8] =
    b"serverware.policyCustodySettlementState/v3";
const SETTLEMENT_NONCE_LEDGER_DOMAIN: &[u8] =
    b"serverware.policyCustodyTransitionNonceLedger/v3";
const SETTLEMENT_TRANSITION_DOMAIN: &[u8] =
    b"serverware.policyCustodySettlementTransition/v3";
const SETTLEMENT_TRANSITION_PAYLOAD_DOMAIN: &[u8] =
    b"serverware.policyCustodySettlementTransitionPayload/v3";
const ENDPOINT_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyEndpointRequest/v3";
const ENDPOINT_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyEndpointResponse/v3";
const ENDPOINT_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyEndpointReceipt/v3";
const DURABLE_CONSUME_BINDING_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableConsumeBinding/v3";
const CLEANUP_AUTHORIZATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupAuthorization/v3";
const CLEANUP_CURSOR_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupConsumptionCursor/v3";
const WATCHDOG_REGISTRATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyWatchdogRegistration/v3";
const WATCHDOG_FD_MANIFEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyWatchdogFdManifest/v3";
const WATCHDOG_OWNERSHIP_STATE_DOMAIN: &[u8] =
    b"serverware.policyCustodyWatchdogOwnershipState/v3";
const WATCHDOG_OWNERSHIP_ENVELOPE_DOMAIN: &[u8] =
    b"serverware.policyCustodyWatchdogOwnershipEnvelope/v3";
const TRUSTED_HOST_CONSUME_HEAD_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostConsumeHead/v3";
const TRUSTED_HOST_CURRENT_HEAD_ATTESTATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostCurrentHeadAttestation/v3";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtocolError {
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl ProtocolError {
    pub(super) fn new(
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

pub(super) fn digest_is_zero(digest: &Sha256Digest) -> bool {
    digest.as_str() == ZERO_SHA256
}

pub(super) fn require_nonzero_digest(
    field: &'static str,
    digest: &Sha256Digest,
) -> Result<(), ProtocolError> {
    if digest_is_zero(digest) {
        return Err(ProtocolError::new(
            "zero_digest",
            format!("{field} must not be the all-zero SHA-256 digest"),
        ));
    }
    Ok(())
}

pub(super) fn pidfd_stat_identity_sha256(
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Sha256Digest {
    hash_domain_frames(
        PIDFD_STAT_IDENTITY_DOMAIN,
        &[
            &device.to_be_bytes(),
            &inode.to_be_bytes(),
            &mode.to_be_bytes(),
            &uid.to_be_bytes(),
            &gid.to_be_bytes(),
        ],
    )
}

fn require_nonzero_digests(
    fields: &[(&'static str, &Sha256Digest)],
) -> Result<(), ProtocolError> {
    for (field, digest) in fields {
        require_nonzero_digest(field, digest)?;
    }
    Ok(())
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProtocolBoottimeDomain {
    authority_boot_id: [u8; 16],
    time_namespace_device: u64,
    time_namespace_inode: u64,
}

impl ProtocolBoottimeDomain {
    pub(super) fn from_runtime(domain: BoottimeDomain) -> Self {
        let time_namespace = domain.time_namespace();
        Self {
            authority_boot_id: domain.authority_boot_id(),
            time_namespace_device: time_namespace.device(),
            time_namespace_inode: time_namespace.inode(),
        }
    }

    pub(super) fn to_runtime(
        &self,
    ) -> Result<BoottimeDomain, ProtocolError> {
        BoottimeDomain::from_expected(
            self.authority_boot_id,
            self.time_namespace_device,
            self.time_namespace_inode,
        )
        .map_err(|error| {
            ProtocolError::new(
                "invalid_boottime_domain",
                error.to_string(),
            )
        })
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProtocolBoottimeDeadline {
    domain: ProtocolBoottimeDomain,
    absolute_boottime_nanos: u64,
}

impl ProtocolBoottimeDeadline {
    pub(super) fn from_runtime(deadline: BoottimeDeadline) -> Self {
        Self {
            domain: ProtocolBoottimeDomain::from_runtime(
                deadline.domain(),
            ),
            absolute_boottime_nanos: deadline.absolute_nanos(),
        }
    }

    pub(super) fn domain(&self) -> &ProtocolBoottimeDomain {
        &self.domain
    }

    pub(super) fn absolute_boottime_nanos(&self) -> u64 {
        self.absolute_boottime_nanos
    }

    pub(super) fn to_runtime(
        &self,
    ) -> Result<BoottimeDeadline, ProtocolError> {
        BoottimeDeadline::from_absolute_in_expected_domain(
            self.domain.to_runtime()?,
            self.absolute_boottime_nanos,
        )
        .map_err(|error| {
            ProtocolError::new(
                "invalid_boottime_deadline",
                error.to_string(),
            )
        })
    }
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
#[serde(rename_all = "camelCase")]
pub(super) enum PolicyCustodyOperation {
    RecoverCurrentState,
    VerifyCheckpointSuccessor,
    VerifyCurrentCheckpointHead,
    VerifyObservationEvidence,
    PrepareGenerationPublication,
    CommitGenerationPublication,
    AbortGenerationPublication,
    BeginIngress,
    ReserveSpoolAppend,
    AppendSpoolEvent,
    CompactSpool,
    CommitRequest,
    AppendActiveEffectBarrier,
    CommitActiveEffect,
    ReconcileActiveEffect,
    AppendTerminal,
    ConsumeAndPublishActivation,
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
pub(super) enum PolicyCustodyEndpointRole {
    SignerHsm,
    SettlementStore,
    FenceAuthority,
    CleanupWatchdog,
    CgroupExecutor,
    TerminationLedger,
}

impl PolicyCustodyEndpointRole {
    pub(super) fn receipt_signature_domain(self) -> &'static [u8] {
        match self {
            Self::SignerHsm => {
                b"serverware.policyCustodySignerHsmReceipt/v3"
            }
            Self::SettlementStore => {
                b"serverware.policyCustodySettlementStoreReceipt/v3"
            }
            Self::FenceAuthority => {
                b"serverware.policyCustodyFenceAuthorityReceipt/v3"
            }
            Self::CleanupWatchdog => {
                b"serverware.policyCustodyCleanupWatchdogReceipt/v3"
            }
            Self::CgroupExecutor => {
                b"serverware.policyCustodyCgroupExecutorReceipt/v3"
            }
            Self::TerminationLedger => {
                b"serverware.policyCustodyTerminationLedgerReceipt/v3"
            }
        }
    }

    pub(super) fn response_signature_domain(self) -> &'static [u8] {
        match self {
            Self::SignerHsm => {
                b"serverware.policyCustodySignerHsmResponse/v3"
            }
            Self::SettlementStore => {
                b"serverware.policyCustodySettlementStoreResponse/v3"
            }
            Self::FenceAuthority => {
                b"serverware.policyCustodyFenceAuthorityResponse/v3"
            }
            Self::CleanupWatchdog => {
                b"serverware.policyCustodyCleanupWatchdogResponse/v3"
            }
            Self::CgroupExecutor => {
                b"serverware.policyCustodyCgroupExecutorResponse/v3"
            }
            Self::TerminationLedger => {
                b"serverware.policyCustodyTerminationLedgerResponse/v3"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CgroupIdentity {
    pub(super) canonical_path_sha256: Sha256Digest,
    pub(super) operation_name_sha256: Sha256Digest,
    pub(super) cgroup_id: u64,
}

impl CgroupIdentity {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "cgroup.canonicalPathSha256",
                &self.canonical_path_sha256,
            ),
            (
                "cgroup.operationNameSha256",
                &self.operation_name_sha256,
            ),
        ])?;
        if self.cgroup_id == 0 {
            return Err(ProtocolError::new(
                "invalid_cgroup_identity",
                "cgroup identity must contain a nonzero kernel cgroup id",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EndpointProcessIdentity {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_uid: u32,
    pub(super) endpoint_gid: u32,
    pub(super) endpoint_pid: i32,
    pub(super) endpoint_start_time_ticks: u64,
    pub(super) endpoint_pidfd_inode: u64,
    pub(super) endpoint_pidfd_stat_sha256: Sha256Digest,
    pub(super) executable_device: u64,
    pub(super) executable_inode: u64,
    pub(super) executable_length: u64,
    pub(super) executable_sha256: Sha256Digest,
    pub(super) executable_ima_sha256: Sha256Digest,
    pub(super) executable_fs_verity_sha256: Sha256Digest,
    pub(super) identity_sha256: Sha256Digest,
}

impl EndpointProcessIdentity {
    pub(super) fn computed_identity_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes = canonical_json_bytes(&(
            self.endpoint_role,
            self.endpoint_uid,
            self.endpoint_gid,
            self.endpoint_pid,
            self.endpoint_start_time_ticks,
            self.endpoint_pidfd_inode,
            &self.endpoint_pidfd_stat_sha256,
            self.executable_device,
            self.executable_inode,
            self.executable_length,
            &self.executable_sha256,
            &self.executable_ima_sha256,
            &self.executable_fs_verity_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_process_identity",
                "endpoint process identity is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            PROCESS_IDENTITY_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "process.pidfdStatSha256",
                &self.endpoint_pidfd_stat_sha256,
            ),
            ("process.executableSha256", &self.executable_sha256),
            (
                "process.executableImaSha256",
                &self.executable_ima_sha256,
            ),
            (
                "process.executableFsVeritySha256",
                &self.executable_fs_verity_sha256,
            ),
            ("process.identitySha256", &self.identity_sha256),
        ])?;
        if self.endpoint_pid <= 0
            || self.endpoint_start_time_ticks == 0
            || self.endpoint_pidfd_inode == 0
            || self.executable_device == 0
            || self.executable_inode == 0
            || self.executable_length == 0
            || self.identity_sha256 != self.computed_identity_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_process_identity",
                "endpoint process identity is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CurrentKeyRevocationStatus {
    AuthorizedAndNotRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EndpointKeyAuthorizationPayload {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) exact_endpoint_generation: u64,
    pub(super) authorized_signing_key_id: Sha256Digest,
    pub(super) authorized_signing_key_spki_sha256: Sha256Digest,
    pub(super) checkpoint_sequence: u64,
    pub(super) predecessor_checkpoint_sha256: Sha256Digest,
    pub(super) revocation_generation_high_water: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) revocation_status: CurrentKeyRevocationStatus,
    pub(super) rollback_floor_checkpoint_sequence: u64,
    pub(super) rollback_floor_endpoint_generation: u64,
    pub(super) rollback_floor_consumer_sequence: u64,
    pub(super) valid_from_boottime: ProtocolBoottimeDeadline,
    pub(super) valid_until_boottime: ProtocolBoottimeDeadline,
}

impl EndpointKeyAuthorizationPayload {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "keyAuthorization.processIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            (
                "keyAuthorization.signingKeyId",
                &self.authorized_signing_key_id,
            ),
            (
                "keyAuthorization.signingKeySpkiSha256",
                &self.authorized_signing_key_spki_sha256,
            ),
            (
                "keyAuthorization.predecessorCheckpointSha256",
                &self.predecessor_checkpoint_sha256,
            ),
            (
                "keyAuthorization.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
        ])?;
        self.valid_from_boottime.to_runtime()?;
        self.valid_until_boottime.to_runtime()?;
        if self.api_version != POLICY_CUSTODY_KEY_AUTHORIZATION_VERSION
            || self.exact_endpoint_generation == 0
            || self.checkpoint_sequence == 0
            || self.revocation_generation_high_water == 0
            || self.rollback_floor_checkpoint_sequence == 0
            || self.rollback_floor_endpoint_generation == 0
            || self.rollback_floor_consumer_sequence == 0
            || self.checkpoint_sequence
                < self.rollback_floor_checkpoint_sequence
            || self.exact_endpoint_generation
                < self.rollback_floor_endpoint_generation
            || self.valid_from_boottime.domain()
                != self.valid_until_boottime.domain()
            || self.valid_from_boottime.absolute_boottime_nanos()
                >= self.valid_until_boottime.absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "invalid_key_authorization",
                "current-key authorization checkpoint is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedEndpointKeyAuthorizationCheckpoint {
    pub(super) payload: EndpointKeyAuthorizationPayload,
    pub(super) authority_key_id: Sha256Digest,
    pub(super) authority_key_spki_sha256: Sha256Digest,
    pub(super) authority_signature_base64: String,
    pub(super) checkpoint_sha256: Sha256Digest,
}

impl SignedEndpointKeyAuthorizationCheckpoint {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.payload,
            &self.authority_key_id,
            &self.authority_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_key_authorization",
                "current-key authorization checkpoint is not canonical",
            )
        })
    }

    pub(super) fn authority_signature_preimage(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        domain_separated_signature_preimage(
            KEY_AUTHORIZATION_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_checkpoint_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            KEY_AUTHORIZATION_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.authority_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.payload.validate_shape()?;
        require_nonzero_digests(&[
            (
                "keyAuthorization.authorityKeyId",
                &self.authority_key_id,
            ),
            (
                "keyAuthorization.authorityKeySpkiSha256",
                &self.authority_key_spki_sha256,
            ),
            (
                "keyAuthorization.checkpointSha256",
                &self.checkpoint_sha256,
            ),
        ])?;
        if self.authority_signature_base64.is_empty()
            || self.checkpoint_sha256
                != self.expected_checkpoint_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_key_authorization_checkpoint",
                "current-key authorization signature or digest is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementIdentity {
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) cgroup_identity: CgroupIdentity,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
}

impl SettlementIdentity {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            ("settlement.operationIdSha256", &self.operation_id_sha256),
            (
                "settlement.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            ("settlement.requestSha256", &self.request_sha256),
            (
                "settlement.supervisorCapabilitySha256",
                &self.supervisor_capability_sha256,
            ),
            (
                "settlement.fenceTokenSha256",
                &self.fence_token_sha256,
            ),
        ])?;
        self.cgroup_identity.validate()?;
        self.operation_deadline.to_runtime()?;
        Ok(())
    }

    pub(super) fn durable_consume_binding_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&(
            self.operation,
            &self.operation_id_sha256,
            &self.durable_request_sha256,
            &self.request_sha256,
            &self.supervisor_capability_sha256,
            &self.fence_token_sha256,
            &self.cgroup_identity,
            &self.operation_deadline,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_durable_consume_binding",
                "durable consume identity is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            DURABLE_CONSUME_BINDING_DOMAIN,
            &[bytes.as_slice()],
        ))
    }
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
pub(super) enum DurableSettlementPhase {
    Preflighted,
    ResultCommitted,
    ResultAborted,
    FenceClosed,
    TerminationCommitted,
}

impl DurableSettlementPhase {
    pub(super) fn expected_revision(self) -> u64 {
        match self {
            Self::Preflighted => 1,
            Self::ResultCommitted | Self::ResultAborted => 2,
            Self::FenceClosed => 3,
            Self::TerminationCommitted => 4,
        }
    }

    pub(super) fn is_adjacent_successor_of(
        self,
        predecessor: Self,
    ) -> bool {
        matches!(
            (predecessor, self),
            (
                Self::Preflighted,
                Self::ResultCommitted | Self::ResultAborted
            ) | (
                Self::ResultCommitted | Self::ResultAborted,
                Self::FenceClosed
            ) | (Self::FenceClosed, Self::TerminationCommitted)
        )
    }

    pub(super) fn recovery_successor(self) -> Option<Self> {
        match self {
            Self::Preflighted => Some(Self::ResultAborted),
            Self::ResultCommitted | Self::ResultAborted => {
                Some(Self::FenceClosed)
            }
            Self::FenceClosed => Some(Self::TerminationCommitted),
            Self::TerminationCommitted => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementStateReference {
    pub(super) phase: DurableSettlementPhase,
    pub(super) state_revision: u64,
    pub(super) state_sha256: Sha256Digest,
}

impl SettlementStateReference {
    pub(super) fn from_record(record: &DurableSettlementRecord) -> Self {
        Self {
            phase: record.phase,
            state_revision: record.state_revision,
            state_sha256: record.state_sha256.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "settlementReference.stateSha256",
            &self.state_sha256,
        )?;
        if self.state_revision != self.phase.expected_revision() {
            return Err(ProtocolError::new(
                "invalid_state_reference",
                "settlement state reference phase and revision disagree",
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DurableConsumeAtomicityModel {
    IndependentDurableConsumesNoDistributedAtomicity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableConsumeStatement {
    pub(super) api_version: String,
    pub(super) consumer_role: PolicyCustodyEndpointRole,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) consume_nonce_sha256: Sha256Digest,
    pub(super) consumer_generation: u64,
    pub(super) consumer_sequence: u64,
    pub(super) predecessor_receipt_sha256: Sha256Digest,
    pub(super) consume_binding_sha256: Sha256Digest,
    pub(super) consumed_at_boottime_nanos: u64,
    pub(super) occurred_before_operation_deadline: bool,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
}

impl DurableConsumeStatement {
    pub(super) fn validate_chain_shape(
        &self,
        expected_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            ("consume.operationIdSha256", &self.operation_id_sha256),
            (
                "consume.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            ("consume.requestSha256", &self.request_sha256),
            (
                "consume.supervisorCapabilitySha256",
                &self.supervisor_capability_sha256,
            ),
            ("consume.fenceTokenSha256", &self.fence_token_sha256),
            ("consume.consumeNonceSha256", &self.consume_nonce_sha256),
            (
                "consume.predecessorReceiptSha256",
                &self.predecessor_receipt_sha256,
            ),
            (
                "consume.consumeBindingSha256",
                &self.consume_binding_sha256,
            ),
        ])?;
        self.operation_deadline.to_runtime()?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.consumer_role != expected_role
            || self.consumer_generation == 0
            || self.consumer_sequence == 0
            || self.consumed_at_boottime_nanos == 0
            || !self.occurred_before_operation_deadline
            || self.consumed_at_boottime_nanos
                >= self
                    .operation_deadline
                    .absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "invalid_durable_consume_chain_statement",
                "durable consume chain statement is incomplete or internally inconsistent",
            ));
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        expected_role: PolicyCustodyEndpointRole,
        identity: &SettlementIdentity,
    ) -> Result<(), ProtocolError> {
        self.validate_chain_shape(expected_role)?;
        if self.operation != identity.operation
            || self.operation_id_sha256 != identity.operation_id_sha256
            || self.durable_request_sha256
                != identity.durable_request_sha256
            || self.request_sha256 != identity.request_sha256
            || self.supervisor_capability_sha256
                != identity.supervisor_capability_sha256
            || self.fence_token_sha256 != identity.fence_token_sha256
            || self.consume_binding_sha256
                != identity.durable_consume_binding_sha256()?
            || self.consumed_at_boottime_nanos
                >= identity
                    .operation_deadline
                    .absolute_boottime_nanos()
            || self.operation_deadline != identity.operation_deadline
        {
            return Err(ProtocolError::new(
                "durable_consume_binding_mismatch",
                "durable consume statement does not match the settlement identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedDurableConsumeReceiptEnvelope {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) canonical_statement_base64: String,
    pub(super) statement_sha256: Sha256Digest,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) envelope_sha256: Sha256Digest,
}

impl SignedDurableConsumeReceiptEnvelope {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.api_version,
            self.endpoint_role,
            &self.endpoint_process_identity_sha256,
            self.endpoint_generation,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            &self.canonical_statement_base64,
            &self.statement_sha256,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_endpoint_receipt",
                "endpoint receipt signature payload is not canonical",
            )
        })
    }

    pub(super) fn expected_envelope_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            ENDPOINT_RECEIPT_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "receipt.processIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            (
                "receipt.keyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "receipt.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("receipt.statementSha256", &self.statement_sha256),
            ("receipt.signingKeyId", &self.signing_key_id),
            (
                "receipt.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            ("receipt.envelopeSha256", &self.envelope_sha256),
        ])?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.canonical_statement_base64.is_empty()
            || self.signature_base64.is_empty()
            || self.envelope_sha256
                != self.expected_envelope_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_endpoint_receipt",
                "signed endpoint receipt is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableConsumeRequestV3 {
    pub(super) api_version: String,
    pub(super) identity: SettlementIdentity,
    pub(super) consumer_role: PolicyCustodyEndpointRole,
    pub(super) consume_nonce_sha256: Sha256Digest,
    pub(super) expected_consumer_generation: u64,
    pub(super) expected_consumer_sequence: u64,
    pub(super) expected_predecessor_receipt_sha256: Sha256Digest,
    pub(super) issued_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl DurableConsumeRequestV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.identity.validate()?;
        self.deadline.to_runtime()?;
        require_nonzero_digests(&[
            (
                "durableConsumeRequest.consumeNonceSha256",
                &self.consume_nonce_sha256,
            ),
            (
                "durableConsumeRequest.predecessorReceiptSha256",
                &self.expected_predecessor_receipt_sha256,
            ),
        ])?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || !matches!(
                self.consumer_role,
                PolicyCustodyEndpointRole::SignerHsm
                    | PolicyCustodyEndpointRole::SettlementStore
            )
            || self.expected_consumer_generation == 0
            || self.expected_consumer_sequence == 0
            || self.issued_at_boottime_nanos == 0
            || self.issued_at_boottime_nanos
                >= self.deadline.absolute_boottime_nanos()
            || self.deadline != self.identity.operation_deadline
        {
            return Err(ProtocolError::new(
                "invalid_durable_consume_request",
                "durable-consume request is incomplete, uses a forbidden role, or is outside the exact operation deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PersistedDurableConsumeReceiptV3<
    S = DurableConsumeStatement,
> {
    pub(super) api_version: String,
    pub(super) statement: S,
    pub(super) signed_envelope: SignedDurableConsumeReceiptEnvelope,
    pub(super) exact_canonical_statement_bytes: Vec<u8>,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
}

impl<S: Serialize> PersistedDurableConsumeReceiptV3<S> {
    pub(super) fn from_signed(
        statement: S,
        signed_envelope: SignedDurableConsumeReceiptEnvelope,
        expected_role: PolicyCustodyEndpointRole,
        expected_consumer_generation: u64,
    ) -> Result<Self, ProtocolError> {
        let exact_canonical_statement_bytes =
            canonical_json_bytes(&statement).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_durable_consume_statement",
                    "durable consume producer received a noncanonical statement",
                )
            })?;
        let exact_signed_envelope_bytes =
            canonical_json_bytes(&signed_envelope).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_durable_consume_envelope",
                    "durable consume producer received a noncanonical signed envelope",
                )
            })?;
        let persisted = Self {
            api_version:
                POLICY_CUSTODY_DURABLE_CONSUME_EVIDENCE_VERSION
                    .to_owned(),
            statement,
            signed_envelope,
            exact_canonical_statement_bytes,
            exact_signed_envelope_bytes,
        };
        persisted.validate_persisted_exact_bytes(
            expected_role,
            expected_consumer_generation,
        )?;
        Ok(persisted)
    }

    pub(super) fn validate_persisted_exact_bytes(
        &self,
        expected_role: PolicyCustodyEndpointRole,
        expected_consumer_generation: u64,
    ) -> Result<(), ProtocolError> {
        self.signed_envelope.validate_shape()?;
        let canonical_statement =
            canonical_json_bytes(&self.statement).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_durable_consume_statement",
                    "persisted durable consume statement is not canonical",
                )
            })?;
        let canonical_envelope =
            canonical_json_bytes(&self.signed_envelope).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_durable_consume_envelope",
                    "persisted durable consume envelope is not canonical",
                )
            })?;
        if self.api_version
                != POLICY_CUSTODY_DURABLE_CONSUME_EVIDENCE_VERSION
            || expected_consumer_generation == 0
            || self.exact_canonical_statement_bytes
                != canonical_statement
            || self.exact_signed_envelope_bytes != canonical_envelope
            || self.signed_envelope.endpoint_role != expected_role
            || self.signed_envelope.endpoint_generation
                != expected_consumer_generation
            || self.signed_envelope.statement_sha256
                != endpoint_receipt_statement_sha256(
                    &self.exact_canonical_statement_bytes,
                )
            || self.signed_envelope.canonical_statement_base64
                != URL_SAFE_NO_PAD
                    .encode(&self.exact_canonical_statement_bytes)
        {
            return Err(ProtocolError::new(
                "durable_consume_exact_bytes_mismatch",
                "persisted durable consume statement or envelope bytes do not match the generic signed v3 evidence representation",
            ));
        }
        Ok(())
    }
}

impl PersistedDurableConsumeReceiptV3<DurableConsumeStatement> {
    pub(super) fn validate_exact_bytes(
        &self,
        expected_role: PolicyCustodyEndpointRole,
        identity: &SettlementIdentity,
    ) -> Result<(), ProtocolError> {
        self.statement.validate(expected_role, identity)?;
        self.validate_persisted_exact_bytes(
            expected_role,
            self.statement.consumer_generation,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeEndpointConsumeCursorWire {
    pub(super) sequence_high_water: u64,
    pub(super) expected_next_sequence: u64,
    pub(super) expected_predecessor_receipt_sha256: Sha256Digest,
}

impl TrustedHostNoTeeEndpointConsumeCursorWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "trustedHostConsumeCursor.predecessorReceiptSha256",
            &self.expected_predecessor_receipt_sha256,
        )?;
        if self.expected_next_sequence
            != self.sequence_high_water.checked_add(1).ok_or_else(|| {
                ProtocolError::new(
                    "trusted_host_consume_sequence_overflow",
                    "trusted-host consume cursor sequence overflowed",
                )
            })?
        {
            return Err(ProtocolError::new(
                "invalid_trusted_host_consume_cursor",
                "trusted-host consume cursor is not an adjacent high-water cursor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeConsumeHeadStatementWire {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) cursor: TrustedHostNoTeeEndpointConsumeCursorWire,
    pub(super) observed_at_boottime_nanos: u64,
}

impl TrustedHostNoTeeConsumeHeadStatementWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.cursor.validate_shape()?;
        require_nonzero_digest(
            "trustedHostConsumeHead.keyAuthorizationCheckpointSha256",
            &self.current_key_authorization_checkpoint_sha256,
        )?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.endpoint_generation == 0
            || self.observed_at_boottime_nanos == 0
        {
            return Err(ProtocolError::new(
                "invalid_trusted_host_consume_head",
                "trusted-host consume head statement is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedTrustedHostNoTeeConsumeHeadWire {
    pub(super) statement: TrustedHostNoTeeConsumeHeadStatementWire,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) head_sha256: Sha256Digest,
}

impl SignedTrustedHostNoTeeConsumeHeadWire {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.statement,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_trusted_host_consume_head",
                "trusted-host consume head signature payload is not canonical",
            )
        })
    }

    pub(super) fn signature_preimage(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        domain_separated_signature_preimage(
            TRUSTED_HOST_CONSUME_HEAD_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_head_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            TRUSTED_HOST_CONSUME_HEAD_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.statement.validate_shape()?;
        require_nonzero_digests(&[
            (
                "trustedHostConsumeHead.signingKeyId",
                &self.signing_key_id,
            ),
            (
                "trustedHostConsumeHead.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "trustedHostConsumeHead.headSha256",
                &self.head_sha256,
            ),
        ])?;
        if self.signature_base64.is_empty()
            || self.head_sha256 != self.expected_head_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_signed_trusted_host_consume_head",
                "trusted-host consume head signature or digest is invalid",
            ));
        }
        Ok(())
    }
}

/// A fresh checkpoint-authority statement proving which role checkpoint was
/// current for one exact trust request. The endpoint can relay this object but
/// cannot mint it, replay it for another nonce, or choose an older head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeCurrentHeadStatementWire {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) request_nonce_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) checkpoint_sequence: u64,
    pub(super) checkpoint_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) revocation_generation_high_water: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) issued_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl TrustedHostNoTeeCurrentHeadStatementWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "trustedHostCurrentHead.requestNonceSha256",
                &self.request_nonce_sha256,
            ),
            (
                "trustedHostCurrentHead.requestSha256",
                &self.request_sha256,
            ),
            (
                "trustedHostCurrentHead.checkpointSha256",
                &self.checkpoint_sha256,
            ),
            (
                "trustedHostCurrentHead.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
        ])?;
        self.deadline.to_runtime()?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.checkpoint_sequence == 0
            || self.endpoint_generation == 0
            || self.revocation_generation_high_water == 0
            || self.issued_at_boottime_nanos == 0
            || self.issued_at_boottime_nanos
                >= self.deadline.absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "invalid_trusted_host_current_head_statement",
                "trusted-host current-head statement is incomplete or outside its absolute deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedTrustedHostNoTeeCurrentHeadWire {
    pub(super) statement: TrustedHostNoTeeCurrentHeadStatementWire,
    pub(super) authority_key_id: Sha256Digest,
    pub(super) authority_key_spki_sha256: Sha256Digest,
    pub(super) authority_signature_base64: String,
    pub(super) attestation_sha256: Sha256Digest,
}

impl SignedTrustedHostNoTeeCurrentHeadWire {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.statement,
            &self.authority_key_id,
            &self.authority_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_trusted_host_current_head",
                "trusted-host current-head signature payload is not canonical",
            )
        })
    }

    pub(super) fn authority_signature_preimage(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        domain_separated_signature_preimage(
            TRUSTED_HOST_CURRENT_HEAD_ATTESTATION_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_attestation_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            TRUSTED_HOST_CURRENT_HEAD_ATTESTATION_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.authority_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn from_authority_signature(
        statement: TrustedHostNoTeeCurrentHeadStatementWire,
        authority_key_id: Sha256Digest,
        authority_key_spki_sha256: Sha256Digest,
        authority_signature_base64: String,
    ) -> Result<Self, ProtocolError> {
        let mut signed = Self {
            statement,
            authority_key_id,
            authority_key_spki_sha256,
            authority_signature_base64,
            attestation_sha256: Sha256Digest::compute(&[]),
        };
        signed.attestation_sha256 =
            signed.expected_attestation_sha256()?;
        signed.validate_shape()?;
        Ok(signed)
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.statement.validate_shape()?;
        require_nonzero_digests(&[
            (
                "trustedHostCurrentHead.authorityKeyId",
                &self.authority_key_id,
            ),
            (
                "trustedHostCurrentHead.authorityKeySpkiSha256",
                &self.authority_key_spki_sha256,
            ),
            (
                "trustedHostCurrentHead.attestationSha256",
                &self.attestation_sha256,
            ),
        ])?;
        if self.authority_signature_base64.is_empty()
            || self.attestation_sha256
                != self.expected_attestation_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_signed_trusted_host_current_head",
                "trusted-host current-head signature envelope is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeCheckpointPredecessorPathWire {
    pub(super) from_checkpoint_sequence: u64,
    pub(super) from_checkpoint_sha256: Sha256Digest,
    pub(super) to_checkpoint_sequence: u64,
    pub(super) to_checkpoint_sha256: Sha256Digest,
    pub(super) successors:
        Vec<SignedEndpointKeyAuthorizationCheckpoint>,
}

impl TrustedHostNoTeeCheckpointPredecessorPathWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "checkpointPath.fromCheckpointSha256",
                &self.from_checkpoint_sha256,
            ),
            (
                "checkpointPath.toCheckpointSha256",
                &self.to_checkpoint_sha256,
            ),
        ])?;
        if self.from_checkpoint_sequence == 0
            || self.to_checkpoint_sequence
                < self.from_checkpoint_sequence
        {
            return Err(ProtocolError::new(
                "invalid_checkpoint_predecessor_path",
                "checkpoint predecessor path bounds are invalid",
            ));
        }
        let distance = self
            .to_checkpoint_sequence
            .checked_sub(self.from_checkpoint_sequence)
            .ok_or_else(|| {
                ProtocolError::new(
                    "invalid_checkpoint_predecessor_path",
                    "checkpoint predecessor path sequence underflowed",
                )
            })?;
        let expected_length = usize::try_from(distance).map_err(|_| {
            ProtocolError::new(
                "checkpoint_predecessor_path_too_long",
                "checkpoint predecessor path length does not fit usize",
            )
        })?;
        if expected_length > MAX_TRUST_ANCESTRY_STEPS
            || self.successors.len() != expected_length
        {
            return Err(ProtocolError::new(
                "incomplete_checkpoint_predecessor_path",
                "checkpoint predecessor path is missing, skipped, or over its bound",
            ));
        }
        let mut previous_sequence = self.from_checkpoint_sequence;
        let mut previous_sha256 = self.from_checkpoint_sha256.clone();
        for successor in &self.successors {
            successor.validate_shape()?;
            let expected_sequence =
                previous_sequence.checked_add(1).ok_or_else(|| {
                    ProtocolError::new(
                        "checkpoint_predecessor_path_overflow",
                        "checkpoint predecessor path sequence overflowed",
                    )
                })?;
            if successor.payload.checkpoint_sequence
                    != expected_sequence
                || successor.payload.predecessor_checkpoint_sha256
                    != previous_sha256
            {
                return Err(ProtocolError::new(
                    "nonadjacent_checkpoint_predecessor_path",
                    "checkpoint predecessor path contains a skipped or ambiguous successor",
                ));
            }
            previous_sequence = successor.payload.checkpoint_sequence;
            previous_sha256 = successor.checkpoint_sha256.clone();
        }
        if previous_sequence != self.to_checkpoint_sequence
            || previous_sha256 != self.to_checkpoint_sha256
        {
            return Err(ProtocolError::new(
                "checkpoint_predecessor_path_terminal_mismatch",
                "checkpoint predecessor path does not terminate at the declared current checkpoint",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "receiptKind",
    content = "receipt",
    rename_all = "kebab-case"
)]
pub(super) enum TrustedHostNoTeePersistedConsumeReceiptWire {
    PolicyOperation(PersistedDurableConsumeReceiptV3),
    CleanupAuthorization(
        PersistedCleanupAuthorizationConsumptionV3,
    ),
}

impl TrustedHostNoTeePersistedConsumeReceiptWire {
    pub(super) fn validate_chain_shape(
        &self,
        expected_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ProtocolError> {
        match self {
            Self::PolicyOperation(persisted) => {
                persisted
                    .statement
                    .validate_chain_shape(expected_role)?;
                persisted.validate_persisted_exact_bytes(
                    expected_role,
                    persisted.statement.consumer_generation,
                )
            }
            Self::CleanupAuthorization(persisted) => {
                persisted.statement.validate_shape()?;
                if persisted.statement.endpoint_role != expected_role {
                    return Err(ProtocolError::new(
                        "cleanup_consume_inclusion_role_mismatch",
                        "cleanup consume inclusion receipt has the wrong endpoint role",
                    ));
                }
                persisted.validate_persisted_exact_bytes(
                    expected_role,
                    persisted.statement.consumer_generation,
                )
            }
        }
    }

    pub(super) fn consumer_generation(&self) -> u64 {
        match self {
            Self::PolicyOperation(persisted) => {
                persisted.statement.consumer_generation
            }
            Self::CleanupAuthorization(persisted) => {
                persisted.statement.consumer_generation
            }
        }
    }

    pub(super) fn consumer_sequence(&self) -> u64 {
        match self {
            Self::PolicyOperation(persisted) => {
                persisted.statement.consumer_sequence
            }
            Self::CleanupAuthorization(persisted) => {
                persisted.statement.consumer_sequence
            }
        }
    }

    pub(super) fn predecessor_receipt_sha256(
        &self,
    ) -> &Sha256Digest {
        match self {
            Self::PolicyOperation(persisted) => {
                &persisted.statement.predecessor_receipt_sha256
            }
            Self::CleanupAuthorization(persisted) => {
                &persisted.statement.predecessor_receipt_sha256
            }
        }
    }

    pub(super) fn consumed_at_boottime_nanos(&self) -> u64 {
        match self {
            Self::PolicyOperation(persisted) => {
                persisted.statement.consumed_at_boottime_nanos
            }
            Self::CleanupAuthorization(persisted) => {
                persisted.statement.consumed_at_boottime_nanos
            }
        }
    }

    pub(super) fn signed_envelope(
        &self,
    ) -> &SignedDurableConsumeReceiptEnvelope {
        match self {
            Self::PolicyOperation(persisted) => {
                &persisted.signed_envelope
            }
            Self::CleanupAuthorization(persisted) => {
                &persisted.signed_envelope
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeDurableConsumeInclusionStepWire {
    pub(super) persisted:
        TrustedHostNoTeePersistedConsumeReceiptWire,
    pub(super) signing_key_authorization:
        SignedEndpointKeyAuthorizationCheckpoint,
    pub(super) signing_public_key_spki_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeDurableConsumeInclusionPathWire {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) from_sequence_high_water: u64,
    pub(super) from_predecessor_receipt_sha256: Sha256Digest,
    pub(super) to_sequence_high_water: u64,
    pub(super) to_predecessor_receipt_sha256: Sha256Digest,
    pub(super) successors:
        Vec<TrustedHostNoTeeDurableConsumeInclusionStepWire>,
}

impl TrustedHostNoTeeDurableConsumeInclusionPathWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "consumePath.fromPredecessorReceiptSha256",
                &self.from_predecessor_receipt_sha256,
            ),
            (
                "consumePath.toPredecessorReceiptSha256",
                &self.to_predecessor_receipt_sha256,
            ),
        ])?;
        if self.to_sequence_high_water < self.from_sequence_high_water {
            return Err(ProtocolError::new(
                "invalid_durable_consume_inclusion_path",
                "durable-consume inclusion path rolled back its sequence",
            ));
        }
        let distance = self
            .to_sequence_high_water
            .checked_sub(self.from_sequence_high_water)
            .ok_or_else(|| {
                ProtocolError::new(
                    "invalid_durable_consume_inclusion_path",
                    "durable-consume inclusion path sequence underflowed",
                )
            })?;
        let expected_length = usize::try_from(distance).map_err(|_| {
            ProtocolError::new(
                "durable_consume_inclusion_path_too_long",
                "durable-consume inclusion path length does not fit usize",
            )
        })?;
        if expected_length > MAX_TRUST_ANCESTRY_STEPS
            || self.successors.len() != expected_length
        {
            return Err(ProtocolError::new(
                "incomplete_durable_consume_inclusion_path",
                "durable-consume inclusion path is missing, skipped, or over its bound",
            ));
        }
        let mut previous_sequence = self.from_sequence_high_water;
        let mut previous_receipt_sha256 =
            self.from_predecessor_receipt_sha256.clone();
        for successor in &self.successors {
            successor.signing_key_authorization.validate_shape()?;
            successor
                .persisted
                .validate_chain_shape(self.endpoint_role)?;
            let expected_sequence =
                previous_sequence.checked_add(1).ok_or_else(|| {
                    ProtocolError::new(
                        "durable_consume_inclusion_path_overflow",
                        "durable-consume inclusion path sequence overflowed",
                    )
                })?;
            if successor.persisted.consumer_sequence()
                    != expected_sequence
                || successor
                    .persisted
                    .predecessor_receipt_sha256()
                    != &previous_receipt_sha256
                || successor.persisted.consumer_generation()
                    != successor
                        .persisted
                        .signed_envelope()
                        .endpoint_generation
                || successor
                    .persisted
                    .signed_envelope()
                    .current_key_authorization_checkpoint_sha256
                    != successor
                        .signing_key_authorization
                        .checkpoint_sha256
            {
                return Err(ProtocolError::new(
                    "nonadjacent_durable_consume_inclusion_path",
                    "durable-consume inclusion path contains a skipped or ambiguous receipt",
                ));
            }
            previous_sequence =
                successor.persisted.consumer_sequence();
            previous_receipt_sha256 = successor
                .persisted
                .signed_envelope()
                .envelope_sha256
                .clone();
        }
        if previous_sequence != self.to_sequence_high_water
            || previous_receipt_sha256
                != self.to_predecessor_receipt_sha256
        {
            return Err(ProtocolError::new(
                "durable_consume_inclusion_path_terminal_mismatch",
                "durable-consume inclusion path does not terminate at the declared current head",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeSignedFloorEvidenceWire {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) signing_public_key_spki_base64: String,
    pub(super) key_authorization:
        SignedEndpointKeyAuthorizationCheckpoint,
    pub(super) consume_head: SignedTrustedHostNoTeeConsumeHeadWire,
}

impl TrustedHostNoTeeSignedFloorEvidenceWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.key_authorization.validate_shape()?;
        self.consume_head.validate_shape()?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.signing_public_key_spki_base64.is_empty()
            || self.key_authorization.payload.endpoint_role
                != self.endpoint_role
            || self.consume_head.statement.endpoint_role
                != self.endpoint_role
            || self.consume_head.statement.endpoint_generation
                != self
                    .key_authorization
                    .payload
                    .exact_endpoint_generation
            || self
                .consume_head
                .statement
                .current_key_authorization_checkpoint_sha256
                != self.key_authorization.checkpoint_sha256
        {
            return Err(ProtocolError::new(
                "invalid_trusted_host_signed_floor",
                "trusted-host signed floor evidence is incomplete or internally inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeAcceptedFloorWire {
    pub(super) checkpoint_sequence: u64,
    pub(super) checkpoint_sha256: Sha256Digest,
    pub(super) consume_cursor:
        TrustedHostNoTeeEndpointConsumeCursorWire,
}

impl TrustedHostNoTeeAcceptedFloorWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.consume_cursor.validate_shape()?;
        require_nonzero_digest(
            "acceptedFloor.checkpointSha256",
            &self.checkpoint_sha256,
        )?;
        if self.checkpoint_sequence == 0 {
            return Err(ProtocolError::new(
                "invalid_trusted_host_accepted_floor",
                "trusted-host accepted checkpoint floor is absent",
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
pub(super) enum TrustedHostNoTeeTrustOperationWire {
    CurrentEndpointTrust {
        accepted_floor: TrustedHostNoTeeAcceptedFloorWire,
    },
    VerifyHistoricalDurableConsume {
        persisted: PersistedDurableConsumeReceiptV3,
        identity: SettlementIdentity,
        expected_current_head:
            TrustedHostNoTeeEndpointConsumeCursorWire,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeTrustRequestWire {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) request_nonce_sha256: Sha256Digest,
    pub(super) request_entropy_base64: String,
    pub(super) requested_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
    pub(super) operation: TrustedHostNoTeeTrustOperationWire,
}

impl TrustedHostNoTeeTrustRequestWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "trustedHostTrustRequest.requestNonceSha256",
            &self.request_nonce_sha256,
        )?;
        let entropy = URL_SAFE_NO_PAD
            .decode(&self.request_entropy_base64)
            .map_err(|_| {
                ProtocolError::new(
                    "invalid_trusted_host_request_entropy",
                    "trusted-host request entropy is not canonical base64url",
                )
            })?;
        self.deadline.to_runtime()?;
        match &self.operation {
            TrustedHostNoTeeTrustOperationWire::CurrentEndpointTrust {
                accepted_floor,
            } => accepted_floor.validate_shape()?,
            TrustedHostNoTeeTrustOperationWire::
                VerifyHistoricalDurableConsume {
                    persisted,
                    identity,
                    expected_current_head,
                } => {
                    expected_current_head.validate_shape()?;
                    persisted.validate_exact_bytes(
                        self.endpoint_role,
                        identity,
                    )?;
                }
        }
        let nonce_preimage = canonical_json_bytes(&(
            &self.api_version,
            self.endpoint_role,
            &self.request_entropy_base64,
            self.requested_at_boottime_nanos,
            &self.deadline,
            &self.operation,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_trusted_host_request_nonce",
                "trusted-host request nonce preimage is not canonical",
            )
        })?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || entropy.len() != 32
            || self.request_nonce_sha256
                != Sha256Digest::compute(&nonce_preimage)
            || self.requested_at_boottime_nanos == 0
            || self.requested_at_boottime_nanos
                >= self.deadline.absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "invalid_trusted_host_trust_request",
                "trusted-host trust request is incomplete or expired",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum TrustedHostNoTeeTrustResponseWire {
    CurrentEndpointTrust {
        current_head_attestation:
            SignedTrustedHostNoTeeCurrentHeadWire,
        current_key_authorization:
            SignedEndpointKeyAuthorizationCheckpoint,
        current_signing_public_key_spki_base64: String,
        checkpoint_predecessor_path:
            TrustedHostNoTeeCheckpointPredecessorPathWire,
        current_consume_head: SignedTrustedHostNoTeeConsumeHeadWire,
        consume_head_inclusion_path:
            TrustedHostNoTeeDurableConsumeInclusionPathWire,
    },
    HistoricalDurableConsume {
        current_head_attestation:
            SignedTrustedHostNoTeeCurrentHeadWire,
        persisted: PersistedDurableConsumeReceiptV3,
        historical_key_authorization:
            SignedEndpointKeyAuthorizationCheckpoint,
        historical_signing_public_key_spki_base64: String,
        historical_checkpoint_predecessor_path:
            TrustedHostNoTeeCheckpointPredecessorPathWire,
        current_consume_head: SignedTrustedHostNoTeeConsumeHeadWire,
        durable_consume_inclusion_path:
            TrustedHostNoTeeDurableConsumeInclusionPathWire,
    },
}

impl TrustedHostNoTeeTrustResponseWire {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        match self {
            Self::CurrentEndpointTrust {
                current_head_attestation,
                current_key_authorization,
                current_signing_public_key_spki_base64,
                checkpoint_predecessor_path,
                current_consume_head,
                consume_head_inclusion_path,
            } => {
                current_head_attestation.validate_shape()?;
                current_key_authorization.validate_shape()?;
                checkpoint_predecessor_path.validate_shape()?;
                current_consume_head.validate_shape()?;
                consume_head_inclusion_path.validate_shape()?;
                if current_signing_public_key_spki_base64.is_empty()
                    || current_head_attestation
                        .statement
                        .endpoint_role
                        != current_key_authorization
                            .payload
                            .endpoint_role
                    || current_head_attestation
                        .statement
                        .checkpoint_sequence
                        != current_key_authorization
                            .payload
                            .checkpoint_sequence
                    || current_head_attestation
                        .statement
                        .checkpoint_sha256
                        != current_key_authorization.checkpoint_sha256
                    || current_head_attestation
                        .statement
                        .endpoint_generation
                        != current_key_authorization
                            .payload
                            .exact_endpoint_generation
                    || current_head_attestation
                        .statement
                        .revocation_generation_high_water
                        != current_key_authorization
                            .payload
                            .revocation_generation_high_water
                    || current_head_attestation
                        .statement
                        .revocation_root_sha256
                        != current_key_authorization
                            .payload
                            .revocation_root_sha256
                    || checkpoint_predecessor_path
                        .to_checkpoint_sequence
                        != current_key_authorization
                            .payload
                            .checkpoint_sequence
                    || checkpoint_predecessor_path
                        .to_checkpoint_sha256
                        != current_key_authorization.checkpoint_sha256
                    || current_consume_head
                        .statement
                        .current_key_authorization_checkpoint_sha256
                        != current_key_authorization.checkpoint_sha256
                    || consume_head_inclusion_path.endpoint_role
                        != current_key_authorization
                            .payload
                            .endpoint_role
                    || consume_head_inclusion_path
                        .to_sequence_high_water
                        != current_consume_head
                            .statement
                            .cursor
                            .sequence_high_water
                    || consume_head_inclusion_path
                        .to_predecessor_receipt_sha256
                        != current_consume_head
                            .statement
                            .cursor
                            .expected_predecessor_receipt_sha256
                {
                    return Err(ProtocolError::new(
                        "invalid_current_trusted_host_response",
                        "current trusted-host response does not bind its checkpoint, consume head, and inclusion path",
                    ));
                }
            }
            Self::HistoricalDurableConsume {
                current_head_attestation,
                persisted,
                historical_key_authorization,
                historical_signing_public_key_spki_base64,
                historical_checkpoint_predecessor_path,
                current_consume_head,
                durable_consume_inclusion_path,
            } => {
                current_head_attestation.validate_shape()?;
                historical_key_authorization.validate_shape()?;
                historical_checkpoint_predecessor_path
                    .validate_shape()?;
                current_consume_head.validate_shape()?;
                durable_consume_inclusion_path.validate_shape()?;
                persisted.statement.validate_chain_shape(
                    persisted.signed_envelope.endpoint_role,
                )?;
                persisted.validate_persisted_exact_bytes(
                    persisted.signed_envelope.endpoint_role,
                    persisted.statement.consumer_generation,
                )?;
                if historical_signing_public_key_spki_base64.is_empty()
                    || current_head_attestation
                        .statement
                        .endpoint_role
                        != current_consume_head
                            .statement
                            .endpoint_role
                    || current_head_attestation
                        .statement
                        .checkpoint_sha256
                        != current_consume_head
                            .statement
                            .current_key_authorization_checkpoint_sha256
                    || historical_checkpoint_predecessor_path
                        .from_checkpoint_sequence
                        != historical_key_authorization
                            .payload
                            .checkpoint_sequence
                    || historical_checkpoint_predecessor_path
                        .from_checkpoint_sha256
                        != historical_key_authorization
                            .checkpoint_sha256
                    || historical_checkpoint_predecessor_path
                        .to_checkpoint_sha256
                        != current_consume_head
                            .statement
                            .current_key_authorization_checkpoint_sha256
                    || durable_consume_inclusion_path.endpoint_role
                        != persisted.signed_envelope.endpoint_role
                    || durable_consume_inclusion_path
                        .from_sequence_high_water
                        != persisted.statement.consumer_sequence
                    || durable_consume_inclusion_path
                        .from_predecessor_receipt_sha256
                        != persisted.signed_envelope.envelope_sha256
                    || durable_consume_inclusion_path
                        .to_sequence_high_water
                        != current_consume_head
                            .statement
                            .cursor
                            .sequence_high_water
                    || durable_consume_inclusion_path
                        .to_predecessor_receipt_sha256
                        != current_consume_head
                            .statement
                            .cursor
                            .expected_predecessor_receipt_sha256
                {
                    return Err(ProtocolError::new(
                        "invalid_historical_trusted_host_response",
                        "historical trusted-host response does not bind its receipt, checkpoint ancestry, and current consume head",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IndependentDurableConsumeEvidence {
    pub(super) api_version: String,
    pub(super) atomicity_model: DurableConsumeAtomicityModel,
    pub(super) signer_hsm: PersistedDurableConsumeReceiptV3,
    pub(super) settlement_store: PersistedDurableConsumeReceiptV3,
}

impl IndependentDurableConsumeEvidence {
    pub(super) fn from_persisted_receipts(
        signer_hsm: PersistedDurableConsumeReceiptV3,
        settlement_store: PersistedDurableConsumeReceiptV3,
    ) -> Result<Self, ProtocolError> {
        let evidence = Self {
            api_version:
                POLICY_CUSTODY_DURABLE_CONSUME_EVIDENCE_VERSION
                    .to_owned(),
            atomicity_model:
                DurableConsumeAtomicityModel::
                    IndependentDurableConsumesNoDistributedAtomicity,
            signer_hsm,
            settlement_store,
        };
        evidence.validate_envelope_shape()?;
        Ok(evidence)
    }

    pub(super) fn validate_envelope_shape(
        &self,
    ) -> Result<(), ProtocolError> {
        self.signer_hsm.signed_envelope.validate_shape()?;
        self.settlement_store.signed_envelope.validate_shape()?;
        if self.api_version
                != POLICY_CUSTODY_DURABLE_CONSUME_EVIDENCE_VERSION
            || self.atomicity_model
                != DurableConsumeAtomicityModel::
                    IndependentDurableConsumesNoDistributedAtomicity
            || self.signer_hsm.signed_envelope.endpoint_role
                != PolicyCustodyEndpointRole::SignerHsm
            || self.settlement_store.signed_envelope.endpoint_role
                != PolicyCustodyEndpointRole::SettlementStore
            || self
                .signer_hsm
                .signed_envelope
                .endpoint_process_identity_sha256
                == self
                    .settlement_store
                    .signed_envelope
                    .endpoint_process_identity_sha256
            || self.signer_hsm.signed_envelope.signing_key_id
                == self.settlement_store.signed_envelope.signing_key_id
            || self
                .signer_hsm
                .signed_envelope
                .signing_key_spki_sha256
                == self
                    .settlement_store
                    .signed_envelope
                    .signing_key_spki_sha256
        {
            return Err(ProtocolError::new(
                "independent_consume_shape_mismatch",
                "HSM and store evidence must be independently signed by distinct role identities",
            ));
        }
        Ok(())
    }
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
pub(super) enum WatchdogRegistrationFdRole {
    ParentPidfd,
    SupervisorPidfd,
    WorkerPidfd,
    OperationCgroup,
    SupervisorHeartbeatEventfd,
    WatchdogHeartbeatEventfd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogRetainedFdIdentityV3 {
    pub(super) role: WatchdogRegistrationFdRole,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mount_id: u64,
    pub(super) retained_fd_stat_sha256: Sha256Digest,
}

impl WatchdogRetainedFdIdentityV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "watchdogRetainedFd.retainedFdStatSha256",
            &self.retained_fd_stat_sha256,
        )?;
        if self.inode == 0 || self.mount_id == 0 {
            return Err(ProtocolError::new(
                "invalid_watchdog_retained_fd_identity",
                "watchdog retained descriptor identity is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogProcessIdentityV3 {
    pub(super) pid: i32,
    pub(super) start_time_ticks: u64,
    pub(super) pidfd_inode: u64,
    pub(super) pidfd_stat_sha256: Sha256Digest,
    pub(super) executable_sha256: Sha256Digest,
}

impl WatchdogProcessIdentityV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            ("watchdogProcess.pidfdStatSha256", &self.pidfd_stat_sha256),
            (
                "watchdogProcess.executableSha256",
                &self.executable_sha256,
            ),
        ])?;
        if self.pid <= 0
            || self.start_time_ticks == 0
            || self.pidfd_inode == 0
        {
            return Err(ProtocolError::new(
                "invalid_watchdog_process_identity",
                "watchdog process identity is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogRetainedCgroupIdentityV3 {
    pub(super) protocol: CgroupIdentity,
    pub(super) mount_id: u64,
    pub(super) inode: u64,
    pub(super) retained_fd_stat_sha256: Sha256Digest,
}

impl WatchdogRetainedCgroupIdentityV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.protocol.validate()?;
        require_nonzero_digest(
            "watchdogCgroup.retainedFdStatSha256",
            &self.retained_fd_stat_sha256,
        )?;
        if self.mount_id == 0 || self.inode == 0 {
            return Err(ProtocolError::new(
                "invalid_watchdog_cgroup_identity",
                "watchdog retained cgroup identity is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogLeaseV3 {
    pub(super) owner_identity_sha256: Sha256Digest,
    pub(super) lease_token_sha256: Sha256Digest,
    pub(super) heartbeat_interval_nanos: u64,
    pub(super) heartbeat_stall_deadline_nanos: u64,
}

impl WatchdogLeaseV3 {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "watchdogLease.ownerIdentitySha256",
                &self.owner_identity_sha256,
            ),
            (
                "watchdogLease.leaseTokenSha256",
                &self.lease_token_sha256,
            ),
        ])?;
        if self.heartbeat_interval_nanos == 0
            || self.heartbeat_stall_deadline_nanos
                <= self.heartbeat_interval_nanos
        {
            return Err(ProtocolError::new(
                "invalid_watchdog_lease",
                "watchdog heartbeat lease is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogRegistrationV3 {
    pub(super) api_version: String,
    pub(super) parent: WatchdogProcessIdentityV3,
    pub(super) supervisor: WatchdogProcessIdentityV3,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) cgroup: WatchdogRetainedCgroupIdentityV3,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) seccomp_binding_sha256: Sha256Digest,
    pub(super) filter_ready_proof_sha256: Sha256Digest,
    pub(super) retained_fds: Vec<WatchdogRetainedFdIdentityV3>,
    pub(super) fd_manifest_sha256: Sha256Digest,
    pub(super) lease: WatchdogLeaseV3,
    pub(super) registration_nonce_sha256: Sha256Digest,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) cleanup_deadline: ProtocolBoottimeDeadline,
    pub(super) registration_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchdogRegistrationHashPayload<'a> {
    api_version: &'a str,
    parent: &'a WatchdogProcessIdentityV3,
    supervisor: &'a WatchdogProcessIdentityV3,
    worker: &'a WatchdogProcessIdentityV3,
    cgroup: &'a WatchdogRetainedCgroupIdentityV3,
    operation: PolicyCustodyOperation,
    operation_id_sha256: &'a Sha256Digest,
    durable_request_sha256: &'a Sha256Digest,
    request_sha256: &'a Sha256Digest,
    supervisor_capability_sha256: &'a Sha256Digest,
    fence_token_sha256: &'a Sha256Digest,
    seccomp_binding_sha256: &'a Sha256Digest,
    filter_ready_proof_sha256: &'a Sha256Digest,
    retained_fds: &'a [WatchdogRetainedFdIdentityV3],
    fd_manifest_sha256: &'a Sha256Digest,
    lease: &'a WatchdogLeaseV3,
    registration_nonce_sha256: &'a Sha256Digest,
    operation_deadline: &'a ProtocolBoottimeDeadline,
    cleanup_deadline: &'a ProtocolBoottimeDeadline,
}

impl WatchdogRegistrationV3 {
    pub(super) fn finalize_manifest_and_registration(
        mut self,
    ) -> Result<Self, ProtocolError> {
        self.fd_manifest_sha256 =
            self.expected_fd_manifest_sha256()?;
        self.registration_sha256 =
            self.expected_registration_sha256()?;
        self.validate()?;
        Ok(self)
    }

    pub(super) fn expected_fd_manifest_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical =
            canonical_json_bytes(&self.retained_fds).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_watchdog_fd_manifest",
                    "watchdog descriptor manifest is not canonical",
                )
            })?;
        Ok(hash_domain_frames(
            WATCHDOG_FD_MANIFEST_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn expected_registration_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(
            &WatchdogRegistrationHashPayload {
                api_version: &self.api_version,
                parent: &self.parent,
                supervisor: &self.supervisor,
                worker: &self.worker,
                cgroup: &self.cgroup,
                operation: self.operation,
                operation_id_sha256: &self.operation_id_sha256,
                durable_request_sha256:
                    &self.durable_request_sha256,
                request_sha256: &self.request_sha256,
                supervisor_capability_sha256:
                    &self.supervisor_capability_sha256,
                fence_token_sha256: &self.fence_token_sha256,
                seccomp_binding_sha256:
                    &self.seccomp_binding_sha256,
                filter_ready_proof_sha256:
                    &self.filter_ready_proof_sha256,
                retained_fds: &self.retained_fds,
                fd_manifest_sha256: &self.fd_manifest_sha256,
                lease: &self.lease,
                registration_nonce_sha256:
                    &self.registration_nonce_sha256,
                operation_deadline: &self.operation_deadline,
                cleanup_deadline: &self.cleanup_deadline,
            },
        )
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_watchdog_registration",
                "watchdog registration is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            WATCHDOG_REGISTRATION_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        const EXACT_FD_ROLES: [WatchdogRegistrationFdRole; 6] = [
            WatchdogRegistrationFdRole::ParentPidfd,
            WatchdogRegistrationFdRole::SupervisorPidfd,
            WatchdogRegistrationFdRole::WorkerPidfd,
            WatchdogRegistrationFdRole::OperationCgroup,
            WatchdogRegistrationFdRole::SupervisorHeartbeatEventfd,
            WatchdogRegistrationFdRole::WatchdogHeartbeatEventfd,
        ];
        self.parent.validate()?;
        self.supervisor.validate()?;
        self.worker.validate()?;
        self.cgroup.validate()?;
        self.lease.validate()?;
        for retained in &self.retained_fds {
            retained.validate()?;
        }
        if self.retained_fds.len() != EXACT_FD_ROLES.len() {
            return Err(ProtocolError::new(
                "invalid_watchdog_registration",
                "watchdog registration does not retain the exact descriptor set",
            ));
        }
        let parent_pidfd = &self.retained_fds[0];
        let supervisor_pidfd = &self.retained_fds[1];
        let worker_pidfd = &self.retained_fds[2];
        let operation_cgroup = &self.retained_fds[3];
        self.operation_deadline.to_runtime()?;
        self.cleanup_deadline.to_runtime()?;
        require_nonzero_digests(&[
            (
                "watchdogRegistration.operationIdSha256",
                &self.operation_id_sha256,
            ),
            (
                "watchdogRegistration.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            (
                "watchdogRegistration.requestSha256",
                &self.request_sha256,
            ),
            (
                "watchdogRegistration.supervisorCapabilitySha256",
                &self.supervisor_capability_sha256,
            ),
            (
                "watchdogRegistration.fenceTokenSha256",
                &self.fence_token_sha256,
            ),
            (
                "watchdogRegistration.seccompBindingSha256",
                &self.seccomp_binding_sha256,
            ),
            (
                "watchdogRegistration.filterReadyProofSha256",
                &self.filter_ready_proof_sha256,
            ),
            (
                "watchdogRegistration.fdManifestSha256",
                &self.fd_manifest_sha256,
            ),
            (
                "watchdogRegistration.registrationNonceSha256",
                &self.registration_nonce_sha256,
            ),
            (
                "watchdogRegistration.registrationSha256",
                &self.registration_sha256,
            ),
        ])?;
        if self.api_version
                != POLICY_CUSTODY_WATCHDOG_REGISTRATION_VERSION
            || self
                .retained_fds
                .iter()
                .map(|retained| retained.role)
                .ne(EXACT_FD_ROLES)
            || parent_pidfd.inode != self.parent.pidfd_inode
            || parent_pidfd.retained_fd_stat_sha256
                != self.parent.pidfd_stat_sha256
            || supervisor_pidfd.inode != self.supervisor.pidfd_inode
            || supervisor_pidfd.retained_fd_stat_sha256
                != self.supervisor.pidfd_stat_sha256
            || worker_pidfd.inode != self.worker.pidfd_inode
            || worker_pidfd.retained_fd_stat_sha256
                != self.worker.pidfd_stat_sha256
            || operation_cgroup.inode != self.cgroup.inode
            || operation_cgroup.mount_id != self.cgroup.mount_id
            || operation_cgroup.retained_fd_stat_sha256
                != self.cgroup.retained_fd_stat_sha256
            || self.fd_manifest_sha256
                != self.expected_fd_manifest_sha256()?
            || self.operation_deadline.domain()
                != self.cleanup_deadline.domain()
            || self.operation_deadline.absolute_boottime_nanos()
                >= self.cleanup_deadline.absolute_boottime_nanos()
            || self.registration_sha256
                != self.expected_registration_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_watchdog_registration",
                "watchdog registration identity, descriptor manifest, lease, or deadline binding is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum WatchdogOwnershipPhaseV3 {
    Armed,
    Reconciling,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogOwnershipStateV3 {
    pub(super) api_version: String,
    pub(super) registration_sha256: Sha256Digest,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) revision: u64,
    pub(super) phase: WatchdogOwnershipPhaseV3,
    pub(super) parent: WatchdogProcessIdentityV3,
    pub(super) supervisor: WatchdogProcessIdentityV3,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) cgroup: WatchdogRetainedCgroupIdentityV3,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) supervisor_capability_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) fd_manifest_sha256: Sha256Digest,
    pub(super) lease: WatchdogLeaseV3,
    pub(super) predecessor_state_sha256: Sha256Digest,
    pub(super) persisted_at_boottime_nanos: u64,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) cleanup_deadline: ProtocolBoottimeDeadline,
    pub(super) state_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchdogOwnershipStateHashPayload<'a> {
    api_version: &'a str,
    registration_sha256: &'a Sha256Digest,
    ownership_id_sha256: &'a Sha256Digest,
    revision: u64,
    phase: WatchdogOwnershipPhaseV3,
    parent: &'a WatchdogProcessIdentityV3,
    supervisor: &'a WatchdogProcessIdentityV3,
    worker: &'a WatchdogProcessIdentityV3,
    cgroup: &'a WatchdogRetainedCgroupIdentityV3,
    operation: PolicyCustodyOperation,
    operation_id_sha256: &'a Sha256Digest,
    durable_request_sha256: &'a Sha256Digest,
    request_sha256: &'a Sha256Digest,
    supervisor_capability_sha256: &'a Sha256Digest,
    fence_token_sha256: &'a Sha256Digest,
    fd_manifest_sha256: &'a Sha256Digest,
    lease: &'a WatchdogLeaseV3,
    predecessor_state_sha256: &'a Sha256Digest,
    persisted_at_boottime_nanos: u64,
    operation_deadline: &'a ProtocolBoottimeDeadline,
    cleanup_deadline: &'a ProtocolBoottimeDeadline,
}

impl WatchdogOwnershipStateV3 {
    pub(super) fn expected_state_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let canonical = canonical_json_bytes(
            &WatchdogOwnershipStateHashPayload {
                api_version: &self.api_version,
                registration_sha256: &self.registration_sha256,
                ownership_id_sha256: &self.ownership_id_sha256,
                revision: self.revision,
                phase: self.phase,
                parent: &self.parent,
                supervisor: &self.supervisor,
                worker: &self.worker,
                cgroup: &self.cgroup,
                operation: self.operation,
                operation_id_sha256: &self.operation_id_sha256,
                durable_request_sha256:
                    &self.durable_request_sha256,
                request_sha256: &self.request_sha256,
                supervisor_capability_sha256:
                    &self.supervisor_capability_sha256,
                fence_token_sha256: &self.fence_token_sha256,
                fd_manifest_sha256: &self.fd_manifest_sha256,
                lease: &self.lease,
                predecessor_state_sha256:
                    &self.predecessor_state_sha256,
                persisted_at_boottime_nanos:
                    self.persisted_at_boottime_nanos,
                operation_deadline: &self.operation_deadline,
                cleanup_deadline: &self.cleanup_deadline,
            },
        )
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_watchdog_ownership_state",
                "watchdog ownership state is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            WATCHDOG_OWNERSHIP_STATE_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    pub(super) fn validate_against_registration(
        &self,
        registration: &WatchdogRegistrationV3,
    ) -> Result<(), ProtocolError> {
        registration.validate()?;
        self.parent.validate()?;
        self.supervisor.validate()?;
        self.worker.validate()?;
        self.cgroup.validate()?;
        self.lease.validate()?;
        require_nonzero_digests(&[
            (
                "watchdogOwnership.ownershipIdSha256",
                &self.ownership_id_sha256,
            ),
            (
                "watchdogOwnership.predecessorStateSha256",
                &self.predecessor_state_sha256,
            ),
            (
                "watchdogOwnership.stateSha256",
                &self.state_sha256,
            ),
        ])?;
        if self.api_version != POLICY_CUSTODY_WATCHDOG_OWNERSHIP_VERSION
            || self.revision == 0
            || self.phase != WatchdogOwnershipPhaseV3::Armed
            || self.registration_sha256
                != registration.registration_sha256
            || self.parent != registration.parent
            || self.supervisor != registration.supervisor
            || self.worker != registration.worker
            || self.cgroup != registration.cgroup
            || self.operation != registration.operation
            || self.operation_id_sha256
                != registration.operation_id_sha256
            || self.durable_request_sha256
                != registration.durable_request_sha256
            || self.request_sha256 != registration.request_sha256
            || self.supervisor_capability_sha256
                != registration.supervisor_capability_sha256
            || self.fence_token_sha256
                != registration.fence_token_sha256
            || self.fd_manifest_sha256
                != registration.fd_manifest_sha256
            || self.lease != registration.lease
            || self.operation_deadline
                != registration.operation_deadline
            || self.cleanup_deadline != registration.cleanup_deadline
            || self.persisted_at_boottime_nanos == 0
            || self.persisted_at_boottime_nanos
                >= registration
                    .operation_deadline
                    .absolute_boottime_nanos()
            || self.state_sha256 != self.expected_state_sha256()?
        {
            return Err(ProtocolError::new(
                "watchdog_ownership_registration_mismatch",
                "durable watchdog ownership state does not exactly bind the registration",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedWatchdogOwnershipAckV3 {
    pub(super) api_version: String,
    pub(super) ownership: WatchdogOwnershipStateV3,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) envelope_sha256: Sha256Digest,
}

impl SignedWatchdogOwnershipAckV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.api_version,
            &self.ownership,
            self.endpoint_role,
            &self.endpoint_process_identity_sha256,
            self.endpoint_generation,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_watchdog_ownership_ack",
                "watchdog ownership acknowledgement is not canonical",
            )
        })
    }

    pub(super) fn expected_envelope_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            WATCHDOG_OWNERSHIP_ENVELOPE_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "watchdogAck.endpointProcessIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            (
                "watchdogAck.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "watchdogAck.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("watchdogAck.signingKeyId", &self.signing_key_id),
            (
                "watchdogAck.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            ("watchdogAck.envelopeSha256", &self.envelope_sha256),
        ])?;
        if self.api_version != POLICY_CUSTODY_WATCHDOG_OWNERSHIP_VERSION
            || self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.signature_base64.is_empty()
            || self.envelope_sha256
                != self.expected_envelope_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_watchdog_ownership_ack",
                "signed watchdog ownership acknowledgement is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogOwnershipQueryV3 {
    pub(super) api_version: String,
    pub(super) registration_sha256: Sha256Digest,
    pub(super) ownership_id_sha256: Sha256Digest,
    pub(super) expected_state_sha256: Sha256Digest,
    pub(super) query_nonce_sha256: Sha256Digest,
    pub(super) issued_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl WatchdogOwnershipQueryV3 {
    pub(super) fn fresh(
        registration_sha256: Sha256Digest,
        ownership_id_sha256: Sha256Digest,
        expected_state_sha256: Sha256Digest,
        query_nonce_sha256: Sha256Digest,
        issued_at_boottime_nanos: u64,
        deadline: ProtocolBoottimeDeadline,
    ) -> Result<Self, ProtocolError> {
        let query = Self {
            api_version:
                POLICY_CUSTODY_WATCHDOG_OWNERSHIP_VERSION.to_owned(),
            registration_sha256,
            ownership_id_sha256,
            expected_state_sha256,
            query_nonce_sha256,
            issued_at_boottime_nanos,
            deadline,
        };
        query.validate()?;
        Ok(query)
    }

    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "watchdogOwnershipQuery.registrationSha256",
                &self.registration_sha256,
            ),
            (
                "watchdogOwnershipQuery.ownershipIdSha256",
                &self.ownership_id_sha256,
            ),
            (
                "watchdogOwnershipQuery.expectedStateSha256",
                &self.expected_state_sha256,
            ),
            (
                "watchdogOwnershipQuery.queryNonceSha256",
                &self.query_nonce_sha256,
            ),
        ])?;
        self.deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_WATCHDOG_OWNERSHIP_VERSION
            || self.query_nonce_sha256 == self.registration_sha256
            || self.query_nonce_sha256 == self.ownership_id_sha256
            || self.query_nonce_sha256 == self.expected_state_sha256
            || self.issued_at_boottime_nanos == 0
            || self.issued_at_boottime_nanos
                >= self.deadline.absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "invalid_watchdog_ownership_query",
                "watchdog ownership query version, identity, nonce, issuance time, or deadline is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogOwnershipQueryResultV3 {
    pub(super) authoritative_ownership:
        Option<SignedWatchdogOwnershipAckV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WatchdogOwnershipQueryReplyV3 {
    pub(super) response: WatchdogOwnershipQueryResultV3,
    pub(super) signed_envelope: SignedEndpointResponseEnvelope,
    pub(super) exact_canonical_response_bytes: Vec<u8>,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
}

impl WatchdogOwnershipQueryReplyV3 {
    pub(super) fn validate_exact_fresh_binding(
        &self,
        query: &WatchdogOwnershipQueryV3,
    ) -> Result<(), ProtocolError> {
        query.validate()?;
        self.signed_envelope.validate_shape()?;
        let authoritative = self
            .response
            .authoritative_ownership
            .as_ref()
            .ok_or_else(|| {
                ProtocolError::new(
                    "missing_watchdog_ownership",
                    "watchdog ownership query reply omitted authoritative state",
                )
            })?;
        authoritative.validate_shape()?;
        let canonical_request =
            canonical_json_bytes(query).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_watchdog_ownership_query",
                    "watchdog ownership query is not canonical",
                )
            })?;
        let canonical_response =
            canonical_json_bytes(&self.response).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_watchdog_ownership_query_reply",
                    "watchdog ownership query response is not canonical",
                )
            })?;
        let canonical_envelope =
            canonical_json_bytes(&self.signed_envelope).map_err(
                |_| {
                    ProtocolError::new(
                        "noncanonical_watchdog_ownership_query_envelope",
                        "watchdog ownership query response envelope is not canonical",
                    )
                },
            )?;
        if self.exact_canonical_response_bytes != canonical_response
            || self.exact_signed_envelope_bytes != canonical_envelope
            || self.signed_envelope.endpoint_role
                != PolicyCustodyEndpointRole::CleanupWatchdog
            || self.signed_envelope.request_nonce_sha256
                != query.query_nonce_sha256
            || self.signed_envelope.request_sha256
                != endpoint_request_sha256(&canonical_request)
            || self.signed_envelope.response_sha256
                != endpoint_response_sha256(&canonical_response)
            || self.signed_envelope.canonical_response_base64
                != URL_SAFE_NO_PAD.encode(&canonical_response)
            || self.signed_envelope.observed_at_boottime_nanos
                < query.issued_at_boottime_nanos
            || self.signed_envelope.observed_at_boottime_nanos
                >= query.deadline.absolute_boottime_nanos()
            || authoritative.ownership.registration_sha256
                != query.registration_sha256
            || authoritative.ownership.ownership_id_sha256
                != query.ownership_id_sha256
            || authoritative.ownership.state_sha256
                != query.expected_state_sha256
        {
            return Err(ProtocolError::new(
                "watchdog_ownership_query_binding_mismatch",
                "watchdog ownership query reply does not carry a fresh exact signed request, response, and authoritative-state binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "disposition",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum ResultDisposition {
    Committed {
        result_envelope_sha256: Sha256Digest,
        result_persistence_receipt_sha256: Sha256Digest,
    },
    Aborted {
        abort_reason_sha256: Sha256Digest,
        abort_receipt_sha256: Sha256Digest,
        signed_abort_action: SignedCleanupResultV3,
    },
}

impl ResultDisposition {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Committed {
                result_envelope_sha256,
                result_persistence_receipt_sha256,
            } => require_nonzero_digests(&[
                ("result.envelopeSha256", result_envelope_sha256),
                (
                    "result.persistenceReceiptSha256",
                    result_persistence_receipt_sha256,
                ),
            ]),
            Self::Aborted {
                abort_reason_sha256,
                abort_receipt_sha256,
                signed_abort_action,
            } => {
                require_nonzero_digests(&[
                    ("result.abortReasonSha256", abort_reason_sha256),
                    ("result.abortReceiptSha256", abort_receipt_sha256),
                ])?;
                signed_abort_action.validate_shape()?;
                if signed_abort_action.payload.action
                        != CleanupAction::CommitResultAborted
                    || !matches!(
                        signed_abort_action.payload.worker_observation,
                        WorkerPidfdObservation::NotObserved
                    )
                    || !matches!(
                        signed_abort_action.payload.cgroup_observation,
                        CgroupPopulationObservation::NotObserved
                    )
                    || signed_abort_action.result_receipt_sha256
                        != *abort_receipt_sha256
                {
                    return Err(ProtocolError::new(
                        "invalid_signed_abort_action",
                        "aborted settlement branch lacks the exact signed abort action and receipt",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TransitionNonceLedger {
    pub(super) nonce_sha256s: Vec<Sha256Digest>,
    pub(super) ledger_sha256: Sha256Digest,
}

impl TransitionNonceLedger {
    pub(super) fn computed_ledger_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes =
            canonical_json_bytes(&self.nonce_sha256s).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_transition_nonce_ledger",
                    "transition nonce ledger is not canonical",
                )
            })?;
        Ok(hash_domain_frames(
            SETTLEMENT_NONCE_LEDGER_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn validate(
        &self,
        expected_revision: u64,
        current_nonce: &Sha256Digest,
    ) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "transitionNonceLedger.ledgerSha256",
            &self.ledger_sha256,
        )?;
        let expected_length =
            usize::try_from(expected_revision).map_err(|_| {
                ProtocolError::new(
                    "invalid_transition_nonce_ledger",
                    "settlement revision does not fit usize",
                )
            })?;
        let mut unique = BTreeSet::new();
        for nonce in &self.nonce_sha256s {
            require_nonzero_digest(
                "transitionNonceLedger.nonceSha256",
                nonce,
            )?;
            if !unique.insert(nonce) {
                return Err(ProtocolError::new(
                    "reused_transition_nonce",
                    "transition nonce ledger contains a repeated nonce",
                ));
            }
        }
        if expected_length == 0
            || expected_length > MAX_SETTLEMENT_CHAIN_STATES
            || self.nonce_sha256s.len() != expected_length
            || self.nonce_sha256s.last() != Some(current_nonce)
            || self.ledger_sha256 != self.computed_ledger_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_transition_nonce_ledger",
                "transition nonce ledger does not prove the complete operation history",
            ));
        }
        Ok(())
    }

    fn validate_successor(
        &self,
        predecessor: &Self,
        current_nonce: &Sha256Digest,
    ) -> Result<(), ProtocolError> {
        let mut expected = predecessor.nonce_sha256s.clone();
        expected.push(current_nonce.clone());
        if self.nonce_sha256s != expected {
            return Err(ProtocolError::new(
                "transition_nonce_ledger_discontinuity",
                "successor nonce ledger is not the predecessor ledger plus one unique nonce",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableSettlementRecord {
    pub(super) api_version: String,
    pub(super) identity: SettlementIdentity,
    pub(super) phase: DurableSettlementPhase,
    pub(super) state_revision: u64,
    pub(super) durable_consumes: IndependentDurableConsumeEvidence,
    pub(super) result_disposition: Option<ResultDisposition>,
    pub(super) fence_close_receipt_sha256: Option<Sha256Digest>,
    pub(super) termination_receipt_sha256: Option<Sha256Digest>,
    pub(super) transition_nonce_sha256: Sha256Digest,
    pub(super) transition_nonce_ledger: TransitionNonceLedger,
    pub(super) predecessor: Option<SettlementStateReference>,
    pub(super) state_sha256: Sha256Digest,
}

impl DurableSettlementRecord {
    pub(super) fn computed_state_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes = canonical_json_bytes(&(
            &self.api_version,
            &self.identity,
            self.phase,
            self.state_revision,
            &self.durable_consumes,
            &self.result_disposition,
            &self.fence_close_receipt_sha256,
            &self.termination_receipt_sha256,
            &self.transition_nonce_sha256,
            &self.transition_nonce_ledger,
            &self.predecessor,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_settlement_state",
                "settlement state payload is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            SETTLEMENT_STATE_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.identity.validate()?;
        self.durable_consumes.validate_envelope_shape()?;
        require_nonzero_digests(&[
            (
                "settlement.transitionNonceSha256",
                &self.transition_nonce_sha256,
            ),
            ("settlement.stateSha256", &self.state_sha256),
        ])?;
        if let Some(disposition) = &self.result_disposition {
            disposition.validate()?;
        }
        if let Some(digest) = &self.fence_close_receipt_sha256 {
            require_nonzero_digest(
                "settlement.fenceCloseReceiptSha256",
                digest,
            )?;
        }
        if let Some(digest) = &self.termination_receipt_sha256 {
            require_nonzero_digest(
                "settlement.terminationReceiptSha256",
                digest,
            )?;
        }
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        self.transition_nonce_ledger.validate(
            self.state_revision,
            &self.transition_nonce_sha256,
        )?;
        if self.api_version != POLICY_CUSTODY_SETTLEMENT_VERSION
            || self.state_revision != self.phase.expected_revision()
            || self.state_sha256 != self.computed_state_sha256()?
        {
            return Err(ProtocolError::new(
                "settlement_state_shape_mismatch",
                "settlement state version, revision, or digest is invalid",
            ));
        }
        match self.phase {
            DurableSettlementPhase::Preflighted
                if self.result_disposition.is_none()
                    && self.fence_close_receipt_sha256.is_none()
                    && self.termination_receipt_sha256.is_none()
                    && self.predecessor.is_none() => {}
            DurableSettlementPhase::ResultCommitted
                if matches!(
                    self.result_disposition.as_ref(),
                    Some(ResultDisposition::Committed { .. })
                ) && self.fence_close_receipt_sha256.is_none()
                    && self.termination_receipt_sha256.is_none()
                    && self.predecessor.is_some() => {}
            DurableSettlementPhase::ResultAborted
                if matches!(
                    self.result_disposition.as_ref(),
                    Some(ResultDisposition::Aborted { .. })
                ) && self.fence_close_receipt_sha256.is_none()
                    && self.termination_receipt_sha256.is_none()
                    && self.predecessor.is_some() => {}
            DurableSettlementPhase::FenceClosed
                if self.result_disposition.is_some()
                    && self.fence_close_receipt_sha256.is_some()
                    && self.termination_receipt_sha256.is_none()
                    && self.predecessor.is_some() => {}
            DurableSettlementPhase::TerminationCommitted
                if self.result_disposition.is_some()
                    && self.fence_close_receipt_sha256.is_some()
                    && self.termination_receipt_sha256.is_some()
                    && self.predecessor.is_some() => {}
            _ => {
                return Err(ProtocolError::new(
                    "invalid_settlement_branch",
                    "settlement record is not on the committed or aborted durable branch",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_successor(
        &self,
        predecessor: &Self,
    ) -> Result<(), ProtocolError> {
        predecessor.validate_shape()?;
        self.validate_shape()?;
        if !self.phase.is_adjacent_successor_of(predecessor.phase)
            || self.state_revision
                != predecessor.state_revision.saturating_add(1)
            || self.predecessor.as_ref()
                != Some(&SettlementStateReference::from_record(predecessor))
            || self.identity != predecessor.identity
            || self.durable_consumes != predecessor.durable_consumes
            || predecessor.result_disposition.is_some()
                && self.result_disposition
                    != predecessor.result_disposition
            || predecessor.fence_close_receipt_sha256.is_some()
                && self.fence_close_receipt_sha256
                    != predecessor.fence_close_receipt_sha256
            || predecessor.termination_receipt_sha256.is_some()
                && self.termination_receipt_sha256
                    != predecessor.termination_receipt_sha256
        {
            return Err(ProtocolError::new(
                "nonadjacent_settlement_transition",
                "CAS candidate is not exactly one adjacent durable transition",
            ));
        }
        self.transition_nonce_ledger.validate_successor(
            &predecessor.transition_nonce_ledger,
            &self.transition_nonce_sha256,
        )
    }

    pub(super) fn receipt_releasable(&self) -> bool {
        self.phase == DurableSettlementPhase::TerminationCommitted
            && matches!(
                self.result_disposition.as_ref(),
                Some(ResultDisposition::Committed { .. })
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementTransitionIdentity {
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) predecessor: SettlementStateReference,
    pub(super) target_phase: DurableSettlementPhase,
    pub(super) target_state_sha256: Sha256Digest,
    pub(super) transition_nonce_sha256: Sha256Digest,
    pub(super) transition_nonce_ledger_sha256: Sha256Digest,
    pub(super) transition_payload_sha256: Sha256Digest,
    pub(super) transition_id_sha256: Sha256Digest,
}

impl SettlementTransitionIdentity {
    pub(super) fn computed_transition_payload_sha256(
        candidate: &DurableSettlementRecord,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes = canonical_json_bytes(candidate).map_err(|_| {
            ProtocolError::new(
                "noncanonical_transition_payload",
                "settlement transition candidate is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            SETTLEMENT_TRANSITION_PAYLOAD_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn computed_transition_id_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes = canonical_json_bytes(&(
            &self.operation_id_sha256,
            &self.durable_request_sha256,
            &self.fence_token_sha256,
            &self.predecessor,
            self.target_phase,
            &self.target_state_sha256,
            &self.transition_nonce_sha256,
            &self.transition_nonce_ledger_sha256,
            &self.transition_payload_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_transition_identity",
                "settlement transition identity is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            SETTLEMENT_TRANSITION_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn validate(
        &self,
        candidate: &DurableSettlementRecord,
    ) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            ("transition.operationIdSha256", &self.operation_id_sha256),
            (
                "transition.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            (
                "transition.fenceTokenSha256",
                &self.fence_token_sha256,
            ),
            (
                "transition.targetStateSha256",
                &self.target_state_sha256,
            ),
            (
                "transition.transitionNonceSha256",
                &self.transition_nonce_sha256,
            ),
            (
                "transition.nonceLedgerSha256",
                &self.transition_nonce_ledger_sha256,
            ),
            (
                "transition.payloadSha256",
                &self.transition_payload_sha256,
            ),
            ("transition.idSha256", &self.transition_id_sha256),
        ])?;
        self.predecessor.validate()?;
        if self.operation_id_sha256
                != candidate.identity.operation_id_sha256
            || self.durable_request_sha256
                != candidate.identity.durable_request_sha256
            || self.fence_token_sha256
                != candidate.identity.fence_token_sha256
            || candidate.predecessor.as_ref() != Some(&self.predecessor)
            || self.target_phase != candidate.phase
            || self.target_state_sha256 != candidate.state_sha256
            || self.transition_nonce_sha256
                != candidate.transition_nonce_sha256
            || self.transition_nonce_ledger_sha256
                != candidate.transition_nonce_ledger.ledger_sha256
            || self.transition_payload_sha256
                != Self::computed_transition_payload_sha256(candidate)?
            || self.transition_id_sha256
                != self.computed_transition_id_sha256()?
        {
            return Err(ProtocolError::new(
                "transition_identity_mismatch",
                "transition identity does not bind the exact candidate, nonce ledger, and predecessor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementQuery {
    pub(super) api_version: String,
    pub(super) identity: SettlementIdentity,
    pub(super) query_nonce_sha256: Sha256Digest,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl SettlementQuery {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        self.identity.validate()?;
        require_nonzero_digest(
            "settlementQuery.queryNonceSha256",
            &self.query_nonce_sha256,
        )?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.deadline != self.identity.operation_deadline
        {
            return Err(ProtocolError::new(
                "invalid_settlement_query",
                "settlement query version, identity, or deadline is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementCompareAndSwap {
    pub(super) api_version: String,
    pub(super) identity: SettlementIdentity,
    pub(super) expected: SettlementStateReference,
    pub(super) transition: SettlementTransitionIdentity,
    pub(super) candidate: DurableSettlementRecord,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl SettlementCompareAndSwap {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.expected.validate()?;
        let predecessor = self
            .candidate
            .predecessor
            .as_ref()
            .ok_or_else(|| {
                ProtocolError::new(
                    "cas_predecessor_missing",
                    "CAS candidate must bind an exact predecessor",
                )
            })?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.identity != self.candidate.identity
            || &self.expected != predecessor
            || !self
                .candidate
                .phase
                .is_adjacent_successor_of(self.expected.phase)
            || self.candidate.state_revision
                != self.expected.state_revision.saturating_add(1)
            || self.deadline != self.identity.operation_deadline
        {
            return Err(ProtocolError::new(
                "cas_binding_mismatch",
                "CAS request does not bind one adjacent settlement transition",
            ));
        }
        self.candidate.validate_shape()?;
        self.transition.validate(&self.candidate)
    }

    pub(super) fn validate(
        &self,
        predecessor: &DurableSettlementRecord,
    ) -> Result<(), ProtocolError> {
        self.validate_shape()?;
        if self.identity != predecessor.identity
            || self.expected
                != SettlementStateReference::from_record(predecessor)
        {
            return Err(ProtocolError::new(
                "cas_binding_mismatch",
                "CAS request does not bind the expected settlement state",
            ));
        }
        self.candidate.validate_successor(predecessor)?;
        self.transition.validate(&self.candidate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "command",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum SettlementCommand {
    Query(SettlementQuery),
    CompareAndSwap(SettlementCompareAndSwap),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettlementQueryReply {
    pub(super) authoritative_state: Option<DurableSettlementRecord>,
    pub(super) canonical_state_chain: Vec<DurableSettlementRecord>,
}

impl SettlementQueryReply {
    pub(super) fn validate(
        &self,
        identity: &SettlementIdentity,
    ) -> Result<(), ProtocolError> {
        match &self.authoritative_state {
            None if self.canonical_state_chain.is_empty() => return Ok(()),
            None => {
                return Err(ProtocolError::new(
                    "orphan_settlement_chain",
                    "query returned a chain without an authoritative state",
                ));
            }
            Some(state) => {
                state.validate_shape()?;
                if state.identity != *identity {
                    return Err(ProtocolError::new(
                        "settlement_query_identity_mismatch",
                        "query returned another operation",
                    ));
                }
            }
        }
        if self.canonical_state_chain.is_empty()
            || self.canonical_state_chain.len()
                > MAX_SETTLEMENT_CHAIN_STATES
            || self.canonical_state_chain.first().is_none_or(|state| {
                state.phase != DurableSettlementPhase::Preflighted
                    || state.predecessor.is_some()
            })
            || self.canonical_state_chain.last()
                != self.authoritative_state.as_ref()
        {
            return Err(ProtocolError::new(
                "invalid_settlement_chain",
                "query did not return the complete bounded canonical state chain",
            ));
        }
        for state in &self.canonical_state_chain {
            state.validate_shape()?;
            if state.identity != *identity {
                return Err(ProtocolError::new(
                    "settlement_chain_identity_mismatch",
                    "canonical state chain crosses operation identities",
                ));
            }
        }
        for states in self.canonical_state_chain.windows(2) {
            states[1].validate_successor(&states[0])?;
        }
        let authoritative = self
            .authoritative_state
            .as_ref()
            .ok_or_else(|| {
                ProtocolError::new(
                    "missing_authoritative_state",
                    "validated settlement chain has no authoritative state",
                )
            })?;
        if self.canonical_state_chain.len()
            != usize::try_from(authoritative.state_revision).map_err(
                |_| {
                    ProtocolError::new(
                        "invalid_settlement_chain",
                        "authoritative revision does not fit usize",
                    )
                },
            )?
        {
            return Err(ProtocolError::new(
                "incomplete_settlement_chain",
                "canonical state chain omits an adjacent successor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum SettlementCasReply {
    Applied {
        transition_id_sha256: Sha256Digest,
        authoritative_state: DurableSettlementRecord,
    },
    AlreadyApplied {
        transition_id_sha256: Sha256Digest,
        authoritative_state: DurableSettlementRecord,
    },
    Conflict {
        authoritative_state: DurableSettlementRecord,
    },
}

impl SettlementCasReply {
    pub(super) fn authoritative_state(
        &self,
    ) -> &DurableSettlementRecord {
        match self {
            Self::Applied {
                authoritative_state,
                ..
            }
            | Self::AlreadyApplied {
                authoritative_state,
                ..
            }
            | Self::Conflict {
                authoritative_state,
            } => authoritative_state,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum EndpointRequestKind {
    DurableConsume,
    SettlementQuery,
    SettlementCompareAndSwap,
    CleanupAuthorizationQuery,
    CleanupAuthorizationCompareAndSwap,
}

impl EndpointRequestKind {
    pub(super) fn permits_role(
        self,
        endpoint_role: PolicyCustodyEndpointRole,
    ) -> bool {
        match self {
            Self::DurableConsume => matches!(
                endpoint_role,
                PolicyCustodyEndpointRole::SignerHsm
                    | PolicyCustodyEndpointRole::SettlementStore
            ),
            Self::SettlementQuery
            | Self::SettlementCompareAndSwap => {
                endpoint_role
                    == PolicyCustodyEndpointRole::SettlementStore
            }
            Self::CleanupAuthorizationQuery
            | Self::CleanupAuthorizationCompareAndSwap => matches!(
                endpoint_role,
                PolicyCustodyEndpointRole::FenceAuthority
                    | PolicyCustodyEndpointRole::CgroupExecutor
                    | PolicyCustodyEndpointRole::SettlementStore
                    | PolicyCustodyEndpointRole::TerminationLedger
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EndpointRequestEnvelope {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) request_kind: EndpointRequestKind,
    pub(super) request_nonce_sha256: Sha256Digest,
    pub(super) canonical_request_base64: String,
    pub(super) request_sha256: Sha256Digest,
    pub(super) deadline: ProtocolBoottimeDeadline,
    pub(super) envelope_sha256: Sha256Digest,
}

impl EndpointRequestEnvelope {
    pub(super) fn computed_envelope_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        let bytes = canonical_json_bytes(&(
            &self.api_version,
            self.endpoint_role,
            self.request_kind,
            &self.request_nonce_sha256,
            &self.canonical_request_base64,
            &self.request_sha256,
            &self.deadline,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_endpoint_request",
                "endpoint request envelope is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            ENDPOINT_REQUEST_DOMAIN,
            &[bytes.as_slice()],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "endpointRequest.requestNonceSha256",
                &self.request_nonce_sha256,
            ),
            (
                "endpointRequest.requestSha256",
                &self.request_sha256,
            ),
            (
                "endpointRequest.envelopeSha256",
                &self.envelope_sha256,
            ),
        ])?;
        self.deadline.to_runtime()?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || !self.request_kind.permits_role(self.endpoint_role)
            || self.canonical_request_base64.is_empty()
            || self.envelope_sha256
                != self.computed_envelope_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_endpoint_request",
                "endpoint request envelope is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedEndpointResponseEnvelope {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity: EndpointProcessIdentity,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) request_nonce_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) canonical_response_base64: String,
    pub(super) response_sha256: Sha256Digest,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) envelope_sha256: Sha256Digest,
}

impl SignedEndpointResponseEnvelope {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.api_version,
            self.endpoint_role,
            &self.endpoint_process_identity,
            &self.endpoint_process_identity_sha256,
            self.endpoint_generation,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            &self.request_nonce_sha256,
            &self.request_sha256,
            &self.canonical_response_base64,
            &self.response_sha256,
            self.observed_at_boottime_nanos,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_endpoint_response",
                "endpoint response signature payload is not canonical",
            )
        })
    }

    pub(super) fn expected_envelope_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            ENDPOINT_RESPONSE_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.endpoint_process_identity.validate_shape()?;
        require_nonzero_digests(&[
            (
                "endpointResponse.processIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            (
                "endpointResponse.keyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "endpointResponse.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            (
                "endpointResponse.requestNonceSha256",
                &self.request_nonce_sha256,
            ),
            (
                "endpointResponse.requestSha256",
                &self.request_sha256,
            ),
            (
                "endpointResponse.responseSha256",
                &self.response_sha256,
            ),
            (
                "endpointResponse.signingKeyId",
                &self.signing_key_id,
            ),
            (
                "endpointResponse.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "endpointResponse.envelopeSha256",
                &self.envelope_sha256,
            ),
        ])?;
        if self.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.endpoint_process_identity_sha256
                != self.endpoint_process_identity.identity_sha256
            || self.endpoint_generation == 0
            || self.revocation_generation == 0
            || self.canonical_response_base64.is_empty()
            || self.observed_at_boottime_nanos == 0
            || self.signature_base64.is_empty()
            || self.envelope_sha256
                != self.expected_envelope_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_endpoint_response",
                "signed endpoint response is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupAction {
    RevokeFence,
    KillCgroup,
    ReapWorker,
    CommitResultAborted,
    CommitFenceClosed,
    CommitTermination,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(super) enum WorkerPidfdObservation {
    NotObserved,
    Reaped {
        wait_status: i32,
        reap_observation_sha256: Sha256Digest,
        reaped_at_boottime_nanos: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "population", rename_all = "kebab-case")]
pub(super) enum CgroupPopulationObservation {
    NotObserved,
    Populated {
        cgroup_events_sha256: Sha256Digest,
        observed_at_boottime_nanos: u64,
    },
    Empty {
        cgroup_events_sha256: Sha256Digest,
        observed_at_boottime_nanos: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupResultSignedPayload {
    pub(super) api_version: String,
    pub(super) action: CleanupAction,
    pub(super) executor_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
    pub(super) predecessor: CleanupPredecessor,
    pub(super) authorization_nonce_sha256: Sha256Digest,
    pub(super) authorization_sha256: Sha256Digest,
    pub(super) authorization_consumption_receipt_sha256: Sha256Digest,
    pub(super) authorization_consumption_sequence: u64,
    pub(super) worker_pidfd_identity: WatchdogProcessIdentityV3,
    pub(super) cgroup_fd_identity: WatchdogRetainedCgroupIdentityV3,
    pub(super) worker_observation: WorkerPidfdObservation,
    pub(super) cgroup_observation: CgroupPopulationObservation,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) cleanup_deadline: ProtocolBoottimeDeadline,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) result_sequence: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) trust_checkpoint_id_sha256: Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedCleanupResultV3 {
    pub(super) payload: CleanupResultSignedPayload,
    pub(super) exact_canonical_payload: Box<[u8]>,
    pub(super) signature_base64: String,
    pub(super) result_receipt_sha256: Sha256Digest,
}

impl SignedCleanupResultV3 {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "cleanupResult.endpointProcessIdentitySha256",
                &self.payload.endpoint_process_identity_sha256,
            ),
            (
                "cleanupResult.operationIdSha256",
                &self.payload.operation_id_sha256,
            ),
            (
                "cleanupResult.durableRequestSha256",
                &self.payload.durable_request_sha256,
            ),
            (
                "cleanupResult.requestSha256",
                &self.payload.request_sha256,
            ),
            (
                "cleanupResult.terminationFenceSha256",
                &self.payload.termination_fence_sha256,
            ),
            (
                "cleanupResult.authorizationNonceSha256",
                &self.payload.authorization_nonce_sha256,
            ),
            (
                "cleanupResult.authorizationSha256",
                &self.payload.authorization_sha256,
            ),
            (
                "cleanupResult.authorizationConsumptionReceiptSha256",
                &self
                    .payload
                    .authorization_consumption_receipt_sha256,
            ),
            (
                "cleanupResult.signingKeyId",
                &self.payload.signing_key_id,
            ),
            (
                "cleanupResult.signingKeySpkiSha256",
                &self.payload.signing_key_spki_sha256,
            ),
            (
                "cleanupResult.trustCheckpointIdSha256",
                &self.payload.trust_checkpoint_id_sha256,
            ),
            (
                "cleanupResult.revocationRootSha256",
                &self.payload.revocation_root_sha256,
            ),
            (
                "cleanupResult.resultReceiptSha256",
                &self.result_receipt_sha256,
            ),
        ])?;
        self.payload.predecessor.validate()?;
        self.payload.worker_pidfd_identity.validate()?;
        self.payload.cgroup_fd_identity.validate()?;
        self.payload.operation_deadline.to_runtime()?;
        self.payload.cleanup_deadline.to_runtime()?;
        let canonical =
            canonical_json_bytes(&self.payload).map_err(|_| {
                ProtocolError::new(
                    "noncanonical_cleanup_result",
                    "cleanup result payload is not canonical",
                )
            })?;
        if self.payload.endpoint_generation == 0
            || self.payload.authorization_consumption_sequence == 0
            || self.payload.result_sequence == 0
            || self.payload.revocation_generation == 0
            || self.payload.observed_at_boottime_nanos == 0
            || self.payload.operation_deadline.domain()
                != self.payload.cleanup_deadline.domain()
            || self
                .payload
                .operation_deadline
                .absolute_boottime_nanos()
                >= self
                    .payload
                    .cleanup_deadline
                    .absolute_boottime_nanos()
            || self.exact_canonical_payload.as_ref()
                != canonical.as_slice()
            || self.signature_base64.is_empty()
        {
            return Err(ProtocolError::new(
                "invalid_cleanup_result",
                "signed cleanup result is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

impl CleanupAction {
    pub(super) fn required_executor_role(
        self,
    ) -> PolicyCustodyEndpointRole {
        PolicyCustodyEndpointRole::CleanupWatchdog
    }

    pub(super) fn required_endpoint_role(
        self,
    ) -> PolicyCustodyEndpointRole {
        match self {
            Self::RevokeFence => {
                PolicyCustodyEndpointRole::FenceAuthority
            }
            Self::KillCgroup | Self::ReapWorker => {
                PolicyCustodyEndpointRole::CgroupExecutor
            }
            Self::CommitResultAborted | Self::CommitFenceClosed => {
                PolicyCustodyEndpointRole::SettlementStore
            }
            Self::CommitTermination => {
                PolicyCustodyEndpointRole::TerminationLedger
            }
        }
    }

    pub(super) fn accepts_predecessor_phase(
        self,
        phase: DurableSettlementPhase,
    ) -> bool {
        match self {
            Self::CommitResultAborted => {
                phase == DurableSettlementPhase::Preflighted
            }
            Self::RevokeFence
            | Self::KillCgroup
            | Self::CommitFenceClosed => matches!(
                phase,
                DurableSettlementPhase::ResultCommitted
                    | DurableSettlementPhase::ResultAborted
            ),
            Self::ReapWorker | Self::CommitTermination => {
                phase == DurableSettlementPhase::FenceClosed
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupPredecessor {
    pub(super) phase: DurableSettlementPhase,
    pub(super) state_revision: u64,
    pub(super) state_sha256: Sha256Digest,
}

impl From<&DurableSettlementRecord> for CleanupPredecessor {
    fn from(record: &DurableSettlementRecord) -> Self {
        Self {
            phase: record.phase,
            state_revision: record.state_revision,
            state_sha256: record.state_sha256.clone(),
        }
    }
}

impl CleanupPredecessor {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digest(
            "cleanup.predecessorStateSha256",
            &self.state_sha256,
        )?;
        if self.state_revision != self.phase.expected_revision() {
            return Err(ProtocolError::new(
                "invalid_cleanup_predecessor",
                "cleanup predecessor phase and revision disagree",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupAuthorizationPayloadV3 {
    pub(super) api_version: String,
    pub(super) action: CleanupAction,
    pub(super) executor_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) cgroup_identity: CgroupIdentity,
    pub(super) predecessor: CleanupPredecessor,
    pub(super) authorization_nonce_sha256: Sha256Digest,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) absolute_boottime_deadline:
        ProtocolBoottimeDeadline,
}

impl CleanupAuthorizationPayloadV3 {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.cgroup_identity.validate()?;
        self.predecessor.validate()?;
        require_nonzero_digests(&[
            (
                "cleanup.operationIdSha256",
                &self.operation_id_sha256,
            ),
            (
                "cleanup.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            ("cleanup.requestSha256", &self.request_sha256),
            (
                "cleanup.fenceTokenSha256",
                &self.fence_token_sha256,
            ),
            (
                "cleanup.authorizationNonceSha256",
                &self.authorization_nonce_sha256,
            ),
        ])?;
        self.operation_deadline.to_runtime()?;
        self.absolute_boottime_deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.executor_role
                != self.action.required_executor_role()
            || self.endpoint_role
                != self.action.required_endpoint_role()
            || !self
                .action
                .accepts_predecessor_phase(self.predecessor.phase)
            || self.operation_deadline.domain()
                != self.absolute_boottime_deadline.domain()
            || self
                .absolute_boottime_deadline
                .absolute_boottime_nanos()
                <= self
                    .operation_deadline
                    .absolute_boottime_nanos()
        {
            return Err(ProtocolError::new(
                "cleanup_authorization_shape_mismatch",
                "cleanup authorization has an invalid action, role, predecessor, or deadline",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_against(
        &self,
        state: &DurableSettlementRecord,
    ) -> Result<(), ProtocolError> {
        self.validate_shape()?;
        if self.operation != state.identity.operation
            || self.operation_id_sha256
                != state.identity.operation_id_sha256
            || self.durable_request_sha256
                != state.identity.durable_request_sha256
            || self.request_sha256 != state.identity.request_sha256
            || self.fence_token_sha256
                != state.identity.fence_token_sha256
            || self.cgroup_identity != state.identity.cgroup_identity
            || self.predecessor != CleanupPredecessor::from(state)
            || self.operation_deadline
                != state.identity.operation_deadline
        {
            return Err(ProtocolError::new(
                "cleanup_authorization_binding_mismatch",
                "cleanup authorization violates its exact action, roles, predecessor, operation, or deadline binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedCleanupAuthorizationV3 {
    pub(super) payload: CleanupAuthorizationPayloadV3,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) authority_key_id: Sha256Digest,
    pub(super) authority_key_spki_sha256: Sha256Digest,
    pub(super) authority_signature_base64: String,
    pub(super) authorization_sha256: Sha256Digest,
}

impl SignedCleanupAuthorizationV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.payload,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            &self.authority_key_id,
            &self.authority_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_cleanup_authorization",
                "cleanup authorization signature payload is not canonical",
            )
        })
    }

    pub(super) fn expected_authorization_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            CLEANUP_AUTHORIZATION_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.authority_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn authority_signature_preimage(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        domain_separated_signature_preimage(
            CLEANUP_AUTHORIZATION_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.payload.validate_shape()?;
        require_nonzero_digests(&[
            (
                "cleanup.keyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanup.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("cleanup.authorityKeyId", &self.authority_key_id),
            (
                "cleanup.authorityKeySpkiSha256",
                &self.authority_key_spki_sha256,
            ),
            (
                "cleanup.authorizationSha256",
                &self.authorization_sha256,
            ),
            (
                "cleanup.authorizationNonceSha256",
                &self.payload.authorization_nonce_sha256,
            ),
        ])?;
        if self.revocation_generation == 0
            || self.authority_signature_base64.is_empty()
            || self.authorization_sha256
                != self.expected_authorization_sha256()?
            || self.payload.executor_role
                != self.payload.action.required_executor_role()
            || self.payload.endpoint_role
                != self.payload.action.required_endpoint_role()
            || !self
                .payload
                .action
                .accepts_predecessor_phase(
                    self.payload.predecessor.phase,
                )
        {
            return Err(ProtocolError::new(
                "cleanup_authorization_shape_mismatch",
                "cleanup authorization signature, nonce, role, or predecessor binding is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupAuthorizationConsumptionStatement {
    pub(super) api_version: String,
    pub(super) authorization_sha256: Sha256Digest,
    pub(super) authorization_nonce_sha256: Sha256Digest,
    pub(super) action: CleanupAction,
    pub(super) executor_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) request_sha256: Sha256Digest,
    pub(super) fence_token_sha256: Sha256Digest,
    pub(super) cgroup_identity: CgroupIdentity,
    pub(super) predecessor: CleanupPredecessor,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) absolute_boottime_deadline:
        ProtocolBoottimeDeadline,
    pub(super) predecessor_receipt_sha256: Sha256Digest,
    pub(super) consumed_at_boottime_nanos: u64,
    pub(super) occurred_before_cleanup_deadline: bool,
    pub(super) consumer_generation: u64,
    pub(super) consumer_sequence: u64,
}

impl CleanupAuthorizationConsumptionStatement {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.cgroup_identity.validate()?;
        self.predecessor.validate()?;
        require_nonzero_digests(&[
            (
                "cleanupConsumption.authorizationSha256",
                &self.authorization_sha256,
            ),
            (
                "cleanupConsumption.authorizationNonceSha256",
                &self.authorization_nonce_sha256,
            ),
            (
                "cleanupConsumption.operationIdSha256",
                &self.operation_id_sha256,
            ),
            (
                "cleanupConsumption.durableRequestSha256",
                &self.durable_request_sha256,
            ),
            (
                "cleanupConsumption.requestSha256",
                &self.request_sha256,
            ),
            (
                "cleanupConsumption.fenceTokenSha256",
                &self.fence_token_sha256,
            ),
            (
                "cleanupConsumption.predecessorReceiptSha256",
                &self.predecessor_receipt_sha256,
            ),
        ])?;
        self.operation_deadline.to_runtime()?;
        self.absolute_boottime_deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.executor_role
                != self.action.required_executor_role()
            || self.endpoint_role
                != self.action.required_endpoint_role()
            || !self
                .action
                .accepts_predecessor_phase(self.predecessor.phase)
            || self.operation_deadline.domain()
                != self.absolute_boottime_deadline.domain()
            || self
                .absolute_boottime_deadline
                .absolute_boottime_nanos()
                <= self
                    .operation_deadline
                    .absolute_boottime_nanos()
            || self.consumed_at_boottime_nanos == 0
            || self.consumed_at_boottime_nanos
                < self
                    .operation_deadline
                    .absolute_boottime_nanos()
            || self.consumed_at_boottime_nanos
                >= self
                    .absolute_boottime_deadline
                    .absolute_boottime_nanos()
            || !self.occurred_before_cleanup_deadline
            || self.consumer_generation == 0
            || self.consumer_sequence == 0
        {
            return Err(ProtocolError::new(
                "cleanup_consumption_shape_mismatch",
                "cleanup consumption has an invalid role, predecessor, sequence, or deadline",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_against(
        &self,
        authorization: &SignedCleanupAuthorizationV3,
    ) -> Result<(), ProtocolError> {
        authorization.validate_shape()?;
        self.validate_shape()?;
        let payload = &authorization.payload;
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.authorization_sha256
                != authorization.authorization_sha256
            || self.authorization_nonce_sha256
                != payload.authorization_nonce_sha256
            || self.action != payload.action
            || self.executor_role != payload.executor_role
            || self.endpoint_role != payload.endpoint_role
            || self.operation != payload.operation
            || self.operation_id_sha256
                != payload.operation_id_sha256
            || self.durable_request_sha256
                != payload.durable_request_sha256
            || self.request_sha256 != payload.request_sha256
            || self.fence_token_sha256 != payload.fence_token_sha256
            || self.cgroup_identity != payload.cgroup_identity
            || self.predecessor != payload.predecessor
            || self.operation_deadline != payload.operation_deadline
            || self.absolute_boottime_deadline
                != payload.absolute_boottime_deadline
        {
            return Err(ProtocolError::new(
                "cleanup_consumption_binding_mismatch",
                "cleanup consumption does not bind the exact one-use authorization",
            ));
        }
        Ok(())
    }
}

pub(super) type PersistedCleanupAuthorizationConsumptionV3 =
    PersistedDurableConsumeReceiptV3<
        CleanupAuthorizationConsumptionStatement,
    >;

impl PersistedDurableConsumeReceiptV3<
    CleanupAuthorizationConsumptionStatement,
> {
    pub(super) fn validate_cleanup_exact_bytes(
        &self,
        expected_role: PolicyCustodyEndpointRole,
        authorization: Option<&SignedCleanupAuthorizationV3>,
    ) -> Result<(), ProtocolError> {
        self.statement.validate_shape()?;
        if let Some(authorization) = authorization {
            self.statement.validate_against(authorization)?;
        }
        self.validate_persisted_exact_bytes(
            expected_role,
            self.statement.consumer_generation,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupConsumptionQuery {
    pub(super) api_version: String,
    pub(super) authorization_nonce_sha256: Sha256Digest,
    pub(super) query_nonce_sha256: Sha256Digest,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl CleanupConsumptionQuery {
    pub(super) fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_digests(&[
            (
                "cleanupQuery.authorizationNonceSha256",
                &self.authorization_nonce_sha256,
            ),
            (
                "cleanupQuery.queryNonceSha256",
                &self.query_nonce_sha256,
            ),
        ])?;
        self.deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.authorization_nonce_sha256
                == self.query_nonce_sha256
        {
            return Err(ProtocolError::new(
                "invalid_cleanup_query",
                "cleanup query version, deadline, or nonce is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupConsumptionCompareAndSwap {
    pub(super) api_version: String,
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(super) expected_consumer_sequence_high_water: u64,
    pub(super) expected_predecessor_receipt_sha256: Sha256Digest,
    pub(super) cas_nonce_sha256: Sha256Digest,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

impl CleanupConsumptionCompareAndSwap {
    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.authorization.validate_shape()?;
        require_nonzero_digests(&[
            (
                "cleanupCas.expectedPredecessorReceiptSha256",
                &self.expected_predecessor_receipt_sha256,
            ),
            ("cleanupCas.casNonceSha256", &self.cas_nonce_sha256),
        ])?;
        self.deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.cas_nonce_sha256
                == self
                    .authorization
                    .payload
                    .authorization_nonce_sha256
            || self.deadline
                != self
                    .authorization
                    .payload
                    .absolute_boottime_deadline
        {
            return Err(ProtocolError::new(
                "invalid_cleanup_cas",
                "cleanup CAS does not bind its exact high-water, predecessor, nonce, and deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "command",
    content = "body",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupConsumptionCommand {
    Query(CleanupConsumptionQuery),
    CompareAndSwap(CleanupConsumptionCompareAndSwap),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupConsumptionQueryReply {
    pub(super) authoritative_consumption:
        Option<PersistedCleanupAuthorizationConsumptionV3>,
    pub(super) authoritative_cursor:
        SignedCleanupConsumptionCursorV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "evidence",
    rename_all = "kebab-case"
)]
pub(super) enum CleanupConsumptionCasReply {
    Applied {
        consumption: PersistedCleanupAuthorizationConsumptionV3,
        authoritative_cursor: SignedCleanupConsumptionCursorV3,
    },
    AlreadyApplied {
        consumption: PersistedCleanupAuthorizationConsumptionV3,
        authoritative_cursor: SignedCleanupConsumptionCursorV3,
    },
    Conflict {
        authoritative_consumption:
            Option<PersistedCleanupAuthorizationConsumptionV3>,
        authoritative_cursor: SignedCleanupConsumptionCursorV3,
    },
}

impl CleanupConsumptionCasReply {
    pub(super) fn consumption(
        &self,
    ) -> Option<&PersistedCleanupAuthorizationConsumptionV3> {
        match self {
            Self::Applied { consumption, .. }
            | Self::AlreadyApplied { consumption, .. } => Some(consumption),
            Self::Conflict {
                authoritative_consumption,
                ..
            } => authoritative_consumption.as_ref(),
        }
    }

    pub(super) fn authoritative_cursor(
        &self,
    ) -> &SignedCleanupConsumptionCursorV3 {
        match self {
            Self::Applied {
                authoritative_cursor,
                ..
            }
            | Self::AlreadyApplied {
                authoritative_cursor,
                ..
            }
            | Self::Conflict {
                authoritative_cursor,
                ..
            } => authoritative_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CleanupConsumptionCursorV3 {
    pub(super) api_version: String,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_generation: u64,
    pub(super) sequence_high_water: u64,
    pub(super) predecessor_receipt_sha256: Sha256Digest,
    pub(super) observed_at_boottime_nanos: u64,
    pub(super) deadline: ProtocolBoottimeDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedCleanupConsumptionCursorV3 {
    pub(super) cursor: CleanupConsumptionCursorV3,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) cursor_receipt_sha256: Sha256Digest,
}

impl SignedCleanupConsumptionCursorV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProtocolError> {
        canonical_json_bytes(&(
            &self.cursor,
            &self.endpoint_process_identity_sha256,
            &self.current_key_authorization_checkpoint_sha256,
            self.revocation_generation,
            &self.revocation_root_sha256,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ProtocolError::new(
                "noncanonical_cleanup_cursor",
                "cleanup cursor signature payload is not canonical",
            )
        })
    }

    pub(super) fn expected_cursor_receipt_sha256(
        &self,
    ) -> Result<Sha256Digest, ProtocolError> {
        Ok(hash_domain_frames(
            CLEANUP_CURSOR_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.cursor.deadline.to_runtime()?;
        require_nonzero_digests(&[
            (
                "cleanupCursor.predecessorReceiptSha256",
                &self.cursor.predecessor_receipt_sha256,
            ),
            (
                "cleanupCursor.endpointProcessIdentitySha256",
                &self.endpoint_process_identity_sha256,
            ),
            (
                "cleanupCursor.currentKeyAuthorizationCheckpointSha256",
                &self.current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanupCursor.revocationRootSha256",
                &self.revocation_root_sha256,
            ),
            ("cleanupCursor.signingKeyId", &self.signing_key_id),
            (
                "cleanupCursor.signingKeySpkiSha256",
                &self.signing_key_spki_sha256,
            ),
            (
                "cleanupCursor.cursorReceiptSha256",
                &self.cursor_receipt_sha256,
            ),
        ])?;
        if self.cursor.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || self.cursor.endpoint_generation == 0
            || self.cursor.observed_at_boottime_nanos == 0
            || self.cursor.observed_at_boottime_nanos
                >= self
                    .cursor
                    .deadline
                    .absolute_boottime_nanos()
            || self.revocation_generation == 0
            || self.signature_base64.is_empty()
            || self.cursor_receipt_sha256
                != self.expected_cursor_receipt_sha256()?
        {
            return Err(ProtocolError::new(
                "invalid_cleanup_cursor",
                "signed authoritative cleanup cursor is incomplete",
            ));
        }
        Ok(())
    }
}

pub(super) fn endpoint_request_sha256(
    canonical_request: &[u8],
) -> Sha256Digest {
    hash_domain_frames(
        ENDPOINT_REQUEST_DOMAIN,
        &[canonical_request],
    )
}

pub(super) fn endpoint_response_sha256(
    canonical_response: &[u8],
) -> Sha256Digest {
    hash_domain_frames(
        ENDPOINT_RESPONSE_DOMAIN,
        &[canonical_response],
    )
}

pub(super) fn endpoint_receipt_statement_sha256(
    canonical_statement: &[u8],
) -> Sha256Digest {
    hash_domain_frames(
        ENDPOINT_RECEIPT_DOMAIN,
        &[canonical_statement],
    )
}

pub(super) fn domain_separated_signature_preimage(
    domain: &[u8],
    canonical_payload: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let domain_length = u64::try_from(domain.len()).map_err(|_| {
        ProtocolError::new(
            "signature_domain_too_large",
            "signature domain length does not fit u64",
        )
    })?;
    let payload_length =
        u64::try_from(canonical_payload.len()).map_err(|_| {
            ProtocolError::new(
                "signature_payload_too_large",
                "signature payload length does not fit u64",
            )
        })?;
    let capacity = domain
        .len()
        .checked_add(canonical_payload.len())
        .and_then(|length| length.checked_add(32))
        .ok_or_else(|| {
            ProtocolError::new(
                "signature_preimage_too_large",
                "signature preimage length overflow",
            )
        })?;
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(b"serverware-signature-v1\0");
    preimage.extend_from_slice(&domain_length.to_be_bytes());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&payload_length.to_be_bytes());
    preimage.extend_from_slice(canonical_payload);
    Ok(preimage)
}
