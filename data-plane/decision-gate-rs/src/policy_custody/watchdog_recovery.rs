//! Independent policy-custody watchdog and deterministic recovery orchestration.
//!
//! The launcher owns process creation, retained descriptors, namespaces,
//! seccomp, and privilege dropping. This module accepts only retained pidfds,
//! retained cgroup descriptors, absolute `CLOCK_BOOTTIME` authority, typed
//! protocol records, and independently signed evidence.

use super::boottime::{
    boottime_now_nanos, create_nonblocking_eventfd, poll_until,
    try_read_eventfd_nonblocking, try_write_eventfd_nonblocking,
    BackoffOutcome, BoottimeBackoff,
    BoottimeDeadline as AbsoluteBoottimeDeadline, BoottimeDomain,
    DeadlineOperationError, LinuxAbsoluteBoottimePoller, PollInterest,
    PollTarget, WaitOutcome,
};
use super::endpoint_clients::{
    verify_independent_durable_consumes_with_current_provider,
    verify_watchdog_ownership_ack_with_current_provider,
    verify_watchdog_ownership_query_confirmation,
    CurrentEndpointTrustProvider, VerifiedIndependentDurableConsumes,
    VerifiedWatchdogOwnershipAck,
};
use super::protocol::{
    endpoint_response_sha256, CleanupAction,
    CgroupPopulationObservation,
    CleanupConsumptionCasReply, CleanupConsumptionQueryReply,
    CleanupPredecessor, DurableSettlementPhase,
    DurableSettlementRecord,
    IndependentDurableConsumeEvidence,
    PersistedCleanupAuthorizationConsumptionV3,
    PolicyCustodyEndpointRole, PolicyCustodyOperation,
    ProtocolBoottimeDeadline, ResultDisposition,
    SettlementIdentity, SettlementStateReference,
    SignedCleanupAuthorizationV3, SignedCleanupResultV3,
    SignedEndpointResponseEnvelope, SignedWatchdogOwnershipAckV3,
    TransitionNonceLedger,
    WatchdogLeaseV3, WatchdogProcessIdentityV3,
    WatchdogOwnershipQueryReplyV3, WatchdogOwnershipQueryV3,
    WatchdogRegistrationFdRole, WatchdogRegistrationV3,
    WatchdogRetainedCgroupIdentityV3,
    WatchdogRetainedFdIdentityV3,
    WorkerPidfdObservation,
    POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION,
    POLICY_CUSTODY_SETTLEMENT_VERSION,
};
use super::services::wire::{
    DurableCleanupEffectEvidenceV3,
    CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
};
use super::super::{canonical_json_bytes, Sha256Digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd,
};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::Zeroize;

const MAX_RECOVERY_TRANSITIONS: usize = 4;
const MAX_STARTUP_SCAN_PASSES: usize = 64;
const ABSOLUTE_MAX_SCAN_RECORDS: usize = 1_024;
const ABSOLUTE_MAX_RETRY_ATTEMPTS: u8 = 16;
const ABSOLUTE_MAX_CLEANUP_ACTIONS: usize = 16;
const MAX_SIGNED_EVIDENCE_BYTES: usize = 64 * 1024;
const CLEANUP_RESULT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyVerifiedCleanupResult/v1";
const CLEANUP_RESULT_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyVerifiedCleanupResultReceipt/v1";
const CLEANUP_INTENT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectIntentReceipt/v3";
const VERIFIED_CLEANUP_EVIDENCE_VERSION: &str =
    "serverware.policyCustodyWatchdogVerifiedCleanupEvidence/v3";

pub(super) type RecoveryDigest = Sha256Digest;

fn digest_is_zero(digest: &RecoveryDigest) -> bool {
    digest.as_str()
        == "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<RecoveryDigest, RecoveryError> {
    let canonical = canonical_json_bytes(value).map_err(|_| {
        RecoveryError::Invalid("signed evidence is not canonical")
    })?;
    let domain_length = u64::try_from(domain.len()).map_err(|_| {
        RecoveryError::Invalid("signature domain length overflow")
    })?;
    let canonical_length =
        u64::try_from(canonical.len()).map_err(|_| {
            RecoveryError::Invalid("canonical payload length overflow")
        })?;
    let mut framed = Vec::with_capacity(
        domain
            .len()
            .checked_add(canonical.len())
            .and_then(|length| length.checked_add(16))
            .ok_or(RecoveryError::Invalid(
                "signed evidence frame length overflow",
            ))?,
    );
    framed.extend_from_slice(&domain_length.to_be_bytes());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(&canonical_length.to_be_bytes());
    framed.extend_from_slice(&canonical);
    Ok(Sha256Digest::compute(&framed))
}

fn protocol_error(
    _: impl fmt::Display,
    message: &'static str,
) -> RecoveryError {
    RecoveryError::Authorization(message)
}

fn require_exact_deadline(
    passed: &AbsoluteBoottimeDeadline,
    expected: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    if passed != expected {
        return Err(RecoveryError::Deadline(
            "passed deadline is not the exact durable deadline",
        ));
    }
    expected.domain().require_current().map_err(|_| {
        RecoveryError::Deadline(
            "durable BOOTTIME domain is not the current domain",
        )
    })?;
    expected.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "durable BOOTTIME deadline is not live",
        )
    })
}

pub(super) fn drive_nonblocking_until<T>(
    progress_fd: RawFd,
    deadline: &AbsoluteBoottimeDeadline,
    mut attempt: impl FnMut() -> Result<Option<T>, RecoveryError>,
) -> Result<T, RecoveryError> {
    if progress_fd < 0 {
        return Err(RecoveryError::Invalid(
            "nonblocking operation progress descriptor is invalid",
        ));
    }
    loop {
        let token = deadline.mutation_token().map_err(|_| {
            RecoveryError::Deadline(
                "cannot mint same-deadline one-use operation token",
            )
        })?;
        let attempted = token
            .execute_nonblocking(|| attempt())
            .map_err(|error| match error {
                DeadlineOperationError::Authority(_) => {
                    RecoveryError::Deadline(
                        "nonblocking operation crossed its BOOTTIME authority",
                    )
                }
                DeadlineOperationError::Action(error) => error,
            })?;
        if !attempted.completed_before_deadline() {
            return Err(RecoveryError::Deadline(
                "nonblocking operation completed after its BOOTTIME deadline",
            ));
        }
        if let Some(value) = attempted.into_value() {
            deadline.require_live().map_err(|_| {
                RecoveryError::Deadline(
                    "BOOTTIME deadline expired after operation success",
                )
            })?;
            return Ok(value);
        }
        let progress =
            unsafe { BorrowedFd::borrow_raw(progress_fd) };
        match poll_until(*deadline, &[PollTarget::eventfd(progress)])
            .map_err(|_| {
                RecoveryError::Deadline(
                    "absolute BOOTTIME progress poll failed",
                )
            })?
        {
            WaitOutcome::Progress(events)
                if events.iter().any(|event| {
                    event.readable()
                        || event.hung_up()
                        || event.errored()
                }) => {}
            WaitOutcome::Progress(_) => {
                return Err(RecoveryError::Invalid(
                    "progress descriptor woke without progress events",
                ));
            }
            WaitOutcome::DeadlineExpired => {
                return Err(RecoveryError::Deadline(
                    "nonblocking operation exceeded its BOOTTIME deadline",
                ));
            }
        }
    }
}

pub(super) type DurableRecoveryPhase = DurableSettlementPhase;
pub(super) type ProcessIdentity = WatchdogProcessIdentityV3;
pub(super) type RetainedCgroupIdentity =
    WatchdogRetainedCgroupIdentityV3;
pub(super) type WatchdogLeaseIdentity = WatchdogLeaseV3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnershipPhase {
    Armed,
    Reconciling,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DurableOwnershipRecord {
    pub(super) registration: WatchdogRegistrationV3,
    pub(super) signed_ownership_ack: SignedWatchdogOwnershipAckV3,
    pub(super) ownership_id_sha256: RecoveryDigest,
    pub(super) revision: u64,
    pub(super) phase: OwnershipPhase,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: RecoveryDigest,
    pub(super) durable_request_sha256: RecoveryDigest,
    pub(super) request_sha256: RecoveryDigest,
    pub(super) supervisor_capability_sha256: RecoveryDigest,
    pub(super) termination_fence_sha256: RecoveryDigest,
    pub(super) parent: ProcessIdentity,
    pub(super) supervisor: ProcessIdentity,
    pub(super) worker: ProcessIdentity,
    pub(super) cgroup: RetainedCgroupIdentity,
    pub(super) predecessor_sha256: RecoveryDigest,
    pub(super) state_sha256: RecoveryDigest,
    pub(super) operation_deadline: AbsoluteBoottimeDeadline,
    pub(super) cleanup_deadline: AbsoluteBoottimeDeadline,
    pub(super) watchdog_lease: Option<WatchdogLeaseIdentity>,
}

impl DurableOwnershipRecord {
    fn validate(&self) -> Result<(), RecoveryError> {
        self.registration.validate().map_err(|error| {
            protocol_error(
                error,
                "watchdog registration is invalid",
            )
        })?;
        self.signed_ownership_ack
            .validate_shape()
            .map_err(|error| {
                protocol_error(
                    error,
                    "signed watchdog ownership acknowledgement is invalid",
                )
            })?;
        self.signed_ownership_ack
            .ownership
            .validate_against_registration(&self.registration)
            .map_err(|error| {
                protocol_error(
                    error,
                    "durable watchdog ownership does not bind registration",
                )
            })?;
        if digest_is_zero(&self.ownership_id_sha256)
            || self.revision == 0
            || digest_is_zero(&self.operation_id_sha256)
            || digest_is_zero(&self.durable_request_sha256)
            || digest_is_zero(&self.request_sha256)
            || digest_is_zero(&self.supervisor_capability_sha256)
            || digest_is_zero(&self.termination_fence_sha256)
            || digest_is_zero(&self.predecessor_sha256)
            || digest_is_zero(&self.state_sha256)
            || self.operation_deadline.domain()
                != self.cleanup_deadline.domain()
            || self.operation_deadline.absolute_nanos()
                >= self.cleanup_deadline.absolute_nanos()
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
        {
            return Err(RecoveryError::Invalid(
                "ownership record is incomplete",
            ));
        }
        self.operation_deadline
            .domain()
            .require_current()
            .map_err(|_| {
                RecoveryError::Deadline(
                    "ownership BOOTTIME domain is not current",
                )
            })?;
        self.parent.validate().map_err(|error| {
            protocol_error(error, "parent process identity is invalid")
        })?;
        self.supervisor.validate().map_err(|error| {
            protocol_error(
                error,
                "supervisor process identity is invalid",
            )
        })?;
        self.worker.validate().map_err(|error| {
            protocol_error(error, "worker process identity is invalid")
        })?;
        self.cgroup.validate().map_err(|error| {
            protocol_error(
                error,
                "retained cgroup identity is invalid",
            )
        })?;
        match (&self.phase, &self.watchdog_lease) {
            (OwnershipPhase::Armed, None) => Ok(()),
            (
                OwnershipPhase::Reconciling | OwnershipPhase::Terminal,
                Some(lease),
            ) => lease.validate().map_err(|error| {
                protocol_error(error, "watchdog lease is invalid")
            }),
            _ => Err(RecoveryError::Invalid(
                "ownership phase and watchdog lease disagree",
            )),
        }
    }

    fn recovery_key(&self) -> RecoveryKey {
        RecoveryKey {
            operation_id_sha256: self.operation_id_sha256.clone(),
            durable_request_sha256:
                self.durable_request_sha256.clone(),
            termination_fence_sha256:
                self.termination_fence_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecoveryKey {
    pub(super) operation_id_sha256: RecoveryDigest,
    pub(super) durable_request_sha256: RecoveryDigest,
    pub(super) termination_fence_sha256: RecoveryDigest,
}

#[derive(Clone, Copy)]
pub(super) struct CurrentSignatureVerification<'a> {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256:
        &'a RecoveryDigest,
    pub(super) endpoint_generation: u64,
    pub(super) signing_key_id: &'a RecoveryDigest,
    pub(super) signing_key_spki_sha256: &'a RecoveryDigest,
    pub(super) trust_checkpoint_id_sha256:
        &'a RecoveryDigest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: &'a RecoveryDigest,
    pub(super) signature_domain: &'a [u8],
    pub(super) signature_payload: &'a [u8],
    pub(super) signature_base64: &'a str,
    pub(super) observed_at_boottime_nanos: u64,
}

#[derive(Clone, Copy)]
pub(super) struct CurrentCleanupAuthorityVerification<'a> {
    pub(super) authority_key_id: &'a RecoveryDigest,
    pub(super) authority_key_spki_sha256: &'a RecoveryDigest,
    pub(super) trust_checkpoint_id_sha256:
        &'a RecoveryDigest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: &'a RecoveryDigest,
    pub(super) signature_preimage: &'a [u8],
    pub(super) signature_base64: &'a str,
}

pub(super) trait CurrentSignatureAuthority:
    CurrentEndpointTrustProvider
{
    /// Verify against the currently authorized endpoint key and the current
    /// revocation checkpoint. Historical or merely pinned keys are rejected.
    fn try_verify_current_endpoint_signature_nonblocking(
        &mut self,
        request: CurrentSignatureVerification<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;

    /// Verify the cleanup authority signature against current key and
    /// revocation state before the one-use authorization is consumed.
    fn try_verify_current_cleanup_authority_nonblocking(
        &mut self,
        request: CurrentCleanupAuthorityVerification<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;
}

fn verify_current_endpoint_signature_pre_post<
    V: CurrentSignatureAuthority,
>(
    authority: &mut V,
    request: CurrentSignatureVerification<'_>,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    let progress_fd = authority.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        authority.try_verify_current_endpoint_signature_nonblocking(
            request,
            deadline,
        )
    })?;
    deadline.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "current-key checkpoint expired during verification",
        )
    })?;
    let progress_fd = authority.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        authority.try_verify_current_endpoint_signature_nonblocking(
            request,
            deadline,
        )
    })?;
    deadline.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "current-key checkpoint expired after verification",
        )
    })
}

fn verify_current_cleanup_authority_pre_post<
    V: CurrentSignatureAuthority,
>(
    authority: &mut V,
    request: CurrentCleanupAuthorityVerification<'_>,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    let progress_fd = authority.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        authority.try_verify_current_cleanup_authority_nonblocking(
            request,
            deadline,
        )
    })?;
    deadline.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "cleanup authority checkpoint expired during verification",
        )
    })?;
    let progress_fd = authority.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        authority.try_verify_current_cleanup_authority_nonblocking(
            request,
            deadline,
        )
    })?;
    deadline.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "cleanup authority checkpoint expired after verification",
        )
    })
}

fn expected_action_roles(
    action: CleanupAction,
) -> (
    PolicyCustodyEndpointRole,
    PolicyCustodyEndpointRole,
) {
    (
        action.required_executor_role(),
        action.required_endpoint_role(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExactCleanupBinding {
    pub(super) action: CleanupAction,
    pub(super) executor_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) operation: PolicyCustodyOperation,
    pub(super) operation_id_sha256: RecoveryDigest,
    pub(super) durable_request_sha256: RecoveryDigest,
    pub(super) request_sha256: RecoveryDigest,
    pub(super) termination_fence_sha256: RecoveryDigest,
    pub(super) cgroup: RetainedCgroupIdentity,
    pub(super) predecessor: CleanupPredecessor,
    pub(super) authorization_nonce_sha256: RecoveryDigest,
    pub(super) operation_deadline: ProtocolBoottimeDeadline,
    pub(super) cleanup_deadline: ProtocolBoottimeDeadline,
}

impl ExactCleanupBinding {
    fn validate(
        &self,
        owner: &DurableOwnershipRecord,
        queried_predecessor: &CleanupPredecessor,
        passed_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        let (executor_role, endpoint_role) =
            expected_action_roles(self.action);
        require_exact_deadline(
            passed_deadline,
            &owner.cleanup_deadline,
        )?;
        if self.executor_role != executor_role
            || self.endpoint_role != endpoint_role
            || self.operation != owner.operation
            || self.operation_id_sha256
                != owner.operation_id_sha256
            || self.durable_request_sha256
                != owner.durable_request_sha256
            || self.request_sha256 != owner.request_sha256
            || self.termination_fence_sha256
                != owner.termination_fence_sha256
            || self.cgroup != owner.cgroup
            || &self.predecessor != queried_predecessor
            || !self
                .action
                .accepts_predecessor_phase(
                    self.predecessor.phase,
                )
            || digest_is_zero(&self.authorization_nonce_sha256)
            || self.operation_deadline
                != ProtocolBoottimeDeadline::from_runtime(
                    owner.operation_deadline,
                )
            || self.cleanup_deadline
                != ProtocolBoottimeDeadline::from_runtime(
                    owner.cleanup_deadline,
                )
        {
            return Err(RecoveryError::Authorization(
                "cleanup authorization v3 exact binding mismatch",
            ));
        }
        self.cgroup.validate()
    }

    fn validate_authorization(
        &self,
        authorization: &SignedCleanupAuthorizationV3,
    ) -> Result<(), RecoveryError> {
        authorization.validate_shape().map_err(|error| {
            protocol_error(
                error,
                "cleanup authorization shape is invalid",
            )
        })?;
        let payload = &authorization.payload;
        if payload.api_version
                != POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
            || payload.action != self.action
            || payload.executor_role != self.executor_role
            || payload.endpoint_role != self.endpoint_role
            || payload.operation != self.operation
            || payload.operation_id_sha256
                != self.operation_id_sha256
            || payload.durable_request_sha256
                != self.durable_request_sha256
            || payload.request_sha256 != self.request_sha256
            || payload.fence_token_sha256
                != self.termination_fence_sha256
            || payload.cgroup_identity != self.cgroup.protocol
            || payload.predecessor != self.predecessor
            || payload.authorization_nonce_sha256
                != self.authorization_nonce_sha256
            || payload.operation_deadline != self.operation_deadline
            || payload.absolute_boottime_deadline
                != self.cleanup_deadline
        {
            return Err(RecoveryError::Authorization(
                "cleanup authorization payload changed the exact binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthorizedCleanupStep {
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(super) binding: ExactCleanupBinding,
    pub(super) expected_consumption_sequence: u64,
    pub(super) expected_consumption_predecessor_receipt_sha256:
        RecoveryDigest,
    pub(super) expected_result_sequence: u64,
    pub(super) trace_requests: CleanupTraceRequestBindings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CleanupTraceRequestBindings {
    pub(super) before_query_nonce_sha256: RecoveryDigest,
    pub(super) before_query_request_sha256: RecoveryDigest,
    pub(super) cas_nonce_sha256: RecoveryDigest,
    pub(super) cas_request_sha256: RecoveryDigest,
    pub(super) after_query_nonce_sha256: RecoveryDigest,
    pub(super) after_query_request_sha256: RecoveryDigest,
}

impl CleanupTraceRequestBindings {
    fn validate(&self) -> Result<(), RecoveryError> {
        if digest_is_zero(&self.before_query_nonce_sha256)
            || digest_is_zero(&self.before_query_request_sha256)
            || digest_is_zero(&self.cas_nonce_sha256)
            || digest_is_zero(&self.cas_request_sha256)
            || digest_is_zero(&self.after_query_nonce_sha256)
            || digest_is_zero(&self.after_query_request_sha256)
            || self.before_query_nonce_sha256
                == self.cas_nonce_sha256
            || self.before_query_nonce_sha256
                == self.after_query_nonce_sha256
            || self.cas_nonce_sha256
                == self.after_query_nonce_sha256
            || self.before_query_request_sha256
                == self.cas_request_sha256
            || self.before_query_request_sha256
                == self.after_query_request_sha256
            || self.cas_request_sha256
                == self.after_query_request_sha256
        {
            return Err(RecoveryError::Authorization(
                "cleanup Query/CAS/Query request bindings are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnverifiedSignedEndpointResponse<R> {
    pub(super) response: R,
    pub(super) envelope: SignedEndpointResponseEnvelope,
    pub(super) exact_canonical_response: Box<[u8]>,
    pub(super) exact_signature_payload: Box<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnverifiedCleanupAuthorizationConsumption {
    pub(super) before:
        UnverifiedSignedEndpointResponse<CleanupConsumptionQueryReply>,
    pub(super) compare_and_swap:
        UnverifiedSignedEndpointResponse<CleanupConsumptionCasReply>,
    pub(super) after:
        UnverifiedSignedEndpointResponse<CleanupConsumptionQueryReply>,
    pub(super) persisted:
        PersistedCleanupAuthorizationConsumptionV3,
    pub(super) exact_signature_payload: Box<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedCleanupAuthorizationConsumption {
    evidence: UnverifiedCleanupAuthorizationConsumption,
}

pub(super) type UnverifiedSignedCleanupResult =
    SignedCleanupResultV3;
pub(super) type UnverifiedDurableCleanupEffectEvidence =
    DurableCleanupEffectEvidenceV3;

/// Private fields prevent construction without the verifier below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedCleanupResult {
    binding: ExactCleanupBinding,
    consumption: VerifiedCleanupAuthorizationConsumption,
    result: UnverifiedSignedCleanupResult,
    durable_effect: UnverifiedDurableCleanupEffectEvidence,
}

impl VerifiedCleanupResult {
    pub(super) fn action(&self) -> CleanupAction {
        self.binding.action
    }

    pub(super) fn result_receipt_sha256(&self) -> &RecoveryDigest {
        &self.result.result_receipt_sha256
    }

    pub(super) fn signed_result(&self) -> &SignedCleanupResultV3 {
        &self.result
    }

    pub(super) fn durable_effect(
        &self,
    ) -> &UnverifiedDurableCleanupEffectEvidence {
        &self.durable_effect
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredCleanupEvidence {
    pub(super) authorization: SignedCleanupAuthorizationV3,
    pub(super) binding: ExactCleanupBinding,
    pub(super) expected_consumption_sequence: u64,
    pub(super) expected_consumption_predecessor_receipt_sha256:
        RecoveryDigest,
    pub(super) expected_result_sequence: u64,
    pub(super) trace_requests: CleanupTraceRequestBindings,
    pub(super) consumption:
        UnverifiedCleanupAuthorizationConsumption,
    pub(super) result: UnverifiedSignedCleanupResult,
    pub(super) durable_effect:
        UnverifiedDurableCleanupEffectEvidence,
}

fn verify_signed_endpoint_response<
    R: Serialize,
    V: CurrentSignatureAuthority,
>(
    authority: &mut V,
    evidence: &UnverifiedSignedEndpointResponse<R>,
    endpoint_role: PolicyCustodyEndpointRole,
    request_nonce_sha256: &RecoveryDigest,
    request_sha256: &RecoveryDigest,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    require_exact_deadline(deadline, deadline)?;
    evidence.envelope.validate_shape().map_err(|error| {
        protocol_error(
            error,
            "cleanup trace response envelope is invalid",
        )
    })?;
    let canonical_response =
        canonical_json_bytes(&evidence.response).map_err(|_| {
            RecoveryError::Authorization(
                "cleanup trace response is noncanonical",
            )
        })?;
    let signature_payload = evidence
        .envelope
        .canonical_signature_payload()
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup trace signature payload is invalid",
            )
        })?;
    if evidence.envelope.endpoint_role != endpoint_role
        || &evidence.envelope.request_nonce_sha256
            != request_nonce_sha256
        || &evidence.envelope.request_sha256 != request_sha256
        || evidence.envelope.response_sha256
            != endpoint_response_sha256(&canonical_response)
        || evidence.envelope.canonical_response_base64
            != URL_SAFE_NO_PAD.encode(&canonical_response)
        || evidence.exact_canonical_response.as_ref()
            != canonical_response.as_slice()
        || evidence.exact_signature_payload.as_ref()
            != signature_payload.as_slice()
        || evidence.exact_signature_payload.len()
            > MAX_SIGNED_EVIDENCE_BYTES
        || evidence.envelope.observed_at_boottime_nanos == 0
        || evidence.envelope.observed_at_boottime_nanos
            >= deadline.absolute_nanos()
    {
        return Err(RecoveryError::Authorization(
            "cleanup trace response binding mismatch",
        ));
    }
    verify_current_endpoint_signature_pre_post(
        authority,
        CurrentSignatureVerification {
            endpoint_role,
            endpoint_process_identity_sha256:
                &evidence
                    .envelope
                    .endpoint_process_identity_sha256,
            endpoint_generation: evidence.envelope.endpoint_generation,
            signing_key_id: &evidence.envelope.signing_key_id,
            signing_key_spki_sha256:
                &evidence.envelope.signing_key_spki_sha256,
            trust_checkpoint_id_sha256:
                &evidence
                    .envelope
                    .current_key_authorization_checkpoint_sha256,
            revocation_generation:
                evidence.envelope.revocation_generation,
            revocation_root_sha256:
                &evidence.envelope.revocation_root_sha256,
            signature_domain: endpoint_role.response_signature_domain(),
            signature_payload:
                evidence.exact_signature_payload.as_ref(),
            signature_base64: &evidence.envelope.signature_base64,
            observed_at_boottime_nanos:
                evidence.envelope.observed_at_boottime_nanos,
        },
        deadline,
    )
}

fn verify_cleanup_consumption<V: CurrentSignatureAuthority>(
    authority: &mut V,
    authorization: &SignedCleanupAuthorizationV3,
    binding: &ExactCleanupBinding,
    expected_sequence: u64,
    expected_predecessor_receipt_sha256: &RecoveryDigest,
    trace_requests: &CleanupTraceRequestBindings,
    evidence: UnverifiedCleanupAuthorizationConsumption,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<VerifiedCleanupAuthorizationConsumption, RecoveryError> {
    let statement = &evidence.persisted.statement;
    let signed = &evidence.persisted.signed_envelope;
    require_exact_deadline(
        deadline,
        &statement
            .absolute_boottime_deadline
            .to_runtime()
            .map_err(|error| {
                protocol_error(
                    error,
                    "cleanup consumption deadline is invalid",
                )
            })?,
    )?;
    binding.validate_authorization(authorization)?;
    trace_requests.validate()?;
    verify_signed_endpoint_response(
        authority,
        &evidence.before,
        binding.endpoint_role,
        &trace_requests.before_query_nonce_sha256,
        &trace_requests.before_query_request_sha256,
        deadline,
    )?;
    verify_signed_endpoint_response(
        authority,
        &evidence.compare_and_swap,
        binding.endpoint_role,
        &trace_requests.cas_nonce_sha256,
        &trace_requests.cas_request_sha256,
        deadline,
    )?;
    verify_signed_endpoint_response(
        authority,
        &evidence.after,
        binding.endpoint_role,
        &trace_requests.after_query_nonce_sha256,
        &trace_requests.after_query_request_sha256,
        deadline,
    )?;
    evidence
        .persisted
        .validate_cleanup_exact_bytes(
            binding.endpoint_role,
            Some(authorization),
        )
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup consumption is not the canonical persisted durable-consume receipt",
            )
        })?;
    statement
        .validate_against(authorization)
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup consumption statement binding mismatch",
            )
        })?;
    let authority_preimage = authorization
        .authority_signature_preimage()
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup authority signature preimage is invalid",
            )
        })?;
    verify_current_cleanup_authority_pre_post(
        authority,
        CurrentCleanupAuthorityVerification {
            authority_key_id: &authorization.authority_key_id,
            authority_key_spki_sha256:
                &authorization.authority_key_spki_sha256,
            trust_checkpoint_id_sha256:
                &authorization
                    .current_key_authorization_checkpoint_sha256,
            revocation_generation:
                authorization.revocation_generation,
            revocation_root_sha256:
                &authorization.revocation_root_sha256,
            signature_preimage: &authority_preimage,
            signature_base64:
                &authorization.authority_signature_base64,
        },
        deadline,
    )?;

    let canonical_statement =
        &evidence.persisted.exact_canonical_statement_bytes;
    let signature_payload = signed
        .canonical_signature_payload()
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup consumption signature payload is invalid",
            )
        })?;
    signed.validate_shape().map_err(|error| {
        protocol_error(
            error,
            "cleanup consumption receipt digest is invalid",
        )
    })?;
    let before_consumption =
        evidence.before.response.authoritative_consumption.as_ref();
    let after_consumption =
        evidence.after.response.authoritative_consumption.as_ref();
    let before_observed =
        evidence.before.envelope.observed_at_boottime_nanos;
    let cas_observed = evidence
        .compare_and_swap
        .envelope
        .observed_at_boottime_nanos;
    let after_observed =
        evidence.after.envelope.observed_at_boottime_nanos;
    let disposition_matches = match &evidence.compare_and_swap.response {
        CleanupConsumptionCasReply::Applied {
            consumption,
            ..
        } => {
            before_consumption.is_none()
                && consumption == &evidence.persisted
                && before_observed
                    <= statement.consumed_at_boottime_nanos
        }
        CleanupConsumptionCasReply::AlreadyApplied {
            consumption,
            ..
        } => {
            before_consumption == Some(&evidence.persisted)
                && consumption == &evidence.persisted
        }
        CleanupConsumptionCasReply::Conflict { .. } => false,
    };
    if expected_sequence == 0
        || statement.consumer_sequence != expected_sequence
        || &statement.predecessor_receipt_sha256
            != expected_predecessor_receipt_sha256
        || !disposition_matches
        || after_consumption != Some(&evidence.persisted)
        || before_observed > cas_observed
        || cas_observed > after_observed
        || statement.consumed_at_boottime_nanos
            > cas_observed
        || statement.consumed_at_boottime_nanos
            < binding
                .operation_deadline
                .absolute_boottime_nanos()
        || statement.consumed_at_boottime_nanos
            >= binding.cleanup_deadline.absolute_boottime_nanos()
        || !statement.occurred_before_cleanup_deadline
        || signed.statement_sha256
            != super::protocol::endpoint_receipt_statement_sha256(
                canonical_statement,
            )
        || signed.endpoint_role != binding.endpoint_role
        || signed.canonical_statement_base64
            != URL_SAFE_NO_PAD.encode(&canonical_statement)
        || evidence
            .persisted
            .exact_canonical_statement_bytes
            .as_slice()
            != canonical_statement.as_slice()
        || evidence.exact_signature_payload.as_ref()
            != signature_payload.as_slice()
        || evidence.exact_signature_payload.len()
            > MAX_SIGNED_EVIDENCE_BYTES
        || signed.signature_base64.is_empty()
        || digest_is_zero(
            &signed.endpoint_process_identity_sha256,
        )
        || digest_is_zero(&signed.signing_key_id)
        || digest_is_zero(
            &signed.signing_key_spki_sha256,
        )
        || signed.endpoint_generation == 0
        || signed.endpoint_generation != statement.consumer_generation
        || digest_is_zero(
            &signed
                .current_key_authorization_checkpoint_sha256,
        )
        || signed.revocation_generation == 0
        || digest_is_zero(
            &signed.revocation_root_sha256,
        )
    {
        return Err(RecoveryError::Authorization(
            "cleanup authorization consumption is not exact and durable",
        ));
    }
    verify_current_endpoint_signature_pre_post(
        authority,
        CurrentSignatureVerification {
            endpoint_role: binding.endpoint_role,
            endpoint_process_identity_sha256:
                &signed.endpoint_process_identity_sha256,
            endpoint_generation: signed.endpoint_generation,
            signing_key_id: &signed.signing_key_id,
            signing_key_spki_sha256:
                &signed.signing_key_spki_sha256,
            trust_checkpoint_id_sha256:
                &signed
                    .current_key_authorization_checkpoint_sha256,
            revocation_generation:
                signed.revocation_generation,
            revocation_root_sha256:
                &signed.revocation_root_sha256,
            signature_domain:
                binding.endpoint_role.receipt_signature_domain(),
            signature_payload:
                evidence.exact_signature_payload.as_ref(),
            signature_base64: &signed.signature_base64,
            observed_at_boottime_nanos:
                statement.consumed_at_boottime_nanos,
        },
        deadline,
    )?;
    Ok(VerifiedCleanupAuthorizationConsumption { evidence })
}

fn verify_cleanup_result<V: CurrentSignatureAuthority>(
    authority: &mut V,
    owner: &DurableOwnershipRecord,
    binding: ExactCleanupBinding,
    consumption: VerifiedCleanupAuthorizationConsumption,
    expected_result_sequence: u64,
    durable_effect: UnverifiedDurableCleanupEffectEvidence,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<VerifiedCleanupResult, RecoveryError> {
    require_exact_deadline(deadline, &owner.cleanup_deadline)?;
    durable_effect.validate().map_err(|error| {
        protocol_error(
            error,
            "durable cleanup effect evidence is invalid",
        )
    })?;
    let persisted_intent = &durable_effect.intent;
    let persisted_execution = &durable_effect.execution;
    if persisted_intent.intent.action != binding.action
        || persisted_intent.intent.operation != binding.operation
        || persisted_intent.intent.operation_id_sha256
            != binding.operation_id_sha256
        || persisted_intent.intent.durable_request_sha256
            != binding.durable_request_sha256
        || persisted_intent.intent.request_sha256
            != binding.request_sha256
        || persisted_intent.intent.termination_fence_sha256
            != binding.termination_fence_sha256
        || persisted_intent.intent.predecessor
            != binding.predecessor
        || persisted_intent.intent.operation_deadline
            != binding.operation_deadline
        || persisted_intent.intent.cleanup_deadline
            != binding.cleanup_deadline
        || persisted_intent.intent.authorization_consumption
            != consumption.evidence.persisted
        || persisted_intent.intent.expected_result_sequence
            != expected_result_sequence
        || persisted_intent.endpoint_process_identity_sha256
            != persisted_execution.endpoint_process_identity_sha256
        || persisted_intent.endpoint_generation
            != persisted_execution.endpoint_generation
        || persisted_intent.helper_generation
            != persisted_execution.helper_generation
        || persisted_intent.signing_key_id
            != persisted_execution.signing_key_id
        || persisted_intent.signing_key_spki_sha256
            != persisted_execution.signing_key_spki_sha256
        || persisted_intent
            .current_key_authorization_checkpoint_sha256
            != persisted_execution
                .current_key_authorization_checkpoint_sha256
        || persisted_intent.revocation_generation
            != persisted_execution.revocation_generation
        || persisted_intent.revocation_root_sha256
            != persisted_execution.revocation_root_sha256
    {
        return Err(RecoveryError::Cleanup(
            "durable cleanup effect does not bind the verified authorization, target, operation, fence, deadlines, sequence, and helper authority",
        ));
    }
    let intent_signature_payload = persisted_intent
        .canonical_signature_payload()
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup effect intent signature payload is invalid",
            )
        })?;
    verify_current_endpoint_signature_pre_post(
        authority,
        CurrentSignatureVerification {
            endpoint_role: binding.endpoint_role,
            endpoint_process_identity_sha256:
                &persisted_intent
                    .endpoint_process_identity_sha256,
            endpoint_generation:
                persisted_intent.endpoint_generation,
            signing_key_id: &persisted_intent.signing_key_id,
            signing_key_spki_sha256:
                &persisted_intent.signing_key_spki_sha256,
            trust_checkpoint_id_sha256: &persisted_intent
                .current_key_authorization_checkpoint_sha256,
            revocation_generation:
                persisted_intent.revocation_generation,
            revocation_root_sha256:
                &persisted_intent.revocation_root_sha256,
            signature_domain: CLEANUP_INTENT_SIGNATURE_DOMAIN,
            signature_payload: &intent_signature_payload,
            signature_base64: &persisted_intent.signature_base64,
            observed_at_boottime_nanos:
                persisted_intent.persisted_at_boottime_nanos,
        },
        deadline,
    )?;
    let execution_signature_payload = persisted_execution
        .canonical_signature_payload()
        .map_err(|error| {
            protocol_error(
                error,
                "cleanup execution signature payload is invalid",
            )
        })?;
    verify_current_endpoint_signature_pre_post(
        authority,
        CurrentSignatureVerification {
            endpoint_role: binding.endpoint_role,
            endpoint_process_identity_sha256:
                &persisted_execution
                    .endpoint_process_identity_sha256,
            endpoint_generation:
                persisted_execution.endpoint_generation,
            signing_key_id:
                &persisted_execution.signing_key_id,
            signing_key_spki_sha256:
                &persisted_execution.signing_key_spki_sha256,
            trust_checkpoint_id_sha256: &persisted_execution
                .current_key_authorization_checkpoint_sha256,
            revocation_generation:
                persisted_execution.revocation_generation,
            revocation_root_sha256:
                &persisted_execution.revocation_root_sha256,
            signature_domain:
                CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
            signature_payload: &execution_signature_payload,
            signature_base64:
                &persisted_execution.signature_base64,
            observed_at_boottime_nanos:
                persisted_execution.entered_at_boottime_nanos,
        },
        deadline,
    )?;
    let result = durable_effect.result.signed_result.clone();
    result.validate_shape().map_err(|error| {
        protocol_error(
            error,
            "signed cleanup result shape is invalid",
        )
    })?;
    let payload = &result.payload;
    let consumed = &consumption.evidence;
    let canonical =
        canonical_json_bytes(payload).map_err(|_| {
            RecoveryError::Authorization(
                "cleanup result payload is noncanonical",
            )
        })?;
    let expected_receipt = canonical_digest(
        CLEANUP_RESULT_RECEIPT_DOMAIN,
        &(CLEANUP_RESULT_SIGNATURE_DOMAIN, &canonical, result.signature_base64.as_bytes()),
    )?;
    let worker_observation_valid = match (
        binding.action,
        &payload.worker_observation,
    ) {
        (
            CleanupAction::ReapWorker,
            WorkerPidfdObservation::Reaped {
                reap_observation_sha256,
                reaped_at_boottime_nanos,
                ..
            },
        ) => {
            !digest_is_zero(reap_observation_sha256)
                && *reaped_at_boottime_nanos
                    >= consumed
                        .persisted
                        .statement
                        .consumed_at_boottime_nanos
                && *reaped_at_boottime_nanos
                    < owner.cleanup_deadline.absolute_nanos()
        }
        (CleanupAction::ReapWorker, _) => false,
        (_, WorkerPidfdObservation::NotObserved) => true,
        _ => false,
    };
    let cgroup_observation_valid = match (
        binding.action,
        &payload.cgroup_observation,
    ) {
        (
            CleanupAction::KillCgroup,
            CgroupPopulationObservation::Empty {
                cgroup_events_sha256,
                observed_at_boottime_nanos,
            },
        ) => {
            !digest_is_zero(cgroup_events_sha256)
                && *observed_at_boottime_nanos
                    >= consumed
                        .persisted
                        .statement
                        .consumed_at_boottime_nanos
                && *observed_at_boottime_nanos
                    < owner.cleanup_deadline.absolute_nanos()
        }
        (CleanupAction::KillCgroup, _) => false,
        (_, CgroupPopulationObservation::NotObserved) => true,
        _ => false,
    };
    if payload.api_version != VERIFIED_CLEANUP_EVIDENCE_VERSION
        || payload.action != binding.action
        || payload.executor_role != binding.executor_role
        || payload.endpoint_role != binding.endpoint_role
        || payload.operation != binding.operation
        || payload.operation_id_sha256
            != binding.operation_id_sha256
        || payload.durable_request_sha256
            != binding.durable_request_sha256
        || payload.request_sha256 != binding.request_sha256
        || payload.termination_fence_sha256
            != binding.termination_fence_sha256
        || payload.predecessor != binding.predecessor
        || payload.authorization_nonce_sha256
            != binding.authorization_nonce_sha256
        || payload.authorization_sha256
            != consumed.persisted.statement.authorization_sha256
        || payload.authorization_consumption_receipt_sha256
            != consumed.persisted.signed_envelope.envelope_sha256
        || payload.authorization_consumption_sequence
            != consumed.persisted.statement.consumer_sequence
        || payload.worker_pidfd_identity != owner.worker
        || payload.cgroup_fd_identity != owner.cgroup
        || payload.operation_deadline != binding.operation_deadline
        || payload.cleanup_deadline != binding.cleanup_deadline
        || payload.observed_at_boottime_nanos
            < consumed
                .persisted
                .statement
                .consumed_at_boottime_nanos
        || payload.observed_at_boottime_nanos
            >= owner.cleanup_deadline.absolute_nanos()
        || payload.result_sequence != expected_result_sequence
        || expected_result_sequence == 0
        || payload.endpoint_generation == 0
        || digest_is_zero(
            &payload.endpoint_process_identity_sha256,
        )
        || digest_is_zero(&payload.signing_key_id)
        || digest_is_zero(&payload.signing_key_spki_sha256)
        || digest_is_zero(&payload.trust_checkpoint_id_sha256)
        || payload.revocation_generation == 0
        || digest_is_zero(&payload.revocation_root_sha256)
        || !worker_observation_valid
        || !cgroup_observation_valid
        || result.exact_canonical_payload.as_ref()
            != canonical.as_slice()
        || result.exact_canonical_payload.len()
            > MAX_SIGNED_EVIDENCE_BYTES
        || result.signature_base64.is_empty()
        || result.result_receipt_sha256 != expected_receipt
    {
        return Err(RecoveryError::Cleanup(
            "signed cleanup result does not bind the exact observed result",
        ));
    }
    verify_current_endpoint_signature_pre_post(
        authority,
        CurrentSignatureVerification {
            endpoint_role: payload.endpoint_role,
            endpoint_process_identity_sha256:
                &payload.endpoint_process_identity_sha256,
            endpoint_generation: payload.endpoint_generation,
            signing_key_id: &payload.signing_key_id,
            signing_key_spki_sha256:
                &payload.signing_key_spki_sha256,
            trust_checkpoint_id_sha256:
                &payload.trust_checkpoint_id_sha256,
            revocation_generation: payload.revocation_generation,
            revocation_root_sha256:
                &payload.revocation_root_sha256,
            signature_domain: CLEANUP_RESULT_SIGNATURE_DOMAIN,
            signature_payload:
                result.exact_canonical_payload.as_ref(),
            signature_base64: &result.signature_base64,
            observed_at_boottime_nanos:
                payload.observed_at_boottime_nanos,
        },
        deadline,
    )?;
    Ok(VerifiedCleanupResult {
        binding,
        consumption,
        result,
        durable_effect,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CleanupProofBundle {
    actions: Vec<VerifiedCleanupResult>,
}

impl CleanupProofBundle {
    fn push(
        &mut self,
        proof: VerifiedCleanupResult,
    ) -> Result<(), RecoveryError> {
        if self.actions.len() >= ABSOLUTE_MAX_CLEANUP_ACTIONS {
            return Err(RecoveryError::Invalid(
                "cleanup proof bundle exceeds its fixed bound",
            ));
        }
        if self.actions.iter().any(|existing| {
            existing.binding.authorization_nonce_sha256
                == proof.binding.authorization_nonce_sha256
                || existing.result.payload.result_sequence
                    == proof.result.payload.result_sequence
        }) {
            return Err(RecoveryError::Authorization(
                "cleanup proof bundle reuses a nonce or result sequence",
            ));
        }
        self.actions.push(proof);
        Ok(())
    }

    fn prove_terminal_cleanup(&self) -> Result<(), RecoveryError> {
        self.actions
            .iter()
            .find(|proof| {
                proof.binding.action == CleanupAction::ReapWorker
                    && matches!(
                        proof.result.payload.worker_observation,
                        WorkerPidfdObservation::Reaped { .. }
                    )
            })
            .ok_or(RecoveryError::Cleanup(
                "terminal cleanup lacks signed exact-pidfd reap evidence",
            ))?;
        self.actions
            .iter()
            .find(|proof| {
                proof.binding.action == CleanupAction::KillCgroup
                    && matches!(
                        proof.result.payload.cgroup_observation,
                        CgroupPopulationObservation::Empty { .. }
                    )
            })
            .ok_or(RecoveryError::Cleanup(
                "terminal cleanup lacks signed exact-cgroup empty evidence",
            ))?;
        Ok(())
    }

    fn prove_result_aborted(
        &self,
    ) -> Result<&VerifiedCleanupResult, RecoveryError> {
        if self.actions.len() != 1
            || self.actions[0].binding.action
                != CleanupAction::CommitResultAborted
            || !matches!(
                self.actions[0].result.payload.worker_observation,
                WorkerPidfdObservation::NotObserved
            )
            || !matches!(
                self.actions[0].result.payload.cgroup_observation,
                CgroupPopulationObservation::NotObserved
            )
        {
            return Err(RecoveryError::Cleanup(
                "Preflighted recovery requires exactly one verified CommitResultAborted action",
            ));
        }
        if digest_is_zero(
            self.actions[0].result_receipt_sha256(),
        ) {
            return Err(RecoveryError::Cleanup(
                "CommitResultAborted lacks a signed abort receipt",
            ));
        }
        Ok(&self.actions[0])
    }

    pub(super) fn actions(&self) -> &[VerifiedCleanupResult] {
        &self.actions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CasDisposition {
    Applied,
    AlreadyApplied,
    Conflict,
}

pub(super) struct CasTransitionResult<R> {
    pub(super) disposition: CasDisposition,
    pub(super) authoritative_state: R,
}

pub(super) struct RecoveryScanPage<R> {
    pub(super) records: Vec<R>,
    pub(super) continuation: Option<RecoveryDigest>,
}

pub(super) trait RecoveryProtocol {
    type SettlementRecord: Clone;
    type SettlementTransition;

    fn progress_fd(&self) -> BorrowedFd<'_>;

    fn try_validate_settlement_nonblocking(
        &self,
        key: &RecoveryKey,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;

    fn try_phase_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<DurableRecoveryPhase>, RecoveryError>;

    fn try_state_sha256_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<RecoveryDigest>, RecoveryError>;

    fn try_revision_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError>;

    fn try_settlement_identity_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<SettlementIdentity>, RecoveryError>;

    fn try_result_binding_sha256_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<RecoveryDigest>, RecoveryError>;

    fn try_queried_predecessor_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<CleanupPredecessor>, RecoveryError>;

    fn try_independent_durable_consumes_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<Option<IndependentDurableConsumeEvidence>>,
        RecoveryError,
    >;

    fn try_cleanup_plan_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        record: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Vec<AuthorizedCleanupStep>>, RecoveryError>;

    fn try_stored_cleanup_evidence_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Vec<StoredCleanupEvidence>>, RecoveryError>;

    /// Prove that the cleanup authorization's exact predecessor is present in
    /// the validated durable chain ending at `record`.
    fn try_validate_cleanup_predecessor_in_chain_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        predecessor: &CleanupPredecessor,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;

    fn try_build_one_transition_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        current: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        durable_consumes:
            Option<&VerifiedIndependentDurableConsumes>,
        signed_result_aborted:
            Option<&VerifiedCleanupResult>,
        cleanup_proofs: &CleanupProofBundle,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Self::SettlementTransition>, RecoveryError>;

    fn try_validate_successor_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        previous: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        observed: &Self::SettlementRecord,
        signed_result_aborted:
            Option<&VerifiedCleanupResult>,
        cleanup_proofs: &CleanupProofBundle,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;
}

fn drive_protocol_nonblocking<P, T>(
    protocol: &P,
    deadline: &AbsoluteBoottimeDeadline,
    mut attempt: impl FnMut(&P) -> Result<Option<T>, RecoveryError>,
) -> Result<T, RecoveryError>
where
    P: RecoveryProtocol,
{
    let progress_fd = protocol.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        attempt(protocol)
    })
}

pub(super) trait DurableRecoveryStore<P: RecoveryProtocol> {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    fn try_scan_incomplete_ownership_nonblocking(
        &mut self,
        continuation: Option<RecoveryDigest>,
        maximum_records: usize,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<RecoveryScanPage<DurableOwnershipRecord>>,
        RecoveryError,
    >;

    fn try_query_ownership_nonblocking(
        &mut self,
        ownership_id_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Option<DurableOwnershipRecord>>, RecoveryError>;

    fn try_cas_ownership_reconciling_nonblocking(
        &mut self,
        expected: &DurableOwnershipRecord,
        watchdog_lease: &WatchdogLeaseIdentity,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<DurableOwnershipRecord>>,
        RecoveryError,
    >;

    fn try_cas_ownership_terminal_nonblocking(
        &mut self,
        expected: &DurableOwnershipRecord,
        watchdog_lease: &WatchdogLeaseIdentity,
        settlement_state_sha256: RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<DurableOwnershipRecord>>,
        RecoveryError,
    >;

    fn try_query_settlement_nonblocking(
        &mut self,
        key: &RecoveryKey,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Option<P::SettlementRecord>>, RecoveryError>;

    fn try_cas_one_settlement_transition_nonblocking(
        &mut self,
        key: &RecoveryKey,
        expected_revision: u64,
        expected_state_sha256: RecoveryDigest,
        transition: &P::SettlementTransition,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<P::SettlementRecord>>,
        RecoveryError,
    >;
}

pub(super) trait RecoveryRuntimeMaterialStore:
    DurableRecoveryStore<TrustedHostRecoveryProtocol>
{
    fn try_recovery_runtime_material_nonblocking(
        &mut self,
        ownership_id_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<Option<
            super::services::RecoveryRuntimeMaterialV3,
        >>,
        RecoveryError,
    >;
}

pub(super) trait CleanupAuthorizationConsumer {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Consume the exact nonce durably and return the signed endpoint receipt.
    /// Verification remains local to this module.
    fn try_consume_exact_v3_nonblocking(
        &mut self,
        authorization: &SignedCleanupAuthorizationV3,
        trace_requests: &CleanupTraceRequestBindings,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<UnverifiedCleanupAuthorizationConsumption>,
        RecoveryError,
    >;
}

pub(super) struct CleanupTarget {
    pub(super) worker_pidfd: OwnedFd,
    pub(super) operation_cgroup_fd: OwnedFd,
    pub(super) worker: ProcessIdentity,
    pub(super) cgroup: RetainedCgroupIdentity,
}

pub(super) trait RecoveryTargetProvider {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Return duplicates of descriptors inherited at watchdog launch or
    /// received over an authenticated descriptor channel. Numeric PID or path
    /// reconstruction is forbidden.
    fn try_cleanup_target_nonblocking(
        &mut self,
        owner: &DurableOwnershipRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<CleanupTarget>, RecoveryError>;
}

pub(super) trait BoundedCleanupHelper {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Use a retained executable FD and `clone3(CLONE_PIDFD)`, kill on the
    /// exact deadline, and reap the exact helper pidfd before returning.
    fn try_execute_exact_nonblocking(
        &mut self,
        target: &CleanupTarget,
        binding: &ExactCleanupBinding,
        consumption_receipt_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<UnverifiedDurableCleanupEffectEvidence>,
        RecoveryError,
    >;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WatchdogPollEvents {
    pub(super) parent_exited: bool,
    pub(super) supervisor_exited: bool,
    pub(super) worker_exited: bool,
    pub(super) watchdog_exited: bool,
    pub(super) heartbeat_readable: bool,
    pub(super) timer_expired: bool,
}

#[derive(Clone, Copy)]
pub(super) struct WatchdogPollDescriptors<'a> {
    pub(super) parent_pidfd: BorrowedFd<'a>,
    pub(super) supervisor_pidfd: BorrowedFd<'a>,
    pub(super) worker_pidfd: BorrowedFd<'a>,
    pub(super) watchdog_pidfd: Option<BorrowedFd<'a>>,
    pub(super) heartbeat_eventfd: BorrowedFd<'a>,
}

pub(super) trait BoottimeWatchdogPoller {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Attempt one nonblocking observation of the retained pidfds, eventfd,
    /// and absolute `CLOCK_BOOTTIME` timer.
    fn try_poll_nonblocking(
        &mut self,
        descriptors: WatchdogPollDescriptors<'_>,
        wake_at_boottime_nanos: u64,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<WatchdogPollEvents>, RecoveryError>;

    fn try_now_boottime_nanos_nonblocking(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError>;
}

pub(super) trait HeartbeatEvent {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    fn try_drain_counter_delta_nonblocking(
        &mut self,
        heartbeat_eventfd: BorrowedFd<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError>;

    fn try_publish_tick_nonblocking(
        &mut self,
        heartbeat_eventfd: BorrowedFd<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError>;
}

fn poll_watchdog_until<B: BoottimeWatchdogPoller>(
    poller: &mut B,
    descriptors: WatchdogPollDescriptors<'_>,
    wake_at_boottime_nanos: u64,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<WatchdogPollEvents, RecoveryError> {
    let progress_fd = poller.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        poller.try_poll_nonblocking(
            descriptors,
            wake_at_boottime_nanos,
            deadline,
        )
    })
}

fn read_boottime_now<B: BoottimeWatchdogPoller>(
    poller: &mut B,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<u64, RecoveryError> {
    let progress_fd = poller.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        poller.try_now_boottime_nanos_nonblocking(deadline)
    })
}

fn drain_heartbeat_until<E: HeartbeatEvent>(
    heartbeat: &mut E,
    heartbeat_eventfd: BorrowedFd<'_>,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<u64, RecoveryError> {
    let progress_fd = heartbeat.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        heartbeat.try_drain_counter_delta_nonblocking(
            heartbeat_eventfd,
            deadline,
        )
    })
}

fn publish_heartbeat_until<E: HeartbeatEvent>(
    heartbeat: &mut E,
    heartbeat_eventfd: BorrowedFd<'_>,
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    let progress_fd = heartbeat.progress_fd().as_raw_fd();
    drive_nonblocking_until(progress_fd, deadline, || {
        heartbeat.try_publish_tick_nonblocking(
            heartbeat_eventfd,
            deadline,
        )
    })
}

pub(super) struct WatchdogDescriptors {
    pub(super) parent_pidfd: OwnedFd,
    pub(super) supervisor_pidfd: OwnedFd,
    pub(super) worker_pidfd: OwnedFd,
    pub(super) supervisor_heartbeat_eventfd: OwnedFd,
    pub(super) watchdog_heartbeat_eventfd: OwnedFd,
}

impl WatchdogDescriptors {
    fn poll_descriptors(&self) -> WatchdogPollDescriptors<'_> {
        WatchdogPollDescriptors {
            parent_pidfd: self.parent_pidfd.as_fd(),
            supervisor_pidfd: self.supervisor_pidfd.as_fd(),
            worker_pidfd: self.worker_pidfd.as_fd(),
            watchdog_pidfd: None,
            heartbeat_eventfd:
                self.supervisor_heartbeat_eventfd.as_fd(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HardUnreadyReason {
    WatchdogExited,
    ParentExited,
    SupervisorExited,
    WorkerExited,
    HeartbeatStalled,
    HeartbeatIoFailure,
    ClockFailure,
    PollFailure,
    MonitorFailure,
    StartupReconciliationFailed,
    RuntimeReconciliationFailed,
    CleanupUnproven,
    DurableConflict,
}

pub(super) struct HardUnreadyLatch {
    latched: AtomicBool,
    reason: Mutex<Option<HardUnreadyReason>>,
}

impl HardUnreadyLatch {
    pub(super) const fn new() -> Self {
        Self {
            latched: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }

    pub(super) fn latch(&self, reason: HardUnreadyReason) {
        self.latched.store(true, Ordering::Release);
        let mut stored = self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if stored.is_none() {
            *stored = Some(reason);
        }
    }

    pub(super) fn is_latched(&self) -> bool {
        self.latched.load(Ordering::Acquire)
    }

    pub(super) fn reason(&self) -> Option<HardUnreadyReason> {
        *self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn latch_error<T>(
    latch: &HardUnreadyLatch,
    reason: HardUnreadyReason,
    result: Result<T, RecoveryError>,
) -> Result<T, RecoveryError> {
    result.map_err(|error| {
        latch.latch(reason);
        error
    })
}

fn checked_monitor_add(
    latch: &HardUnreadyLatch,
    value: u64,
    increment: u64,
    message: &'static str,
) -> Result<u64, RecoveryError> {
    value.checked_add(increment).ok_or_else(|| {
        latch.latch(HardUnreadyReason::MonitorFailure);
        RecoveryError::Invalid(message)
    })
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RecoveryLimits {
    pub(super) maximum_scan_records: usize,
    pub(super) maximum_retry_attempts: u8,
    pub(super) initial_backoff_nanos: u64,
    pub(super) maximum_backoff_nanos: u64,
    pub(super) heartbeat_interval_nanos: u64,
}

impl RecoveryLimits {
    pub(super) fn validate(self) -> Result<(), RecoveryError> {
        if self.maximum_scan_records == 0
            || self.maximum_scan_records > ABSOLUTE_MAX_SCAN_RECORDS
            || self.maximum_retry_attempts == 0
            || self.maximum_retry_attempts
                > ABSOLUTE_MAX_RETRY_ATTEMPTS
            || self.initial_backoff_nanos == 0
            || self.maximum_backoff_nanos < self.initial_backoff_nanos
            || self.heartbeat_interval_nanos == 0
        {
            return Err(RecoveryError::Invalid(
                "watchdog recovery limits are invalid",
            ));
        }
        Ok(())
    }

}

pub(super) struct WatchdogRecovery<'a, P, S, A, T, H, B, E, V>
where
    P: RecoveryProtocol,
    S: DurableRecoveryStore<P>,
    A: CleanupAuthorizationConsumer,
    T: RecoveryTargetProvider,
    H: BoundedCleanupHelper,
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
    V: CurrentSignatureAuthority,
{
    pub(super) protocol: &'a P,
    pub(super) store: &'a mut S,
    pub(super) cleanup_authority: &'a mut A,
    pub(super) targets: &'a mut T,
    pub(super) cleanup_helper: &'a mut H,
    pub(super) signature_authority: &'a mut V,
    pub(super) poller: &'a mut B,
    pub(super) heartbeat: &'a mut E,
    pub(super) descriptors: &'a WatchdogDescriptors,
    pub(super) watchdog_lease: WatchdogLeaseIdentity,
    pub(super) hard_unready: &'a HardUnreadyLatch,
    pub(super) limits: RecoveryLimits,
}

impl<P, S, A, T, H, B, E, V>
    WatchdogRecovery<'_, P, S, A, T, H, B, E, V>
where
    P: RecoveryProtocol,
    S: DurableRecoveryStore<P>,
    A: CleanupAuthorizationConsumer,
    T: RecoveryTargetProvider,
    H: BoundedCleanupHelper,
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
    V: CurrentSignatureAuthority,
{
    pub(super) fn reconcile_startup(
        &mut self,
        scan_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        if let Err(error) = self.limits.validate() {
            self.hard_unready
                .latch(HardUnreadyReason::StartupReconciliationFailed);
            return Err(error);
        }
        if let Err(error) =
            scan_deadline.domain().require_current()
        {
            self.hard_unready
                .latch(HardUnreadyReason::ClockFailure);
            return Err(RecoveryError::Deadline(match error {
                _ => "startup scan BOOTTIME domain is not current",
            }));
        }
        let reconciliation = self.reconcile_scan(scan_deadline);
        if reconciliation.is_err() {
            self.hard_unready
                .latch(HardUnreadyReason::StartupReconciliationFailed);
        }
        reconciliation?;
        if self.hard_unready.is_latched() {
            return Err(RecoveryError::HardUnready(
                self.hard_unready.reason().unwrap_or(
                    HardUnreadyReason::StartupReconciliationFailed,
                ),
            ));
        }
        Ok(())
    }

    /// Reconcile one owner against an operation-specific durable protocol
    /// snapshot. Concrete drivers use this entry point after a bounded scan
    /// because applying one operation's settlement chain to every owner in a
    /// page would make recovery authority ambiguous.
    pub(super) fn reconcile_exact_owner_startup(
        &mut self,
        owner: &DurableOwnershipRecord,
        scan_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        if let Err(error) = self.limits.validate() {
            self.hard_unready
                .latch(HardUnreadyReason::StartupReconciliationFailed);
            return Err(error);
        }
        if scan_deadline.domain().require_current().is_err()
            || owner
                .cleanup_deadline
                .domain()
                .require_current()
                .is_err()
            || owner.cleanup_deadline.absolute_nanos()
                > scan_deadline.absolute_nanos()
        {
            self.hard_unready
                .latch(HardUnreadyReason::ClockFailure);
            return Err(RecoveryError::Deadline(
                "exact-owner recovery deadline is outside the bounded startup scan",
            ));
        }
        let reconciliation = self.reconcile_owner(owner);
        if reconciliation.is_err() {
            self.hard_unready
                .latch(HardUnreadyReason::StartupReconciliationFailed);
        }
        reconciliation?;
        if self.hard_unready.is_latched() {
            return Err(RecoveryError::HardUnready(
                self.hard_unready.reason().unwrap_or(
                    HardUnreadyReason::StartupReconciliationFailed,
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn run(
        &mut self,
        service_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        self.reconcile_startup(service_deadline)?;
        let mut heartbeat_counter = latch_error(
            self.hard_unready,
            HardUnreadyReason::HeartbeatIoFailure,
            drain_heartbeat_until(
                self.heartbeat,
                self.descriptors
                    .supervisor_heartbeat_eventfd
                    .as_fd(),
                service_deadline,
            ),
        )?;
        self.publish_watchdog_heartbeat(service_deadline)?;
        let now = latch_error(
            self.hard_unready,
            HardUnreadyReason::ClockFailure,
            read_boottime_now(self.poller, service_deadline),
        )?;
        let mut heartbeat_due = checked_monitor_add(
            self.hard_unready,
            now,
            self.limits.heartbeat_interval_nanos,
            "watchdog heartbeat deadline overflow",
        )?;

        loop {
            if self.hard_unready.is_latched() {
                return Err(RecoveryError::HardUnready(
                    self.hard_unready.reason().unwrap_or(
                        HardUnreadyReason::RuntimeReconciliationFailed,
                    ),
                ));
            }
            let events = latch_error(
                self.hard_unready,
                HardUnreadyReason::PollFailure,
                poll_watchdog_until(
                    self.poller,
                    self.descriptors.poll_descriptors(),
                    heartbeat_due,
                    service_deadline,
                ),
            )?;
            if events.parent_exited {
                self.hard_unready
                    .latch(HardUnreadyReason::ParentExited);
                let _ = self.reconcile_scan(service_deadline);
                return Err(RecoveryError::HardUnready(
                    HardUnreadyReason::ParentExited,
                ));
            }
            if events.supervisor_exited {
                self.hard_unready
                    .latch(HardUnreadyReason::SupervisorExited);
                let _ = self.reconcile_scan(service_deadline);
                return Err(RecoveryError::HardUnready(
                    HardUnreadyReason::SupervisorExited,
                ));
            }
            if events.watchdog_exited {
                self.hard_unready
                    .latch(HardUnreadyReason::WatchdogExited);
                return Err(RecoveryError::HardUnready(
                    HardUnreadyReason::WatchdogExited,
                ));
            }
            if events.worker_exited {
                let reconciliation =
                    self.reconcile_scan(service_deadline);
                if reconciliation.is_err() {
                    self.hard_unready.latch(
                        HardUnreadyReason::RuntimeReconciliationFailed,
                    );
                }
                reconciliation?;
            }
            if events.heartbeat_readable {
                let delta = latch_error(
                    self.hard_unready,
                    HardUnreadyReason::HeartbeatIoFailure,
                    drain_heartbeat_until(
                        self.heartbeat,
                        self.descriptors
                            .supervisor_heartbeat_eventfd
                            .as_fd(),
                        service_deadline,
                    ),
                )?;
                if delta == 0 {
                    self.hard_unready
                        .latch(HardUnreadyReason::HeartbeatStalled);
                    return Err(RecoveryError::HardUnready(
                        HardUnreadyReason::HeartbeatStalled,
                    ));
                }
                heartbeat_counter = checked_monitor_add(
                    self.hard_unready,
                    heartbeat_counter,
                    delta,
                    "watchdog heartbeat counter overflow",
                )?;
                let observed = latch_error(
                    self.hard_unready,
                    HardUnreadyReason::ClockFailure,
                    read_boottime_now(
                        self.poller,
                        service_deadline,
                    ),
                )?;
                heartbeat_due = checked_monitor_add(
                    self.hard_unready,
                    observed,
                    self.limits.heartbeat_interval_nanos,
                    "watchdog heartbeat deadline overflow",
                )?;
            }
            let observed = latch_error(
                self.hard_unready,
                HardUnreadyReason::ClockFailure,
                read_boottime_now(
                    self.poller,
                    service_deadline,
                ),
            )?;
            if events.timer_expired || observed >= heartbeat_due {
                self.hard_unready
                    .latch(HardUnreadyReason::HeartbeatStalled);
                return Err(RecoveryError::HardUnready(
                    HardUnreadyReason::HeartbeatStalled,
                ));
            }
            self.publish_watchdog_heartbeat(service_deadline)?;
        }
    }

    fn publish_watchdog_heartbeat(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        latch_error(
            self.hard_unready,
            HardUnreadyReason::HeartbeatIoFailure,
            publish_heartbeat_until(
                self.heartbeat,
                self.descriptors.watchdog_heartbeat_eventfd.as_fd(),
                deadline,
            ),
        )
    }

    fn reconcile_scan(
        &mut self,
        scan_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        let mut continuation = None;
        for _ in 0..MAX_STARTUP_SCAN_PASSES {
            let page_continuation = continuation;
            let maximum_scan_records =
                self.limits.maximum_scan_records;
            let page =
                self.with_bounded_retry(scan_deadline, |store| {
                    let progress_fd =
                        store.progress_fd().as_raw_fd();
                    drive_nonblocking_until(
                        progress_fd,
                        scan_deadline,
                        || {
                            store
                                .try_scan_incomplete_ownership_nonblocking(
                                    page_continuation.clone(),
                                    maximum_scan_records,
                                    scan_deadline,
                                )
                        },
                    )
                })?;
            if page.records.len() > maximum_scan_records {
                return Err(RecoveryError::Invalid(
                    "ownership scan exceeded the requested bound",
                ));
            }
            for owner in page.records {
                self.reconcile_owner(&owner)?;
            }
            continuation = page.continuation;
            if continuation.is_none() {
                return Ok(());
            }
        }
        Err(RecoveryError::Durable(
            "ownership scan did not converge within its bound",
        ))
    }

    fn ownership_conflict<T>(
        &self,
        message: &'static str,
    ) -> Result<T, RecoveryError> {
        self.hard_unready
            .latch(HardUnreadyReason::DurableConflict);
        Err(RecoveryError::Conflict(message))
    }

    fn validate_ownership_identity(
        &self,
        expected: &DurableOwnershipRecord,
        observed: &DurableOwnershipRecord,
    ) -> Result<(), RecoveryError> {
        observed.validate()?;
        if observed.ownership_id_sha256
                != expected.ownership_id_sha256
            || observed.operation != expected.operation
            || observed.operation_id_sha256
                != expected.operation_id_sha256
            || observed.durable_request_sha256
                != expected.durable_request_sha256
            || observed.request_sha256 != expected.request_sha256
            || observed.termination_fence_sha256
                != expected.termination_fence_sha256
            || observed.cgroup != expected.cgroup
            || observed.operation_deadline
                != expected.operation_deadline
            || observed.cleanup_deadline != expected.cleanup_deadline
        {
            return self.ownership_conflict(
                "ownership query changed the recovery identity",
            );
        }
        Ok(())
    }

    fn require_owned_phase(
        &self,
        observed: &DurableOwnershipRecord,
        expected_phase: OwnershipPhase,
    ) -> Result<(), RecoveryError> {
        if observed.phase != expected_phase
            || observed.watchdog_lease.as_ref()
                != Some(&self.watchdog_lease)
        {
            return self.ownership_conflict(
                "ownership phase is not held by this watchdog lease",
            );
        }
        Ok(())
    }

    fn reconcile_owner(
        &mut self,
        scanned_owner: &DurableOwnershipRecord,
    ) -> Result<(), RecoveryError> {
        scanned_owner.validate()?;
        verify_watchdog_ownership_ack_with_current_provider(
            self.signature_authority,
            &scanned_owner.registration,
            &scanned_owner.signed_ownership_ack,
            &ProtocolBoottimeDeadline::from_runtime(
                scanned_owner.cleanup_deadline,
            ),
        )
        .map_err(|_| {
            RecoveryError::Authorization(
                "durable watchdog ownership acknowledgement failed current-key verification",
            )
        })?;
        self.watchdog_lease.validate().map_err(|error| {
            protocol_error(error, "watchdog lease is invalid")
        })?;
        let deadline = scanned_owner.cleanup_deadline;
        require_exact_deadline(&deadline, &scanned_owner.cleanup_deadline)?;
        let progress_fd = self.store.progress_fd().as_raw_fd();
        let queried_owner = drive_nonblocking_until(
            progress_fd,
            &deadline,
            || {
                self.store.try_query_ownership_nonblocking(
                    &scanned_owner.ownership_id_sha256,
                    &deadline,
                )
            },
        )?
            .ok_or(RecoveryError::Durable(
                "ownership record disappeared during query",
            ))?;
        self.validate_ownership_identity(
            scanned_owner,
            &queried_owner,
        )?;

        let active_owner = match queried_owner.phase {
            OwnershipPhase::Armed => {
                let progress_fd =
                    self.store.progress_fd().as_raw_fd();
                let cas = drive_nonblocking_until(
                    progress_fd,
                    &deadline,
                    || {
                        self.store
                            .try_cas_ownership_reconciling_nonblocking(
                                &queried_owner,
                                &self.watchdog_lease,
                                &deadline,
                            )
                    },
                )?;
                match cas.disposition {
                    CasDisposition::Conflict => {
                        return self.ownership_conflict(
                            "ownership reconciling CAS conflicted",
                        );
                    }
                    CasDisposition::Applied
                    | CasDisposition::AlreadyApplied => {
                        self.validate_ownership_identity(
                            &queried_owner,
                            &cas.authoritative_state,
                        )?;
                        self.require_owned_phase(
                            &cas.authoritative_state,
                            OwnershipPhase::Reconciling,
                        )?;
                    }
                }
                let progress_fd =
                    self.store.progress_fd().as_raw_fd();
                let observed = drive_nonblocking_until(
                    progress_fd,
                    &deadline,
                    || {
                        self.store.try_query_ownership_nonblocking(
                            &scanned_owner.ownership_id_sha256,
                            &deadline,
                        )
                    },
                )?
                    .ok_or(RecoveryError::Durable(
                        "ownership record disappeared after reconciling CAS",
                    ))?;
                self.validate_ownership_identity(
                    &queried_owner,
                    &observed,
                )?;
                self.require_owned_phase(
                    &observed,
                    OwnershipPhase::Reconciling,
                )?;
                observed
            }
            OwnershipPhase::Reconciling => {
                self.require_owned_phase(
                    &queried_owner,
                    OwnershipPhase::Reconciling,
                )?;
                queried_owner
            }
            OwnershipPhase::Terminal => {
                self.require_owned_phase(
                    &queried_owner,
                    OwnershipPhase::Terminal,
                )?;
                self.drive_settlement_to_terminal(&queried_owner)?;
                return Ok(());
            }
        };

        let settlement =
            self.drive_settlement_to_terminal(&active_owner)?;
        let progress_fd = self.store.progress_fd().as_raw_fd();
        let expected = drive_nonblocking_until(
            progress_fd,
            &deadline,
            || {
                self.store.try_query_ownership_nonblocking(
                    &active_owner.ownership_id_sha256,
                    &deadline,
                )
            },
        )?
            .ok_or(RecoveryError::Durable(
                "ownership record disappeared before terminal CAS",
            ))?;
        self.validate_ownership_identity(&active_owner, &expected)?;
        self.require_owned_phase(
            &expected,
            OwnershipPhase::Reconciling,
        )?;
        let settlement_state_sha256 = drive_protocol_nonblocking(
            self.protocol,
            &deadline,
            |protocol| {
                protocol.try_state_sha256_nonblocking(
                    &settlement,
                    &deadline,
                )
            },
        )?;
        let progress_fd = self.store.progress_fd().as_raw_fd();
        let terminal = drive_nonblocking_until(
            progress_fd,
            &deadline,
            || {
                self.store
                    .try_cas_ownership_terminal_nonblocking(
                        &expected,
                        &self.watchdog_lease,
                        settlement_state_sha256.clone(),
                        &deadline,
                    )
            },
        )?;
        match terminal.disposition {
            CasDisposition::Conflict => {
                return self.ownership_conflict(
                    "ownership terminal CAS conflicted",
                );
            }
            CasDisposition::Applied
            | CasDisposition::AlreadyApplied => {
                self.validate_ownership_identity(
                    &expected,
                    &terminal.authoritative_state,
                )?;
                self.require_owned_phase(
                    &terminal.authoritative_state,
                    OwnershipPhase::Terminal,
                )?;
            }
        }
        let progress_fd = self.store.progress_fd().as_raw_fd();
        let observed = drive_nonblocking_until(
            progress_fd,
            &deadline,
            || {
                self.store.try_query_ownership_nonblocking(
                    &active_owner.ownership_id_sha256,
                    &deadline,
                )
            },
        )?
            .ok_or(RecoveryError::Durable(
                "ownership record disappeared after terminal CAS",
            ))?;
        self.validate_ownership_identity(&expected, &observed)?;
        self.require_owned_phase(
            &observed,
            OwnershipPhase::Terminal,
        )
    }

    fn settlement_identity_for_owner(
        &self,
        record: &P::SettlementRecord,
        owner: &DurableOwnershipRecord,
    ) -> Result<SettlementIdentity, RecoveryError> {
        let identity = drive_protocol_nonblocking(
            self.protocol,
            &owner.cleanup_deadline,
            |protocol| {
                protocol.try_settlement_identity_nonblocking(
                    record,
                    &owner.cleanup_deadline,
                )
            },
        )?;
        if identity.operation != owner.operation
            || identity.operation_id_sha256
                != owner.operation_id_sha256
            || identity.durable_request_sha256
                != owner.durable_request_sha256
            || identity.request_sha256 != owner.request_sha256
            || identity.supervisor_capability_sha256
                != owner.supervisor_capability_sha256
            || identity.fence_token_sha256
                != owner.termination_fence_sha256
            || identity.cgroup_identity != owner.cgroup.protocol
            || identity.operation_deadline
                != ProtocolBoottimeDeadline::from_runtime(
                    owner.operation_deadline,
                )
        {
            return Err(RecoveryError::Durable(
                "settlement identity does not match durable ownership",
            ));
        }
        Ok(identity)
    }

    fn verify_record_consumes(
        &mut self,
        owner: &DurableOwnershipRecord,
        record: &P::SettlementRecord,
    ) -> Result<Option<VerifiedIndependentDurableConsumes>, RecoveryError> {
        let raw = drive_protocol_nonblocking(
            self.protocol,
            &owner.cleanup_deadline,
            |protocol| {
                protocol
                    .try_independent_durable_consumes_nonblocking(
                        record,
                        &owner.cleanup_deadline,
                    )
            },
        )?;
        match raw {
            None => Ok(None),
            Some(raw) => {
                let identity =
                    self.settlement_identity_for_owner(record, owner)?;
                let verified =
                    verify_independent_durable_consumes_with_current_provider(
                    self.signature_authority,
                    &raw,
                    &identity,
                    &ProtocolBoottimeDeadline::from_runtime(
                        owner.cleanup_deadline,
                    ),
                )
                .map_err(|_| {
                    RecoveryError::Authorization(
                        "canonical v3 durable consumes failed current-key verification",
                    )
                })?;
                let signer = verified.signer_hsm().statement();
                let store = verified.settlement_store().statement();
                if !signer.occurred_before_operation_deadline
                    || !store.occurred_before_operation_deadline
                    || signer.consumed_at_boottime_nanos
                        >= owner.operation_deadline.absolute_nanos()
                    || store.consumed_at_boottime_nanos
                        >= owner.operation_deadline.absolute_nanos()
                    || digest_is_zero(&drive_protocol_nonblocking(
                        self.protocol,
                        &owner.cleanup_deadline,
                        |protocol| {
                            protocol
                                .try_result_binding_sha256_nonblocking(
                                    record,
                                    &owner.cleanup_deadline,
                                )
                        },
                    )?)
                {
                    return Err(RecoveryError::Authorization(
                        "verified durable consumes do not match the durable sequence or result record",
                    ));
                }
                owner.cleanup_deadline.require_live().map_err(|_| {
                    RecoveryError::Deadline(
                        "cleanup deadline expired after durable consume verification",
                    )
                })?;
                Ok(Some(verified))
            }
        }
    }

    fn verify_stored_cleanup_bundle(
        &mut self,
        owner: &DurableOwnershipRecord,
        record: &P::SettlementRecord,
    ) -> Result<CleanupProofBundle, RecoveryError> {
        let mut bundle = CleanupProofBundle::default();
        let evidence = drive_protocol_nonblocking(
            self.protocol,
            &owner.cleanup_deadline,
            |protocol| {
                protocol
                    .try_stored_cleanup_evidence_nonblocking(
                        record,
                        &owner.cleanup_deadline,
                    )
            },
        )?;
        if evidence.len() > ABSOLUTE_MAX_CLEANUP_ACTIONS {
            return Err(RecoveryError::Cleanup(
                "stored terminal cleanup evidence exceeds its bound",
            ));
        }
        for item in evidence {
            drive_protocol_nonblocking(
                self.protocol,
                &owner.cleanup_deadline,
                |protocol| {
                    protocol
                        .try_validate_cleanup_predecessor_in_chain_nonblocking(
                            record,
                            &item.binding.predecessor,
                            &owner.cleanup_deadline,
                        )
                },
            )?;
            item.binding.validate(
                owner,
                &item.binding.predecessor,
                &owner.cleanup_deadline,
            )?;
            let consumption = verify_cleanup_consumption(
                self.signature_authority,
                &item.authorization,
                &item.binding,
                item.expected_consumption_sequence,
                &item
                    .expected_consumption_predecessor_receipt_sha256,
                &item.trace_requests,
                item.consumption,
                &owner.cleanup_deadline,
            )?;
            let result = verify_cleanup_result(
                self.signature_authority,
                owner,
                item.binding,
                consumption,
                item.expected_result_sequence,
                item.durable_effect,
                &owner.cleanup_deadline,
            )?;
            bundle.push(result)?;
        }
        Ok(bundle)
    }

    fn drive_settlement_to_terminal(
        &mut self,
        owner: &DurableOwnershipRecord,
    ) -> Result<P::SettlementRecord, RecoveryError> {
        let deadline = owner.cleanup_deadline;
        let key = owner.recovery_key();
        for _ in 0..MAX_RECOVERY_TRANSITIONS {
            let progress_fd = self.store.progress_fd().as_raw_fd();
            let current = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.store.try_query_settlement_nonblocking(
                        &key,
                        &deadline,
                    )
                },
            )?
                .ok_or(RecoveryError::Durable(
                    "settlement record is missing",
                ))?;
            drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_validate_settlement_nonblocking(
                        &key,
                        &current,
                        &deadline,
                    )
                },
            )?;
            let current_phase = drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_phase_nonblocking(
                        &current,
                        &deadline,
                    )
                },
            )?;
            let Some(target) = current_phase.recovery_successor() else {
                self.verify_stored_cleanup_bundle(owner, &current)?
                    .prove_terminal_cleanup()?;
                return Ok(current);
            };

            let durable_consumes =
                self.verify_record_consumes(owner, &current)?;
            if matches!(
                current_phase,
                DurableRecoveryPhase::ResultCommitted
                    | DurableRecoveryPhase::FenceClosed
                    | DurableRecoveryPhase::TerminationCommitted
            ) && durable_consumes.is_none()
            {
                return Err(RecoveryError::Durable(
                    "committed result branch lacks verified independent consumes",
                ));
            }
            let cleanup_proofs =
                self.execute_cleanup_plan(owner, &current, target)?;
            let signed_result_aborted =
                if target == DurableRecoveryPhase::ResultAborted {
                    Some(cleanup_proofs.prove_result_aborted()?)
                } else {
                    None
                };
            if target == DurableRecoveryPhase::TerminationCommitted {
                cleanup_proofs.prove_terminal_cleanup()?;
            }
            let transition = drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_build_one_transition_nonblocking(
                        owner,
                        &current,
                        target,
                        durable_consumes.as_ref(),
                        signed_result_aborted,
                        &cleanup_proofs,
                        &deadline,
                    )
                },
            )?;
            let expected_revision = drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_revision_nonblocking(
                        &current,
                        &deadline,
                    )
                },
            )?;
            let expected_state_sha256 = drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_state_sha256_nonblocking(
                        &current,
                        &deadline,
                    )
                },
            )?;
            let progress_fd = self.store.progress_fd().as_raw_fd();
            let cas = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.store
                        .try_cas_one_settlement_transition_nonblocking(
                            &key,
                            expected_revision,
                            expected_state_sha256.clone(),
                            &transition,
                            &deadline,
                        )
                },
            )?;
            let progress_fd = self.store.progress_fd().as_raw_fd();
            let observed = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.store.try_query_settlement_nonblocking(
                        &key,
                        &deadline,
                    )
                },
            )?
                .ok_or(RecoveryError::Durable(
                    "settlement disappeared after transition CAS",
                ))?;
            drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_validate_settlement_nonblocking(
                        &key,
                        &observed,
                        &deadline,
                    )
                },
            )?;
            match cas.disposition {
                CasDisposition::Conflict => {
                    self.hard_unready
                        .latch(HardUnreadyReason::DurableConflict);
                    return Err(RecoveryError::Conflict(
                        "settlement transition CAS conflicted",
                    ));
                }
                CasDisposition::Applied
                | CasDisposition::AlreadyApplied => {
                    drive_protocol_nonblocking(
                        self.protocol,
                        &deadline,
                        |protocol| {
                            protocol
                                .try_validate_successor_nonblocking(
                                    owner,
                                    &current,
                                    target,
                                    &observed,
                                    signed_result_aborted,
                                    &cleanup_proofs,
                                    &deadline,
                                )
                        },
                    )?;
                }
            }
            if drive_protocol_nonblocking(
                self.protocol,
                &deadline,
                |protocol| {
                    protocol.try_phase_nonblocking(
                        &observed,
                        &deadline,
                    )
                },
            )?
                == DurableRecoveryPhase::TerminationCommitted
            {
                cleanup_proofs.prove_terminal_cleanup()?;
                return Ok(observed);
            }
        }
        Err(RecoveryError::Durable(
            "settlement recovery exceeded the exact transition bound",
        ))
    }

    fn execute_cleanup_plan(
        &mut self,
        owner: &DurableOwnershipRecord,
        current: &P::SettlementRecord,
        target_phase: DurableRecoveryPhase,
    ) -> Result<CleanupProofBundle, RecoveryError> {
        let deadline = owner.cleanup_deadline;
        let predecessor = drive_protocol_nonblocking(
            self.protocol,
            &deadline,
            |protocol| {
                protocol.try_queried_predecessor_nonblocking(
                    current,
                    &deadline,
                )
            },
        )?;
        let plan = drive_protocol_nonblocking(
            self.protocol,
            &deadline,
            |protocol| {
                protocol.try_cleanup_plan_nonblocking(
                    owner,
                    current,
                    target_phase,
                    &deadline,
                )
            },
        )?;
        if plan.len() > ABSOLUTE_MAX_CLEANUP_ACTIONS {
            return Err(RecoveryError::Invalid(
                "cleanup plan exceeds the fixed action bound",
            ));
        }
        if target_phase == DurableRecoveryPhase::ResultAborted
            && (plan.len() != 1
                || plan[0].binding.action
                    != CleanupAction::CommitResultAborted)
        {
            return Err(RecoveryError::Invalid(
                "Preflighted recovery must contain exactly one CommitResultAborted authorization",
            ));
        }
        if matches!(
            target_phase,
            DurableRecoveryPhase::FenceClosed
                | DurableRecoveryPhase::TerminationCommitted
        ) && plan.is_empty()
        {
            return Err(RecoveryError::Invalid(
                "cleanup transition contains no authorized actions",
            ));
        }
        let mut proofs =
            self.verify_stored_cleanup_bundle(owner, current)?;
        let mut consumed_nonces = BTreeSet::new();
        for step in plan {
            self.require_settlement_head_unchanged(
                owner,
                current,
                &deadline,
            )?;
            step.binding.validate(
                owner,
                &predecessor,
                &deadline,
            )?;
            step.binding
                .validate_authorization(&step.authorization)?;
            if !consumed_nonces.insert(
                step.binding.authorization_nonce_sha256.clone(),
            ) {
                return Err(RecoveryError::Authorization(
                    "cleanup plan reuses an authorization nonce",
                ));
            }
            let progress_fd = self
                .cleanup_authority
                .progress_fd()
                .as_raw_fd();
            let raw_consumption = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.cleanup_authority
                        .try_consume_exact_v3_nonblocking(
                            &step.authorization,
                            &step.trace_requests,
                            &deadline,
                        )
                },
            )?;
            let consumption = verify_cleanup_consumption(
                self.signature_authority,
                &step.authorization,
                &step.binding,
                step.expected_consumption_sequence,
                &step
                    .expected_consumption_predecessor_receipt_sha256,
                &step.trace_requests,
                raw_consumption,
                &deadline,
            )?;
            let progress_fd =
                self.targets.progress_fd().as_raw_fd();
            let target = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.targets.try_cleanup_target_nonblocking(
                        owner,
                        &deadline,
                    )
                },
            )?;
            if target.worker != owner.worker
                || target.cgroup != owner.cgroup
            {
                return Err(RecoveryError::Cleanup(
                    "cleanup descriptor target changed identity",
                ));
            }
            let progress_fd = self
                .cleanup_helper
                .progress_fd()
                .as_raw_fd();
            let raw_result = drive_nonblocking_until(
                progress_fd,
                &deadline,
                || {
                    self.cleanup_helper
                        .try_execute_exact_nonblocking(
                            &target,
                            &step.binding,
                            &consumption
                                .evidence
                                .persisted
                                .signed_envelope
                                .envelope_sha256,
                            &deadline,
                        )
                },
            )?;
            let proof = verify_cleanup_result(
                self.signature_authority,
                owner,
                step.binding,
                consumption,
                step.expected_result_sequence,
                raw_result,
                &deadline,
            )?;
            self.require_settlement_head_unchanged(
                owner,
                current,
                &deadline,
            )?;
            proofs.push(proof)?;
        }
        Ok(proofs)
    }

    fn require_settlement_head_unchanged(
        &mut self,
        owner: &DurableOwnershipRecord,
        expected: &P::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        let key = owner.recovery_key();
        let progress_fd = self.store.progress_fd().as_raw_fd();
        let observed = drive_nonblocking_until(
            progress_fd,
            deadline,
            || {
                self.store.try_query_settlement_nonblocking(
                    &key,
                    deadline,
                )
            },
        )?
            .ok_or(RecoveryError::Durable(
                "settlement head disappeared during cleanup",
            ))?;
        drive_protocol_nonblocking(
            self.protocol,
            deadline,
            |protocol| {
                protocol.try_validate_settlement_nonblocking(
                    &key,
                    &observed,
                    deadline,
                )
            },
        )?;
        let observed_revision = drive_protocol_nonblocking(
            self.protocol,
            deadline,
            |protocol| {
                protocol.try_revision_nonblocking(
                    &observed,
                    deadline,
                )
            },
        )?;
        let expected_revision = drive_protocol_nonblocking(
            self.protocol,
            deadline,
            |protocol| {
                protocol.try_revision_nonblocking(
                    expected,
                    deadline,
                )
            },
        )?;
        let observed_state_sha256 = drive_protocol_nonblocking(
            self.protocol,
            deadline,
            |protocol| {
                protocol.try_state_sha256_nonblocking(
                    &observed,
                    deadline,
                )
            },
        )?;
        let expected_state_sha256 = drive_protocol_nonblocking(
            self.protocol,
            deadline,
            |protocol| {
                protocol.try_state_sha256_nonblocking(
                    expected,
                    deadline,
                )
            },
        )?;
        if observed_revision != expected_revision
            || observed_state_sha256 != expected_state_sha256
        {
            return Err(RecoveryError::Conflict(
                "settlement head changed during cleanup authorization or execution",
            ));
        }
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "cleanup deadline expired during settlement head recheck",
            )
        })
    }

    fn with_bounded_retry<T>(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
        mut operation: impl FnMut(&mut S) -> Result<T, RecoveryError>,
    ) -> Result<T, RecoveryError> {
        let mut backoff = BoottimeBackoff::new(
            self.limits.initial_backoff_nanos,
            self.limits.maximum_backoff_nanos,
            2,
        )
        .map_err(|_| {
            RecoveryError::Invalid(
                "watchdog BOOTTIME backoff is invalid",
            )
        })?;
        for _ in 0..self.limits.maximum_retry_attempts {
            match operation(self.store) {
                Ok(value) => return Ok(value),
                Err(error) if error.is_transient() => {
                    match backoff.wait_poll(*deadline, &[]).map_err(
                        |_| {
                            RecoveryError::Deadline(
                                "watchdog BOOTTIME backoff failed",
                            )
                        },
                    )? {
                        BackoffOutcome::RetryDue { .. } => {}
                        BackoffOutcome::AuthorizationExpired => {
                            return Err(RecoveryError::Deadline(
                                "watchdog retry authority expired",
                            ));
                        }
                        BackoffOutcome::Progress(_) => {
                            return Err(RecoveryError::Invalid(
                                "watchdog backoff reported impossible external progress",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(RecoveryError::Durable(
            "watchdog retry budget exhausted",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContinuousMonitorDirective {
    ObserveUntil(AbsoluteBoottimeDeadline),
    AuthorizedShutdown,
}

pub(super) trait ContinuousMonitorDriver {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Return bounded observation windows forever, or `AuthorizedShutdown`
    /// only after independently verifying the durable shutdown authorization.
    fn try_next_directive_nonblocking(
        &mut self,
        expected_domain: BoottimeDomain,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<ContinuousMonitorDirective>, RecoveryError>;
}

/// Supervisor-side monitor for the independently launched watchdog.
pub(super) struct WatchdogHealthMonitor<'a, B, E>
where
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
{
    pub(super) watchdog_pidfd: OwnedFd,
    pub(super) watchdog_heartbeat_eventfd: OwnedFd,
    pub(super) parent_pidfd: BorrowedFd<'a>,
    pub(super) supervisor_pidfd: BorrowedFd<'a>,
    pub(super) worker_pidfd: BorrowedFd<'a>,
    pub(super) poller: &'a mut B,
    pub(super) heartbeat: &'a mut E,
    pub(super) hard_unready: &'a HardUnreadyLatch,
    pub(super) heartbeat_counter: u64,
    pub(super) heartbeat_due_boottime_nanos: u64,
    pub(super) heartbeat_interval_nanos: u64,
    pub(super) boottime_domain: BoottimeDomain,
}

impl<B, E> WatchdogHealthMonitor<'_, B, E>
where
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
{
    pub(super) fn drive_continuously<D: ContinuousMonitorDriver>(
        &mut self,
        driver: &mut D,
        monitor_authority_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        loop {
            if self.boottime_domain.require_current().is_err() {
                self.hard_unready
                    .latch(HardUnreadyReason::ClockFailure);
                return Err(RecoveryError::Deadline(
                    "monitor BOOTTIME domain is not current",
                ));
            }
            monitor_authority_deadline
                .require_expected_domain(self.boottime_domain)
                .map_err(|_| {
                    RecoveryError::Deadline(
                        "continuous monitor authority domain mismatch",
                    )
                })?;
            monitor_authority_deadline.require_live().map_err(|_| {
                RecoveryError::Deadline(
                    "continuous monitor authority expired",
                )
            })?;
            let progress_fd =
                driver.progress_fd().as_raw_fd();
            let directive = latch_error(
                self.hard_unready,
                HardUnreadyReason::MonitorFailure,
                drive_nonblocking_until(
                    progress_fd,
                    monitor_authority_deadline,
                    || {
                        driver.try_next_directive_nonblocking(
                            self.boottime_domain,
                            monitor_authority_deadline,
                        )
                    },
                ),
            )?;
            match directive {
                ContinuousMonitorDirective::AuthorizedShutdown => {
                    return Ok(());
                }
                ContinuousMonitorDirective::ObserveUntil(deadline) => {
                    if let Err(error) = deadline
                        .require_expected_domain(self.boottime_domain)
                    {
                        self.hard_unready
                            .latch(HardUnreadyReason::ClockFailure);
                        return Err(RecoveryError::Deadline(match error {
                            _ => "monitor deadline BOOTTIME domain mismatch",
                        }));
                    }
                    if deadline.absolute_nanos()
                        > monitor_authority_deadline.absolute_nanos()
                    {
                        self.hard_unready
                            .latch(HardUnreadyReason::MonitorFailure);
                        return Err(RecoveryError::Deadline(
                            "monitor observation exceeds its authority deadline",
                        ));
                    }
                    self.observe_once(&deadline)?;
                }
            }
        }
    }

    fn observe_once(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        if self.heartbeat_interval_nanos == 0
            || self.heartbeat_due_boottime_nanos == 0
            || deadline.absolute_nanos()
                < self.heartbeat_due_boottime_nanos
        {
            self.hard_unready
                .latch(HardUnreadyReason::MonitorFailure);
            return Err(RecoveryError::Invalid(
                "watchdog heartbeat configuration is invalid",
            ));
        }
        let events = latch_error(
            self.hard_unready,
            HardUnreadyReason::PollFailure,
            poll_watchdog_until(
                self.poller,
                WatchdogPollDescriptors {
                    parent_pidfd: self.parent_pidfd,
                    supervisor_pidfd: self.supervisor_pidfd,
                    worker_pidfd: self.worker_pidfd,
                    watchdog_pidfd:
                        Some(self.watchdog_pidfd.as_fd()),
                    heartbeat_eventfd:
                        self.watchdog_heartbeat_eventfd.as_fd(),
                },
                self.heartbeat_due_boottime_nanos,
                deadline,
            ),
        )?;
        if events.parent_exited {
            self.hard_unready
                .latch(HardUnreadyReason::ParentExited);
            return Err(RecoveryError::HardUnready(
                HardUnreadyReason::ParentExited,
            ));
        }
        if events.supervisor_exited {
            self.hard_unready
                .latch(HardUnreadyReason::SupervisorExited);
            return Err(RecoveryError::HardUnready(
                HardUnreadyReason::SupervisorExited,
            ));
        }
        if events.watchdog_exited {
            self.hard_unready
                .latch(HardUnreadyReason::WatchdogExited);
            return Err(RecoveryError::HardUnready(
                HardUnreadyReason::WatchdogExited,
            ));
        }
        if events.worker_exited {
            self.hard_unready
                .latch(HardUnreadyReason::WorkerExited);
            return Err(RecoveryError::HardUnready(
                HardUnreadyReason::WorkerExited,
            ));
        }
        if events.heartbeat_readable {
            let delta = latch_error(
                self.hard_unready,
                HardUnreadyReason::HeartbeatIoFailure,
                drain_heartbeat_until(
                    self.heartbeat,
                    self.watchdog_heartbeat_eventfd.as_fd(),
                    deadline,
                ),
            )?;
            if delta == 0 {
                self.hard_unready
                    .latch(HardUnreadyReason::HeartbeatStalled);
                return Err(RecoveryError::HardUnready(
                    HardUnreadyReason::HeartbeatStalled,
                ));
            }
            self.heartbeat_counter = checked_monitor_add(
                self.hard_unready,
                self.heartbeat_counter,
                delta,
                "watchdog heartbeat counter overflow",
            )?;
            let now = latch_error(
                self.hard_unready,
                HardUnreadyReason::ClockFailure,
                read_boottime_now(self.poller, deadline),
            )?;
            self.heartbeat_due_boottime_nanos =
                checked_monitor_add(
                    self.hard_unready,
                    now,
                    self.heartbeat_interval_nanos,
                    "watchdog heartbeat deadline overflow",
                )?;
        }
        let now = latch_error(
            self.hard_unready,
            HardUnreadyReason::ClockFailure,
            read_boottime_now(self.poller, deadline),
        )?;
        if events.timer_expired
            || now >= self.heartbeat_due_boottime_nanos
        {
            self.hard_unready
                .latch(HardUnreadyReason::HeartbeatStalled);
            return Err(RecoveryError::HardUnready(
                HardUnreadyReason::HeartbeatStalled,
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) enum RecoveryError {
    Invalid(&'static str),
    Authorization(&'static str),
    Durable(&'static str),
    Conflict(&'static str),
    Cleanup(&'static str),
    Deadline(&'static str),
    Transient(&'static str),
    HardUnready(HardUnreadyReason),
}

impl RecoveryError {
    fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Authorization(message)
            | Self::Durable(message)
            | Self::Conflict(message)
            | Self::Cleanup(message)
            | Self::Deadline(message)
            | Self::Transient(message) => formatter.write_str(message),
            Self::HardUnready(reason) => {
                write!(formatter, "policy custody is hard-unready: {reason:?}")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Explicit deployment evidence for the software-only trusted-host profile.
/// This is deliberately not interchangeable with TEE or hardware attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustedHostNoTeeReport {
    pub(super) profile: String,
    pub(super) authority_is_co_located: bool,
    pub(super) hardware_key_protection: bool,
    pub(super) hardware_attestation: bool,
    pub(super) transport: String,
    pub(super) key_delivery: String,
    pub(super) deployment_configuration_sha256: RecoveryDigest,
    pub(super) signing_credential_sha256: Option<RecoveryDigest>,
}

impl TrustedHostNoTeeReport {
    pub(super) fn local_systemd(
        deployment_configuration_sha256: RecoveryDigest,
    ) -> Result<Self, RecoveryError> {
        if digest_is_zero(&deployment_configuration_sha256) {
            return Err(RecoveryError::Invalid(
                "systemd deployment configuration binding is zero",
            ));
        }
        Ok(Self {
            profile: "TrustedHostNoTee".to_string(),
            authority_is_co_located: true,
            hardware_key_protection: false,
            hardware_attestation: false,
            transport:
                "local-authenticated-unix-seqpacket".to_string(),
            key_delivery:
                "systemd-credential-file-descriptor".to_string(),
            deployment_configuration_sha256,
            signing_credential_sha256: None,
        })
    }

    pub(super) fn with_signing_credential(
        mut self,
        signing_credential_sha256: RecoveryDigest,
    ) -> Result<Self, RecoveryError> {
        if digest_is_zero(&signing_credential_sha256) {
            return Err(RecoveryError::Invalid(
                "systemd signing credential binding is zero",
            ));
        }
        self.signing_credential_sha256 =
            Some(signing_credential_sha256);
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        if self.profile != "TrustedHostNoTee"
            || !self.authority_is_co_located
            || self.hardware_key_protection
            || self.hardware_attestation
            || self.transport
                != "local-authenticated-unix-seqpacket"
            || self.key_delivery
                != "systemd-credential-file-descriptor"
            || digest_is_zero(
                &self.deployment_configuration_sha256,
            )
            || self
                .signing_credential_sha256
                .as_ref()
                .is_some_and(digest_is_zero)
        {
            return Err(RecoveryError::Invalid(
                "TrustedHostNoTee report is inconsistent",
            ));
        }
        Ok(())
    }
}

pub(super) struct LinuxBoottimeWatchdogPoller {
    progress: LinuxAbsoluteBoottimePoller,
}

impl LinuxBoottimeWatchdogPoller {
    pub(super) fn new() -> Result<Self, RecoveryError> {
        Ok(Self {
            progress: LinuxAbsoluteBoottimePoller::new().map_err(|_| {
                RecoveryError::Invalid(
                    "Linux absolute BOOTTIME poller is unavailable",
                )
            })?,
        })
    }
}

impl BoottimeWatchdogPoller for LinuxBoottimeWatchdogPoller {
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.progress_fd()
    }

    fn try_poll_nonblocking(
        &mut self,
        descriptors: WatchdogPollDescriptors<'_>,
        wake_at_boottime_nanos: u64,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<WatchdogPollEvents>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog poll authority is no longer live",
            )
        })?;
        let mut targets = Vec::with_capacity(5);
        targets.push(PollTarget::pidfd(descriptors.parent_pidfd));
        targets.push(PollTarget::pidfd(
            descriptors.supervisor_pidfd,
        ));
        targets.push(PollTarget::pidfd(descriptors.worker_pidfd));
        let watchdog_index = descriptors.watchdog_pidfd.map(|pidfd| {
            let index = targets.len();
            targets.push(PollTarget::pidfd(pidfd));
            index
        });
        let heartbeat_index = targets.len();
        targets.push(PollTarget::eventfd(
            descriptors.heartbeat_eventfd,
        ));
        let Some(outcome) = self
            .progress
            .try_poll_absolute_nonblocking(
                wake_at_boottime_nanos,
                *deadline,
                &targets,
            )
            .map_err(|_| {
                RecoveryError::Deadline(
                    "absolute BOOTTIME watchdog poll failed",
                )
            })?
        else {
            return Ok(None);
        };
        let observed = |index| {
            outcome.progress.iter().any(|event| {
                event.index() == index
                    && (event.readable()
                        || event.hung_up()
                        || event.errored())
            })
        };
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog poll crossed its exact deadline",
            )
        })?;
        Ok(Some(WatchdogPollEvents {
            parent_exited: observed(0),
            supervisor_exited: observed(1),
            worker_exited: observed(2),
            watchdog_exited:
                watchdog_index.is_some_and(observed),
            heartbeat_readable: observed(heartbeat_index),
            timer_expired: outcome.timer_expired,
        }))
    }

    fn try_now_boottime_nanos_nonblocking(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "BOOTTIME observation authority expired",
            )
        })?;
        let observed = boottime_now_nanos().map_err(|_| {
            RecoveryError::Deadline(
                "CLOCK_BOOTTIME observation failed",
            )
        })?;
        if observed >= deadline.absolute_nanos() {
            return Err(RecoveryError::Deadline(
                "BOOTTIME observation crossed its exact deadline",
            ));
        }
        Ok(Some(observed))
    }
}

pub(super) struct LinuxHeartbeatEvent {
    progress: LinuxAbsoluteBoottimePoller,
}

impl LinuxHeartbeatEvent {
    pub(super) fn new() -> Result<Self, RecoveryError> {
        Ok(Self {
            progress: LinuxAbsoluteBoottimePoller::new().map_err(|_| {
                RecoveryError::Invalid(
                    "Linux heartbeat progress poller is unavailable",
                )
            })?,
        })
    }

    pub(super) fn create_counter(
        initial_value: u32,
    ) -> Result<OwnedFd, RecoveryError> {
        create_nonblocking_eventfd(initial_value).map_err(|_| {
            RecoveryError::Invalid(
                "nonblocking heartbeat eventfd creation failed",
            )
        })
    }
}

impl HeartbeatEvent for LinuxHeartbeatEvent {
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.progress_fd()
    }

    fn try_drain_counter_delta_nonblocking(
        &mut self,
        heartbeat_eventfd: BorrowedFd<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "heartbeat drain authority expired",
            )
        })?;
        match try_read_eventfd_nonblocking(heartbeat_eventfd).map_err(
            |_| {
                RecoveryError::Cleanup(
                    "heartbeat eventfd read failed",
                )
            },
        )? {
            Some(counter) => {
                deadline.require_live().map_err(|_| {
                    RecoveryError::Deadline(
                        "heartbeat drain crossed its exact deadline",
                    )
                })?;
                Ok(Some(counter))
            }
            None => {
                self.progress
                    .arm_progress(&[PollTarget::eventfd(
                        heartbeat_eventfd,
                    )])
                    .map_err(|_| {
                        RecoveryError::Cleanup(
                            "heartbeat read progress registration failed",
                        )
                    })?;
                Ok(None)
            }
        }
    }

    fn try_publish_tick_nonblocking(
        &mut self,
        heartbeat_eventfd: BorrowedFd<'_>,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "heartbeat publish authority expired",
            )
        })?;
        match try_write_eventfd_nonblocking(heartbeat_eventfd, 1)
            .map_err(|_| {
                RecoveryError::Cleanup(
                    "heartbeat eventfd write failed",
                )
            })?
        {
            Some(()) => {
                deadline.require_live().map_err(|_| {
                    RecoveryError::Deadline(
                        "heartbeat publish crossed its exact deadline",
                    )
                })?;
                Ok(Some(()))
            }
            None => {
                self.progress
                    .arm_progress(&[PollTarget::eventfd_with_interest(
                        heartbeat_eventfd,
                        PollInterest::WRITABLE,
                    )])
                    .map_err(|_| {
                        RecoveryError::Cleanup(
                            "heartbeat write progress registration failed",
                        )
                    })?;
                Ok(None)
            }
        }
    }
}

const RECOVERY_TRANSITION_NONCE_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTransitionNonce/v3";
const RECOVERY_ABORT_REASON_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryAbortReason/v3";

/// Mechanical v3 recovery protocol. Signed authorizations and stored evidence
/// are supplied only after the watchdog authority and endpoint clients have
/// verified them; this type performs no I/O and never manufactures authority.
pub(super) struct TrustedHostRecoveryProtocol {
    progress: OwnedFd,
    canonical_chain: Vec<DurableSettlementRecord>,
    authorized_steps: Vec<AuthorizedCleanupStep>,
    stored_evidence: Vec<StoredCleanupEvidence>,
}

impl TrustedHostRecoveryProtocol {
    pub(super) fn new(
        canonical_chain: Vec<DurableSettlementRecord>,
        authorized_steps: Vec<AuthorizedCleanupStep>,
        stored_evidence: Vec<StoredCleanupEvidence>,
    ) -> Result<Self, RecoveryError> {
        if canonical_chain.is_empty()
            || canonical_chain.len() > MAX_RECOVERY_TRANSITIONS
        {
            return Err(RecoveryError::Invalid(
                "recovery protocol requires one bounded canonical chain",
            ));
        }
        for record in &canonical_chain {
            record.validate_shape().map_err(|error| {
                protocol_error(
                    error,
                    "recovery canonical settlement state is invalid",
                )
            })?;
        }
        for pair in canonical_chain.windows(2) {
            pair[1].validate_successor(&pair[0]).map_err(|error| {
                protocol_error(
                    error,
                    "recovery canonical chain is discontinuous",
                )
            })?;
        }
        if authorized_steps.len() > ABSOLUTE_MAX_CLEANUP_ACTIONS
            || stored_evidence.len() > ABSOLUTE_MAX_CLEANUP_ACTIONS
        {
            return Err(RecoveryError::Invalid(
                "recovery cleanup evidence exceeds its fixed bound",
            ));
        }
        for step in &authorized_steps {
            step.binding
                .validate_authorization(&step.authorization)?;
            step.trace_requests.validate()?;
            if step.expected_consumption_sequence == 0
                || step.expected_result_sequence == 0
                || digest_is_zero(
                    &step
                        .expected_consumption_predecessor_receipt_sha256,
                )
            {
                return Err(RecoveryError::Authorization(
                    "authorized cleanup step is incomplete",
                ));
            }
        }
        for evidence in &stored_evidence {
            evidence
                .binding
                .validate_authorization(&evidence.authorization)?;
            evidence.trace_requests.validate()?;
            if evidence.expected_consumption_sequence == 0
                || evidence.expected_result_sequence == 0
                || digest_is_zero(
                    &evidence
                        .expected_consumption_predecessor_receipt_sha256,
                )
            {
                return Err(RecoveryError::Authorization(
                    "stored cleanup evidence is incomplete",
                ));
            }
        }
        let progress = create_nonblocking_eventfd(0).map_err(|_| {
            RecoveryError::Invalid(
                "recovery protocol progress eventfd creation failed",
            )
        })?;
        Ok(Self {
            progress,
            canonical_chain,
            authorized_steps,
            stored_evidence,
        })
    }

    fn require_attempt(
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "recovery protocol attempt exceeded its exact deadline",
            )
        })
    }

    fn expected_identity(
        owner: &DurableOwnershipRecord,
    ) -> SettlementIdentity {
        SettlementIdentity {
            operation: owner.operation,
            operation_id_sha256:
                owner.operation_id_sha256.clone(),
            durable_request_sha256:
                owner.durable_request_sha256.clone(),
            request_sha256: owner.request_sha256.clone(),
            supervisor_capability_sha256:
                owner.supervisor_capability_sha256.clone(),
            fence_token_sha256:
                owner.termination_fence_sha256.clone(),
            cgroup_identity: owner.cgroup.protocol.clone(),
            operation_deadline:
                ProtocolBoottimeDeadline::from_runtime(
                    owner.operation_deadline,
                ),
        }
    }

    fn validate_key(
        key: &RecoveryKey,
        record: &DurableSettlementRecord,
    ) -> Result<(), RecoveryError> {
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement state is invalid")
        })?;
        if key.operation_id_sha256
                != record.identity.operation_id_sha256
            || key.durable_request_sha256
                != record.identity.durable_request_sha256
            || key.termination_fence_sha256
                != record.identity.fence_token_sha256
        {
            return Err(RecoveryError::Durable(
                "recovery key does not bind the settlement identity",
            ));
        }
        Ok(())
    }

    fn action_is_for_target(
        action: CleanupAction,
        target: DurableRecoveryPhase,
    ) -> bool {
        match target {
            DurableRecoveryPhase::ResultAborted => {
                action == CleanupAction::CommitResultAborted
            }
            DurableRecoveryPhase::FenceClosed => matches!(
                action,
                CleanupAction::RevokeFence
                    | CleanupAction::KillCgroup
                    | CleanupAction::CommitFenceClosed
            ),
            DurableRecoveryPhase::TerminationCommitted => matches!(
                action,
                CleanupAction::ReapWorker
                    | CleanupAction::CommitTermination
            ),
            DurableRecoveryPhase::Preflighted
            | DurableRecoveryPhase::ResultCommitted => false,
        }
    }

    fn unique_receipt_for_action(
        proofs: &CleanupProofBundle,
        action: CleanupAction,
    ) -> Result<RecoveryDigest, RecoveryError> {
        let mut matching = proofs
            .actions()
            .iter()
            .filter(|proof| proof.action() == action);
        let receipt = matching
            .next()
            .ok_or(RecoveryError::Cleanup(
                "recovery transition lacks its signed cleanup action",
            ))?
            .result_receipt_sha256()
            .clone();
        if matching.next().is_some() || digest_is_zero(&receipt) {
            return Err(RecoveryError::Cleanup(
                "recovery transition has ambiguous cleanup receipts",
            ));
        }
        Ok(receipt)
    }

    fn build_candidate(
        owner: &DurableOwnershipRecord,
        current: &DurableSettlementRecord,
        target: DurableRecoveryPhase,
        durable_consumes:
            Option<&VerifiedIndependentDurableConsumes>,
        signed_result_aborted: Option<&VerifiedCleanupResult>,
        cleanup_proofs: &CleanupProofBundle,
    ) -> Result<DurableSettlementRecord, RecoveryError> {
        if current.identity != Self::expected_identity(owner) {
            return Err(RecoveryError::Durable(
                "settlement identity changed before recovery transition",
            ));
        }
        if !target.is_adjacent_successor_of(current.phase) {
            return Err(RecoveryError::Durable(
                "recovery target is not an adjacent settlement phase",
            ));
        }
        if current.phase != DurableRecoveryPhase::Preflighted
            && durable_consumes.is_none()
        {
            return Err(RecoveryError::Authorization(
                "recovery transition lacks verified durable consumes",
            ));
        }

        let mut result_disposition =
            current.result_disposition.clone();
        let mut fence_close_receipt_sha256 =
            current.fence_close_receipt_sha256.clone();
        let mut termination_receipt_sha256 =
            current.termination_receipt_sha256.clone();
        match target {
            DurableRecoveryPhase::ResultAborted => {
                let abort = signed_result_aborted.ok_or(
                    RecoveryError::Cleanup(
                        "ResultAborted transition lacks a signed abort action",
                    ),
                )?;
                if abort.action() != CleanupAction::CommitResultAborted {
                    return Err(RecoveryError::Cleanup(
                        "ResultAborted transition used the wrong cleanup action",
                    ));
                }
                let abort_receipt =
                    abort.result_receipt_sha256().clone();
                let abort_reason_sha256 = canonical_digest(
                    RECOVERY_ABORT_REASON_DOMAIN,
                    &(
                        &current.state_sha256,
                        &abort_receipt,
                        &owner.operation_id_sha256,
                    ),
                )?;
                result_disposition = Some(ResultDisposition::Aborted {
                    abort_reason_sha256,
                    abort_receipt_sha256: abort_receipt,
                    signed_abort_action:
                        abort.signed_result().clone(),
                });
            }
            DurableRecoveryPhase::FenceClosed => {
                fence_close_receipt_sha256 = Some(
                    Self::unique_receipt_for_action(
                        cleanup_proofs,
                        CleanupAction::CommitFenceClosed,
                    )?,
                );
            }
            DurableRecoveryPhase::TerminationCommitted => {
                termination_receipt_sha256 = Some(
                    Self::unique_receipt_for_action(
                        cleanup_proofs,
                        CleanupAction::CommitTermination,
                    )?,
                );
            }
            DurableRecoveryPhase::Preflighted
            | DurableRecoveryPhase::ResultCommitted => {
                return Err(RecoveryError::Invalid(
                    "recovery cannot construct this settlement phase",
                ));
            }
        }

        let proof_receipts: Vec<&RecoveryDigest> = cleanup_proofs
            .actions()
            .iter()
            .map(VerifiedCleanupResult::result_receipt_sha256)
            .collect();
        let transition_nonce_sha256 = canonical_digest(
            RECOVERY_TRANSITION_NONCE_DOMAIN,
            &(
                &owner.operation_id_sha256,
                &current.state_sha256,
                target,
                &proof_receipts,
            ),
        )?;
        if current
            .transition_nonce_ledger
            .nonce_sha256s
            .contains(&transition_nonce_sha256)
        {
            return Err(RecoveryError::Conflict(
                "recovery transition nonce was already used",
            ));
        }
        let mut transition_nonce_ledger = TransitionNonceLedger {
            nonce_sha256s:
                current.transition_nonce_ledger.nonce_sha256s.clone(),
            ledger_sha256:
                Sha256Digest::compute(b"recovery-ledger-pending"),
        };
        transition_nonce_ledger
            .nonce_sha256s
            .push(transition_nonce_sha256.clone());
        transition_nonce_ledger.ledger_sha256 =
            transition_nonce_ledger
                .computed_ledger_sha256()
                .map_err(|error| {
                    protocol_error(
                        error,
                        "recovery nonce ledger is invalid",
                    )
                })?;
        let mut candidate = DurableSettlementRecord {
            api_version:
                POLICY_CUSTODY_SETTLEMENT_VERSION.to_string(),
            identity: current.identity.clone(),
            phase: target,
            state_revision: target.expected_revision(),
            durable_consumes: current.durable_consumes.clone(),
            result_disposition,
            fence_close_receipt_sha256,
            termination_receipt_sha256,
            transition_nonce_sha256,
            transition_nonce_ledger,
            predecessor: Some(SettlementStateReference::from_record(
                current,
            )),
            state_sha256:
                Sha256Digest::compute(b"recovery-state-pending"),
        };
        candidate.state_sha256 =
            candidate.computed_state_sha256().map_err(|error| {
                protocol_error(
                    error,
                    "recovery state digest cannot be computed",
                )
            })?;
        candidate.validate_successor(current).map_err(|error| {
            protocol_error(
                error,
                "recovery candidate is not a valid successor",
            )
        })?;
        Ok(candidate)
    }
}

impl RecoveryProtocol for TrustedHostRecoveryProtocol {
    type SettlementRecord = DurableSettlementRecord;
    type SettlementTransition = DurableSettlementRecord;

    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.as_fd()
    }

    fn try_validate_settlement_nonblocking(
        &self,
        key: &RecoveryKey,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        Self::require_attempt(deadline)?;
        Self::validate_key(key, record)?;
        Ok(Some(()))
    }

    fn try_phase_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<DurableRecoveryPhase>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement phase is invalid")
        })?;
        Ok(Some(record.phase))
    }

    fn try_state_sha256_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<RecoveryDigest>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement digest is invalid")
        })?;
        Ok(Some(record.state_sha256.clone()))
    }

    fn try_revision_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<u64>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement revision is invalid")
        })?;
        Ok(Some(record.state_revision))
    }

    fn try_settlement_identity_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<SettlementIdentity>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement identity is invalid")
        })?;
        Ok(Some(record.identity.clone()))
    }

    fn try_result_binding_sha256_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<RecoveryDigest>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "settlement result binding is invalid")
        })?;
        let binding = match record.result_disposition.as_ref() {
            Some(ResultDisposition::Committed {
                result_envelope_sha256,
                ..
            }) => result_envelope_sha256.clone(),
            Some(ResultDisposition::Aborted {
                abort_receipt_sha256,
                ..
            }) => abort_receipt_sha256.clone(),
            None => record
                .identity
                .durable_consume_binding_sha256()
                .map_err(|error| {
                    protocol_error(
                        error,
                        "preflight durable-consume binding is invalid",
                    )
                })?,
        };
        Ok(Some(binding))
    }

    fn try_queried_predecessor_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<CleanupPredecessor>, RecoveryError> {
        Self::require_attempt(deadline)?;
        record.validate_shape().map_err(|error| {
            protocol_error(error, "cleanup predecessor is invalid")
        })?;
        Ok(Some(CleanupPredecessor::from(record)))
    }

    fn try_independent_durable_consumes_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<Option<IndependentDurableConsumeEvidence>>,
        RecoveryError,
    > {
        Self::require_attempt(deadline)?;
        record
            .durable_consumes
            .validate_envelope_shape()
            .map_err(|error| {
                protocol_error(
                    error,
                    "settlement durable-consume evidence is invalid",
                )
            })?;
        Ok(Some(Some(record.durable_consumes.clone())))
    }

    fn try_cleanup_plan_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        record: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Vec<AuthorizedCleanupStep>>, RecoveryError> {
        require_exact_deadline(deadline, &owner.cleanup_deadline)?;
        if record.identity != Self::expected_identity(owner)
            || !target.is_adjacent_successor_of(record.phase)
        {
            return Err(RecoveryError::Authorization(
                "cleanup plan does not bind the current settlement state",
            ));
        }
        let predecessor = CleanupPredecessor::from(record);
        let plan: Vec<AuthorizedCleanupStep> = self
            .authorized_steps
            .iter()
            .filter(|step| {
                step.binding.predecessor == predecessor
                    && Self::action_is_for_target(
                        step.binding.action,
                        target,
                    )
            })
            .cloned()
            .collect();
        Ok(Some(plan))
    }

    fn try_stored_cleanup_evidence_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Vec<StoredCleanupEvidence>>, RecoveryError> {
        Self::require_attempt(deadline)?;
        let evidence = self
            .stored_evidence
            .iter()
            .filter(|item| {
                item.binding.operation_id_sha256
                        == record.identity.operation_id_sha256
                    && item.binding.predecessor.state_revision
                        <= record.state_revision
                    && self.canonical_chain.iter().any(|state| {
                        state.state_sha256
                            == item.binding.predecessor.state_sha256
                    })
            })
            .cloned()
            .collect();
        Ok(Some(evidence))
    }

    fn try_validate_cleanup_predecessor_in_chain_nonblocking(
        &self,
        record: &Self::SettlementRecord,
        predecessor: &CleanupPredecessor,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        Self::require_attempt(deadline)?;
        let position = self
            .canonical_chain
            .iter()
            .position(|state| {
                state.phase == predecessor.phase
                    && state.state_revision
                        == predecessor.state_revision
                    && state.state_sha256 == predecessor.state_sha256
            })
            .ok_or(RecoveryError::Durable(
                "cleanup predecessor is absent from the canonical chain",
            ))?;
        let record_position = self
            .canonical_chain
            .iter()
            .position(|state| state == record)
            .ok_or(RecoveryError::Durable(
                "queried settlement is absent from the canonical chain",
            ))?;
        if position > record_position {
            return Err(RecoveryError::Durable(
                "cleanup predecessor follows the queried settlement",
            ));
        }
        Ok(Some(()))
    }

    fn try_build_one_transition_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        current: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        durable_consumes:
            Option<&VerifiedIndependentDurableConsumes>,
        signed_result_aborted:
            Option<&VerifiedCleanupResult>,
        cleanup_proofs: &CleanupProofBundle,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Self::SettlementTransition>, RecoveryError> {
        require_exact_deadline(deadline, &owner.cleanup_deadline)?;
        Ok(Some(Self::build_candidate(
            owner,
            current,
            target,
            durable_consumes,
            signed_result_aborted,
            cleanup_proofs,
        )?))
    }

    fn try_validate_successor_nonblocking(
        &self,
        owner: &DurableOwnershipRecord,
        previous: &Self::SettlementRecord,
        target: DurableRecoveryPhase,
        observed: &Self::SettlementRecord,
        signed_result_aborted:
            Option<&VerifiedCleanupResult>,
        cleanup_proofs: &CleanupProofBundle,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        require_exact_deadline(deadline, &owner.cleanup_deadline)?;
        observed.validate_successor(previous).map_err(|error| {
            protocol_error(
                error,
                "observed recovery state is not the requested successor",
            )
        })?;
        if observed.identity != Self::expected_identity(owner)
            || observed.phase != target
        {
            return Err(RecoveryError::Durable(
                "observed recovery successor changed its target or identity",
            ));
        }
        match target {
            DurableRecoveryPhase::ResultAborted => {
                let abort = signed_result_aborted.ok_or(
                    RecoveryError::Cleanup(
                        "observed ResultAborted lacks its verified action",
                    ),
                )?;
                if !matches!(
                    observed.result_disposition.as_ref(),
                    Some(ResultDisposition::Aborted {
                        abort_receipt_sha256,
                        ..
                    }) if abort_receipt_sha256
                        == abort.result_receipt_sha256()
                ) {
                    return Err(RecoveryError::Cleanup(
                        "observed ResultAborted changed the abort receipt",
                    ));
                }
            }
            DurableRecoveryPhase::FenceClosed => {
                if observed.fence_close_receipt_sha256.as_ref()
                    != Some(&Self::unique_receipt_for_action(
                        cleanup_proofs,
                        CleanupAction::CommitFenceClosed,
                    )?)
                {
                    return Err(RecoveryError::Cleanup(
                        "observed FenceClosed changed its signed receipt",
                    ));
                }
            }
            DurableRecoveryPhase::TerminationCommitted => {
                if observed.termination_receipt_sha256.as_ref()
                    != Some(&Self::unique_receipt_for_action(
                        cleanup_proofs,
                        CleanupAction::CommitTermination,
                    )?)
                {
                    return Err(RecoveryError::Cleanup(
                        "observed termination changed its signed receipt",
                    ));
                }
            }
            DurableRecoveryPhase::Preflighted
            | DurableRecoveryPhase::ResultCommitted => {
                return Err(RecoveryError::Invalid(
                    "recovery observed an impossible target phase",
                ));
            }
        }
        Ok(Some(()))
    }
}

const MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES: usize = 64 * 1024;
const WATCHDOG_QUERY_NONCE_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustedHostWatchdogExchange {
    Idle,
    AwaitingRegistrationAck {
        registration_sha256: RecoveryDigest,
    },
    Registered {
        registration_sha256: RecoveryDigest,
        ownership_id_sha256: RecoveryDigest,
        ownership_state_sha256: RecoveryDigest,
    },
    AwaitingQueryReply {
        registration_sha256: RecoveryDigest,
        ownership_id_sha256: RecoveryDigest,
        ownership_state_sha256: RecoveryDigest,
        query_nonce_sha256: RecoveryDigest,
    },
}

#[repr(C, align(16))]
struct TrustedHostScmRights([u8; 256]);

/// Nonblocking client for the signed watchdog authority wire protocol already
/// used by the launcher. The UDS must be supplied by systemd socket activation;
/// no path lookup or reconnect fallback is permitted.
pub(super) struct TrustedHostWatchdogAuthorityClient {
    socket: OwnedFd,
    expected_peer_uid: libc::uid_t,
    expected_peer_gid: libc::gid_t,
    expected_peer_pid: Option<libc::pid_t>,
    progress: LinuxAbsoluteBoottimePoller,
    report: TrustedHostNoTeeReport,
    exchange: TrustedHostWatchdogExchange,
}

impl TrustedHostWatchdogAuthorityClient {
    pub(super) fn from_systemd_socket(
        socket: OwnedFd,
        expected_peer_uid: libc::uid_t,
        expected_peer_gid: libc::gid_t,
        expected_peer_pid: Option<libc::pid_t>,
        report: TrustedHostNoTeeReport,
    ) -> Result<Self, RecoveryError> {
        report.validate()?;
        if expected_peer_pid.is_some_and(|pid| pid <= 0) {
            return Err(RecoveryError::Invalid(
                "watchdog peer credential pin is invalid",
            ));
        }
        let flags = unsafe {
            libc::fcntl(socket.as_raw_fd(), libc::F_GETFL)
        };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    socket.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } != 0
        {
            return Err(RecoveryError::Invalid(
                "watchdog socket cannot be made nonblocking",
            ));
        }
        let client = Self {
            socket,
            expected_peer_uid,
            expected_peer_gid,
            expected_peer_pid,
            progress:
                LinuxAbsoluteBoottimePoller::new().map_err(|_| {
                    RecoveryError::Invalid(
                        "watchdog UDS progress poller is unavailable",
                    )
                })?,
            report,
            exchange: TrustedHostWatchdogExchange::Idle,
        };
        client.revalidate_peer()?;
        Ok(client)
    }

    pub(super) fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.progress_fd()
    }

    pub(super) fn security_report(
        &self,
    ) -> &TrustedHostNoTeeReport {
        &self.report
    }

    pub(super) fn try_send_registration_nonblocking(
        &mut self,
        registration: &WatchdogRegistrationV3,
        retained_fds: &[BorrowedFd<'_>; 6],
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog registration authority expired",
            )
        })?;
        registration.validate().map_err(|error| {
            protocol_error(error, "watchdog registration is invalid")
        })?;
        if registration.operation_deadline
            != ProtocolBoottimeDeadline::from_runtime(*deadline)
            || retained_fds.iter().any(|fd| fd.as_raw_fd() < 0)
        {
            return Err(RecoveryError::Invalid(
                "watchdog registration deadline or retained FDs changed",
            ));
        }
        match &self.exchange {
            TrustedHostWatchdogExchange::Idle => {}
            TrustedHostWatchdogExchange::AwaitingRegistrationAck {
                registration_sha256,
            } if registration_sha256
                == &registration.registration_sha256 =>
            {
                return Ok(Some(()));
            }
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog client has another in-flight exchange",
                ));
            }
        }
        self.revalidate_peer()?;
        require_exact_retained_watchdog_fds(
            registration,
            retained_fds,
        )?;
        let frame = exact_canonical_frame(registration)?;
        let raw_fds: [RawFd; 6] =
            std::array::from_fn(|index| {
                retained_fds[index].as_raw_fd()
            });
        match try_send_seqpacket_with_rights_nonblocking(
            self.socket.as_raw_fd(),
            &frame,
            &raw_fds,
        )? {
            Some(()) => {
                require_exact_retained_watchdog_fds(
                    registration,
                    retained_fds,
                )?;
                self.revalidate_peer()?;
                deadline.require_live().map_err(|_| {
                    RecoveryError::Deadline(
                        "watchdog registration send crossed its deadline",
                    )
                })?;
                self.exchange =
                    TrustedHostWatchdogExchange::
                        AwaitingRegistrationAck {
                            registration_sha256:
                                registration
                                    .registration_sha256
                                    .clone(),
                        };
                Ok(Some(()))
            }
            None => {
                self.progress
                    .arm_progress(&[PollTarget::socket(
                        self.socket.as_fd(),
                        PollInterest::WRITABLE,
                    )])
                    .map_err(|_| {
                        RecoveryError::Transient(
                            "watchdog registration progress registration failed",
                        )
                    })?;
                Ok(None)
            }
        }
    }

    pub(super) fn try_receive_registration_ack_nonblocking(
        &mut self,
        registration: &WatchdogRegistrationV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<SignedWatchdogOwnershipAckV3>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog acknowledgement authority expired",
            )
        })?;
        match &self.exchange {
            TrustedHostWatchdogExchange::AwaitingRegistrationAck {
                registration_sha256,
            } if registration_sha256
                == &registration.registration_sha256 => {}
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog acknowledgement has no matching registration",
                ));
            }
        }
        self.revalidate_peer()?;
        let Some(frame) = try_receive_seqpacket_nonblocking(
            self.socket.as_raw_fd(),
            MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES,
        )?
        else {
            self.progress
                .arm_progress(&[PollTarget::socket(
                    self.socket.as_fd(),
                    PollInterest::READABLE,
                )])
                .map_err(|_| {
                    RecoveryError::Transient(
                        "watchdog acknowledgement progress registration failed",
                    )
                })?;
            return Ok(None);
        };
        let acknowledgement:
            SignedWatchdogOwnershipAckV3 =
            decode_exact_canonical_frame(&frame)?;
        acknowledgement.validate_shape().map_err(|error| {
            protocol_error(
                error,
                "watchdog acknowledgement shape is invalid",
            )
        })?;
        acknowledgement
            .ownership
            .validate_against_registration(registration)
            .map_err(|error| {
                protocol_error(
                    error,
                    "watchdog acknowledgement changed the registration",
                )
            })?;
        self.revalidate_peer()?;
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog acknowledgement crossed its deadline",
            )
        })?;
        Ok(Some(acknowledgement))
    }

    pub(super) fn verify_registration_ack_current<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &mut self,
        provider: &mut P,
        registration: &WatchdogRegistrationV3,
        acknowledgement: &SignedWatchdogOwnershipAckV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<VerifiedWatchdogOwnershipAck, RecoveryError> {
        match &self.exchange {
            TrustedHostWatchdogExchange::AwaitingRegistrationAck {
                registration_sha256,
            } if registration_sha256
                == &registration.registration_sha256 => {}
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog acknowledgement verification has no pending registration",
                ));
            }
        }
        let verified =
            verify_watchdog_ownership_ack_with_current_provider(
            provider,
            registration,
            acknowledgement,
            &ProtocolBoottimeDeadline::from_runtime(*deadline),
        )
        .map_err(|_| {
            RecoveryError::Authorization(
                "watchdog acknowledgement failed current-key verification",
            )
        })?;
        self.exchange = TrustedHostWatchdogExchange::Registered {
            registration_sha256:
                registration.registration_sha256.clone(),
            ownership_id_sha256: verified
                .acknowledgement()
                .ownership
                .ownership_id_sha256
                .clone(),
            ownership_state_sha256: verified
                .acknowledgement()
                .ownership
                .state_sha256
                .clone(),
        };
        Ok(verified)
    }

    pub(super) fn fresh_query(
        registration: &WatchdogRegistrationV3,
        verified: &VerifiedWatchdogOwnershipAck,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<WatchdogOwnershipQueryV3, RecoveryError> {
        registration.validate().map_err(|error| {
            protocol_error(
                error,
                "watchdog query registration is invalid",
            )
        })?;
        if verified
            .acknowledgement()
            .ownership
            .registration_sha256
            != registration.registration_sha256
        {
            return Err(RecoveryError::Authorization(
                "watchdog query acknowledgement changed its registration",
            ));
        }
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog query authority expired",
            )
        })?;
        let mut nonce = [0_u8; WATCHDOG_QUERY_NONCE_BYTES];
        fill_random_nonblocking_exact(&mut nonce)?;
        let issued_at_boottime_nanos =
            match boottime_now_nanos() {
                Ok(observed)
                    if observed > 0
                        && observed < deadline.absolute_nanos() =>
                {
                    observed
                }
                Ok(_) => {
                    nonce.zeroize();
                    return Err(RecoveryError::Deadline(
                        "watchdog query issuance crossed its exact deadline",
                    ));
                }
                Err(_) => {
                    nonce.zeroize();
                    return Err(RecoveryError::Deadline(
                        "watchdog query issuance lacks CLOCK_BOOTTIME",
                    ));
                }
            };
        let query = WatchdogOwnershipQueryV3::fresh(
            registration.registration_sha256.clone(),
            verified
                .acknowledgement()
                .ownership
                .ownership_id_sha256
                .clone(),
            verified
                .acknowledgement()
                .ownership
                .state_sha256
                .clone(),
            Sha256Digest::compute(&nonce),
            issued_at_boottime_nanos,
            ProtocolBoottimeDeadline::from_runtime(*deadline),
        );
        nonce.zeroize();
        query.map_err(|error| {
            protocol_error(error, "fresh watchdog query is invalid")
        })
    }

    pub(super) fn try_send_query_nonblocking(
        &mut self,
        query: &WatchdogOwnershipQueryV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog query authority expired",
            )
        })?;
        query.validate().map_err(|error| {
            protocol_error(error, "watchdog query is invalid")
        })?;
        if query.deadline
            != ProtocolBoottimeDeadline::from_runtime(*deadline)
        {
            return Err(RecoveryError::Deadline(
                "watchdog query changed its exact deadline",
            ));
        }
        let (
            registration_sha256,
            ownership_id_sha256,
            ownership_state_sha256,
        ) = match &self.exchange {
            TrustedHostWatchdogExchange::Registered {
                registration_sha256,
                ownership_id_sha256,
                ownership_state_sha256,
            } if query.registration_sha256
                    == *registration_sha256
                && query.ownership_id_sha256
                    == *ownership_id_sha256
                && query.expected_state_sha256
                    == *ownership_state_sha256 =>
            {
                (
                    registration_sha256.clone(),
                    ownership_id_sha256.clone(),
                    ownership_state_sha256.clone(),
                )
            }
            TrustedHostWatchdogExchange::AwaitingQueryReply {
                registration_sha256,
                ownership_id_sha256,
                ownership_state_sha256,
                query_nonce_sha256,
            } if query.registration_sha256
                    == *registration_sha256
                && query.ownership_id_sha256
                    == *ownership_id_sha256
                && query.expected_state_sha256
                    == *ownership_state_sha256
                && query.query_nonce_sha256
                    == *query_nonce_sha256 =>
            {
                return Ok(Some(()));
            }
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog query does not bind the registered ownership",
                ));
            }
        };
        self.revalidate_peer()?;
        let frame = exact_canonical_frame(query)?;
        match try_send_seqpacket_with_rights_nonblocking(
            self.socket.as_raw_fd(),
            &frame,
            &[],
        )? {
            Some(()) => {
                self.revalidate_peer()?;
                deadline.require_live().map_err(|_| {
                    RecoveryError::Deadline(
                        "watchdog query send crossed its deadline",
                    )
                })?;
                self.exchange =
                    TrustedHostWatchdogExchange::AwaitingQueryReply {
                        registration_sha256,
                        ownership_id_sha256,
                        ownership_state_sha256,
                        query_nonce_sha256:
                            query.query_nonce_sha256.clone(),
                    };
                Ok(Some(()))
            }
            None => {
                self.progress
                    .arm_progress(&[PollTarget::socket(
                        self.socket.as_fd(),
                        PollInterest::WRITABLE,
                    )])
                    .map_err(|_| {
                        RecoveryError::Transient(
                            "watchdog query progress registration failed",
                        )
                    })?;
                Ok(None)
            }
        }
    }

    pub(super) fn try_receive_query_reply_nonblocking(
        &mut self,
        query: &WatchdogOwnershipQueryV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<WatchdogOwnershipQueryReplyV3>, RecoveryError> {
        let (
            registration_sha256,
            ownership_id_sha256,
            ownership_state_sha256,
        ) = match &self.exchange {
            TrustedHostWatchdogExchange::AwaitingQueryReply {
                registration_sha256,
                ownership_id_sha256,
                ownership_state_sha256,
                query_nonce_sha256,
            } if query.query_nonce_sha256
                == *query_nonce_sha256 =>
            {
                (
                    registration_sha256.clone(),
                    ownership_id_sha256.clone(),
                    ownership_state_sha256.clone(),
                )
            }
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog query reply has no matching request",
                ));
            }
        };
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog query reply authority expired",
            )
        })?;
        self.revalidate_peer()?;
        let Some(frame) = try_receive_seqpacket_nonblocking(
            self.socket.as_raw_fd(),
            MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES,
        )?
        else {
            self.progress
                .arm_progress(&[PollTarget::socket(
                    self.socket.as_fd(),
                    PollInterest::READABLE,
                )])
                .map_err(|_| {
                    RecoveryError::Transient(
                        "watchdog query reply progress registration failed",
                    )
                })?;
            return Ok(None);
        };
        let reply: WatchdogOwnershipQueryReplyV3 =
            decode_exact_canonical_frame(&frame)?;
        reply
            .validate_exact_fresh_binding(query)
            .map_err(|error| {
                protocol_error(
                    error,
                    "watchdog query reply lacks an exact fresh binding",
                )
            })?;
        reply.signed_envelope.validate_shape().map_err(|error| {
            protocol_error(
                error,
                "watchdog query reply signature envelope is invalid",
            )
        })?;
        let authoritative = reply
            .response
            .authoritative_ownership
            .as_ref()
            .ok_or(RecoveryError::Authorization(
                "watchdog query did not return authoritative ownership",
            ))?;
        if authoritative.ownership.registration_sha256
                != registration_sha256
            || authoritative.ownership.ownership_id_sha256
                != ownership_id_sha256
            || authoritative.ownership.state_sha256
                != ownership_state_sha256
            || reply.signed_envelope.request_nonce_sha256
                != query.query_nonce_sha256
        {
            return Err(RecoveryError::Authorization(
                "watchdog query reply changed the registered ownership",
            ));
        }
        self.revalidate_peer()?;
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "watchdog query reply crossed its exact deadline",
            )
        })?;
        Ok(Some(reply))
    }

    pub(super) fn verify_query_reply_current<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &mut self,
        provider: &mut P,
        registration: &WatchdogRegistrationV3,
        initially_verified: &VerifiedWatchdogOwnershipAck,
        query: &WatchdogOwnershipQueryV3,
        reply: &WatchdogOwnershipQueryReplyV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<VerifiedWatchdogOwnershipAck, RecoveryError> {
        let (
            registration_sha256,
            ownership_id_sha256,
            ownership_state_sha256,
        ) = match &self.exchange {
            TrustedHostWatchdogExchange::AwaitingQueryReply {
                registration_sha256,
                ownership_id_sha256,
                ownership_state_sha256,
                query_nonce_sha256,
            } if query.registration_sha256
                    == *registration_sha256
                && query.ownership_id_sha256
                    == *ownership_id_sha256
                && query.expected_state_sha256
                    == *ownership_state_sha256
                && query.query_nonce_sha256
                    == *query_nonce_sha256 =>
            {
                (
                    registration_sha256.clone(),
                    ownership_id_sha256.clone(),
                    ownership_state_sha256.clone(),
                )
            }
            _ => {
                return Err(RecoveryError::Conflict(
                    "watchdog query verification has no matching pending reply",
                ));
            }
        };
        let verified = verify_watchdog_ownership_query_confirmation(
            provider,
            registration,
            initially_verified,
            query,
            reply,
            &ProtocolBoottimeDeadline::from_runtime(*deadline),
        )
        .map_err(|_| {
            RecoveryError::Authorization(
                "watchdog query reply failed fresh current-key verification",
            )
        })?;
        self.exchange = TrustedHostWatchdogExchange::Registered {
            registration_sha256,
            ownership_id_sha256,
            ownership_state_sha256,
        };
        Ok(verified)
    }

    fn revalidate_peer(&self) -> Result<(), RecoveryError> {
        let mut socket_type: libc::c_int = 0;
        let mut domain: libc::c_int = 0;
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let expected_integer_length =
            libc::socklen_t::try_from(size_of::<libc::c_int>())
                .map_err(|_| {
                    RecoveryError::Invalid(
                        "watchdog socket option length overflow",
                    )
                })?;
        let expected_credential_length =
            libc::socklen_t::try_from(size_of::<libc::ucred>())
                .map_err(|_| {
                    RecoveryError::Invalid(
                        "watchdog credential length overflow",
                    )
                })?;
        let mut integer_length = expected_integer_length;
        let mut credential_length = expected_credential_length;
        if unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut libc::c_int).cast(),
                &mut integer_length,
            )
        } != 0
            || integer_length != expected_integer_length
        {
            return Err(RecoveryError::Authorization(
                "watchdog socket type cannot be verified",
            ));
        }
        integer_length = expected_integer_length;
        if unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut integer_length,
            )
        } != 0
            || unsafe {
                libc::getsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast(),
                    &mut credential_length,
                )
            } != 0
            || integer_length != expected_integer_length
            || credential_length != expected_credential_length
            || socket_type != libc::SOCK_SEQPACKET
            || domain != libc::AF_UNIX
            || credentials.uid != self.expected_peer_uid
            || credentials.gid != self.expected_peer_gid
            || self
                .expected_peer_pid
                .is_some_and(|pid| credentials.pid != pid)
        {
            return Err(RecoveryError::Authorization(
                "watchdog UDS peer is not the pinned local authority",
            ));
        }
        Ok(())
    }
}

fn exact_canonical_frame<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, RecoveryError> {
    let frame = canonical_json_bytes(value).map_err(|_| {
        RecoveryError::Invalid(
            "watchdog protocol frame is not canonical",
        )
    })?;
    if frame.is_empty()
        || frame.len() > MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES
    {
        return Err(RecoveryError::Invalid(
            "watchdog protocol frame exceeds its fixed bound",
        ));
    }
    Ok(frame)
}

fn require_exact_retained_watchdog_fds(
    registration: &WatchdogRegistrationV3,
    retained_fds: &[BorrowedFd<'_>; 6],
) -> Result<(), RecoveryError> {
    if registration.retained_fds.len() != retained_fds.len() {
        return Err(RecoveryError::Authorization(
            "watchdog retained-FD manifest length changed",
        ));
    }
    for (expected, descriptor) in registration
        .retained_fds
        .iter()
        .zip(retained_fds)
    {
        if observed_retained_watchdog_fd(
            expected.role,
            *descriptor,
        )? != *expected
        {
            return Err(RecoveryError::Authorization(
                "watchdog retained-FD identity changed",
            ));
        }
    }
    require_distinct_watchdog_open_file_descriptions(retained_fds)?;
    Ok(())
}

fn require_distinct_watchdog_open_file_descriptions(
    descriptors: &[BorrowedFd<'_>; 6],
) -> Result<(), RecoveryError> {
    const KCMP_FILE: libc::c_int = 0;
    let process = unsafe { libc::getpid() };
    for left in 0..descriptors.len() {
        for right in (left + 1)..descriptors.len() {
            let compared = unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    process,
                    process,
                    KCMP_FILE,
                    descriptors[left].as_raw_fd(),
                    descriptors[right].as_raw_fd(),
                )
            };
            if compared == 0 {
                return Err(RecoveryError::Authorization(
                    "watchdog retained descriptor roles alias one open file description",
                ));
            }
            if compared < 0 {
                return Err(RecoveryError::Authorization(
                    "watchdog retained descriptor alias proof is unavailable",
                ));
            }
        }
    }
    Ok(())
}

fn observed_retained_watchdog_fd(
    role: WatchdogRegistrationFdRole,
    descriptor: BorrowedFd<'_>,
) -> Result<WatchdogRetainedFdIdentityV3, RecoveryError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: libc::statx = unsafe { zeroed() };
    const STATX_MNT_ID_MASK: libc::c_uint = 0x0000_1000;
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
        || unsafe {
            libc::statx(
                descriptor.as_raw_fd(),
                b"\0".as_ptr().cast(),
                libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_BASIC_STATS | STATX_MNT_ID_MASK,
                &mut statx,
            )
        } != 0
        || statx.stx_mask & libc::STATX_BASIC_STATS
            != libc::STATX_BASIC_STATS
        || statx.stx_mask & STATX_MNT_ID_MASK == 0
        || stat.st_size < 0
        || statx.stx_ino != stat.st_ino
        || statx.stx_size != stat.st_size as u64
        || u32::from(statx.stx_mode) != stat.st_mode
    {
        return Err(RecoveryError::Authorization(
            "watchdog retained FD stat/statx identity is unavailable",
        ));
    }
    let device = stat.st_dev.to_be_bytes();
    let inode = stat.st_ino.to_be_bytes();
    let mode = stat.st_mode.to_be_bytes();
    let uid = stat.st_uid.to_be_bytes();
    let gid = stat.st_gid.to_be_bytes();
    let length = (stat.st_size as u64).to_be_bytes();
    let modified_seconds = stat.st_mtime.to_be_bytes();
    let modified_nanoseconds = stat.st_mtime_nsec.to_be_bytes();
    let changed_seconds = stat.st_ctime.to_be_bytes();
    let changed_nanoseconds = stat.st_ctime_nsec.to_be_bytes();
    let mount_id = statx.stx_mnt_id.to_be_bytes();
    let frames: [&[u8]; 11] = [
        &device,
        &inode,
        &mode,
        &uid,
        &gid,
        &length,
        &modified_seconds,
        &modified_nanoseconds,
        &changed_seconds,
        &changed_nanoseconds,
        &mount_id,
    ];
    let mut hasher = Sha256::new();
    for frame in frames {
        hasher.update((frame.len() as u64).to_be_bytes());
        hasher.update(frame);
    }
    let digest = Sha256Digest::parse(format!(
        "sha256:{}",
        hex::encode(hasher.finalize())
    ))
    .map_err(|_| {
        RecoveryError::Invalid(
            "watchdog retained-FD digest encoding failed",
        )
    })?;
    let observed = WatchdogRetainedFdIdentityV3 {
        role,
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mount_id: statx.stx_mnt_id,
        retained_fd_stat_sha256: digest,
    };
    observed.validate().map_err(|error| {
        protocol_error(
            error,
            "observed watchdog retained-FD identity is invalid",
        )
    })?;
    Ok(observed)
}

fn decode_exact_canonical_frame<T>(
    frame: &[u8],
) -> Result<T, RecoveryError>
where
    T: DeserializeOwned + Serialize,
{
    if frame.is_empty()
        || frame.len() > MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES
    {
        return Err(RecoveryError::Invalid(
            "watchdog response frame exceeds its fixed bound",
        ));
    }
    let value: T = serde_json::from_slice(frame).map_err(|_| {
        RecoveryError::Invalid(
            "watchdog response is not typed JSON",
        )
    })?;
    if exact_canonical_frame(&value)? != frame {
        return Err(RecoveryError::Invalid(
            "watchdog response is not exact canonical JSON",
        ));
    }
    Ok(value)
}

fn try_send_seqpacket_with_rights_nonblocking(
    socket_fd: RawFd,
    frame: &[u8],
    rights: &[RawFd],
) -> Result<Option<()>, RecoveryError> {
    if frame.is_empty()
        || frame.len() > MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES
        || rights.len() > 6
        || rights.iter().any(|fd| *fd < 0)
    {
        return Err(RecoveryError::Invalid(
            "watchdog seqpacket or SCM_RIGHTS set is invalid",
        ));
    }
    let mut io_vector = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    let mut control = TrustedHostScmRights([0; 256]);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    if !rights.is_empty() {
        let rights_bytes = rights
            .len()
            .checked_mul(size_of::<RawFd>())
            .ok_or(RecoveryError::Invalid(
                "SCM_RIGHTS byte length overflow",
            ))?;
        let rights_bytes_u32 =
            libc::c_uint::try_from(rights_bytes).map_err(|_| {
                RecoveryError::Invalid(
                    "SCM_RIGHTS byte length conversion failed",
                )
            })?;
        let control_length =
            unsafe { libc::CMSG_SPACE(rights_bytes_u32) } as usize;
        if control_length > control.0.len() {
            return Err(RecoveryError::Invalid(
                "SCM_RIGHTS exceeds its fixed control buffer",
            ));
        }
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = control_length;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(RecoveryError::Invalid(
                "SCM_RIGHTS control header is unavailable",
            ));
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(rights_bytes_u32) as usize;
            ptr::copy_nonoverlapping(
                rights.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                rights_bytes,
            );
        }
    }
    loop {
        let sent = unsafe {
            libc::sendmsg(
                socket_fd,
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent == frame.len() as isize {
            return Ok(Some(()));
        }
        if sent >= 0 {
            return Err(RecoveryError::Durable(
                "watchdog seqpacket send was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => {
                return Err(RecoveryError::Transient(
                    "watchdog seqpacket send failed",
                ));
            }
        }
    }
}

fn try_receive_seqpacket_nonblocking(
    socket_fd: RawFd,
    maximum_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, RecoveryError> {
    if maximum_frame_bytes == 0
        || maximum_frame_bytes
            > MAX_TRUSTED_HOST_WATCHDOG_FRAME_BYTES
    {
        return Err(RecoveryError::Invalid(
            "watchdog receive frame bound is invalid",
        ));
    }
    loop {
        let mut frame = vec![0_u8; maximum_frame_bytes];
        let received = unsafe {
            libc::recv(
                socket_fd,
                frame.as_mut_ptr().cast(),
                frame.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received > 0
            && usize::try_from(received).ok().is_some_and(|length| {
                length <= frame.len()
            })
        {
            frame.truncate(usize::try_from(received).map_err(|_| {
                RecoveryError::Invalid(
                    "watchdog response length overflow",
                )
            })?);
            return Ok(Some(frame));
        }
        if received == 0 {
            return Err(RecoveryError::Durable(
                "watchdog authority closed its authenticated socket",
            ));
        }
        if received > 0 {
            return Err(RecoveryError::Invalid(
                "watchdog response exceeded its fixed frame bound",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => {
                return Err(RecoveryError::Transient(
                    "watchdog seqpacket receive failed",
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn fill_random_nonblocking_exact(
    bytes: &mut [u8],
) -> Result<(), RecoveryError> {
    let mut filled = 0_usize;
    while filled < bytes.len() {
        let received = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes[filled..].as_mut_ptr(),
                bytes.len() - filled,
                libc::GRND_NONBLOCK,
            )
        };
        if received > 0 {
            filled = filled
                .checked_add(usize::try_from(received).map_err(
                    |_| {
                        RecoveryError::Invalid(
                            "getrandom length overflow",
                        )
                    },
                )?)
                .ok_or(RecoveryError::Invalid(
                    "getrandom accumulation overflow",
                ))?;
            continue;
        }
        if received == 0 {
            return Err(RecoveryError::Invalid(
                "getrandom returned no entropy",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::EAGAIN) => {
                bytes.zeroize();
                return Err(RecoveryError::Transient(
                    "getrandom entropy is not ready",
                ));
            }
            _ => {
                bytes.zeroize();
                return Err(RecoveryError::Invalid(
                    "getrandom failed",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn fill_random_nonblocking_exact(
    bytes: &mut [u8],
) -> Result<(), RecoveryError> {
    bytes.zeroize();
    Err(RecoveryError::Invalid(
        "trusted-host watchdog requires Linux getrandom",
    ))
}
