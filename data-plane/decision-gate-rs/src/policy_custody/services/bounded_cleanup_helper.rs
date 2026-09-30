//! TrustedHostNoTee bounded cleanup helper.
//!
//! The service is deliberately a local, software-only authority. It accepts
//! only authenticated inherited AF_UNIX SOCK_SEQPACKET peers, binds every
//! effect to v3 policy-custody evidence, persists an immutable signed intent
//! before mutation, and executes only through SCM_RIGHTS-retained descriptors.

use super::common::{
    decode_canonical_frame, encode_canonical_frame,
    AuthenticatedInheritedSeqpacket, DurableAppendJournal,
    ExpectedPeerCredentials, NonblockingExchangeProgress,
    NonblockingRequestReplyExchange, PeerCredentialsV3, ServiceError,
    JournalAppendOutcome,
    ReceivedSeqpacket,
    ServiceHandshakeReplyV3, ServiceHandshakeRequestV3,
    ServiceCurrentHeadBindingV3, ServiceRequestFrameV3,
    ServiceResponseFrameV3, TrustedHostNoTeeServiceReportV3,
    TrustedHostServiceRoleV3, MAX_SERVICE_FRAME_BYTES,
};
use super::wire::{
    BoundedCleanupHelperReplyV3, BoundedCleanupHelperRequestV3,
    CleanupEffectExpectedStateV3,
    CleanupEffectIntentV3, CleanupEffectJournalStateV3,
    CleanupEffectKeyV3, PersistedCleanupEffectExecutionV3,
    PersistedCleanupEffectIntentV3,
    PersistedCleanupEffectResultV3,
    DurableCleanupEffectEvidenceV3,
    PersistedCleanupWorkerParentProofV3,
    CleanupHelperBootstrapReplyV3,
    CleanupHelperBootstrapRequestV3,
    CleanupHelperExpectedManifestV3,
    CleanupHelperReadinessSealV3,
    PolicyCustodyServiceReplyV3, PolicyCustodyServiceRequestV3,
    CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION,
    CLEANUP_WORKER_PARENT_PROOF_DOMAIN,
};
use super::super::boottime::{
    boottime_now_nanos, BoottimeDeadline as AbsoluteBoottimeDeadline,
};
use super::super::protocol::{
    domain_separated_signature_preimage, require_nonzero_digest,
    CgroupPopulationObservation, CleanupAction,
    CleanupResultSignedPayload, PolicyCustodyEndpointRole,
    ProtocolBoottimeDeadline, SignedCleanupResultV3,
    WatchdogRegistrationFdRole, WatchdogRetainedFdIdentityV3,
    WorkerPidfdObservation,
};
use super::super::watchdog_recovery::{
    BoundedCleanupHelper, CleanupTarget, ExactCleanupBinding,
    RecoveryDigest, RecoveryError,
    UnverifiedDurableCleanupEffectEvidence,
};
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::ptr;

const CLEANUP_INTENT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectIntentReceipt/v3";
const CLEANUP_INTENT_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectIntentReceipt/v3";
const CLEANUP_RESULT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyVerifiedCleanupResult/v1";
const CLEANUP_RESULT_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyVerifiedCleanupResultReceipt/v1";
const CLEANUP_RESULT_RECORD_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupEffectResultRecord/v3";
const MAX_CLIENT_OPERATIONS: usize = 256;
const CLEANUP_PREPARE_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupPrepareIdempotency/v3";
const CLEANUP_EXECUTE_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupExecuteIdempotency/v3";
const CLEANUP_QUERY_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupQueryIdempotency/v3";
const CLEANUP_REQUEST_ID_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupHelperRequestId/v3";
const CLEANUP_REAP_OBSERVATION_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupReapObservationIdempotency/v3";
const CLEANUP_REAP_OBSERVATION_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupReapObservation/v3";
const CLEANUP_EXECUTION_CHECKPOINT_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupExecutionCheckpointIdempotency/v3";
const CLEANUP_EXECUTION_CHECKPOINT_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupExecutionCheckpointRequest/v3";
const CLEANUP_PARENT_PROOF_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupParentProofIdempotency/v3";
const CLEANUP_PARENT_PROOF_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupParentProofRequest/v3";
const REAP_OBSERVATION_VERSION: &str =
    "serverware.policyCustodyCleanupReapObservation/v3";
const VERIFIED_CLEANUP_EVIDENCE_VERSION: &str =
    "serverware.policyCustodyWatchdogVerifiedCleanupEvidence/v3";
const MAX_CLIENT_TRANSITIONS_PER_CALL: usize = 8;
const MAX_CGROUP_EVENTS_BYTES: usize = 4_096;
const MAX_QUERY_SEQUENCE: u64 = 1_000_000;
const MAX_CLEANUP_JOURNAL_RECORDS: usize = 1_000_000;
const MAX_CLEANUP_JOURNAL_RECOVERY_BYTES: usize =
    256 * 1024 * 1024;
const EXACT_EXECUTE_RIGHTS: usize = 2;
const P_PIDFD_IDTYPE: libc::c_uint = 3;
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;

fn service_to_recovery(error: ServiceError) -> RecoveryError {
    match error {
        ServiceError::IdempotencyConflict => RecoveryError::Conflict(
            "bounded cleanup service idempotency conflict",
        ),
        ServiceError::JournalBusy => RecoveryError::Durable(
            "bounded cleanup service journal is busy",
        ),
        ServiceError::Io(_) => RecoveryError::Transient(
            "bounded cleanup service transport failed",
        ),
        ServiceError::Protocol(_)
        | ServiceError::Invalid(_)
        | ServiceError::InvalidOwned(_) => RecoveryError::Authorization(
            "bounded cleanup service rejected a v3 frame",
        ),
    }
}

fn require_live_protocol_deadline(
    deadline: &ProtocolBoottimeDeadline,
) -> Result<AbsoluteBoottimeDeadline, ServiceError> {
    let runtime = deadline.to_runtime()?;
    runtime.require_live().map_err(|_| {
        ServiceError::Invalid(
            "bounded cleanup operation crossed its exact BOOTTIME deadline",
        )
    })?;
    Ok(runtime)
}

fn require_exact_runtime_deadline(
    passed: &AbsoluteBoottimeDeadline,
    expected: &ProtocolBoottimeDeadline,
) -> Result<(), RecoveryError> {
    let expected = expected.to_runtime().map_err(|_| {
        RecoveryError::Invalid(
            "bounded cleanup intent has an invalid BOOTTIME deadline",
        )
    })?;
    if *passed != expected {
        return Err(RecoveryError::Authorization(
            "bounded cleanup call changed its exact BOOTTIME deadline",
        ));
    }
    Ok(())
}

fn prepare_idempotency(key: &CleanupEffectKeyV3) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_PREPARE_IDEMPOTENCY_DOMAIN,
        &[key.intent_sha256.as_str().as_bytes()],
    )
}

fn execute_idempotency(
    key: &CleanupEffectKeyV3,
    intent_receipt_sha256: &Sha256Digest,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_EXECUTE_IDEMPOTENCY_DOMAIN,
        &[
            key.intent_sha256.as_str().as_bytes(),
            intent_receipt_sha256.as_str().as_bytes(),
        ],
    )
}

fn reap_observation_idempotency(
    key: &CleanupEffectKeyV3,
    intent_receipt_sha256: &Sha256Digest,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_REAP_OBSERVATION_IDEMPOTENCY_DOMAIN,
        &[
            key.intent_sha256.as_str().as_bytes(),
            intent_receipt_sha256.as_str().as_bytes(),
        ],
    )
}

fn execution_checkpoint_idempotency(
    key: &CleanupEffectKeyV3,
    intent_receipt_sha256: &Sha256Digest,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_EXECUTION_CHECKPOINT_IDEMPOTENCY_DOMAIN,
        &[
            key.intent_sha256.as_str().as_bytes(),
            intent_receipt_sha256.as_str().as_bytes(),
        ],
    )
}

fn parent_proof_idempotency(
    key: &CleanupEffectKeyV3,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_PARENT_PROOF_IDEMPOTENCY_DOMAIN,
        &[key.intent_sha256.as_str().as_bytes()],
    )
}

fn exact_execution_checkpoint_request(
    prepared: &PersistedCleanupEffectIntentV3,
    exact_execute_request: &[u8],
) -> Result<Vec<u8>, ServiceError> {
    encode_canonical_frame(&(
        CLEANUP_EXECUTION_CHECKPOINT_REQUEST_DOMAIN,
        prepared.intent.key(),
        &prepared.intent_receipt_sha256,
        Sha256Digest::compute(exact_execute_request),
        &prepared.intent.evidence_query_deadline,
    ))
}

fn exact_parent_proof_request(
    intent: &CleanupEffectIntentV3,
) -> Result<Vec<u8>, ServiceError> {
    encode_canonical_frame(&(
        CLEANUP_PARENT_PROOF_REQUEST_DOMAIN,
        intent.key(),
        &intent.worker,
        &intent.retained_descriptors.worker_pidfd,
        &intent.evidence_query_deadline,
    ))
}

fn exact_reap_observation_request(
    prepared: &PersistedCleanupEffectIntentV3,
) -> Result<Vec<u8>, ServiceError> {
    encode_canonical_frame(&(
        "serverware.policyCustodyCleanupReapObservationRequest/v3",
        prepared.intent.key(),
        &prepared.intent_receipt_sha256,
        &prepared.intent.retained_descriptors.worker_pidfd,
        prepared.intent.worker.pid,
        &prepared.intent.cleanup_deadline,
    ))
}

fn query_identity(
    key: &CleanupEffectKeyV3,
    sequence: u64,
) -> (Sha256Digest, Sha256Digest) {
    let sequence = sequence.to_be_bytes();
    let request_id = hash_domain_frames(
        CLEANUP_REQUEST_ID_DOMAIN,
        &[
            b"query",
            key.intent_sha256.as_str().as_bytes(),
            &sequence,
        ],
    );
    let idempotency = query_idempotency_for_request(key, &request_id);
    (request_id, idempotency)
}

fn query_idempotency_for_request(
    key: &CleanupEffectKeyV3,
    request_id: &Sha256Digest,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_QUERY_IDEMPOTENCY_DOMAIN,
        &[
            key.intent_sha256.as_str().as_bytes(),
            request_id.as_str().as_bytes(),
        ],
    )
}

fn stage_request_id(
    stage: &[u8],
    key: &CleanupEffectKeyV3,
) -> Sha256Digest {
    hash_domain_frames(
        CLEANUP_REQUEST_ID_DOMAIN,
        &[stage, key.intent_sha256.as_str().as_bytes()],
    )
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid(
            "bounded cleanup signed value is not canonical",
        )
    })?;
    let domain_length = u64::try_from(domain.len()).map_err(|_| {
        ServiceError::Invalid("signature domain length overflow")
    })?;
    let canonical_length =
        u64::try_from(canonical.len()).map_err(|_| {
            ServiceError::Invalid("canonical value length overflow")
        })?;
    let mut framed = Vec::with_capacity(
        domain
            .len()
            .checked_add(canonical.len())
            .and_then(|length| length.checked_add(16))
            .ok_or(ServiceError::Invalid(
                "signed value frame length overflow",
            ))?,
    );
    framed.extend_from_slice(&domain_length.to_be_bytes());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(&canonical_length.to_be_bytes());
    framed.extend_from_slice(&canonical);
    Ok(Sha256Digest::compute(&framed))
}

#[derive(Clone)]
pub(super) struct TrustedHostCleanupEffectOperationV3 {
    pub(super) intent: CleanupEffectIntentV3,
    pub(super) mutation_current_head: ServiceCurrentHeadBindingV3,
    pub(super) evidence_current_head: ServiceCurrentHeadBindingV3,
}

impl TrustedHostCleanupEffectOperationV3 {
    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        self.intent.validate()?;
        self.mutation_current_head.validate(
            self.intent.action.required_endpoint_role(),
            &self.intent.cleanup_deadline,
        )?;
        self.evidence_current_head.validate(
            self.intent.action.required_endpoint_role(),
            &self.intent.evidence_query_deadline,
        )
    }
}

#[derive(Clone)]
pub(super) struct ValidatedCleanupHelperHandshakeV3 {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) request: ServiceHandshakeRequestV3,
    pub(super) reply: ServiceHandshakeReplyV3,
}

impl ValidatedCleanupHelperHandshakeV3 {
    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        if self.request.service_role
            != TrustedHostServiceRoleV3::BoundedCleanupHelper
        {
            return Err(ServiceError::Invalid(
                "cleanup helper handshake has the wrong service role",
            ));
        }
        self.reply
            .validate_for_request(&self.request, self.endpoint_role)
    }
}

struct ClientOperationState {
    operation: TrustedHostCleanupEffectOperationV3,
    next_query_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientPhase {
    Query,
    Prepare,
    Execute,
}

struct ActiveClientOperation {
    operation_index: usize,
    phase: ClientPhase,
}

/// Nonblocking, owner-scoped adapter for the existing watchdog recovery trait.
///
/// Construction receives the full verified v3 operation material that the
/// legacy trait cannot carry. Every trait call is matched back to that material
/// before the client starts Query -> Prepare -> Execute.
pub(super) struct TrustedHostNoTeeBoundedCleanupHelperClient {
    progress_socket: OwnedFd,
    exchange: NonblockingRequestReplyExchange,
    handshake_roles: BTreeSet<PolicyCustodyEndpointRole>,
    operations: Vec<ClientOperationState>,
    active: Option<ActiveClientOperation>,
}

impl TrustedHostNoTeeBoundedCleanupHelperClient {
    pub(super) fn from_handshaken_inherited_socket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        handshakes: Vec<ValidatedCleanupHelperHandshakeV3>,
        operations: Vec<TrustedHostCleanupEffectOperationV3>,
    ) -> Result<Self, ServiceError> {
        if handshakes.is_empty()
            || operations.len() > MAX_CLIENT_OPERATIONS
        {
            return Err(ServiceError::Invalid(
                "cleanup helper client requires handshakes and a bounded operation set",
            ));
        }
        let mut handshake_roles = BTreeSet::new();
        for handshake in &handshakes {
            handshake.validate()?;
            if !handshake_roles.insert(handshake.endpoint_role) {
                return Err(ServiceError::Invalid(
                    "cleanup helper client has a duplicate role-specific handshake",
                ));
            }
        }
        for operation in &operations {
            operation.validate()?;
            let endpoint_role =
                operation.intent.action.required_endpoint_role();
            if !handshakes
                .iter()
                .any(|handshake| handshake.endpoint_role == endpoint_role)
            {
                return Err(ServiceError::Invalid(
                    "cleanup helper operation lacks a role-specific handshake",
                ));
            }
        }
        let progress_socket = duplicate_cloexec(socket.as_raw_fd())?;
        let peer = AuthenticatedInheritedSeqpacket::from_inherited(
            socket,
            expected_peer,
        )?;
        Ok(Self {
            progress_socket,
            exchange: NonblockingRequestReplyExchange::new(peer),
            handshake_roles,
            operations: operations
                .into_iter()
                .map(|operation| ClientOperationState {
                    operation,
                    next_query_sequence: 1,
                })
                .collect(),
            active: None,
        })
    }

    /// Installs material discovered by the durable startup scan. Installation
    /// is allowed only while the shared exchange is idle, is bounded across
    /// the lifetime of the client, and rejects duplicate effect keys even when
    /// the duplicate bytes are identical.
    pub(super) fn install_verified_operations_while_idle(
        &mut self,
        operations: Vec<TrustedHostCleanupEffectOperationV3>,
    ) -> Result<(), ServiceError> {
        if self.active.is_some() || !self.exchange.is_idle() {
            return Err(ServiceError::Invalid(
                "cleanup helper operations cannot change during an exchange",
            ));
        }
        let next_count = self
            .operations
            .len()
            .checked_add(operations.len())
            .ok_or(ServiceError::Invalid(
                "cleanup helper operation count overflowed",
            ))?;
        if operations.is_empty() || next_count > MAX_CLIENT_OPERATIONS {
            return Err(ServiceError::Invalid(
                "cleanup helper operation installation is empty or exceeds its fixed bound",
            ));
        }
        let mut incoming_keys = BTreeSet::new();
        for operation in &operations {
            operation.validate()?;
            let role =
                operation.intent.action.required_endpoint_role();
            if !self.handshake_roles.contains(&role) {
                return Err(ServiceError::Invalid(
                    "cleanup helper operation lacks a role-specific handshake",
                ));
            }
            let key = operation.intent.key();
            let encoded_key = encode_canonical_frame(&key)?;
            let key_sha256 = Sha256Digest::compute(&encoded_key);
            if !incoming_keys.insert(key_sha256)
                || self.operations.iter().any(|installed| {
                    installed.operation.intent.key() == key
                })
            {
                return Err(ServiceError::Invalid(
                    "cleanup helper operation installation duplicates an exact effect key",
                ));
            }
        }
        self.operations.extend(operations.into_iter().map(
            |operation| ClientOperationState {
                operation,
                next_query_sequence: 1,
            },
        ));
        Ok(())
    }

    fn matching_operation(
        &self,
        target: &CleanupTarget,
        binding: &ExactCleanupBinding,
        consumption_receipt_sha256: &RecoveryDigest,
    ) -> Result<usize, RecoveryError> {
        self.operations
            .iter()
            .position(|candidate| {
                let intent = &candidate.operation.intent;
                intent.action == binding.action
                    && intent.operation == binding.operation
                    && intent.operation_id_sha256
                        == binding.operation_id_sha256
                    && intent.durable_request_sha256
                        == binding.durable_request_sha256
                    && intent.request_sha256
                        == binding.request_sha256
                    && intent.termination_fence_sha256
                        == binding.termination_fence_sha256
                    && intent.cgroup == target.cgroup
                    && intent.worker == target.worker
                    && intent.predecessor == binding.predecessor
                    && intent.authorization.payload.authorization_nonce_sha256
                        == binding.authorization_nonce_sha256
                    && intent.operation_deadline
                        == binding.operation_deadline
                    && intent.cleanup_deadline
                        == binding.cleanup_deadline
                    && intent
                        .authorization_consumption
                        .signed_envelope
                        .envelope_sha256
                        == *consumption_receipt_sha256
            })
            .ok_or(RecoveryError::Authorization(
                "cleanup helper has no exact owner-scoped v3 operation",
            ))
    }

    fn begin_query(
        &mut self,
        operation_index: usize,
        target: &CleanupTarget,
    ) -> Result<(), RecoveryError> {
        let state = self.operations.get_mut(operation_index).ok_or(
            RecoveryError::Invalid(
                "cleanup helper operation index is invalid",
            ),
        )?;
        if state.next_query_sequence == 0
            || state.next_query_sequence > MAX_QUERY_SEQUENCE
        {
            return Err(RecoveryError::Conflict(
                "cleanup helper query sequence exhausted",
            ));
        }
        let key = state.operation.intent.key();
        let (request_id, idempotency) =
            query_identity(&key, state.next_query_sequence);
        state.next_query_sequence = state
            .next_query_sequence
            .checked_add(1)
            .ok_or(RecoveryError::Conflict(
                "cleanup helper query sequence overflow",
            ))?;
        let request =
            BoundedCleanupHelperRequestV3::Query {
                api_version:
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id.clone(),
                key,
                deadline:
                    state
                        .operation
                        .intent
                        .evidence_query_deadline
                        .clone(),
            };
        let payload =
            PolicyCustodyServiceRequestV3::BoundedCleanupHelper(
                request,
            );
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            request_id,
            idempotency,
            state
                .operation
                .intent
                .evidence_query_deadline
                .clone(),
            state.operation.evidence_current_head.clone(),
            &payload,
        )
        .map_err(service_to_recovery)?;
        let rights = [
            target.worker_pidfd.as_fd(),
            target.operation_cgroup_fd.as_fd(),
        ];
        self.exchange
            .begin(
                &frame,
                TrustedHostServiceRoleV3::BoundedCleanupHelper,
                state
                    .operation
                    .intent
                    .action
                    .required_endpoint_role(),
                &rights,
                EXACT_EXECUTE_RIGHTS,
                0,
            )
            .map_err(service_to_recovery)?;
        self.active = Some(ActiveClientOperation {
            operation_index,
            phase: ClientPhase::Query,
        });
        Ok(())
    }

    fn begin_prepare(
        &mut self,
        operation_index: usize,
    ) -> Result<(), RecoveryError> {
        let operation = self
            .operations
            .get(operation_index)
            .ok_or(RecoveryError::Invalid(
                "cleanup helper operation index is invalid",
            ))?
            .operation
            .clone();
        let key = operation.intent.key();
        let request_id = stage_request_id(b"prepare", &key);
        let request =
            BoundedCleanupHelperRequestV3::Prepare {
                api_version:
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id.clone(),
                intent: operation.intent.clone(),
                deadline: operation.intent.cleanup_deadline.clone(),
            };
        let payload =
            PolicyCustodyServiceRequestV3::BoundedCleanupHelper(
                request,
            );
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            request_id,
            prepare_idempotency(&key),
            operation.intent.cleanup_deadline.clone(),
            operation.mutation_current_head,
            &payload,
        )
        .map_err(service_to_recovery)?;
        self.exchange
            .begin(
                &frame,
                TrustedHostServiceRoleV3::BoundedCleanupHelper,
                operation
                    .intent
                    .action
                    .required_endpoint_role(),
                &[],
                0,
                0,
            )
            .map_err(service_to_recovery)?;
        self.active = Some(ActiveClientOperation {
            operation_index,
            phase: ClientPhase::Prepare,
        });
        Ok(())
    }

    fn begin_execute(
        &mut self,
        operation_index: usize,
        prepared: &PersistedCleanupEffectIntentV3,
        target: &CleanupTarget,
    ) -> Result<(), RecoveryError> {
        let operation = self
            .operations
            .get(operation_index)
            .ok_or(RecoveryError::Invalid(
                "cleanup helper operation index is invalid",
            ))?
            .operation
            .clone();
        prepared.validate().map_err(|_| {
            RecoveryError::Authorization(
                "cleanup helper returned an invalid persisted intent",
            )
        })?;
        if prepared.intent != operation.intent {
            return Err(RecoveryError::Conflict(
                "cleanup helper prepared a different exact intent",
            ));
        }
        let key = operation.intent.key();
        let request_id = stage_request_id(b"execute", &key);
        let request =
            BoundedCleanupHelperRequestV3::Execute {
                api_version:
                    POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id.clone(),
                key: key.clone(),
                prepared_intent_receipt_sha256:
                    prepared.intent_receipt_sha256.clone(),
                deadline: operation.intent.cleanup_deadline.clone(),
            };
        let payload =
            PolicyCustodyServiceRequestV3::BoundedCleanupHelper(
                request,
            );
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            request_id,
            execute_idempotency(
                &key,
                &prepared.intent_receipt_sha256,
            ),
            operation.intent.cleanup_deadline.clone(),
            operation.mutation_current_head,
            &payload,
        )
        .map_err(service_to_recovery)?;
        let rights = [
            target.worker_pidfd.as_fd(),
            target.operation_cgroup_fd.as_fd(),
        ];
        self.exchange
            .begin(
                &frame,
                TrustedHostServiceRoleV3::BoundedCleanupHelper,
                operation
                    .intent
                    .action
                    .required_endpoint_role(),
                &rights,
                EXACT_EXECUTE_RIGHTS,
                0,
            )
            .map_err(service_to_recovery)?;
        self.active = Some(ActiveClientOperation {
            operation_index,
            phase: ClientPhase::Execute,
        });
        Ok(())
    }

    fn decode_reply(
        response: &ServiceResponseFrameV3,
    ) -> Result<BoundedCleanupHelperReplyV3, RecoveryError> {
        let reply: PolicyCustodyServiceReplyV3 = response
            .decode_payload()
            .map_err(service_to_recovery)?;
        reply.validate().map_err(|_| {
            RecoveryError::Authorization(
                "cleanup helper returned invalid v3 evidence",
            )
        })?;
        match reply {
            PolicyCustodyServiceReplyV3::BoundedCleanupHelper(
                reply,
            ) => Ok(reply),
            _ => Err(RecoveryError::Authorization(
                "cleanup helper returned the wrong authority reply",
            )),
        }
    }

    fn require_state_matches(
        operation: &TrustedHostCleanupEffectOperationV3,
        state: &CleanupEffectJournalStateV3,
    ) -> Result<(), RecoveryError> {
        state.validate().map_err(|_| {
            RecoveryError::Authorization(
                "cleanup helper query returned invalid journal state",
            )
        })?;
        match state {
            CleanupEffectJournalStateV3::Prepared { intent }
                if intent.intent == operation.intent =>
            {
                Ok(())
            }
            CleanupEffectJournalStateV3::Executing {
                intent,
                execution,
            } if intent.intent == operation.intent
                && execution.key == operation.intent.key() =>
            {
                Ok(())
            }
            CleanupEffectJournalStateV3::Completed {
                intent,
                execution,
                result,
            } if intent.intent == operation.intent
                && execution.key == operation.intent.key()
                && result.key == operation.intent.key() =>
            {
                Ok(())
            }
            _ => Err(RecoveryError::Conflict(
                "cleanup helper query resolved to another exact effect",
            )),
        }
    }
}

impl BoundedCleanupHelper
    for TrustedHostNoTeeBoundedCleanupHelperClient
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_socket.as_fd()
    }

    fn try_execute_exact_nonblocking(
        &mut self,
        target: &CleanupTarget,
        binding: &ExactCleanupBinding,
        consumption_receipt_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<UnverifiedDurableCleanupEffectEvidence>,
        RecoveryError,
    >
    {
        require_exact_runtime_deadline(deadline, &binding.cleanup_deadline)?;
        let operation_index = self.matching_operation(
            target,
            binding,
            consumption_receipt_sha256,
        )?;
        require_live_protocol_deadline(
            &self.operations[operation_index]
                .operation
                .intent
                .evidence_query_deadline,
        )
        .map_err(service_to_recovery)?;
        if let Some(active) = &self.active {
            if active.operation_index != operation_index {
                return Err(RecoveryError::Conflict(
                    "another bounded cleanup operation is in flight",
                ));
            }
        } else {
            self.begin_query(operation_index, target)?;
        }

        for _ in 0..MAX_CLIENT_TRANSITIONS_PER_CALL {
            let phase = self
                .active
                .as_ref()
                .ok_or(RecoveryError::Invalid(
                    "cleanup helper client lost its active phase",
                ))?
                .phase;
            let progress = match self.exchange.try_progress() {
                Ok(progress) => progress,
                Err(error) => {
                    self.active = None;
                    return Err(service_to_recovery(error));
                }
            };
            let completed = match progress {
                NonblockingExchangeProgress::Pending => {
                    return Ok(None);
                }
                NonblockingExchangeProgress::Complete(completed) => {
                    completed
                }
            };
            if !completed.rights.is_empty() {
                return Err(RecoveryError::Authorization(
                    "cleanup helper reply included unexpected descriptors",
                ));
            }
            let reply = Self::decode_reply(&completed.response)?;
            let operation = self.operations[operation_index]
                .operation
                .clone();
            match (phase, reply) {
                (
                    ClientPhase::Query,
                    BoundedCleanupHelperReplyV3::Query {
                        authoritative: None,
                    },
                ) => {
                    require_live_protocol_deadline(
                        &operation.intent.cleanup_deadline,
                    )
                    .map_err(service_to_recovery)?;
                    self.begin_prepare(operation_index)?;
                }
                (
                    ClientPhase::Query,
                    BoundedCleanupHelperReplyV3::Query {
                        authoritative: Some(state),
                    },
                ) => {
                    Self::require_state_matches(&operation, &state)?;
                    match state {
                        CleanupEffectJournalStateV3::Prepared {
                            intent,
                        } => {
                            require_live_protocol_deadline(
                                &operation.intent.cleanup_deadline,
                            )
                            .map_err(service_to_recovery)?;
                            self.begin_execute(
                                operation_index,
                                &intent,
                                target,
                            )?;
                        }
                        CleanupEffectJournalStateV3::Executing {
                            ..
                        } => {
                            self.active = None;
                            return Ok(None);
                        }
                        CleanupEffectJournalStateV3::Completed {
                            intent,
                            execution,
                            result,
                        } => {
                            self.active = None;
                            return Ok(Some(
                                DurableCleanupEffectEvidenceV3 {
                                    intent,
                                    execution,
                                    result,
                                },
                            ));
                        }
                    }
                }
                (
                    ClientPhase::Prepare,
                    BoundedCleanupHelperReplyV3::Prepare {
                        authoritative,
                    },
                ) => {
                    if authoritative.intent != operation.intent {
                        return Err(RecoveryError::Conflict(
                            "cleanup helper prepare changed the exact intent",
                        ));
                    }
                    self.begin_execute(
                        operation_index,
                        &authoritative,
                        target,
                    )?;
                }
                (
                    ClientPhase::Execute,
                    BoundedCleanupHelperReplyV3::Execute {
                        authoritative,
                        prepared_intent,
                        execution,
                    },
                ) => {
                    authoritative
                        .validate_against(
                            &prepared_intent,
                            &execution,
                        )
                        .map_err(|_| {
                            RecoveryError::Authorization(
                                "cleanup helper execute returned invalid evidence",
                            )
                        })?;
                    if prepared_intent.intent != operation.intent {
                        return Err(RecoveryError::Conflict(
                            "cleanup helper execute changed the exact intent",
                        ));
                    }
                    self.active = None;
                    return Ok(Some(
                        DurableCleanupEffectEvidenceV3 {
                            intent: prepared_intent,
                            execution,
                            result: authoritative,
                        },
                    ));
                }
                _ => {
                    return Err(RecoveryError::Authorization(
                        "cleanup helper reply does not match the active phase",
                    ));
                }
            }
        }
        Err(RecoveryError::Invalid(
            "cleanup helper exceeded its bounded local transition count",
        ))
    }
}

pub(super) struct CleanupHelperSigningAuthorityV3 {
    signing_key: SigningKey,
    current_head_authority: VerifyingKey,
    current_head_authority_key_id: Sha256Digest,
    current_head_authority_key_spki_sha256: Sha256Digest,
    endpoint_process_identity_sha256: Sha256Digest,
    endpoint_generation: u64,
    helper_generation: u64,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    checkpoint_sequence: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl CleanupHelperSigningAuthorityV3 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        signing_key: SigningKey,
        current_head_authority: VerifyingKey,
        current_head_authority_key_id: Sha256Digest,
        endpoint_process_identity_sha256: Sha256Digest,
        endpoint_generation: u64,
        helper_generation: u64,
        signing_key_id: Sha256Digest,
        checkpoint_sequence: u64,
        current_key_authorization_checkpoint_sha256: Sha256Digest,
        revocation_generation: u64,
        revocation_root_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        for (field, digest) in [
            (
                "cleanupHelper.currentHeadAuthorityKeyId",
                &current_head_authority_key_id,
            ),
            (
                "cleanupHelper.endpointProcessIdentitySha256",
                &endpoint_process_identity_sha256,
            ),
            ("cleanupHelper.signingKeyId", &signing_key_id),
            (
                "cleanupHelper.currentKeyAuthorizationCheckpointSha256",
                &current_key_authorization_checkpoint_sha256,
            ),
            (
                "cleanupHelper.revocationRootSha256",
                &revocation_root_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        if endpoint_generation == 0
            || helper_generation == 0
            || checkpoint_sequence == 0
            || revocation_generation == 0
        {
            return Err(ServiceError::Invalid(
                "cleanup helper signing generations are incomplete",
            ));
        }
        let signing_spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup helper signing key SPKI is unavailable",
                )
            })?;
        let current_head_spki = current_head_authority
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "current-head authority SPKI is unavailable",
                )
            })?;
        Ok(Self {
            signing_key,
            current_head_authority,
            current_head_authority_key_id,
            current_head_authority_key_spki_sha256:
                Sha256Digest::compute(current_head_spki.as_bytes()),
            endpoint_process_identity_sha256,
            endpoint_generation,
            helper_generation,
            signing_key_id,
            signing_key_spki_sha256:
                Sha256Digest::compute(signing_spki.as_bytes()),
            checkpoint_sequence,
            current_key_authorization_checkpoint_sha256,
            revocation_generation,
            revocation_root_sha256,
        })
    }

    fn verify_current_head(
        &self,
        current_head: &ServiceCurrentHeadBindingV3,
        endpoint_role: PolicyCustodyEndpointRole,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), ServiceError> {
        current_head.validate(endpoint_role, deadline)?;
        let signed = &current_head.signed_current_head;
        let statement = &signed.statement;
        if signed.authority_key_id
                != self.current_head_authority_key_id
            || signed.authority_key_spki_sha256
                != self.current_head_authority_key_spki_sha256
            || statement.checkpoint_sequence
                != self.checkpoint_sequence
            || statement.checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || statement.endpoint_generation
                != self.endpoint_generation
            || statement.revocation_generation_high_water
                != self.revocation_generation
            || statement.revocation_root_sha256
                != self.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup helper current head does not match its configured authority",
            ));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&signed.authority_signature_base64)
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup helper current-head signature is not base64url",
                )
            })?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| {
                ServiceError::Invalid(
                    "cleanup helper current-head signature has the wrong size",
                )
            })?;
        let preimage = signed.authority_signature_preimage()?;
        self.current_head_authority
            .verify_strict(&preimage, &signature)
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup helper current-head signature is invalid",
                )
            })?;
        require_live_protocol_deadline(deadline)?;
        Ok(())
    }

    fn persist_intent(
        &self,
        intent: CleanupEffectIntentV3,
    ) -> Result<PersistedCleanupEffectIntentV3, ServiceError> {
        intent.validate()?;
        let exact_canonical_intent_bytes =
            canonical_json_bytes(&intent).map_err(|_| {
                ServiceError::Invalid(
                    "cleanup effect intent is not canonical",
                )
            })?;
        let persisted_at_boottime_nanos =
            boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "cleanup intent lacks CLOCK_BOOTTIME",
                )
            })?;
        if persisted_at_boottime_nanos
            >= intent.cleanup_deadline.absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup intent crossed its exact deadline before persistence",
            ));
        }
        let signature_payload = canonical_json_bytes(&(
            &intent.intent_sha256,
            &exact_canonical_intent_bytes,
            persisted_at_boottime_nanos,
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
            ServiceError::Invalid(
                "cleanup intent receipt is not canonical",
            )
        })?;
        let preimage = domain_separated_signature_preimage(
            CLEANUP_INTENT_SIGNATURE_DOMAIN,
            &signature_payload,
        )?;
        let signature_base64 = URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        );
        let intent_receipt_sha256 = hash_domain_frames(
            CLEANUP_INTENT_RECEIPT_DOMAIN,
            &[
                signature_payload.as_slice(),
                signature_base64.as_bytes(),
            ],
        );
        let persisted = PersistedCleanupEffectIntentV3 {
            intent,
            exact_canonical_intent_bytes,
            persisted_at_boottime_nanos,
            endpoint_process_identity_sha256:
                self.endpoint_process_identity_sha256.clone(),
            endpoint_generation: self.endpoint_generation,
            helper_generation: self.helper_generation,
            signing_key_id: self.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.signing_key_spki_sha256.clone(),
            current_key_authorization_checkpoint_sha256: self
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation: self.revocation_generation,
            revocation_root_sha256:
                self.revocation_root_sha256.clone(),
            signature_base64,
            intent_receipt_sha256,
        };
        persisted.validate()?;
        self.verify_intent(&persisted)?;
        Ok(persisted)
    }

    fn verify_intent(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
    ) -> Result<(), ServiceError> {
        prepared.validate()?;
        if prepared.endpoint_process_identity_sha256
                != self.endpoint_process_identity_sha256
            || prepared.endpoint_generation
                != self.endpoint_generation
            || prepared.helper_generation != self.helper_generation
            || prepared.signing_key_id != self.signing_key_id
            || prepared.signing_key_spki_sha256
                != self.signing_key_spki_sha256
            || prepared.current_key_authorization_checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || prepared.revocation_generation
                != self.revocation_generation
            || prepared.revocation_root_sha256
                != self.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup intent receipt is not current for this helper",
            ));
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&prepared.signature_base64)
                .map_err(|_| {
                    ServiceError::Invalid(
                        "cleanup intent receipt signature is not base64url",
                    )
                })?,
        )
        .map_err(|_| {
            ServiceError::Invalid(
                "cleanup intent receipt signature has the wrong size",
            )
        })?;
        let preimage = domain_separated_signature_preimage(
            CLEANUP_INTENT_SIGNATURE_DOMAIN,
            &prepared.canonical_signature_payload()?,
        )?;
        self.signing_key
            .verifying_key()
            .verify_strict(&preimage, &signature)
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup intent receipt signature is invalid",
                )
            })
    }

    fn sign_parent_proof(
        &self,
        intent: &CleanupEffectIntentV3,
        relationship_proved_at_boottime_nanos: u64,
    ) -> Result<PersistedCleanupWorkerParentProofV3, ServiceError> {
        intent.validate()?;
        if intent.action != CleanupAction::ReapWorker
            || relationship_proved_at_boottime_nanos == 0
            || relationship_proved_at_boottime_nanos
                >= intent.cleanup_deadline.absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup parent proof is outside the exact ReapWorker intent",
            ));
        }
        let mut proof = PersistedCleanupWorkerParentProofV3 {
            api_version:
                POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                    .to_string(),
            key: intent.key(),
            worker: intent.worker.clone(),
            worker_pidfd_identity:
                intent.retained_descriptors.worker_pidfd.clone(),
            helper_process_identity_sha256:
                self.endpoint_process_identity_sha256.clone(),
            helper_pid: unsafe { libc::getpid() },
            subreaper_enabled: true,
            relationship_proved_at_boottime_nanos,
            evidence_query_deadline:
                intent.evidence_query_deadline.clone(),
            helper_generation: self.helper_generation,
            signing_key_id: self.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.signing_key_spki_sha256.clone(),
            current_key_authorization_checkpoint_sha256: self
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation: self.revocation_generation,
            revocation_root_sha256:
                self.revocation_root_sha256.clone(),
            signature_base64: String::new(),
            proof_sha256: Sha256Digest::compute(&[]),
        };
        let preimage = domain_separated_signature_preimage(
            CLEANUP_WORKER_PARENT_PROOF_DOMAIN,
            &proof.canonical_signature_payload()?,
        )?;
        proof.signature_base64 = URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        );
        proof.proof_sha256 = proof.expected_proof_sha256()?;
        proof.validate_against(intent)?;
        Ok(proof)
    }

    fn verify_parent_proof(
        &self,
        proof: &PersistedCleanupWorkerParentProofV3,
        intent: &CleanupEffectIntentV3,
    ) -> Result<(), ServiceError> {
        proof.validate_against(intent)?;
        if proof.helper_process_identity_sha256
                != self.endpoint_process_identity_sha256
            || proof.helper_pid != unsafe { libc::getpid() }
            || proof.helper_generation != self.helper_generation
            || proof.signing_key_id != self.signing_key_id
            || proof.signing_key_spki_sha256
                != self.signing_key_spki_sha256
            || proof.current_key_authorization_checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || proof.revocation_generation
                != self.revocation_generation
            || proof.revocation_root_sha256
                != self.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup worker parent proof is not current for this helper",
            ));
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&proof.signature_base64)
                .map_err(|_| {
                    ServiceError::Invalid(
                        "cleanup worker parent proof signature is not base64url",
                    )
                })?,
        )
        .map_err(|_| {
            ServiceError::Invalid(
                "cleanup worker parent proof signature has the wrong size",
            )
        })?;
        let preimage = domain_separated_signature_preimage(
            CLEANUP_WORKER_PARENT_PROOF_DOMAIN,
            &proof.canonical_signature_payload()?,
        )?;
        self.signing_key
            .verifying_key()
            .verify_strict(&preimage, &signature)
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup worker parent proof signature is invalid",
                )
            })
    }

    fn persist_execution(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        request: &ServiceRequestFrameV3,
        exact_execute_request_bytes: &[u8],
        parent_proof: Option<PersistedCleanupWorkerParentProofV3>,
    ) -> Result<PersistedCleanupEffectExecutionV3, ServiceError> {
        self.verify_intent(prepared)?;
        let entered_at_boottime_nanos =
            boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "cleanup execution checkpoint lacks CLOCK_BOOTTIME",
                )
            })?;
        if request.binding.request_id_sha256
                != stage_request_id(
                    b"execute",
                    &prepared.intent.key(),
                )
            || request.binding.idempotency_sha256
                != execute_idempotency(
                    &prepared.intent.key(),
                    &prepared.intent_receipt_sha256,
                )
            || request.binding.deadline
                != prepared.intent.cleanup_deadline
            || entered_at_boottime_nanos
                >= prepared
                    .intent
                    .cleanup_deadline
                    .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup execution checkpoint changed its exact execute request or deadline",
            ));
        }
        let mut execution = PersistedCleanupEffectExecutionV3 {
            api_version:
                POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                    .to_string(),
            key: prepared.intent.key(),
            intent_receipt_sha256:
                prepared.intent_receipt_sha256.clone(),
            execute_request_id_sha256:
                request.binding.request_id_sha256.clone(),
            execute_idempotency_sha256:
                request.binding.idempotency_sha256.clone(),
            exact_execute_request_bytes:
                exact_execute_request_bytes.to_vec(),
            execute_request_sha256:
                Sha256Digest::compute(exact_execute_request_bytes),
            worker_pidfd_identity: prepared
                .intent
                .retained_descriptors
                .worker_pidfd
                .clone(),
            cgroup_fd_identity: prepared
                .intent
                .retained_descriptors
                .operation_cgroup
                .clone(),
            parent_proof,
            entered_at_boottime_nanos,
            evidence_query_deadline:
                prepared.intent.evidence_query_deadline.clone(),
            endpoint_process_identity_sha256:
                self.endpoint_process_identity_sha256.clone(),
            endpoint_generation: self.endpoint_generation,
            helper_generation: self.helper_generation,
            signing_key_id: self.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.signing_key_spki_sha256.clone(),
            current_key_authorization_checkpoint_sha256: self
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation: self.revocation_generation,
            revocation_root_sha256:
                self.revocation_root_sha256.clone(),
            signature_base64: String::new(),
            execution_record_sha256: Sha256Digest::compute(&[]),
        };
        let preimage = domain_separated_signature_preimage(
            CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
            &execution.canonical_signature_payload()?,
        )?;
        execution.signature_base64 = URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        );
        execution.execution_record_sha256 =
            execution.expected_record_sha256()?;
        execution.validate_against(prepared)?;
        Ok(execution)
    }

    fn verify_execution(
        &self,
        execution: &PersistedCleanupEffectExecutionV3,
        prepared: &PersistedCleanupEffectIntentV3,
    ) -> Result<(), ServiceError> {
        self.verify_intent(prepared)?;
        execution.validate_against(prepared)?;
        if execution.endpoint_process_identity_sha256
                != self.endpoint_process_identity_sha256
            || execution.endpoint_generation
                != self.endpoint_generation
            || execution.helper_generation != self.helper_generation
            || execution.signing_key_id != self.signing_key_id
            || execution.signing_key_spki_sha256
                != self.signing_key_spki_sha256
            || execution.current_key_authorization_checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || execution.revocation_generation
                != self.revocation_generation
            || execution.revocation_root_sha256
                != self.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup execution checkpoint is not current for this helper",
            ));
        }
        if let Some(parent_proof) = &execution.parent_proof {
            self.verify_parent_proof(
                parent_proof,
                &prepared.intent,
            )?;
        }
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&execution.signature_base64)
                .map_err(|_| {
                    ServiceError::Invalid(
                        "cleanup execution signature is not base64url",
                    )
                })?,
        )
        .map_err(|_| {
            ServiceError::Invalid(
                "cleanup execution signature has the wrong size",
            )
        })?;
        let preimage = domain_separated_signature_preimage(
            CLEANUP_EFFECT_EXECUTION_RECORD_DOMAIN,
            &execution.canonical_signature_payload()?,
        )?;
        self.signing_key
            .verifying_key()
            .verify_strict(&preimage, &signature)
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup execution signature is invalid",
                )
            })
    }

    fn sign_result(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        worker_observation: WorkerPidfdObservation,
        cgroup_observation: CgroupPopulationObservation,
        observed_at_boottime_nanos: u64,
    ) -> Result<SignedCleanupResultV3, ServiceError> {
        prepared.validate()?;
        let intent = &prepared.intent;
        let authorization = &intent.authorization.payload;
        let consumption = &intent.authorization_consumption;
        if observed_at_boottime_nanos == 0
            || observed_at_boottime_nanos
                >= intent
                    .evidence_query_deadline
                    .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup result observation is outside its evidence-query deadline",
            ));
        }
        let payload = CleanupResultSignedPayload {
            api_version: VERIFIED_CLEANUP_EVIDENCE_VERSION.to_string(),
            action: intent.action,
            executor_role: authorization.executor_role,
            endpoint_role: authorization.endpoint_role,
            endpoint_process_identity_sha256:
                self.endpoint_process_identity_sha256.clone(),
            endpoint_generation: self.endpoint_generation,
            operation: intent.operation,
            operation_id_sha256:
                intent.operation_id_sha256.clone(),
            durable_request_sha256:
                intent.durable_request_sha256.clone(),
            request_sha256: intent.request_sha256.clone(),
            termination_fence_sha256:
                intent.termination_fence_sha256.clone(),
            predecessor: intent.predecessor.clone(),
            authorization_nonce_sha256:
                authorization.authorization_nonce_sha256.clone(),
            authorization_sha256:
                intent.authorization.authorization_sha256.clone(),
            authorization_consumption_receipt_sha256:
                consumption.signed_envelope.envelope_sha256.clone(),
            authorization_consumption_sequence:
                consumption.statement.consumer_sequence,
            worker_pidfd_identity: intent.worker.clone(),
            cgroup_fd_identity: intent.cgroup.clone(),
            worker_observation,
            cgroup_observation,
            operation_deadline: intent.operation_deadline.clone(),
            cleanup_deadline: intent.cleanup_deadline.clone(),
            observed_at_boottime_nanos,
            result_sequence: intent.expected_result_sequence,
            signing_key_id: self.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.signing_key_spki_sha256.clone(),
            trust_checkpoint_id_sha256: self
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation: self.revocation_generation,
            revocation_root_sha256:
                self.revocation_root_sha256.clone(),
        };
        let exact_canonical_payload =
            canonical_json_bytes(&payload).map_err(|_| {
                ServiceError::Invalid(
                    "cleanup result payload is not canonical",
                )
            })?;
        let preimage = domain_separated_signature_preimage(
            CLEANUP_RESULT_SIGNATURE_DOMAIN,
            &exact_canonical_payload,
        )?;
        let signature_base64 = URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        );
        let result_receipt_sha256 = canonical_digest(
            CLEANUP_RESULT_RECEIPT_DOMAIN,
            &(
                CLEANUP_RESULT_SIGNATURE_DOMAIN,
                &exact_canonical_payload,
                signature_base64.as_bytes(),
            ),
        )?;
        let signed = SignedCleanupResultV3 {
            payload,
            exact_canonical_payload:
                exact_canonical_payload.into_boxed_slice(),
            signature_base64,
            result_receipt_sha256,
        };
        signed.validate_shape()?;
        Ok(signed)
    }

    fn persist_result(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        execution: &PersistedCleanupEffectExecutionV3,
        signed_result: SignedCleanupResultV3,
    ) -> Result<PersistedCleanupEffectResultV3, ServiceError> {
        self.verify_intent(prepared)?;
        self.verify_execution(execution, prepared)?;
        let exact_signed_result_bytes =
            canonical_json_bytes(&signed_result).map_err(|_| {
                ServiceError::Invalid(
                    "signed cleanup result is not canonical",
                )
            })?;
        let persisted_at_boottime_nanos =
            boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "cleanup result persistence lacks CLOCK_BOOTTIME",
                )
            })?;
        if persisted_at_boottime_nanos
            >= prepared
                .intent
                .evidence_query_deadline
                .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup result crossed its evidence-query deadline before persistence",
            ));
        }
        let key = prepared.intent.key();
        let result_record_sha256 = hash_domain_frames(
            CLEANUP_RESULT_RECORD_DOMAIN,
            &[canonical_json_bytes(&(
                &key,
                &prepared.intent_receipt_sha256,
                &execution.execution_record_sha256,
                &signed_result,
                &exact_signed_result_bytes,
                persisted_at_boottime_nanos,
            ))
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup result record is not canonical",
                )
            })?
            .as_slice()],
        );
        let persisted = PersistedCleanupEffectResultV3 {
            key,
            intent_receipt_sha256:
                prepared.intent_receipt_sha256.clone(),
            execution_record_sha256:
                execution.execution_record_sha256.clone(),
            signed_result,
            exact_signed_result_bytes,
            persisted_at_boottime_nanos,
            result_record_sha256,
        };
        persisted.validate_against(prepared, execution)?;
        Ok(persisted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CleanupHelperServerProgress {
    Idle,
    EffectPending,
    ReplyPending,
    ReplySent,
}

enum EffectExecutionState {
    StartNew,
    StartReconciliation,
    KillCgroup {
        kill: Option<OwnedFd>,
        events: OwnedFd,
        effect_deadline: ProtocolBoottimeDeadline,
    },
    ReapWorker {
        observation: Option<DurableReapObservationV3>,
    },
}

enum CleanupJournalCommand {
    RepairLookup {
        idempotency_sha256: Sha256Digest,
    },
    Append {
        idempotency_sha256: Sha256Digest,
        exact_request: Vec<u8>,
        exact_response: Vec<u8>,
    },
    CurrentHead,
}

enum CleanupJournalReply {
    Lookup(Option<Vec<u8>>),
    Append(JournalAppendOutcome),
    CurrentHead(Option<Sha256Digest>),
}

struct CleanupDurabilityJournal {
    worker:
        super::BoundedServiceWorker<CleanupJournalCommand, CleanupJournalReply>,
}

impl CleanupDurabilityJournal {
    fn start(
        mut journal: DurableAppendJournal,
        maximum_work_nanos: u64,
    ) -> Result<Self, ServiceError> {
        let worker = super::BoundedServiceWorker::start(
            "policy-custody-cleanup-durability",
            maximum_work_nanos,
            move |command, fence: &super::BoundedDurabilityFence| {
                fence.require_open()?;
                let result = match command {
                    CleanupJournalCommand::RepairLookup {
                        idempotency_sha256,
                    } => journal
                        .repair_and_lookup_persisted_exact_response(
                            &idempotency_sha256,
                        )
                        .map(CleanupJournalReply::Lookup),
                    CleanupJournalCommand::Append {
                        idempotency_sha256,
                        exact_request,
                        exact_response,
                    } => journal
                        .append_exact_exchange(
                            idempotency_sha256,
                            &exact_request,
                            &exact_response,
                        )
                        .map(CleanupJournalReply::Append),
                    CleanupJournalCommand::CurrentHead => Ok(
                        CleanupJournalReply::CurrentHead(
                            journal.current_head_sha256().cloned(),
                        ),
                    ),
                };
                fence.require_open()?;
                result
            },
        )
        .map_err(|error| {
            ServiceError::InvalidOwned(error.to_string())
        })?;
        Ok(Self { worker })
    }

    fn repair_lookup(
        &self,
        idempotency_sha256: Sha256Digest,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        match self
            .worker
            .execute(
                CleanupJournalCommand::RepairLookup {
                    idempotency_sha256,
                },
                deadline_boottime_nanos,
            )
            .map_err(|error| {
                ServiceError::InvalidOwned(error.to_string())
            })?
        {
            CleanupJournalReply::Lookup(response) => Ok(response),
            _ => Err(ServiceError::Invalid(
                "cleanup durability worker returned the wrong lookup completion",
            )),
        }
    }

    fn append(
        &self,
        idempotency_sha256: Sha256Digest,
        exact_request: &[u8],
        exact_response: &[u8],
        deadline_boottime_nanos: u64,
    ) -> Result<JournalAppendOutcome, ServiceError> {
        match self
            .worker
            .execute(
                CleanupJournalCommand::Append {
                    idempotency_sha256,
                    exact_request: exact_request.to_vec(),
                    exact_response: exact_response.to_vec(),
                },
                deadline_boottime_nanos,
            )
            .map_err(|error| {
                ServiceError::InvalidOwned(error.to_string())
            })?
        {
            CleanupJournalReply::Append(outcome) => Ok(outcome),
            _ => Err(ServiceError::Invalid(
                "cleanup durability worker returned the wrong append completion",
            )),
        }
    }

    fn current_head(
        &self,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<Sha256Digest>, ServiceError> {
        match self
            .worker
            .execute(
                CleanupJournalCommand::CurrentHead,
                deadline_boottime_nanos,
            )
            .map_err(|error| {
                ServiceError::InvalidOwned(error.to_string())
            })?
        {
            CleanupJournalReply::CurrentHead(head) => Ok(head),
            _ => Err(ServiceError::Invalid(
                "cleanup durability worker returned the wrong current-head completion",
            )),
        }
    }
}

enum EffectCompletionRequest {
    Execute,
    Query {
        exact_request_frame: Vec<u8>,
        request: ServiceRequestFrameV3,
        endpoint_role: PolicyCustodyEndpointRole,
    },
}

struct PendingEffectExecution {
    exact_execute_request_frame: Vec<u8>,
    execute_request: ServiceRequestFrameV3,
    completion_request: EffectCompletionRequest,
    prepared: PersistedCleanupEffectIntentV3,
    execution: PersistedCleanupEffectExecutionV3,
    worker_pidfd: OwnedFd,
    cgroup_fd: OwnedFd,
    state: EffectExecutionState,
}

struct ReadyReapWorker {
    intent: CleanupEffectIntentV3,
    proof: PersistedCleanupWorkerParentProofV3,
    worker_pidfd: OwnedFd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableReapObservationV3 {
    api_version: String,
    key: CleanupEffectKeyV3,
    intent_receipt_sha256: Sha256Digest,
    worker_pidfd_identity: WatchdogRetainedFdIdentityV3,
    observed_pid: i32,
    signal_code: i32,
    wait_status: i32,
    observed_at_boottime_nanos: u64,
    observation_sha256: Sha256Digest,
}

impl DurableReapObservationV3 {
    fn new(
        prepared: &PersistedCleanupEffectIntentV3,
        worker_pidfd_identity: WatchdogRetainedFdIdentityV3,
        observed_pid: i32,
        signal_code: i32,
        wait_status: i32,
        observed_at_boottime_nanos: u64,
    ) -> Result<Self, ServiceError> {
        let mut observation = Self {
            api_version: REAP_OBSERVATION_VERSION.to_string(),
            key: prepared.intent.key(),
            intent_receipt_sha256:
                prepared.intent_receipt_sha256.clone(),
            worker_pidfd_identity,
            observed_pid,
            signal_code,
            wait_status,
            observed_at_boottime_nanos,
            observation_sha256: Sha256Digest::compute(&[]),
        };
        observation.observation_sha256 =
            observation.expected_sha256()?;
        observation.validate(prepared)?;
        Ok(observation)
    }

    fn expected_sha256(&self) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            &self.key,
            &self.intent_receipt_sha256,
            &self.worker_pidfd_identity,
            self.observed_pid,
            self.signal_code,
            self.wait_status,
            self.observed_at_boottime_nanos,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "reap observation is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            CLEANUP_REAP_OBSERVATION_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    fn validate(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
    ) -> Result<(), ServiceError> {
        self.key.validate()?;
        self.worker_pidfd_identity.validate()?;
        require_nonzero_digest(
            "reapObservation.intentReceiptSha256",
            &self.intent_receipt_sha256,
        )?;
        require_nonzero_digest(
            "reapObservation.observationSha256",
            &self.observation_sha256,
        )?;
        if self.api_version != REAP_OBSERVATION_VERSION
            || self.key != prepared.intent.key()
            || self.intent_receipt_sha256
                != prepared.intent_receipt_sha256
            || self.worker_pidfd_identity
                != prepared.intent.retained_descriptors.worker_pidfd
            || self.observed_pid != prepared.intent.worker.pid
            || self.observed_at_boottime_nanos == 0
            || self.observed_at_boottime_nanos
                >= prepared
                    .intent
                    .cleanup_deadline
                    .absolute_boottime_nanos()
            || self.observation_sha256 != self.expected_sha256()?
        {
            return Err(ServiceError::Invalid(
                "durable reap observation changed its exact pidfd, owner, status, or deadline",
            ));
        }
        Ok(())
    }
}

/// Single-writer role server. Descriptor I/O remains on the serving thread;
/// all journal recovery and fsync work is submitted to one fixed-capacity
/// durability worker and completes through its exact eventfd result.
pub(super) struct TrustedHostNoTeeBoundedCleanupHelperServer {
    socket: OwnedFd,
    peer_authentication: AuthenticatedInheritedSeqpacket,
    peer_credentials: PeerCredentialsV3,
    journal: CleanupDurabilityJournal,
    signer: CleanupHelperSigningAuthorityV3,
    report: TrustedHostNoTeeServiceReportV3,
    operation_generation: u64,
    shared_configuration_sha256: Sha256Digest,
    expected_manifest: Option<CleanupHelperExpectedManifestV3>,
    readiness_seal: Option<CleanupHelperReadinessSealV3>,
    registered_reap_ordinals: BTreeSet<u16>,
    reconciled_executing_ordinals: BTreeSet<u16>,
    ready_reap_workers: Vec<ReadyReapWorker>,
    readiness_sealed: bool,
    pending_effect: Option<PendingEffectExecution>,
    pending_reply: Option<Vec<u8>>,
}
impl super::generation_service::Owner for TrustedHostNoTeeBoundedCleanupHelperServer {
    fn generation_state(&self,deadline:u64)->Result<Sha256Digest,ServiceError> {
        if self.pending_effect.is_some() || self.pending_reply.is_some() {
            return Err(ServiceError::Invalid("generation cannot fence active cleanup work"));
        }
        self.peer_authentication.revalidate_peer()?;
        for worker in &self.ready_reap_workers {
            let observed=observe_retained_descriptor(WatchdogRegistrationFdRole::WorkerPidfd,worker.worker_pidfd.as_fd())?;
            if observed!=worker.intent.retained_descriptors.worker_pidfd {
                return Err(ServiceError::Invalid("generation cleanup worker descriptor changed"));
            }
            self.signer.verify_parent_proof(&worker.proof,&worker.intent)?;
        }
        let workers:Vec<_>=self.ready_reap_workers.iter().map(|w|(&w.intent,&w.proof)).collect();
        Ok(Sha256Digest::compute(&super::encode_canonical_frame(&(
            &self.report,self.readiness_seal()?,self.journal.current_head(deadline)?,
            &self.registered_reap_ordinals,&self.reconciled_executing_ordinals,workers))?))
    }
    fn sign_generation_effect(&self,effect:super::generation_service::Effect)->Result<super::generation_service::Receipt,ServiceError> {
        super::generation_service::sign(effect,&self.signer.signing_key)
    }
    fn sign_generation_observation(&self,payload:super::generation_service::ObservationPayload)->Result<super::generation_service::Observation,ServiceError> {
        super::generation_service::sign_observation(payload,&self.signer.signing_key)
    }
}

impl TrustedHostNoTeeBoundedCleanupHelperServer {
    pub(super) fn from_inherited_socket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        journal_directory: OwnedFd,
        signer: CleanupHelperSigningAuthorityV3,
        report: TrustedHostNoTeeServiceReportV3,
        maximum_durability_worker_nanos: u64,
        operation_generation: u64,
        shared_configuration_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        report.validate_for_role(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
        )?;
        if report.service_process_identity_sha256
            != signer.endpoint_process_identity_sha256
            || operation_generation == 0
        {
            return Err(ServiceError::Invalid(
                "cleanup helper report, signing authority, or operation generation is invalid",
            ));
        }
        require_nonzero_digest(
            "cleanupHelper.sharedConfigurationSha256",
            &shared_configuration_sha256,
        )?;
        let peer_authentication =
            AuthenticatedInheritedSeqpacket::from_inherited(
                duplicate_cloexec(socket.as_raw_fd())?,
                expected_peer,
            )?;
        let peer_credentials =
            peer_authentication.peer_credentials();
        enable_child_subreaper()?;
        let mut journal = DurableAppendJournal::from_directory(
            journal_directory,
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            MAX_SERVICE_FRAME_BYTES,
        )?;
        journal.verified_complete_chain(
            MAX_CLEANUP_JOURNAL_RECORDS,
            MAX_CLEANUP_JOURNAL_RECOVERY_BYTES,
        )?;
        let journal = CleanupDurabilityJournal::start(
            journal,
            maximum_durability_worker_nanos,
        )?;
        Ok(Self {
            socket,
            peer_authentication,
            peer_credentials,
            journal,
            signer,
            report,
            operation_generation,
            shared_configuration_sha256,
            expected_manifest: None,
            readiness_seal: None,
            registered_reap_ordinals: BTreeSet::new(),
            reconciled_executing_ordinals: BTreeSet::new(),
            ready_reap_workers: Vec::new(),
            readiness_sealed: false,
            pending_effect: None,
            pending_reply: None,
        })
    }

    pub(super) fn handle_authenticated_bootstrap_packet(
        &mut self,
        packet: ReceivedSeqpacket,
        startup_deadline_nanos: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        self.peer_authentication.revalidate_peer()?;
        if self.peer_credentials.pid <= 0
            || self.readiness_sealed
            || self.readiness_seal.is_some()
        {
            return Err(ServiceError::Invalid(
                "cleanup-helper bootstrap is unavailable or already sealed",
            ));
        }
        let request: CleanupHelperBootstrapRequestV3 =
            decode_canonical_frame(&packet.frame)?;
        let reply = match &request {
            CleanupHelperBootstrapRequestV3::InstallManifest {
                manifest,
            } => {
                if !packet.rights.is_empty() {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper manifest bootstrap must not carry SCM_RIGHTS",
                    ));
                }
                manifest.validate()?;
                if manifest.operation_generation
                        != self.operation_generation
                    || manifest.shared_configuration_sha256
                        != self.shared_configuration_sha256
                    || manifest.service_configuration_sha256
                        != self
                            .report
                            .deployment_configuration_sha256
                {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper manifest changed generation or configuration",
                    ));
                }
                if self.expected_manifest.as_ref().is_some_and(
                    |installed| installed != manifest,
                ) {
                    return Err(ServiceError::IdempotencyConflict);
                }
                for expected in &manifest.ordered_effects {
                    let observed = self
                        .query_effect_state(
                            &expected.intent.key(),
                            startup_deadline_nanos,
                        )?
                        .ok_or(ServiceError::Invalid(
                            "cleanup-helper expected effect is absent from the recovered journal",
                        ))?;
                    let exact_intent = match &observed {
                        CleanupEffectJournalStateV3::Prepared {
                            intent,
                        }
                        | CleanupEffectJournalStateV3::Executing {
                            intent,
                            ..
                        }
                        | CleanupEffectJournalStateV3::Completed {
                            intent,
                            ..
                        } => &intent.intent,
                    };
                    let state_matches = matches!(
                        (&expected.expected_state, &observed),
                        (
                            CleanupEffectExpectedStateV3::Prepared,
                            CleanupEffectJournalStateV3::Prepared { .. }
                        ) | (
                            CleanupEffectExpectedStateV3::Executing,
                            CleanupEffectJournalStateV3::Executing { .. }
                        ) | (
                            CleanupEffectExpectedStateV3::Completed,
                            CleanupEffectJournalStateV3::Completed { .. }
                        )
                    );
                    if exact_intent != &expected.intent
                        || !state_matches
                    {
                        return Err(ServiceError::Invalid(
                            "cleanup-helper recovered effect differs from the expected exact intent or journal state",
                        ));
                    }
                }
                self.expected_manifest = Some(manifest.clone());
                CleanupHelperBootstrapReplyV3::ManifestInstalled {
                    manifest_sha256:
                        manifest.manifest_sha256.clone(),
                }
            }
            CleanupHelperBootstrapRequestV3::RegisterReapWorker {
                manifest_sha256,
                ordinal,
                intent,
            } => {
                if packet.rights.len() != 1 {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper ReapWorker bootstrap registration requires exactly one pidfd",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper ReapWorker registration arrived before its manifest",
                    ))?;
                let index = usize::from(*ordinal)
                    .checked_sub(1)
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper ReapWorker ordinal must be positive",
                    ))?;
                let expected = manifest
                    .ordered_effects
                    .get(index)
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper ReapWorker ordinal is outside its manifest",
                    ))?;
                if manifest_sha256 != &manifest.manifest_sha256
                    || expected.intent != *intent
                    || intent.action != CleanupAction::ReapWorker
                    || self.registered_reap_ordinals.contains(ordinal)
                {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper ReapWorker registration is duplicate or differs from its exact manifest ordinal",
                    ));
                }
                let worker_pidfd = packet
                    .rights
                    .into_iter()
                    .next()
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper ReapWorker pidfd disappeared",
                    ))?;
                self.register_reap_worker_for_readiness(
                    intent.clone(),
                    worker_pidfd,
                )?;
                self.registered_reap_ordinals.insert(*ordinal);
                CleanupHelperBootstrapReplyV3::
                    ReapWorkerRegistered {
                        manifest_sha256:
                            manifest_sha256.clone(),
                        ordinal: *ordinal,
                        key: intent.key(),
                    }
            }
            CleanupHelperBootstrapRequestV3::ReconcileExecuting {
                manifest_sha256,
                ordinal,
                key,
            } => {
                if packet.rights.len() != EXACT_EXECUTE_RIGHTS {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper executing reconciliation requires exactly worker-pidfd and operation-cgroup SCM_RIGHTS descriptors",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper reconciliation arrived before its manifest",
                    ))?;
                let index = usize::from(*ordinal)
                    .checked_sub(1)
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper reconciliation ordinal must be positive",
                    ))?;
                let expected = manifest
                    .ordered_effects
                    .get(index)
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper reconciliation ordinal is outside its manifest",
                    ))?;
                if manifest_sha256 != &manifest.manifest_sha256
                    || expected.expected_state
                        != CleanupEffectExpectedStateV3::Executing
                    || expected.intent.key() != *key
                    || self
                        .reconciled_executing_ordinals
                        .contains(ordinal)
                {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper reconciliation is duplicate or differs from its exact manifest ordinal",
                    ));
                }
                let completed_result_record_sha256 = self
                    .reconcile_executing_for_readiness(
                        key,
                        packet.rights,
                        startup_deadline_nanos,
                    )?;
                self.reconciled_executing_ordinals
                    .insert(*ordinal);
                CleanupHelperBootstrapReplyV3::
                    ExecutingReconciled {
                        manifest_sha256:
                            manifest_sha256.clone(),
                        ordinal: *ordinal,
                        key: key.clone(),
                        completed_result_record_sha256,
                    }
            }
            CleanupHelperBootstrapRequestV3::Seal {
                manifest_sha256,
                reattachment_epoch_sha256,
            } => {
                if !packet.rights.is_empty() {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper bootstrap seal must not carry SCM_RIGHTS",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper seal arrived before its manifest",
                    ))?
                    .clone();
                if manifest_sha256 != &manifest.manifest_sha256
                    || reattachment_epoch_sha256
                        == &Sha256Digest::compute(&[])
                    || manifest.ordered_effects.is_empty()
                {
                    return Err(ServiceError::Invalid(
                        "cleanup-helper cannot seal an empty or different effect manifest",
                    ));
                }
                for (index, expected) in
                    manifest.ordered_effects.iter().enumerate()
                {
                    let ordinal =
                        u16::try_from(index + 1).map_err(|_| {
                            ServiceError::Invalid(
                                "cleanup-helper manifest ordinal overflowed",
                            )
                        })?;
                    if expected.intent.action
                            == CleanupAction::ReapWorker
                        && !self
                            .registered_reap_ordinals
                            .contains(&ordinal)
                    {
                        return Err(ServiceError::Invalid(
                            "cleanup-helper cannot seal before every expected ReapWorker pidfd is reacquired",
                        ));
                    }
                    let state = self
                        .query_effect_state(
                            &expected.intent.key(),
                            startup_deadline_nanos,
                        )?
                        .ok_or(ServiceError::Invalid(
                            "cleanup-helper effect disappeared before readiness seal",
                        ))?;
                    if matches!(
                        state,
                        CleanupEffectJournalStateV3::Executing { .. }
                    ) {
                        return Err(ServiceError::Invalid(
                            "cleanup-helper cannot seal with a nonterminal Executing effect",
                        ));
                    }
                    if expected.expected_state
                            == CleanupEffectExpectedStateV3::Executing
                        && !self
                            .reconciled_executing_ordinals
                            .contains(&ordinal)
                    {
                        return Err(ServiceError::Invalid(
                            "cleanup-helper cannot seal before every expected Executing effect is reconciled",
                        ));
                    }
                }
                for ready in &self.ready_reap_workers {
                    require_live_protocol_deadline(
                        &ready.intent.cleanup_deadline,
                    )?;
                    self.signer.verify_parent_proof(
                        &ready.proof,
                        &ready.intent,
                    )?;
                }
                let journal_head = self
                    .journal
                    .current_head(startup_deadline_nanos)?
                    .ok_or(ServiceError::Invalid(
                        "cleanup-helper cannot seal before a durable effect journal head exists",
                    ))?;
                let ordered_effect_key_sha256 = manifest
                    .ordered_effects
                    .iter()
                    .map(|effect| {
                        encode_canonical_frame(&effect.intent.key())
                            .map(|bytes| Sha256Digest::compute(&bytes))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let reconciled_executing_effects =
                    u16::try_from(
                        self.reconciled_executing_ordinals.len(),
                    )
                    .map_err(|_| {
                        ServiceError::Invalid(
                            "cleanup-helper reconciliation count overflowed",
                        )
                    })?;
                let authorized_endpoint_roles = manifest
                    .ordered_effects
                    .iter()
                    .map(|effect| {
                        effect
                            .intent
                            .action
                            .required_endpoint_role()
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let mut seal = CleanupHelperReadinessSealV3 {
                    api_version:
                        POLICY_CUSTODY_CLEANUP_HELPER_WIRE_VERSION
                            .to_string(),
                    operation_generation:
                        manifest.operation_generation,
                    reattachment_epoch_sha256:
                        reattachment_epoch_sha256.clone(),
                    shared_configuration_sha256:
                        manifest.shared_configuration_sha256.clone(),
                    service_configuration_sha256:
                        manifest.service_configuration_sha256.clone(),
                    manifest_sha256:
                        manifest.manifest_sha256.clone(),
                    ordered_effect_key_sha256,
                    authorized_endpoint_roles,
                    reconciled_executing_effects,
                    journal_head_before_seal_sha256: journal_head,
                    seal_sha256: Sha256Digest::compute(&[]),
                };
                seal.seal_sha256 =
                    seal.expected_seal_sha256()?;
                seal.validate_against(&manifest)?;
                CleanupHelperBootstrapReplyV3::Sealed { seal }
            }
        };
        let exact_reply = encode_canonical_frame(&reply)?;
        let persisted = self
            .journal
            .append(
                Sha256Digest::compute(&packet.frame),
                &packet.frame,
                &exact_reply,
                startup_deadline_nanos,
            )?
            .exact_response_bytes()
            .to_vec();
        if persisted != exact_reply {
            return Err(ServiceError::IdempotencyConflict);
        }
        if let CleanupHelperBootstrapReplyV3::Sealed { seal } =
            reply
        {
            self.readiness_seal = Some(seal);
            self.readiness_sealed = true;
        }
        Ok(persisted)
    }

    fn reconcile_executing_for_readiness(
        &mut self,
        key: &CleanupEffectKeyV3,
        rights: Vec<OwnedFd>,
        startup_deadline_nanos: u64,
    ) -> Result<Sha256Digest, ServiceError> {
        let state = self
            .query_effect_state(key, startup_deadline_nanos)?
            .ok_or(ServiceError::Invalid(
                "cleanup-helper reconciliation effect is absent",
            ))?;
        let (prepared, execution) = match state {
            CleanupEffectJournalStateV3::Executing {
                intent,
                execution,
            } => (intent, execution),
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup-helper reconciliation effect is not Executing",
                ))
            }
        };
        let (worker_pidfd, cgroup_fd) =
            exact_two_rights(rights)?;
        verify_execution_descriptors(
            &prepared.intent,
            worker_pidfd.as_fd(),
            cgroup_fd.as_fd(),
        )?;
        let worker_pidfd = self.execution_worker_pidfd(
            &prepared,
            &execution,
            worker_pidfd,
        )?;
        let execute_request: ServiceRequestFrameV3 =
            decode_canonical_frame(
                &execution.exact_execute_request_bytes,
            )?;
        self.signer
            .verify_execution(&execution, &prepared)?;
        let mut pending = PendingEffectExecution {
            exact_execute_request_frame:
                execution.exact_execute_request_bytes.clone(),
            execute_request,
            completion_request: EffectCompletionRequest::Execute,
            prepared,
            execution,
            worker_pidfd,
            cgroup_fd,
            state: EffectExecutionState::StartReconciliation,
        };
        loop {
            if boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "cleanup-helper readiness reconciliation lacks CLOCK_BOOTTIME",
                )
            })? >= startup_deadline_nanos
            {
                return Err(ServiceError::Invalid(
                    "cleanup-helper readiness reconciliation crossed the startup deadline",
                ));
            }
            match self.try_progress_effect(pending)? {
                EffectProgress::Pending(next) => {
                    wait_for_bootstrap_effect(
                        &next,
                        startup_deadline_nanos,
                    )?;
                    pending = next;
                }
                EffectProgress::Complete(_) => {
                    let completed = self
                        .query_effect_state(
                            key,
                            startup_deadline_nanos,
                        )?
                        .ok_or(ServiceError::Invalid(
                            "cleanup-helper reconciled effect disappeared",
                        ))?;
                    return match completed {
                        CleanupEffectJournalStateV3::Completed {
                            result,
                            ..
                        } => Ok(result.result_record_sha256),
                        _ => Err(ServiceError::Invalid(
                            "cleanup-helper reconciliation did not produce a durable terminal result",
                        )),
                    };
                }
            }
        }
    }

    pub(super) fn bootstrap_is_sealed(&self) -> bool {
        self.readiness_sealed
            && self.readiness_seal.is_some()
            && self.expected_manifest.as_ref().is_some_and(
                |manifest| !manifest.ordered_effects.is_empty(),
            )
    }

    pub(super) fn readiness_seal(
        &self,
    ) -> Result<&CleanupHelperReadinessSealV3, ServiceError> {
        if !self.bootstrap_is_sealed() {
            return Err(ServiceError::Invalid(
                "cleanup-helper readiness is not durably sealed",
            ));
        }
        self.readiness_seal.as_ref().ok_or(ServiceError::Invalid(
            "cleanup-helper readiness seal is absent",
        ))
    }

    pub(super) fn expected_handshake_roles(
        &self,
    ) -> Result<&[PolicyCustodyEndpointRole], ServiceError> {
        Ok(&self.readiness_seal()?.authorized_endpoint_roles)
    }

    pub(super) fn register_reap_worker_for_readiness(
        &mut self,
        intent: CleanupEffectIntentV3,
        worker_pidfd: OwnedFd,
    ) -> Result<(), ServiceError> {
        if self.readiness_sealed
            || self.pending_effect.is_some()
            || self.pending_reply.is_some()
        {
            return Err(ServiceError::Invalid(
                "cleanup helper readiness registration is closed",
            ));
        }
        intent.validate()?;
        if intent.action != CleanupAction::ReapWorker {
            return Err(ServiceError::Invalid(
                "cleanup helper parent registration is only valid for ReapWorker",
            ));
        }
        require_live_protocol_deadline(&intent.cleanup_deadline)?;
        let observed = observe_retained_descriptor(
            WatchdogRegistrationFdRole::WorkerPidfd,
            worker_pidfd.as_fd(),
        )?;
        if observed != intent.retained_descriptors.worker_pidfd
            || observed.retained_fd_stat_sha256
                != intent.worker_pidfd_identity_sha256
            || self.ready_reap_workers.iter().any(|ready| {
                ready.intent.key() == intent.key()
            })
        {
            return Err(ServiceError::Invalid(
                "cleanup helper readiness registration changed or duplicated the exact worker pidfd",
            ));
        }
        let proved_at =
            prove_worker_parent_relationship(worker_pidfd.as_fd())?;
        let exact_request = exact_parent_proof_request(&intent)?;
        let idempotency = parent_proof_idempotency(&intent.key());
        let durability_deadline = intent
            .cleanup_deadline
            .absolute_boottime_nanos();
        let proof = if let Some(exact) = self
            .journal
            .repair_lookup(
                idempotency.clone(),
                durability_deadline,
            )?
        {
            let replay = self.journal.append(
                idempotency,
                &exact_request,
                &exact,
                durability_deadline,
            )?;
            decode_canonical_frame::<
                PersistedCleanupWorkerParentProofV3,
            >(replay.exact_response_bytes())?
        } else {
            let proof =
                self.signer.sign_parent_proof(&intent, proved_at)?;
            let exact = encode_canonical_frame(&proof)?;
            let persisted = self.journal.append(
                idempotency,
                &exact_request,
                &exact,
                durability_deadline,
            )?;
            decode_canonical_frame::<
                PersistedCleanupWorkerParentProofV3,
            >(persisted.exact_response_bytes())?
        };
        self.signer.verify_parent_proof(&proof, &intent)?;
        require_live_protocol_deadline(&intent.cleanup_deadline)?;
        self.ready_reap_workers.push(ReadyReapWorker {
            intent,
            proof,
            worker_pidfd,
        });
        Ok(())
    }

    pub(super) fn seal_readiness(
        &mut self,
    ) -> Result<(), ServiceError> {
        if self.bootstrap_is_sealed() {
            Ok(())
        } else {
            Err(ServiceError::Invalid(
                "cleanup-helper readiness can only be sealed by the durable nonempty bootstrap manifest protocol",
            ))
        }
    }

    pub(super) fn peer_credentials(&self) -> PeerCredentialsV3 {
        self.peer_credentials
    }

    pub(super) fn security_report(
        &self,
    ) -> &TrustedHostNoTeeServiceReportV3 {
        &self.report
    }

    pub(super) fn progress_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub(super) fn effect_progress_fd(
        &self,
    ) -> Option<BorrowedFd<'_>> {
        self.pending_effect
            .as_ref()
            .and_then(|pending| match &pending.state {
                EffectExecutionState::KillCgroup { events, .. } => {
                    Some(events.as_fd())
                }
                EffectExecutionState::ReapWorker { .. } => {
                    Some(pending.worker_pidfd.as_fd())
                }
                EffectExecutionState::StartNew
                | EffectExecutionState::StartReconciliation => None,
            })
    }

    pub(super) fn next_deadline_boottime_nanos(
        &self,
    ) -> Result<Option<u64>, ServiceError> {
        if let Some(pending) = &self.pending_effect {
            return Ok(Some(
                pending
                    .prepared
                    .intent
                    .cleanup_deadline
                    .absolute_boottime_nanos(),
            ));
        }
        if let Some(reply) = &self.pending_reply {
            let response: ServiceResponseFrameV3 =
                decode_canonical_frame(reply)?;
            return Ok(Some(
                response
                    .request_binding
                    .deadline
                    .absolute_boottime_nanos(),
            ));
        }
        Ok(None)
    }

    pub(super) fn handshake_reply(
        &self,
        request: &ServiceHandshakeRequestV3,
        endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<ServiceHandshakeReplyV3, ServiceError> {
        if !self.readiness_sealed {
            return Err(ServiceError::Invalid(
                "cleanup helper cannot report readiness before worker-parent registration is durably sealed",
            ));
        }
        request.validate(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            endpoint_role,
        )?;
        self.signer.verify_current_head(
            &request.expected_current_head,
            endpoint_role,
            &request.deadline,
        )?;
        ServiceHandshakeReplyV3::for_request(
            request,
            self.report.service_process_identity_sha256.clone(),
            self.report.clone(),
        )
    }

    pub(super) fn try_serve_one_bounded_blocking(
        &mut self,
    ) -> Result<CleanupHelperServerProgress, ServiceError> {
        self.try_serve_one_bounded_blocking_scoped(&super::Bootstrap::Host)
    }

    pub(super) fn try_serve_one_bounded_blocking_scoped(
        &mut self,
        bootstrap: &super::Bootstrap,
    ) -> Result<CleanupHelperServerProgress, ServiceError> {
        self.try_serve_one_generation_scoped(bootstrap,&mut None)
    }

    pub(super) fn try_serve_one_generation_scoped(
        &mut self,bootstrap:&super::Bootstrap,generation:&mut Option<super::generation_service::Gate>,
    )->Result<CleanupHelperServerProgress,ServiceError> {
        bootstrap.check().map_err(|_| ServiceError::Invalid(
            "cleanup helper guest originals or lifetime unavailable",
        ))?;
        if let Some(deadline) = self.next_deadline_boottime_nanos()? {
            bootstrap.require_deadline(deadline).map_err(|_| ServiceError::Invalid(
                "cleanup progression exceeds original guest lifetime",
            ))?;
        }
        self.peer_authentication.revalidate_peer()?;
        if let Some(reply) = self.pending_reply.take() {
            if try_send_seqpacket(self.socket.as_raw_fd(), &reply)? {
                self.peer_authentication.revalidate_peer()?;
                return Ok(CleanupHelperServerProgress::ReplySent);
            }
            self.pending_reply = Some(reply);
            return Ok(CleanupHelperServerProgress::ReplyPending);
        }
        if let Some(pending) = self.pending_effect.take() {
            match self.try_progress_effect(pending)? {
                EffectProgress::Pending(pending) => {
                    self.pending_effect = Some(pending);
                    return Ok(
                        CleanupHelperServerProgress::EffectPending,
                    );
                }
                EffectProgress::Complete(reply) => {
                    self.pending_reply = Some(reply);
                    return self.try_serve_one_generation_scoped(bootstrap,generation);
                }
            }
        }
        let Some(packet) =
            try_receive_seqpacket_any_rights(
                self.socket.as_raw_fd(),
                self.peer_credentials,
            )?
        else {
            return Ok(CleanupHelperServerProgress::Idle);
        };
        if let Some(gate)=generation {
            if !packet.rights.is_empty() && super::generation_service::is_command(&packet.frame)? {
                return Err(ServiceError::Invalid("generation command carried descriptors"));
            }
            if let Some(reply)=gate.handle(&packet.frame,self)? {
                let deadline=super::generation_service::frame_deadline(&packet.frame)?;
                bootstrap.require_deadline(deadline).map_err(|_|ServiceError::Invalid("generation deadline changed"))?;
                super::send_packet_until(self.socket.as_raw_fd(),&reply,&[],Some(deadline))
                    .map_err(|_|ServiceError::Invalid("generation reply outcome unknown"))?;
                self.peer_authentication.revalidate_peer()?;
                return Ok(CleanupHelperServerProgress::ReplySent);
            }
        }
        if let Some(reply) = self.handle_packet(packet, bootstrap)? {
            self.pending_reply = Some(reply);
            return self.try_serve_one_generation_scoped(bootstrap,generation);
        }
        Ok(CleanupHelperServerProgress::EffectPending)
    }

    fn handle_packet(
        &mut self,
        packet: ServerPacket,
        bootstrap: &super::Bootstrap,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let request: ServiceRequestFrameV3 =
            decode_canonical_frame(&packet.frame)?;
        bootstrap.require_deadline(request.binding.deadline.absolute_boottime_nanos())
            .map_err(|_| ServiceError::Invalid(
                "cleanup request exceeds original guest lifetime",
            ))?;
        let payload: PolicyCustodyServiceRequestV3 =
            request.decode_payload()?;
        payload.validate()?;
        let helper_request = match payload {
            PolicyCustodyServiceRequestV3::BoundedCleanupHelper(
                request,
            ) => request,
            _ => {
                return Err(ServiceError::Invalid(
                    "bounded cleanup helper received another authority request",
                ));
            }
        };
        let endpoint_role = helper_request_endpoint_role(&helper_request);
        request.validate(
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
            endpoint_role,
        )?;
        self.signer.verify_current_head(
            &request.binding.current_head,
            endpoint_role,
            &request.binding.deadline,
        )?;
        require_request_binding_matches_payload(
            &request,
            &helper_request,
        )?;
        let expected_rights = match &helper_request {
            BoundedCleanupHelperRequestV3::Query { .. }
            | BoundedCleanupHelperRequestV3::Execute { .. } => {
                EXACT_EXECUTE_RIGHTS
            }
            BoundedCleanupHelperRequestV3::Prepare { .. } => 0,
        };
        if packet.rights.len() != expected_rights {
            return Err(ServiceError::Invalid(
                "bounded cleanup request changed its exact SCM_RIGHTS contract",
            ));
        }
        let request_deadline =
            request.binding.deadline.absolute_boottime_nanos();
        if let Some(replayed) = self
            .journal
            .repair_lookup(
                request.binding.idempotency_sha256.clone(),
                request_deadline,
            )?
        {
            let response: ServiceResponseFrameV3 =
                decode_canonical_frame(&replayed).map_err(|_| {
                    ServiceError::IdempotencyConflict
                })?;
            response
                .validate_for_request(&request.binding, endpoint_role)
                .map_err(|_| ServiceError::IdempotencyConflict)?;
            let replay = self.journal.append(
                request.binding.idempotency_sha256.clone(),
                &packet.frame,
                &replayed,
                request_deadline,
            )?;
            return Ok(Some(
                replay.exact_response_bytes().to_vec(),
            ));
        }
        match helper_request {
            BoundedCleanupHelperRequestV3::Query {
                request_id_sha256,
                key,
                deadline,
                ..
            } => {
                if request.binding.idempotency_sha256
                    != query_idempotency_for_request(
                        &key,
                        &request_id_sha256,
                    )
                {
                    return Err(ServiceError::IdempotencyConflict);
                }
                let authoritative = self.query_effect_state(
                    &key,
                    request_deadline,
                )?;
                if let Some(state) = &authoritative {
                    let intent = match state {
                        CleanupEffectJournalStateV3::Prepared {
                            intent,
                        }
                        | CleanupEffectJournalStateV3::Executing {
                            intent,
                            ..
                        }
                        | CleanupEffectJournalStateV3::Completed {
                            intent,
                            ..
                        } => intent,
                    };
                    if deadline
                        != intent.intent.evidence_query_deadline
                    {
                        return Err(ServiceError::Invalid(
                            "cleanup query changed the exact evidence-query deadline",
                        ));
                    }
                }
                if let Some(
                    CleanupEffectJournalStateV3::Executing {
                        intent,
                        execution,
                    },
                ) = authoritative.clone()
                {
                    let (worker_pidfd, cgroup_fd) =
                        exact_two_rights(packet.rights)?;
                    verify_execution_descriptors(
                        &intent.intent,
                        worker_pidfd.as_fd(),
                        cgroup_fd.as_fd(),
                    )?;
                    let worker_pidfd = self
                        .execution_worker_pidfd(
                            &intent,
                            &execution,
                            worker_pidfd,
                        )?;
                    let execute_request: ServiceRequestFrameV3 =
                        decode_canonical_frame(
                            &execution.exact_execute_request_bytes,
                        )?;
                    self.signer
                        .verify_execution(&execution, &intent)?;
                    self.pending_effect =
                        Some(PendingEffectExecution {
                            exact_execute_request_frame: execution
                                .exact_execute_request_bytes
                                .clone(),
                            execute_request,
                            completion_request:
                                EffectCompletionRequest::Query {
                                    exact_request_frame:
                                        packet.frame,
                                    request,
                                    endpoint_role,
                                },
                            prepared: intent,
                            execution,
                            worker_pidfd,
                            cgroup_fd,
                            state: EffectExecutionState::
                                StartReconciliation,
                        });
                    return Ok(None);
                }
                self.persist_response(
                    &packet.frame,
                    &request,
                    endpoint_role,
                    BoundedCleanupHelperReplyV3::Query {
                        authoritative,
                    },
                )
                .map(Some)
            }
            BoundedCleanupHelperRequestV3::Prepare {
                intent,
                ..
            } => {
                if !self.readiness_sealed {
                    return Err(ServiceError::Invalid(
                        "cleanup helper cannot prepare before readiness is sealed",
                    ));
                }
                let key = intent.key();
                if request.binding.idempotency_sha256
                    != prepare_idempotency(&key)
                {
                    return Err(ServiceError::IdempotencyConflict);
                }
                if let Some(existing) =
                    self.load_prepared_intent(
                        &key,
                        request_deadline,
                    )?
                {
                    if existing.intent != intent {
                        return Err(ServiceError::IdempotencyConflict);
                    }
                    return self
                        .persist_response(
                            &packet.frame,
                            &request,
                            endpoint_role,
                            BoundedCleanupHelperReplyV3::Prepare {
                                authoritative: existing,
                            },
                        )
                        .map(Some);
                }
                if intent.action == CleanupAction::ReapWorker {
                    self.ready_reap_worker(&intent)?;
                }
                let prepared = self.signer.persist_intent(intent)?;
                self.persist_response(
                    &packet.frame,
                    &request,
                    endpoint_role,
                    BoundedCleanupHelperReplyV3::Prepare {
                        authoritative: prepared,
                    },
                )
                .map(Some)
            }
            BoundedCleanupHelperRequestV3::Execute {
                key,
                prepared_intent_receipt_sha256,
                deadline,
                ..
            } => {
                if !self.readiness_sealed {
                    return Err(ServiceError::Invalid(
                        "cleanup helper cannot execute before readiness is sealed",
                    ));
                }
                let prepared = self
                    .load_prepared_intent(
                        &key,
                        request_deadline,
                    )?
                    .ok_or(ServiceError::Invalid(
                        "cleanup execute has no durable prepared intent",
                    ))?;
                if prepared.intent_receipt_sha256
                    != prepared_intent_receipt_sha256
                    || deadline != prepared.intent.cleanup_deadline
                    || request.binding.idempotency_sha256
                        != execute_idempotency(
                            &key,
                            &prepared_intent_receipt_sha256,
                        )
                {
                    return Err(ServiceError::IdempotencyConflict);
                }
                let existing_execution =
                    self.load_execution_checkpoint(
                        &key,
                        &prepared,
                        request_deadline,
                    )?;
                if let Some(execution) = &existing_execution {
                    if let Some(result) = self.load_completed_result(
                        &key,
                        &prepared,
                        execution,
                        request_deadline,
                    )? {
                    return self
                        .persist_response(
                            &packet.frame,
                            &request,
                            endpoint_role,
                            BoundedCleanupHelperReplyV3::Execute {
                                authoritative: result,
                                prepared_intent: prepared,
                                execution: execution.clone(),
                            },
                        )
                        .map(Some);
                    }
                }
                let (worker_pidfd, cgroup_fd) =
                    exact_two_rights(packet.rights)?;
                verify_execution_descriptors(
                    &prepared.intent,
                    worker_pidfd.as_fd(),
                    cgroup_fd.as_fd(),
                )?;
                let (worker_pidfd, parent_proof) =
                    self.execution_worker_and_parent_proof(
                        &prepared,
                        worker_pidfd,
                        existing_execution.is_none(),
                    )?;
                let (execution, state) =
                    if let Some(execution) = existing_execution {
                        self.signer.verify_execution(
                            &execution,
                            &prepared,
                        )?;
                        if execution.exact_execute_request_bytes
                                != packet.frame
                            || execution.parent_proof
                                != parent_proof
                        {
                            return Err(
                                ServiceError::IdempotencyConflict,
                            );
                        }
                        (
                            execution,
                            EffectExecutionState::
                                StartReconciliation,
                        )
                    } else {
                        let execution = self.signer.persist_execution(
                            &prepared,
                            &request,
                            &packet.frame,
                            parent_proof,
                        )?;
                        self.persist_execution_checkpoint(
                            &prepared,
                            &execution,
                        )?;
                        (
                            execution,
                            EffectExecutionState::StartNew,
                        )
                    };
                self.pending_effect = Some(PendingEffectExecution {
                    exact_execute_request_frame: packet.frame,
                    execute_request: request,
                    completion_request:
                        EffectCompletionRequest::Execute,
                    prepared,
                    execution,
                    worker_pidfd,
                    cgroup_fd,
                    state,
                });
                Ok(None)
            }
        }
    }

    fn persist_response(
        &mut self,
        exact_request_frame: &[u8],
        request: &ServiceRequestFrameV3,
        endpoint_role: PolicyCustodyEndpointRole,
        reply: BoundedCleanupHelperReplyV3,
    ) -> Result<Vec<u8>, ServiceError> {
        reply.validate()?;
        let payload =
            PolicyCustodyServiceReplyV3::BoundedCleanupHelper(reply);
        let response = ServiceResponseFrameV3::from_payload(
            request.binding.clone(),
            &payload,
        )?;
        response.validate_for_request(
            &request.binding,
            endpoint_role,
        )?;
        let exact_response = encode_canonical_frame(&response)?;
        let outcome = self.journal.append(
            request.binding.idempotency_sha256.clone(),
            exact_request_frame,
            &exact_response,
            request.binding.deadline.absolute_boottime_nanos(),
        )?;
        Ok(outcome.exact_response_bytes().to_vec())
    }

    fn query_effect_state(
        &mut self,
        key: &CleanupEffectKeyV3,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<CleanupEffectJournalStateV3>, ServiceError> {
        let Some(prepared) = self.load_prepared_intent(
            key,
            deadline_boottime_nanos,
        )? else {
            return Ok(None);
        };
        let execution = self.load_execution_checkpoint(
            key,
            &prepared,
            deadline_boottime_nanos,
        )?;
        if let Some(execution) = execution {
            if let Some(result) = self.load_completed_result(
                key,
                &prepared,
                &execution,
                deadline_boottime_nanos,
            )? {
            return Ok(Some(CleanupEffectJournalStateV3::Completed {
                intent: prepared,
                execution,
                result,
            }));
            }
            return Ok(Some(CleanupEffectJournalStateV3::Executing {
                intent: prepared,
                execution,
            }));
        }
        Ok(Some(CleanupEffectJournalStateV3::Prepared {
            intent: prepared,
        }))
    }

    fn load_prepared_intent(
        &mut self,
        key: &CleanupEffectKeyV3,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<PersistedCleanupEffectIntentV3>, ServiceError>
    {
        let Some(bytes) = self
            .journal
            .repair_lookup(
                prepare_idempotency(key),
                deadline_boottime_nanos,
            )?
        else {
            return Ok(None);
        };
        let response: ServiceResponseFrameV3 =
            decode_canonical_frame(&bytes)?;
        let payload: PolicyCustodyServiceReplyV3 =
            response.decode_payload()?;
        match payload {
            PolicyCustodyServiceReplyV3::BoundedCleanupHelper(
                BoundedCleanupHelperReplyV3::Prepare {
                    authoritative,
                },
            ) => {
                authoritative.validate()?;
                if authoritative.intent.key() != *key {
                    return Err(ServiceError::IdempotencyConflict);
                }
                self.signer.verify_intent(&authoritative)?;
                Ok(Some(authoritative))
            }
            _ => Err(ServiceError::IdempotencyConflict),
        }
    }

    fn load_completed_result(
        &mut self,
        key: &CleanupEffectKeyV3,
        prepared: &PersistedCleanupEffectIntentV3,
        execution: &PersistedCleanupEffectExecutionV3,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<PersistedCleanupEffectResultV3>, ServiceError>
    {
        let Some(bytes) = self
            .journal
            .repair_lookup(
                execute_idempotency(
                    key,
                    &prepared.intent_receipt_sha256,
                ),
                deadline_boottime_nanos,
            )?
        else {
            return Ok(None);
        };
        let response: ServiceResponseFrameV3 =
            decode_canonical_frame(&bytes)?;
        let payload: PolicyCustodyServiceReplyV3 =
            response.decode_payload()?;
        match payload {
            PolicyCustodyServiceReplyV3::BoundedCleanupHelper(
                BoundedCleanupHelperReplyV3::Execute {
                    authoritative,
                    prepared_intent,
                    execution: persisted_execution,
                },
            ) => {
                if prepared_intent != *prepared
                    || persisted_execution != *execution
                {
                    return Err(ServiceError::IdempotencyConflict);
                }
                authoritative
                    .validate_against(prepared, execution)?;
                Ok(Some(authoritative))
            }
            _ => Err(ServiceError::IdempotencyConflict),
        }
    }

    fn persist_execution_checkpoint(
        &mut self,
        prepared: &PersistedCleanupEffectIntentV3,
        execution: &PersistedCleanupEffectExecutionV3,
    ) -> Result<(), ServiceError> {
        self.signer.verify_execution(execution, prepared)?;
        let exact_request = exact_execution_checkpoint_request(
            prepared,
            &execution.exact_execute_request_bytes,
        )?;
        let exact_execution = encode_canonical_frame(execution)?;
        let persisted = self.journal.append(
            execution_checkpoint_idempotency(
                &prepared.intent.key(),
                &prepared.intent_receipt_sha256,
            ),
            &exact_request,
            &exact_execution,
            prepared
                .intent
                .cleanup_deadline
                .absolute_boottime_nanos(),
        )?;
        let durable: PersistedCleanupEffectExecutionV3 =
            decode_canonical_frame(
                persisted.exact_response_bytes(),
            )?;
        self.signer.verify_execution(&durable, prepared)?;
        if durable != *execution {
            return Err(ServiceError::IdempotencyConflict);
        }
        Ok(())
    }

    fn load_execution_checkpoint(
        &mut self,
        key: &CleanupEffectKeyV3,
        prepared: &PersistedCleanupEffectIntentV3,
        deadline_boottime_nanos: u64,
    ) -> Result<Option<PersistedCleanupEffectExecutionV3>, ServiceError>
    {
        let idempotency = execution_checkpoint_idempotency(
            key,
            &prepared.intent_receipt_sha256,
        );
        let Some(bytes) = self
            .journal
            .repair_lookup(
                idempotency.clone(),
                deadline_boottime_nanos,
            )?
        else {
            return Ok(None);
        };
        let execution: PersistedCleanupEffectExecutionV3 =
            decode_canonical_frame(&bytes)?;
        self.signer.verify_execution(&execution, prepared)?;
        let exact_request = exact_execution_checkpoint_request(
            prepared,
            &execution.exact_execute_request_bytes,
        )?;
        let replay = self.journal.append(
            idempotency,
            &exact_request,
            &bytes,
            deadline_boottime_nanos,
        )?;
        let durable: PersistedCleanupEffectExecutionV3 =
            decode_canonical_frame(replay.exact_response_bytes())?;
        self.signer.verify_execution(&durable, prepared)?;
        if durable != execution {
            return Err(ServiceError::IdempotencyConflict);
        }
        Ok(Some(durable))
    }

    fn ready_reap_worker(
        &self,
        intent: &CleanupEffectIntentV3,
    ) -> Result<&ReadyReapWorker, ServiceError> {
        self.ready_reap_workers
            .iter()
            .find(|ready| {
                ready.intent.key() == intent.key()
                    && ready.intent == *intent
            })
            .ok_or(ServiceError::Invalid(
                "ReapWorker lacks a durable readiness-time parent/subreaper proof",
            ))
    }

    fn execution_worker_and_parent_proof(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        received_worker_pidfd: OwnedFd,
        require_live_parent: bool,
    ) -> Result<
        (
            OwnedFd,
            Option<PersistedCleanupWorkerParentProofV3>,
        ),
        ServiceError,
    > {
        match prepared.intent.action {
            CleanupAction::KillCgroup => {
                Ok((received_worker_pidfd, None))
            }
            CleanupAction::ReapWorker => {
                let ready =
                    self.ready_reap_worker(&prepared.intent)?;
                require_same_open_file_description(
                    received_worker_pidfd.as_fd(),
                    ready.worker_pidfd.as_fd(),
                )?;
                self.signer.verify_parent_proof(
                    &ready.proof,
                    &prepared.intent,
                )?;
                if require_live_parent {
                    prove_worker_parent_relationship(
                        ready.worker_pidfd.as_fd(),
                    )?;
                }
                Ok((
                    duplicate_cloexec(
                        ready.worker_pidfd.as_raw_fd(),
                    )?,
                    Some(ready.proof.clone()),
                ))
            }
            CleanupAction::RevokeFence
            | CleanupAction::CommitResultAborted
            | CleanupAction::CommitFenceClosed
            | CleanupAction::CommitTermination => {
                Err(ServiceError::Invalid(
                    "cleanup helper has no retained-capability handler for this action",
                ))
            }
        }
    }

    fn execution_worker_pidfd(
        &self,
        prepared: &PersistedCleanupEffectIntentV3,
        execution: &PersistedCleanupEffectExecutionV3,
        received_worker_pidfd: OwnedFd,
    ) -> Result<OwnedFd, ServiceError> {
        self.signer.verify_execution(execution, prepared)?;
        let (worker_pidfd, parent_proof) =
            self.execution_worker_and_parent_proof(
                prepared,
                received_worker_pidfd,
                false,
            )?;
        if parent_proof != execution.parent_proof {
            return Err(ServiceError::IdempotencyConflict);
        }
        Ok(worker_pidfd)
    }

    fn try_progress_effect(
        &mut self,
        mut pending: PendingEffectExecution,
    ) -> Result<EffectProgress, ServiceError> {
        match &mut pending.state {
            EffectExecutionState::StartNew => {
                require_live_protocol_deadline(
                    &pending.prepared.intent.cleanup_deadline,
                )?;
                match pending.prepared.intent.action {
                    CleanupAction::KillCgroup => {
                        let kill = open_cgroup_control(
                            pending.cgroup_fd.as_fd(),
                            b"cgroup.kill\0",
                            libc::O_WRONLY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK,
                        )?;
                        let events = open_cgroup_control(
                            pending.cgroup_fd.as_fd(),
                            b"cgroup.events\0",
                            libc::O_RDONLY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK,
                        )?;
                        pending.state =
                            EffectExecutionState::KillCgroup {
                                kill: Some(kill),
                                events,
                                effect_deadline: pending
                                    .prepared
                                    .intent
                                    .cleanup_deadline
                                    .clone(),
                            };
                        return Ok(EffectProgress::Pending(pending));
                    }
                    CleanupAction::ReapWorker => {
                        let observation = self
                            .load_reap_observation(
                                &pending.prepared,
                            )?;
                        pending.state =
                            EffectExecutionState::ReapWorker {
                                observation,
                            };
                        return Ok(EffectProgress::Pending(pending));
                    }
                    CleanupAction::RevokeFence
                    | CleanupAction::CommitResultAborted
                    | CleanupAction::CommitFenceClosed
                    | CleanupAction::CommitTermination => {
                        return Err(ServiceError::Invalid(
                            "cleanup helper has no retained-capability handler for this action",
                        ));
                    }
                }
            }
            EffectExecutionState::StartReconciliation => {
                require_live_protocol_deadline(
                    &pending
                        .prepared
                        .intent
                        .evidence_query_deadline,
                )?;
                match pending.prepared.intent.action {
                    CleanupAction::KillCgroup => {
                        let kill = open_cgroup_control(
                            pending.cgroup_fd.as_fd(),
                            b"cgroup.kill\0",
                            libc::O_WRONLY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK,
                        )?;
                        let events = open_cgroup_control(
                            pending.cgroup_fd.as_fd(),
                            b"cgroup.events\0",
                            libc::O_RDONLY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK,
                        )?;
                        pending.state =
                            EffectExecutionState::KillCgroup {
                                kill: Some(kill),
                                events,
                                effect_deadline: pending
                                    .prepared
                                    .intent
                                    .evidence_query_deadline
                                    .clone(),
                            };
                        return Ok(EffectProgress::Pending(pending));
                    }
                    CleanupAction::ReapWorker => {
                        let observation = self
                            .load_reap_observation(
                                &pending.prepared,
                            )?;
                        pending.state =
                            EffectExecutionState::ReapWorker {
                                observation,
                            };
                        return Ok(EffectProgress::Pending(pending));
                    }
                    CleanupAction::RevokeFence
                    | CleanupAction::CommitResultAborted
                    | CleanupAction::CommitFenceClosed
                    | CleanupAction::CommitTermination => {
                        return Err(ServiceError::Invalid(
                            "cleanup helper cannot reconcile an unsupported action",
                        ));
                    }
                }
            }
            EffectExecutionState::KillCgroup {
                kill,
                events,
                effect_deadline,
            } => {
                if let Some(kill_descriptor) = kill.as_ref() {
                    let deadline = require_live_protocol_deadline(
                        effect_deadline,
                    )?;
                    if !try_write_cgroup_kill(
                        kill_descriptor.as_fd(),
                    )? {
                        return Ok(EffectProgress::Pending(pending));
                    }
                    deadline.require_live().map_err(|_| {
                        ServiceError::Invalid(
                            "cgroup.kill crossed its exact deadline",
                        )
                    })?;
                    kill.take();
                }
                require_live_protocol_deadline(
                    &pending
                        .prepared
                        .intent
                        .evidence_query_deadline,
                )?;
                let Some((populated, exact_events)) =
                    try_read_cgroup_events(events.as_fd())?
                else {
                    return Ok(EffectProgress::Pending(pending));
                };
                if populated {
                    return Ok(EffectProgress::Pending(pending));
                }
                let observed =
                    boottime_now_nanos().map_err(|_| {
                        ServiceError::Invalid(
                            "empty cgroup observation lacks CLOCK_BOOTTIME",
                        )
                    })?;
                return self.finish_effect(
                    pending,
                    WorkerPidfdObservation::NotObserved,
                    CgroupPopulationObservation::Empty {
                        cgroup_events_sha256:
                            Sha256Digest::compute(&exact_events),
                        observed_at_boottime_nanos: observed,
                    },
                    observed,
                );
            }
            EffectExecutionState::ReapWorker { observation } => {
                require_live_protocol_deadline(
                    &pending
                        .prepared
                        .intent
                        .evidence_query_deadline,
                )?;
                let cleanup_live = pending
                    .prepared
                    .intent
                    .cleanup_deadline
                    .to_runtime()?
                    .require_live()
                    .is_ok();
                if observation.is_none() {
                    if !cleanup_live {
                        return Ok(EffectProgress::Pending(pending));
                    }
                    let Some(observed) = observe_reapable_pidfd(
                        pending.worker_pidfd.as_fd(),
                        &pending.prepared,
                    )? else {
                        return Ok(EffectProgress::Pending(pending));
                    };
                    let exact = encode_canonical_frame(&observed)?;
                    let idempotency = reap_observation_idempotency(
                        &pending.prepared.intent.key(),
                        &pending.prepared.intent_receipt_sha256,
                    );
                    let exact_request =
                        exact_reap_observation_request(
                            &pending.prepared,
                        )?;
                    let persisted = self
                        .journal
                        .append(
                            idempotency,
                            &exact_request,
                            &exact,
                            pending
                                .prepared
                                .intent
                                .evidence_query_deadline
                                .absolute_boottime_nanos(),
                        )?;
                    let durable: DurableReapObservationV3 =
                        decode_canonical_frame(
                            persisted.exact_response_bytes(),
                        )?;
                    durable.validate(&pending.prepared)?;
                    *observation = Some(durable);
                    return Ok(EffectProgress::Pending(pending));
                }
                let durable = observation
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "durable reap observation disappeared",
                    ))?
                    .clone();
                if !cleanup_live {
                    if !pidfd_was_already_reaped(
                        pending.worker_pidfd.as_fd(),
                        &durable,
                    )? {
                        return Ok(EffectProgress::Pending(pending));
                    }
                } else {
                    reap_pidfd_exact(
                        pending.worker_pidfd.as_fd(),
                        &durable,
                    )?;
                }
                let observed_at_boottime_nanos =
                    boottime_now_nanos().map_err(|_| {
                        ServiceError::Invalid(
                            "worker reconciliation lacks CLOCK_BOOTTIME",
                        )
                    })?;
                return self.finish_effect(
                    pending,
                    WorkerPidfdObservation::Reaped {
                        wait_status: durable.wait_status,
                        reap_observation_sha256:
                            durable.observation_sha256,
                        reaped_at_boottime_nanos:
                            durable.observed_at_boottime_nanos,
                    },
                    CgroupPopulationObservation::NotObserved,
                    observed_at_boottime_nanos,
                );
            }
        }
    }

    fn finish_effect(
        &mut self,
        pending: PendingEffectExecution,
        worker_observation: WorkerPidfdObservation,
        cgroup_observation: CgroupPopulationObservation,
        observed_at_boottime_nanos: u64,
    ) -> Result<EffectProgress, ServiceError> {
        require_live_protocol_deadline(
            &pending
                .prepared
                .intent
                .evidence_query_deadline,
        )?;
        let signed = self.signer.sign_result(
            &pending.prepared,
            worker_observation,
            cgroup_observation,
            observed_at_boottime_nanos,
        )?;
        let persisted = self
            .signer
            .persist_result(
                &pending.prepared,
                &pending.execution,
                signed,
            )?;
        let endpoint_role =
            pending.prepared.intent.action.required_endpoint_role();
        let execute_response = self.persist_response(
            &pending.exact_execute_request_frame,
            &pending.execute_request,
            endpoint_role,
            BoundedCleanupHelperReplyV3::Execute {
                authoritative: persisted.clone(),
                prepared_intent: pending.prepared.clone(),
                execution: pending.execution.clone(),
            },
        )?;
        let response = match pending.completion_request {
            EffectCompletionRequest::Execute => execute_response,
            EffectCompletionRequest::Query {
                exact_request_frame,
                request,
                endpoint_role,
            } => self.persist_response(
                &exact_request_frame,
                &request,
                endpoint_role,
                BoundedCleanupHelperReplyV3::Query {
                    authoritative: Some(
                        CleanupEffectJournalStateV3::Completed {
                            intent: pending.prepared,
                            execution: pending.execution,
                            result: persisted,
                        },
                    ),
                },
            )?,
        };
        Ok(EffectProgress::Complete(response))
    }

    fn load_reap_observation(
        &mut self,
        prepared: &PersistedCleanupEffectIntentV3,
    ) -> Result<Option<DurableReapObservationV3>, ServiceError> {
        let idempotency = reap_observation_idempotency(
            &prepared.intent.key(),
            &prepared.intent_receipt_sha256,
        );
        let Some(bytes) = self
            .journal
            .repair_lookup(
                idempotency.clone(),
                prepared
                    .intent
                    .evidence_query_deadline
                    .absolute_boottime_nanos(),
            )?
        else {
            return Ok(None);
        };
        let exact_request =
            exact_reap_observation_request(prepared)?;
        let replay = self.journal.append(
            idempotency,
            &exact_request,
            &bytes,
            prepared
                .intent
                .evidence_query_deadline
                .absolute_boottime_nanos(),
        )?;
        let observation: DurableReapObservationV3 =
            decode_canonical_frame(replay.exact_response_bytes())?;
        observation.validate(prepared)?;
        Ok(Some(observation))
    }
}

enum EffectProgress {
    Pending(PendingEffectExecution),
    Complete(Vec<u8>),
}

fn wait_for_bootstrap_effect(
    pending: &PendingEffectExecution,
    startup_deadline_nanos: u64,
) -> Result<(), ServiceError> {
    let (fd, events) = match &pending.state {
        EffectExecutionState::StartNew
        | EffectExecutionState::StartReconciliation => {
            return Ok(())
        }
        EffectExecutionState::KillCgroup { events, .. } => {
            (events.as_raw_fd(), libc::POLLIN)
        }
        EffectExecutionState::ReapWorker { .. } => {
            (pending.worker_pidfd.as_raw_fd(), libc::POLLIN)
        }
    };
    let now = boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "cleanup-helper bootstrap wait lacks CLOCK_BOOTTIME",
        )
    })?;
    if now >= startup_deadline_nanos {
        return Err(ServiceError::Invalid(
            "cleanup-helper bootstrap effect wait crossed its startup deadline",
        ));
    }
    let timeout_millis = startup_deadline_nanos
        .saturating_sub(now)
        .saturating_add(999_999)
        / 1_000_000;
    let timeout = i32::try_from(timeout_millis.min(100))
        .map_err(|_| {
            ServiceError::Invalid(
                "cleanup-helper bootstrap poll timeout overflowed",
            )
        })?;
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = loop {
        let result =
            unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(error.into());
    };
    if result > 0
        && descriptor.revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
    {
        return Err(ServiceError::Invalid(
            "cleanup-helper bootstrap effect descriptor failed",
        ));
    }
    Ok(())
}

struct ServerPacket {
    frame: Vec<u8>,
    rights: Vec<OwnedFd>,
}

fn exact_two_rights(
    rights: Vec<OwnedFd>,
) -> Result<(OwnedFd, OwnedFd), ServiceError> {
    let mut rights = rights.into_iter();
    let worker_pidfd = rights.next().ok_or(ServiceError::Invalid(
        "cleanup request omitted the exact worker pidfd",
    ))?;
    let cgroup_fd = rights.next().ok_or(ServiceError::Invalid(
        "cleanup request omitted the exact cgroup descriptor",
    ))?;
    if rights.next().is_some() {
        return Err(ServiceError::Invalid(
            "cleanup request included extra descriptors",
        ));
    }
    Ok((worker_pidfd, cgroup_fd))
}

fn helper_request_endpoint_role(
    request: &BoundedCleanupHelperRequestV3,
) -> PolicyCustodyEndpointRole {
    match request {
        BoundedCleanupHelperRequestV3::Query { key, .. }
        | BoundedCleanupHelperRequestV3::Execute { key, .. } => {
            key.action.required_endpoint_role()
        }
        BoundedCleanupHelperRequestV3::Prepare { intent, .. } => {
            intent.action.required_endpoint_role()
        }
    }
}

fn require_request_binding_matches_payload(
    frame: &ServiceRequestFrameV3,
    request: &BoundedCleanupHelperRequestV3,
) -> Result<(), ServiceError> {
    let (request_id, deadline) = match request {
        BoundedCleanupHelperRequestV3::Query {
            request_id_sha256,
            deadline,
            ..
        }
        | BoundedCleanupHelperRequestV3::Prepare {
            request_id_sha256,
            deadline,
            ..
        }
        | BoundedCleanupHelperRequestV3::Execute {
            request_id_sha256,
            deadline,
            ..
        } => (request_id_sha256, deadline),
    };
    if request_id != &frame.binding.request_id_sha256
        || deadline != &frame.binding.deadline
    {
        return Err(ServiceError::Invalid(
            "cleanup helper payload changed its framed request id or deadline",
        ));
    }
    require_live_protocol_deadline(deadline)?;
    Ok(())
}

fn duplicate_cloexec(fd: RawFd) -> Result<OwnedFd, ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "cannot duplicate an invalid cleanup helper descriptor",
        ));
    }
    let duplicate =
        unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn validate_server_socket(
    socket: &OwnedFd,
    expected_peer: ExpectedPeerCredentials,
) -> Result<PeerCredentialsV3, ServiceError> {
    let fd = socket.as_raw_fd();
    let mut socket_type: libc::c_int = 0;
    let mut accepting: libc::c_int = 0;
    let mut integer_length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut integer_length,
        )
    } != 0
        || integer_length as usize != size_of::<libc::c_int>()
    {
        return Err(io::Error::last_os_error().into());
    }
    integer_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut integer_length,
        )
    } != 0
        || integer_length as usize != size_of::<libc::c_int>()
        || socket_type != libc::SOCK_SEQPACKET
        || accepting != 0
    {
        return Err(ServiceError::Invalid(
            "cleanup helper server descriptor is not a connected SOCK_SEQPACKET",
        ));
    }
    let mut peer_address: libc::sockaddr_storage =
        unsafe { zeroed() };
    let mut peer_length =
        size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut peer_address as *mut libc::sockaddr_storage)
                .cast(),
            &mut peer_length,
        )
    } != 0
        || (peer_length as usize) < size_of::<libc::sa_family_t>()
        || peer_address.ss_family as i32 != libc::AF_UNIX
    {
        return Err(ServiceError::Invalid(
            "cleanup helper server peer is not AF_UNIX",
        ));
    }
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut credential_length =
        size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut credential_length,
        )
    } != 0
        || credential_length as usize != size_of::<libc::ucred>()
    {
        return Err(ServiceError::Invalid(
            "cleanup helper server cannot authenticate its peer",
        ));
    }
    let peer = PeerCredentialsV3 {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    };
    expected_peer.validate(peer)?;
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let descriptor_flags =
        unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if status < 0
        || descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                status | libc::O_NONBLOCK,
            )
        } < 0
        || unsafe {
            libc::fcntl(
                fd,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(peer)
}

fn enable_child_subreaper() -> Result<(), ServiceError> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }
        != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut enabled: libc::c_int = 0;
    if unsafe {
        libc::prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            &mut enabled as *mut libc::c_int,
            0,
            0,
            0,
        )
    } != 0
        || enabled != 1
    {
        return Err(ServiceError::Invalid(
            "cleanup helper could not prove subreaper authority",
        ));
    }
    Ok(())
}

fn prove_worker_parent_relationship(
    worker_pidfd: BorrowedFd<'_>,
) -> Result<u64, ServiceError> {
    let mut subreaper: libc::c_int = 0;
    if unsafe {
        libc::prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            &mut subreaper as *mut libc::c_int,
            0,
            0,
            0,
        )
    } != 0
        || subreaper != 1
    {
        return Err(ServiceError::Invalid(
            "cleanup helper is not the configured child subreaper",
        ));
    }
    let mut information: libc::siginfo_t = unsafe { zeroed() };
    let result = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            P_PIDFD_IDTYPE,
            worker_pidfd.as_raw_fd() as libc::id_t,
            &mut information as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ptr::null_mut::<libc::rusage>(),
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Err(ServiceError::Invalid(
                "cleanup helper is not the worker's actual parent or subreaper",
            ));
        }
        return Err(error.into());
    }
    boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "cleanup worker parent proof lacks CLOCK_BOOTTIME",
        )
    })
}

fn require_same_open_file_description(
    left: BorrowedFd<'_>,
    right: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    const KCMP_FILE: libc::c_int = 0;
    let process = unsafe { libc::getpid() };
    let compared = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            process,
            process,
            KCMP_FILE,
            left.as_raw_fd(),
            right.as_raw_fd(),
        )
    };
    if compared != 0 {
        return Err(ServiceError::Invalid(
            "cleanup worker pidfd is not the readiness-retained open-file description",
        ));
    }
    Ok(())
}

fn try_send_seqpacket(
    socket_fd: RawFd,
    frame: &[u8],
) -> Result<bool, ServiceError> {
    if frame.is_empty() || frame.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(ServiceError::Invalid(
            "cleanup helper reply violates its frame bound",
        ));
    }
    loop {
        let sent = unsafe {
            libc::send(
                socket_fd,
                frame.as_ptr().cast(),
                frame.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent == frame.len() as isize {
            return Ok(true);
        }
        if sent >= 0 {
            return Err(ServiceError::Invalid(
                "cleanup helper SOCK_SEQPACKET reply was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(false),
            _ => return Err(error.into()),
        }
    }
}

#[repr(align(16))]
struct ServerAncillary([u8; 256]);

fn try_receive_seqpacket_any_rights(
    socket_fd: RawFd,
    expected_peer: PeerCredentialsV3,
) -> Result<Option<ServerPacket>, ServiceError> {
    let mut frame = vec![0_u8; MAX_SERVICE_FRAME_BYTES];
    let mut vector = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut ancillary = ServerAncillary([0; 256]);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.0.as_mut_ptr().cast();
    message.msg_controllen = ancillary.0.len();
    let received = loop {
        let result = unsafe {
            libc::recvmsg(
                socket_fd,
                &mut message,
                libc::MSG_DONTWAIT
                    | libc::MSG_TRUNC
                    | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => return Err(error.into()),
        }
    };
    if received == 0 {
        return Err(ServiceError::Invalid(
            "cleanup helper peer closed its service socket",
        ));
    }
    let rights = received_rights(&message, expected_peer)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(ServiceError::Invalid(
            "cleanup helper request or SCM_RIGHTS was truncated",
        ));
    }
    let received = usize::try_from(received).map_err(|_| {
        ServiceError::Invalid(
            "cleanup helper request length overflow",
        )
    })?;
    if received > frame.len() {
        return Err(ServiceError::Invalid(
            "cleanup helper request exceeds its frame bound",
        ));
    }
    frame.truncate(received);
    Ok(Some(ServerPacket { frame, rights }))
}

fn received_rights(
    message: &libc::msghdr,
    expected_peer: PeerCredentialsV3,
) -> Result<Vec<OwnedFd>, ServiceError> {
    let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
    let credential_length =
        unsafe { libc::CMSG_LEN(size_of::<libc::ucred>() as u32) }
            as usize;
    let mut rights = Vec::with_capacity(EXACT_EXECUTE_RIGHTS);
    let mut credentials_seen = false;
    let mut rights_seen = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let length = unsafe { (*header).cmsg_len };
        if level != libc::SOL_SOCKET || length < minimum {
            return Err(ServiceError::Invalid(
                "cleanup helper request has malformed ancillary data",
            ));
        }
        match kind {
            libc::SCM_CREDENTIALS => {
                if credentials_seen || length != credential_length {
                    return Err(ServiceError::Invalid(
                        "cleanup helper request has duplicate or malformed credentials",
                    ));
                }
                let observed = unsafe {
                    ptr::read_unaligned(
                        libc::CMSG_DATA(header)
                            .cast::<libc::ucred>(),
                    )
                };
                if observed.pid != expected_peer.pid
                    || observed.uid != expected_peer.uid
                    || observed.gid != expected_peer.gid
                {
                    return Err(ServiceError::Invalid(
                        "cleanup helper request credentials changed",
                    ));
                }
                credentials_seen = true;
            }
            libc::SCM_RIGHTS => {
                if rights_seen
                    || (length - minimum) % size_of::<RawFd>() != 0
                {
                    return Err(ServiceError::Invalid(
                        "cleanup helper request has duplicate or malformed SCM_RIGHTS",
                    ));
                }
                let count =
                    (length - minimum) / size_of::<RawFd>();
                if count > EXACT_EXECUTE_RIGHTS {
                    return Err(ServiceError::Invalid(
                        "cleanup helper received too many descriptors",
                    ));
                }
                let raw = unsafe {
                    std::slice::from_raw_parts(
                        libc::CMSG_DATA(header).cast::<RawFd>(),
                        count,
                    )
                };
                for descriptor in raw {
                    if *descriptor < 0 {
                        return Err(ServiceError::Invalid(
                            "cleanup helper received an invalid descriptor",
                        ));
                    }
                    rights.push(unsafe {
                        OwnedFd::from_raw_fd(*descriptor)
                    });
                }
                rights_seen = true;
            }
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup helper request has unsupported ancillary data",
                ));
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if !credentials_seen {
        return Err(ServiceError::Invalid(
            "cleanup helper request is missing kernel credentials",
        ));
    }
    Ok(rights)
}

fn observe_retained_descriptor(
    role: WatchdogRegistrationFdRole,
    descriptor: BorrowedFd<'_>,
) -> Result<WatchdogRetainedFdIdentityV3, ServiceError> {
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
        return Err(ServiceError::Invalid(
            "cleanup helper retained descriptor identity is unavailable",
        ));
    }
    let frames = [
        stat.st_dev.to_be_bytes().to_vec(),
        stat.st_ino.to_be_bytes().to_vec(),
        stat.st_mode.to_be_bytes().to_vec(),
        stat.st_uid.to_be_bytes().to_vec(),
        stat.st_gid.to_be_bytes().to_vec(),
        (stat.st_size as u64).to_be_bytes().to_vec(),
        stat.st_mtime.to_be_bytes().to_vec(),
        stat.st_mtime_nsec.to_be_bytes().to_vec(),
        stat.st_ctime.to_be_bytes().to_vec(),
        stat.st_ctime_nsec.to_be_bytes().to_vec(),
        statx.stx_mnt_id.to_be_bytes().to_vec(),
    ];
    let mut hasher = Sha256::new();
    for frame in &frames {
        hasher.update((frame.len() as u64).to_be_bytes());
        hasher.update(frame);
    }
    let digest = Sha256Digest::parse(format!(
        "sha256:{}",
        hex::encode(hasher.finalize())
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "cleanup helper retained descriptor digest encoding failed",
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
    observed.validate()?;
    Ok(observed)
}

fn verify_execution_descriptors(
    intent: &CleanupEffectIntentV3,
    worker_pidfd: BorrowedFd<'_>,
    cgroup_fd: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    intent.validate()?;
    let worker = observe_retained_descriptor(
        WatchdogRegistrationFdRole::WorkerPidfd,
        worker_pidfd,
    )?;
    let cgroup = observe_retained_descriptor(
        WatchdogRegistrationFdRole::OperationCgroup,
        cgroup_fd,
    )?;
    if worker != intent.retained_descriptors.worker_pidfd
        || cgroup != intent.retained_descriptors.operation_cgroup
        || worker.inode != intent.worker.pidfd_inode
        || worker.retained_fd_stat_sha256
            != intent.worker.pidfd_stat_sha256
        || cgroup.inode != intent.cgroup.inode
        || cgroup.mount_id != intent.cgroup.mount_id
        || cgroup.retained_fd_stat_sha256
            != intent.cgroup.retained_fd_stat_sha256
    {
        return Err(ServiceError::Invalid(
            "cleanup helper SCM_RIGHTS descriptors changed their exact retained identities",
        ));
    }
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    if unsafe {
        libc::fstatfs(cgroup_fd.as_raw_fd(), &mut filesystem)
    } != 0
        || filesystem.f_type != CGROUP2_SUPER_MAGIC as _
        || cgroup.mode & libc::S_IFMT as u32
            != libc::S_IFDIR as u32
        || cgroup.uid != 0
        || cgroup.mode & 0o022 != 0
    {
        return Err(ServiceError::Invalid(
            "cleanup helper cgroup descriptor is not a protected cgroup-v2 directory",
        ));
    }
    Ok(())
}

fn open_cgroup_control(
    cgroup_fd: BorrowedFd<'_>,
    nul_terminated_name: &[u8],
    flags: libc::c_int,
) -> Result<OwnedFd, ServiceError> {
    if nul_terminated_name.last() != Some(&0)
        || nul_terminated_name[..nul_terminated_name.len() - 1]
            .contains(&b'/')
    {
        return Err(ServiceError::Invalid(
            "cleanup helper cgroup control is not one relative component",
        ));
    }
    let descriptor = unsafe {
        libc::openat(
            cgroup_fd.as_raw_fd(),
            nul_terminated_name.as_ptr().cast(),
            flags,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return Err(ServiceError::Invalid(
            "cleanup helper cgroup control is not a regular cgroupfs file",
        ));
    }
    Ok(descriptor)
}

fn try_write_cgroup_kill(
    descriptor: BorrowedFd<'_>,
) -> Result<bool, ServiceError> {
    loop {
        let written = unsafe {
            libc::write(
                descriptor.as_raw_fd(),
                b"1".as_ptr().cast(),
                1,
            )
        };
        if written == 1 {
            return Ok(true);
        }
        if written >= 0 {
            return Err(ServiceError::Invalid(
                "cleanup helper cgroup.kill write was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(false),
            _ => return Err(error.into()),
        }
    }
}

fn try_read_cgroup_events(
    descriptor: BorrowedFd<'_>,
) -> Result<Option<(bool, Vec<u8>)>, ServiceError> {
    if unsafe {
        libc::lseek(descriptor.as_raw_fd(), 0, libc::SEEK_SET)
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut bytes = [0_u8; MAX_CGROUP_EVENTS_BYTES];
    let mut length = 0_usize;
    loop {
        if length == bytes.len() {
            return Err(ServiceError::Invalid(
                "cleanup helper cgroup.events exceeds its bound",
            ));
        }
        let read = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                bytes[length..].as_mut_ptr().cast(),
                bytes.len() - length,
            )
        };
        if read > 0 {
            length = length
                .checked_add(usize::try_from(read).map_err(|_| {
                    ServiceError::Invalid(
                        "cleanup helper cgroup.events length overflow",
                    )
                })?)
                .ok_or(ServiceError::Invalid(
                    "cleanup helper cgroup.events offset overflow",
                ))?;
            continue;
        }
        if read == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) if length == 0 => return Ok(None),
            Some(libc::EAGAIN) => break,
            _ => return Err(error.into()),
        }
    }
    if !bytes[..length].is_ascii() {
        return Err(ServiceError::Invalid(
            "cleanup helper cgroup.events is not ASCII",
        ));
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| {
        ServiceError::Invalid(
            "cleanup helper cgroup.events is not UTF-8",
        )
    })?;
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(ServiceError::Invalid(
            "cleanup helper cgroup.events has an empty record",
        ))?;
        let value = fields.next().ok_or(ServiceError::Invalid(
            "cleanup helper cgroup.events lacks a value",
        ))?;
        if fields.next().is_some() {
            return Err(ServiceError::Invalid(
                "cleanup helper cgroup.events has extra fields",
            ));
        }
        if name == "populated" {
            if populated.is_some() || !matches!(value, "0" | "1") {
                return Err(ServiceError::Invalid(
                    "cleanup helper cgroup.events populated value is invalid",
                ));
            }
            populated = Some(value == "1");
        }
    }
    Ok(Some((
        populated.ok_or(ServiceError::Invalid(
            "cleanup helper cgroup.events lacks populated",
        ))?,
        bytes[..length].to_vec(),
    )))
}

fn observe_reapable_pidfd(
    worker_pidfd: BorrowedFd<'_>,
    prepared: &PersistedCleanupEffectIntentV3,
) -> Result<Option<DurableReapObservationV3>, ServiceError> {
    let mut information: libc::siginfo_t = unsafe { zeroed() };
    let result = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            P_PIDFD_IDTYPE,
            worker_pidfd.as_raw_fd() as libc::id_t,
            &mut information as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ptr::null_mut::<libc::rusage>(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let observed_pid = unsafe { information.si_pid() };
    if observed_pid == 0 {
        return Ok(None);
    }
    if observed_pid != prepared.intent.worker.pid {
        return Err(ServiceError::Invalid(
            "cleanup helper pidfd resolved to another child",
        ));
    }
    let observed_at_boottime_nanos =
        boottime_now_nanos().map_err(|_| {
            ServiceError::Invalid(
                "cleanup helper reap observation lacks CLOCK_BOOTTIME",
            )
        })?;
    DurableReapObservationV3::new(
        prepared,
        prepared.intent.retained_descriptors.worker_pidfd.clone(),
        observed_pid,
        information.si_code,
        unsafe { information.si_status() },
        observed_at_boottime_nanos,
    )
    .map(Some)
}

fn reap_pidfd_exact(
    worker_pidfd: BorrowedFd<'_>,
    observation: &DurableReapObservationV3,
) -> Result<(), ServiceError> {
    let mut information: libc::siginfo_t = unsafe { zeroed() };
    let result = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            P_PIDFD_IDTYPE,
            worker_pidfd.as_raw_fd() as libc::id_t,
            &mut information as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG,
            ptr::null_mut::<libc::rusage>(),
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD)
            && pidfd_is_terminal(worker_pidfd)?
        {
            // A retry after the exact child was already consumed can no
            // longer obtain siginfo. The fsynced WNOWAIT observation is the
            // authoritative status, and the same pidfd proves the target is
            // terminal without a numeric-PID lookup.
            return Ok(());
        }
        return Err(error.into());
    }
    if unsafe { information.si_pid() } != observation.observed_pid
        || information.si_code != observation.signal_code
        || unsafe { information.si_status() }
            != observation.wait_status
    {
        return Err(ServiceError::Invalid(
            "cleanup helper exact pidfd reap changed its durable observation",
        ));
    }
    Ok(())
}

fn pidfd_was_already_reaped(
    worker_pidfd: BorrowedFd<'_>,
    observation: &DurableReapObservationV3,
) -> Result<bool, ServiceError> {
    let mut information: libc::siginfo_t = unsafe { zeroed() };
    let result = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            P_PIDFD_IDTYPE,
            worker_pidfd.as_raw_fd() as libc::id_t,
            &mut information as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ptr::null_mut::<libc::rusage>(),
        )
    };
    if result == 0 {
        let observed_pid = unsafe { information.si_pid() };
        if observed_pid == 0 {
            return Ok(false);
        }
        if observed_pid != observation.observed_pid
            || information.si_code != observation.signal_code
            || unsafe { information.si_status() }
                != observation.wait_status
        {
            return Err(ServiceError::Invalid(
                "cleanup helper parent query changed the durable worker observation",
            ));
        }
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD)
        && pidfd_is_terminal(worker_pidfd)?
    {
        return Ok(true);
    }
    Err(error.into())
}

fn pidfd_is_terminal(
    worker_pidfd: BorrowedFd<'_>,
) -> Result<bool, ServiceError> {
    let mut descriptor = libc::pollfd {
        fd: worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready == 0 {
            return Ok(false);
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.into());
        }
        if descriptor.revents
            & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)
            != 0
            && descriptor.revents & libc::POLLNVAL == 0
        {
            return Ok(true);
        }
        return Err(ServiceError::Invalid(
            "cleanup helper pidfd returned an invalid terminal event",
        ));
    }
}
