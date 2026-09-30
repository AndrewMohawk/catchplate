//! TrustedHostNoTee cleanup-authorization consumption authority.
//!
//! The client is a single-flight, nonblocking Query/CAS/Query state machine.
//! The server handler is transport-neutral so the shared authenticated
//! `SOCK_SEQPACKET` dispatcher can own accept/send progress. The exact signed
//! exchange is the sole durable state transition and is committed before the
//! derived in-memory state becomes visible.

use super::common::{
    decode_canonical_frame, encode_canonical_frame,
    AuthenticatedInheritedSeqpacket, DurableAppendJournal,
    ExpectedPeerCredentials, NonblockingExchangeFlightState,
    NonblockingExchangeProgress, NonblockingRequestReplyExchange,
    ServiceCurrentHeadBindingV3, ServiceError,
    ServiceRequestFrameV3, ServiceResponseFrameV3,
    TrustedHostNoTeeServiceReportV3, TrustedHostServiceRoleV3,
    VerifiedJournalChainV3, MAX_SERVICE_FRAME_BYTES,
};
use super::wire::{
    CleanupAuthorizationConsumerReplyV3,
    CleanupAuthorizationConsumerRequestV3,
    PolicyCustodyServiceReplyV3, PolicyCustodyServiceRequestV3,
    PolicyCustodyServiceRoleV3, ServiceResponseSignatureV3,
    SignedPolicyCustodyServiceReplyV3, SignedServiceResponseV3,
    POLICY_CUSTODY_SERVICES_WIRE_VERSION,
};
use super::super::boottime::{
    boottime_now_nanos,
    BoottimeDeadline as AbsoluteBoottimeDeadline,
};
use super::super::protocol::{
    domain_separated_signature_preimage, endpoint_request_sha256,
    endpoint_response_sha256, endpoint_receipt_statement_sha256,
    CleanupAuthorizationConsumptionStatement,
    CleanupConsumptionCasReply, CleanupConsumptionCommand,
    CleanupConsumptionCompareAndSwap, CleanupConsumptionCursorV3,
    CleanupConsumptionQuery, CleanupConsumptionQueryReply,
    EndpointProcessIdentity,
    PersistedCleanupAuthorizationConsumptionV3,
    PolicyCustodyEndpointRole, ProtocolBoottimeDeadline,
    SignedCleanupAuthorizationV3, SignedCleanupConsumptionCursorV3,
    SignedDurableConsumeReceiptEnvelope,
    SignedEndpointResponseEnvelope,
    POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION,
    POLICY_CUSTODY_PROTOCOL_VERSION,
};
use super::super::watchdog_recovery::{
    CleanupAuthorizationConsumer, CleanupTraceRequestBindings,
    RecoveryError, UnverifiedCleanupAuthorizationConsumption,
    UnverifiedSignedEndpointResponse,
};
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::mem::zeroed;
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};

const SERVICE_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyServiceResponse/v3";
const DURABLE_STATE_DOMAIN: &[u8] =
    b"serverware.policyCustodyCleanupAuthorizationConsumerState/v3";
const DURABLE_STATE_VERSION: &str =
    "serverware.policyCustodyCleanupAuthorizationConsumerState/v3";
const DURABLE_STATE_FILE: &str = "cleanup-consumer-state.v3.json";
const DURABLE_STATE_LOCK: &str = "cleanup-consumer-state.v3.lock";
const MAX_DURABLE_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DURABLE_CONSUMPTIONS: usize = 1_024;
const MAX_CLEANUP_JOURNAL_RECORDS: usize = 1_000_000;
const MAX_CLEANUP_JOURNAL_RECOVERY_BYTES: usize =
    256 * 1024 * 1024;
const EXACT_TRACE_HEAD_COUNT: usize = 3;

fn invalid_recovery(message: &'static str) -> RecoveryError {
    RecoveryError::Authorization(message)
}

fn service_to_recovery(_: ServiceError) -> RecoveryError {
    RecoveryError::Transient(
        "cleanup authorization consumer service exchange failed",
    )
}

fn protocol_to_service(
    error: impl std::fmt::Display,
) -> ServiceError {
    ServiceError::InvalidOwned(error.to_string())
}

fn digest_is_zero(digest: &Sha256Digest) -> bool {
    digest.as_str()
        == "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

fn require_live_protocol_deadline(
    deadline: &ProtocolBoottimeDeadline,
) -> Result<u64, ServiceError> {
    let runtime = deadline.to_runtime()?;
    runtime.require_live().map_err(|_| {
        ServiceError::Invalid("service request deadline is not live")
    })?;
    let now = boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "CLOCK_BOOTTIME is unavailable for the service request",
        )
    })?;
    if now >= deadline.absolute_boottime_nanos() {
        return Err(ServiceError::Invalid(
            "service request crossed its absolute BOOTTIME deadline",
        ));
    }
    Ok(now)
}

fn exact_command_sha256(
    request: &CleanupAuthorizationConsumerRequestV3,
) -> Result<Sha256Digest, ServiceError> {
    let command = match request {
        CleanupAuthorizationConsumerRequestV3::Query(query) => {
            CleanupConsumptionCommand::Query(query.clone())
        }
        CleanupAuthorizationConsumerRequestV3::CompareAndSwap(cas) => {
            CleanupConsumptionCommand::CompareAndSwap(cas.clone())
        }
    };
    let canonical = canonical_json_bytes(&command).map_err(|_| {
        ServiceError::Invalid(
            "cleanup Query/CAS command is not canonical",
        )
    })?;
    Ok(endpoint_request_sha256(&canonical))
}

fn command_nonce(
    request: &CleanupAuthorizationConsumerRequestV3,
) -> &Sha256Digest {
    match request {
        CleanupAuthorizationConsumerRequestV3::Query(query) => {
            &query.query_nonce_sha256
        }
        CleanupAuthorizationConsumerRequestV3::CompareAndSwap(cas) => {
            &cas.cas_nonce_sha256
        }
    }
}

fn command_deadline(
    request: &CleanupAuthorizationConsumerRequestV3,
) -> &ProtocolBoottimeDeadline {
    match request {
        CleanupAuthorizationConsumerRequestV3::Query(query) => {
            &query.deadline
        }
        CleanupAuthorizationConsumerRequestV3::CompareAndSwap(cas) => {
            &cas.deadline
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CleanupAuthorizationConsumerServiceEvidenceV3 {
    signed_service_reply: SignedPolicyCustodyServiceReplyV3,
    endpoint_envelope: SignedEndpointResponseEnvelope,
    exact_endpoint_response_bytes: Vec<u8>,
    exact_endpoint_signature_payload_bytes: Vec<u8>,
}

impl CleanupAuthorizationConsumerServiceEvidenceV3 {
    fn validate(
        &self,
        request: &CleanupAuthorizationConsumerRequestV3,
        request_binding: &super::common::ServiceRequestBindingV3,
        endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        self.signed_service_reply.validate(
            PolicyCustodyServiceRoleV3::CleanupAuthorizationConsumer,
            &request_binding.request_id_sha256,
            &request_binding.deadline,
        )?;
        self.signed_service_reply.response.validate()?;
        self.endpoint_envelope.validate_shape()?;
        let expected_reply = match (
            request,
            &self.signed_service_reply.response,
        ) {
            (
                CleanupAuthorizationConsumerRequestV3::Query(_),
                PolicyCustodyServiceReplyV3::
                    CleanupAuthorizationConsumer(
                        CleanupAuthorizationConsumerReplyV3::Query(
                            reply,
                        ),
                    ),
            ) => encode_canonical_frame(reply)?,
            (
                CleanupAuthorizationConsumerRequestV3::
                    CompareAndSwap(_),
                PolicyCustodyServiceReplyV3::
                    CleanupAuthorizationConsumer(
                        CleanupAuthorizationConsumerReplyV3::
                            CompareAndSwap(reply),
                    ),
            ) => encode_canonical_frame(reply)?,
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup consumer response changed its operation",
                ))
            }
        };
        let head = &request_binding
            .current_head
            .signed_current_head
            .statement;
        let expected_signature_payload =
            self.endpoint_envelope.canonical_signature_payload()?;
        if self.exact_endpoint_response_bytes != expected_reply
            || self.exact_endpoint_signature_payload_bytes
                != expected_signature_payload
            || self.endpoint_envelope.endpoint_role != endpoint_role
            || self
                .endpoint_envelope
                .endpoint_process_identity
                .endpoint_role
                != endpoint_role
            || self.endpoint_envelope.endpoint_generation
                != head.endpoint_generation
            || self
                .endpoint_envelope
                .current_key_authorization_checkpoint_sha256
                != head.checkpoint_sha256
            || self.endpoint_envelope.revocation_generation
                != head.revocation_generation_high_water
            || self.endpoint_envelope.revocation_root_sha256
                != head.revocation_root_sha256
            || self.endpoint_envelope.request_nonce_sha256
                != *command_nonce(request)
            || self.endpoint_envelope.request_sha256
                != exact_command_sha256(request)?
            || self.endpoint_envelope.canonical_response_base64
                != URL_SAFE_NO_PAD.encode(&expected_reply)
            || self.endpoint_envelope.response_sha256
                != endpoint_response_sha256(&expected_reply)
            || self.endpoint_envelope.observed_at_boottime_nanos
                >= request_binding
                    .deadline
                    .absolute_boottime_nanos()
            || self
                .signed_service_reply
                .signature
                .endpoint_generation
                != head.endpoint_generation
            || self
                .signed_service_reply
                .signature
                .current_key_authorization_checkpoint_sha256
                != head.checkpoint_sha256
            || self
                .signed_service_reply
                .signature
                .revocation_generation
                != head.revocation_generation_high_water
            || self
                .signed_service_reply
                .signature
                .revocation_root_sha256
                != head.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup consumer response changed its exact request, deadline, current head, or endpoint evidence",
            ));
        }
        Ok(())
    }

    fn query_evidence(
        &self,
    ) -> Result<
        (
            CleanupConsumptionQueryReply,
            UnverifiedSignedEndpointResponse<
                CleanupConsumptionQueryReply,
            >,
        ),
        ServiceError,
    > {
        let reply = match &self.signed_service_reply.response {
            PolicyCustodyServiceReplyV3::
                CleanupAuthorizationConsumer(
                    CleanupAuthorizationConsumerReplyV3::Query(
                        reply,
                    ),
                ) => reply.clone(),
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup query returned a non-query response",
                ))
            }
        };
        Ok((
            reply.clone(),
            UnverifiedSignedEndpointResponse {
                response: reply,
                envelope: self.endpoint_envelope.clone(),
                exact_canonical_response: self
                    .exact_endpoint_response_bytes
                    .clone()
                    .into_boxed_slice(),
                exact_signature_payload: self
                    .exact_endpoint_signature_payload_bytes
                    .clone()
                    .into_boxed_slice(),
            },
        ))
    }

    fn cas_evidence(
        &self,
    ) -> Result<
        (
            CleanupConsumptionCasReply,
            UnverifiedSignedEndpointResponse<
                CleanupConsumptionCasReply,
            >,
        ),
        ServiceError,
    > {
        let reply = match &self.signed_service_reply.response {
            PolicyCustodyServiceReplyV3::
                CleanupAuthorizationConsumer(
                    CleanupAuthorizationConsumerReplyV3::
                        CompareAndSwap(reply),
                ) => reply.clone(),
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup CAS returned a non-CAS response",
                ))
            }
        };
        Ok((
            reply.clone(),
            UnverifiedSignedEndpointResponse {
                response: reply,
                envelope: self.endpoint_envelope.clone(),
                exact_canonical_response: self
                    .exact_endpoint_response_bytes
                    .clone()
                    .into_boxed_slice(),
                exact_signature_payload: self
                    .exact_endpoint_signature_payload_bytes
                    .clone()
                    .into_boxed_slice(),
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExactCleanupTraceCurrentHeadsV3 {
    pub(super) before_query: ServiceCurrentHeadBindingV3,
    pub(super) compare_and_swap: ServiceCurrentHeadBindingV3,
    pub(super) after_query: ServiceCurrentHeadBindingV3,
}

impl ExactCleanupTraceCurrentHeadsV3 {
    fn all(&self) -> [&ServiceCurrentHeadBindingV3; 3] {
        [
            &self.before_query,
            &self.compare_and_swap,
            &self.after_query,
        ]
    }

    fn for_exact_request(
        &self,
        endpoint_role: PolicyCustodyEndpointRole,
        request_nonce_sha256: &Sha256Digest,
        request_sha256: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<ServiceCurrentHeadBindingV3, RecoveryError> {
        let mut selected = None;
        for candidate in self.all() {
            candidate
                .validate(endpoint_role, deadline)
                .map_err(service_to_recovery)?;
            let statement =
                &candidate.signed_current_head.statement;
            if &statement.request_nonce_sha256
                    == request_nonce_sha256
                && &statement.request_sha256 == request_sha256
            {
                if selected.is_some() {
                    return Err(invalid_recovery(
                        "duplicate current-head binding for cleanup request",
                    ));
                }
                selected = Some(candidate.clone());
            }
        }
        selected.ok_or_else(|| {
            invalid_recovery(
                "missing exact fresh current-head binding for cleanup request",
            )
        })
    }

    fn require_one_authority(
        &self,
        endpoint_role: PolicyCustodyEndpointRole,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        let heads = self.all();
        if heads.len() != EXACT_TRACE_HEAD_COUNT {
            return Err(invalid_recovery(
                "cleanup trace does not contain exactly three current heads",
            ));
        }
        let first = &heads[0].signed_current_head;
        first
            .validate_shape()
            .map_err(|_| invalid_recovery(
                "cleanup current head is invalid",
            ))?;
        for head in &heads {
            head.validate(endpoint_role, deadline)
                .map_err(service_to_recovery)?;
        }
        for pair in heads.windows(2) {
            let previous = &pair[0].signed_current_head;
            let current = &pair[1].signed_current_head;
            if current.authority_key_id
                    != previous.authority_key_id
                || current.authority_key_spki_sha256
                    != previous.authority_key_spki_sha256
                || current.statement.endpoint_generation
                    != previous.statement.endpoint_generation
                || current.statement.checkpoint_sequence
                    < previous.statement.checkpoint_sequence
                || (current.statement.checkpoint_sequence
                        == previous.statement.checkpoint_sequence
                    && current.statement.checkpoint_sha256
                        != previous.statement.checkpoint_sha256)
                || current
                    .statement
                    .revocation_generation_high_water
                    < previous
                        .statement
                        .revocation_generation_high_water
                || (current
                        .statement
                        .revocation_generation_high_water
                        == previous
                            .statement
                            .revocation_generation_high_water
                    && current.statement.revocation_root_sha256
                        != previous
                            .statement
                            .revocation_root_sha256)
            {
                return Err(invalid_recovery(
                    "cleanup trace current heads changed authority, generation, or rolled back between adjacent requests",
                ));
            }
        }
        Ok(())
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientStep {
    BeforeQuery,
    CompareAndSwap,
    AfterQuery,
}

struct PendingClientOperation {
    fingerprint: Sha256Digest,
    authorization: SignedCleanupAuthorizationV3,
    trace: CleanupTraceRequestBindings,
    deadline: ProtocolBoottimeDeadline,
    step: ClientStep,
    active_request: CleanupAuthorizationConsumerRequestV3,
    before_reply: Option<CleanupConsumptionQueryReply>,
    before_evidence: Option<
        UnverifiedSignedEndpointResponse<
            CleanupConsumptionQueryReply,
        >,
    >,
    cas_reply: Option<CleanupConsumptionCasReply>,
    cas_evidence: Option<
        UnverifiedSignedEndpointResponse<CleanupConsumptionCasReply>,
    >,
}

pub(super) struct TrustedHostNoTeeCleanupAuthorizationConsumerClient {
    exchange: NonblockingRequestReplyExchange,
    progress: OwnedFd,
    endpoint_role: PolicyCustodyEndpointRole,
    current_heads: ExactCleanupTraceCurrentHeadsV3,
    pending: Option<PendingClientOperation>,
}

impl TrustedHostNoTeeCleanupAuthorizationConsumerClient {
    pub(super) fn from_inherited_seqpacket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        endpoint_role: PolicyCustodyEndpointRole,
        current_heads: ExactCleanupTraceCurrentHeadsV3,
    ) -> Result<Self, ServiceError> {
        let progress = duplicate_cloexec(socket.as_raw_fd())?;
        let peer = AuthenticatedInheritedSeqpacket::from_inherited(
            socket,
            expected_peer,
        )?;
        Ok(Self {
            exchange: NonblockingRequestReplyExchange::new(peer),
            progress,
            endpoint_role,
            current_heads,
            pending: None,
        })
    }

    pub(super) fn replace_inherited_seqpacket_after_failure(
        &mut self,
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
    ) -> Result<(), ServiceError> {
        if self.pending.is_none() {
            return Err(ServiceError::Invalid(
                "cleanup consumer has no exact operation to resume",
            ));
        }
        let progress = duplicate_cloexec(socket.as_raw_fd())?;
        let peer = AuthenticatedInheritedSeqpacket::from_inherited(
            socket,
            expected_peer,
        )?;
        self.exchange
            .replace_peer_and_retry_exact_flight(peer)?;
        self.progress = progress;
        Ok(())
    }

    fn operation_fingerprint(
        authorization: &SignedCleanupAuthorizationV3,
        trace: &CleanupTraceRequestBindings,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<Sha256Digest, RecoveryError> {
        let canonical = canonical_json_bytes(&(
            authorization,
            &trace.before_query_nonce_sha256,
            &trace.before_query_request_sha256,
            &trace.cas_nonce_sha256,
            &trace.cas_request_sha256,
            &trace.after_query_nonce_sha256,
            &trace.after_query_request_sha256,
            deadline,
        ))
        .map_err(|_| {
            invalid_recovery(
                "cleanup operation fingerprint is not canonical",
            )
        })?;
        Ok(Sha256Digest::compute(&canonical))
    }

    fn validate_trace(
        &self,
        authorization: &SignedCleanupAuthorizationV3,
        trace: &CleanupTraceRequestBindings,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), RecoveryError> {
        authorization.validate_shape().map_err(|_| {
            invalid_recovery("cleanup authorization shape is invalid")
        })?;
        if authorization.payload.endpoint_role != self.endpoint_role
            || authorization.payload.absolute_boottime_deadline
                != *deadline
        {
            return Err(invalid_recovery(
                "cleanup authorization changed endpoint role or exact deadline",
            ));
        }
        let digests = [
            &trace.before_query_nonce_sha256,
            &trace.before_query_request_sha256,
            &trace.cas_nonce_sha256,
            &trace.cas_request_sha256,
            &trace.after_query_nonce_sha256,
            &trace.after_query_request_sha256,
        ];
        if digests.iter().any(|digest| digest_is_zero(digest))
            || trace.before_query_nonce_sha256
                == trace.cas_nonce_sha256
            || trace.before_query_nonce_sha256
                == trace.after_query_nonce_sha256
            || trace.cas_nonce_sha256
                == trace.after_query_nonce_sha256
            || trace.before_query_request_sha256
                == trace.cas_request_sha256
            || trace.before_query_request_sha256
                == trace.after_query_request_sha256
            || trace.cas_request_sha256
                == trace.after_query_request_sha256
        {
            return Err(invalid_recovery(
                "cleanup Query/CAS/Query trace bindings are invalid",
            ));
        }
        self.current_heads
            .require_one_authority(self.endpoint_role, deadline)
    }

    fn query_request(
        authorization: &SignedCleanupAuthorizationV3,
        query_nonce_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    ) -> CleanupAuthorizationConsumerRequestV3 {
        CleanupAuthorizationConsumerRequestV3::Query(
            CleanupConsumptionQuery {
                api_version:
                    POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
                        .to_string(),
                authorization_nonce_sha256: authorization
                    .payload
                    .authorization_nonce_sha256
                    .clone(),
                query_nonce_sha256,
                deadline,
            },
        )
    }

    fn begin_request(
        &mut self,
        request: &CleanupAuthorizationConsumerRequestV3,
        expected_request_sha256: &Sha256Digest,
    ) -> Result<(), RecoveryError> {
        request.validate().map_err(|_| {
            invalid_recovery("cleanup service request is invalid")
        })?;
        let actual_request_sha256 =
            exact_command_sha256(request).map_err(service_to_recovery)?;
        if &actual_request_sha256 != expected_request_sha256 {
            return Err(invalid_recovery(
                "cleanup trace request digest does not match the exact v3 command",
            ));
        }
        let deadline = command_deadline(request).clone();
        let nonce = command_nonce(request).clone();
        let head = self.current_heads.for_exact_request(
            self.endpoint_role,
            &nonce,
            &actual_request_sha256,
            &deadline,
        )?;
        let payload =
            PolicyCustodyServiceRequestV3::
                CleanupAuthorizationConsumer(request.clone());
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            nonce,
            actual_request_sha256,
            deadline,
            head,
            &payload,
        )
        .map_err(service_to_recovery)?;
        self.exchange
            .begin(
                &frame,
                TrustedHostServiceRoleV3::
                    CleanupAuthorizationConsumer,
                self.endpoint_role,
                &[],
                0,
                0,
            )
            .map_err(service_to_recovery)
    }

    fn decode_completed(
        completed: super::common::CompletedServiceExchange,
        request: &CleanupAuthorizationConsumerRequestV3,
        endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<
        CleanupAuthorizationConsumerServiceEvidenceV3,
        RecoveryError,
    > {
        if !completed.rights.is_empty() {
            return Err(invalid_recovery(
                "cleanup consumer response unexpectedly carried descriptors",
            ));
        }
        let evidence: CleanupAuthorizationConsumerServiceEvidenceV3 =
            completed
                .response
                .decode_payload()
                .map_err(service_to_recovery)?;
        evidence
            .validate(
                request,
                &completed.response.request_binding,
                endpoint_role,
            )
            .map_err(service_to_recovery)?;
        Ok(evidence)
    }

    fn validate_before_reply(
        reply: &CleanupConsumptionQueryReply,
        deadline: &ProtocolBoottimeDeadline,
        endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), RecoveryError> {
        reply
            .authoritative_cursor
            .validate_shape()
            .map_err(|_| {
                invalid_recovery(
                    "pre-CAS cleanup cursor is invalid",
                )
            })?;
        if reply.authoritative_cursor.cursor.endpoint_role
                != endpoint_role
            || reply.authoritative_cursor.cursor.deadline
                != *deadline
        {
            return Err(invalid_recovery(
                "pre-CAS cleanup cursor changed role or deadline",
            ));
        }
        Ok(())
    }

    fn cas_request(
        pending: &PendingClientOperation,
    ) -> Result<CleanupAuthorizationConsumerRequestV3, RecoveryError> {
        let before = pending.before_reply.as_ref().ok_or_else(|| {
            invalid_recovery(
                "cleanup CAS lacks its authoritative pre-query",
            )
        })?;
        let cursor = &before.authoritative_cursor.cursor;
        Ok(
            CleanupAuthorizationConsumerRequestV3::CompareAndSwap(
                CleanupConsumptionCompareAndSwap {
                    api_version:
                        POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
                            .to_string(),
                    authorization: pending.authorization.clone(),
                    expected_consumer_sequence_high_water:
                        cursor.sequence_high_water,
                    expected_predecessor_receipt_sha256:
                        cursor.predecessor_receipt_sha256.clone(),
                    cas_nonce_sha256:
                        pending.trace.cas_nonce_sha256.clone(),
                    deadline: pending.deadline.clone(),
                },
            ),
        )
    }

    fn validate_cas_reply(
        reply: &CleanupConsumptionCasReply,
        request: &CleanupConsumptionCompareAndSwap,
    ) -> Result<(), RecoveryError> {
        reply
            .authoritative_cursor()
            .validate_shape()
            .map_err(|_| {
                invalid_recovery(
                    "cleanup CAS cursor is invalid",
                )
            })?;
        let cursor = &reply.authoritative_cursor().cursor;
        if cursor.endpoint_role
                != request.authorization.payload.endpoint_role
            || cursor.deadline != request.deadline
            || cursor.sequence_high_water
                < request.expected_consumer_sequence_high_water
        {
            return Err(invalid_recovery(
                "cleanup CAS cursor rolled back or changed role/deadline",
            ));
        }
        match reply {
            CleanupConsumptionCasReply::Applied {
                consumption,
                ..
            }
            | CleanupConsumptionCasReply::AlreadyApplied {
                consumption,
                ..
            } => {
                consumption
                    .validate_cleanup_exact_bytes(
                        request.authorization.payload.endpoint_role,
                        Some(&request.authorization),
                    )
                    .map_err(|_| {
                        invalid_recovery(
                            "cleanup CAS returned invalid persisted consumption",
                        )
                    })?;
                let expected_sequence = request
                    .expected_consumer_sequence_high_water
                    .checked_add(1)
                    .ok_or_else(|| {
                        invalid_recovery(
                            "cleanup consumer sequence overflow",
                        )
                    })?;
                if consumption.statement.consumer_sequence
                        != expected_sequence
                    || consumption
                        .statement
                        .predecessor_receipt_sha256
                        != request
                            .expected_predecessor_receipt_sha256
                    || cursor.sequence_high_water
                        != consumption.statement.consumer_sequence
                    || cursor.predecessor_receipt_sha256
                        != consumption
                            .signed_envelope
                            .envelope_sha256
                {
                    return Err(invalid_recovery(
                        "cleanup CAS changed sequence or predecessor",
                    ));
                }
            }
            CleanupConsumptionCasReply::Conflict { .. } => {}
        }
        Ok(())
    }

    fn finish(
        pending: PendingClientOperation,
        after_reply: CleanupConsumptionQueryReply,
        after_evidence: UnverifiedSignedEndpointResponse<
            CleanupConsumptionQueryReply,
        >,
    ) -> Result<
        UnverifiedCleanupAuthorizationConsumption,
        RecoveryError,
    > {
        let before_reply = pending.before_reply.ok_or_else(|| {
            invalid_recovery("cleanup trace lost pre-query reply")
        })?;
        let before = pending.before_evidence.ok_or_else(|| {
            invalid_recovery("cleanup trace lost pre-query evidence")
        })?;
        let cas_reply = pending.cas_reply.ok_or_else(|| {
            invalid_recovery("cleanup trace lost CAS reply")
        })?;
        let compare_and_swap =
            pending.cas_evidence.ok_or_else(|| {
                invalid_recovery(
                    "cleanup trace lost CAS endpoint evidence",
                )
            })?;
        let consumption = cas_reply.consumption().cloned().ok_or_else(
            || {
                RecoveryError::Conflict(
                    "cleanup authorization CAS conflicted",
                )
            },
        )?;
        if after_reply.authoritative_cursor
                != *cas_reply.authoritative_cursor()
            || after_reply.authoritative_consumption
                != Some(consumption.clone())
            || before_reply.authoritative_cursor.cursor.deadline
                != pending.deadline
        {
            return Err(invalid_recovery(
                "post-CAS query did not resolve to the exact durable consumption and cursor",
            ));
        }
        let exact_signature_payload = consumption
            .signed_envelope
            .canonical_signature_payload()
            .map_err(|_| {
                invalid_recovery(
                    "cleanup consumption signature payload is invalid",
                )
            })?
            .into_boxed_slice();
        Ok(UnverifiedCleanupAuthorizationConsumption {
            before,
            compare_and_swap,
            after: after_evidence,
            persisted: consumption,
            exact_signature_payload,
        })
    }
}

impl CleanupAuthorizationConsumer
    for TrustedHostNoTeeCleanupAuthorizationConsumerClient
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.as_fd()
    }

    fn try_consume_exact_v3_nonblocking(
        &mut self,
        authorization: &SignedCleanupAuthorizationV3,
        trace_requests: &CleanupTraceRequestBindings,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<UnverifiedCleanupAuthorizationConsumption>,
        RecoveryError,
    > {
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "cleanup consumption deadline is not live",
            )
        })?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        self.validate_trace(
            authorization,
            trace_requests,
            &protocol_deadline,
        )?;
        let fingerprint = Self::operation_fingerprint(
            authorization,
            trace_requests,
            &protocol_deadline,
        )?;

        if self.pending.is_none() {
            let before_request = Self::query_request(
                authorization,
                trace_requests
                    .before_query_nonce_sha256
                    .clone(),
                protocol_deadline.clone(),
            );
            self.begin_request(
                &before_request,
                &trace_requests.before_query_request_sha256,
            )?;
            self.pending = Some(PendingClientOperation {
                fingerprint: fingerprint.clone(),
                authorization: authorization.clone(),
                trace: trace_requests.clone(),
                deadline: protocol_deadline.clone(),
                step: ClientStep::BeforeQuery,
                active_request: before_request,
                before_reply: None,
                before_evidence: None,
                cas_reply: None,
                cas_evidence: None,
            });
        }

        if self.pending.as_ref().is_some_and(|pending| {
            pending.fingerprint != fingerprint
        }) {
            return Err(RecoveryError::Conflict(
                "cleanup consumer already has a different operation in flight",
            ));
        }

        let progress = match self.exchange.try_progress() {
            Ok(progress) => progress,
            Err(_) => {
                return Err(match self.exchange.flight_state() {
                    NonblockingExchangeFlightState::Idle => {
                        invalid_recovery(
                            "cleanup consumer transport failed without a retained exact request",
                        )
                    }
                    NonblockingExchangeFlightState::
                        ExactRequestNotSent =>
                    {
                        RecoveryError::Transient(
                            "cleanup consumer retained the exact unsent request after transport failure",
                        )
                    }
                    NonblockingExchangeFlightState::
                        ExactRequestSentAwaitingReply =>
                    {
                        RecoveryError::Transient(
                            "cleanup consumer retained the exact sent request and will not create replacement bytes before its authoritative reply",
                        )
                    }
                })
            }
        };
        let NonblockingExchangeProgress::Complete(completed) =
            progress
        else {
            return Ok(None);
        };
        let active_request = self
            .pending
            .as_ref()
            .ok_or_else(|| {
                invalid_recovery(
                    "cleanup consumer lost its in-flight operation",
                )
            })?
            .active_request
            .clone();
        let evidence = Self::decode_completed(
            completed,
            &active_request,
            self.endpoint_role,
        )?;
        let step = self
            .pending
            .as_ref()
            .ok_or_else(|| {
                invalid_recovery(
                    "cleanup consumer lost its response phase",
                )
            })?
            .step;

        match step {
            ClientStep::BeforeQuery => {
                let (reply, endpoint_evidence) =
                    evidence.query_evidence().map_err(
                        service_to_recovery,
                    )?;
                Self::validate_before_reply(
                    &reply,
                    command_deadline(&active_request),
                    self.endpoint_role,
                )?;
                {
                    let pending =
                        self.pending.as_mut().ok_or_else(|| {
                            invalid_recovery(
                                "cleanup consumer lost pre-query state",
                            )
                        })?;
                    pending.before_reply = Some(reply);
                    pending.before_evidence =
                        Some(endpoint_evidence);
                }
                let cas_request = Self::cas_request(
                    self.pending.as_ref().ok_or_else(|| {
                        invalid_recovery(
                            "cleanup consumer lost CAS inputs",
                        )
                    })?,
                )?;
                self.begin_request(
                    &cas_request,
                    &trace_requests.cas_request_sha256,
                )?;
                let pending =
                    self.pending.as_mut().ok_or_else(|| {
                        invalid_recovery(
                            "cleanup consumer lost CAS phase",
                        )
                    })?;
                pending.active_request = cas_request;
                pending.step = ClientStep::CompareAndSwap;
                Ok(None)
            }
            ClientStep::CompareAndSwap => {
                let cas_request = match &active_request {
                    CleanupAuthorizationConsumerRequestV3::
                        CompareAndSwap(request) => request,
                    _ => {
                        return Err(invalid_recovery(
                            "cleanup consumer CAS phase has a query request",
                        ))
                    }
                };
                let (reply, endpoint_evidence) =
                    evidence.cas_evidence().map_err(
                        service_to_recovery,
                    )?;
                Self::validate_cas_reply(&reply, cas_request)?;
                {
                    let pending =
                        self.pending.as_mut().ok_or_else(|| {
                            invalid_recovery(
                                "cleanup consumer lost CAS state",
                            )
                        })?;
                    pending.cas_reply = Some(reply);
                    pending.cas_evidence =
                        Some(endpoint_evidence);
                }
                let after_request = Self::query_request(
                    authorization,
                    trace_requests
                        .after_query_nonce_sha256
                        .clone(),
                    protocol_deadline,
                );
                self.begin_request(
                    &after_request,
                    &trace_requests.after_query_request_sha256,
                )?;
                let pending =
                    self.pending.as_mut().ok_or_else(|| {
                        invalid_recovery(
                            "cleanup consumer lost post-query phase",
                        )
                    })?;
                pending.active_request = after_request;
                pending.step = ClientStep::AfterQuery;
                Ok(None)
            }
            ClientStep::AfterQuery => {
                let (reply, endpoint_evidence) =
                    evidence.query_evidence().map_err(
                        service_to_recovery,
                    )?;
                let pending = self.pending.take().ok_or_else(|| {
                    invalid_recovery(
                        "cleanup consumer lost completed operation",
                    )
                })?;
                Self::finish(
                    pending,
                    reply,
                    endpoint_evidence,
                )
                .map(Some)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct TrustedHostNoTeeCleanupConsumerSigningIdentity {
    pub(super) endpoint_process_identity: EndpointProcessIdentity,
    pub(super) endpoint_generation: u64,
    pub(super) current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_root_sha256: Sha256Digest,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
}

impl TrustedHostNoTeeCleanupConsumerSigningIdentity {
    fn validate(
        &self,
        signing_key: &SigningKey,
    ) -> Result<(), ServiceError> {
        self.endpoint_process_identity.validate_shape()?;
        if self.endpoint_generation == 0
            || self.revocation_generation == 0
            || digest_is_zero(
                &self.current_key_authorization_checkpoint_sha256,
            )
            || digest_is_zero(&self.revocation_root_sha256)
            || digest_is_zero(&self.signing_key_id)
            || digest_is_zero(&self.signing_key_spki_sha256)
        {
            return Err(ServiceError::Invalid(
                "cleanup consumer signing identity is incomplete",
            ));
        }
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup consumer signing key has no SPKI encoding",
                )
            })?;
        if Sha256Digest::compute(spki.as_bytes())
            != self.signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup consumer signing credential changed its authorized SPKI",
            ));
        }
        Ok(())
    }

    fn endpoint_role(&self) -> PolicyCustodyEndpointRole {
        self.endpoint_process_identity.endpoint_role
    }
}

pub(super) struct TrustedHostNoTeeCurrentHeadVerifier {
    authority_verifying_key: VerifyingKey,
    authority_key_id: Sha256Digest,
    authority_key_spki_sha256: Sha256Digest,
    minimum_checkpoint_sequence: u64,
    minimum_revocation_generation: u64,
}

impl TrustedHostNoTeeCurrentHeadVerifier {
    pub(super) fn new(
        authority_verifying_key: VerifyingKey,
        authority_key_id: Sha256Digest,
        authority_key_spki_sha256: Sha256Digest,
        minimum_checkpoint_sequence: u64,
        minimum_revocation_generation: u64,
    ) -> Result<Self, ServiceError> {
        if digest_is_zero(&authority_key_id)
            || digest_is_zero(&authority_key_spki_sha256)
            || minimum_checkpoint_sequence == 0
            || minimum_revocation_generation == 0
        {
            return Err(ServiceError::Invalid(
                "current-head verifier rollback floors are incomplete",
            ));
        }
        let spki = authority_verifying_key
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "current-head authority key has no SPKI encoding",
                )
            })?;
        if Sha256Digest::compute(spki.as_bytes())
            != authority_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "current-head authority key does not match its SPKI pin",
            ));
        }
        Ok(Self {
            authority_verifying_key,
            authority_key_id,
            authority_key_spki_sha256,
            minimum_checkpoint_sequence,
            minimum_revocation_generation,
        })
    }

    fn verify(
        &self,
        binding: &super::common::ServiceRequestBindingV3,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        request: &CleanupAuthorizationConsumerRequestV3,
    ) -> Result<(), ServiceError> {
        let now = require_live_protocol_deadline(&binding.deadline)?;
        self.verify_at(binding, identity, request, Some(now))
    }

    fn verify_historical(
        &self,
        binding: &super::common::ServiceRequestBindingV3,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        request: &CleanupAuthorizationConsumerRequestV3,
    ) -> Result<(), ServiceError> {
        self.verify_at(binding, identity, request, None)
    }

    fn verify_at(
        &self,
        binding: &super::common::ServiceRequestBindingV3,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        request: &CleanupAuthorizationConsumerRequestV3,
        now: Option<u64>,
    ) -> Result<(), ServiceError> {
        binding.validate(
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            identity.endpoint_role(),
        )?;
        let signed = &binding.current_head.signed_current_head;
        signed.validate_shape()?;
        let statement = &signed.statement;
        let exact_request_sha256 = exact_command_sha256(request)?;
        if signed.authority_key_id != self.authority_key_id
            || signed.authority_key_spki_sha256
                != self.authority_key_spki_sha256
            || statement.endpoint_role != identity.endpoint_role()
            || statement.request_nonce_sha256
                != *command_nonce(request)
            || statement.request_sha256 != exact_request_sha256
            || binding.request_id_sha256
                != *command_nonce(request)
            || binding.idempotency_sha256
                != exact_request_sha256
            || binding.deadline != *command_deadline(request)
            || statement.deadline != binding.deadline
            || statement.endpoint_generation
                != identity.endpoint_generation
            || statement.checkpoint_sha256
                != identity
                    .current_key_authorization_checkpoint_sha256
            || statement.checkpoint_sequence
                < self.minimum_checkpoint_sequence
            || statement.revocation_generation_high_water
                != identity.revocation_generation
            || statement.revocation_generation_high_water
                < self.minimum_revocation_generation
            || statement.revocation_root_sha256
                != identity.revocation_root_sha256
            || statement.issued_at_boottime_nanos == 0
            || statement.issued_at_boottime_nanos
                >= binding.deadline.absolute_boottime_nanos()
            || now.is_some_and(|now| {
                statement.issued_at_boottime_nanos > now
            })
        {
            return Err(ServiceError::Invalid(
                "cleanup consumer request lacks the exact fresh non-rolled-back current head and revocation checkpoint",
            ));
        }
        let preimage = signed.authority_signature_preimage()?;
        verify_signature_preimage(
            &self.authority_verifying_key,
            &preimage,
            &signed.authority_signature_base64,
        )
    }
}

pub(super) struct TrustedHostNoTeeCleanupAuthorizationVerifier {
    authority_verifying_key: VerifyingKey,
    authority_key_id: Sha256Digest,
    authority_key_spki_sha256: Sha256Digest,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl TrustedHostNoTeeCleanupAuthorizationVerifier {
    pub(super) fn new(
        authority_verifying_key: VerifyingKey,
        authority_key_id: Sha256Digest,
        authority_key_spki_sha256: Sha256Digest,
        current_key_authorization_checkpoint_sha256: Sha256Digest,
        revocation_generation: u64,
        revocation_root_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        if digest_is_zero(&authority_key_id)
            || digest_is_zero(&authority_key_spki_sha256)
            || digest_is_zero(
                &current_key_authorization_checkpoint_sha256,
            )
            || revocation_generation == 0
            || digest_is_zero(&revocation_root_sha256)
        {
            return Err(ServiceError::Invalid(
                "cleanup authorization verifier current-key state is incomplete",
            ));
        }
        let spki = authority_verifying_key
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "cleanup authorization authority key has no SPKI encoding",
                )
            })?;
        if Sha256Digest::compute(spki.as_bytes())
            != authority_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup authorization authority key does not match its SPKI pin",
            ));
        }
        Ok(Self {
            authority_verifying_key,
            authority_key_id,
            authority_key_spki_sha256,
            current_key_authorization_checkpoint_sha256,
            revocation_generation,
            revocation_root_sha256,
        })
    }

    fn verify(
        &self,
        authorization: &SignedCleanupAuthorizationV3,
    ) -> Result<(), ServiceError> {
        require_live_protocol_deadline(
            &authorization
                .payload
                .absolute_boottime_deadline,
        )?;
        self.verify_historical(authorization)
    }

    fn verify_historical(
        &self,
        authorization: &SignedCleanupAuthorizationV3,
    ) -> Result<(), ServiceError> {
        authorization.validate_shape()?;
        if authorization.authority_key_id != self.authority_key_id
            || authorization.authority_key_spki_sha256
                != self.authority_key_spki_sha256
            || authorization
                .current_key_authorization_checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || authorization.revocation_generation
                != self.revocation_generation
            || authorization.revocation_root_sha256
                != self.revocation_root_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup authorization was not signed by the fresh configured current authority and revocation head",
            ));
        }
        let preimage =
            authorization.authority_signature_preimage()?;
        verify_signature_preimage(
            &self.authority_verifying_key,
            &preimage,
            &authorization.authority_signature_base64,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableCleanupConsumerStateV3 {
    api_version: String,
    endpoint_role: PolicyCustodyEndpointRole,
    endpoint_generation: u64,
    sequence_high_water: u64,
    predecessor_receipt_sha256: Sha256Digest,
    authoritative_cursor:
        Option<SignedCleanupConsumptionCursorV3>,
    consumptions: BTreeMap<
        String,
        PersistedCleanupAuthorizationConsumptionV3,
    >,
    state_sha256: Sha256Digest,
}

impl DurableCleanupConsumerStateV3 {
    fn genesis(
        endpoint_role: PolicyCustodyEndpointRole,
        endpoint_generation: u64,
        predecessor_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        let mut state = Self {
            api_version: DURABLE_STATE_VERSION.to_string(),
            endpoint_role,
            endpoint_generation,
            sequence_high_water: 0,
            predecessor_receipt_sha256,
            authoritative_cursor: None,
            consumptions: BTreeMap::new(),
            state_sha256: Sha256Digest::compute(&[]),
        };
        state.state_sha256 = state.computed_state_sha256()?;
        state.validate(endpoint_role, endpoint_generation)?;
        Ok(state)
    }

    fn computed_state_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.endpoint_role,
            self.endpoint_generation,
            self.sequence_high_water,
            &self.predecessor_receipt_sha256,
            &self.authoritative_cursor,
            &self.consumptions,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "cleanup consumer durable state is not canonical",
            )
        })?;
        Ok(hash_domain_frames(
            DURABLE_STATE_DOMAIN,
            &[canonical.as_slice()],
        ))
    }

    fn validate(
        &self,
        endpoint_role: PolicyCustodyEndpointRole,
        endpoint_generation: u64,
    ) -> Result<(), ServiceError> {
        if self.api_version != DURABLE_STATE_VERSION
            || self.endpoint_role != endpoint_role
            || self.endpoint_generation != endpoint_generation
            || endpoint_generation == 0
            || digest_is_zero(&self.predecessor_receipt_sha256)
            || digest_is_zero(&self.state_sha256)
            || self.consumptions.len() > MAX_DURABLE_CONSUMPTIONS
            || self.state_sha256 != self.computed_state_sha256()?
        {
            return Err(ServiceError::Invalid(
                "cleanup consumer durable state is incomplete or rolled back",
            ));
        }
        let mut maximum_sequence = 0_u64;
        for (nonce, consumption) in &self.consumptions {
            consumption.validate_cleanup_exact_bytes(
                endpoint_role,
                None,
            )?;
            if nonce
                != consumption
                    .statement
                    .authorization_nonce_sha256
                    .as_str()
                || consumption.statement.consumer_generation
                    != endpoint_generation
            {
                return Err(ServiceError::Invalid(
                    "cleanup durable nonce index changed its signed consumption",
                ));
            }
            maximum_sequence = maximum_sequence
                .max(consumption.statement.consumer_sequence);
        }
        if maximum_sequence != self.sequence_high_water
            || (self.sequence_high_water == 0
                && self.authoritative_cursor.is_some())
            || (self.sequence_high_water > 0
                && (match self.authoritative_cursor.as_ref() {
                    Some(cursor) => {
                        cursor.validate_shape().is_err()
                            || cursor.cursor.endpoint_role
                                != endpoint_role
                            || cursor.cursor.endpoint_generation
                                != endpoint_generation
                            || cursor.cursor.sequence_high_water
                                != self.sequence_high_water
                            || cursor
                                .cursor
                                .predecessor_receipt_sha256
                                != self.predecessor_receipt_sha256
                    }
                    None => true,
                }
                    || !self.consumptions.values().any(
                        |consumption| {
                            consumption
                                .statement
                                .consumer_sequence
                                == self.sequence_high_water
                                && consumption
                                    .signed_envelope
                                    .envelope_sha256
                                    == self
                                        .predecessor_receipt_sha256
                        },
                    )))
        {
            return Err(ServiceError::Invalid(
                "cleanup durable head does not match its highest signed consumption",
            ));
        }
        Ok(())
    }

    fn candidate_with(
        &self,
        consumption: PersistedCleanupAuthorizationConsumptionV3,
        authoritative_cursor: SignedCleanupConsumptionCursorV3,
    ) -> Result<Self, ServiceError> {
        consumption.validate_cleanup_exact_bytes(
            self.endpoint_role,
            None,
        )?;
        let expected_sequence = self
            .sequence_high_water
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "cleanup consumer sequence exhausted",
            ))?;
        if consumption.statement.consumer_sequence
                != expected_sequence
            || consumption
                .statement
                .predecessor_receipt_sha256
                != self.predecessor_receipt_sha256
            || self
                .consumptions
                .contains_key(
                    consumption
                        .statement
                        .authorization_nonce_sha256
                        .as_str(),
                )
            || self.consumptions.len() >= MAX_DURABLE_CONSUMPTIONS
        {
            return Err(ServiceError::Invalid(
                "cleanup consumption is not the exact next unused nonce transition",
            ));
        }
        let mut next = self.clone();
        next.sequence_high_water = expected_sequence;
        next.predecessor_receipt_sha256 =
            consumption.signed_envelope.envelope_sha256.clone();
        authoritative_cursor.validate_shape()?;
        if authoritative_cursor.cursor.endpoint_role
                != next.endpoint_role
            || authoritative_cursor.cursor.endpoint_generation
                != next.endpoint_generation
            || authoritative_cursor.cursor.sequence_high_water
                != expected_sequence
            || authoritative_cursor
                .cursor
                .predecessor_receipt_sha256
                != next.predecessor_receipt_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup authoritative cursor does not bind the exact next durable state",
            ));
        }
        next.authoritative_cursor = Some(authoritative_cursor);
        next.consumptions.insert(
            consumption
                .statement
                .authorization_nonce_sha256
                .as_str()
                .to_string(),
            consumption,
        );
        next.state_sha256 = next.computed_state_sha256()?;
        next.validate(self.endpoint_role, self.endpoint_generation)?;
        Ok(next)
    }
}

struct DurableCleanupConsumerState {
    _legacy_directory: OwnedFd,
    _legacy_writer_lock: OwnedFd,
    state: DurableCleanupConsumerStateV3,
}

impl DurableCleanupConsumerState {
    fn from_authoritative_journal(
        directory: OwnedFd,
        authoritative: DurableCleanupConsumerStateV3,
        genesis_predecessor_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        require_directory(directory.as_raw_fd())?;
        let writer_lock = openat_owned(
            directory.as_raw_fd(),
            DURABLE_STATE_LOCK,
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
            0o600,
        )?;
        require_regular_file(writer_lock.as_raw_fd())?;
        if unsafe {
            libc::flock(
                writer_lock.as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        authoritative.validate(
            authoritative.endpoint_role,
            authoritative.endpoint_generation,
        )?;
        let legacy: Option<DurableCleanupConsumerStateV3> =
            read_optional_canonical_file(
            directory.as_raw_fd(),
            DURABLE_STATE_FILE,
            MAX_DURABLE_STATE_BYTES,
        )?;
        if let Some(legacy) = legacy {
            legacy.validate(
                authoritative.endpoint_role,
                authoritative.endpoint_generation,
            )?;
            Self::require_legacy_prefix(
                &legacy,
                &authoritative,
                &genesis_predecessor_receipt_sha256,
            )?;
            unlinkat_if_present(
                directory.as_raw_fd(),
                DURABLE_STATE_FILE,
            )?;
            sync_fd(directory.as_raw_fd())?;
        }
        Ok(Self {
            _legacy_directory: directory,
            _legacy_writer_lock: writer_lock,
            state: authoritative,
        })
    }

    fn consumption(
        &self,
        authorization_nonce_sha256: &Sha256Digest,
    ) -> Option<&PersistedCleanupAuthorizationConsumptionV3> {
        self.state
            .consumptions
            .get(authorization_nonce_sha256.as_str())
    }

    fn candidate_with(
        &self,
        consumption: PersistedCleanupAuthorizationConsumptionV3,
        authoritative_cursor: SignedCleanupConsumptionCursorV3,
    ) -> Result<DurableCleanupConsumerStateV3, ServiceError> {
        self.state
            .candidate_with(consumption, authoritative_cursor)
    }

    fn publish_committed(
        &mut self,
        next: DurableCleanupConsumerStateV3,
    ) -> Result<(), ServiceError> {
        let expected_sequence = self
            .state
            .sequence_high_water
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "cleanup consumer sequence exhausted",
            ))?;
        next.validate(
            self.state.endpoint_role,
            self.state.endpoint_generation,
        )?;
        if next.sequence_high_water != expected_sequence
            || !self.state.consumptions.iter().all(
                |(nonce, consumption)| {
                    next.consumptions.get(nonce)
                        == Some(consumption)
                },
            )
        {
            return Err(ServiceError::Invalid(
                "cleanup journal commit did not produce the exact next in-memory state",
            ));
        }
        self.state = next;
        Ok(())
    }

    fn require_legacy_prefix(
        legacy: &DurableCleanupConsumerStateV3,
        authoritative: &DurableCleanupConsumerStateV3,
        genesis_predecessor_receipt_sha256: &Sha256Digest,
    ) -> Result<(), ServiceError> {
        if legacy.sequence_high_water
                > authoritative.sequence_high_water
            || !legacy.consumptions.iter().all(
                |(nonce, consumption)| {
                    authoritative.consumptions.get(nonce)
                        == Some(consumption)
                },
            )
        {
            return Err(ServiceError::Invalid(
                "legacy cleanup state is ahead of or diverges from the authoritative journal",
            ));
        }
        let expected_predecessor = if legacy.sequence_high_water == 0 {
            genesis_predecessor_receipt_sha256.clone()
        } else {
            authoritative
                .consumptions
                .values()
                .find(|consumption| {
                    consumption.statement.consumer_sequence
                        == legacy.sequence_high_water
                })
                .map(|consumption| {
                    consumption
                        .signed_envelope
                        .envelope_sha256
                        .clone()
                })
                .ok_or(ServiceError::Invalid(
                    "legacy cleanup state sequence is absent from the authoritative journal",
                ))?
        };
        if legacy.predecessor_receipt_sha256
                != expected_predecessor
            || (legacy.sequence_high_water
                    == authoritative.sequence_high_water
                && legacy != authoritative)
        {
            return Err(ServiceError::Invalid(
                "legacy cleanup state is not an exact prefix of the authoritative journal state",
            ));
        }
        Ok(())
    }
}

pub(super) struct TrustedHostNoTeeCleanupAuthorizationConsumerServer {
    signing_key: SigningKey,
    identity: TrustedHostNoTeeCleanupConsumerSigningIdentity,
    current_head_verifier: TrustedHostNoTeeCurrentHeadVerifier,
    cleanup_authorization_verifier:
        TrustedHostNoTeeCleanupAuthorizationVerifier,
    state: DurableCleanupConsumerState,
    response_journal: DurableAppendJournal,
    report: TrustedHostNoTeeServiceReportV3,
}
impl super::generation_service::Owner for TrustedHostNoTeeCleanupAuthorizationConsumerServer {
    fn generation_state(&self,_deadline:u64)->Result<Sha256Digest,ServiceError> {
        Ok(Sha256Digest::compute(&super::encode_canonical_frame(&(
            &self.state.state,self.response_journal.current_head_sha256(),&self.report))?))
    }
    fn sign_generation_effect(&self,effect:super::generation_service::Effect)->Result<super::generation_service::Receipt,ServiceError> {
        super::generation_service::sign(effect,&self.signing_key)
    }
    fn sign_generation_observation(&self,payload:super::generation_service::ObservationPayload)->Result<super::generation_service::Observation,ServiceError> {
        super::generation_service::sign_observation(payload,&self.signing_key)
    }
}

impl TrustedHostNoTeeCleanupAuthorizationConsumerServer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        signing_key: SigningKey,
        identity: TrustedHostNoTeeCleanupConsumerSigningIdentity,
        current_head_verifier:
            TrustedHostNoTeeCurrentHeadVerifier,
        cleanup_authorization_verifier:
            TrustedHostNoTeeCleanupAuthorizationVerifier,
        state_directory: OwnedFd,
        response_journal_directory: OwnedFd,
        genesis_predecessor_receipt_sha256: Sha256Digest,
        operation_generation: u64,
        service_restart_epoch: u64,
        service_invocation_id_sha256: Sha256Digest,
        readiness_epoch: u64,
        durability_worker_queue_depth: u16,
        maximum_durability_worker_nanos: u64,
        authority_history_manifest_sha256: Sha256Digest,
        production_dispatch_protocol_set_sha256: Sha256Digest,
        shared_configuration_sha256: Sha256Digest,
        deployment_generation_sha256: Sha256Digest,
        deployment_configuration_sha256: Sha256Digest,
        signing_credential_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        identity.validate(&signing_key)?;
        let mut response_journal =
            DurableAppendJournal::from_directory(
            response_journal_directory,
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            MAX_SERVICE_FRAME_BYTES,
        )?;
        let chain = response_journal.verified_complete_chain(
            MAX_CLEANUP_JOURNAL_RECORDS,
            MAX_CLEANUP_JOURNAL_RECOVERY_BYTES,
        )?;
        let verifying_key = signing_key.verifying_key();
        let authoritative =
            Self::recover_authoritative_state(
                &verifying_key,
                &identity,
                &current_head_verifier,
                &cleanup_authorization_verifier,
                genesis_predecessor_receipt_sha256.clone(),
                &chain,
            )?;
        let state =
            DurableCleanupConsumerState::
                from_authoritative_journal(
                    state_directory,
                    authoritative,
                    genesis_predecessor_receipt_sha256,
                )?;
        let report = TrustedHostNoTeeServiceReportV3::new(
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            operation_generation,
            service_restart_epoch,
            service_invocation_id_sha256,
            readiness_epoch,
            durability_worker_queue_depth,
            maximum_durability_worker_nanos,
            authority_history_manifest_sha256,
            production_dispatch_protocol_set_sha256,
            shared_configuration_sha256,
            deployment_generation_sha256,
            deployment_configuration_sha256,
            identity.endpoint_process_identity.identity_sha256.clone(),
            Some(signing_credential_sha256),
        )?;
        Ok(Self {
            signing_key,
            identity,
            current_head_verifier,
            cleanup_authorization_verifier,
            state,
            response_journal,
            report,
        })
    }

    fn recover_authoritative_state(
        verifying_key: &VerifyingKey,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        current_head_verifier:
            &TrustedHostNoTeeCurrentHeadVerifier,
        authorization_verifier:
            &TrustedHostNoTeeCleanupAuthorizationVerifier,
        genesis_predecessor_receipt_sha256: Sha256Digest,
        chain: &VerifiedJournalChainV3,
    ) -> Result<DurableCleanupConsumerStateV3, ServiceError> {
        let mut state = DurableCleanupConsumerStateV3::genesis(
            identity.endpoint_role(),
            identity.endpoint_generation,
            genesis_predecessor_receipt_sha256,
        )?;
        for record in &chain.records {
            let request_frame: ServiceRequestFrameV3 =
                decode_canonical_frame(
                    &record.exact_request_bytes,
                )?;
            request_frame.validate(
                TrustedHostServiceRoleV3::
                    CleanupAuthorizationConsumer,
                identity.endpoint_role(),
            )?;
            if request_frame.binding.idempotency_sha256
                    != record.idempotency_sha256
            {
                return Err(ServiceError::Invalid(
                    "cleanup journal record changed its exact request idempotency binding",
                ));
            }
            let outer_request: PolicyCustodyServiceRequestV3 =
                request_frame.decode_payload()?;
            let request = match outer_request {
                PolicyCustodyServiceRequestV3::
                    CleanupAuthorizationConsumer(request) => {
                    request
                }
                _ => {
                    return Err(ServiceError::Invalid(
                        "cleanup journal contains another authority's request",
                    ))
                }
            };
            request.validate()?;
            current_head_verifier.verify_historical(
                &request_frame.binding,
                identity,
                &request,
            )?;

            let response_frame: ServiceResponseFrameV3 =
                decode_canonical_frame(
                    &record.exact_response_bytes,
                )?;
            response_frame.validate_for_request(
                &request_frame.binding,
                identity.endpoint_role(),
            )?;
            let evidence:
                CleanupAuthorizationConsumerServiceEvidenceV3 =
                response_frame.decode_payload()?;
            evidence.validate(
                &request,
                &request_frame.binding,
                identity.endpoint_role(),
            )?;
            Self::verify_recovered_service_evidence(
                verifying_key,
                identity,
                &evidence,
            )?;
            let reply = match &evidence
                .signed_service_reply
                .response
            {
                PolicyCustodyServiceReplyV3::
                    CleanupAuthorizationConsumer(reply) => reply,
                _ => {
                    return Err(ServiceError::Invalid(
                        "cleanup journal response changed authority role",
                    ))
                }
            };
            Self::apply_recovered_reply(
                verifying_key,
                identity,
                authorization_verifier,
                &mut state,
                &request,
                reply,
            )?;
        }
        state.validate(
            identity.endpoint_role(),
            identity.endpoint_generation,
        )?;
        Ok(state)
    }

    fn verify_recovered_service_evidence(
        verifying_key: &VerifyingKey,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        evidence: &CleanupAuthorizationConsumerServiceEvidenceV3,
    ) -> Result<(), ServiceError> {
        let service_signature =
            &evidence.signed_service_reply.signature;
        if service_signature.endpoint_process_identity
                != identity.endpoint_process_identity
            || service_signature.endpoint_generation
                != identity.endpoint_generation
            || service_signature
                .current_key_authorization_checkpoint_sha256
                != identity
                    .current_key_authorization_checkpoint_sha256
            || service_signature.revocation_generation
                != identity.revocation_generation
            || service_signature.revocation_root_sha256
                != identity.revocation_root_sha256
            || service_signature.signing_key_id
                != identity.signing_key_id
            || service_signature.signing_key_spki_sha256
                != identity.signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup journal service signature changed the serving identity",
            ));
        }
        let service_payload =
            service_signature.canonical_signature_payload()?;
        let service_preimage =
            domain_separated_signature_preimage(
                SERVICE_RESPONSE_SIGNATURE_DOMAIN,
                &service_payload,
            )?;
        verify_signature_preimage(
            verifying_key,
            &service_preimage,
            &service_signature.signature_base64,
        )?;

        let endpoint = &evidence.endpoint_envelope;
        if endpoint.endpoint_process_identity
                != identity.endpoint_process_identity
            || endpoint.endpoint_generation
                != identity.endpoint_generation
            || endpoint
                .current_key_authorization_checkpoint_sha256
                != identity
                    .current_key_authorization_checkpoint_sha256
            || endpoint.revocation_generation
                != identity.revocation_generation
            || endpoint.revocation_root_sha256
                != identity.revocation_root_sha256
            || endpoint.signing_key_id != identity.signing_key_id
            || endpoint.signing_key_spki_sha256
                != identity.signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup journal endpoint signature changed the serving identity",
            ));
        }
        let endpoint_payload =
            endpoint.canonical_signature_payload()?;
        let endpoint_preimage =
            domain_separated_signature_preimage(
                identity.endpoint_role().response_signature_domain(),
                &endpoint_payload,
            )?;
        verify_signature_preimage(
            verifying_key,
            &endpoint_preimage,
            &endpoint.signature_base64,
        )
    }

    fn verify_recovered_cursor(
        verifying_key: &VerifyingKey,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        cursor: &SignedCleanupConsumptionCursorV3,
    ) -> Result<(), ServiceError> {
        cursor.validate_shape()?;
        if cursor.endpoint_process_identity_sha256
                != identity
                    .endpoint_process_identity
                    .identity_sha256
            || cursor.current_key_authorization_checkpoint_sha256
                != identity
                    .current_key_authorization_checkpoint_sha256
            || cursor.revocation_generation
                != identity.revocation_generation
            || cursor.revocation_root_sha256
                != identity.revocation_root_sha256
            || cursor.signing_key_id != identity.signing_key_id
            || cursor.signing_key_spki_sha256
                != identity.signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup journal cursor changed the serving identity",
            ));
        }
        let payload = cursor.canonical_signature_payload()?;
        let preimage = domain_separated_signature_preimage(
            identity.endpoint_role().receipt_signature_domain(),
            &payload,
        )?;
        verify_signature_preimage(
            verifying_key,
            &preimage,
            &cursor.signature_base64,
        )
    }

    fn verify_recovered_consumption(
        verifying_key: &VerifyingKey,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        consumption:
            &PersistedCleanupAuthorizationConsumptionV3,
        authorization: &SignedCleanupAuthorizationV3,
    ) -> Result<(), ServiceError> {
        consumption.validate_cleanup_exact_bytes(
            identity.endpoint_role(),
            Some(authorization),
        )?;
        let envelope = &consumption.signed_envelope;
        if envelope.endpoint_process_identity_sha256
                != identity
                    .endpoint_process_identity
                    .identity_sha256
            || envelope.endpoint_generation
                != identity.endpoint_generation
            || envelope
                .current_key_authorization_checkpoint_sha256
                != identity
                    .current_key_authorization_checkpoint_sha256
            || envelope.revocation_generation
                != identity.revocation_generation
            || envelope.revocation_root_sha256
                != identity.revocation_root_sha256
            || envelope.signing_key_id != identity.signing_key_id
            || envelope.signing_key_spki_sha256
                != identity.signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "cleanup journal consumption changed the serving identity",
            ));
        }
        let payload = envelope.canonical_signature_payload()?;
        let preimage = domain_separated_signature_preimage(
            identity.endpoint_role().receipt_signature_domain(),
            &payload,
        )?;
        verify_signature_preimage(
            verifying_key,
            &preimage,
            &envelope.signature_base64,
        )
    }

    fn require_cursor_matches_state(
        cursor: &SignedCleanupConsumptionCursorV3,
        state: &DurableCleanupConsumerStateV3,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), ServiceError> {
        if cursor.cursor.endpoint_role != state.endpoint_role
            || cursor.cursor.endpoint_generation
                != state.endpoint_generation
            || cursor.cursor.sequence_high_water
                != state.sequence_high_water
            || cursor.cursor.predecessor_receipt_sha256
                != state.predecessor_receipt_sha256
            || cursor.cursor.deadline != *deadline
        {
            return Err(ServiceError::Invalid(
                "cleanup journal cursor does not match the authoritative replay state",
            ));
        }
        Ok(())
    }

    fn apply_recovered_reply(
        verifying_key: &VerifyingKey,
        identity: &TrustedHostNoTeeCleanupConsumerSigningIdentity,
        authorization_verifier:
            &TrustedHostNoTeeCleanupAuthorizationVerifier,
        state: &mut DurableCleanupConsumerStateV3,
        request: &CleanupAuthorizationConsumerRequestV3,
        reply: &CleanupAuthorizationConsumerReplyV3,
    ) -> Result<(), ServiceError> {
        match (request, reply) {
            (
                CleanupAuthorizationConsumerRequestV3::Query(
                    query,
                ),
                CleanupAuthorizationConsumerReplyV3::Query(
                    reply,
                ),
            ) => {
                Self::verify_recovered_cursor(
                    verifying_key,
                    identity,
                    &reply.authoritative_cursor,
                )?;
                Self::require_cursor_matches_state(
                    &reply.authoritative_cursor,
                    state,
                    &query.deadline,
                )?;
                if reply.authoritative_consumption
                    != state
                        .consumptions
                        .get(
                            query
                                .authorization_nonce_sha256
                                .as_str(),
                        )
                        .cloned()
                {
                    return Err(ServiceError::Invalid(
                        "cleanup journal query response does not match replay state",
                    ));
                }
                Ok(())
            }
            (
                CleanupAuthorizationConsumerRequestV3::
                    CompareAndSwap(request),
                CleanupAuthorizationConsumerReplyV3::
                    CompareAndSwap(reply),
            ) => {
                authorization_verifier.verify_historical(
                    &request.authorization,
                )?;
                let cursor = reply.authoritative_cursor();
                Self::verify_recovered_cursor(
                    verifying_key,
                    identity,
                    cursor,
                )?;
                let nonce = &request
                    .authorization
                    .payload
                    .authorization_nonce_sha256;
                let existing =
                    state.consumptions.get(nonce.as_str()).cloned();
                match reply {
                    CleanupConsumptionCasReply::Applied {
                        consumption,
                        authoritative_cursor,
                    } => {
                        if existing.is_some()
                            || request
                                .expected_consumer_sequence_high_water
                                != state.sequence_high_water
                            || request
                                .expected_predecessor_receipt_sha256
                                != state.predecessor_receipt_sha256
                        {
                            return Err(ServiceError::Invalid(
                                "cleanup journal applied a CAS that was not the exact next transition",
                            ));
                        }
                        Self::verify_recovered_consumption(
                            verifying_key,
                            identity,
                            consumption,
                            &request.authorization,
                        )?;
                        *state = state.candidate_with(
                            consumption.clone(),
                            authoritative_cursor.clone(),
                        )?;
                        Ok(())
                    }
                    CleanupConsumptionCasReply::AlreadyApplied {
                        consumption,
                        authoritative_cursor,
                    } => {
                        if existing.as_ref() != Some(consumption)
                            || consumption
                                .statement
                                .authorization_sha256
                                != request
                                    .authorization
                                    .authorization_sha256
                        {
                            return Err(ServiceError::Invalid(
                                "cleanup journal already-applied reply changed the authoritative consumption",
                            ));
                        }
                        Self::verify_recovered_consumption(
                            verifying_key,
                            identity,
                            consumption,
                            &request.authorization,
                        )?;
                        Self::require_cursor_matches_state(
                            authoritative_cursor,
                            state,
                            &request.deadline,
                        )
                    }
                    CleanupConsumptionCasReply::Conflict {
                        authoritative_consumption,
                        authoritative_cursor,
                    } => {
                        let expected_conflict = match &existing {
                            Some(consumption) => {
                                consumption
                                    .statement
                                    .authorization_sha256
                                    != request
                                        .authorization
                                        .authorization_sha256
                            }
                            None => {
                                request
                                    .expected_consumer_sequence_high_water
                                    != state.sequence_high_water
                                    || request
                                        .expected_predecessor_receipt_sha256
                                        != state
                                            .predecessor_receipt_sha256
                            }
                        };
                        if !expected_conflict
                            || authoritative_consumption
                                != &existing
                        {
                            return Err(ServiceError::Invalid(
                                "cleanup journal conflict reply is inconsistent with replay state",
                            ));
                        }
                        Self::require_cursor_matches_state(
                            authoritative_cursor,
                            state,
                            &request.deadline,
                        )
                    }
                }
            }
            _ => Err(ServiceError::Invalid(
                "cleanup journal request and reply operations differ",
            )),
        }
    }

    pub(super) fn security_report(
        &self,
    ) -> &TrustedHostNoTeeServiceReportV3 {
        &self.report
    }

    /// Handle one exact canonical request frame received from the shared
    /// authenticated local seqpacket dispatcher. No descriptor is permitted.
    pub(super) fn handle_exact_request_frame(
        &mut self,
        exact_request_frame: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let frame: ServiceRequestFrameV3 =
            decode_canonical_frame(exact_request_frame)?;
        frame.validate(
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            self.identity.endpoint_role(),
        )?;
        let outer: PolicyCustodyServiceRequestV3 =
            frame.decode_payload()?;
        let request = match outer {
            PolicyCustodyServiceRequestV3::
                CleanupAuthorizationConsumer(request) => request,
            _ => {
                return Err(ServiceError::Invalid(
                    "cleanup consumer received another authority's request",
                ))
            }
        };
        request.validate()?;
        self.current_head_verifier.verify(
            &frame.binding,
            &self.identity,
            &request,
        )?;

        if let Some(persisted) = self
            .response_journal
            .repair_and_lookup_persisted_exact_response(
                &frame.binding.idempotency_sha256,
            )?
        {
            let response: ServiceResponseFrameV3 =
                decode_canonical_frame(&persisted)?;
            response.validate_for_request(
                &frame.binding,
                self.identity.endpoint_role(),
            )?;
            let replay = self.response_journal.append_exact_exchange(
                frame.binding.idempotency_sha256.clone(),
                exact_request_frame,
                &persisted,
            )?;
            return Ok(replay.exact_response_bytes().to_vec());
        }

        let (reply, next_state) =
            self.prepare_request(&request)?;
        let evidence =
            self.sign_service_evidence(&frame, &request, reply)?;
        let response = ServiceResponseFrameV3::from_payload(
            frame.binding.clone(),
            &evidence,
        )?;
        let exact_response = encode_canonical_frame(&response)?;
        let persisted = self.response_journal.append_exact_exchange(
            frame.binding.idempotency_sha256,
            exact_request_frame,
            &exact_response,
        )?;
        if let Some(next_state) = next_state {
            self.state.publish_committed(next_state)?;
        }
        Ok(persisted.exact_response_bytes().to_vec())
    }

    fn prepare_request(
        &self,
        request: &CleanupAuthorizationConsumerRequestV3,
    ) -> Result<
        (
            CleanupAuthorizationConsumerReplyV3,
            Option<DurableCleanupConsumerStateV3>,
        ),
        ServiceError,
    > {
        match request {
            CleanupAuthorizationConsumerRequestV3::Query(query) => {
                let cursor =
                    self.sign_cursor(&query.deadline)?;
                let consumption = self
                    .state
                    .consumption(
                        &query.authorization_nonce_sha256,
                    )
                    .cloned();
                Ok((
                    CleanupAuthorizationConsumerReplyV3::Query(
                        CleanupConsumptionQueryReply {
                            authoritative_consumption: consumption,
                            authoritative_cursor: cursor,
                        },
                    ),
                    None,
                ))
            }
            CleanupAuthorizationConsumerRequestV3::
                CompareAndSwap(cas) => {
                let (reply, next_state) =
                    self.prepare_compare_and_swap(cas)?;
                Ok((
                    CleanupAuthorizationConsumerReplyV3::
                        CompareAndSwap(reply),
                    next_state,
                ))
            }
        }
    }

    fn prepare_compare_and_swap(
        &self,
        request: &CleanupConsumptionCompareAndSwap,
    ) -> Result<
        (
            CleanupConsumptionCasReply,
            Option<DurableCleanupConsumerStateV3>,
        ),
        ServiceError,
    > {
        request.validate_shape()?;
        let authorization = &request.authorization;
        self.cleanup_authorization_verifier
            .verify(authorization)?;
        let nonce =
            &authorization.payload.authorization_nonce_sha256;
        if authorization.payload.endpoint_role
                != self.identity.endpoint_role()
            || request.deadline
                != authorization
                    .payload
                    .absolute_boottime_deadline
        {
            return Err(ServiceError::Invalid(
                "cleanup CAS changed authorization role or deadline",
            ));
        }

        if let Some(existing) =
            self.state.consumption(nonce).cloned()
        {
            let cursor = self.sign_cursor(&request.deadline)?;
            if existing.statement.authorization_sha256
                == authorization.authorization_sha256
            {
                return Ok((
                    CleanupConsumptionCasReply::AlreadyApplied {
                        consumption: existing,
                        authoritative_cursor: cursor,
                    },
                    None,
                ));
            }
            return Ok((
                CleanupConsumptionCasReply::Conflict {
                    authoritative_consumption: Some(existing),
                    authoritative_cursor: cursor,
                },
                None,
            ));
        }

        if request.expected_consumer_sequence_high_water
                != self.state.state.sequence_high_water
            || request.expected_predecessor_receipt_sha256
                != self.state.state.predecessor_receipt_sha256
        {
            return Ok((
                CleanupConsumptionCasReply::Conflict {
                    authoritative_consumption: None,
                    authoritative_cursor:
                        self.sign_cursor(&request.deadline)?,
                },
                None,
            ));
        }

        let consumed_at = require_live_protocol_deadline(
            &request.deadline,
        )?;
        if consumed_at
            < authorization
                .payload
                .operation_deadline
                .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "cleanup authorization cannot be consumed before the operation deadline",
            ));
        }
        let sequence = self
            .state
            .state
            .sequence_high_water
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "cleanup consumer sequence exhausted",
            ))?;
        let payload = &authorization.payload;
        let statement = CleanupAuthorizationConsumptionStatement {
            api_version:
                POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
                    .to_string(),
            authorization_sha256:
                authorization.authorization_sha256.clone(),
            authorization_nonce_sha256:
                payload.authorization_nonce_sha256.clone(),
            action: payload.action,
            executor_role: payload.executor_role,
            endpoint_role: payload.endpoint_role,
            operation: payload.operation,
            operation_id_sha256:
                payload.operation_id_sha256.clone(),
            durable_request_sha256:
                payload.durable_request_sha256.clone(),
            request_sha256: payload.request_sha256.clone(),
            fence_token_sha256:
                payload.fence_token_sha256.clone(),
            cgroup_identity: payload.cgroup_identity.clone(),
            predecessor: payload.predecessor.clone(),
            operation_deadline:
                payload.operation_deadline.clone(),
            absolute_boottime_deadline:
                payload.absolute_boottime_deadline.clone(),
            predecessor_receipt_sha256: self
                .state
                .state
                .predecessor_receipt_sha256
                .clone(),
            consumed_at_boottime_nanos: consumed_at,
            occurred_before_cleanup_deadline: true,
            consumer_generation: self.identity.endpoint_generation,
            consumer_sequence: sequence,
        };
        statement.validate_against(authorization)?;
        let consumption = self.sign_consumption(statement)?;
        let next_predecessor =
            consumption.signed_envelope.envelope_sha256.clone();
        let authoritative_cursor = self.sign_cursor_values(
            &request.deadline,
            sequence,
            next_predecessor.clone(),
        )?;
        let next_state = self.state.candidate_with(
            consumption.clone(),
            authoritative_cursor.clone(),
        )?;
        if next_state.sequence_high_water != sequence
            || next_state.predecessor_receipt_sha256
                != next_predecessor
        {
            return Err(ServiceError::Invalid(
                "cleanup CAS did not derive the exact signed state successor",
            ));
        }
        Ok((
            CleanupConsumptionCasReply::Applied {
                consumption,
                authoritative_cursor,
            },
            Some(next_state),
        ))
    }

    fn sign_consumption(
        &self,
        statement: CleanupAuthorizationConsumptionStatement,
    ) -> Result<
        PersistedCleanupAuthorizationConsumptionV3,
        ServiceError,
    > {
        let canonical_statement = encode_canonical_frame(&statement)?;
        let mut envelope = SignedDurableConsumeReceiptEnvelope {
            api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_string(),
            endpoint_role: self.identity.endpoint_role(),
            endpoint_process_identity_sha256: self
                .identity
                .endpoint_process_identity
                .identity_sha256
                .clone(),
            endpoint_generation: self.identity.endpoint_generation,
            current_key_authorization_checkpoint_sha256: self
                .identity
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation:
                self.identity.revocation_generation,
            revocation_root_sha256:
                self.identity.revocation_root_sha256.clone(),
            canonical_statement_base64:
                URL_SAFE_NO_PAD.encode(&canonical_statement),
            statement_sha256:
                endpoint_receipt_statement_sha256(
                    &canonical_statement,
                ),
            signing_key_id:
                self.identity.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.identity.signing_key_spki_sha256.clone(),
            signature_base64: String::new(),
            envelope_sha256: Sha256Digest::compute(&[]),
        };
        let payload = envelope.canonical_signature_payload()?;
        envelope.signature_base64 = self.sign_domain(
            self.identity.endpoint_role().receipt_signature_domain(),
            &payload,
        )?;
        envelope.envelope_sha256 =
            envelope.expected_envelope_sha256()?;
        PersistedCleanupAuthorizationConsumptionV3::from_signed(
            statement,
            envelope,
            self.identity.endpoint_role(),
            self.identity.endpoint_generation,
        )
        .map_err(protocol_to_service)
    }

    fn sign_cursor(
        &self,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<SignedCleanupConsumptionCursorV3, ServiceError> {
        if let Some(cursor) = &self.state.state.authoritative_cursor {
            if cursor.cursor.deadline == *deadline {
                cursor.validate_shape()?;
                return Ok(cursor.clone());
            }
        }
        self.sign_cursor_values(
            deadline,
            self.state.state.sequence_high_water,
            self.state
                .state
                .predecessor_receipt_sha256
                .clone(),
        )
    }

    fn sign_cursor_values(
        &self,
        deadline: &ProtocolBoottimeDeadline,
        sequence_high_water: u64,
        predecessor_receipt_sha256: Sha256Digest,
    ) -> Result<SignedCleanupConsumptionCursorV3, ServiceError> {
        let observed = require_live_protocol_deadline(deadline)?;
        let mut signed = SignedCleanupConsumptionCursorV3 {
            cursor: CleanupConsumptionCursorV3 {
                api_version:
                    POLICY_CUSTODY_CLEANUP_AUTHORIZATION_VERSION
                        .to_string(),
                endpoint_role: self.identity.endpoint_role(),
                endpoint_generation:
                    self.identity.endpoint_generation,
                sequence_high_water,
                predecessor_receipt_sha256,
                observed_at_boottime_nanos: observed,
                deadline: deadline.clone(),
            },
            endpoint_process_identity_sha256: self
                .identity
                .endpoint_process_identity
                .identity_sha256
                .clone(),
            current_key_authorization_checkpoint_sha256: self
                .identity
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation:
                self.identity.revocation_generation,
            revocation_root_sha256:
                self.identity.revocation_root_sha256.clone(),
            signing_key_id:
                self.identity.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.identity.signing_key_spki_sha256.clone(),
            signature_base64: String::new(),
            cursor_receipt_sha256: Sha256Digest::compute(&[]),
        };
        let payload = signed.canonical_signature_payload()?;
        signed.signature_base64 = self.sign_domain(
            self.identity.endpoint_role().receipt_signature_domain(),
            &payload,
        )?;
        signed.cursor_receipt_sha256 =
            signed.expected_cursor_receipt_sha256()?;
        signed.validate_shape()?;
        Ok(signed)
    }

    fn sign_service_evidence(
        &self,
        request_frame: &ServiceRequestFrameV3,
        request: &CleanupAuthorizationConsumerRequestV3,
        reply: CleanupAuthorizationConsumerReplyV3,
    ) -> Result<
        CleanupAuthorizationConsumerServiceEvidenceV3,
        ServiceError,
    > {
        let inner_response_bytes = match &reply {
            CleanupAuthorizationConsumerReplyV3::Query(reply) => {
                encode_canonical_frame(reply)?
            }
            CleanupAuthorizationConsumerReplyV3::CompareAndSwap(
                reply,
            ) => encode_canonical_frame(reply)?,
        };
        let endpoint_envelope = self.sign_endpoint_envelope(
            request,
            &inner_response_bytes,
        )?;
        let endpoint_signature_payload =
            endpoint_envelope.canonical_signature_payload()?;
        let outer_reply =
            PolicyCustodyServiceReplyV3::
                CleanupAuthorizationConsumer(reply);
        outer_reply.validate()?;
        let exact_outer_reply = encode_canonical_frame(&outer_reply)?;
        let signed_service_reply = self.sign_outer_reply(
            &request_frame.binding,
            outer_reply,
            &exact_outer_reply,
        )?;
        Ok(CleanupAuthorizationConsumerServiceEvidenceV3 {
            signed_service_reply,
            endpoint_envelope,
            exact_endpoint_response_bytes: inner_response_bytes,
            exact_endpoint_signature_payload_bytes:
                endpoint_signature_payload,
        })
    }

    fn sign_endpoint_envelope(
        &self,
        request: &CleanupAuthorizationConsumerRequestV3,
        exact_response: &[u8],
    ) -> Result<SignedEndpointResponseEnvelope, ServiceError> {
        let observed =
            require_live_protocol_deadline(command_deadline(request))?;
        let mut envelope = SignedEndpointResponseEnvelope {
            api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_string(),
            endpoint_role: self.identity.endpoint_role(),
            endpoint_process_identity:
                self.identity.endpoint_process_identity.clone(),
            endpoint_process_identity_sha256: self
                .identity
                .endpoint_process_identity
                .identity_sha256
                .clone(),
            endpoint_generation: self.identity.endpoint_generation,
            current_key_authorization_checkpoint_sha256: self
                .identity
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation:
                self.identity.revocation_generation,
            revocation_root_sha256:
                self.identity.revocation_root_sha256.clone(),
            request_nonce_sha256: command_nonce(request).clone(),
            request_sha256: exact_command_sha256(request)?,
            canonical_response_base64:
                URL_SAFE_NO_PAD.encode(exact_response),
            response_sha256:
                endpoint_response_sha256(exact_response),
            observed_at_boottime_nanos: observed,
            signing_key_id:
                self.identity.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.identity.signing_key_spki_sha256.clone(),
            signature_base64: String::new(),
            envelope_sha256: Sha256Digest::compute(&[]),
        };
        let payload = envelope.canonical_signature_payload()?;
        envelope.signature_base64 = self.sign_domain(
            self.identity.endpoint_role().response_signature_domain(),
            &payload,
        )?;
        envelope.envelope_sha256 =
            envelope.expected_envelope_sha256()?;
        envelope.validate_shape()?;
        Ok(envelope)
    }

    fn sign_outer_reply(
        &self,
        request_binding: &super::common::ServiceRequestBindingV3,
        response: PolicyCustodyServiceReplyV3,
        exact_response: &[u8],
    ) -> Result<SignedPolicyCustodyServiceReplyV3, ServiceError> {
        let observed =
            require_live_protocol_deadline(&request_binding.deadline)?;
        let response_sha256 =
            endpoint_response_sha256(exact_response);
        let signature_payload = canonical_json_bytes(&(
            POLICY_CUSTODY_SERVICES_WIRE_VERSION,
            PolicyCustodyServiceRoleV3::
                CleanupAuthorizationConsumer,
            &request_binding.request_id_sha256,
            &response_sha256,
            &self.identity.endpoint_process_identity,
            self.identity.endpoint_generation,
            &self
                .identity
                .current_key_authorization_checkpoint_sha256,
            self.identity.revocation_generation,
            &self.identity.revocation_root_sha256,
            observed,
            &self.identity.signing_key_id,
            &self.identity.signing_key_spki_sha256,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service response signature payload is not canonical",
            )
        })?;
        let signature_base64 = self.sign_domain(
            SERVICE_RESPONSE_SIGNATURE_DOMAIN,
            &signature_payload,
        )?;
        let receipt_sha256 = hash_domain_frames(
            SERVICE_RESPONSE_SIGNATURE_DOMAIN,
            &[
                signature_payload.as_slice(),
                signature_base64.as_bytes(),
            ],
        );
        let signature = ServiceResponseSignatureV3 {
            api_version:
                POLICY_CUSTODY_SERVICES_WIRE_VERSION.to_string(),
            service_role:
                PolicyCustodyServiceRoleV3::
                    CleanupAuthorizationConsumer,
            request_id_sha256:
                request_binding.request_id_sha256.clone(),
            response_sha256,
            endpoint_process_identity:
                self.identity.endpoint_process_identity.clone(),
            endpoint_generation: self.identity.endpoint_generation,
            current_key_authorization_checkpoint_sha256: self
                .identity
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation:
                self.identity.revocation_generation,
            revocation_root_sha256:
                self.identity.revocation_root_sha256.clone(),
            observed_at_boottime_nanos: observed,
            signing_key_id:
                self.identity.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.identity.signing_key_spki_sha256.clone(),
            signature_base64,
            receipt_sha256,
        };
        let exact_signature = encode_canonical_frame(&signature)?;
        let signed = SignedServiceResponseV3 {
            response,
            exact_canonical_response_bytes:
                exact_response.to_vec(),
            signature,
            exact_signature_envelope_bytes: exact_signature,
        };
        signed.validate(
            PolicyCustodyServiceRoleV3::
                CleanupAuthorizationConsumer,
            &request_binding.request_id_sha256,
            &request_binding.deadline,
        )?;
        Ok(signed)
    }

    fn sign_domain(
        &self,
        domain: &[u8],
        canonical_payload: &[u8],
    ) -> Result<String, ServiceError> {
        let preimage = domain_separated_signature_preimage(
            domain,
            canonical_payload,
        )?;
        Ok(URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        ))
    }
}

fn verify_signature_preimage(
    key: &VerifyingKey,
    preimage: &[u8],
    signature_base64: &str,
) -> Result<(), ServiceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| {
            ServiceError::Invalid(
                "current-head signature is not canonical base64url",
            )
        })?;
    let signature = Signature::from_slice(&bytes).map_err(|_| {
        ServiceError::Invalid(
            "current-head signature has the wrong length",
        )
    })?;
    key.verify_strict(preimage, &signature).map_err(|_| {
        ServiceError::Invalid(
            "current-head authority signature verification failed",
        )
    })
}

fn duplicate_cloexec(fd: RawFd) -> Result<OwnedFd, ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "cleanup consumer progress descriptor is invalid",
        ));
    }
    let duplicate =
        unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn require_directory(fd: RawFd) -> Result<(), ServiceError> {
    let mut metadata: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_nlink == 0
    {
        return Err(ServiceError::Invalid(
            "cleanup consumer state descriptor is not a linked directory",
        ));
    }
    Ok(())
}

fn require_regular_file(fd: RawFd) -> Result<(), ServiceError> {
    let mut metadata: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
    {
        return Err(ServiceError::Invalid(
            "cleanup consumer state entry is not a singly linked regular file",
        ));
    }
    Ok(())
}

fn safe_name(name: &str) -> Result<CString, ServiceError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        return Err(ServiceError::Invalid(
            "cleanup consumer state filename is unsafe",
        ));
    }
    CString::new(name).map_err(|_| {
        ServiceError::Invalid(
            "cleanup consumer state filename contains NUL",
        )
    })
}

fn openat_owned(
    directory_fd: RawFd,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<OwnedFd, ServiceError> {
    let name = safe_name(name)?;
    let raw = unsafe {
        libc::openat(directory_fd, name.as_ptr(), flags, mode)
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ServiceError> {
    let bytes = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid(
            "cleanup consumer durable value is not canonical",
        )
    })?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ServiceError::Invalid(
            "cleanup consumer durable value exceeds its fixed bound",
        ));
    }
    Ok(bytes)
}

fn decode_bounded<T>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ServiceError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ServiceError::Invalid(
            "cleanup consumer durable value exceeds its fixed bound",
        ));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| {
        ServiceError::Invalid(
            "cleanup consumer durable value is not typed JSON",
        )
    })?;
    if encode_bounded(&value, maximum)? != bytes {
        return Err(ServiceError::Invalid(
            "cleanup consumer durable value is not exact canonical JSON",
        ));
    }
    Ok(value)
}

fn read_optional_canonical_file<T>(
    directory_fd: RawFd,
    name: &str,
    maximum: usize,
) -> Result<Option<T>, ServiceError>
where
    T: DeserializeOwned + Serialize,
{
    let descriptor = match openat_owned(
        directory_fd,
        name,
        libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK,
        0,
    ) {
        Ok(descriptor) => descriptor,
        Err(ServiceError::Io(error))
            if error.raw_os_error() == Some(libc::ENOENT) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    require_regular_file(descriptor.as_raw_fd())?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(
            u64::try_from(maximum)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    decode_bounded(&bytes, maximum).map(Some)
}

fn unlinkat_if_present(
    directory_fd: RawFd,
    name: &str,
) -> Result<(), ServiceError> {
    let name = safe_name(name)?;
    if unsafe {
        libc::unlinkat(directory_fd, name.as_ptr(), 0)
    } == 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(());
    }
    Err(error.into())
}

fn sync_fd(fd: RawFd) -> Result<(), ServiceError> {
    loop {
        if unsafe { libc::fsync(fd) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}
