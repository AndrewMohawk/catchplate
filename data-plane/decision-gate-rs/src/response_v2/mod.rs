//! Main-side response-observation v2 integration.
//!
//! Privileged custody implementation modules live under `response_v2/custody`;
//! this module contains only the decision-gate client and release path.

mod attestation;
mod client_transport;
mod envelope_authentication;
mod envelope_semantics;
mod http11;
mod integration;
mod native_config;
mod release;
mod transparency_contract;
mod transaction;

pub(super) use attestation::*;
use client_transport::*;
pub(super) use envelope_authentication::*;
pub(super) use envelope_semantics::*;
pub(super) use http11::*;
pub(super) use release::*;
pub(super) use transparency_contract::*;
use transaction::*;

use crate::*;
use serverware_decision_gate::{
    V2CanonicalFinalEnvelopeV1, V2PinnedRoleKeyV1,
    V2_ATTEST_OPERATION, V2_AUTHORITY_OPERATION,
    V2_CANONICAL_FINAL_ENVELOPE_VERSION,
    V2_DISPATCH_OPERATION, V2_FINALIZE_OPERATION,
    V2_DURABLE_REPLAY_RECORD_SIGNATURE_DOMAIN,
    V2_OUTCOME_UNKNOWN_SIGNATURE_DOMAIN,
    V2_PUBLISH_OPERATION, V2_RECOVER_OPERATION,
    V2_PUBLIC_RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
    V2_RECOVERY_OUTCOME_SIGNATURE_DOMAIN,
    V2_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
    V2_RESERVE_OPERATION, V2_RETRIEVE_OPERATION,
    V2_STAGE_OPERATION, V2_TERMINAL_OPERATION,
    V2_VERIFY_ARCHIVE_OPERATION,
};

/// Main-visible wrapper; the closed JSON schema and conversion live in the
/// private native_config child, without widening its internal DTO visibility.
#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct NativeResponseObservationV2ConfigV1(
    native_config::NativeResponseObservationV2ConfigV1,
);

impl NativeResponseObservationV2ConfigV1 {
    pub(super) fn into_config(self) -> Result<ResponseObservationV2ClientConfig, String> {
        self.0.into_config()
    }
}

pub(super) fn initialize_response_observation_v2_client(
    is_production: bool,
) -> Result<Option<ResponseObservationV2Client>, String> {
    client_transport::initialize_response_observation_v2_client(
        is_production,
    )
}

pub(super) fn validate_response_observation_v2_client_config(
    config: &ResponseObservationV2ClientConfig,
) -> Result<(), String> {
    client_transport::validate_response_observation_v2_client_config(config)
}

pub(super) fn validate_response_observation_v2_client_config_for_native_serving(
    config: &ResponseObservationV2ClientConfig,
) -> Result<(), String> {
    client_transport::validate_response_observation_v2_client_config_for_native_serving(config)
}

pub(super) fn initialize_response_observation_v2_client_from_config(
    config: ResponseObservationV2ClientConfig,
    absolute_deadline: u64,
) -> Result<ResponseObservationV2Client, String> {
    client_transport::initialize_response_observation_v2_client_from_config(
        config,
        absolute_deadline,
    )
}

pub(super) fn start_response_observation_v2_health_probe(
    client: Option<ResponseObservationV2Client>,
) {
    integration::start_response_observation_v2_health_probe(client);
}

pub(super) fn probe_response_observation_v2_once(
    client: &ResponseObservationV2Client,
    max_duration: Duration,
) -> bool {
    integration::probe_response_observation_v2_once(client, max_duration)
}

pub(super) fn execute_response_observation_v2_transaction(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    decision: &Value,
    request: &IncomingRequest,
    upstream_url: &Url,
    provider_headers: &HeaderMap,
    injection_plan: &Value,
    release_authorization: &mut Option<ReleaseAuthorizationGuard<'_>>,
    execution: &ResponseObservationV2Execution<'_>,
    shadow_finalization: Option<&policy_core::ShadowRequestHandle>,
    shadow_dispatch_barrier_crossed: &mut bool,
) -> Result<
    SensitiveResponseBytes,
    ResponseObservationV2TransactionError,
> {
    let mut canonical_provider_headers = BTreeMap::new();
    for (name, value) in provider_headers {
        let value = value.to_str().map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
        if canonical_provider_headers
            .insert(name.as_str().to_owned(), value.to_owned())
            .is_some()
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
    }
    transaction::execute_response_observation_v2_transaction(
        state,
        snapshot,
        decision,
        request,
        upstream_url,
        &canonical_provider_headers,
        injection_plan,
        release_authorization,
        execution,
        shadow_finalization,
        shadow_dispatch_barrier_crossed,
    )
}

#[derive(Clone, Copy)]
pub(super) struct ResponseObservationV2Deadline {
    absolute_boottime_ns: u64,
}

impl ResponseObservationV2Deadline {
    pub(super) fn after(duration: Duration) -> Result<Self, String> {
        let now = Self::now_boottime_ns()?;
        let duration_ns = u64::try_from(duration.as_nanos())
            .map_err(|_| {
                "response-observation v2 deadline duration overflows"
                    .to_string()
            })?;
        Ok(Self {
            absolute_boottime_ns: now.checked_add(duration_ns).ok_or(
                "response-observation v2 deadline overflows",
            )?,
        })
    }

    pub(super) fn from_absolute(
        absolute_boottime_ns: u64,
    ) -> Self {
        Self {
            absolute_boottime_ns,
        }
    }

    pub(super) fn remaining(self) -> Result<Duration, String> {
        let now = Self::now_boottime_ns()?;
        Ok(Duration::from_nanos(
            self.absolute_boottime_ns.saturating_sub(now),
        ))
    }

    pub(super) fn expired(self) -> bool {
        self.remaining()
            .map_or(true, |remaining| remaining.is_zero())
    }

    pub(super) fn short_poll_timeout_ms(self) -> libc::c_int {
        self.remaining()
            .ok()
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| {
                remaining
                    .as_millis()
                    .min(100)
                    .max(1)
                    .min(libc::c_int::MAX as u128)
                    as libc::c_int
            })
            .unwrap_or(0)
    }

    fn now_boottime_ns() -> Result<u64, String> {
        #[cfg(target_os = "linux")]
        {
            let mut observed: libc::timespec =
                unsafe { std::mem::zeroed() };
            if unsafe {
                libc::clock_gettime(
                    libc::CLOCK_BOOTTIME,
                    &mut observed,
                )
            } != 0
                || observed.tv_sec < 0
                || observed.tv_nsec < 0
                || observed.tv_nsec >= 1_000_000_000
            {
                return Err(
                    "read CLOCK_BOOTTIME for response-observation v2 deadline"
                        .to_string(),
                );
            }
            u64::try_from(observed.tv_sec)
                .ok()
                .and_then(|seconds| {
                    seconds.checked_mul(1_000_000_000)
                })
                .and_then(|base| {
                    base.checked_add(observed.tv_nsec as u64)
                })
                .ok_or_else(|| {
                    "response-observation v2 CLOCK_BOOTTIME overflows"
                        .to_string()
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(
                "response-observation v2 requires CLOCK_BOOTTIME"
                    .to_string(),
            )
        }
    }
}

pub(super) struct ResponseObservationV2Execution<'a> {
    pub(super) context: &'a ResponseObservationContext,
    pub(super) route: ResponseObservationRouteConfig,
    pub(super) connection_identity_sha256: String,
}

pub(super) struct ResponseObservationV2AttemptCursor {
    pub(super) attempt: AttemptStateReference,
    pub(super) transaction: V2TransactionBindingV1,
    pub(super) monotonic_deadline: V2MonotonicDeadlineV1,
    pub(super) deadline_at_epoch_ms: u64,
}

impl ResponseObservationV2AttemptCursor {
    pub(super) fn operation_binding(
        &self,
        request_id: &str,
        boot_id: &str,
        client_identity_sha256: &str,
    ) -> V2OperationBinding {
        V2OperationBinding {
            request_id: request_id.to_owned(),
            custody_boot_id: boot_id.to_owned(),
            client_identity_sha256: client_identity_sha256.to_owned(),
            transaction: self.transaction.clone(),
            attempt_id: self.attempt.attempt_id.clone(),
            predecessor_lifecycle_state: self.attempt.state,
            predecessor_state_sha256: self.attempt.state_sha256.clone(),
            attempt_revision: self.attempt.attempt_revision,
            fencing_token: self.attempt.fencing_token,
            monotonic_deadline: self.monotonic_deadline.clone(),
            deadline_at_epoch_ms: self.deadline_at_epoch_ms,
        }
    }

    pub(super) fn read_binding(
        &self,
        request_id: &str,
        boot_id: &str,
        client_identity_sha256: &str,
    ) -> V2ReadBinding {
        V2ReadBinding {
            request_id: request_id.to_owned(),
            custody_boot_id: boot_id.to_owned(),
            client_identity_sha256: client_identity_sha256.to_owned(),
            transaction: self.transaction.clone(),
            attempt_id: self.attempt.attempt_id.clone(),
            lifecycle_state: self.attempt.state,
            state_sha256: self.attempt.state_sha256.clone(),
            attempt_revision: self.attempt.attempt_revision,
            fencing_token: self.attempt.fencing_token,
            monotonic_deadline: self.monotonic_deadline.clone(),
            deadline_at_epoch_ms: self.deadline_at_epoch_ms,
        }
    }

    pub(super) fn advance(
        &mut self,
        request: &V2OperationRequest,
        expected_state: V2AttemptState,
        transition_evidence_sha256: &str,
        attempt: AttemptStateReference,
    ) -> bool {
        let Some(binding) = request.mutation_binding() else {
            return false;
        };
        let state_allocated_fence = self.attempt.state == V2AttemptState::Genesis
            && matches!(
                expected_state,
                V2AttemptState::Reserved | V2AttemptState::Denied
            )
            && self.attempt.fencing_token == 0
            && attempt.fencing_token > 0;
        let expected_state_sha256 =
            response_observation_v2_lifecycle_state_sha256(
                request,
                binding,
                &attempt,
                transition_evidence_sha256,
            );
        if attempt.attempt_id != self.attempt.attempt_id
            || attempt.state != expected_state
            || attempt.attempt_revision
                != self.attempt.attempt_revision.saturating_add(1)
            || (!state_allocated_fence
                && attempt.fencing_token != self.attempt.fencing_token)
            || attempt.state_sha256 != expected_state_sha256
            || binding.attempt_id != self.attempt.attempt_id
            || binding.predecessor_lifecycle_state != self.attempt.state
            || binding.predecessor_state_sha256 != self.attempt.state_sha256
            || binding.attempt_revision != self.attempt.attempt_revision
            || binding.fencing_token != self.attempt.fencing_token
            || binding.transaction != self.transaction
            || binding.monotonic_deadline != self.monotonic_deadline
            || binding.deadline_at_epoch_ms != self.deadline_at_epoch_ms
            || !is_sha256_digest(transition_evidence_sha256)
        {
            return false;
        }
        self.attempt = attempt;
        true
    }
}

#[derive(Clone)]
pub(super) struct ResponseObservationV2Client {
    pub(super) socket_path: PathBuf,
    pub(super) expected_uid: libc::uid_t,
    pub(super) boot_id: String,
    pub(super) authenticated_client_identity_sha256: String,
    pub(super) pinned_genesis_state_sha256: String,
    pub(super) attestation_mode: V2AttestationMode,
    pub(super) signer_key_sha256: String,
    pub(super) role_identity_root_sha256: String,
    pub(super) proof_pins_root_sha256: String,
    pub(super) tee_verifier: Option<ResponseV2PinnedTeeVerifier>,
    pub(super) tee_topology_profile:
        Option<ResponseObservationV2TeeTopologyProfile>,
    pub(super) transparency_trust_pin:
        Arc<ReleaseTransparencyTrustPinV2>,
    pub(super) generation_id: String,
    pub(super) expected_source_commit_sha256: String,
    pub(super) expected_source_tree_sha256: String,
    pub(super) provider_generation: u64,
    pub(super) trust_root_sha256: String,
    pub(super) trust_checkpoint_sha256: String,
    pub(super) revocation_epoch: u64,
    pub(super) role_keys: Arc<BTreeMap<String, V2PinnedRoleKeyV1>>,
    pub(super) healthy: Arc<AtomicU64>,
}

pub(super) struct ResponseObservationV2ClientConfig {
    pub(super) socket_path: PathBuf,
    pub(super) expected_uid: libc::uid_t,
    pub(super) startup_timeout: Duration,
    pub(super) attestation_mode: V2AttestationMode,
    pub(super) signer_key_sha256: String,
    pub(super) role_identity_root_sha256: String,
    pub(super) proof_pins_root_sha256: String,
    pub(super) tee_verifier: Option<ResponseV2PinnedTeeVerifier>,
    pub(super) tee_topology_profile:
        Option<ResponseObservationV2TeeTopologyProfile>,
    pub(super) transparency_trust_pin:
        Arc<ReleaseTransparencyTrustPinV2>,
    pub(super) role_keys: Arc<BTreeMap<String, V2PinnedRoleKeyV1>>,
    pub(super) generation_id: String,
    pub(super) expected_source_commit_sha256: String,
    pub(super) expected_source_tree_sha256: String,
    pub(super) expected_provider_generation: Option<u64>,
    pub(super) expected_trust_root_sha256: Option<String>,
    pub(super) expected_trust_checkpoint_sha256: Option<String>,
    pub(super) minimum_revocation_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseObservationV2TeeTopologyProfile {
    LocalSingleNodeOneOfOne,
}

impl ResponseObservationV2TeeTopologyProfile {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::LocalSingleNodeOneOfOne => {
                "local-single-node-1-of-1"
            }
        }
    }
}

pub(super) struct ResponseObservationV2HelloStatus {
    pub(super) boot_id: String,
    pub(super) authenticated_client_identity_sha256: String,
    pub(super) pinned_genesis_state_sha256: String,
    pub(super) providers_ready: bool,
    pub(super) provider_generation: u64,
    pub(super) attestation: V2FreshResponseAttestationV1,
}

pub(super) struct ResponseObservationV2ExactInput {
    pub(super) descriptor: ExactByteObjectDescriptor,
    pub(super) file: File,
}

pub(super) struct ResponseObservationV2OperationReply {
    pub(super) result: V2OperationResult,
    pub(super) exact_bytes: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    pub(super) canonical_response: Zeroizing<Vec<u8>>,
}

pub(super) struct ResponseObservationV2ResponseDataReply {
    pub(super) result: V2ResponseDataResult,
    pub(super) exact_bytes: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    pub(super) canonical_response: Zeroizing<Vec<u8>>,
}

pub(super) struct ResponseObservationV2Session<'a> {
    pub(super) client: &'a ResponseObservationV2Client,
    pub(super) socket: OwnedFd,
    pub(super) lifecycle_deadline:
        ResponseObservationV2Deadline,
    pub(super) monotonic_deadline: V2MonotonicDeadlineV1,
    pub(super) deadline_at_epoch_ms: u64,
    pub(super) hello_attestation: V2FreshResponseAttestationV1,
}

#[derive(Debug)]
pub(super) enum ResponseObservationV2TransactionError {
    Denied,
    OutcomeUnknown,
    Unavailable,
    InvalidResponse,
    DeniedWithAttempt(ResponseObservationV2ResumeIdentity),
    OutcomeUnknownWithAttempt(ResponseObservationV2ResumeIdentity),
    UnavailableWithAttempt(ResponseObservationV2ResumeIdentity),
    InvalidResponseWithAttempt(ResponseObservationV2ResumeIdentity),
}

#[derive(Debug, Clone)]
pub(super) struct ResponseObservationV2ResumeIdentity {
    pub(super) attempt_id: String,
    pub(super) stable_resume_id: String,
}

impl ResponseObservationV2TransactionError {
    pub(super) fn attempt_id(&self) -> Option<&str> {
        match self {
            Self::DeniedWithAttempt(identity)
            | Self::OutcomeUnknownWithAttempt(identity)
            | Self::UnavailableWithAttempt(identity)
            | Self::InvalidResponseWithAttempt(identity) => {
                Some(&identity.attempt_id)
            }
            _ => None,
        }
    }

    pub(super) fn stable_resume_id(&self) -> Option<&str> {
        match self {
            Self::DeniedWithAttempt(identity)
            | Self::OutcomeUnknownWithAttempt(identity)
            | Self::UnavailableWithAttempt(identity)
            | Self::InvalidResponseWithAttempt(identity) => {
                Some(&identity.stable_resume_id)
            }
            _ => None,
        }
    }

    pub(super) fn with_resume(
        self,
        attempt_id: &str,
        stable_resume_id: &str,
    ) -> Self {
        let identity = ResponseObservationV2ResumeIdentity {
            attempt_id: attempt_id.to_owned(),
            stable_resume_id: stable_resume_id.to_owned(),
        };
        match self {
            Self::Denied | Self::DeniedWithAttempt(_) => {
                Self::DeniedWithAttempt(identity)
            }
            Self::OutcomeUnknown | Self::OutcomeUnknownWithAttempt(_) => {
                Self::OutcomeUnknownWithAttempt(identity)
            }
            Self::Unavailable | Self::UnavailableWithAttempt(_) => {
                Self::UnavailableWithAttempt(identity)
            }
            Self::InvalidResponse | Self::InvalidResponseWithAttempt(_) => {
                Self::InvalidResponseWithAttempt(identity)
            }
        }
    }

    pub(super) fn response(&self) -> SensitiveResponseBytes {
        let (status, code, attempt_id) = match self {
            Self::Denied => (
                StatusCode::FORBIDDEN,
                "response_observation_v2_denied",
                None,
            ),
            Self::OutcomeUnknown => (
                StatusCode::CONFLICT,
                "response_observation_v2_outcome_unknown",
                None,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "response_observation_v2_role_unready",
                None,
            ),
            Self::InvalidResponse => (
                StatusCode::BAD_GATEWAY,
                "response_observation_v2_invalid_terminal",
                None,
            ),
            Self::DeniedWithAttempt(identity) => (
                StatusCode::FORBIDDEN,
                "response_observation_v2_denied",
                Some(identity),
            ),
            Self::OutcomeUnknownWithAttempt(identity) => (
                StatusCode::CONFLICT,
                "response_observation_v2_outcome_unknown",
                Some(identity),
            ),
            Self::UnavailableWithAttempt(identity) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "response_observation_v2_role_unready",
                Some(identity),
            ),
            Self::InvalidResponseWithAttempt(identity) => (
                StatusCode::BAD_GATEWAY,
                "response_observation_v2_invalid_terminal",
                Some(identity),
            ),
        };
        json_status_response(
            status,
            json!({
                "error": code,
                "attemptId":
                    attempt_id.map(|identity| &identity.attempt_id),
                "resumeId":
                    attempt_id.map(|identity| {
                        &identity.stable_resume_id
                    }),
            }),
        )
        .into()
    }
}

#[derive(Debug)]
pub(super) enum ResponseObservationV2ExchangeError {
    Definitive(ResponseObservationV2TransactionError),
    PostSendOutcomeUnknown(V2DurableReplayKeyV1),
}
